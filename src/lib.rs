use pyo3::prelude::*;

use bytes::{Buf, BufMut};
use std::iter::Iterator;
use std::fs::OpenOptions;
use std::io::{self, 
    Read, BufReader, 
    Write, BufWriter, 
    Seek, SeekFrom, 
};


mod blowfish;
use crate::blowfish::BlowFish;

#[pymodule]
fn pk2(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Entry>().unwrap();
    m.add_class::<Extractor>().unwrap();
    Ok(())
}


const ENTRY_SIZE: u64 = 128;
const SKIP_HEADER_SIZE: u64 = 256;
const PK2_KEYS: &[u8] = &[0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8];
const DIRECTORY: u8 = 1;
const FILE: u8 = 2;

/**
 * Entries should be of Size 128 Byte.
 */
#[pyclass]
#[derive(Clone, Copy)]
struct Entry {

    #[pyo3(get)]
    offset: u64,            // for use in code, not saved in data

    #[pyo3(get)]
    entry_type: u8,         // 1 Byte;

    name: [u8; 81],         // 81 Byte;
    
    access_date: u64,        // 8 Byte; Format is 'filetime' and we don't update it anyway.
    create_date: u64,        // 8 Byte; Format is 'filetime' and we don't update it anyway.
    modify_date: u64,        // 8 Byte; Format is 'filetime' and we don't update it anyway.
    
    // IF it's a file, this specifies the starting address of the file
    // IF it's a dir, it points to the first entry in that dir
    #[pyo3(get)]
    position: u64,          // 8 Byte;

    // IF it's a file, then this is its size
    #[pyo3(get)]
    size: u32,              // 4 Byte;

    // This specifies the offset of the next entry in the same level(directory for example)
    // if '0' means our next entry is directly below us.
    #[pyo3(get)]
    next_chain: u64,        // 8 Byte;

    // Just to make it 128 Byte.
    padding: u16            // 2 Byte, unused
}

#[pymethods]
impl Entry {
    #[getter]
    fn name(&self) -> String {
        let name: Vec<u8> = self.name.iter().filter(|chr| chr > &&0).map(|x| *x).collect();
        String::from_utf8(name).unwrap_or(String::from("Couldn't"))
    }

    fn to_string(&self) -> String {
        format!("Entry<type: {}, name: {}, position: {}, size: {}, next_chain: {}>",
                    self.entry_type, self.name(), self.position, self.size, self.next_chain)
    }
}

impl Entry {
    fn from_bytes(mut buffer: &[u8]) -> Self {
        let entry_type = buffer.get_u8();
        let mut name = [0; 81];
        buffer.copy_to_slice(&mut name);
        Self {
            offset: 0,
            entry_type,
            name,
            access_date: buffer.get_u64_le(),
            create_date: buffer.get_u64_le(),
            modify_date: buffer.get_u64_le(),
            position: buffer.get_u64_le(),
            size: buffer.get_u32_le(),
            next_chain: buffer.get_u64_le(),
            padding: buffer.get_u16()
        }
    }

    fn into_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(ENTRY_SIZE as usize);
        
        buffer.put_u8(self.entry_type);
        buffer.write(&self.name).unwrap();
        buffer.put_u64_le(self.access_date);
        buffer.put_u64_le(self.create_date);
        buffer.put_u64_le(self.modify_date);
        buffer.put_u64_le(self.position);
        buffer.put_u32_le(self.size);
        buffer.put_u64_le(self.next_chain);
        buffer.put_u16(self.padding);
        buffer
    }
}

#[pyclass]
pub struct Extractor {
    pk2_path: String,
    blowfish: BlowFish,
    root: Option<Entry>,
}

#[pymethods]
impl Extractor {
    #[new]
    pub fn new(pk2_path: Option<&str>) -> PyResult<Self> {
        let mut extractor = Self {
            pk2_path: pk2_path.unwrap().to_string(),
            blowfish: BlowFish::new(PK2_KEYS, 0, 6),
            root: None
        };

        extractor.root = extractor.get_entry_at_offset(SKIP_HEADER_SIZE); 
        Ok(extractor)
    }

    fn list(&self, directory: Option<&str>) -> Vec<Entry>
    {
        let directory = directory.expect("Invalid Directory.");
        let path_node = if directory.eq_ignore_ascii_case(".") { 
            self.root 
        } else { 
            self.get_entry_of_path(directory)
        };

        self.get_children_of_node(&path_node.unwrap())
    }

    fn extract(&self, path: Option<&str>) -> PyResult<(Entry, Vec<u8>)> {
        let path = path.expect("Invalid Path.");
        let entry = self.get_entry_of_path(path).unwrap();
        let bytes = self.read_bytes(entry.position, entry.size).unwrap();
        Ok((entry, bytes))
    }

    fn patch(&self, path: &str, buffer: &[u8]) -> PyResult<()> {
        // Get the entry, if doesn't exist will panic!
        let mut entry = self.get_entry_of_path(path).unwrap();

        // we have the entry now so we will write the buffer
        // first to get the offset where it got written
        // we appended buffer at the end of the file
        // and ignored the actual old file, it still exists but we cant get it
        let offset = self.append_bytes(buffer).unwrap();

        // now we will update our existing entry 
        // with the new size and position(which is it's new location)
        entry.position = offset;
        entry.size = buffer.len() as u32;
        let encrypted = self.blowfish.encrypt(&entry.into_bytes(), 128);
        self.write_bytes(entry.offset, &encrypted).expect(
            "Couldn't write updated entry.");
        Ok(())
    }

}


impl Extractor {
    fn get_entry_of_path(&self, path: &str) -> Option<Entry> {
        let path_parts = self.split_path(path);

        let mut graph_path: Vec<Entry> = Vec::new();
        graph_path.push(self.root.unwrap());
        for part in path_parts.iter() {
            graph_path.push(self.get_entry_of_part(part, &graph_path.last().unwrap()).unwrap());
        }

        graph_path.last().map(|entry| *entry)
    }

    fn get_entry_of_part(&self, path: &str, cursor: &Entry) -> Option<Entry> {
        if cursor.entry_type == FILE {
            panic!("Files can't have children, hence can't be searched in.");
        }

        let children = self.get_children_of_node(&cursor);
        for child in children.into_iter() {
            if child.name()[..].eq_ignore_ascii_case(path) {
                return Some(child);
            }
        }
        panic!(format!("Can't find specified path: {}.", path));
    }

    fn get_children_of_node(&self, entry: &Entry) -> Vec<Entry> {
        if entry.entry_type != DIRECTORY {
            return vec![];
        }
        let mut children: Vec<Entry> = Vec::new();
        let mut current_index = entry.position + 128;

        loop {
            let walking_node = self.get_entry_at_offset(current_index).unwrap();

            if walking_node.entry_type > 2 || walking_node.entry_type <= 0 {
                break;
            }

            children.push(walking_node);

            if walking_node.next_chain > 0 && walking_node.next_chain != current_index {
                current_index = walking_node.next_chain;
            } else {
                current_index += ENTRY_SIZE;
            }

            // If at the end of the chain
            if walking_node.offset + 128 == walking_node.position {
                break;
            }
        }

        children
    }

    fn get_entry_at_offset(&self, offset: u64) -> Option<Entry> {
        let bytes = self.read_bytes(offset, ENTRY_SIZE as u32);
        let decrypted = self.blowfish.decrypt(&bytes.unwrap(), ENTRY_SIZE as u32);
        let mut entry = Entry::from_bytes(&decrypted);
        entry.offset = offset;
        Some(entry)
    }

    fn read_bytes(&self, offset: u64, count: u32) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; count as usize];
        let mut reader = BufReader::new(OpenOptions::new().read(true).open(&self.pk2_path)?);
        reader.seek(SeekFrom::Start(offset.into()))?;
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    fn append_bytes(&self, buffer: &[u8]) -> io::Result<u64> {
        let mut writer = BufWriter::new(OpenOptions::new().append(true).open(&self.pk2_path)?);
        let index = writer.seek(SeekFrom::End(0)).unwrap();
        writer.write_all(buffer)?;
        Ok(index)
    }

    fn write_bytes(&self, offset: u64, buffer: &[u8]) -> io::Result<()> {
        let mut writer = BufWriter::new(OpenOptions::new().write(true).open(&self.pk2_path)?);
        writer.seek(SeekFrom::Start(offset.into()))?;
        writer.write_all(buffer)?;
        Ok(())
    }

    fn split_path<'a>(&self, path: &'a str) -> Vec<&'a str> {
        path.split('/').collect::<Vec<&str>>()
                        .into_iter()
                        .filter(|part| part.len() > 0)
                        .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use super::{Entry, Extractor};
    
    #[test]
    fn test_entry_conversion() {
        let buffer: Vec<u8> = (0..128).map(|i| i as u8 ).collect();
        let entry = Entry::from_bytes(buffer.as_slice().try_into().unwrap());
        let back = entry.into_bytes();

        assert_eq!(back.len(), 128);
        for (i, j) in back.iter().zip(buffer.iter()) {
            assert_eq!(i, j);
        }
    }

    #[test]
    fn test_extract() {
        let path = "/home/sorcerer/Desktop/Media.pk2";
        let extractor = Extractor::new(Some(path));
        let _output = extractor.unwrap().extract(
            Some("server_dep/silkroad/textdata/siegefortressreward.txt"));
    }

    #[test]
    fn test_list() {
        let path = "/home/sorcerer/Desktop/Media.pk2";
        let extractor = Extractor::new(Some(path));
        let _output = extractor.unwrap().list(
            Some("server_dep/silkroad/"));
    }

    #[test]
    fn test_patch() {
        let path = "/home/sorcerer/Desktop/Media.pk2";
        let extractor = Extractor::new(Some(path));
        let _index = extractor.unwrap().patch(
            "server_dep/silkroad/textdata/siegefortressreward.txt", 
            &[1,2,3,4,5,6,8,9]
        );
    }

}


