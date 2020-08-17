#![allow(unused)]
#![allow(dead_code)]

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use pyo3::exceptions;
use pyo3::callback::IntoPyCallbackOutput;

use std::convert::TryInto;
use std::iter::Iterator;
use std::fs::OpenOptions;
use std::io::{self, 
    Read, BufRead, BufReader, 
    Write, BufWriter, 
    Seek, SeekFrom, 
};

mod helpers;
mod blowfish;

use crate::helpers::*;
use crate::blowfish::BlowFish;

#[pymodule]
fn pk2(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Entry>();
    m.add_class::<Extractor>();
    Ok(())
}


/**
 * Entries should be of Size 128 Byte.
 */
#[pyclass]
#[derive(Clone, Copy)]
struct Entry {

    #[pyo3(get)]
    offset: u32,          // for use in code, not saved in data

    #[pyo3(get)]
    entry_type: u8,         // 01 Byte;

    name: [u8; 81],         // 81 Byte;
    
    date_data: [u8; 24],    // 24 Byte; useless but better reserved
    
    // IF it's a file, this specifies the starting address of the file
    // IF it's a dir, it points to the first entry in that dir
    #[pyo3(get)]
    pos_low: u32,           // 4 Byte;

    // WILL SEE
    pos_high: u32,          // 4 Byte;

    // IF it's a file, then this is its size
    #[pyo3(get)]
    size: u32,              // 4 Byte;

    // This specifies the offset of the next entry in the same level(directory for example)
    // if '0' means our next entry is directly below us.
    #[pyo3(get)]
    next_chain: u32,        // 4 Byte;

    // Just to make it 128 Byte.
    garbage: [u8; 6]        // 6 Byte;
}

#[pymethods]
impl Entry {
    #[getter]
    fn name(&self) -> String {
        let mut name: Vec<u8> = self.name.iter().filter(|chr| chr > &&0).map(|x| *x).collect();
        let len = name.len();
        name.clone_from_slice(&self.name[0..len]);
        String::from_utf8(name).unwrap_or(String::from("Couldn't"))
    }

    #[getter]
    fn to_string(&self) -> String {
        format!("Entry<type: {}, name: {}, pos_low: {}, size: {}, next_chain: {}>",
                    self.entry_type, self.name(), self.pos_low, self.size, self.next_chain)
    }
}

impl Entry {
    fn from_bytes(buffer: &[u8]) -> Self {
        
        let mut index = 0;
        let entry_type = buffer[index];
        index += 1;

        let mut name = [0; 81];
        name.clone_from_slice(&buffer[index..index+81]);
        index += 81;

        let mut date_data = [0; 24];
        date_data.clone_from_slice(&buffer[index..index+24]);
        index += 24;

        Self {
            offset: 0,
            entry_type,
            name,
            date_data,
            pos_low: four_byte_to_u32(&buffer[index..(index+4)]),
            pos_high: four_byte_to_u32(&buffer[(index+4)..(index+8)]),
            size: four_byte_to_u32(&buffer[(index+8)..(index+12)]),
            next_chain: four_byte_to_u32(&buffer[(index+12)..(index+16)]),
            garbage: buffer[(index+16)..(index+22)].try_into().unwrap()
        }
    }

    fn into_bytes(&self) -> [u8; 128] {
        let mut buffer: [u8; 128] = [0; 128];
        let mut index = 0;
        
        buffer[index] = self.entry_type;
        index += 1;
        
        buffer[index..(index+81)].clone_from_slice(&self.name);
        index += 81;

        buffer[index..(index+24)].clone_from_slice(&self.date_data);
        index += 24;
        
        buffer[index..(index+4)].clone_from_slice(&u32_to_slice(self.pos_low));
        index += 4;
        
        buffer[index..(index+4)].clone_from_slice(&u32_to_slice(self.pos_high));
        index += 4;
        
        buffer[index..(index+4)].clone_from_slice(&u32_to_slice(self.size));
        index += 4;

        buffer[index..(index+4)].clone_from_slice(&u32_to_slice(self.next_chain));
        index += 4;

        buffer[index..(index+6)].clone_from_slice(&self.garbage);

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

        extractor.root = extractor.get_entry_at_offset(SKIP_HEADER_SIZE as u32); 
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
        let entry = self.get_entry_of_path(path);
        let entry = entry.unwrap();
        let bytes = self.read_bytes(entry.pos_low, entry.size).unwrap();
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
        // with the new size and pos_low(which is it's new location)
        entry.pos_low = offset as u32;
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
        let mut current_index = entry.pos_low + 128;

        loop {
            let walking_node = self.get_entry_at_offset(current_index).unwrap();

            if walking_node.entry_type > 2 || walking_node.entry_type <= 0 {
                break;
            }

            children.push(walking_node);

            if walking_node.next_chain > 0 && walking_node.next_chain != current_index {
                current_index = walking_node.next_chain;
            } else {
                current_index += ENTRY_SIZE as u32;
            }

            // If at the end of the chain
            if walking_node.offset + 128 == walking_node.pos_low {
                break;
            }
        }

        children
    }

    fn get_entry_at_offset(&self, offset: u32) -> Option<Entry> {
        let bytes = self.read_bytes(offset, ENTRY_SIZE.into());
        let decrypted = self.blowfish.decrypt(&bytes.unwrap(), ENTRY_SIZE.into());
        let mut entry = Entry::from_bytes(&decrypted);
        entry.offset = offset;
        Some(entry)
    }

    fn read_bytes(&self, offset: u32, count: u32) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; count as usize];
        let mut reader = BufReader::new(OpenOptions::new().read(true).open(&self.pk2_path)?);
        reader.seek(SeekFrom::Start(offset.into()));
        reader.read_exact(&mut buffer);
        Ok(buffer)
    }

    fn append_bytes(&self, buffer: &[u8]) -> io::Result<(u64)> {
        let mut writer = BufWriter::new(OpenOptions::new().append(true).open(&self.pk2_path)?);
        let index = writer.seek(SeekFrom::End(0)).unwrap();
        writer.write_all(buffer).expect("Couldn't append bytes.");
        Ok(index)
    }

    fn write_bytes(&self, offset: u32, buffer: &[u8]) -> io::Result<()> {
        let mut writer = BufWriter::new(OpenOptions::new().write(true).open(&self.pk2_path)?);
        writer.seek(SeekFrom::Start(offset.into()));
        writer.write_all(buffer).expect("Couldn't write to file.");
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
        let output = extractor.unwrap().extract(
            Some("server_dep/silkroad/textdata/siegefortressreward.txt"));
    }

    #[test]
    fn test_list() {
        let path = "/home/sorcerer/Desktop/Media.pk2";
        let extractor = Extractor::new(Some(path));
        let output = extractor.unwrap().extract(
            Some("server_dep/silkroad/textdata/siegefortressreward.txt"));
    }

    #[test]
    #[ignore]
    fn test_patch() {
        let path = "/home/sorcerer/Desktop/Media.pk2";
        let extractor = Extractor::new(Some(path));
        let index = extractor.unwrap().patch(
            "server_dep/silkroad/textdata/siegefortressreward.txt", 
            &[1,2,3,4,5,6,8,9]
        );
    }

}


