pub const ENTRY_SIZE: u8 = 128;
pub const SKIP_HEADER_SIZE: u16 = 256;
pub const PK2_KEYS: &[u8] = &[0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8];
pub const DIRECTORY: u8 = 1;
pub const FILE: u8 = 2;

pub fn four_byte_to_u32(buffer: &[u8]) -> u32 {
    ((((buffer[3] as u32) << 24) | ((buffer[2] as u32) << 16)) | ((buffer[1] as u32) << 8)) | (buffer[0] as u32)
}

pub fn u32_to_slice(number: u32) -> [u8; 4] {
    [
        ((number >> 0x00) as u8), 
        ((number >> 0x08) as u8),
        ((number >> 0x10) as u8),
        ((number >> 0x18) as u8),
    ]
}