use wasm_bpf_binding::binding::wasm_bpf_map_operate;

use crate::{Error, Result};

const BPF_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_MAP_DELETE_ELEM: i32 = 3;
const BPF_MAP_GET_NEXT_KEY: i32 = 4;

pub struct Map {
    pub(crate) name: String,
    pub(crate) fd: i32,
    pub(crate) handle: u64,
}

impl Map {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn fd(&self) -> i32 {
        self.fd
    }
    /// Lookup an element in the map. Returns `true` and fill `value_out` if found
    pub fn lookup(&self, key: &[u8], flags: MapFlags, value_out: &mut [u8]) -> bool {
        let ret = wasm_bpf_map_operate(
            self.fd,
            BPF_MAP_LOOKUP_ELEM,
            key.as_ptr() as u64,
            value_out.as_ptr() as u64,
            0,
            flags.bits(),
        );
        ret != -1
    }
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        let ret = wasm_bpf_map_operate(self.fd, BPF_MAP_DELETE_ELEM, key.as_ptr() as u64, 0, 0, 0);
        if ret != 0 {
            Err(Error::FailedToDelete(ret))
        } else {
            Ok(())
        }
    }
    pub fn update(&self, key: &[u8], value: &[u8], flags: MapFlags) -> Result<()> {
        let ret = wasm_bpf_map_operate(
            self.fd,
            BPF_MAP_UPDATE_ELEM,
            key.as_ptr() as u64,
            value.as_ptr() as u64,
            0,
            flags.bits(),
        );
        if ret != 0 {
            Err(Error::FailedToUpdate(ret))
        } else {
            Ok(())
        }
    }
    pub fn keys(&self, start_key: &[u8]) -> MapKeyIter {
        MapKeyIter {
            fd: self.fd,
            prev: start_key.to_vec(),
        }
    }
}

bitflags::bitflags! {
    /// Flags to configure [`Map`] operations.
    pub struct MapFlags: u64 {
        /// See [`libbpf_sys::BPF_ANY`].
        const ANY      = 0;
        /// See [`libbpf_sys::BPF_NOEXIST`].
        const NO_EXIST = 1;
        /// See [`libbpf_sys::BPF_EXIST`].
        const EXIST    = 2;
        /// See [`libbpf_sys::BPF_F_LOCK`].
        const LOCK     = 4;
    }
}

pub struct MapKeyIter {
    fd: i32,
    prev: Vec<u8>,
}
impl Iterator for MapKeyIter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut next_key = self.prev.clone();
        let ret = wasm_bpf_map_operate(
            self.fd,
            BPF_MAP_GET_NEXT_KEY,
            self.prev.as_ptr() as u64,
            0,
            next_key.as_mut_ptr() as u64,
            0,
        );
        if ret != 0 {
            None
        } else {
            self.prev = next_key.clone();
            Some(next_key)
        }
    }
}
