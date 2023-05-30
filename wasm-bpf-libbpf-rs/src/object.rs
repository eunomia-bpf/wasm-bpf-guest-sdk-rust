//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use wasm_bpf_binding::binding::{
    wasm_bpf_map_fd_by_name, wasm_close_bpf_object, wasm_load_bpf_object,
};

use crate::{map::Map, prog::Program, Error, Result};

#[derive(Default)]
pub struct ObjectBuilder {}

impl ObjectBuilder {
    pub fn open_memory<T: AsRef<str>>(&mut self, mem: &[u8]) -> Result<OpenObject> {
        Ok(OpenObject { buf: mem.to_vec() })
    }
}

pub struct OpenObject {
    buf: Vec<u8>,
}

impl OpenObject {
    pub fn load(self) -> Result<Object> {
        let ptr = &self.buf[..];
        let ptr = ptr.as_ptr();
        let handle = wasm_load_bpf_object(ptr as u32, self.buf.len() as i32);
        if handle == 0 {
            return Err(Error::FailedToOpen);
        }
        Ok(Object { handle })
    }
}

pub struct Object {
    handle: u64,
}

impl Object {
    pub fn prog(&self, name: impl AsRef<str>) -> Option<Program> {
        Some(Program {
            name: name.as_ref().to_string(),
            prog_handle: self.handle,
        })
    }
    pub fn map(&self, name: impl AsRef<str>) -> Option<Map> {
        let mut name_bytes = name.as_ref().as_bytes().to_vec();
        name_bytes.push(0);
        let fd = wasm_bpf_map_fd_by_name(self.handle, name_bytes[..].as_ptr() as u32);
        if fd < 0 {
            None
        } else {
            Some(Map {
                name: name.as_ref().to_string(),
                fd,
                handle: self.handle,
            })
        }
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        wasm_close_bpf_object(self.handle);
    }
}
