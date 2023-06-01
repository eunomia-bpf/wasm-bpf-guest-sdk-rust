//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use wasm_bpf_binding::binding::wasm_attach_bpf_program;

use crate::{Error, Result};

pub struct Program {
    pub(crate) prog_handle: u64,
    pub(crate) name: String,
}

impl Program {
    pub fn name(&self) -> &str {
        &self.name
    }
    fn name_bytes(&self) -> Vec<u8> {
        let mut ret = self.name.bytes().collect::<Vec<_>>();
        ret.push(0);
        ret
    }
    pub fn attach(&self) -> Result<()> {
        let name = self.name_bytes();
        let ret = wasm_attach_bpf_program(self.prog_handle, name[..].as_ptr() as u32, 0);
        if ret != 0 {
            Err(Error::FailedToAttach(self.name.clone(), ret))
        } else {
            Ok(())
        }
    }
    pub fn attach_with_target(&self, target: impl AsRef<str>) -> Result<()> {
        let name = self.name_bytes();
        let mut target_bytes = target.as_ref().as_bytes().to_vec();
        target_bytes.push(0);
        let ret = wasm_attach_bpf_program(
            self.prog_handle,
            name[..].as_ptr() as u32,
            target_bytes[..].as_ptr() as u32,
        );
        if ret != 0 {
            Err(Error::FailedToAttach(self.name.clone(), ret))
        } else {
            Ok(())
        }
    }
}
