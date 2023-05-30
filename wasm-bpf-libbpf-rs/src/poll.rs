//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

use std::{ffi::c_void, slice, time::Duration};

use wasm_bpf_binding::binding::wasm_bpf_buffer_poll;

use crate::{map::Map, Error, Result};

pub trait SampleCallback: FnMut(&[u8]) {}

impl<T> SampleCallback for T where T: FnMut(&[u8]) {}

struct CallbackStruct<'b> {
    sample_callback: Option<Box<dyn SampleCallback + 'b>>,
}
pub struct PollBuilder<'a, 'b> {
    map: &'a Map,
    sample_callback: Option<Box<dyn SampleCallback + 'b>>,
    data_buf: &'b mut [u8],
}
impl<'a, 'b> PollBuilder<'a, 'b> {
    pub fn new(map: &'a Map, data_buf: &'b mut [u8]) -> Self {
        Self {
            map,
            sample_callback: None,
            data_buf,
        }
    }
    pub fn sample_cb<NewCb: SampleCallback + 'b>(self, cb: NewCb) -> Self {
        Self {
            sample_callback: Some(Box::new(cb)),
            ..self
        }
    }
    pub fn build(self) -> Poll<'b> {
        Poll {
            callback: Box::new(CallbackStruct {
                sample_callback: self.sample_callback,
            }),
            fd: self.map.fd(),
            handle: self.map.handle,
            data_buf: self.data_buf,
        }
    }
}

unsafe extern "C" fn call_sample_cb(ctx: *mut c_void, data: *mut c_void, sz: u32) {
    let callback_struct = ctx as *mut CallbackStruct;

    if let Some(cb) = unsafe { &mut (*callback_struct).sample_callback } {
        let slice = unsafe { slice::from_raw_parts(data as *const u8, sz as usize) };
        cb(slice);
    }
}

pub struct Poll<'b> {
    callback: Box<CallbackStruct<'b>>,
    fd: i32,
    handle: u64,
    data_buf: &'b mut [u8],
}

impl<'b> Poll<'b> {
    pub fn poll(&self, timeout: Duration) -> Result<()> {
        if self.callback.sample_callback.is_some() {
            let ret = wasm_bpf_buffer_poll(
                self.handle,
                self.fd,
                call_sample_cb as usize as i32,
                self.callback.as_ref() as *const CallbackStruct as u32,
                self.data_buf.as_ptr() as u32,
                self.data_buf.len() as i32,
                timeout.as_millis() as i32,
            );
            if ret != 0 {
                Err(Error::FailedToPoll(ret))
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }
}
