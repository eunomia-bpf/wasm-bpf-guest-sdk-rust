//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to load bpf object")]
    FailedToOpen,
    #[error("Failed to attach program {0}: return code = {1}")]
    FailedToAttach(String, i32),
    #[error("Failed to delete element, return code = {0}")]
    FailedToDelete(i32),
    #[error("Failed to update element, return code = {0}")]
    FailedToUpdate(i32),
}
