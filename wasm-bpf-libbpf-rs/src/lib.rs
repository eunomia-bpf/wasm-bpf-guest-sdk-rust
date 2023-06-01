//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

pub mod error;
pub mod map;
pub mod object;
pub mod poll;
pub mod prog;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;
