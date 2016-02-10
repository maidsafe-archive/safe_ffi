// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::fmt;

use safe_core::errors::CoreError;
use safe_dns::errors::{DnsError, DNS_ERROR_START_RANGE};
use safe_nfs::errors::NfsError;

const FFI_ERROR_START_RANGE: i32 = DNS_ERROR_START_RANGE - 500;

/// Errors during FFI operations
pub enum FfiError {
    /// Errors from safe_core
    CoreError(CoreError),
    /// Errors from safe_nfs
    NfsError(NfsError),
    /// Errors from safe_dns
    DnsError(DnsError),
    /// Invalid Path given
    InvalidPath,
    /// Given Path does not exist for the client
    PathNotFound,
    /// Given File does not exist for the client
    FileNotFound,
    /// Unexpected or some programming error
    Unexpected(String),
}

impl fmt::Debug for FfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FfiError::CoreError(ref error) => write!(f, "FfiError::CoreError -> {:?}", error),
            FfiError::NfsError(ref error) => write!(f, "FfiError::NfsError -> {:?}", error),
            FfiError::DnsError(ref error) => write!(f, "FfiError::DnsError -> {:?}", error),
            FfiError::InvalidPath => write!(f, "FfiError::InvalidPath"),
            FfiError::PathNotFound => write!(f, "FfiError::PathNotFound"),
            FfiError::FileNotFound => write!(f, "FfiError::FileNotFound"),
            FfiError::Unexpected(ref error) => write!(f, "FfiError::Unexpected::{{{:?}}}", error),
        }
    }
}

impl From<CoreError> for FfiError {
    fn from(error: CoreError) -> FfiError {
        FfiError::CoreError(error)
    }
}

impl From<NfsError> for FfiError {
    fn from(error: NfsError) -> FfiError {
        FfiError::NfsError(error)
    }
}

impl From<DnsError> for FfiError {
    fn from(error: DnsError) -> FfiError {
        FfiError::DnsError(error)
    }
}

impl<'a> From<&'a str> for FfiError {
    fn from(error: &'a str) -> FfiError {
        FfiError::Unexpected(error.to_string())
    }
}

impl Into<i32> for FfiError {
    fn into(self) -> i32 {
        match self {
            FfiError::CoreError(error) => error.into(),
            FfiError::NfsError(error) => error.into(),
            FfiError::DnsError(error) => error.into(),
            FfiError::InvalidPath => FFI_ERROR_START_RANGE,
            FfiError::PathNotFound => FFI_ERROR_START_RANGE - 1,
            FfiError::FileNotFound => FFI_ERROR_START_RANGE - 2,
            FfiError::Unexpected(_) => FFI_ERROR_START_RANGE - 3,
        }
    }
}
