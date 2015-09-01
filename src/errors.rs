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

const FFI_ERROR_START_RANGE: i32 = ::safe_dns::errors::DNS_ERROR_START_RANGE - 500;

/// Errors during FFI operations
pub enum FfiError {
    /// Errors from safe_client
    ClientError(::safe_client::errors::ClientError),
    /// Errors from safe_nfs
    NfsError(::safe_nfs::errors::NfsError),
    /// Errors from safe_dns
    DnsError(::safe_dns::errors::DnsError),
    /// Invalid Path given
    InvalidPath,
    /// Given Path does not exist for the client
    PathNotFound,
    /// Given File does not exist for the client
    FileNotFound,
    /// Unexpected or some programming error
    Unexpected(String),
}

impl ::std::fmt::Debug for FfiError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            FfiError::ClientError(ref error) => write!(f, "FfiError::ClientError -> {:?}", error),
            FfiError::NfsError(ref error)    => write!(f, "FfiError::NfsError -> {:?}", error),
            FfiError::DnsError(ref error)    => write!(f, "FfiError::DnsError -> {:?}", error),
            FfiError::InvalidPath            => write!(f, "FfiError::InvalidPath"),
            FfiError::PathNotFound           => write!(f, "FfiError::PathNotFound"),
            FfiError::FileNotFound           => write!(f, "FfiError::FileNotFound"),
            FfiError::Unexpected(ref error)  => write!(f, "FfiError::Unexpected::{{{:?}}}", error),
        }
    }
}

impl From<::safe_client::errors::ClientError> for FfiError {
    fn from(error: ::safe_client::errors::ClientError) -> FfiError {
        FfiError::ClientError(error)
    }
}

impl From<::safe_nfs::errors::NfsError> for FfiError {
    fn from(error: ::safe_nfs::errors::NfsError) -> FfiError {
        FfiError::NfsError(error)
    }
}

impl From<::safe_dns::errors::DnsError> for FfiError {
    fn from(error: ::safe_dns::errors::DnsError) -> FfiError {
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
            FfiError::ClientError(error) => error.into(),
            FfiError::NfsError(error)    => error.into(),
            FfiError::DnsError(error)    => error.into(),
            FfiError::InvalidPath        => FFI_ERROR_START_RANGE,
            FfiError::PathNotFound       => FFI_ERROR_START_RANGE - 1,
            FfiError::FileNotFound       => FFI_ERROR_START_RANGE - 2,
            FfiError::Unexpected(_)      => FFI_ERROR_START_RANGE - 3,
        }
    }
}
