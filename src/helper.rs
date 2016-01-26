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

use std::error::Error;
use std::sync::{Arc, Mutex};

use libc::c_char;
use std::ffi::CStr;
use errors::FfiError;
use safe_core::client::Client;
use safe_nfs::directory_listing::DirectoryListing;
use safe_nfs::metadata::file_metadata::FileMetadata;
use safe_nfs::metadata::directory_key::DirectoryKey;
use safe_nfs::helper::directory_helper::DirectoryHelper;
use safe_nfs::metadata::directory_metadata::DirectoryMetadata;

#[allow(unsafe_code)]
pub fn c_char_ptr_to_string(c_char_ptr: *const c_char) -> Result<String, FfiError> {
    let cstr = unsafe { CStr::from_ptr(c_char_ptr) };
    Ok(try!(String::from_utf8(cstr.to_bytes().iter().map(|a| *a).collect())
                .map_err(|error| FfiError::from(error.description()))))
}

pub fn tokenise_path(path: &str, keep_empty_splits: bool) -> Vec<String> {
    path.split(|element| element == '/')
        .filter(|token| keep_empty_splits || token.len() != 0)
        .map(|token| token.to_string())
        .collect()
}

pub fn get_final_subdirectory(client: Arc<Mutex<Client>>,
                              tokens: &Vec<String>,
                              starting_directory: Option<&DirectoryKey>)
                              -> Result<DirectoryListing, FfiError> {
    let dir_helper = DirectoryHelper::new(client);

    let mut current_dir_listing = match starting_directory {
        Some(directory_key) => try!(dir_helper.get(directory_key)),
        None => try!(dir_helper.get_user_root_directory_listing()),
    };

    for it in tokens.iter() {
        current_dir_listing = {
            let current_dir_metadata = try!(current_dir_listing.get_sub_directories()
                                                               .iter()
                                                               .find(|a| *a.get_name() == *it)
                                                               .ok_or(FfiError::PathNotFound));
            try!(dir_helper.get(current_dir_metadata.get_key()))
        };
    }

    Ok(current_dir_listing)
}


#[derive(RustcEncodable, Debug)]
pub struct GetDirResponse {
    info: DirectoryInfo,
    files: Vec<FileInfo>,
    sub_directories: Vec<DirectoryInfo>,
}

#[derive(RustcEncodable, Debug)]
struct DirectoryInfo {
    name: String,
    is_private: bool,
    is_versioned: bool,
    user_metadata: String,
    creation_time_sec: i64,
    creation_time_nsec: i64,
    modification_time_sec: i64,
    modification_time_nsec: i64,
}

#[derive(RustcEncodable, Debug)]
struct FileInfo {
    name: String,
    size: i64,
    user_metadata: String,
    creation_time_sec: i64,
    creation_time_nsec: i64,
    modification_time_sec: i64,
    modification_time_nsec: i64,
}

pub fn get_dir_response(client: Arc<Mutex<Client>>, directory_key: DirectoryKey) -> Result<GetDirResponse, FfiError> {
    let dir_helper = DirectoryHelper::new(client);
    let dir_listing = try!(dir_helper.get(&directory_key));
    Ok(convert_to_dir_response(dir_listing))
}

pub fn convert_to_dir_response(directory_listing: DirectoryListing) -> GetDirResponse {
    let dir_info = get_directory_info(directory_listing.get_metadata());
    let mut sub_dirs: Vec<DirectoryInfo> =
        Vec::with_capacity(directory_listing.get_sub_directories().len());
    for metadata in directory_listing.get_sub_directories() {
        sub_dirs.push(get_directory_info(metadata));
    }

    let mut files: Vec<FileInfo> = Vec::with_capacity(directory_listing.get_files().len());
    for file in directory_listing.get_files() {
        files.push(get_file_info(file.get_metadata()));
    }

    GetDirResponse {
        info: dir_info,
        files: files,
        sub_directories: sub_dirs,
    }
}

fn get_directory_info(dir_metadata: &DirectoryMetadata) -> DirectoryInfo {
    use rustc_serialize::base64::ToBase64;

    let dir_key = dir_metadata.get_key();
    let created_time = dir_metadata.get_created_time().to_timespec();
    let modified_time = dir_metadata.get_modified_time().to_timespec();
    DirectoryInfo {
        name: dir_metadata.get_name().clone(),
        is_private: *dir_key.get_access_level() == ::safe_nfs::AccessLevel::Private,
        is_versioned: dir_key.is_versioned(),
        user_metadata: (*dir_metadata.get_user_metadata())
                           .to_base64(::config::get_base64_config()),
        creation_time_sec: created_time.sec,
        creation_time_nsec: created_time.nsec as i64,
        modification_time_sec: modified_time.sec,
        modification_time_nsec: modified_time.nsec as i64,
    }
}

fn get_file_info(file_metadata: &FileMetadata) -> FileInfo {
    use rustc_serialize::base64::ToBase64;

    let created_time = file_metadata.get_created_time().to_timespec();
    let modified_time = file_metadata.get_modified_time().to_timespec();
    FileInfo {
        name: file_metadata.get_name().clone(),
        size: file_metadata.get_size() as i64,
        user_metadata: (*file_metadata.get_user_metadata())
                           .to_base64(::config::get_base64_config()),
        creation_time_sec: created_time.sec,
        creation_time_nsec: created_time.nsec as i64,
        modification_time_sec: modified_time.sec,
        modification_time_nsec: modified_time.nsec as i64,
    }
}
