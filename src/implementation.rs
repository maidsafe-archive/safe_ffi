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

#[allow(unsafe_code)]
pub fn c_uint8_ptr_to_vec(c_uint8_ptr: *const ::libc::uint8_t, c_size: ::libc::size_t) -> Vec<u8> {
    unsafe { ::std::slice::from_raw_parts(c_uint8_ptr, c_size).to_vec() }
}

#[allow(unsafe_code)]
pub fn c_char_ptr_to_string(c_char_ptr: *const ::libc::c_char) -> Result<String, ::errors::FfiError> {
    let cstr = unsafe { ::std::ffi::CStr::from_ptr(c_char_ptr) };
    Ok(try!(String::from_utf8(cstr.to_bytes().iter().map(|a| *a).collect()).map_err(|error| ::errors::FfiError::from(error.description()))))
}

pub fn path_tokeniser(c_path: *const ::libc::c_char) -> Result<Vec<String>, ::errors::FfiError> {
    let string_path = try!(c_char_ptr_to_string(c_path));
    Ok(string_path.split("/").filter(|a| !a.is_empty()).map(|a| a.to_string()).collect())
}

pub fn get_final_subdirectory(client            : ::std::sync::Arc<::std::sync::Mutex<::safe_core::client::Client>>,
                              tokens            : &Vec<String>,
                              starting_directory: Option<&::safe_nfs::metadata::directory_key::DirectoryKey>) -> Result<::safe_nfs::directory_listing::DirectoryListing,
                                                                                                                        ::errors::FfiError> {
    let dir_helper = ::safe_nfs::helper::directory_helper::DirectoryHelper::new(client);

    let mut current_dir_listing = match starting_directory {
        Some(directory_key) => try!(dir_helper.get(directory_key)),
        None => try!(dir_helper.get_user_root_directory_listing()),
    };

    for it in tokens.iter() {
        current_dir_listing = {
            let current_dir_metadata = try!(current_dir_listing.get_sub_directories().iter().find(|a| *a.get_name() == *it)
                                                                                            .ok_or(::errors::FfiError::PathNotFound));
            try!(dir_helper.get(current_dir_metadata.get_key()))
        };
    }

    Ok(current_dir_listing)
}

pub fn get_file_size(client          : ::std::sync::Arc<::std::sync::Mutex<::safe_core::client::Client>>,
                     name            : &String,
                     parent_directory: &::safe_nfs::directory_listing::DirectoryListing) -> Result<u64, ::errors::FfiError> {
    let reader = try!(get_reader(client, name, parent_directory));
    Ok(reader.size())
}

pub fn get_file_content(client          : ::std::sync::Arc<::std::sync::Mutex<::safe_core::client::Client>>,
                        name            : &String,
                        parent_directory: &::safe_nfs::directory_listing::DirectoryListing) -> Result<Vec<u8>, ::errors::FfiError> {
    let mut reader = try!(get_reader(client, name, parent_directory));
    let size = reader.size();
    Ok(try!(reader.read(0, size)))
}

fn get_reader<'a>(client          : ::std::sync::Arc<::std::sync::Mutex<::safe_core::client::Client>>,
                  name            : &String,
                  parent_directory: &'a ::safe_nfs::directory_listing::DirectoryListing) -> Result<::safe_nfs::helper::reader::Reader<'a>, ::errors::FfiError> {
    let file = try!(parent_directory.get_files().iter().find(|a| *a.get_name() == *name).ok_or(::errors::FfiError::FileNotFound));
    let file_helper = ::safe_nfs::helper::file_helper::FileHelper::new(client);
    Ok(file_helper.read(file))
}

#[cfg(test)]
mod test {
    use super::*;
    use std::error::Error;

    #[test]
    fn parse_path() {
        let path_0 = unwrap_result!(::std::ffi::CString::new("/abc/d/ef").map_err(|error| ::errors::FfiError::from(error.description())));
        let path_1 = unwrap_result!(::std::ffi::CString::new("/abc/d/ef/").map_err(|error| ::errors::FfiError::from(error.description())));
        let path_2 = unwrap_result!(::std::ffi::CString::new("///abc///d/ef////").map_err(|error| ::errors::FfiError::from(error.description())));

        let expected = vec!["abc".to_string(),
                            "d".to_string(),
                            "ef".to_string()];

        let tokenised_0 = unwrap_result!(path_tokeniser(path_0.as_ptr()));
        let tokenised_1 = unwrap_result!(path_tokeniser(path_1.as_ptr()));
        let tokenised_2 = unwrap_result!(path_tokeniser(path_2.as_ptr()));

        assert_eq!(tokenised_0, expected);
        assert_eq!(tokenised_1, expected);
        assert_eq!(tokenised_2, expected);
    }
}
