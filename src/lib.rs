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

#![crate_name = "safe_ffi"]
#![crate_type = "lib"]

///////////////////////////////////////////////////
//               LINT
///////////////////////////////////////////////////

#![forbid(bad_style, warnings)]

#![deny(deprecated, improper_ctypes, missing_docs, non_shorthand_field_patterns,
overflowing_literals, plugin_as_library, private_no_mangle_fns, private_no_mangle_statics,
raw_pointer_derive, stable_features, unconditional_recursion, unknown_lints,
unused, unused_allocation, unused_attributes, unused_comparisons,
unused_features, unused_parens, while_true)]

#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, variant_size_differences)]

///////////////////////////////////////////////////

// TODO
//! #Client-FFI Library
//! [Project github page](https://github.com/maidsafe/safe_ffi)

extern crate libc;
extern crate routing;
extern crate safe_nfs;
extern crate safe_dns;
extern crate sodiumoxide;
#[macro_use] extern crate safe_client;

#[macro_use] mod macros;

mod errors;
mod implementation;

/// Create a subdirectory. The Name of the subdirectory is the final token in the given path. Eg.,
/// if given path = "/a/b/c/d" then "d" is interpreted as the subdirectory intended to be created.
#[no_mangle]
pub extern fn create_sub_directory(c_path: *const libc::c_char, is_private: bool) -> libc::int32_t {
    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let sub_dir_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let mut parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));
    let dir_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(implementation::get_test_client());

    let access_level = if is_private {
        safe_nfs::AccessLevel::Private
    } else {
        safe_nfs::AccessLevel::Public
    };

    let _ = ffi_try!(dir_helper.create(sub_dir_name,
                                       safe_nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                       vec![],
                                       false,
                                       access_level,
                                       Some(&mut parent_dir_listing)));

    0
}

/// Create a file. The Name of the file is the final token in the given path. Eg.,
/// if given path = "/a/b/c/d" then "d" is interpreted as the file intended to be created.
#[no_mangle]
pub extern fn create_file(c_path   : *const libc::c_char,
                          c_content: *const libc::uint8_t,
                          c_size   : libc::size_t) -> libc::int32_t {
    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));
    let file_helper = safe_nfs::helper::file_helper::FileHelper::new(implementation::get_test_client());

    let mut writer = ffi_try!(file_helper.create(file_name,
                                                 vec![],
                                                 parent_dir_listing));

    writer.write(&implementation::c_uint8_ptr_to_vec(c_content, c_size), 0);
    let _ = ffi_try!(writer.close());

    0
}

/// Get the size of the file. c_size should be properly and sufficiently pre-allocated.
/// The Name of the file is the final token in the given path. Eg.,
/// if given path = "/a/b/c/d" then "d" is interpreted as the file intended to be read.
#[allow(trivial_numeric_casts)] // TODO refer to the one below - sort that then remove this
#[no_mangle]
pub extern fn get_file_size(c_path: *const libc::c_char, c_size: *mut libc::size_t) -> libc::int32_t {
    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));

    let size = ffi_try!(implementation::get_file_size(&file_name, &parent_dir_listing));

    unsafe { std::ptr::write(c_size, size as libc::size_t) }; // TODO All crates must use usize instead of u64 for file-sizes to avoid casting for lower bit architectures

    0
}

/// Read a file. The Name of the file is the final token in the given path. Eg.,
/// if given path = "/a/b/c/d" then "d" is interpreted as the file intended to be read.
/// c_content_buf should be properly and sufficiently pre-allocated.
#[no_mangle]
pub extern fn get_file_content(c_path: *const libc::c_char, c_content_buf: *mut libc::uint8_t) -> libc::int32_t {
    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));
    let data_vec = ffi_try!(implementation::get_file_content(&file_name, &parent_dir_listing));

    unsafe { std::ptr::copy(data_vec.as_ptr(), c_content_buf, data_vec.len()) };

    0
}

/// Register Dns
#[no_mangle]
pub extern fn register_dns(c_long_name            : *const libc::c_char,
                           c_service_name         : *const libc::c_char,
                           c_service_home_dir_path: *const libc::c_char) -> libc::int32_t {
    let client = implementation::get_test_client();

    let tokens = ffi_try!(implementation::path_tokeniser(c_service_home_dir_path));

    let service_home_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));
    let service_home_dir_key = service_home_dir_listing.get_info().get_key();

    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));

    let (public_encryption_key, secret_encryption_key) = sodiumoxide::crypto::box_::gen_keypair();
    let public_signing_key = ffi_try!(client.lock().unwrap().get_public_signing_key()).clone();
    let secret_signing_key = ffi_try!(client.lock().unwrap().get_secret_signing_key()).clone();

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(client.clone()));
    let record_struct_data = ffi_try!(dns_operations.register_dns(long_name,
                                                                  &public_encryption_key,
                                                                  &secret_encryption_key,
                                                                  &vec![(service_name, (service_home_dir_key.0.clone(), service_home_dir_key.1))],
                                                                  vec![public_signing_key],
                                                                  &secret_signing_key,
                                                                  None));

    client.lock().unwrap().put(routing::data::Data::StructuredData(record_struct_data), None);

    0
}

/// Add a new service to the existing (registered) Dns record
#[no_mangle]
pub extern fn add_service(c_long_name            : *const libc::c_char,
                          c_service_name         : *const libc::c_char,
                          c_service_home_dir_path: *const libc::c_char) -> libc::int32_t {
    let client = implementation::get_test_client();

    let tokens = ffi_try!(implementation::path_tokeniser(c_service_home_dir_path));

    let service_home_dir_listing = ffi_try!(implementation::get_final_subdirectory(&tokens));
    let service_home_dir_key = service_home_dir_listing.get_info().get_key();

    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));

    let secret_signing_key = ffi_try!(client.lock().unwrap().get_secret_signing_key()).clone();

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(client.clone()));
    let record_struct_data = ffi_try!(dns_operations.add_service(&long_name,
                                                                 (service_name, (service_home_dir_key.0.clone(), service_home_dir_key.1)),
                                                                 &secret_signing_key,
                                                                 None));

    client.lock().unwrap().post(routing::data::Data::StructuredData(record_struct_data), None);

    0
}

// TODO The follwoing two functions are a little rough for this iteration. It is intended to
// ultimately accept the complete path to the file, root being cosidered the
// service-home-directory.

/// Get file size from service home directory
#[allow(trivial_numeric_casts)] // TODO refer to the one below - sort that then remove this
#[no_mangle]
pub extern fn get_file_size_from_service_home_dir(c_long_name   : *const libc::c_char,
                                                  c_service_name: *const libc::c_char,
                                                  c_file_name   : *const libc::c_char,
                                                  is_private    : bool,
                                                  c_content_size: *mut libc::size_t) -> libc::int32_t {
    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));
    let file_name = ffi_try!(implementation::c_char_ptr_to_string(c_file_name));

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(implementation::get_test_client()));
    let service_dir_key = ffi_try!(dns_operations.get_service_home_directory_key(&long_name,
                                                                                 &service_name,
                                                                                 None));
    let access_level = if is_private {
        safe_nfs::AccessLevel::Private
    } else {
        safe_nfs::AccessLevel::Public
    };

    let dir_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(implementation::get_test_client());
    let service_dir_listing = ffi_try!(dir_helper.get((&service_dir_key.0, service_dir_key.1),
                                                      false,
                                                      &access_level));

    let file_size = ffi_try!(implementation::get_file_size(&file_name, &service_dir_listing));

    unsafe { std::ptr::write(c_content_size, file_size as libc::size_t) }; // TODO All crates must use usize instead of u64 for file-sizes to avoid casting for lower bit architectures

    0
}

/// Get file content from service home directory
#[no_mangle]
pub extern fn get_file_content_from_service_home_dir(c_long_name   : *const libc::c_char,
                                                     c_service_name: *const libc::c_char,
                                                     c_file_name   : *const libc::c_char,
                                                     is_private    : bool,
                                                     c_content_buf : *mut libc::uint8_t) -> libc::int32_t {
    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));
    let file_name = ffi_try!(implementation::c_char_ptr_to_string(c_file_name));

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(implementation::get_test_client()));
    let service_dir_key = ffi_try!(dns_operations.get_service_home_directory_key(&long_name,
                                                                                 &service_name,
                                                                                 None));
    let access_level = if is_private {
        safe_nfs::AccessLevel::Private
    } else {
        safe_nfs::AccessLevel::Public
    };

    let dir_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(implementation::get_test_client());
    let service_dir_listing = ffi_try!(dir_helper.get((&service_dir_key.0, service_dir_key.1),
                                                      false,
                                                      &access_level));

    let data_vec = ffi_try!(implementation::get_file_content(&file_name, &service_dir_listing));

    unsafe { std::ptr::copy(data_vec.as_ptr(), c_content_buf, data_vec.len()) };

    0
}

#[cfg(test)]
mod test {
    use super::*;
    use std::error::Error;

    #[test]
    fn create_directories_files_and_read_files() {
        let size_of_c_int = ::std::mem::size_of::<::libc::c_int>();
        let size_of_c_char = ::std::mem::size_of::<::libc::c_char>();

        // --------------------------------------------------------------------------------------------------
        //                                       NFS Operations
        // --------------------------------------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Create Sub-directory /a - c string size with \0 = 3
        // --------------------------------------------------------------------
        let mut c_path = unsafe { ::libc::malloc(3 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 3 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        assert_eq!(create_sub_directory(c_path, false), 0);
        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };

        // --------------------------------------------------------------------
        // Create Sub-directory /a/last - c string size with \0 = 8
        // --------------------------------------------------------------------
        c_path = unsafe { ::libc::malloc(8 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a/last").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 8 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        assert_eq!(create_sub_directory(c_path, false), 0);
        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };

        // --------------------------------------------------------------------
        // Create file /a/last/file.txt - c string size with \0 = 17
        // --------------------------------------------------------------------
        c_path = unsafe { ::libc::malloc(17 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        let cstring_content = eval_result!(::std::ffi::CString::new("This is the file content.").map_err(|error| ::errors::FfiError::from(error.description())));

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a/last/file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 17 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        assert_eq!(create_file(c_path, cstring_content.as_ptr() as *const ::libc::uint8_t, cstring_content.as_bytes_with_nul().len() as ::libc::size_t), 0);
        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };

        // --------------------------------------------------------------------
        // Get the size of the file
        // --------------------------------------------------------------------
        c_path = unsafe { ::libc::malloc(17 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a/last/file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 17 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        let c_size = unsafe { ::libc::malloc(1 * size_of_c_int as ::libc::size_t) } as *mut ::libc::size_t;

        assert_eq!(get_file_size(c_path, c_size), 0);
        unsafe { assert_eq!(*c_size as usize, cstring_content.as_bytes_with_nul().len()) };

        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };

        // --------------------------------------------------------------------
        // Get the contents of the file
        // --------------------------------------------------------------------
        c_path = unsafe { ::libc::malloc(17 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a/last/file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 17 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        let mut c_content = unsafe { ::libc::malloc((*c_size as usize * ::std::mem::size_of::<::libc::c_int>()) as ::libc::size_t) } as *mut ::libc::uint8_t;

        assert_eq!(get_file_content(c_path, c_content), 0);

        {
            let read_cstr_content = unsafe { ::std::ffi::CStr::from_ptr(c_content as *const ::libc::c_char) };
            assert_eq!(&*cstring_content, read_cstr_content);
        }

        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_content as *mut ::libc::c_void) };

        // --------------------------------------------------------------------------------------------------
        //                                       DNS Operations
        // --------------------------------------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Create Path String /a/last - c string size with \0 = 8
        // --------------------------------------------------------------------
        c_path = unsafe { ::libc::malloc(8 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a/last").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 8 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path, path_lenght_for_c) };
        }

        // --------------------------------------------------------------------
        // Create File Name String file.txt - c string size with \0 = 9
        // --------------------------------------------------------------------
        let c_file_name = unsafe { ::libc::malloc(9 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_file_name = eval_result!(::std::ffi::CString::new("file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let file_name_length_for_c = cstring_file_name.as_bytes_with_nul().len();
            assert_eq!(file_name_length_for_c, 9 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_file_name.as_ptr(), c_file_name, file_name_length_for_c) };
        }

        let mut long_name = eval_result!(::safe_client::utility::generate_random_vector::<u8>(10));
        // Avoid internal nulls and ensure valid ASCII (thus valid utf8)
        for it in long_name.iter_mut() {
            *it %= 128;
            if *it == 0 {
                *it += 1;
            }
        }
        let size_for_c = long_name.len() + 1;
        // --------------------------------------------------------------------
        // Create Long Name String <random> - c string size with \0 = <calculate>
        // --------------------------------------------------------------------
        let c_long_name = unsafe { ::libc::malloc((size_for_c * size_of_c_char) as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_long_name = eval_result!(::std::ffi::CString::new(long_name).map_err(|error| ::errors::FfiError::from(error.description())));

            let long_name_length_for_c = cstring_long_name.as_bytes_with_nul().len();
            assert_eq!(long_name_length_for_c, size_for_c * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_long_name.as_ptr(), c_long_name, long_name_length_for_c) };
        }

        // --------------------------------------------------------------------
        // Create Service Name String www - c string size with \0 = 4
        // --------------------------------------------------------------------
        let c_service_name_www = unsafe { ::libc::malloc(4 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_service_name = eval_result!(::std::ffi::CString::new("www").map_err(|error| ::errors::FfiError::from(error.description())));

            let service_name_length_for_c = cstring_service_name.as_bytes_with_nul().len();
            assert_eq!(service_name_length_for_c, 4 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_service_name.as_ptr(), c_service_name_www, service_name_length_for_c) };
        }

        // --------------------------------------------------------------------
        // Create Service Name String blog - c string size with \0 = 5
        // --------------------------------------------------------------------
        let c_service_name_blog = unsafe { ::libc::malloc(5 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_service_name = eval_result!(::std::ffi::CString::new("blog").map_err(|error| ::errors::FfiError::from(error.description())));

            let service_name_length_for_c = cstring_service_name.as_bytes_with_nul().len();
            assert_eq!(service_name_length_for_c, 5 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_service_name.as_ptr(), c_service_name_blog, service_name_length_for_c) };
        }

        // Register DNS
        assert_eq!(register_dns(c_long_name, c_service_name_www, c_path), 0);

        // Add Service
        assert_eq!(add_service(c_long_name, c_service_name_blog, c_path), 0);

        // Get specific file for www service
        c_content = unsafe { ::libc::malloc((*c_size as usize * ::std::mem::size_of::<::libc::c_int>()) as ::libc::size_t) } as *mut ::libc::uint8_t;
        assert_eq!(get_file_content_from_service_home_dir(c_long_name, c_service_name_www, c_file_name, false, c_content), 0);

        {
            let read_cstr_content = unsafe { ::std::ffi::CStr::from_ptr(c_content as *const ::libc::c_char) };
            assert_eq!(&*cstring_content, read_cstr_content);
        }

        unsafe { ::libc::free(c_content as *mut ::libc::c_void) };

        // Get specific file for blog service
        c_content = unsafe { ::libc::malloc((*c_size as usize * ::std::mem::size_of::<::libc::c_int>()) as ::libc::size_t) } as *mut ::libc::uint8_t;
        assert_eq!(get_file_content_from_service_home_dir(c_long_name, c_service_name_blog, c_file_name, false, c_content), 0);

        {
            let read_cstr_content = unsafe { ::std::ffi::CStr::from_ptr(c_content as *const ::libc::c_char) };
            assert_eq!(&*cstring_content, read_cstr_content);
        }

        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_size as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_content as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_long_name as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_file_name as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_service_name_www as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_service_name_blog as *mut ::libc::c_void) };
    }
}
