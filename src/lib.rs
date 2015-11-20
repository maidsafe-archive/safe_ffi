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

//! This crate provides FFI-bindings to the Client Modules (`safe_core`, `safe_nfs`, `safe_dns`)
//! In the current implementation the allocations made by this crate are managed within the crate
//! itself and is guaranteed that management of such allocations will not be pushed beyond the FFI
//! boundary. This has a 2-fold outcome: firstly, the passing of data is done by filling of the
//! allocations passed by the caller and is caller's responsibility to manage those. For this every
//! function that fills an allocated memory also has a companion function to return the size of
//! data which the caller can call to find out how much space needs to be allocated in the first
//! place. Second and consequently, the caller does not have to bother calling functions within
//! this crate which only serve to free resources allocated by the crate itself. This otherwise
//! would be error prone and cumbersome. Instead the caller can use whatever idiom in his language
//! to manage memory much more naturally and conveniently (eg., RAII idioms etc)
//!
//! The only exception to the above rule is the obtainment of the client engine itself. The client
//! engine is allocated and managed by the crate. This is necessary because it serves as a context
//! to all operations provided by the crate. Hence the user will obtain the engine on calling any
//! one of the functions to create it and must preserve it for all subsequent operations. When
//! done, to release the resources, `drop_client` may be called.
//!
//! [Project github page](https://github.com/maidsafe/safe_ffi)

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/safe_ffi")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

extern crate libc;
extern crate routing;
extern crate safe_nfs;
extern crate safe_dns;
extern crate sodiumoxide;
#[macro_use] extern crate safe_core;

#[macro_use] mod macros;

mod errors;
mod implementation;

/// Create an unregistered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn create_unregistered_client(client_handle: *mut *const libc::c_void) -> libc::int32_t {
    unsafe {
        *client_handle = cast_to_client_ffi_handle(ffi_try!(safe_core::client::Client::create_unregistered_client()));
    }

    0
}

/// Create a registered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate. `client_handle` is
/// a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn create_account(c_keyword    : *const libc::c_char,
                             c_pin        : *const libc::c_char,
                             c_password   : *const libc::c_char,
                             client_handle: *mut *const libc::c_void) -> libc::int32_t {
    let client = ffi_try!(safe_core::client::Client::create_account(ffi_try!(implementation::c_char_ptr_to_string(c_keyword)),
                                                                      ffi_try!(implementation::c_char_ptr_to_string(c_pin)),
                                                                      ffi_try!(implementation::c_char_ptr_to_string(c_password))));
    unsafe { *client_handle = cast_to_client_ffi_handle(client); }

    0
}

/// Log into a registered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate. `client_handle` is
/// a pointer to a pointer and must point to a valid pointer not junk, else the consequences are
/// undefined.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn log_in(c_keyword    : *const libc::c_char,
                     c_pin        : *const libc::c_char,
                     c_password   : *const libc::c_char,
                     client_handle: *mut *const libc::c_void) -> libc::int32_t {
    let client = ffi_try!(safe_core::client::Client::log_in(ffi_try!(implementation::c_char_ptr_to_string(c_keyword)),
                                                              ffi_try!(implementation::c_char_ptr_to_string(c_pin)),
                                                              ffi_try!(implementation::c_char_ptr_to_string(c_password))));
    unsafe { *client_handle = cast_to_client_ffi_handle(client); }

    0
}

/// Discard and clean up the previously allocated client. Use this only if the client is obtained
/// from one of the client obtainment functions in this crate (`crate_account`, `log_in`,
/// `create_unregistered_client`). Using `client_handle` after a call to this functions is
/// undefined behaviour.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn drop_client(client_handle: *const libc::c_void) {
    let _ = unsafe { std::mem::transmute::<_, Box<std::sync::Arc<std::sync::Mutex<safe_core::client::Client>>>>(client_handle) };
}

/// Create a subdirectory. The Name of the subdirectory is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the subdirectory intended to be created.
#[no_mangle]
pub extern fn create_sub_directory(client_handle: *const libc::c_void,
                                   c_path       : *const libc::c_char,
                                   is_versioned : bool,
                                   is_private   : bool) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let sub_dir_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let mut parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));
    let dir_helper = safe_nfs::helper::directory_helper::DirectoryHelper::new(client);

    let access_level = if is_private {
        safe_nfs::AccessLevel::Private
    } else {
        safe_nfs::AccessLevel::Public
    };

    let _ = ffi_try!(dir_helper.create(sub_dir_name,
                                       safe_nfs::UNVERSIONED_DIRECTORY_LISTING_TAG,
                                       vec![],
                                       is_versioned,
                                       access_level,
                                       Some(&mut parent_dir_listing)));

    0
}

/// Create a file. The Name of the file is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the file intended to be created.
#[no_mangle]
pub extern fn create_file(client_handle: *const libc::c_void,
                          c_path       : *const libc::c_char,
                          c_content    : *const libc::uint8_t,
                          c_size       : libc::size_t) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));
    let file_helper = safe_nfs::helper::file_helper::FileHelper::new(client);

    let mut writer = ffi_try!(file_helper.create(file_name,
                                                 vec![],
                                                 parent_dir_listing));

    writer.write(&implementation::c_uint8_ptr_to_vec(c_content, c_size), 0);
    let _ = ffi_try!(writer.close());

    0
}

/// Get the size of the file. c_size should be properly and sufficiently pre-allocated.
/// The Name of the file is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the file intended to be read.
/// `c_size` should be properly and sufficiently pre-allocated.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn get_file_size(client_handle: *const libc::c_void,
                            c_path       : *const libc::c_char,
                            c_size       : *mut libc::uint64_t) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));

    let size = ffi_try!(implementation::get_file_size(client, &file_name, &parent_dir_listing));

    unsafe { std::ptr::write(c_size, size) };

    0
}

/// Read a file. The Name of the file is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the file intended to be read.
/// `c_content_buf` should be properly and sufficiently pre-allocated.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn get_file_content(client_handle: *const libc::c_void,
                               c_path       : *const libc::c_char,
                               c_content_buf: *mut libc::uint8_t) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let mut tokens = ffi_try!(implementation::path_tokeniser(c_path));

    let file_name = ffi_try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let parent_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));
    let data_vec = ffi_try!(implementation::get_file_content(client, &file_name, &parent_dir_listing));

    unsafe { std::ptr::copy(data_vec.as_ptr(), c_content_buf, data_vec.len()) };

    0
}

/// Register Dns
#[no_mangle]
pub extern fn register_dns(client_handle          : *const libc::c_void,
                           c_long_name            : *const libc::c_char,
                           c_service_name         : *const libc::c_char,
                           c_service_home_dir_path: *const libc::c_char) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let tokens = ffi_try!(implementation::path_tokeniser(c_service_home_dir_path));

    let service_home_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));
    let service_home_dir_key = service_home_dir_listing.get_key();

    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));

    let (public_encryption_key, secret_encryption_key) = sodiumoxide::crypto::box_::gen_keypair();
    let public_signing_key = ffi_try!(client.lock().unwrap().get_public_signing_key()).clone();
    let secret_signing_key = ffi_try!(client.lock().unwrap().get_secret_signing_key()).clone();

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(client.clone()));
    let record_struct_data = ffi_try!(dns_operations.register_dns(long_name,
                                                                  &public_encryption_key,
                                                                  &secret_encryption_key,
                                                                  &vec![(service_name, (service_home_dir_key.clone()))],
                                                                  vec![public_signing_key],
                                                                  &secret_signing_key,
                                                                  None));

    ffi_try!(eval_result!(client.lock()).put(routing::data::Data::StructuredData(record_struct_data), None));

    0
}

/// Add a new service to the existing (registered) Dns record
#[no_mangle]
pub extern fn add_service(client_handle          : *const libc::c_void,
                          c_long_name            : *const libc::c_char,
                          c_service_name         : *const libc::c_char,
                          c_service_home_dir_path: *const libc::c_char) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let tokens = ffi_try!(implementation::path_tokeniser(c_service_home_dir_path));

    let service_home_dir_listing = ffi_try!(implementation::get_final_subdirectory(client.clone(), &tokens, None));
    let service_home_dir_key = service_home_dir_listing.get_key();

    let long_name = ffi_try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = ffi_try!(implementation::c_char_ptr_to_string(c_service_name));

    let secret_signing_key = ffi_try!(client.lock().unwrap().get_secret_signing_key()).clone();

    let dns_operations = ffi_try!(safe_dns::dns_operations::DnsOperations::new(client.clone()));
    let record_struct_data = ffi_try!(dns_operations.add_service(&long_name,
                                                                 (service_name, service_home_dir_key.clone()),
                                                                 &secret_signing_key,
                                                                 None));

    eval_result!(client.lock()).post(routing::data::Data::StructuredData(record_struct_data), None);

    0
}

/// Get file size from service home directory
/// The Name of the file is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the file intended to be read.
/// `c_content_size` should be properly and sufficiently pre-allocated.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn get_file_size_from_service_home_dir(client_handle : *const libc::c_void,
                                                  c_long_name   : *const libc::c_char,
                                                  c_service_name: *const libc::c_char,
                                                  c_file_name   : *const libc::c_char,
                                                  c_content_size: *mut libc::uint64_t) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let (file_name, service_file_dir_listing) = ffi_try!(get_directory_for_service_file(client.clone(),
                                                                                        c_long_name,
                                                                                        c_service_name,
                                                                                        c_file_name));

    let file_size = ffi_try!(implementation::get_file_size(client, &file_name, &service_file_dir_listing));

    unsafe { std::ptr::write(c_content_size, file_size) };

    0
}

/// Get file content from service home directory
/// The Name of the file is the final token in the given path. Eg.,
/// if given path = `/a/b/c/d` then `d` is interpreted as the file intended to be read.
/// `c_content_buf` should be properly and sufficiently pre-allocated.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn get_file_content_from_service_home_dir(client_handle : *const libc::c_void,
                                                     c_long_name   : *const libc::c_char,
                                                     c_service_name: *const libc::c_char,
                                                     c_file_name   : *const libc::c_char,
                                                     c_content_buf : *mut libc::uint8_t) -> libc::int32_t {
    let client = cast_from_client_ffi_handle(client_handle);

    let (file_name, service_file_dir_listing) = ffi_try!(get_directory_for_service_file(client.clone(),
                                                                                        c_long_name,
                                                                                        c_service_name,
                                                                                        c_file_name));

    let data_vec = ffi_try!(implementation::get_file_content(client, &file_name, &service_file_dir_listing));

    unsafe { std::ptr::copy(data_vec.as_ptr(), c_content_buf, data_vec.len()) };

    0
}

#[allow(unsafe_code)]
fn cast_to_client_ffi_handle(client: safe_core::client::Client) -> *const libc::c_void {
    let boxed_client = Box::new(std::sync::Arc::new(std::sync::Mutex::new(client)));
    unsafe { std::mem::transmute(boxed_client) }
}

#[allow(unsafe_code)]
fn cast_from_client_ffi_handle(client_handle: *const libc::c_void) -> std::sync::Arc<std::sync::Mutex<safe_core::client::Client>> {
    let boxed_client: Box<std::sync::Arc<std::sync::Mutex<safe_core::client::Client>>> = unsafe {
        std::mem::transmute(client_handle)
    };

    let client = (*boxed_client).clone();
    std::mem::forget(boxed_client);

    client
}

fn get_directory_for_service_file(client        : std::sync::Arc<std::sync::Mutex<safe_core::client::Client>>,
                                  c_long_name   : *const libc::c_char,
                                  c_service_name: *const libc::c_char,
                                  c_file_name   : *const libc::c_char) -> Result<(String, safe_nfs::directory_listing::DirectoryListing), errors::FfiError> {
    let mut tokens = try!(implementation::path_tokeniser(c_file_name));

    let file_name = try!(tokens.pop().ok_or(errors::FfiError::InvalidPath));
    let long_name = try!(implementation::c_char_ptr_to_string(c_long_name));
    let service_name = try!(implementation::c_char_ptr_to_string(c_service_name));

    let dns_operations = safe_dns::dns_operations::DnsOperations::new_unregistered(client.clone());
    let service_dir_key = try!(dns_operations.get_service_home_directory_key(&long_name,
                                                                             &service_name,
                                                                             None));

    Ok((file_name, try!(implementation::get_final_subdirectory(client,
                                                               &tokens,
                                                               Some(&service_dir_key)))))
}

#[cfg(test)]
mod test {
    #![allow(unsafe_code)]
    use super::*;
    use std::error::Error;

    fn generate_random_cstring(len: usize) -> Result<::std::ffi::CString, ::errors::FfiError> {
        let mut cstring_vec = try!(::safe_core::utility::generate_random_vector::<u8>(len));
        // Avoid internal nulls and ensure valid ASCII (thus valid utf8)
        for it in cstring_vec.iter_mut() {
            *it %= 128;
            if *it == 0 {
                *it += 1;
            }
        }

        ::std::ffi::CString::new(cstring_vec).map_err(|error| ::errors::FfiError::from(error.description()))
    }

    #[test]
    fn account_creation_and_login() {
        let cstring_pin = eval_result!(generate_random_cstring(10));
        let cstring_keyword = eval_result!(generate_random_cstring(10));
        let cstring_password = eval_result!(generate_random_cstring(10));

        {
            let mut client_handle = 0 as *const ::libc::c_void;
            assert_eq!(client_handle, 0 as *const ::libc::c_void);

            {
                let ptr_to_client_handle = &mut client_handle;

                let _ = assert_eq!(create_account(cstring_keyword.as_ptr(),
                                                  cstring_pin.as_ptr(),
                                                  cstring_password.as_ptr(),
                                                  ptr_to_client_handle),
                                   0);
            }

            assert!(client_handle != 0 as *const ::libc::c_void);
            drop_client(client_handle);
        }

        {
            let mut client_handle = 0 as *const ::libc::c_void;
            assert_eq!(client_handle, 0 as *const ::libc::c_void);

            {
                let ptr_to_client_handle = &mut client_handle;

                let _ = assert_eq!(log_in(cstring_keyword.as_ptr(),
                                          cstring_pin.as_ptr(),
                                          cstring_password.as_ptr(),
                                          ptr_to_client_handle),
                                   0);
            }

            assert!(client_handle != 0 as *const ::libc::c_void);
            drop_client(client_handle);
        }
    }

    #[test]
    fn create_directories_files_and_read_files() {
        // Create a client
        let cstring_pin = eval_result!(generate_random_cstring(10));
        let cstring_keyword = eval_result!(generate_random_cstring(10));
        let cstring_password = eval_result!(generate_random_cstring(10));

        let mut client_handle = 0 as *const ::libc::c_void;

        {
            let ptr_to_client_handle = &mut client_handle;
            let _ = assert_eq!(create_account(cstring_keyword.as_ptr(),
                                              cstring_pin.as_ptr(),
                                              cstring_password.as_ptr(),
                                              ptr_to_client_handle),
                               0);
        }

        // Some size references
        let size_of_c_char = ::std::mem::size_of::<::libc::c_char>();
        let size_of_c_uint8 = ::std::mem::size_of::<::libc::uint8_t>();
        let size_of_c_uint64 = ::std::mem::size_of::<::libc::uint64_t>();

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

        // Create unversioned and public
        assert_eq!(create_sub_directory(client_handle, c_path, false, false), 0);
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

        assert_eq!(create_sub_directory(client_handle, c_path, true, false), 0);
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

        assert_eq!(create_file(client_handle,
                               c_path,
                               cstring_content.as_ptr() as *const ::libc::uint8_t, cstring_content.as_bytes_with_nul().len() as ::libc::size_t),
                    0);
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

        let c_size = unsafe { ::libc::malloc(size_of_c_uint64 as ::libc::size_t) } as *mut ::libc::uint64_t;

        assert_eq!(get_file_size(client_handle, c_path, c_size), 0);
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

        // Note: This will result in narrowing on < 64 bit systems - but it's Ok for this test as
        //       we are not dealing with files larger than 2^32 bytes.
        let mut c_content = unsafe { ::libc::malloc((*c_size as usize * size_of_c_uint8) as ::libc::size_t) } as *mut ::libc::uint8_t;

        assert_eq!(get_file_content(client_handle, c_path, c_content), 0);

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
        // Create Path String /a - c string size with \0 = 3
        // --------------------------------------------------------------------
        let c_path_blog = unsafe { ::libc::malloc(3 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_path = eval_result!(::std::ffi::CString::new("/a").map_err(|error| ::errors::FfiError::from(error.description())));

            let path_lenght_for_c = cstring_path.as_bytes_with_nul().len();
            assert_eq!(path_lenght_for_c, 3 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_path.as_ptr(), c_path_blog, path_lenght_for_c) };
        }

        // --------------------------------------------------------------------
        // Create File Name String file.txt - c string size with \0 = 9
        // --------------------------------------------------------------------
        let c_file_name_www = unsafe { ::libc::malloc(9 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_file_name = eval_result!(::std::ffi::CString::new("file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let file_name_length_for_c = cstring_file_name.as_bytes_with_nul().len();
            assert_eq!(file_name_length_for_c, 9 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_file_name.as_ptr(), c_file_name_www, file_name_length_for_c) };
        }

        // --------------------------------------------------------------------
        // Create File Name String last/file.txt - c string size with \0 = 14
        // --------------------------------------------------------------------
        let c_file_name_blog = unsafe { ::libc::malloc(14 * size_of_c_char as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_file_name = eval_result!(::std::ffi::CString::new("last/file.txt").map_err(|error| ::errors::FfiError::from(error.description())));

            let file_name_length_for_c = cstring_file_name.as_bytes_with_nul().len();
            assert_eq!(file_name_length_for_c, 14 * size_of_c_char);

            unsafe { ::std::ptr::copy(cstring_file_name.as_ptr(), c_file_name_blog, file_name_length_for_c) };
        }

        const SIZE_FOR_C: usize = 11;
        // --------------------------------------------------------------------
        // Create Long Name String <random> - c string size with \0 = <calculate>
        // --------------------------------------------------------------------
        let c_long_name = unsafe { ::libc::malloc((SIZE_FOR_C * size_of_c_char) as ::libc::size_t) } as *mut ::libc::c_char;

        {
            let cstring_long_name = eval_result!(generate_random_cstring(SIZE_FOR_C - 1));

            let long_name_length_for_c = cstring_long_name.as_bytes_with_nul().len();
            assert_eq!(long_name_length_for_c, SIZE_FOR_C * size_of_c_char);

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
        assert_eq!(register_dns(client_handle, c_long_name, c_service_name_www, c_path), 0);

        // Add Service
        assert_eq!(add_service(client_handle, c_long_name, c_service_name_blog, c_path_blog), 0);

        // --------------------------------------------------------------------
        // Dns Getters - Browser Equivalents
        // --------------------------------------------------------------------

        // Destroy previous handle
        drop_client(client_handle);

        // Get an unregistered client
        let mut unregistered_client_handle = 0 as *const ::libc::c_void;

        {
            let ptr_to_unregistered_client_handle = &mut unregistered_client_handle;
            let _ = assert_eq!(create_unregistered_client(ptr_to_unregistered_client_handle), 0);
        }

        // Get specific file for www service
        // Note: This will result in narrowing on < 64 bit systems - but it's Ok for this test as
        //       we are not dealing with files larger than 2^32 bytes.
        c_content = unsafe { ::libc::malloc((*c_size as usize * size_of_c_uint8) as ::libc::size_t) } as *mut ::libc::uint8_t;
        assert_eq!(get_file_content_from_service_home_dir(unregistered_client_handle,
                                                          c_long_name,
                                                          c_service_name_www,
                                                          c_file_name_www,
                                                          c_content),
                   0);

        {
            let read_cstr_content = unsafe { ::std::ffi::CStr::from_ptr(c_content as *const ::libc::c_char) };
            assert_eq!(&*cstring_content, read_cstr_content);
        }

        unsafe { ::libc::free(c_content as *mut ::libc::c_void) };

        // Get specific file for blog service
        // Note: This will result in narrowing on < 64 bit systems - but it's Ok for this test as
        //       we are not dealing with files larger than 2^32 bytes.
        c_content = unsafe { ::libc::malloc((*c_size as usize * size_of_c_uint8) as ::libc::size_t) } as *mut ::libc::uint8_t;
        assert_eq!(get_file_content_from_service_home_dir(unregistered_client_handle,
                                                          c_long_name,
                                                          c_service_name_blog,
                                                          c_file_name_blog,
                                                          c_content),
                   0);

        {
            let read_cstr_content = unsafe { ::std::ffi::CStr::from_ptr(c_content as *const ::libc::c_char) };
            assert_eq!(&*cstring_content, read_cstr_content);
        }

        // Destroy client handle
        drop_client(unregistered_client_handle);

        unsafe { ::libc::free(c_path as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_size as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_content as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_path_blog as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_long_name as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_file_name_www as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_file_name_blog as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_service_name_www as *mut ::libc::c_void) };
        unsafe { ::libc::free(c_service_name_blog as *mut ::libc::c_void) };
    }
}
