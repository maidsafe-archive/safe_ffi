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
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]


extern crate libc;
extern crate routing;
extern crate safe_nfs;
extern crate safe_dns;
extern crate safe_core;
extern crate sodiumoxide;
extern crate rustc_serialize;
#[allow(unused_extern_crates)]
#[macro_use] extern crate maidsafe_utilities;

use rustc_serialize::json;
use std::sync::{Arc, Mutex};
use rustc_serialize::Decoder;
use safe_core::client::Client;
use rustc_serialize::Decodable;
use std::mem::{forget, transmute};
use rustc_serialize::base64::FromBase64;
use maidsafe_utilities::serialisation::deserialise;
use safe_nfs::metadata::directory_key::DirectoryKey;

#[macro_use] mod macros;

mod dns;
mod nfs;
mod config;
mod helper;
mod test_utils;
/// Errors thrown by the FFI operations
pub mod errors;

/// ParameterPacket acts as a holder for the standard parameters that would be needed for performing
/// operations across the modules like nfs and dns
#[derive(Clone)]
pub struct ParameterPacket {
    /// Client instance used for performing the API operation
    pub client: Arc<Mutex<Client>>,
    /// Root directory of teh application
    pub app_root_dir_key: DirectoryKey,
    /// Denotes whether the application has access to SAFEDrive
    pub safe_drive_access: bool,
    /// SAFEDrive root directory key
    pub safe_drive_dir_key: DirectoryKey,
}

/// ResponseType tspecifies the standard Response that is to be expected from the ::Action trait
pub type ResponseType = Result<Option<String>, ::errors::FfiError>;

/// ICommand trait
pub trait Action {
    /// ICommand executer
    fn execute(&mut self, params: ParameterPacket) -> ResponseType;
}

/// Create an unregistered client. This or any one of the other companion functions to get a
/// client must be called before initiating any operation allowed by this crate.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn create_unregistered_client(client_handle: *mut *const libc::c_void) -> libc::int32_t {
    unsafe {
        *client_handle = cast_to_client_ffi_handle(ffi_try!(Client::create_unregistered_client()));
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
    let client = ffi_try!(Client::create_account(ffi_try!(helper::c_char_ptr_to_string(c_keyword)),
                                                                      ffi_try!(helper::c_char_ptr_to_string(c_pin)),
                                                                      ffi_try!(helper::c_char_ptr_to_string(c_password))));
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
    let client = ffi_try!(Client::log_in(ffi_try!(helper::c_char_ptr_to_string(c_keyword)),
                                                  ffi_try!(helper::c_char_ptr_to_string(c_pin)),
                                                  ffi_try!(helper::c_char_ptr_to_string(c_password))));
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
    let _ = unsafe { transmute::<_, Box<Arc<Mutex<Client>>>>(client_handle) };
}

/// General function that can be invoked for performing a API specific operation that wont return any result.
/// This function would only perform the operation and return 0 or error code
/// c_payload refers to the JSON payload that can be passed as a JSON string.
/// The JSON string should have keys module, action, app_root_dir_key, safe_drive_dir_key,
/// safe_drive_access and data. `data` refers to API specific payload.
#[no_mangle]
pub extern fn execute(c_payload    : *const libc::c_char,
                      client_handle: *const libc::c_void) -> libc::int32_t {
    let payload: String = ffi_try!(helper::c_char_ptr_to_string(c_payload));
    let json_request = ffi_try!(parse_result!(json::Json::from_str(&payload), "JSON parse error"));
    let mut json_decoder = json::Decoder::new(json_request);

    let client = cast_from_client_ffi_handle(client_handle);
    let (module, action, parameter_packet) = ffi_try!(get_parameter_packet(client, &mut json_decoder));
    let result = module_parser(module, action, parameter_packet, &mut json_decoder);
    let _ = ffi_try!(result);

    0
}

/// General function that can be invoked for performing a API specific operation that will return Vec<u8> result.
/// This function would perform the operation and the result of operation is written in the c_result
/// and also return 0 or error code as return value of the function
/// c_payload refers to the JSON payload that can be passed as a JSON string.
/// The JSON string should have keys module, action, app_root_dir_key, safe_drive_dir_key,
/// safe_drive_access and data. `data` refers to API specific payload.
#[no_mangle]
#[allow(unsafe_code)]
pub extern fn execute_for_content(c_payload    : *const libc::c_char,
                                  client_handle: *const libc::c_void,
                                  c_result     : *mut *const libc::c_void) -> libc::int32_t {
    let payload: String = ffi_try!(helper::c_char_ptr_to_string(c_payload));
    let json_request = ffi_try!(parse_result!(json::Json::from_str(&payload), "JSON parse error"));
    let mut json_decoder = json::Decoder::new(json_request);

    let client = cast_from_client_ffi_handle(client_handle);
    let (module, action, parameter_packet) = ffi_try!(get_parameter_packet(client, &mut json_decoder));
    let result = module_parser(module, action, parameter_packet, &mut json_decoder);
    let data = match ffi_try!(result) {
        Some(response) => response,
        None => "".to_string()
    };

    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), c_result as *mut u8, data.len())
    };

    0
}

fn get_parameter_packet<D>(client: Arc<Mutex<Client>>,
                           json_decoder: &mut D) ->
                           Result<(String, String, ParameterPacket), ::errors::FfiError>
   where D: Decoder, D::Error: ::std::fmt::Debug
{
    let module: String = try!(parse_result!(json_decoder.read_struct_field("module", 0, |d| {
        Decodable::decode(d)
    }), ""));
    let action: String = try!(parse_result!(json_decoder.read_struct_field("action", 1, |d| {
        Decodable::decode(d)
    }), ""));
    let base64_safe_drive_dir_key: String = try!(parse_result!(json_decoder.read_struct_field("safe_drive_dir_key", 2, |d| {
        Decodable::decode(d)
    }), ""));
    let base64_app_dir_key: String = try!(parse_result!(json_decoder.read_struct_field("app_dir_key", 3, |d| {
        Decodable::decode(d)
    }), ""));
    let safe_drive_access: bool = try!(parse_result!(json_decoder.read_struct_field("safe_drive_access", 4, |d| {
        Decodable::decode(d)
    }), ""));

    let serialised_app_dir_key: Vec<u8> = try!(parse_result!(base64_app_dir_key[..].from_base64(), ""));
    let serialised_safe_drive_key: Vec<u8> = try!(parse_result!(base64_safe_drive_dir_key[..].from_base64(), ""));

    let safe_drive_dir_key: DirectoryKey = try!(deserialise(&serialised_safe_drive_key));
    let app_root_dir_key: DirectoryKey = try!(deserialise(&serialised_app_dir_key));

    Ok((module,
        action,
        ParameterPacket {
            client: client,
            app_root_dir_key: app_root_dir_key,
            safe_drive_access: safe_drive_access,
            safe_drive_dir_key: safe_drive_dir_key,
        }
    ))
}

fn module_parser<D>(module: String,
                    action: String,
                    parameter_packet: ParameterPacket,
                    decoder: &mut D) -> ResponseType
    where D: Decoder, D::Error: ::std::fmt::Debug
{
    match &module[..] {
        "dns" => dns::action_dispatcher(action, parameter_packet, decoder),
        "nfs" => nfs::action_dispatcher(action, parameter_packet, decoder),
         _    => {unimplemented!()},
    }
}

#[allow(unsafe_code)]
fn cast_to_client_ffi_handle(client: Client) -> *const libc::c_void {
    let boxed_client = Box::new(Arc::new(Mutex::new(client)));
    unsafe { transmute(boxed_client) }
}

#[allow(unsafe_code)]
fn cast_from_client_ffi_handle(client_handle: *const libc::c_void) -> Arc<Mutex<Client>> {
    let boxed_client: Box<Arc<Mutex<Client>>> = unsafe {
        transmute(client_handle)
    };

    let client = (*boxed_client).clone();
    forget(boxed_client);

    client
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
        let cstring_pin = unwrap_result!(generate_random_cstring(10));
        let cstring_keyword = unwrap_result!(generate_random_cstring(10));
        let cstring_password = unwrap_result!(generate_random_cstring(10));

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
}
