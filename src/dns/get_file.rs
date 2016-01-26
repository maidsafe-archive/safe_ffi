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

use safe_nfs::helper::DirectoryHelper;
use safe_dns::dns_operations::DnsOperations;
use {helper, ParameterPacket, ResponseType, Action};
use nfs::file_response::get_response;

#[derive(RustcDecodable, Debug)]
pub struct GetFile {
    offset: i64,
    length: i64,
    file_path: String,
    is_path_shared: bool,
    include_metadata: bool,
}

impl Action for Getfile {
    fn execute(&mut self, params: ParameterPacket) -> ResponseType {
        let dns_operations = try!(DnsOperations::new(params.client.clone()));
        let directory_key = try!(dns_operations.get_service_home_directory_key(&self.long_name,
                                                                               &self.service_name,
                                                                               None));

        let dir_helper = DirectoryHelper::new(params.client.clone());
        let file_dir = try!(dir_helper.get(directory_key));
        let file = try!(file_dir.find_file(&file_name)
                                .ok_or(::errors::FfiError::InvalidPath));
        let response = try!(get_response(file,
                                         params.client,
                                         self.offset,
                                         self.length,
                                         self.include_metadata));

        Ok(Some(try!(::rustc_serialize::json::encode(&response))))
    }
}
