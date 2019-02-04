/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate aesm_client;
extern crate enclave_runner;
extern crate sgxs_loaders;

use aesm_client::AesmClient;
use enclave_runner::EnclaveBuilder;
use enclave_runner::usercalls::{UsercallExtension, SyncStream};
use sgxs_loaders::isgx::Device as IsgxDevice;

use std::io::{ErrorKind as IoErrorKind, Result as IoResult, Write, Read};
use std::process::{Command, Child, Stdio};
use std::sync::{Arc, Mutex};

/// This example demonstrates use of user-call extensions.
/// User call extension allow the enclave code to "connect" to an external service via a customized enclave runner.
/// Here we customize the runner to intercept calls to connect to an address "cat" which actually connects the enclave application to 
/// stdin and stdout of `cat` process.

struct CatService {
   c : Arc<Mutex<Child>>
}
impl CatService {
   fn new() -> Result<CatService, std::io::Error> {
        Command::new("/bin/cat")
            .stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .map(|c| Arc::new(Mutex::new(c)))
            .map(|c| CatService {c})
   }
}
impl SyncStream for CatService {

    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        self.c.lock().unwrap().stdout.as_mut().expect("failed to get stdout").read(buf)
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        self.c.lock().unwrap().stdin.as_mut().expect("failed to get stdin").write(buf)
    }

    fn flush(&self) -> IoResult<()> {
        self.c.lock().unwrap().stdin.as_mut().expect("failed to get stdin").flush()
    }
}

#[derive(Debug)]
struct ExternalService;
impl UsercallExtension for ExternalService {
    fn connect_stream(
        &self,
        addr: &[u8],
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<SyncStream>>> {
        let name = String::from_utf8(addr.to_vec()).map_err(|_| IoErrorKind::ConnectionRefused)?;
        // If the passed address is not "cat", we return none, whereby the passed address gets treated as 
        // an IP address which is the default behavior.
        match &*name {
           "cat" => { 
               let stream = CatService::new()?;
               if let Some(local_addr) = local_addr {
                   local_addr.push_str("None");
               }
               if let Some(peer_addr) = peer_addr {
                   peer_addr.push_str("None");
               }
               Ok(Some(stream.into()))
           },
           _ => Ok(None)
        }
   }
}


fn usage(name : String) {
     println!("Usage:\n{} <path_to_sgxs_file>", name);
}

fn parse_args() -> Result<String, ()>
{
    let args: Vec<String> = std::env::args().collect();
    match args.len() {
        2 => Ok(args[1].parse().map_err(|_| ())?),
        _ => {
            usage(args[0].parse().map_err(|_| ())?);
            Err(())
        }
    }
}


fn main() {

    let file = parse_args().unwrap();

    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(AesmClient::new())
        .build();

    let mut enclave_builder = EnclaveBuilder::new(file.as_ref());
    enclave_builder.dummy_signature(); 
    enclave_builder.usercall_ext(ExternalService.into());


    let enclave = enclave_builder.build(&mut device).unwrap();

    enclave.run().map_err(|e| {
        println!("Error while executing SGX enclave.\n{}", e);
        std::process::exit(-1)
    }).unwrap();
}
