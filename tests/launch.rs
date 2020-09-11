// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

use sev::certs::Chain;
use sev::firmware::Firmware;
use sev::launch::{HeaderFlags, Launcher, Policy};
use sev::session::Session;

use sev::Generation;

use codicon::Decoder;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};
use mmarinus::{perms, Kind, Map};
use serial_test::serial;
use sev_cache::{Cache, FileLock};

use std::convert::TryFrom;
use std::io::Result;

const CODE: &[u8] = &[
    0xf4, // hlt
];

fn __get_cert_chain(sev: &mut Firmware) -> Chain {
    let mut platform = sev.pdh_cert_export().unwrap();

    let id = sev.get_identifer().unwrap();
    let url = format!("https://kdsintf.amd.com/cek/id/{}", id);

    let mut resp = reqwest::blocking::get(&url)
        .unwrap()
        .error_for_status()
        .unwrap();

    let mut cek = vec![];
    let _ = resp.copy_to(&mut cek).unwrap();
    platform.cek = sev::certs::sev::Certificate::decode(&mut &cek[..], ()).unwrap();

    let ca = Generation::try_from(&platform).unwrap().into();

    Chain { sev: platform, ca }
}

fn get_cert_chain(sev: &mut Firmware) -> (Chain, FileLock) {
    let cache = sev_cache::User::new().unwrap();

    let cached_chain: Result<(Chain, FileLock)> = cache
        .read_lock()
        .and_then(|mut f| Chain::decode(&mut f.file, ()))
        .or_else(|_| {
            use codicon::Encoder;

            let mut lock = cache.create().unwrap();
            let chain = __get_cert_chain(sev);
            chain.encode(&mut lock.file, ()).unwrap();

            Ok(chain)
        })
        .and_then(|_| {
            let mut lock = cache.read_lock().unwrap();
            let chain = Chain::decode(&mut lock.file, ()).unwrap();

            Ok((chain, lock))
        });

    cached_chain.unwrap()
}

#[cfg_attr(not(has_sev), ignore)]
#[test]
#[serial]
fn sev() {
    let mut sev = Firmware::open().unwrap();
    let build = sev.platform_status().unwrap().build;
    let (chain, _lock) = get_cert_chain(&mut sev);

    let policy = Policy::default();
    let session = Session::try_from(policy).unwrap();
    let start = session.start(chain).unwrap();

    let kvm = Kvm::new().unwrap();
    let mut vm = kvm.create_vm().unwrap();

    const MEM_SIZE: usize = 0x1000;
    let address_space = Map::map(MEM_SIZE)
        .anywhere()
        .anonymously()
        .known::<perms::ReadWrite>(Kind::Private)
        .unwrap();

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
        flags: 0,
    };

    unsafe {
        vm.set_user_memory_region(mem_region).unwrap();
    }

    let mut session = session.measure().unwrap();
    session.update_data(address_space.as_ref()).unwrap();

    let (mut launcher, measurement) = {
        let launcher = Launcher::new(&mut vm, &mut sev).unwrap();
        let mut launcher = launcher.start(start).unwrap();
        launcher.update_data(address_space.as_ref()).unwrap();
        let launcher = launcher.measure().unwrap();
        let measurement = launcher.measurement();
        (launcher, measurement)
    };

    let session = session.verify(build, measurement).unwrap();
    let secret = session.secret(HeaderFlags::default(), CODE).unwrap();

    launcher.inject(secret, address_space.addr()).unwrap();

    let _handle = launcher.finish().unwrap();

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = std::ptr::null() as *const u64 as u64;
    regs.rflags = 2;
    vcpu.set_regs(&regs).unwrap();

    loop {
        match vcpu.run().unwrap() {
            VcpuExit::Hlt => break,
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }
}
