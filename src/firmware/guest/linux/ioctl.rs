// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use crate::firmware::guest::*;
use crate::impl_const_id;

use iocuddle::*;

use std::marker::PhantomData;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;

    SnpReportResponse = 0,
    SnpDerivedKeyResponse = 1,
}

impl_const_id! {
    pub ReqId => u32;

    SnpReportRequest = 0,
    SnpDerivedKeyRequestHeader = 1,
}

const SEV_GUEST: Group = Group::new(b'S');

/// Get the SNP guest attestation report.
pub const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequest<SnpReportResponse, SnpReportRequest>> =
    unsafe { SEV_GUEST.write_read(0x0) };

/// Get the SNP derived key.
pub const SNP_GET_DERIVED_KEY: Ioctl<
    WriteRead,
    &GuestRequest<SnpDerivedKeyResponse, SnpDerivedKeyRequestHeader>,
> = unsafe { SEV_GUEST.write_read(0x1) };

#[repr(C)]
pub struct GuestRequest<'a, T: Id, V: ReqId> {
    req: u64,
    resp: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
    _phantom2: PhantomData<&'a V>,
}

impl<'a, T: Id, V: ReqId> GuestRequest<'a, T, V> {
    pub fn from(subcmd: &'a mut T, req: &'a V) -> Self {
        GuestRequest {
            req: req as *const V as u64,
            resp: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
            _phantom2: PhantomData,
        }
    }
}
