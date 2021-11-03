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
}

const SEV_GUEST: Group = Group::new(b'S');

/// Get the SNP guest attestation report.
pub const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequest<SnpReportResponse>> =
    unsafe { SEV_GUEST.write_read(0x0) };

#[repr(C)]
pub struct GuestRequest<'a, T: Id> {
    req: u64,
    resp: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> GuestRequest<'a, T> {
    pub fn from(subcmd: &'a mut T, req: &SnpGuestReqInput) -> Self {
        GuestRequest {
            req: req as *const _ as u64,
            resp: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
