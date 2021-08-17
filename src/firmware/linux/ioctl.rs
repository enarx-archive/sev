// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the AMD Secure Encrypted Virtualization
//! (SEV) platform. These ioctls are exported by the Linux kernel.

use crate::firmware::types::*;

use iocuddle::*;
use sev_iocuddle::impl_const_id;
use sev_iocuddle::sev::{Command, Id, SEV};

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;
    PlatformReset = 0,
    PlatformStatus = 1,
    PekGen = 2,
    PekCsr<'_> = 3,
    PdhGen = 4,
    PdhCertExport<'_> = 5,
    PekCertImport<'_> = 6,
    GetId<'_> = 8, /* GET_ID2 is 8, the deprecated GET_ID ioctl is 7 */
}

/// Resets the SEV platform's persistent state.
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { SEV.write_read(0) };
/// Gathers a status report from the SEV firmware.
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { SEV.write_read(0) };
/// Generate a new Platform Endorsement Key (PEK).
pub const PEK_GEN: Ioctl<WriteRead, &Command<PekGen>> = unsafe { SEV.write_read(0) };
/// Take ownership of the platform.
pub const PEK_CSR: Ioctl<WriteRead, &Command<PekCsr<'_>>> = unsafe { SEV.write_read(0) };
/// (Re)generate the Platform Diffie-Hellman (PDH).
pub const PDH_GEN: Ioctl<WriteRead, &Command<PdhGen>> = unsafe { SEV.write_read(0) };
/// Retrieve the PDH and the platform certificate chain.
pub const PDH_CERT_EXPORT: Ioctl<WriteRead, &Command<PdhCertExport<'_>>> =
    unsafe { SEV.write_read(0) };
/// Join the platform to the domain.
pub const PEK_CERT_IMPORT: Ioctl<WriteRead, &Command<PekCertImport<'_>>> =
    unsafe { SEV.write_read(0) };
/// Get the CPU's unique ID that can be used for getting a certificate for the CEK public key.
pub const GET_ID: Ioctl<WriteRead, &Command<GetId<'_>>> = unsafe { SEV.write_read(0) };
