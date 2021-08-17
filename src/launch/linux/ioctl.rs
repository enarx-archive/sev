// SPDX-License-Identifier: Apache-2.0

use crate::kvm::types::*;
use iocuddle::*;

use sev_iocuddle::impl_const_id;
use sev_iocuddle::kvm::*;
use sev_iocuddle::sev::Id;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    pub Id => u32;
    Init = 0,
    LaunchStart<'_> = 2,
    LaunchUpdateData<'_> = 3,
    LaunchSecret<'_> = 5,
    LaunchMeasure<'_> = 6,
    LaunchFinish = 7,
}

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the SEV platform context.
pub const INIT: Ioctl<WriteRead, &Command<Init>> = unsafe { ENC_OP.lie() };

/// Create encrypted guest context.
pub const LAUNCH_START: Ioctl<WriteRead, &Command<LaunchStart>> = unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK.
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<LaunchUpdateData>> =
    unsafe { ENC_OP.lie() };

/// Inject a secret into the guest.
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<LaunchSecret>> = unsafe { ENC_OP.lie() };

/// Get the guest's measurement.
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<LaunchMeasure>> = unsafe { ENC_OP.lie() };

/// Complete the SEV launch flow and transition the guest into
/// the ready state.
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<LaunchFinish>> = unsafe { ENC_OP.lie() };
