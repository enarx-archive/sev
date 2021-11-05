// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

#[cfg(target_os = "linux")]
mod linux;
mod types;

use super::*;
use std::fmt::Debug;

#[cfg(target_os = "linux")]
pub use linux::GuestFirmware;
pub use types::SnpGetReport;

use bitflags::bitflags;

/// Send a request to SNP_GET_REPORT.
#[repr(C)]
pub struct SnpReportRequest {
    /// Message version number (must be non-zero).
    pub msg_version: u8,

    /// User data to be included in the report.
    pub user_data: [u8; 64],
}

/// Response from SNP guest firmware containing the attestation report.
#[derive(Debug)]
#[repr(C)]
pub struct SnpReportResponse {
    /// Status of the SNP platform.
    pub status: u32,

    /// Size of the report.
    pub size: u32,

    /// Reserved space.
    pub rsvd: [u8; 18],

    /// SNP attestation report.
    pub report: SnpGetReport,

    /// Certificate data to be included with the attestation report.
    pub certs_data: [u8; 3476],
}

impl Default for SnpReportResponse {
    fn default() -> Self {
        Self {
            status: 0,
            size: 0,
            rsvd: [0; 18],
            report: SnpGetReport::default(),
            certs_data: [0; 3476],
        }
    }
}

bitflags! {
    /// Bitmask indicating which data will be mixed into the derived key.
    #[derive(Default, Deserialize, Serialize)]
    pub struct GuestFieldSelect: u64 {
        /// Indicates that the guest policy will be mixed into the key.
        const GUEST_POLICY = 0b00000001u64.to_le();

        /// Indicates that the image ID of the guest will be mixed into the key.
        const IMAGE_ID = 0b00000010u64.to_le();

        /// Indicates the family ID of the guest will be mixed into the key.
        const FAMILY_ID = 0b00000100u64.to_le();

        /// Indicates the measurement of the guest during launch will be mixed into the key.
        const MEASUREMENT = 0b00001000u64.to_le();

        /// Indicates the guest-provided SVN will be mixed into the key.
        const GUEST_SVN = 0b00010000u64.to_le();

        /// Indicates that the guest-provided TCB version string will be mixed into the key.
        const TCB_VERSION = 0b00100000u64.to_le();
    }
}

/// Send a request to SNP_GET_DERIVED_KEY.
#[repr(C)]
pub struct SnpDerivedKeyRequest {
    /// Selects the root key to derive the key from. 0 indicates VCEK. 1 indicates VMRK.
    pub root_key_select: u32,

    /// Reserved space.
    pub rsvd: u32,

    /// Bitmask indicating which data will be mixed into the derived key.
    /// (See Table 16 of the SNP firmware spec for the structure of this bitmask)
    pub guest_field_select: GuestFieldSelect,

    /// The VMPL to mix into the derived key. Must be greater than or equal to the current VMPL.
    pub vmpl: u32,

    /// The guest SVN to mix into the key. Must not exceed the guest SVN provided at launch.
    pub guest_svn: u32,

    /// The TCB version to mix into the derived key. Must not exceed the current TCB version
    pub tcb_version: TcbVersion,
}

/// Response from SNP guest firmware containing the attestation report.
#[derive(Debug, Default)]
#[repr(C)]
pub struct SnpDerivedKeyResponse {
    /// Status of the platform.
    pub status: u32,

    /// Reserved space.
    pub rsvd: [u8; 28],

    /// Derived key.
    pub key: [u8; 32],
}

/// Send a request to SNP_GET_DERIVED_KEY.
#[repr(C)]
pub struct SnpDerivedKeyRequestHeader {
    /// Status of the platform.
    pub msg_version: u8,

    /// The derived key request data.
    pub req: SnpDerivedKeyRequest,
}
