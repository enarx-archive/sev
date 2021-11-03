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

/// Send a request to the SNP guest firmware.
#[repr(C)]
pub struct SnpGuestReqInput {
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
