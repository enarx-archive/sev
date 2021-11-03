// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

mod ioctl;

use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};

use super::*;
use linux::ioctl::*;

/// A handle to the SEV guest platform.
pub struct GuestFirmware(File);

impl GuestFirmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<GuestFirmware> {
        Ok(GuestFirmware(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")?,
        ))
    }

    /// Get the attestation report.
    pub fn get_report(
        &mut self,
        req: SnpGuestReqInput,
    ) -> Result<SnpReportResponse, Indeterminate<Error>> {
        let mut info = SnpReportResponse::default();

        SNP_GET_REPORT.ioctl(&mut self.0, &mut GuestRequest::from(&mut info, &req))?;

        Ok(info)
    }
}

impl AsRawFd for GuestFirmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
