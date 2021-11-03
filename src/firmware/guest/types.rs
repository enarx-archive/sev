// SPDX-License-Identifier: Apache-2.0

use crate::firmware::TcbVersion;
use crate::launch::sev::Measurement;
use crate::launch::snp::Policy;
use crate::Version;

/// SNP guest attestation report data.
#[derive(Debug)]
#[repr(C)]
pub struct SnpGetReport {
    /// Version number.
    pub version: Version,

    /// Security Version Number of the SNP firmware.
    pub guest_svn: u32,

    /// Guest policy.
    pub policy: Policy,

    /// Family ID of the guest.
    pub family_id: [u8; 16],

    /// Image ID of the guest.
    pub image_id: [u8; 16],

    /// VM Permission Level.
    pub vmpl: u32,

    /// Signature algorithm used to sign this report.
    pub sig_algo: u32,

    /// Platform version.
    pub platform_version: TcbVersion,

    /// Information about the platform.
    pub plat_info: u64,

    /// Indicates that the author key is present in the ID authentication information structure.
    pub auth_key_en: u32,

    /// Reserved space.
    pub rsvd1: u32,

    /// Guest-provided data (from the "user_data" value of the SNP request struct).
    pub report_data: [u8; 64],

    /// Guest measurement calculated at launch.
    pub measurement: Measurement,

    /// Data provided to the hypervisor at launch.
    pub host_data: [u8; 32],

    /// SHA-384 digest of the ID public key that signed the ID block provided in
    /// SNP_LAUNCH_FINISH.
    pub id_key_digest: [u8; 48],

    /// SHA-384 digest of the Author public key that certified the ID key, if provided in
    /// SNP_LAUNCH_FINISH. Zeroes if AUTHOR_KEY_EN is 1.
    pub author_key_digest: [u8; 48],

    /// Report ID of the guest.
    pub report_id: [u8; 32],

    /// Report ID of the guest's migration agent.
    pub report_id_ma: [u8; 32],

    /// Reported TCB version used to derive the VCEK that signed this report.
    pub reported_tcb: TcbVersion,

    /// Reserved space.
    pub rsvd2: [u8; 78],

    /// If MaskChipID is set to 0, Identifier unique to the chip. Otherwise, set to 0x0.
    pub chip_id: [u8; 64],
}

impl Default for SnpGetReport {
    fn default() -> Self {
        Self {
            version: Version::default(),
            guest_svn: 0,
            policy: Policy::default(),
            family_id: [0; 16],
            image_id: [0; 16],
            vmpl: 0,
            sig_algo: 0,
            platform_version: TcbVersion::default(),
            plat_info: 0,
            auth_key_en: 0,
            rsvd1: 0,
            report_data: [0; 64],
            measurement: Measurement::default(),
            host_data: [0; 32],
            id_key_digest: [0; 48],
            author_key_digest: [0; 48],
            report_id: [0; 32],
            report_id_ma: [0; 32],
            reported_tcb: TcbVersion::default(),
            rsvd2: [0; 78],
            chip_id: [0; 64],
        }
    }
}
