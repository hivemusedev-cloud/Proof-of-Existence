//! The Windows DPAPI backend (PoE OS Phase 1).
//!
//! Custody: the node's three protocol secrets live as files in
//! a `dpapi/` subdirectory of the node directory — the same
//! items and formats as the file backend — but every file's
//! contents are protected with DPAPI (`CryptProtectData`,
//! user scope): the blobs can only be unprotected by the same
//! Windows user account on the same machine. That is the
//! Windows app-mode store behind the vault trait, the
//! counterpart of the Secret Service keyring on Linux and the
//! Keychain on macOS.
//!
//! The honest limit is the same as the keyring's: DPAPI does
//! not sign ML-DSA or XMSS internally, so key material enters
//! process memory at sign time. What DPAPI buys is custody at
//! rest — a copied data directory is useless without the
//! user's Windows logon — not hardware custody.
//! `mainnet_eligible` is therefore false, like every
//! software-store backend.
//!
//! Persist-before-release holds exactly as with the file
//! backend: the XMSS state is re-protected and written before
//! any signature leaves `sign_xmss` (through
//! `XmssKey::sign_persistent_with`).

use std::path::{Path, PathBuf};

use poe_crypto::hash::H512;
use poe_crypto::pq::DsaKeypair;
use poe_crypto::tickets::TicketChain;
use poe_crypto::xmss::{H32, XmssKey, XmssSignature};
use poe_identity::device_id;
use rand::rngs::ThreadRng;
use rand::RngCore;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

use crate::{hex_decode, hex_encode, KeyVault, VaultError};

fn protect(data: &[u8]) -> Result<Vec<u8>, VaultError> {
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptProtectData(
            &input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(VaultError::Store(format!(
            "DPAPI CryptProtectData failed (error {})",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )));
    }
    let blob = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut std::ffi::c_void);
    }
    Ok(blob)
}

fn unprotect(blob: &[u8]) -> Result<Vec<u8>, VaultError> {
    let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        return Err(VaultError::Store(format!(
            "DPAPI CryptUnprotectData failed (error {}) — the blob belongs to another user or machine, or is corrupt",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
        )));
    }
    let data = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut std::ffi::c_void);
    }
    Ok(data)
}

/// The DPAPI backend: protocol keys as DPAPI-protected files
/// under `<dir>/dpapi/`. Selected with `POE_VAULT=dpapi` on
/// Windows. A DPAPI vault is a different identity from the
/// same directory's plain file keys — switching backends is
/// an operator migration, as with every backend.
pub struct DpapiVault {
    device: DsaKeypair,
    machine: u64,
    chain: TicketChain,
    xmss: XmssKey,
    xmss_path: PathBuf,
    rng: ThreadRng,
}

impl DpapiVault {
    pub fn load_or_create(
        dir: &Path,
        rng: &mut ThreadRng,
        chain_len: usize,
        xmss_height: u32,
    ) -> Result<DpapiVault, VaultError> {
        let vdir = dir.join("dpapi");
        std::fs::create_dir_all(&vdir)?;

        let dev_path = vdir.join("device.key");
        let device = if dev_path.exists() {
            let plain = unprotect(&std::fs::read(&dev_path)?)?;
            let text = String::from_utf8(plain).map_err(|_| VaultError::BadDeviceKey)?;
            let mut lines = text.lines();
            let pk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
            let sk = hex_decode(lines.next().unwrap_or("")).ok_or(VaultError::BadDeviceKey)?;
            DsaKeypair::from_key_bytes(&pk, &sk).ok_or(VaultError::BadDeviceKey)?
        } else {
            let kp = DsaKeypair::generate(rng);
            let text = format!(
                "{}\n{}\n",
                hex_encode(&kp.public_key_bytes()),
                hex_encode(&kp.secret_key_bytes())
            );
            std::fs::write(&dev_path, protect(text.as_bytes())?)?;
            kp
        };
        let machine = device_id(&device.public_key_bytes());

        let chain_path = vdir.join("ticket.seed");
        let chain = if chain_path.exists() {
            let seed = unprotect(&std::fs::read(&chain_path)?)?;
            TicketChain::new(&seed, chain_len)
        } else {
            let mut seed = vec![0u8; 32];
            rng.fill_bytes(&mut seed);
            std::fs::write(&chain_path, protect(&seed)?)?;
            TicketChain::new(&seed, chain_len)
        };

        let xmss_path = vdir.join("xmss.key");
        let xmss = if xmss_path.exists() {
            let state = unprotect(&std::fs::read(&xmss_path)?)?;
            XmssKey::from_state_bytes(&state)?
        } else {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            let key = XmssKey::generate(seed, xmss_height);
            std::fs::write(&xmss_path, protect(&key.state_bytes())?)?;
            key
        };
        Ok(DpapiVault { device, machine, chain, xmss, xmss_path, rng: rand::thread_rng() })
    }
}

impl KeyVault for DpapiVault {
    fn machine(&self) -> u64 {
        self.machine
    }

    fn device_public_key(&self) -> Vec<u8> {
        self.device.public_key_bytes()
    }

    fn sign_device(&mut self, msg: &[u8]) -> Vec<u8> {
        self.device.sign(&mut self.rng, msg)
    }

    fn xmss_root(&self) -> H32 {
        self.xmss.root()
    }

    fn xmss_next_index(&self) -> u64 {
        self.xmss.next_index()
    }

    fn sign_xmss(&mut self, msg: &[u8]) -> Result<XmssSignature, VaultError> {
        let path = self.xmss_path.clone();
        let mut persist = |bytes: &[u8]| -> Result<(), poe_crypto::xmss::XmssError> {
            let blob = protect(bytes).map_err(|e| {
                poe_crypto::xmss::XmssError::Io(std::io::Error::other(e.to_string()))
            })?;
            std::fs::write(&path, blob)?;
            Ok(())
        };
        Ok(self.xmss.sign_persistent_with(&mut persist, msg)?)
    }

    fn chain_commitment(&self) -> H512 {
        self.chain.commitment()
    }

    fn chain_reveal(&self, step: usize) -> H512 {
        self.chain.reveal(step)
    }

    fn backend_name(&self) -> &'static str {
        "Windows DPAPI"
    }

    fn mainnet_eligible(&self) -> bool {
        false
    }
}
