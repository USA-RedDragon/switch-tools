//! NPDM (`main.npdm`): the program's process parameters and the services it
//! may use.

use crate::bytes::{slice, u8_at, u32_at, u64_at};
use crate::error::{Result, malformed};

/// The process address space an NPDM asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressSpace {
    /// 32-bit.
    As32Bit,
    /// 36-bit (old 64-bit layout).
    As64BitOld,
    /// 32-bit without the reserved region.
    As32BitNoReserved,
    /// 39-bit.
    As64Bit,
}

impl AddressSpace {
    /// A lowercase name.
    pub fn name(self) -> &'static str {
        match self {
            AddressSpace::As32Bit => "32-bit",
            AddressSpace::As64BitOld => "36-bit",
            AddressSpace::As32BitNoReserved => "32-bit-no-reserved",
            AddressSpace::As64Bit => "39-bit",
        }
    }
}

/// One service-access entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Service {
    /// The service name (may end in `*` as a wildcard).
    pub name: String,
    /// Whether the program hosts it rather than uses it.
    pub is_server: bool,
}

/// A parsed NPDM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Npdm {
    /// The program name in the header.
    pub name: String,
    /// The product code.
    pub product_code: String,
    /// Whether the program is 64-bit code.
    pub is_64bit: bool,
    /// The address space type.
    pub address_space: AddressSpace,
    /// The main thread priority.
    pub main_thread_priority: u8,
    /// The main thread's default core.
    pub main_thread_core: u8,
    /// The main thread stack size.
    pub main_thread_stack_size: u32,
    /// The system resource size.
    pub system_resource_size: u32,
    /// The NPDM version.
    pub version: u32,
    /// The program ID in ACI0.
    pub program_id: u64,
    /// The services the program may use or host, in file order.
    pub services: Vec<Service>,
}

fn text(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl Npdm {
    /// Parse an NPDM.
    ///
    /// # Errors
    ///
    /// Bad META or ACI0 magic, or a region past the end.
    pub fn parse(b: &[u8]) -> Result<Npdm> {
        if b.get(..4) != Some(b"META") {
            return malformed("NPDM: bad META magic");
        }
        let flags = u8_at(b, 0xC, "META")?;
        let address_space = match (flags >> 1) & 7 {
            0 => AddressSpace::As32Bit,
            1 => AddressSpace::As64BitOld,
            2 => AddressSpace::As32BitNoReserved,
            3 => AddressSpace::As64Bit,
            t => return malformed(format!("NPDM: address space type {t}")),
        };
        let aci_off = u32_at(b, 0x70, "META")? as usize;
        let aci_size = u32_at(b, 0x74, "META")? as usize;
        let aci = slice(b, aci_off, aci_size, "ACI0")?;
        if aci.get(..4) != Some(b"ACI0") {
            return malformed("NPDM: bad ACI0 magic");
        }
        let sac_off = u32_at(aci, 0x28, "ACI0")? as usize;
        let sac_size = u32_at(aci, 0x2C, "ACI0")? as usize;
        let sac = slice(aci, sac_off, sac_size, "service access control")?;
        let mut services = Vec::new();
        let mut i = 0;
        while i < sac.len() {
            let control = sac[i];
            if control == 0 {
                break;
            }
            let len = usize::from(control & 7) + 1;
            let name = slice(sac, i + 1, len, "service name")?;
            services.push(Service {
                name: String::from_utf8_lossy(name).into_owned(),
                is_server: control & 0x80 != 0,
            });
            i += 1 + len;
        }
        Ok(Npdm {
            name: text(slice(b, 0x20, 0x10, "META")?),
            product_code: text(slice(b, 0x30, 0x10, "META")?),
            is_64bit: flags & 1 != 0,
            address_space,
            main_thread_priority: u8_at(b, 0xE, "META")?,
            main_thread_core: u8_at(b, 0xF, "META")?,
            main_thread_stack_size: u32_at(b, 0x1C, "META")?,
            system_resource_size: u32_at(b, 0x14, "META")?,
            version: u32_at(b, 0x18, "META")?,
            program_id: u64_at(aci, 0x10, "ACI0")?,
            services,
        })
    }
}

/// Build an NPDM (fixtures).
pub fn build(name: &str, program_id: u64, stack: u32, services: &[(&str, bool)]) -> Vec<u8> {
    let mut sac = Vec::new();
    for (s, server) in services {
        let len = s.len().clamp(1, 8);
        sac.push(u8::try_from(len - 1).unwrap_or(0) | if *server { 0x80 } else { 0 });
        sac.extend_from_slice(&s.as_bytes()[..len]);
    }
    let mut aci = vec![0u8; 0x40];
    aci[..4].copy_from_slice(b"ACI0");
    aci[0x10..0x18].copy_from_slice(&program_id.to_le_bytes());
    aci[0x28..0x2C].copy_from_slice(&0x40u32.to_le_bytes());
    aci[0x2C..0x30].copy_from_slice(&u32::try_from(sac.len()).unwrap_or(0).to_le_bytes());
    aci.extend_from_slice(&sac);
    let mut m = vec![0u8; 0x80];
    m[..4].copy_from_slice(b"META");
    m[0xC] = 1 | (3 << 1);
    m[0xE] = 44;
    m[0x1C..0x20].copy_from_slice(&stack.to_le_bytes());
    let n = name.len().min(0x10);
    m[0x20..0x20 + n].copy_from_slice(&name.as_bytes()[..n]);
    m[0x70..0x74].copy_from_slice(&0x80u32.to_le_bytes());
    m[0x74..0x78].copy_from_slice(&u32::try_from(aci.len()).unwrap_or(0).to_le_bytes());
    m.extend_from_slice(&aci);
    m
}
