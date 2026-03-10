use anyhow::{bail, Context, Result};
use std::fmt;
use std::fs;
use std::path::Path;

const EIF_MAGIC: &[u8; 4] = b".eif";
const HEADER_SIZE: usize = 0x224;
const MAX_NUM_SECTIONS: usize = 32;

// Section types (from aws-nitro-enclaves-image-format)
const SECTION_KERNEL: u16 = 1;
const SECTION_CMDLINE: u16 = 2;
const SECTION_RAMDISK: u16 = 3;
const SECTION_SIGNATURE: u16 = 4;
const SECTION_METADATA: u16 = 5;

fn section_type_name(t: u16) -> &'static str {
    match t {
        SECTION_KERNEL => "Kernel",
        SECTION_CMDLINE => "Cmdline",
        SECTION_RAMDISK => "Ramdisk",
        SECTION_SIGNATURE => "Signature",
        SECTION_METADATA => "Metadata",
        _ => "Unknown",
    }
}

#[derive(Debug)]
pub struct EifSection {
    pub section_type: u16,
    pub flags: u16,
    pub data: Vec<u8>,
}

impl fmt::Display for EifSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<12} flags={:#06x}  size={}",
            section_type_name(self.section_type),
            self.flags,
            format_size(self.data.len()),
        )
    }
}

#[derive(Debug)]
pub struct EifFile {
    pub version: u16,
    pub flags: u16,
    pub default_mem: u64,
    pub default_cpus: u64,
    pub sections: Vec<EifSection>,
}

impl EifFile {
    pub fn kernel(&self) -> Option<&EifSection> {
        self.sections.iter().find(|s| s.section_type == SECTION_KERNEL)
    }

    pub fn cmdline(&self) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| s.section_type == SECTION_CMDLINE)
            .and_then(|s| {
                let data = if s.data.last() == Some(&0) {
                    &s.data[..s.data.len() - 1]
                } else {
                    &s.data
                };
                std::str::from_utf8(data).ok()
            })
    }

    pub fn ramdisks(&self) -> Vec<&EifSection> {
        self.sections.iter().filter(|s| s.section_type == SECTION_RAMDISK).collect()
    }

    pub fn metadata(&self) -> Option<&str> {
        self.sections
            .iter()
            .find(|s| s.section_type == SECTION_METADATA)
            .and_then(|s| std::str::from_utf8(&s.data).ok())
    }

    pub fn print_summary(&self) {
        println!("EIF version: {}", self.version);
        println!("Flags:       {:#06x}", self.flags);
        println!("Default mem: {} bytes", self.default_mem);
        println!("Default CPUs: {}", self.default_cpus);
        println!("Sections:    {}", self.sections.len());
        println!();
        for (i, section) in self.sections.iter().enumerate() {
            println!("  [{}] {}", i, section);
        }
        if let Some(cmdline) = self.cmdline() {
            println!();
            println!("Cmdline: {}", cmdline);
        }
        if let Some(metadata) = self.metadata() {
            println!();
            println!("Metadata: {}", metadata);
        }
    }
}

fn read_u16_be(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64_be(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MiB ({} bytes)", bytes as f64 / (1024.0 * 1024.0), bytes)
    } else if bytes >= 1024 {
        format!("{:.1} KiB ({} bytes)", bytes as f64 / 1024.0, bytes)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Parse an EIF file from disk.
pub fn parse_eif(path: &Path) -> Result<EifFile> {
    let data = fs::read(path).with_context(|| format!("Failed to read EIF file: {}", path.display()))?;

    if data.len() < HEADER_SIZE {
        bail!("File too small to be a valid EIF ({} bytes, need at least {})", data.len(), HEADER_SIZE);
    }

    // Verify magic
    if &data[0..4] != EIF_MAGIC {
        bail!(
            "Invalid EIF magic: expected {:?}, got {:?}",
            EIF_MAGIC,
            &data[0..4]
        );
    }

    let version = read_u16_be(&data, 0x04);
    let flags = read_u16_be(&data, 0x06);
    let default_mem = read_u64_be(&data, 0x08);
    let default_cpus = read_u64_be(&data, 0x10);
    let num_sections = read_u32_be(&data, 0x18) as usize;

    if num_sections > MAX_NUM_SECTIONS {
        bail!("Too many sections: {} (max {})", num_sections, MAX_NUM_SECTIONS);
    }

    // Read section offsets from header
    let mut section_offsets = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let offset = read_u64_be(&data, 0x1C + i * 8) as usize;
        section_offsets.push(offset);
    }

    // Parse each section at its offset
    let mut sections = Vec::with_capacity(num_sections);
    for (i, &offset) in section_offsets.iter().enumerate() {
        if offset + 12 > data.len() {
            bail!("Section {} offset {:#x} exceeds file size {:#x}", i, offset, data.len());
        }

        let section_type = read_u16_be(&data, offset);
        let section_flags = read_u16_be(&data, offset + 2);
        let section_size = read_u64_be(&data, offset + 4) as usize;

        let data_start = offset + 12; // 2 + 2 + 8 = 12 byte section header
        let data_end = data_start + section_size;

        if data_end > data.len() {
            bail!(
                "Section {} data ({:#x}..{:#x}) exceeds file size {:#x}",
                i, data_start, data_end, data.len()
            );
        }

        sections.push(EifSection {
            section_type,
            flags: section_flags,
            data: data[data_start..data_end].to_vec(),
        });
    }

    Ok(EifFile {
        version,
        flags,
        default_mem,
        default_cpus,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_eif_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../out/nitro.eif")
    }

    #[test]
    fn test_parse_eif_header() {
        let path = test_eif_path();
        if !path.exists() {
            eprintln!("Skipping test: {} not found", path.display());
            return;
        }

        let eif = parse_eif(&path).expect("Failed to parse EIF");
        assert_eq!(eif.version, 4);
        assert!(eif.sections.len() >= 3, "Expected at least 3 sections, got {}", eif.sections.len());
    }

    #[test]
    fn test_parse_eif_sections() {
        let path = test_eif_path();
        if !path.exists() {
            return;
        }

        let eif = parse_eif(&path).expect("Failed to parse EIF");

        // Should have a kernel section
        assert!(eif.kernel().is_some(), "Missing kernel section");
        let kernel = eif.kernel().unwrap();
        assert!(kernel.data.len() > 1024, "Kernel too small: {} bytes", kernel.data.len());

        // Should have cmdline
        let cmdline = eif.cmdline().expect("Missing cmdline section");
        assert!(cmdline.contains("console=ttyS0"), "Cmdline doesn't contain expected content: {}", cmdline);
        assert!(cmdline.contains("nit.target=/run.sh"), "Cmdline missing nit.target");

        // Should have at least one ramdisk
        let ramdisks = eif.ramdisks();
        assert!(!ramdisks.is_empty(), "Missing ramdisk section");
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0u8; HEADER_SIZE + 100];
        let tmp = std::env::temp_dir().join("test_bad_eif");
        fs::write(&tmp, &data).unwrap();
        let result = parse_eif(&tmp);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid EIF magic"));
        let _ = fs::remove_file(&tmp);
    }
}
