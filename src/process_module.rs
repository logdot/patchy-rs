use windows::Win32::System::LibraryLoader::GetModuleHandleW;

use crate::PatchError;

/// A loaded module in the current process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessModule {
    base: usize,
}

impl ProcessModule {
    /// Finds the main executable module in the current process.
    pub fn main() -> Result<Self, PatchError> {
        // SAFETY: A null module name asks Windows for the current executable
        // and imposes no additional caller requirements.
        let module = unsafe { GetModuleHandleW(None) }
            .map_err(|error| PatchError::ModuleLookup(error.to_string()))?;
        Ok(Self {
            base: module.0 as usize,
        })
    }

    /// Creates a module descriptor from a known runtime base address.
    ///
    /// This does not validate that a module is loaded at `base`.
    pub const fn from_base(base: usize) -> Self {
        Self { base }
    }

    /// Returns the module's runtime base address.
    pub const fn base_address(self) -> usize {
        self.base
    }

    /// Resolves a relative virtual address against this module.
    pub fn resolve_rva(self, rva: usize) -> Result<usize, PatchError> {
        self.base
            .checked_add(rva)
            .ok_or(PatchError::AddressOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rvas_are_resolved_with_checked_arithmetic() {
        let module = ProcessModule::from_base(0x140000000);

        assert_eq!(module.resolve_rva(0x36bb5).unwrap(), 0x140036bb5);
        assert!(ProcessModule::from_base(usize::MAX).resolve_rva(1).is_err());
    }
}
