// Axel '0vercl0k' Souchet - June 5 2023
//! This defines a [`Pxe`] type that makes it easy to go from a [`u64`] to
//! a [`Pxe`] and vice-versa. It also makes it easy to grab the flag bits
//! off a [`Pxe`].
//!
//! # Examples
//!
//! ```
//! # use rp_bf::pxe::{Pxe, PxeFlags};
//! let pxe = Pxe::new(
//!     0x6d600,
//!     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present
//! );
//! let encoded = u64::from(pxe);
//! let decoded = Pxe::from(encoded);
//! ```
use bitflags::bitflags;

bitflags! {
    /// The various bits and flags that a [`Pxe`] has.
    #[derive(Debug, Copy, Clone, Default, PartialEq)]
    pub struct PxeFlags : u64 {
        const Present = 1 << 0;
        const Writable = 1 << 1;
        const UserAccessible = 1 << 2;
        const WriteThrough = 1 << 3;
        const CacheDisabled = 1 << 4;
        const Accessed = 1 << 5;
        const Dirty = 1 << 6;
        const LargePage = 1 << 7;
        const NoExecute = 1 << 63;
    }
}

/// A [`Pxe`] is a set of flags ([`PxeFlags`]) and a Page Frame Number (PFN).
/// This representation takes more space than a regular `PXE` but it is more
/// convenient to split the flags / the pfn as [`bitflags!`] doesn't seem to
/// support bitfields.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub struct Pxe {
    /// The PFN of the next table or the final page.
    pub pfn: u64,
    /// PXE flags.
    pub flags: PxeFlags,
}

impl Pxe {
    /// Create a [`Pxe`] from a `pfn` and a set of `flags`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # fn main() {
    /// let pxe = Pxe::new(
    ///     0x6d600,
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present
    /// );
    /// assert_eq!(pxe.pfn, 0x6d600);
    /// # }
    /// ```
    pub fn new(pfn: u64, flags: PxeFlags) -> Self {
        Self { pfn, flags }
    }

    /// Is the bit Present/Valid turned on?
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # fn main() {
    /// let p = Pxe::new(
    ///     0x6d600,
    ///     PxeFlags::Present
    /// );
    /// assert_eq!(p.present(), true);
    /// let np = Pxe::new(
    ///     0x1337,
    ///     PxeFlags::UserAccessible
    /// );
    /// assert_eq!(np.present(), false);
    /// # }
    /// ```
    pub fn present(&self) -> bool {
        self.flags.contains(PxeFlags::Present)
    }
}

/// Convert a [`u64`] into a [`Pxe`].
impl From<u64> for Pxe {
    /// Create a [`u64`] from a [`Pxe`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # fn main() {
    /// let pxe = Pxe::from(0x6D_60_00_25);
    /// assert_eq!(pxe.pfn, 0x6d600);
    /// assert_eq!(pxe.flags, PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present);
    /// # }
    /// ```
    fn from(value: u64) -> Self {
        let pfn = (value >> 12) & 0xf_ffff_ffff;
        let flags = PxeFlags::from_bits(value & PxeFlags::all().bits()).expect("PxeFlags");
        Self::new(pfn, flags)
    }
}

/// Convert a [`Pxe`] into a [`u64`].
impl From<Pxe> for u64 {
    /// Create a [`u64`] from a [`Pxe`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # fn main() {
    /// let pxe = Pxe::new(
    ///     0x6d600,
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present,
    /// );
    /// assert_eq!(u64::from(pxe), 0x6D_60_00_25);
    /// # }
    /// ```
    fn from(pxe: Pxe) -> Self {
        debug_assert!(pxe.pfn <= 0xf_ffff_ffff);
        pxe.flags.bits() | (pxe.pfn << 12u64)
    }
}
