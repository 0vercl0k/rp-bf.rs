// Axel '0vercl0k' Souchet - May 30 2023
//! This contains types that are useful to manipulate
//! Guest Virtual Addresses ([`Gva`]) and Guest Physical Addresses ([`Gpa`]).
//! Because ultimately they are both [`u64`] under the hood, a lot of operations
//! apply to both [`Gva`] & [`Gpa`] ([`Gxa::page_align`], etc.) and those are
//! implemented into the parent trait [`Gxa`].
//!
//! # Examples
//!
//! ```
//! use rp_bf::gxa::{Gxa, Gva};
//! let gva = Gva::new(1337);
//! let page_aligned_gva = gva.page_align();
//! let page_offset = gva.offset();
//! ```
use std::fmt::Display;

use crate::ptables::PHY_PAGE_SIZE;

/// A bunch of useful methods to manipulate 64-bit addresses of
/// any kind.
pub trait Gxa: Sized + Default + Copy + From<u64> {
    /// Get the underlying [`u64`] out of it.
    fn u64(&self) -> u64;

    /// Get the page offset.
    fn offset(&self) -> u64 {
        self.u64() & 0xf_ff
    }

    /// Is it page aligned?
    fn page_aligned(&self) -> bool {
        self.offset() == 0
    }

    /// Page-align it.
    fn page_align(&self) -> Self {
        Self::from(self.u64() & !0xfff)
    }

    /// Get the next aligned page.
    fn next_aligned_page(self) -> Self {
        Self::from(
            self.page_align()
                .u64()
                .checked_add(PHY_PAGE_SIZE as u64)
                .expect("Cannot overflow"),
        )
    }
}

/// Strong type for Guest Physical Addresses.
///
/// # Examples
///
/// ```
/// # use rp_bf::gxa::{Gxa, Gpa};
/// # fn main() {
/// let gpa = Gpa::new(0x1337_123);
/// assert_eq!(gpa.offset(), 0x123);
/// assert_eq!(gpa.page_aligned(), false);
/// let aligned_gpa = gpa.page_align();
/// assert_eq!(aligned_gpa.u64(), 0x1337_000);
/// assert_eq!(aligned_gpa.page_aligned(), true);
/// let next_gpa = gpa.next_aligned_page();
/// assert_eq!(next_gpa.u64(), 0x1338_000);
/// # }
/// ```
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq, Default)]
pub struct Gpa(u64);

impl Gpa {
    /// Create a new [`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::new(1337);
    /// # }
    /// ```
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Create a new [`Gpa`] from a Page Frame Number or PFN.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::from_pfn(0x1337);
    /// assert_eq!(gpa.u64(), 0x1337_000);
    /// # }
    /// ```
    pub const fn from_pfn(pfn: u64) -> Self {
        Self(pfn << (4 * 3))
    }

    /// Get the Page Frame Number from a [`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::new(0x1337_337);
    /// assert_eq!(gpa.pfn(), 0x1337);
    /// # }
    /// ```
    pub const fn pfn(&self) -> u64 {
        self.0 >> (4 * 3)
    }
}

impl Gxa for Gpa {
    /// Get the underlying [`u64`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::new(1337);
    /// assert_eq!(gpa.u64(), 1337);
    /// # }
    /// ```
    fn u64(&self) -> u64 {
        self.0
    }
}

/// Convert a [`u64`] into a [`Gpa`].
impl From<u64> for Gpa {
    /// Create a [`Gpa`] from a [`u64`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::from(0xdeadbeef_baadc0de);
    /// assert_eq!(u64::from(gpa), 0xdeadbeef_baadc0de);
    /// # }
    /// ```
    fn from(value: u64) -> Self {
        Gpa(value)
    }
}

/// Convert a [`Gpa`] into a [`u64`].
impl From<Gpa> for u64 {
    /// Create a [`u64`] from a [`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::new(0xdeadbeef_baadc0de);
    /// let gpa_u64: u64 = gpa.into();
    /// assert_eq!(gpa_u64, 0xdeadbeef_baadc0de);
    /// assert_eq!(u64::from(gpa), 0xdeadbeef_baadc0de);
    /// # }
    /// ```
    fn from(value: Gpa) -> Self {
        value.0
    }
}

/// Convert a [`&Gpa`][`Gpa`] into a [`u64`].
impl From<&Gpa> for u64 {
    /// Create a [`u64`] from a [`&Gpa`][`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gpa = Gpa::new(0xdeadbeef_baadc0de);
    /// let gpa_p = &gpa;
    /// let gpa_u64: u64 = gpa_p.into();
    /// assert_eq!(gpa_u64, 0xdeadbeef_baadc0de);
    /// assert_eq!(u64::from(gpa_p), 0xdeadbeef_baadc0de);
    /// # }
    /// ```
    fn from(value: &Gpa) -> Self {
        value.0
    }
}

/// Format a [`Gpa`] as a string.
impl Display for Gpa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GPA:{:#x}", self.0)
    }
}

/// Strong type for Guest Virtual Addresses.
///
/// # Examples
///
/// ```
/// # use rp_bf::gxa::{Gxa, Gva};
/// # fn main() {
/// let gva = Gva::new(0x1337_fff);
/// assert_eq!(gva.offset(), 0xfff);
/// assert_eq!(gva.page_aligned(), false);
/// let aligned_gva = gva.page_align();
/// assert_eq!(aligned_gva.u64(), 0x1337_000);
/// assert_eq!(aligned_gva.page_aligned(), true);
/// let next_gva = gva.next_aligned_page();
/// assert_eq!(next_gva.u64(), 0x1338_000);
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Gva(u64);

impl Gva {
    /// Create a new [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let gva = Gva::new(0xdeadbeef);
    /// # }
    /// ```
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Get the PTE index of the [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let first = Gva::new(0xff_ff_b9_dc_ee_77_31_37);
    /// assert_eq!(first.pte_idx(), 371);
    /// let second = Gva::new(0xff_ff_11_22_33_44_55_66);
    /// assert_eq!(second.pte_idx(), 0x45);
    /// # }
    /// ```
    #[allow(clippy::erasing_op, clippy::identity_op)]
    pub const fn pte_idx(&self) -> u64 {
        (self.0 >> (12 + (9 * 0))) & 0b1_1111_1111
    }

    /// Get the PDE index of the [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let first = Gva::new(0xff_ff_b9_dc_ee_77_31_37);
    /// assert_eq!(first.pde_idx(), 371);
    /// let second = Gva::new(0xff_ff_11_22_33_44_55_66);
    /// assert_eq!(second.pde_idx(), 0x19a);
    /// # }
    /// ```
    #[allow(clippy::identity_op)]
    pub const fn pde_idx(&self) -> u64 {
        (self.0 >> (12 + (9 * 1))) & 0b1_1111_1111
    }

    /// Get the PDPE offset of the [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let first = Gva::new(0xff_ff_b9_dc_ee_77_31_37);
    /// assert_eq!(first.pdpe_idx(), 371);
    /// let second = Gva::new(0xff_ff_11_22_33_44_55_66);
    /// assert_eq!(second.pdpe_idx(), 0x88);
    /// # }
    /// ```
    pub const fn pdpe_idx(&self) -> u64 {
        (self.0 >> (12 + (9 * 2))) & 0b1_1111_1111
    }

    /// Get the PML4 index of the [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let first = Gva::new(0xff_ff_b9_dc_ee_77_31_37);
    /// assert_eq!(first.pml4e_idx(), 371);
    /// let second = Gva::new(0xff_ff_11_22_33_44_55_66);
    /// assert_eq!(second.pml4e_idx(), 0x22);
    /// # }
    /// ```
    pub fn pml4e_idx(&self) -> u64 {
        (self.0 >> (12 + (9 * 3))) & 0b1_1111_1111
    }
}

impl Gxa for Gva {
    /// Get the underlying `u64`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let gva = Gva::new(0xdeadbeef);
    /// assert_eq!(gva.u64(), 0xdeadbeef);
    /// # }
    /// ```
    fn u64(&self) -> u64 {
        self.0
    }
}

/// Convert a [`Gva`] into a [`u64`].
impl From<u64> for Gva {
    /// Create a [`Gva`] from a [`u64`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let gva = Gva::from(0xbaadc0de_deadbeef);
    /// assert_eq!(u64::from(gva), 0xbaadc0de_deadbeef);
    /// # }
    /// ```
    fn from(value: u64) -> Self {
        Gva(value)
    }
}

/// Convert a [`Gva`] into a [`u64`].
impl From<Gva> for u64 {
    /// Create a [`u64`] from a [`Gva`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let gva = Gva::new(0xbaadc0de_deadbeef);
    /// let gva_u64: u64 = gva.into();
    /// assert_eq!(gva_u64, 0xbaadc0de_deadbeef);
    /// assert_eq!(u64::from(gva), 0xbaadc0de_deadbeef);
    /// # }
    /// ```
    fn from(value: Gva) -> Self {
        value.0
    }
}

/// Convert a [`&Gva`][Gva] into a [`u64`].
impl From<&Gva> for u64 {
    /// Create a [`u64`] from a [&Gpa][`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # fn main() {
    /// let gva = Gpa::new(0xbaadc0de_deadbeef);
    /// let gva_p = &gva;
    /// let gva_u64: u64 = gva_p.into();
    /// assert_eq!(gva_u64, 0xbaadc0de_deadbeef);
    /// assert_eq!(u64::from(gva_p), 0xbaadc0de_deadbeef);
    /// # }
    /// ```
    fn from(value: &Gva) -> Self {
        value.0
    }
}

/// Format [`Gva`] as a string.
impl Display for Gva {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gva:{:#x}", self.0)
    }
}
