// Axel '0vercl0k' Souchet - May 30 2023
//! This module contains the logic to create the set of physical memory pages
//! ([`PhyPage`]) required to build a virtual address space. It creates the
//! minimun set of physical pages to create a specific virtual address space.
use crate::gxa::{Gpa, Gva, Gxa};
use crate::pxe::{Pxe, PxeFlags};

use std::alloc::{alloc, dealloc, Layout};
use std::collections::{hash_map, hash_map::Iter, HashMap};
use std::default::Default;
use std::mem::{align_of, size_of};

/// A physical page is 4k bytes.
pub const PHY_PAGE_SIZE: usize = 4 * 1_024;

/// A PXE is 8 bytes long, so a physical page can hold at most 512 entries
/// ([0..511]).
pub const MAX_PXE_IDX: usize = PHY_PAGE_SIZE / size_of::<u64>();

/// A [`PhyPage`] is a pointer to a 4k page in the host address space and its
/// associated [`Gpa`].
///
/// # Examples
///
/// ```
/// # use rp_bf::gxa::{Gxa, Gpa};
/// # use rp_bf::ptables::PhyPage;
/// # fn main() {
/// let p = PhyPage::new(Gpa::new(0x1000));
/// assert_eq!(p.hva().is_null(), false);
/// # }
/// ```
#[derive(Debug)]
pub struct PhyPage {
    /// A 4k Host Virtual Address backing storage.
    hva: *mut u8,
    /// The associated Guest Physical Address
    gpa: Gpa,
}

/// Every [`PhyPage`] allocates a 4k page & that pointer is aligned on
/// `sizeof(u64)`.
///
/// # Safety
///
/// Using [`from_size_align_unchecked`][Layout::from_size_align_unchecked] is
/// safe because `align` is not zero, is a power of 2 and because `size` aligned
/// up to `align` doesn't overflow an `isize`.
pub const PHY_PAGE_LAYOUT: Layout =
    unsafe { Layout::from_size_align_unchecked(PHY_PAGE_SIZE, align_of::<u64>()) };

impl PhyPage {
    /// Create a [`PhyPage`] at a specific [`Gpa`].
    ///
    /// # Safety
    ///
    /// Callers need to be careful as the page pointed by `hva` is not zero
    /// initialized.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # use rp_bf::ptables::PhyPage;
    /// # fn main() {
    /// let p = PhyPage::new(Gpa::new(0x1_000));
    /// assert_eq!(p.hva().is_null(), false);
    /// let result = std::panic::catch_unwind(|| PhyPage::new(Gpa::new(0x1_337)));
    /// assert!(result.is_err());
    /// # }
    /// ```
    pub fn new(gpa: Gpa) -> Self {
        // It is probably a bug if you are trying to place a `PhyPage` at a non
        // page-aligned `Gpa`.
        assert!(gpa.page_aligned(), "{gpa} is expected to be page aligned");

        // Safety: This is safe because we force the allocation to be aligned on u64's
        // alignment and we'll only access that memory as `u64` or as a set of bytes.
        let hva = unsafe { alloc(PHY_PAGE_LAYOUT) };

        // Make sure that the allocator didn't fail..
        assert!(!hva.is_null(), "allocation of a PhyPage failed");

        // .. and that we got the expected alignment.
        debug_assert_eq!(
            hva.align_offset(PHY_PAGE_LAYOUT.align()),
            0,
            "expected align offset to be 0 as {:#?}",
            hva
        );

        Self { hva, gpa }
    }

    /// Create a [`PhyPage`] at a [`Gpa`] and zero-initialize the backing page.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # use rp_bf::ptables::{PhyPage, MAX_PXE_IDX};
    /// # fn main() {
    /// let p = PhyPage::new_zeroed(Gpa::new(0x1_000));
    /// assert_eq!(p.hva().is_null(), false);
    /// let result = std::panic::catch_unwind(|| PhyPage::new_zeroed(Gpa::new(0x1_337)));
    /// assert!(result.is_err());
    /// let mut counter = 0;
    /// for idx in 0..MAX_PXE_IDX {
    ///     counter += u64::from(p.pxe(idx));
    /// }
    /// assert_eq!(counter, 0);
    /// # }
    /// ```
    pub fn new_zeroed(gpa: Gpa) -> Self {
        // It is probably a bug if you are trying to place a `PhyPage` at a non
        // page-aligned `Gpa`.
        assert!(gpa.page_aligned(), "{gpa} is expected to be page aligned");

        let p = Self::new(gpa);
        let ptr = p.hva;
        for idx in 0..PHY_PAGE_SIZE {
            unsafe { ptr.add(idx).write(0) };
        }

        p
    }

    /// Read the `idx`th `PXE` out of the page.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # use rp_bf::ptables::PhyPage;
    /// # fn main() {
    /// let mut p = PhyPage::new_zeroed(Gpa::new(0x1_000));
    /// let pxe = Pxe::new(
    ///     0x6d600,
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present,
    /// );
    /// p.set_pxe(511, pxe);
    /// let read_pxe = p.pxe(511);
    /// assert_eq!(read_pxe, pxe);
    /// # }
    pub fn pxe(&self, idx: usize) -> Pxe {
        assert!(
            idx < MAX_PXE_IDX,
            "expected a PXE index in [0..511] but got {idx}"
        );
        let pxe_ptr = self.hva as *const u64;
        unsafe { pxe_ptr.add(idx).read() }.into()
    }

    /// Write the `pxe` at index `idx`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # use rp_bf::pxe::{Pxe, PxeFlags};
    /// # use rp_bf::ptables::{PhyPage, MAX_PXE_IDX};
    /// # fn main() {
    /// let result = std::panic::catch_unwind(|| {
    ///     let mut p = PhyPage::new_zeroed(Gpa::new(0x1_000));
    ///     let pxe = Pxe::new(
    ///         0x6d600,
    ///         PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present,
    ///     );
    ///     p.set_pxe(MAX_PXE_IDX, pxe);
    /// });
    /// let mut p = PhyPage::new_zeroed(Gpa::new(0x1_000));
    /// let pxe = Pxe::new(
    ///     0x6d600,
    ///     PxeFlags::UserAccessible | PxeFlags::Accessed | PxeFlags::Present,
    /// );
    /// p.set_pxe(0, pxe);
    /// let read_pxe = p.pxe(0);
    /// assert_eq!(read_pxe, pxe);
    /// # }
    pub fn set_pxe(&mut self, idx: usize, pxe: Pxe) {
        assert!(
            idx < MAX_PXE_IDX,
            "expected a PXE index in [0..511] but got {idx}"
        );
        let pxe_ptr = self.hva as *mut u64;
        unsafe { pxe_ptr.add(idx).write(pxe.into()) }
    }

    /// Get a const pointer to the page content in the host address space (HVA).
    ///
    /// # Examples
    /// ```
    /// # use rp_bf::gxa::{Gxa, Gpa};
    /// # use rp_bf::ptables::{PhyPage, PHY_PAGE_SIZE};
    /// # fn main() {
    /// let p = PhyPage::new_zeroed(Gpa::new(0x1_000));
    /// let mut counter = 0;
    /// for idx in 0..PHY_PAGE_SIZE {
    ///     counter += u64::from(unsafe { p.hva().add(idx).read() });
    /// }
    /// assert_eq!(counter, 0);
    /// # }
    /// ```
    pub fn hva(&self) -> *const u8 {
        self.hva
    }
}

/// A [`Translation`] maps a [`Gpa`] to a [`PhyPage`]. This is useful to know
/// where the content of a page is stored at in the host address space from its
/// [`Gpa`].
type Translation = HashMap<Gpa, PhyPage>;

/// A virtual address space is basically a set of [`PhyPage`].
#[derive(Debug, Default)]
pub struct AddrSpace {
    pub translation: Translation,
}

impl AddrSpace {
    /// Get the size of the virtual address space in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::{VirtAddrSpaceBuilder, PHY_PAGE_SIZE};
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// for gva_addr in (0..0x5_000).step_by(PHY_PAGE_SIZE) {
    ///     let gva = Gva::new(gva_addr);
    ///     builder.add_virtual_page(gva, None, true, false);
    /// }
    /// // 1 PML4, 1 PDPT, 1 PDT, 1 PT, 5 pages
    /// assert_eq!(builder.bytes(), (5 + 1 + 1 + 1 + 1) * PHY_PAGE_SIZE);
    /// # }
    pub fn bytes(&self) -> usize {
        self.translation.len() * PHY_PAGE_SIZE
    }

    /// Get a pointer to the page (in the host address space) that backs a
    /// [`Gpa`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::{VirtAddrSpaceBuilder, PHY_PAGE_SIZE};
    /// # use rp_bf::gxa::{Gxa, Gva, Gpa};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// let gva = Gva::new(0xffffffff_deadbeef);
    /// let page_content = [0x1u8; PHY_PAGE_SIZE];
    /// let gpa = builder.add_virtual_page(
    ///     gva.page_align(),
    ///     Some(&page_content),
    ///     true,
    ///     true
    /// );
    /// # }
    pub fn hva_from_gpa(&self, gpa: Gpa) -> Option<*const u8> {
        debug_assert!(
            gpa.page_aligned(),
            "GPA in the translation table should be page aligned but {gpa} isn't"
        );

        self.translation.get(&gpa).map(|page| page.hva())
    }

    pub fn iter(&self) -> Iter<'_, Gpa, PhyPage> {
        self.translation.iter()
    }
}

// impl Iterator for AddrSpace {
//     type Item = ;
//     fn next(&mut self) -> Option<Self::Item> {

//     }
// }

/// Release all the memory that we manually allocated.
impl Drop for AddrSpace {
    fn drop(&mut self) {
        for (_, page) in self.translation.drain() {
            unsafe { dealloc(page.hva, PHY_PAGE_LAYOUT) };
        }
    }
}

/// This builds the set of physical memory pages required for a virtual address
/// space. It packs all the physical pages starting at GPA:0 (where it puts the
/// PML4) onwards.
///
/// # Examples
///
/// ```
/// # use rp_bf::ptables::VirtAddrSpaceBuilder;
/// # use rp_bf::gxa::{Gva, Gxa};
/// # fn main() {
/// let mut builder = VirtAddrSpaceBuilder::new();
/// let gva = Gva::new(0x7f_fb_3a_3d_c7_fb);
/// builder.add_virtual_page(gva.page_align(), None, true, false);
/// # }
/// ```
#[derive(Default, Debug)]
pub struct VirtAddrSpaceBuilder {
    cur_gpa: Gpa,
    translation: Translation,
}

impl VirtAddrSpaceBuilder {
    /// Create a [`VirtAddrSpaceBuilder`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::VirtAddrSpaceBuilder;
    /// # use rp_bf::gxa::{Gva, Gxa};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// let gva = Gva::new(0x7f_fb_3a_3d_c7_fb);
    /// builder.add_virtual_page(gva.page_align(), None, true, false);
    /// # }
    /// ```
    pub fn new() -> Self {
        let mut builder = VirtAddrSpaceBuilder {
            translation: Translation::new(),
            ..Default::default()
        };

        // The code assumes that there is a PML4 available at GPA:0,
        // so let's allocate one.
        builder.alloc_phy_page(true);

        builder
    }

    /// Allocate a new [`PhyPage`] and keep track of it in the `translation`
    /// table.
    fn alloc_phy_page(&mut self, zeroed: bool) -> &mut PhyPage {
        // Allocate a page, and increment the current GPA.
        let gpa = self.cur_gpa;
        let page = if zeroed {
            PhyPage::new_zeroed(gpa)
        } else {
            PhyPage::new(gpa)
        };
        self.cur_gpa = self.cur_gpa.next_aligned_page();

        // Keep track of it.
        let page = match self.translation.entry(gpa) {
            hash_map::Entry::Occupied(_) => panic!("{gpa} was already in the translation table"),
            hash_map::Entry::Vacant(v) => v.insert(page),
        };

        page
    }

    /// Read the `idx`th PXE off the backing page at `gpa`.
    fn pxe(&self, gpa: Gpa, idx: usize) -> Pxe {
        debug_assert!(
            gpa.page_aligned(),
            "expected a page-aligned GPA but got {gpa}"
        );

        self.translation
            .get(&gpa)
            .unwrap_or_else(|| panic!("{gpa} isn't in the translation table"))
            .pxe(idx)
    }

    /// Write a [`Pxe`] at a specific index off the backing page at `gpa`.
    fn set_pxe(&mut self, gpa: Gpa, idx: usize, pxe: Pxe) {
        debug_assert!(
            gpa.page_aligned(),
            "expected a page-aligned GPA but got {gpa}"
        );

        self.translation
            .get_mut(&gpa)
            .unwrap_or_else(|| panic!("{gpa} isn't in the translation table"))
            .set_pxe(idx, pxe);
    }

    /// Add a virtual page to the address space. Under the hood, this builds the
    /// required page table hierarchy necessary to materialize a virtual
    /// memory page filled w/ `data` at `gva`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::{VirtAddrSpaceBuilder, PHY_PAGE_SIZE};
    /// # use rp_bf::gxa::{Gva, Gxa};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// let gva = Gva::new(0x7f_fb_3a_3d_c7_fb);
    /// builder.add_virtual_page(gva.page_align(), None, true, false);
    /// // 1 for the PML4, 1 for the PDPT, 1 for the PDT, 1 for the PT, 1 for backing
    /// // storage.
    /// assert_eq!(builder.bytes() / PHY_PAGE_SIZE, 5);
    /// # }
    /// ```
    pub fn add_virtual_page(
        &mut self,
        gva: Gva,
        data: Option<&[u8; PHY_PAGE_SIZE]>,
        executable: bool,
        writable: bool,
    ) -> Gpa {
        debug_assert!(
            gva.page_aligned(),
            "virtual page addresses expected to be aligned but {gva}"
        );

        // We'll start the loop with a 'fake' PXE that has a PFN to GPA:0 which is
        // where we store the PML4.
        let mut last_pxe = Pxe::new(0, PxeFlags::empty());
        let mut last_pxe_table = Gpa::from_pfn(0);
        let pxe_indexes = [
            gva.pml4e_idx(),
            gva.pdpe_idx(),
            gva.pde_idx(),
            gva.pte_idx(),
        ];

        let mut iter = pxe_indexes.iter().peekable();
        while let Some(&pxe_index) = iter.next() {
            let pxe_index = pxe_index as usize;

            // Is it the last level of PXE?
            let last = iter.peek().is_none();

            // So here's how this works. We start with a table of PXEs (PML4, PDPT, etc.),
            // and we read the PXE that we need to map `gva`.
            //
            // If the PXE is present, it means that we already allocated backing storage,
            // so our job is done there and we can loop.
            //
            // If the PXE is not present, then it means we need to allocate backing storage
            // for the table, and we need to link the PXE to this new table by setting the
            // right PFN in the PXE. At the end of the loop we linked
            // PML4E->PDPTE->PDE->PTE->page
            let table_gpa = Gpa::from_pfn(last_pxe.pfn);
            last_pxe_table = table_gpa;
            let pxe = self.pxe(table_gpa, pxe_index);
            if !pxe.present() {
                let phy_page = self.alloc_phy_page(if last {
                    // If this is the last level, then no need to zero initialize the page content
                    // as we'll overwrite it with `data`.
                    false
                } else {
                    // If we're allocating a page to store `Pxe`s, let's make sure it is zero
                    // initialized.
                    true
                });

                let fixed_pxe = Pxe::new(
                    phy_page.gpa.pfn(),
                    PxeFlags::Present | PxeFlags::UserAccessible | PxeFlags::Writable,
                );

                self.set_pxe(table_gpa, pxe_index, fixed_pxe);
                last_pxe = fixed_pxe;
                continue;
            }

            assert!(!last, "Every GVA added should be unique, so the last level of PXE should never already exists ({gva})");
            last_pxe = pxe;
        }

        // At this stage, we have backing storage to store the page content
        // and we know where it is because we have the last pxe (PTE), so we have
        // the pfn.
        let table_gpa = Gpa::from_pfn(last_pxe.pfn);

        // Find out where it is in the host space, and copy the `data` inside it.
        let phy_page = self
            .translation
            .get_mut(&table_gpa)
            .expect("Backing storage for the page must exist");

        // If we have data to write to the page, then let's do that.
        if let Some(data) = data {
            unsafe { phy_page.hva.copy_from(data.as_ptr(), PHY_PAGE_SIZE) };
        }

        // The last thing we need to do is to update the PXE (PTE) to tweak the page
        // properties. Do we want it to be executable, or not present, etc.
        let mut flags = PxeFlags::UserAccessible;
        flags.set(PxeFlags::Writable, writable);
        flags.set(PxeFlags::NoExecute, !executable);
        flags.set(PxeFlags::Present, data.is_some());
        let fixed_pxe = Pxe::new(phy_page.gpa.pfn(), flags);

        // Slap the PXE in place!
        self.set_pxe(last_pxe_table, gva.pte_idx() as usize, fixed_pxe);

        Gpa::from_pfn(fixed_pxe.pfn)
    }

    /// Get a reference to the translation table that maps [`Gpa`] to a
    /// [`PhyPage`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::{VirtAddrSpaceBuilder, AddrSpace, PHY_PAGE_SIZE};
    /// # use rp_bf::gxa::{Gxa, Gva, Gpa};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// let mut len = 0;
    /// let mut gpas = Vec::new();
    /// for gva_addr in (0..0x5_000).step_by(PHY_PAGE_SIZE) {
    ///     let gva = Gva::new(gva_addr);
    ///     let gpa = builder.add_virtual_page(gva, None, true, false);
    ///     gpas.push(gpa);
    /// }
    /// let addr_space = builder.build();
    /// for gpa in gpas {
    ///     let page = addr_space.translation.get(&gpa);
    ///     assert!(page.is_some());
    /// }
    /// # }
    pub fn build(mut self) -> AddrSpace {
        AddrSpace {
            translation: std::mem::take(&mut self.translation),
        }
    }

    /// Get the size of the virtual address space in bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rp_bf::ptables::{VirtAddrSpaceBuilder, PHY_PAGE_SIZE};
    /// # use rp_bf::gxa::{Gxa, Gva};
    /// # fn main() {
    /// let mut builder = VirtAddrSpaceBuilder::new();
    /// for gva_addr in (0..0x5_000).step_by(PHY_PAGE_SIZE) {
    ///     let gva = Gva::new(gva_addr);
    ///     builder.add_virtual_page(gva, None, true, false);
    /// }
    /// // 1 PML4, 1 PDPT, 1 PDT, 1 PT, 5 pages
    /// assert_eq!(builder.bytes(), (5 + 1 + 1 + 1 + 1) * PHY_PAGE_SIZE);
    /// # }
    pub fn bytes(&self) -> usize {
        self.translation.len() * PHY_PAGE_SIZE
    }
}

/// Release all the memory that we manually allocated.
impl Drop for VirtAddrSpaceBuilder {
    fn drop(&mut self) {
        for (_, page) in self.translation.drain() {
            unsafe { dealloc(page.hva, PHY_PAGE_LAYOUT) };
        }
    }
}
