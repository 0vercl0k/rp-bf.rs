// Axel '0vercl0k' Souchet - May 30 2023
//! This module contains all the emulation logic.
use core::panic;
use std::alloc::{alloc, Layout};
use std::collections::HashSet;
use std::ptr::slice_from_raw_parts;
use std::time::{Duration, Instant};
use std::{cmp, mem};

use bochscpu::cpu::{Cpu, RunState, State};
use bochscpu::hook::{Hooks, MemAccess};
use bochscpu::mem::{phy_write, virt_read_slice_checked, virt_translate_checked};
use log::{debug, info, trace};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::gxa::{Gpa, Gva, Gxa};
use crate::ptables::{AddrSpace, PHY_PAGE_SIZE};

/// Statistics after emulating a slice of code.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunStats {
    /// The number of instruction emulated.
    pub ninstrs: u64,
    /// The number of memory reads in bytes made by the emulated code.
    pub nreads: u64,
    /// The number of memory writes in bytes made by the emulated code.
    pub nwrites: u64,
    /// The time spent emulating.
    pub time: Duration,
}

/// Global statistics persisting across emulation run.
#[derive(Debug, Default, Clone)]
pub struct EmuStats {
    /// The number of instructions emulated.
    pub ninstrs: u64,
    /// The number of memory reads in bytes made by the emulated code.
    pub nreads: u64,
    /// The number of memory writes in bytes made by the emulated code.
    pub nwrites: u64,
    /// The number of testcases that terminated w/ a timeout.
    pub ntimeouts: u64,
    /// The number of testcases that terminated w/ a crash.
    pub ncrashes: u64,
    /// The time spent emulating.
    pub time: Duration,
}

/// Every testcase going through the emulation finished with either a
/// [`TestcaseResult::Timeout`] or with a [`TestcaseResult::Crash`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TestcaseResult {
    /// The testcase terminated with a crash.
    Crash,
    /// The testcase terminated with a timeout.
    Timeout,
}

impl Default for TestcaseResult {
    fn default() -> Self {
        Self::Crash
    }
}

/// Macro to define accessor for GPRs.
#[macro_export]
macro_rules! accessor {
    ($( $x:ident ),+ ) => {
        $(
            /// Get the $x register.
            #[allow(dead_code)]
            pub fn $x(&self) -> u64 {
                unsafe { self.cpu().$x() }
            }
        ) +
    };
}

/// This marker page uses an address that is part of the kernel space (in a
/// normal windows environment) but mapped as user accessible, but not present.
/// Basically, this is a page that no user-mode code would access, it wouldn't
/// be possible which makes it a good way to use it to clobber registers and
/// see if it leads to any controlled access.
///
/// For a 64-bit process on 64-bit Windows, the virtual address space is the
/// 128-terabyte range 0x000'00000000 through 0x7FFF'FFFFFFFF.
/// <https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces>
pub const MARKER_PAGE_ADDR: Gva = Gva::new(0xffff8123_45678000);

/// The emulator lets you emulate Intel code from a user-mode dump using the
/// [`Bochs`](mod@bochscpu) emulator. [`bochscpu`] is a full system emulator
/// which means the environment needs every architectural bits you would expect
/// from an Intel system: an IDT, page tables, MSR, GPRs, etc. But none of those
/// bits are stored in a user-mode dumps..?
///
/// Correct, the trick we use is to: 1) populate the architectural details with
/// defaults 2) reecreate a virtual address space matching the user-mode dump's.
/// No interruption, context-switching, and calling into the kernel is allowed.
/// Executing kernel-code could be lifted but for now the tool focuses on
/// user-mode only.
#[derive(Debug, Default)]
pub struct Emu {
    /// Bochscpu is a full system emulator so we use the
    /// [`VirtAddrSpaceBuilder`] to build the page table hierarchy and to
    /// provide the minimum set of physical memory pages to create a mirror of
    /// the address space.
    addr_space: AddrSpace,
    /// The CPU state.
    state: State,
    /// How did the current testcase finish?
    testcase_result: TestcaseResult,
    /// Set of [`Gpa`] that we need to restore.
    dirty_gpas: HashSet<Gpa>,
    /// The maximum number of instructions a testcase can execute before being
    /// terminated with a [`TestcaseResult::Timeout`].
    instr_limit: Option<u64>,
    /// Statistics for the current testcase (reset for every testcase).
    run_stats: RunStats,
    /// Global statistics (not reset across testcases).
    emu_stats: EmuStats,
}

/// Define how to handle the various events we care about. We want to know:
///   - when memory is written to to track dirtiness
///   - when an instruction is executed to be able to count them and honor the
///     instruction limit
///   - when the CPU crashes to terminate the testcase
impl Hooks for Emu {
    // fn before_execution(&mut self, _id: u32, _ins: *mut std::ffi::c_void) {
    //     let cpu = self.cpu();
    //     debug!("before_execution: {:#x}", unsafe { cpu.rip() });
    //     unsafe { cpu.print_gprs() };
    // }

    fn after_execution(&mut self, _id: u32, _ins: *mut std::ffi::c_void) {
        debug!("after_execution: {:#x}", unsafe { self.cpu().rip() });
        self.run_stats.ninstrs += 1;
        let hit_limit = matches!(self.instr_limit, Some(limit) if self.run_stats.ninstrs >= limit);
        if !hit_limit {
            return;
        }

        info!(
            "Over the {} instruction limit, stopping cpu",
            self.instr_limit.unwrap()
        );

        self.stop(TestcaseResult::Timeout);
    }

    fn lin_access(
        &mut self,
        _id: u32,
        _vaddr: bochscpu::Address,
        paddr: bochscpu::Address,
        len: usize,
        _memty: bochscpu::hook::MemType,
        rw: bochscpu::hook::MemAccess,
    ) {
        let len = len as u64;
        match rw {
            MemAccess::Read => self.run_stats.nreads += len,
            MemAccess::RW => {
                self.run_stats.nwrites += len;
                self.run_stats.nreads += len;
            }
            _ => {}
        };

        // We only care about write access.
        let write_access = matches!(rw, MemAccess::Write | MemAccess::RW);
        if !write_access {
            return;
        }

        let gpa = Gpa::new(paddr);
        debug!("adding {gpa} as dirty");
        self.dirty_gpa_range(gpa, len as usize);
    }

    fn interrupt(&mut self, _id: u32, vector: u32) {
        info!("interrupt: Vector {vector}");
        self.stop(TestcaseResult::Crash);
    }

    fn exception(&mut self, _id: u32, vector: u32, error_code: u32) {
        info!("exception: vector({vector:#x}, error_code({error_code:#x})");
        self.stop(TestcaseResult::Crash);
    }

    fn phy_access(
        &mut self,
        _id: u32,
        paddr: bochscpu::PhyAddress,
        len: usize,
        _memty: bochscpu::hook::MemType,
        rw: bochscpu::hook::MemAccess,
    ) {
        let len = len as u64;
        match rw {
            MemAccess::Read => self.run_stats.nreads += len,
            MemAccess::RW => {
                self.run_stats.nwrites += len;
                self.run_stats.nreads += len;
            }
            _ => {}
        };

        let write_access = matches!(rw, MemAccess::Write | MemAccess::RW);
        if !write_access {
            return;
        }

        let gpa = Gpa::new(paddr);
        debug!("adding {gpa} ({:#x} bytes) as dirty", len);
        self.dirty_gpa_range(gpa, len as usize);
    }

    fn tlb_cntrl(
        &mut self,
        _id: u32,
        _what: bochscpu::hook::TlbCntrl,
        new_cr: Option<bochscpu::PhyAddress>,
    ) {
        // The cr3 register is getting changed, not expected.
        panic!(
            "The cr3 register is getting changed from {:#x} to {:#x}",
            self.state.cr3,
            new_cr.unwrap()
        );
    }

    fn hlt(&mut self, _id: u32) {
        panic!("Hit HLT");
    }
}

impl Emu {
    accessor!(
        rax, rbx, rcx, rdx, rsi, rdi, rip, rsp, rbp, r8, r9, r10, r11, r12, r13, r14, r15, rflags,
        cr3
    );

    /// Creates a new `Emu` instance.
    pub fn new(state: State, addr_space: AddrSpace, instr_limit: Option<u64>) -> Result<Self> {
        unsafe { Cpu::new(0) };
        unsafe {
            // If bochscpu executes code that is asking for physical memory, this is a bug
            // so panic.
            bochscpu::mem::missing_page(|gpa| {
                panic!("missing_page: GPA {gpa:#x}");
            })
        };

        let emu = Self {
            state,
            instr_limit,
            addr_space,
            ..Default::default()
        };

        // Now, let's load up the CPU state. The CPU state is made by a registers
        // specified in the profile JSON file, and registers that we read off the dump.
        unsafe { emu.cpu().set_state(&emu.state) };

        // At this point, we built an address space, let's load it up in the emulator.
        for (gpa, page) in emu.addr_space.iter() {
            // But let's duplicate the pages, as we'll need a virgin copy to restore.
            let layout = Layout::from_size_align(PHY_PAGE_SIZE, PHY_PAGE_SIZE).unwrap();
            let hva = unsafe { alloc(layout) };
            unsafe {
                hva.copy_from(page.hva(), PHY_PAGE_SIZE);
                bochscpu::mem::page_insert(gpa.into(), hva)
            };
        }

        Ok(emu)
    }

    pub fn run(&mut self) -> Result<(TestcaseResult, RunStats)> {
        self.testcase_result = TestcaseResult::Crash;

        let before = Instant::now();
        unsafe { self.cpu().prepare().register(self).run() };
        self.run_stats.time += before.elapsed();

        // Aggregate the run stats into the emu stats.
        self.emu_stats.time += self.run_stats.time;
        self.emu_stats.nreads += self.run_stats.nreads;
        self.emu_stats.nwrites += self.run_stats.nwrites;
        self.emu_stats.ninstrs += self.run_stats.ninstrs;
        match self.testcase_result {
            TestcaseResult::Crash => self.emu_stats.ncrashes += 1,
            TestcaseResult::Timeout => self.emu_stats.ntimeouts += 1,
        };

        // Grab the run stats to return it to the user.
        let run_stats = mem::take(&mut self.run_stats);

        // We made it!
        Ok((self.testcase_result, run_stats))
    }

    pub fn restore(&mut self) -> Result<usize> {
        // To restore the CPU state we use the no flush variation to avoid
        // flushing the TLBs for every candidate. In my experience, this is leads to 10x
        // less memory accesses:
        // Run stats:
        //        Memory accesses: 34.1gb
        // # instructions executed: 353.4m
        //   total time emulating: 25.4min
        //     # instructions / s: 231.6k
        //   crashes/timeouts/oks: 107.0m/237.1k/0.0
        // ----------------------------------
        // Run stats:
        //         Memory accesses: 3.7gb
        // # instructions executed: 353.4m
        //    total time emulating: 5.3min
        //      # instructions / s: 1.1m
        //    crashes/timeouts/oks: 107.0m/237.1k/0.0
        let cpu = self.cpu();
        unsafe { cpu.set_state_no_flush(&self.state) };

        // Restore the pages are dirty.
        let mut size_restored = 0;
        for dirty_gpa in self.dirty_gpas.drain() {
            // Find the non-dirty version of this GPA and get its HVA off the builder.
            let hva = self
                .addr_space
                .hva_from_gpa(dirty_gpa)
                .unwrap_or_else(|| panic!("dirty gpa {dirty_gpa} is unknown"));

            // bxcpu keeps a gpa<->hva mapping, so asking it politely to do the write.
            unsafe {
                let data = slice_from_raw_parts(hva, PHY_PAGE_SIZE).as_ref().unwrap();
                phy_write(dirty_gpa.into(), data)
            };

            size_restored += PHY_PAGE_SIZE;
        }

        Ok(size_restored)
    }

    /// Gets the emu stats.
    pub fn stats(&self) -> EmuStats {
        self.emu_stats.clone()
    }

    #[allow(dead_code)]
    pub fn virt_read(&self, gva: Gva, data: &mut [u8]) -> Result<()> {
        virt_read_slice_checked(self.cr3(), gva.into(), data).map_err(|e| e.into())
    }

    #[allow(dead_code)]
    pub fn virt_read8(&self, gva: Gva) -> Result<u64> {
        let mut value = [0u8; 8];
        self.virt_read(gva, &mut value)?;

        Ok(u64::from_le_bytes(value))
    }

    #[allow(dead_code)]
    fn virt_write_(&mut self, gva: Gva, data: &[u8], dirty: bool) -> Result<usize> {
        let cr3 = self.cr3();
        let mut left2write = data.len();
        let mut cur_gva = gva;
        let mut offset = 0;
        while left2write > 0 {
            let gpa = Gpa::new(virt_translate_checked(cr3, cur_gva.into())?);
            let writable_amount = PHY_PAGE_SIZE - cur_gva.offset() as usize;
            let size2write = cmp::min(writable_amount, left2write);
            let slice = &data[offset..(offset + size2write)];
            phy_write(gpa.into(), slice);
            left2write -= size2write;
            cur_gva = Gva::new(cur_gva.u64() + (size2write as u64));
            offset += size2write;
            if dirty {
                self.dirty_gpa_range(gpa, size2write);
            }
        }

        Ok(left2write)
    }

    #[allow(dead_code)]
    pub fn virt_write<T>(&mut self, gva: Gva, data: &T) -> Result<usize> {
        let ptr = data as *const T as *const u8;
        let len = std::mem::size_of_val(data);
        let slice = unsafe { slice_from_raw_parts(ptr, len).as_ref().unwrap() };
        self.virt_write_(gva, slice, false)
    }

    #[allow(dead_code)]
    pub fn virt_write_dirty<T>(&mut self, gva: Gva, data: &T) -> Result<usize> {
        let ptr = data as *const T as *const u8;
        let len = std::mem::size_of_val(data);
        let slice = unsafe { slice_from_raw_parts(ptr, len).as_ref().unwrap() };

        self.virt_write_(gva, slice, true)
    }

    pub fn cpu(&self) -> Cpu {
        Cpu::from(0)
    }

    pub fn stop(&mut self, testcase_result: TestcaseResult) {
        self.testcase_result = testcase_result;
        unsafe { self.cpu().set_run_state(RunState::Stop) };
    }

    #[allow(dead_code)]
    pub fn set_rax(&self, value: u64) {
        unsafe { self.cpu().set_rax(value) }
    }

    #[allow(dead_code)]
    pub fn set_rbx(&self, value: u64) {
        unsafe { self.cpu().set_rbx(value) }
    }

    #[allow(dead_code)]
    pub fn set_rcx(&self, value: u64) {
        unsafe { self.cpu().set_rcx(value) }
    }

    #[allow(dead_code)]
    pub fn set_rdx(&self, value: u64) {
        unsafe { self.cpu().set_rdx(value) }
    }

    #[allow(dead_code)]
    pub fn set_rsi(&self, value: u64) {
        unsafe { self.cpu().set_rsi(value) }
    }

    #[allow(dead_code)]
    pub fn set_rdi(&self, value: u64) {
        unsafe { self.cpu().set_rdi(value) }
    }

    #[allow(dead_code)]
    pub fn set_rip(&self, value: u64) {
        unsafe { self.cpu().set_rip(value) }
    }

    #[allow(dead_code)]
    pub fn set_rsp(&self, value: u64) {
        unsafe { self.cpu().set_rsp(value) }
    }

    #[allow(dead_code)]
    pub fn set_rbp(&self, value: u64) {
        unsafe { self.cpu().set_rbp(value) }
    }

    #[allow(dead_code)]
    pub fn set_r8(&self, value: u64) {
        unsafe { self.cpu().set_r8(value) }
    }

    #[allow(dead_code)]
    pub fn set_r9(&self, value: u64) {
        unsafe { self.cpu().set_r9(value) }
    }

    #[allow(dead_code)]
    pub fn set_r10(&self, value: u64) {
        unsafe { self.cpu().set_r10(value) }
    }

    #[allow(dead_code)]
    pub fn set_r11(&self, value: u64) {
        unsafe { self.cpu().set_r11(value) }
    }

    #[allow(dead_code)]
    pub fn set_r12(&self, value: u64) {
        unsafe { self.cpu().set_r12(value) }
    }

    #[allow(dead_code)]
    pub fn set_r13(&self, value: u64) {
        unsafe { self.cpu().set_r13(value) }
    }

    #[allow(dead_code)]
    pub fn set_r14(&self, value: u64) {
        unsafe { self.cpu().set_r14(value) }
    }

    #[allow(dead_code)]
    pub fn set_r15(&self, value: u64) {
        unsafe { self.cpu().set_r15(value) }
    }

    #[allow(dead_code)]
    pub fn set_rflags(&self, value: u64) {
        unsafe { self.cpu().set_rflags(value) }
    }

    fn dirty_gpa_range(&mut self, gpa: Gpa, len: usize) {
        let aligned_size = Gpa::new(len as u64).next_aligned_page().u64();
        let aligned_gpa = gpa.page_align().u64();
        let iter = aligned_gpa..(aligned_gpa + aligned_size);
        for aligned_dirty_gpa in iter.step_by(PHY_PAGE_SIZE) {
            trace!("adding {aligned_dirty_gpa:#x} dirty gpa");
            self.dirty_gpas.insert(Gpa::new(aligned_dirty_gpa));
        }
    }
}
