// Axel '0vercl0k' Souchet - May 30 2023
//! This crate allows you to find sequence of instructions that matches post
//! conditions that you define yourself. I have used it in the past to find key
//! ROP gadgets that I wasn't able to find manually. A typical use-case is as
//! follows: you are attacking a remote server, you don't have an infoleak but a
//! small module doesn't have ASLR on and gets mapped at the same base address
//! everytime.
//!
//! # How does it work at a high-level?
//!
//! You grab a user-mode dump with WinDbg as close as possible from where the
//! gadget you're looking for would be executed. You can simply make your target
//! crash and fix up the CPU context or the memory manually in the pre callback.
//! Then, you write a small Rust module that defines:
//!   - a pre callback. The pre callback is called right before emulating a
//!     sequence of
//!   instructions. You're free to modify the state as you wish.
//!   - a post callback. The post callback is called once the emulation
//!     terminated (either
//!   because it executed more instructions than the maximum amount allowed, or
//! because it   crashed) and this is where you evaluate if the sequence of
//! instructions resulted in   what you were looking for. You can check if
//! specific registers were set, a specific   piece of memory was set to a
//! specific value, if the stack has been pivoted, etc.
//!
//! Once you have that, the [`explore`] function creates an emulator instance
//! initialized with all the memory and CPU state found in the user-mode dump,
//! and then it'll proceed to try to start emulating from every single
//! executable byte.
//!
//! # How does it work really?
//!
//! One of the challenge is that the emulator used is the Bochs emulator. If you
//! have never heard about this emulator it is a full system emulator; which
//! means that it is able to do what your CPU can do: execute kernel-mode code,
//! do cross-rings switch, etc.
//!
//! The user-mode dump contains only virtual memory range & the user-mode side
//! of the CPU context. This means we are missing the physical memory & various
//! important CPU registers that control various architectural things:
//! segmentation, paging, etc.
//!
//! To work around that, the [`ptables`] module builds manually the minimum set
//! of page tables and physical memory that the CPU needs to mirror the virtual
//! address space available in the user-mode dump. Then, we manually configure
//! system registers to mirror a typical Windows environment.
//!
//! # What does a [`Finder`] module look like?
//!
//! You can find two examples that demonstrate two situations I ran into when
//! developing an exploit for Pwn2Own Miami 2022. In that example, I am looking
//! for a gadget to boost my constrained arbitrary call to an unconstrained
//! arbitrary call:
//! ```norun
//! impl Finder for Pwn2OwnMiami2022_1 {
//!    fn pre(&mut self, emu: &mut Emu, candidate: u64) -> Result<()> {
//!        // ```
//!        // (1574.be0): Access violation - code c0000005 (first/second chance not available)
//!        // For analysis of this file, run !analyze -v
//!        // oleaut32!VariantClearWorker+0xff:
//!        // 00007ffb`3a3dc7fb 488b4010        mov     rax,qword ptr [rax+10h] ds:deadbeef`baadc0ee=????????????????
//!        //
//!        // 0:011> u . l3
//!        // oleaut32!VariantClearWorker+0xff:
//!        // 00007ffb`3a3dc7fb 488b4010        mov     rax,qword ptr [rax+10h]
//!        // 00007ffb`3a3dc7ff ff15c3ce0000    call    qword ptr [oleaut32!_guard_dispatch_icall_fptr (00007ffb`3a3e96c8)]
//!        //
//!        // 0:011> u poi(00007ffb`3a3e96c8)
//!        // oleaut32!guard_dispatch_icall_nop:
//!        // 00007ffb`3a36e280 ffe0            jmp     rax
//!        // ```
//!        let rcx = emu.rcx();
//!
//!        // Rewind to the instruction right before the crash:
//!        // ```
//!        // 0:011> ub .
//!        // oleaut32!VariantClearWorker+0xe6:
//!        // ...
//!        // 00007ffb`3a3dc7f8 488b01          mov     rax,qword ptr [rcx]
//!        // ```
//!        emu.set_rip(0x00007ffb_3a3dc7f8);
//!
//!        // Overwrite the buffer we control with the |MARKER_PAGE_ADDR|. The first qword
//!        // is used to hijack control flow, so this is where we write the candidate
//!        // address.
//!        for qword in 0..18 {
//!            let idx = qword * std::mem::size_of::<u64>();
//!            let idx = idx as u64;
//!            let value = if qword == 0 {
//!                candidate
//!            } else {
//!                MARKER_PAGE_ADDR.u64()
//!            };
//!
//!            emu.virt_write(Gva::new(rcx + idx), &value)?;
//!        }
//!
//!        Ok(())
//!    }
//!
//!    fn post(&mut self, emu: &Emu) -> Result<bool> {
//!        // What we want here, is to find sequence of instructions that leads to @rip
//!        // being controlled. To do that, in the |Pre| callback we populate the buffer
//!        // we control with the |MarkerPageAddr| which is basically a magic address
//!        // that'll trigger a fault if it's access / written to / executed. Basically,
//!        // we want to force a crash as this might mean that we successfully found a
//!        // gadget that'll allow us to turn the constrained arbritrary call from above,
//!        // to an uncontrolled where we don't need to worry about dereferences (cf |mov
//!        // rax, qword ptr [rax+10h]|).
//!        //
//!        // Here is the gadget I ended up using:
//!        // ```
//!        // 0:011> u poi(1400aed18)
//!        // 00007ffb2137ffe0   sub     rsp,38h
//!        // 00007ffb2137ffe4   test    rcx,rcx
//!        // 00007ffb2137ffe7   je      00007ffb`21380015
//!        // 00007ffb2137ffe9   cmp     qword ptr [rcx+10h],0
//!        // 00007ffb2137ffee   jne     00007ffb`2137fff4
//!        // ...
//!        // 00007ffb2137fff4   and     qword ptr [rsp+40h],0
//!        // 00007ffb2137fffa   mov     rax,qword ptr [rcx+10h]
//!        // 00007ffb2137fffe   call    qword ptr [mfc140u!__guard_dispatch_icall_fptr (00007ffb`21415b60)]
//!        // ```
//!        let mask = 0xffffffff_ffff0000u64;
//!        let marker = MARKER_PAGE_ADDR.u64();
//!        let rip_has_marker = (emu.rip() & mask) == (marker & mask);
//!
//!        Ok(rip_has_marker)
//!    }
//! }
//! ```
pub mod emu;
pub mod error;
pub mod gxa;
pub mod ptables;
pub mod pxe;
pub mod ui;
pub mod utils;

use crate::emu::{Emu, TestcaseResult};
use crate::error::{Result, RpBfError};
use crate::gxa::Gva;
use crate::ptables::{VirtAddrSpaceBuilder, PHY_PAGE_SIZE};
use crate::utils::ToHuman;

use bochscpu::cpu::{Seg, State};
use emu::{RunStats, MARKER_PAGE_ADDR};
use log::trace;
use ptables::AddrSpace;
use serde::{Deserialize, Serialize};
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use udmp_parser_rs::UserDumpParser;

/// Subset of [`State`] so that the JSON profile file doesn't need to specify
/// every single field in a CPU context. The function [`UserState::to_bxcpu`]
/// builds a complete [`State`] structure from those registers.
#[derive(Deserialize, Debug)]
struct UserState {
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr6: u32,
    dr7: u32,
    es: Seg,
    cs: Seg,
    ss: Seg,
    ds: Seg,
    fs: Seg,
    gs: Seg,
    cr0: u32,
    cr2: u64,
    cr4: u32,
    cr8: u64,
    xcr0: u32,
    sysenter_cs: u64,
    sysenter_eip: u64,
    sysenter_esp: u64,
    pat: u64,
    efer: u32,
    star: u64,
}

impl UserState {
    /// Create a complete boschcpu [`State`] from a [`UserState`] which is a
    /// subset of it.
    fn to_bxcpu(&self, ctx: &udmp_parser_rs::ThreadContextX64, teb: u64) -> State {
        let mut state = State {
            rax: ctx.rax,
            rcx: ctx.rcx,
            rdx: ctx.rdx,
            rbx: ctx.rbx,
            rsp: ctx.rsp,
            rbp: ctx.rbp,
            rsi: ctx.rsi,
            rdi: ctx.rdi,
            r8: ctx.r8,
            r9: ctx.r9,
            r10: ctx.r10,
            r11: ctx.r11,
            r12: ctx.r12,
            r13: ctx.r13,
            r14: ctx.r14,
            r15: ctx.r15,
            rip: ctx.rip,
            rflags: ctx.eflags as u64,
            mxcsr: ctx.mxcsr,
            ..Default::default()
        };
        // state.mxcsr_mask = ctx.;
        // state.fpcw = ctx.fpcw;
        // state.fpsw = ctx.fpsw;
        // state.fptw = ctx.fptw;
        // state.zmm[0].q = ctx.vector_register[0].;
        // state.fpop =

        // XXX: ????
        state.fs.base = 0xde_ad_be_ef;
        state.gs.base = teb;
        // We put the PML4 at GPA:0.
        state.cr3 = 0;
        state.tsc = 0;
        // Take over a few architectural details to prevent context switching,
        // interruptions, etc.
        state.gdtr.base = 0x11_22_33_44_55_66_77_00;
        state.gdtr.limit = 0;

        state.idtr.base = 0x11_22_33_44_55_66_77_00;
        state.idtr.limit = 0;

        state.lstar = 0x11_22_33_44_55_66_77_01;
        state.cstar = 0x11_22_33_44_55_66_77_02;
        state.sfmask = 0xff_ff_ff_ff_ff_ff_ff_ff;

        state.tr.present = true;
        state.tr.base = 0x11_22_33_44_55_66_77_03;
        state.tr.limit = 0;

        state.kernel_gs_base = 0x11_22_33_44_55_66_77_04;
        state.apic_base = 0x11_22_33_44_55_66_77_05;

        state.ldtr.present = true;
        state.ldtr.base = 0x11_22_33_44_55_66_77_06;
        state.ldtr.limit = 0;

        // Populate the rest of the state from the JSON's file.
        state.dr0 = self.dr0;
        state.dr1 = self.dr1;
        state.dr2 = self.dr2;
        state.dr3 = self.dr3;
        state.dr6 = self.dr6;
        state.dr7 = self.dr7;
        state.es = self.es;
        state.cs = self.cs;
        state.ss = self.ss;
        state.ds = self.ds;
        state.fs = self.fs;
        state.gs = self.gs;

        state.cr0 = self.cr0;
        state.cr2 = self.cr2;
        state.cr4 = self.cr4;
        state.cr8 = self.cr8;
        state.xcr0 = self.xcr0;

        state.sysenter_cs = self.sysenter_cs;
        state.sysenter_eip = self.sysenter_eip;
        state.sysenter_esp = self.sysenter_esp;
        state.pat = self.pat;
        state.efer = self.efer;
        state.star = self.star;

        state
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemBlockInfo {
    pub start_addr: u64,
    pub end_addr: u64,
    pub rights: String,
    pub module_path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Candidate {
    pub addr: u64,
    pub mem_info: MemBlockInfo,
    pub res: TestcaseResult,
    pub stats: RunStats,
}

pub trait Finder {
    fn pre(&mut self, emu: &mut Emu, candidate: u64) -> anyhow::Result<()>;
    fn post(&mut self, emu: &Emu) -> anyhow::Result<bool>;
}

fn page_rights_allowed(filter: Option<&String>, rights: &str) -> bool {
    let Some(filter) = filter else {
        // If the user didn't specify a filter, allow it.
        return true;
    };

    let filter = filter.bytes();
    let mut allowed = true;
    let rights = rights.bytes();
    debug_assert!(filter.len() == rights.len() && rights.len() == 3);

    for (allowed_right, right) in filter.zip(rights) {
        allowed = allowed && (allowed_right == b'*' || allowed_right == right);
    }

    allowed
}

/// Build a bochscpu CPU [`State`] from a [`UserState`] which is specified from
/// a profile JSON file, and the thread context coming from a dump file. The
/// profile JSON file specifies a bunch of system registers to configure the
/// emulator to be able to run Windows user-mode code (IDT, MSRs, etc.). But it
/// doesn't specify every single registers as a lot of them depends on the CPU
/// context when the dump was grabbed. The idea is to specify the registers that
/// won't change in the profile, and take the ones that change from the dump and
/// build a state from those two.
/// Also the profile could also be used to configure a runtime environment that
/// is slightly different; maybe a newer or older version of Windows, or maybe a
/// kernel-mode environment for example.
fn build_state(dump: &UserDumpParser, profile: &Path) -> Result<State> {
    // We only support x64 for now.
    let is_x64 = dump.is_arch_x64();
    if !is_x64 {
        return Err(RpBfError::NotX64);
    }

    // Ensure that we have at least one thread.
    let threads = dump.threads();
    if threads.is_empty() {
        return Err(RpBfError::NoThreads);
    }

    // Grab the foreground TID if one is available.
    let foreground_tid = dump.foreground_tid;

    // Grab the first TID.
    let first_tid = threads.values().next().unwrap().id;

    // Let's pick the foreground if it is specified, or grab the first TID
    // otherwise.
    let selected_thread_tid = foreground_tid.unwrap_or(first_tid);
    let selected_thread = threads.get(&selected_thread_tid).unwrap();

    let x64_context = match selected_thread.context() {
        udmp_parser_rs::ThreadContext::X64(ctx) => ctx,
        _ => return Err(RpBfError::NotX64),
    };

    let profile_content = fs::read(profile)?;
    let user_state = serde_json::from_slice::<UserState>(&profile_content)?;
    let state = user_state.to_bxcpu(x64_context, selected_thread.teb);

    Ok(state)
}

/// Build the memory state which mirrors the virtual address space found inside
/// the user dump. This creates a [`AddrSpace`] which is basically a list of
/// physical memory pages.
fn build_mem(dump: &UserDumpParser) -> Result<AddrSpace> {
    let mut builder = VirtAddrSpaceBuilder::new();

    // Let's walk through the memory available in the dump, and artificially a
    // mirror of the virtual address space. The builder instance allows us to build
    // the physical memory space as well as the minimal page table hierarchy
    // required.
    for mem_block in dump.mem_blocks().values() {
        // If the range is empty, skip it.
        if mem_block.data.is_empty() {
            continue;
        }

        // .. and its information.
        let executable = mem_block.is_executable();
        let writable = mem_block.is_writable();
        // Build an iterator that yield the start page address of every pages in the
        // memory range.
        let addr_iter = mem_block.range.clone().step_by(PHY_PAGE_SIZE);
        // Build an iterator that returns chunks that are a page long.
        let chunks = mem_block.data.chunks(PHY_PAGE_SIZE);
        // Zip up the two iterators to get an address and associated content, and walk
        // them.
        for (addr, chunk) in addr_iter.zip(chunks) {
            assert_eq!(
                chunk.len(),
                PHY_PAGE_SIZE,
                "Chunk at {:#x} is not a page long but {} bytes",
                addr,
                chunk.len()
            );

            builder.add_virtual_page(
                Gva::new(addr),
                Some(chunk.try_into().unwrap()),
                executable,
                writable,
            );
        }
    }

    // Add a 'magic' page that we can use to make deterministic faults. This marker
    // page uses an address that is part of the kernel space (in a normal windows
    // environment) but mapped as user accessible, but not present.
    // Basically, this is a page that no user-mode code would access, it wouldn't be
    // possible which makes it a good way to use it to clobber registers and
    // see if it leads to any controlled access.
    //
    // For a 64-bit process on 64-bit Windows, the virtual address space is the
    // 128-terabyte range 0x000'00000000 through 0x7FFF'FFFFFFFF.
    // https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces
    builder.add_virtual_page(MARKER_PAGE_ADDR, None, true, true);

    Ok(builder.build())
}

#[derive(Debug)]
pub struct Opts {
    /// Set an instruction limit
    pub limit: Option<u64>,
    /// Profile configuration path
    pub profile: PathBuf,
    /// Dump file path
    pub dump: PathBuf,
    /// Search only specific memory range(s) (0x112233-0x223344,...)
    pub ranges: Option<Vec<Range<u64>>>,
    /// Search only specific memory ranges(s) based on their memory rights (r-*)
    pub kind: Option<String>,
    /// Stop after finding an amount of results
    pub limit_results: Option<usize>,
}

pub fn explore(
    opts: &Opts,
    finder: &mut dyn Finder,
    ui: &mut dyn ui::Ui,
) -> Result<Vec<Candidate>> {
    let dump = udmp_parser_rs::UserDumpParser::new(&opts.dump)?;
    let state = build_state(&dump, &opts.profile)?;
    let addr_space = build_mem(&dump)?;
    let vspace_size = addr_space.bytes();

    let mut emu = Emu::new(state, addr_space, opts.limit)?;
    trace!(
        "Loaded up {} (mapped {} 4k pages)",
        vspace_size.bytes_human(),
        (vspace_size / PHY_PAGE_SIZE).bytes_human()
    );

    trace!("Starting emulation..");
    let mut wins = Vec::new();
    let mut how_many_total = 0u64;
    let mut how_many_skipped = 0u64;

    for (mem_address, mem_block) in dump.mem_blocks() {
        if mem_block.data.is_empty() {
            continue;
        }

        // Find the module that backs this memory region if there's any.
        let module_path = dump
            .get_module(*mem_address)
            .map(|m| m.path.clone())
            .unwrap_or(PathBuf::new());
        // Find the executable name part. Skip the last '\' if there's any.
        let module_name = module_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or(String::from("Unknown"));
        // Calculate the protection for this region.
        let mut rights = String::with_capacity(3);
        rights.push(if mem_block.is_readable() { 'r' } else { '-' });
        rights.push(if mem_block.is_writable() { 'w' } else { '-' });
        rights.push(if mem_block.is_executable() { 'x' } else { '-' });

        // Check if this is the kind of page we are interested in; skip the region if
        // not.
        if !page_rights_allowed(opts.kind.as_ref(), &rights) {
            trace!(
                "Skipping {:?} ({rights}) because of filter {:?}",
                mem_block.range,
                opts.kind
            );
            how_many_skipped += mem_block.range.end - mem_block.range.start;
            continue;
        }

        'outer: for candidate in mem_block.range.start..mem_block.range.end {
            // Is `candidate` included in one of the ranges we need to search?
            let allowed_range = opts
                .ranges
                .as_ref()
                .map(|ranges| {
                    let contained = ranges.iter().any(|range| range.contains(&candidate));

                    contained
                })
                .unwrap_or(true);

            // If not allowed, skip it.
            if !allowed_range {
                how_many_skipped += 1;
                continue;
            }

            // Invoke the `pre` callback to set-up state.
            trace!("Trying out {candidate:#x}");
            finder.pre(&mut emu, candidate)?;

            // Run the emulation with the candidate.
            let (res, stats) = emu.run()?;
            how_many_total += 1;

            // We found a candidate if it lead to a crash & the `post` condition
            // returned `true`.
            let crashed = matches!(res, TestcaseResult::Crash);
            let found_candidate = crashed && finder.post(&emu)?;
            if found_candidate {
                let candidate = Candidate {
                    res,
                    stats,
                    addr: candidate,
                    mem_info: MemBlockInfo {
                        start_addr: mem_block.range.start,
                        end_addr: mem_block.range.end,
                        rights: rights.clone(),
                        module_path: module_path.to_string_lossy().into(),
                    },
                };

                ui.found_candidate(&candidate)?;
                wins.push(candidate);
            }

            let stats = emu.stats();
            ui.update(
                &stats,
                &module_name,
                candidate,
                how_many_skipped,
                how_many_total,
                wins.len(),
                &mem_block.range,
            )?;

            emu.restore()?;

            let hit_limit = opts
                .limit_results
                .map(|nwins_limit| wins.len() >= nwins_limit)
                .unwrap_or(false);
            if hit_limit {
                break 'outer;
            }
        }
    }

    let stats = emu.stats();
    ui.finish(&stats)?;

    Ok(wins)
}
