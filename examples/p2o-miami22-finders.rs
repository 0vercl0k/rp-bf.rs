// Axel '0vercl0k' Souchet - May 30 2023
extern crate rp_bf;

mod ui {
    use std::fs;
    use std::ops::Range;
    use std::path::Path;
    use std::time::Instant;

    use anyhow::{Context, Result};
    use rp_bf::emu::EmuStats;
    use rp_bf::ui::Ui;
    use rp_bf::utils::{percentage, ToHuman};
    use rp_bf::Candidate;
    use superconsole::style::Stylize;
    use superconsole::{Component, Dimensions, DrawMode, Line, Lines, Span, SuperConsole};

    use crate::CliOpts;

    const SPINNER: [&str; 12] = [
        "🕛", "🕐", "🕑", "🕒", "🕓", "🕔", "🕕", "🕖", "🕗", "🕘", "🕙", "🕚",
    ];

    fn write_results(out: &Path, candidate: &Candidate) -> Result<()> {
        let content = fs::read(out)?;
        let mut wins = serde_json::from_slice::<Vec<Candidate>>(&content)?;
        wins.push(candidate.clone());
        fs::write(out, serde_json::to_vec(&wins)?)?;
        Ok(())
    }

    #[derive(Debug)]
    pub struct ScanningScreen<'a> {
        pub module_name: &'a str,
        pub range: Range<u64>,
        pub candidate: u64,
        pub how_many_skipped: u64,
        pub how_many_total: u64,
        pub nwins: usize,
        pub ninstrs: u64,
        pub spinner: usize,
    }

    impl Component for ScanningScreen<'_> {
        fn draw_unchecked(
            &self,
            _dimensions: Dimensions,
            _mode: DrawMode,
        ) -> anyhow::Result<Lines> {
            let how_many = self.range.end - self.range.start;
            let how_many_done = (self.candidate - self.range.start) + 1;
            let how_many_percent = percentage(how_many_done, how_many);
            let percent_string = format!("{}%", how_many_percent).bold();
            let percent_line = Span::new_styled(match how_many_percent {
                0..=50 => percent_string.red(),
                51..=75 => percent_string.yellow(),
                76..=100 => percent_string.green(),
                _ => unreachable!(),
            })?;

            let header_line = Line::from_iter([
                Span::new_unstyled(format!("{} ", SPINNER[self.spinner % SPINNER.len()]))?,
                Span::new_styled("Scanning ".to_owned().green().bold())?,
                Span::new_styled(
                    format!("{}@{:#x}", self.module_name, self.range.start)
                        .white()
                        .bold(),
                )?,
                Span::new_unstyled("/")?,
                percent_line,
            ]);

            let detail_line = Line::unstyled(&format!(
                "🧾 {} wins, tried {} addrs, emulated {} ins, skipped {} addrs",
                self.nwins,
                self.how_many_total.number_human(),
                self.ninstrs.number_human(),
                self.how_many_skipped.number_human()
            ))?;

            Ok(Lines(vec![header_line, detail_line]))
        }
    }

    #[derive(Debug)]
    pub struct RunStatsScreen<'a> {
        pub stats: &'a EmuStats,
    }

    impl<'a> Component for RunStatsScreen<'a> {
        fn draw_unchecked(
            &self,
            _dimensions: Dimensions,
            _mode: DrawMode,
        ) -> anyhow::Result<Lines> {
            let mut lines = Lines::default();
            lines.push(Line::unstyled("Run stats:")?);
            lines.push(Line::unstyled(&format!(
                "   read memory accesses: {}",
                self.stats.nreads.bytes_human()
            ))?);
            lines.push(Line::unstyled(&format!(
                "  write memory accesses: {}",
                self.stats.nwrites.bytes_human()
            ))?);
            lines.push(Line::unstyled(&format!(
                "# instructions executed: {}",
                self.stats.ninstrs.number_human()
            ))?);
            lines.push(Line::unstyled(&format!(
                "   total time emulating: {:?}",
                self.stats.time
            ))?);
            lines.push(Line::unstyled(&format!(
                "       crashes/timeouts: {}/{}",
                self.stats.ncrashes.number_human(),
                self.stats.ntimeouts.number_human()
            ))?);

            let time_as_s = self.stats.time.as_secs();
            if time_as_s > 0 {
                lines.push(Line::unstyled(&format!(
                    "       # instructions/s: {}",
                    (self.stats.ninstrs / time_as_s).number_human()
                ))?);
            }

            Ok(lines)
        }
    }

    /// A TUI based on [`superconsole`] that implements [`Ui`].
    pub struct SuperconsoleUi<'opts> {
        console: SuperConsole,
        last_stats_time: Instant,
        spinner: usize,
        opts: &'opts CliOpts,
    }

    impl<'opts> SuperconsoleUi<'opts> {
        pub fn new(opts: &'opts CliOpts) -> Result<Self> {
            let console = SuperConsole::new().context("create superconsole")?;
            Ok(Self {
                console,
                last_stats_time: Instant::now(),
                spinner: 0,
                opts,
            })
        }
    }

    impl<'opts> Ui for SuperconsoleUi<'opts> {
        fn init(&mut self) -> Result<()> {
            Ok(())
        }

        fn found_candidate(&mut self, candidate: &Candidate) -> Result<()> {
            // Find the executable name part. Skip the last '\' if there's any.
            let module_path = candidate.mem_info.module_path.as_str();
            let module_name_off = module_path.rfind('\\').map(|off| off + 1);
            let module_name = module_name_off
                .map(|off| &module_path[off..])
                .unwrap_or("Unknown");

            let line = Line::from_iter([
                Span::new_styled("✓ ".to_owned().green().bold())?,
                Span::new_styled(format!("{:#x}", candidate.addr).white().bold())?,
                Span::new_unstyled(format!(" ({}) in ", candidate.mem_info.rights))?,
                Span::new_styled(module_name.to_string().white().bold())?,
                Span::new_unstyled(format!(
                    "/{:#x}-{:#x}, stats: {:?}",
                    candidate.mem_info.start_addr, candidate.mem_info.end_addr, candidate.stats
                ))?,
            ]);

            self.console.emit(Lines(vec![line]));
            write_results(&self.opts.out, candidate)?;

            Ok(())
        }

        fn update(
            &mut self,
            stats: &EmuStats,
            module_name: &str,
            candidate: u64,
            how_many_skipped: u64,
            how_many_total: u64,
            nwins: usize,
            range: &Range<u64>,
        ) -> Result<()> {
            let time2update = self.last_stats_time.elapsed().as_millis() >= 250;
            if !time2update {
                return Ok(());
            }

            self.last_stats_time = Instant::now();
            let aligned = ScanningScreen {
                module_name,
                candidate,
                how_many_skipped,
                how_many_total,
                spinner: self.spinner,
                nwins,
                ninstrs: stats.ninstrs,
                range: Range {
                    start: range.start,
                    end: range.end,
                },
            };

            self.console.render(&aligned)?;
            self.spinner += 1;

            Ok(())
        }

        fn finish(&mut self, stats: &EmuStats) -> Result<()> {
            self.console.render(&RunStatsScreen { stats })?;

            Ok(())
        }
    }

    pub struct BasicUi<'cli> {
        opts: &'cli CliOpts,
    }

    impl<'cli> BasicUi<'cli> {
        pub fn new(opts: &'cli CliOpts) -> Self {
            Self { opts }
        }
    }

    impl<'cli> Ui for BasicUi<'cli> {
        fn found_candidate(&mut self, candidate: &Candidate) -> Result<()> {
            // Find the executable name part. Skip the last '\' if there's any.
            let module_path = candidate.mem_info.module_path.as_str();
            let module_name_off = module_path.rfind('\\').map(|off| off + 1);
            let module_name = module_name_off
                .map(|off| &module_path[off..])
                .unwrap_or("Unknown");

            println!(
                "✓ {:#x} ({}) in {}/{:#x}-{:#x}, stats: {:?}",
                candidate.addr,
                candidate.mem_info.rights,
                module_name,
                candidate.mem_info.start_addr,
                candidate.mem_info.end_addr,
                candidate.stats
            );

            write_results(&self.opts.out, candidate)?;

            Ok(())
        }

        fn finish(&mut self, stats: &EmuStats) -> Result<()> {
            println!("Run stats:");
            println!("   read memory accesses: {}", stats.nreads.bytes_human());
            println!("  write memory accesses: {}", stats.nwrites.bytes_human());
            println!("# instructions executed: {}", stats.ninstrs.number_human());
            println!("   total time emulating: {:?}", stats.time);
            println!(
                "       crashes/timeouts: {}/{}",
                stats.ncrashes.number_human(),
                stats.ntimeouts.number_human()
            );

            let time_as_s = stats.time.as_secs();
            if time_as_s > 0 {
                println!(
                    "       # instructions/s: {}",
                    (stats.ninstrs / time_as_s).number_human()
                );
            }

            Ok(())
        }
    }
}

use std::fs::{self, File};
use std::io::Write;
use std::ops::{Range, RangeInclusive};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use log::trace;
use rp_bf::emu::{Emu, MARKER_PAGE_ADDR};
use rp_bf::gxa::{Gva, Gxa};
use rp_bf::ui::Ui;
use rp_bf::{utils, Candidate, Finder, Opts};

fn has_stack_pivoted_in_range(emu: &Emu, range: RangeInclusive<u64>) -> bool {
    let rsp = emu.rsp();
    range.contains(&rsp)
}

#[derive(Default)]
struct Pwn2OwnMiami2022_1;

impl Finder for Pwn2OwnMiami2022_1 {
    fn pre(&mut self, emu: &mut Emu, candidate: u64) -> Result<()> {
        // ```
        // (1574.be0): Access violation - code c0000005 (first/second chance not available)
        // For analysis of this file, run !analyze -v
        // oleaut32!VariantClearWorker+0xff:
        // 00007ffb`3a3dc7fb 488b4010        mov     rax,qword ptr [rax+10h] ds:deadbeef`baadc0ee=????????????????
        //
        // 0:011> u . l3
        // oleaut32!VariantClearWorker+0xff:
        // 00007ffb`3a3dc7fb 488b4010        mov     rax,qword ptr [rax+10h]
        // 00007ffb`3a3dc7ff ff15c3ce0000    call    qword ptr [oleaut32!_guard_dispatch_icall_fptr (00007ffb`3a3e96c8)]
        //
        // 0:011> u poi(00007ffb`3a3e96c8)
        // oleaut32!guard_dispatch_icall_nop:
        // 00007ffb`3a36e280 ffe0            jmp     rax
        // ```
        let rcx = emu.rcx();

        // Rewind to the instruction right before the crash:
        // ```
        // 0:011> ub .
        // oleaut32!VariantClearWorker+0xe6:
        // ...
        // 00007ffb`3a3dc7f8 488b01          mov     rax,qword ptr [rcx]
        // ```
        emu.set_rip(0x00007ffb_3a3dc7f8);

        // Overwrite the buffer we control with the `MARKER_PAGE_ADDR`. The first qword
        // is used to hijack control flow, so this is where we write the candidate
        // address.
        for qword in 0..18 {
            let idx = qword * std::mem::size_of::<u64>();
            let idx = idx as u64;
            let value = if qword == 0 {
                candidate
            } else {
                MARKER_PAGE_ADDR.u64()
            };

            emu.virt_write(Gva::new(rcx + idx), &value)?;
        }

        Ok(())
    }

    fn post(&mut self, emu: &Emu) -> Result<bool> {
        // What we want here, is to find sequence of instructions that leads to @rip
        // being controlled. To do that, in the |Pre| callback we populate the buffer
        // we control with the `MARKER_PAGE_ADDR` which is basically a magic address
        // that'll trigger a fault if it's access / written to / executed. Basically,
        // we want to force a crash as this might mean that we successfully found a
        // gadget that'll allow us to turn the constrained arbritrary call from above,
        // to an uncontrolled where we don't need to worry about dereferences (cf |mov
        // rax, qword ptr [rax+10h]|).
        //
        // Here is the gadget I ended up using:
        // ```
        // 0:011> u poi(1400aed18)
        // 00007ffb2137ffe0   sub     rsp,38h
        // 00007ffb2137ffe4   test    rcx,rcx
        // 00007ffb2137ffe7   je      00007ffb`21380015
        // 00007ffb2137ffe9   cmp     qword ptr [rcx+10h],0
        // 00007ffb2137ffee   jne     00007ffb`2137fff4
        // ...
        // 00007ffb2137fff4   and     qword ptr [rsp+40h],0
        // 00007ffb2137fffa   mov     rax,qword ptr [rcx+10h]
        // 00007ffb2137fffe   call    qword ptr [mfc140u!__guard_dispatch_icall_fptr (00007ffb`21415b60)]
        // ```
        let mask = 0xffffffff_ffff0000u64;
        let marker = MARKER_PAGE_ADDR.u64();
        let rip_has_marker = (emu.rip() & mask) == (marker & mask);

        Ok(rip_has_marker)
    }
}

#[derive(Default)]
struct Pwn2OwnMiami2022_2 {
    rcx_before: u64,
}

impl Finder for Pwn2OwnMiami2022_2 {
    fn pre(&mut self, emu: &mut Emu, candidate: u64) -> Result<()> {
        // Here, we continue where we left off after the gadget found in |miami1|,
        // where we went from constrained arbitrary call, to unconstrained arbitrary
        // call. At this point, we want to pivot the stack to our heap chunk.
        //
        // ```
        // (1de8.1f6c): Access violation - code c0000005 (first/second chance not available)
        // For analysis of this file, run !analyze -v
        // mfc140u!_guard_dispatch_icall_nop:
        // 00007ffd`57427190 ffe0            jmp     rax {deadbeef`baadc0de}
        //
        // 0:011> dqs @rcx
        // 00000000`1970bf00  00000001`400aed08 GenBroker64+0xaed08
        // 00000000`1970bf08  bbbbbbbb`bbbbbbbb
        // 00000000`1970bf10  deadbeef`baadc0de <-- this is where @rax comes from
        // 00000000`1970bf18  61616161`61616161
        // ```
        self.rcx_before = emu.rcx();

        // Fix-up @rax with the candidate address.
        emu.set_rax(candidate);

        // Fix-up the buffer, where the address of the candidate would be if we were
        // executing it after |miami1|.
        let size_of_u64 = std::mem::size_of::<u64>() as u64;
        let second_qword = size_of_u64 * 2;
        emu.virt_write(Gva::from(self.rcx_before + second_qword), &candidate)?;

        // Overwrite the buffer we control with the `MARKER_PAGE_ADDR`. Skip the first 3
        // qwords, because the first and third ones are already used to hijack flow
        // and the second we skip it as it makes things easier.
        for qword_idx in 3..18 {
            let byte_idx = qword_idx * size_of_u64;
            emu.virt_write(
                Gva::from(self.rcx_before + byte_idx),
                &MARKER_PAGE_ADDR.u64(),
            )?;
        }

        Ok(())
    }

    fn post(&mut self, emu: &Emu) -> Result<bool> {
        // Let's check if we pivoted into our buffer AND that we also are able to
        // start a ROP chain.
        let wanted_landing_start = self.rcx_before + 0x18;
        let wanted_landing_end = self.rcx_before + 0x90;
        let pivoted = has_stack_pivoted_in_range(emu, wanted_landing_start..=wanted_landing_end);

        let mask = 0xffffffff_ffff0000;
        let rip = emu.rip();
        let rip_has_marker = (rip & mask) == (MARKER_PAGE_ADDR.u64() & mask);
        let is_interesting = pivoted && rip_has_marker;

        Ok(is_interesting)
    }
}

#[derive(Parser, Debug)]
#[command(about, author)]
struct CliOpts {
    /// Set an instruction limit
    #[arg(short, long, value_name = "instr limit", default_value_t = 50)]
    limit: u64,
    /// Finder module name
    #[arg(short, long, value_name = "finder name")]
    finder: String,
    /// Profile configuration path
    #[arg(
        short,
        long,
        value_name = "profile path",
        default_value = "win10_ux64.json"
    )]
    profile: PathBuf,
    /// Dump file path
    #[arg(short, long, value_name = "dump file path")]
    dump: PathBuf,
    /// Out file path
    #[arg(short, long, value_name = "output file path")]
    out: PathBuf,
    #[arg(long)]
    overwrite: bool,
    /// Search only specific memory range(s) (0x112233-0x223344,...)
    #[arg(short, long)]
    ranges: Option<String>,
    /// Search only specific memory ranges(s) based on their memory rights (r-*)
    #[arg(short, long)]
    kind: Option<String>,
    /// Stop after finding an amount of results
    #[arg(long)]
    limit_results: Option<usize>,
    /// Turn on the TUI
    #[arg(long)]
    tui: bool,
}

impl CliOpts {
    fn parse_kind(&self) -> Result<Option<String>> {
        let Some(kind) = &self.kind else {
            return Ok(None);
        };

        if kind.len() != 3 {
            return Err(anyhow!("malformed kind"));
        }

        let allowed = "rwx-*";
        let kind = kind.to_lowercase();
        let wellformed = kind.chars().all(|c| allowed.contains(c));
        if wellformed {
            Ok(Some(kind))
        } else {
            Err(anyhow!("malformed kind"))
        }
    }

    fn parse_ranges(&self) -> Result<Option<Vec<Range<u64>>>> {
        trace!("Parsing ranges {:?}", self.ranges);
        let Some(str) = &self.ranges else {
            // If we don't have a range specified, we're done.
            return Ok(None);
        };

        // Strip backticks if there's any. This is convenient if you are copying
        // addresses from WinDbg.
        let str = str.replace('`', "");
        let mut ranges = Vec::new();
        // Ranges are separated by ','.
        for token in str.split(',') {
            // We expect two numbers separated by '-'. If we don't have that, error out.
            let (start, end) = token.split_once('-').context("range malformed")?;
            // Convert the start & end string to `u64`.
            let start = utils::hex_to_str(start)?;
            let end = utils::hex_to_str(end)?;
            // Is the range malformed?
            if start >= end {
                return Err(anyhow!("malformed range"));
            }

            // All right, we got ourselves a range.
            let range = Range { start, end };
            trace!("Adding range {:?}", range);
            ranges.push(range);
        }

        // We're done!
        Ok(Some(ranges))
    }
}

fn main() -> Result<()> {
    // Compile the logging backend only in debug release.
    #[cfg(debug_assertions)]
    env_logger::init();

    let cli_opts = CliOpts::parse();
    let mut finder = match cli_opts.finder.as_str() {
        "miami1" => Box::<Pwn2OwnMiami2022_1>::default() as Box<dyn Finder>,
        "miami2" => Box::<Pwn2OwnMiami2022_2>::default() as Box<dyn Finder>,
        _ => panic!("The finder argument must be either 'miami1', 'miami2', exiting"),
    };

    // If the file exists, let's try to not overwrite a previous session.
    if cli_opts.out.exists() {
        // Deserialize the result file and check if it's empty.
        let read = fs::read(&cli_opts.out)?;
        if !serde_json::from_slice::<Vec<Candidate>>(&read)?.is_empty() {
            // If not empty, we need bail to not overwrite any work unless, the user
            // is using --overwrite.
            print!(
                "The file {} already exists and isn't empty, ",
                cli_opts.out.display()
            );

            if !cli_opts.overwrite {
                println!("exiting to not overwrite previous results");
                return Ok(());
            }

            println!("but overwriting..");
        }
    }

    File::create(&cli_opts.out)?.write_all(b"[]")?;

    let opts = Opts {
        limit: Some(cli_opts.limit),
        profile: cli_opts.profile.clone(),
        dump: cli_opts.dump.clone(),
        ranges: cli_opts.parse_ranges()?,
        kind: cli_opts.parse_kind()?,
        limit_results: cli_opts.limit_results,
    };

    let mut ui: Box<dyn Ui> = if cli_opts.tui {
        Box::new(ui::SuperconsoleUi::new(&cli_opts)?)
    } else {
        Box::new(ui::BasicUi::new(&cli_opts))
    };

    let results = rp_bf::explore(&opts, finder.as_mut(), ui.as_mut())?;
    println!(
        "✓ Finished searching and found a total of {} candidates 🫡",
        results.len()
    );
    Ok(())
}
