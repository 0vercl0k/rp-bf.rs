// Axel '0vercl0k' Souchet - June 22 2023
use crate::emu::EmuStats;
use crate::Candidate;

use anyhow::Result;
use std::ops::Range;

pub trait Ui {
    fn init(&mut self) -> Result<()> {
        Ok(())
    }

    fn found_candidate(&mut self, _candidate: &Candidate) -> Result<()> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn update(
        &mut self,
        _stats: &EmuStats,
        _module_name: &str,
        _candidate: u64,
        _how_many_skipped: u64,
        _how_many_total: u64,
        _nwins: usize,
        _range: &Range<u64>,
    ) -> Result<()> {
        Ok(())
    }

    fn finish(&mut self, _stats: &EmuStats) -> Result<()> {
        Ok(())
    }
}

/// An implementation of [`Ui`] but that doesn't do anything.
#[derive(Default)]
pub struct NoUi;

impl Ui for NoUi {}
