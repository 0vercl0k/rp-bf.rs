// Axel '0vercl0k' Souchet - June 4 2023
//! This module contains various utilities used throughout the codebase.
use std::fmt::Display;

use conv::ValueInto;

use crate::error::Result;

/// Type that implements [`Display`] to print out a size in human form.
///
/// # Examples
///
/// ```
/// # use rp_bf::utils::ToHuman;
/// # fn main() {
/// println!("{}", 1337usize.bytes_human());
/// println!("{}", 132929292u64.number_human());
/// # }
/// ```
pub struct BytesToHuman<T>(T);

impl<T> Display for BytesToHuman<T>
where
    T: Copy + ValueInto<f64>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut unit = "b";
        let mut size: f64 = self.0.value_into().expect("T -> f64 conversion failed");
        let k = 1_024f64;
        let m = k * k;
        let g = m * k;
        if size >= g {
            size /= g;
            unit = "gb"
        } else if size >= m {
            size /= m;
            unit = "mb";
        } else if size >= k {
            size /= k;
            unit = "kb";
        }

        write!(f, "{:.1}{}", size, unit)
    }
}

/// Type that implements [`Display`] to print out a size in human form.
pub struct NumberToHuman<T>(T);

impl<T> Display for NumberToHuman<T>
where
    T: Copy + ValueInto<f64>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut unit = "";
        let mut size: f64 = self.0.value_into().expect("T -> f64 conversion failed");
        let k = 1_000f64;
        let m = k * k;
        let b = m * k;
        if size >= b {
            size /= b;
            unit = "b"
        } else if size >= m {
            size /= m;
            unit = "m";
        } else if size >= k {
            size /= k;
            unit = "k";
        }

        write!(f, "{:.1}{}", size, unit)
    }
}

/// This trait adds convenient functions to display data for Humans. It is the
/// glue between the generic types [`BytesToHuman<T>`], [`NumberToHuman<T>`],
/// etc.
///
/// # Examples
///
/// ```
/// # use rp_bf::utils::ToHuman;
/// # fn main() {
/// println!("{}", 1337usize.bytes_human());
/// println!("{}", 132929292u64.number_human());
/// # }
/// ```
pub trait ToHuman: Sized + Copy {
    fn bytes_human(&self) -> BytesToHuman<Self> {
        BytesToHuman(*self)
    }

    fn number_human(&self) -> NumberToHuman<Self> {
        NumberToHuman(*self)
    }
}

impl ToHuman for u64 {}

impl ToHuman for usize {}

/// Calculate a percentage value.
///
/// # Examples
///
/// ```
/// # use rp_bf::utils::percentage;
/// # fn main() {
/// let nightynine = percentage(99, 100);
/// assert_eq!(nightynine, 99);
/// let result = std::panic::catch_unwind(|| percentage(1337, 0));
/// assert!(result.is_err());
/// # }
/// ```
pub fn percentage(how_many: u64, how_many_total: u64) -> u32 {
    assert!(
        how_many_total > 0,
        "{how_many_total} needs to be bigger than 0"
    );
    ((how_many * 1_00) / how_many_total) as u32
}

/// Convert an hexadecimal string to an integer.
///
/// # Examples
///
/// ```
/// # use rp_bf::utils::hex_to_str;
/// # fn main() {
/// assert_eq!(hex_to_str("0x1337").unwrap(), 0x1337);
/// assert_eq!(hex_to_str("1337").unwrap(), 0x1337);
/// assert!(hex_to_str("hello").is_err());
/// # }
/// ```
pub fn hex_to_str(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(u64::from_str_radix(s, 16)?)
}
