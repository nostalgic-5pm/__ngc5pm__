use crate::domain::value_object::public_id::PublicId;
use derive_more::Display;
use kernel::error::app_error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::{cmp::max, str::FromStr};
use tracing as log;

const ROWS: usize = 9;
const COLS: usize = 23;
const TOP_MSG: &str = "[your_id]";
const BOTTOM_MSG: &str = "[SHA3-256]";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Display)]
#[display("{value}")]
pub struct RandomArt {
    value: String,
}

impl RandomArt {
    pub fn generate(input: &PublicId) -> AppResult<Self> {
        let fp = calculate_sha3_256(input.as_ref().as_str().as_bytes());
        let grid = generate_drunken_bishop_grid(&fp);
        let art = render_drunken_bishop_art(&grid.grid, grid.start_position, grid.end_position);
        Ok(Self { value: art })
    }

    #[inline]
    pub fn from_db<S: AsRef<str>>(s: S) -> Self {
        Self {
            value: s.as_ref().to_string(),
        }
    }

    #[inline]
    pub fn into_db(&self) -> String {
        self.value.clone()
    }
}

/// 32-byte SHA3-256
fn calculate_sha3_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&out);
    fp
}

#[derive(Debug)]
struct DrunkenBishopGrid {
    grid: Vec<Vec<u8>>,
    start_position: (usize, usize),
    end_position: (usize, usize),
}

fn generate_drunken_bishop_grid(data: &[u8]) -> DrunkenBishopGrid {
    let mut grid = vec![vec![0u8; COLS]; ROWS];
    let mut row = ROWS / 2;
    let mut col = COLS / 2;
    let start_position = (row, col);

    for &byte in data {
        let mut bits = byte;
        for _ in 0..4 {
            let dx = if bits & 0x01 != 0 { 1isize } else { -1isize };
            let dy = if bits & 0x02 != 0 { 1isize } else { -1isize };
            row = (row as isize + dy).clamp(0, (ROWS - 1) as isize) as usize;
            col = (col as isize + dx).clamp(0, (COLS - 1) as isize) as usize;
            grid[row][col] = grid[row][col].saturating_add(1);
            bits >>= 2;
        }
    }

    DrunkenBishopGrid {
        grid,
        start_position,
        end_position: (row, col),
    }
}

fn make_border(width: usize, msg: &str) -> String {
    let msgw = msg.chars().count();
    if msgw >= width {
        // メッセージが幅より長い場合でも崩れないように
        return format!("+{msg}+");
    }
    let pad = width - msgw;
    let left = pad / 2;
    let right = pad - left;
    format!("+{}{}{}+", "-".repeat(left), msg, "-".repeat(right))
}

fn render_drunken_bishop_art(
    grid: &[Vec<u8>],
    start_position: (usize, usize),
    end_position: (usize, usize),
) -> String {
    let rows = grid.len();
    let cols = if rows > 0 { grid[0].len() } else { 0 };
    let (sr, sc) = start_position;
    let (er, ec) = end_position;

    let symbols = [
        ' ', '.', 'o', '+', '=', '*', 'B', 'O', 'X', '@', '%', '&', '#', '/', '^',
    ];
    let mut lines = Vec::with_capacity(rows + 2);
    lines.push(make_border(max(cols, COLS), TOP_MSG));

    for (r, row_cells) in grid.iter().enumerate() {
        let mut line = String::with_capacity(cols + 2);
        line.push('|');
        for (c, &count) in row_cells.iter().enumerate() {
            let ch = if (r, c) == (sr, sc) && (r, c) == (er, ec) {
                'E'
            } else if (r, c) == (sr, sc) {
                'S'
            } else if (r, c) == (er, ec) {
                'E'
            } else {
                *symbols
                    .get(count as usize)
                    .unwrap_or(symbols.last().unwrap())
            };
            line.push(ch);
        }
        line.push('|');
        lines.push(line);
    }

    lines.push(make_border(max(cols, COLS), BOTTOM_MSG));
    lines.join("\n")
}

impl FromStr for RandomArt {
    type Err = AppError;

    fn from_str(s: &str) -> AppResult<Self> {
        if s.is_empty() {
            log::error!(
                target: "domain",
                "[INVALID][RANDOM_ART] RandomArt is not empty",
            );
            return Err(AppError::bad_request("RandomArt cannot be empty"));
        }
        Ok(Self::from_db(s))
    }
}
#[cfg(test)]
mod ut {
    use super::*;

    #[test]
    fn random_art_basic() {
        let pid = PublicId::new();
        let art = RandomArt::generate(&pid).unwrap();
        println!("Generated Art:\n{}", art.value);
        assert!(art.into_db().contains('\n'));
    }
}
