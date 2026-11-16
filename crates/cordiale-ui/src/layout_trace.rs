// MIT License
//
// Copyright (c) 2026 Sythos (https://www.sythos.net/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Layout trace of the chat rows.
//!
//! Every chat row reports its index, top and height, in the content of the
//! chat pane, each time the layout changes them. A blank band between two
//! rows is then a number: the distance between the bottom of a row and the
//! top of the next one. A running build prints the trace when the
//! `CORDIALE_LAYOUT_TRACE` variable is `1`. The tests read the same data
//! from a headless window.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use slint::Model as _;

use crate::AppWindow;

/// The measured box of one chat row: top and height, in logical pixels.
pub(crate) type RowBox = (f32, f32);

/// The measured boxes of the rows that the pane has built, by row index.
pub(crate) type RowBoxes = Rc<RefCell<BTreeMap<i32, RowBox>>>;

/// The room between the bottom of one row and the top of the next one.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RowGap {
    /// Index of the upper row.
    pub index: i32,
    /// Distance in logical pixels. A negative value is an overlap.
    pub gap: f32,
}

/// True when the value of `CORDIALE_LAYOUT_TRACE` turns the trace on.
pub(crate) fn trace_enabled(value: Option<&str>) -> bool {
    matches!(value.map(str::trim), Some("1" | "true"))
}

/// The distance between each pair of rows that follow each other by index
/// and whose distance is more than `tolerance` pixels from zero. The pane
/// builds only the rows near the view, so rows with a missing neighbour are
/// not compared.
pub(crate) fn chat_row_gaps(rows: &BTreeMap<i32, RowBox>, tolerance: f32) -> Vec<RowGap> {
    rows.iter()
        .filter_map(|(&index, &(top, height))| {
            let &(next_top, _) = rows.get(&(index + 1))?;
            let gap = next_top - (top + height);
            (gap.abs() > tolerance).then_some(RowGap { index, gap })
        })
        .collect()
}

/// Stores the box of a row, and drops the boxes of rows that the model no
/// longer has.
pub(crate) fn record_row_box(
    rows: &mut BTreeMap<i32, RowBox>,
    index: i32,
    row_box: RowBox,
    row_count: usize,
) {
    rows.insert(index, row_box);
    rows.retain(|&kept, _| usize::try_from(kept).is_ok_and(|kept| kept < row_count));
}

/// Collects the boxes the chat rows report. With `print`, each report and
/// each gap between rows also goes to the standard error output.
pub(crate) fn register_chat_layout_trace(ui: &AppWindow, print: bool) -> RowBoxes {
    let boxes: RowBoxes = Rc::new(RefCell::new(BTreeMap::new()));
    let store = boxes.clone();
    let weak = ui.as_weak();
    ui.on_chat_row_laid_out(move |index, top, height| {
        let Some(ui) = weak.upgrade() else {
            return;
        };
        let mut rows = store.borrow_mut();
        record_row_box(
            &mut rows,
            index,
            (top, height),
            ui.get_chat_lines().row_count(),
        );
        if print {
            eprintln!("chat row {index}: top {top:.1}, height {height:.1}");
            for gap in chat_row_gaps(&rows, 0.5) {
                eprintln!(
                    "chat row {}: {:.1} pixels to the next row",
                    gap.index, gap.gap
                );
            }
        }
    });
    boxes
}
