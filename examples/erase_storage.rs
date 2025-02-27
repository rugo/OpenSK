// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]

extern crate lang_items;

use core::fmt::Write;
use ctap2::env::tock::take_storage;
use libtock_drivers::console::Console;
use libtock_drivers::led;
use libtock_drivers::result::FlexUnwrap;
use persistent_store::{Storage, StorageIndex};

libtock_core::stack_size! {0x800}

fn is_page_erased(storage: &dyn Storage, page: usize) -> bool {
    let index = StorageIndex { page, byte: 0 };
    let length = storage.page_size();
    storage
        .read_slice(index, length)
        .unwrap()
        .iter()
        .all(|&x| x == 0xff)
}

fn main() {
    led::get(1).flex_unwrap().on().flex_unwrap(); // red on dongle
    let mut storage = take_storage().unwrap();
    let num_pages = storage.num_pages();
    writeln!(Console::new(), "Erase {} pages of storage:", num_pages).unwrap();
    for page in 0..num_pages {
        write!(Console::new(), "- Page {} ", page).unwrap();
        if is_page_erased(&storage, page) {
            writeln!(Console::new(), "skipped (was already erased).").unwrap();
        } else {
            storage.erase_page(page).unwrap();
            writeln!(Console::new(), "erased.").unwrap();
        }
    }
    writeln!(Console::new(), "Done.").unwrap();
    led::get(1).flex_unwrap().off().flex_unwrap();
    led::get(0).flex_unwrap().on().flex_unwrap(); // green on dongle
}
