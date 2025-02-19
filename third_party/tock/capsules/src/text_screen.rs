//! Provides userspace with access to the text screen.
//!
//! Usage:
//! -----
//!
//! You need a screen that provides the `hil::text_screen::TextScreen`
//! trait.
//!
//! ```rust
//! let text_screen = components::text_screen::TextScreenComponent::new(board_kernel, lcd)
//!         .finalize(components::screen_buffer_size!(64));
//! ```

use core::convert::From;
use kernel::common::cells::{OptionalCell, TakeCell};
use kernel::hil;
use kernel::ReturnCode;
use kernel::{AppId, AppSlice, Callback, Driver, Grant, Shared};

/// Syscall driver number.
use crate::driver;
pub const DRIVER_NUM: usize = driver::NUM::TextScreen as usize;

#[derive(Clone, Copy, PartialEq)]
enum TextScreenCommand {
    Idle,
    GetResolution,
    Display,
    NoDisplay,
    Blink,
    NoBlink,
    SetCursor,
    NoCursor,
    ShowCursor,
    Write,
    Clear,
    Home,
}

pub struct App {
    callback: Option<Callback>,
    pending_command: bool,
    shared: Option<AppSlice<Shared, u8>>,
    write_position: usize,
    write_len: usize,
    command: TextScreenCommand,
    data1: usize,
    data2: usize,
}

impl Default for App {
    fn default() -> App {
        App {
            callback: None,
            pending_command: false,
            shared: None,
            write_position: 0,
            write_len: 0,
            command: TextScreenCommand::Idle,
            data1: 1,
            data2: 0,
        }
    }
}

pub struct TextScreen<'a> {
    text_screen: &'a dyn hil::text_screen::TextScreen<'static>,
    apps: Grant<App>,
    current_app: OptionalCell<AppId>,
    buffer: TakeCell<'static, [u8]>,
}

impl<'a> TextScreen<'a> {
    pub fn new(
        text_screen: &'static dyn hil::text_screen::TextScreen,
        buffer: &'static mut [u8],
        grant: Grant<App>,
    ) -> TextScreen<'a> {
        TextScreen {
            text_screen: text_screen,
            apps: grant,
            current_app: OptionalCell::empty(),
            buffer: TakeCell::new(buffer),
        }
    }

    fn enqueue_command(
        &self,
        command: TextScreenCommand,
        data1: usize,
        data2: usize,
        appid: AppId,
    ) -> ReturnCode {
        self.apps
            .enter(appid, |app, _| {
                if self.current_app.is_none() {
                    self.current_app.set(appid);
                    app.command = command;
                    let r = self.do_command(command, data1, data2, appid);
                    if r != ReturnCode::SUCCESS {
                        self.current_app.clear();
                    }
                    r
                } else {
                    if app.pending_command == true {
                        ReturnCode::EBUSY
                    } else {
                        app.pending_command = true;
                        app.command = command;
                        app.write_position = 0;
                        app.data1 = data1;
                        app.data2 = data2;
                        ReturnCode::SUCCESS
                    }
                }
            })
            .unwrap_or_else(|err| err.into())
    }

    fn do_command(
        &self,
        command: TextScreenCommand,
        data1: usize,
        data2: usize,
        appid: AppId,
    ) -> ReturnCode {
        match command {
            TextScreenCommand::GetResolution => {
                let (x, y) = self.text_screen.get_size();
                self.schedule_callback(usize::from(ReturnCode::SUCCESS), x, y);
                self.run_next_command();
                ReturnCode::SUCCESS
            }
            TextScreenCommand::Display => self.text_screen.display_on(),
            TextScreenCommand::NoDisplay => self.text_screen.display_off(),
            TextScreenCommand::Blink => self.text_screen.blink_cursor_on(),
            TextScreenCommand::NoBlink => self.text_screen.blink_cursor_off(),
            TextScreenCommand::SetCursor => self.text_screen.set_cursor(data1, data2),
            TextScreenCommand::NoCursor => self.text_screen.hide_cursor(),
            TextScreenCommand::Write => self
                .apps
                .enter(appid, |app, _| {
                    if data1 > 0 {
                        app.write_position = 0;
                        app.write_len = data1;
                        if let Some(to_write_buffer) = &app.shared {
                            self.buffer.take().map_or(ReturnCode::FAIL, |buffer| {
                                for n in 0..data1 {
                                    buffer[n] = to_write_buffer.as_ref()[n];
                                }
                                self.text_screen.print(buffer, data1)
                            })
                        } else {
                            ReturnCode::ENOMEM
                        }
                    } else {
                        ReturnCode::ENOMEM
                    }
                })
                .unwrap_or_else(|err| err.into()),
            TextScreenCommand::Clear => self.text_screen.clear(),
            TextScreenCommand::Home => self.text_screen.clear(),
            TextScreenCommand::ShowCursor => self.text_screen.show_cursor(),
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn run_next_command(&self) {
        // Check for pending events.
        for app in self.apps.iter() {
            let current_command = app.enter(|app, _| {
                if app.pending_command {
                    app.pending_command = false;
                    self.current_app.set(app.appid());
                    let r = self.do_command(app.command, app.data1, app.data2, app.appid());
                    if r != ReturnCode::SUCCESS {
                        self.current_app.clear();
                    }
                    r == ReturnCode::SUCCESS
                } else {
                    false
                }
            });
            if current_command {
                break;
            }
        }
    }

    fn schedule_callback(&self, data1: usize, data2: usize, data3: usize) {
        self.current_app.take().map(|appid| {
            let _ = self.apps.enter(appid, |app, _| {
                app.pending_command = false;
                app.callback.map(|mut cb| {
                    cb.schedule(data1, data2, data3);
                });
            });
        });
    }
}

impl<'a> Driver for TextScreen<'a> {
    fn subscribe(
        &self,
        subscribe_num: usize,
        callback: Option<Callback>,
        app_id: AppId,
    ) -> ReturnCode {
        match subscribe_num {
            0 => self
                .apps
                .enter(app_id, |app, _| {
                    app.callback = callback;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn command(&self, command_num: usize, data1: usize, data2: usize, appid: AppId) -> ReturnCode {
        match command_num {
            // This driver exists.
            0 => ReturnCode::SUCCESS,
            // Get Resolution
            1 => self.enqueue_command(TextScreenCommand::GetResolution, data1, data2, appid),
            // Display
            2 => self.enqueue_command(TextScreenCommand::Display, data1, data2, appid),
            // No Display
            3 => self.enqueue_command(TextScreenCommand::NoDisplay, data1, data2, appid),
            // Blink
            4 => self.enqueue_command(TextScreenCommand::Blink, data1, data2, appid),
            // No Blink
            5 => self.enqueue_command(TextScreenCommand::NoBlink, data1, data2, appid),
            // Show Cursor
            6 => self.enqueue_command(TextScreenCommand::ShowCursor, data1, data2, appid),
            // No Cursor
            7 => self.enqueue_command(TextScreenCommand::NoCursor, data1, data2, appid),
            // Write
            8 => self.enqueue_command(TextScreenCommand::Write, data1, data2, appid),
            // Clear
            9 => self.enqueue_command(TextScreenCommand::Clear, data1, data2, appid),
            // Home
            10 => self.enqueue_command(TextScreenCommand::Home, data1, data2, appid),
            //Set Curosr
            11 => self.enqueue_command(TextScreenCommand::SetCursor, data1, data2, appid),
            // NOSUPPORT
            _ => ReturnCode::ENOSUPPORT,
        }
    }

    fn allow(
        &self,
        appid: AppId,
        allow_num: usize,
        slice: Option<AppSlice<Shared, u8>>,
    ) -> ReturnCode {
        match allow_num {
            0 => self
                .apps
                .enter(appid, |app, _| {
                    let _ = if let Some(ref s) = slice { s.len() } else { 0 };
                    app.shared = slice;
                    app.write_position = 0;
                    ReturnCode::SUCCESS
                })
                .unwrap_or_else(|err| err.into()),
            _ => ReturnCode::ENOSUPPORT,
        }
    }
}

impl<'a> hil::text_screen::TextScreenClient for TextScreen<'a> {
    fn command_complete(&self, r: ReturnCode) {
        self.schedule_callback(usize::from(r), 0, 0);
        self.run_next_command();
    }

    fn write_complete(&self, buffer: &'static mut [u8], r: ReturnCode) {
        self.buffer.replace(buffer);
        self.schedule_callback(usize::from(r), 0, 0);
        self.run_next_command();
    }
}
