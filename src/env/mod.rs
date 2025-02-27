// Copyright 2022 Google LLC
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

use crate::api::attestation_store::AttestationStore;
use crate::api::connection::HidConnection;
use crate::api::customization::Customization;
use crate::api::firmware_protection::FirmwareProtection;
use crate::api::key_store::KeyStore;
use crate::api::upgrade_storage::UpgradeStorage;
use crate::api::user_presence::UserPresence;
use persistent_store::{Storage, Store};
use rng256::Rng256;

#[cfg(feature = "std")]
pub mod test;
pub mod tock;

/// Describes what CTAP needs to function.
pub trait Env {
    type Rng: Rng256;
    type UserPresence: UserPresence;
    type Storage: Storage;
    type KeyStore: KeyStore;
    type UpgradeStorage: UpgradeStorage;
    type FirmwareProtection: FirmwareProtection;
    type Write: core::fmt::Write;
    type Customization: Customization;
    type HidConnection: HidConnection;
    type AttestationStore: AttestationStore;

    fn rng(&mut self) -> &mut Self::Rng;
    fn user_presence(&mut self) -> &mut Self::UserPresence;
    fn store(&mut self) -> &mut Store<Self::Storage>;
    fn key_store(&mut self) -> &mut Self::KeyStore;
    fn attestation_store(&mut self) -> &mut Self::AttestationStore;

    /// Returns the upgrade storage instance.
    ///
    /// Upgrade storage is optional, so implementations may return `None`. However, implementations
    /// should either always return `None` or always return `Some`.
    fn upgrade_storage(&mut self) -> Option<&mut Self::UpgradeStorage>;

    fn firmware_protection(&mut self) -> &mut Self::FirmwareProtection;

    /// Creates a write instance for debugging.
    ///
    /// This API doesn't return a reference such that drop may flush. This matches the Tock
    /// environment. Non-Tock embedded environments should use the defmt feature (to be implemented
    /// using the defmt crate) and ignore this API. Non-embedded environments may either use this
    /// API or use the log feature (to be implemented using the log crate).
    fn write(&mut self) -> Self::Write;

    fn customization(&self) -> &Self::Customization;

    /// I/O connection for sending packets implementing CTAP HID protocol.
    fn main_hid_connection(&mut self) -> &mut Self::HidConnection;

    /// I/O connection for sending packets implementing vendor extensions to CTAP HID protocol.
    #[cfg(feature = "vendor_hid")]
    fn vendor_hid_connection(&mut self) -> &mut Self::HidConnection;
}
