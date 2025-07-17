// Copyright 2022-2024, The Deezel Developers.
// Deezel is a part of the Deezel project.
// Deezel is a free software, licensed under the MIT license.

#[cfg(feature = "std")]
pub use std::io::Cursor;

#[cfg(not(feature = "std"))]
pub use no_std_io::io::Cursor;