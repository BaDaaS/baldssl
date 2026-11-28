//! The run-time choice of a profile.

use super::{Profile, WithProfile};
use crate::Compat;

/// The line of the profile it is applied to.
struct Line;

impl WithProfile for Line {
    type Output = Compat;

    fn call<P>(self) -> Compat
    where
        P: Profile,
    {
        P::COMPAT
    }
}

/// `run` applies the profile the line names: `run(c)` sees `c` for every
/// line compiled in, and refuses the others.
#[test]
fn run_is_the_named_profile() {
    for compat in Compat::ALL {
        let compiled = match compat {
            Compat::V30 => cfg!(feature = "openssl-3-0"),
            Compat::V3 => cfg!(feature = "openssl-3-5"),
            Compat::V36 => cfg!(feature = "openssl-3-6"),
            Compat::V4 => cfg!(feature = "openssl-4"),
        };
        match compat.run(Line) {
            Ok(seen) => assert!(compiled && seen == compat, "{compat:?}"),
            Err(_) => assert!(!compiled, "{compat:?}"),
        }
    }
}
