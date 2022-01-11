#![recursion_limit = "1024"]

#[macro_use]
extern crate anyhow;
use anyhow::Result as Result;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate rocket;

#[cfg(test)]
extern crate regex;

extern crate hagrid_database as database;

use gettext_macros::init_i18n;

#[cfg(debug_assertions)]
init_i18n!("hagrid", en, de, ja);

#[cfg(not(debug_assertions))]
init_i18n!("hagrid", en, de, fr, it, ja, nb, pl, tr, zh_Hans, ko, nl, ru, ar, sv, es, ro);

mod mail;
mod anonymize_utils;
mod tokens;
mod sealed_state;
mod rate_limiter;
mod dump;
mod counters;
mod i18n;
mod i18n_helpers;
mod gettext_strings;
mod web;
mod template_helpers;

#[launch]
fn rocket() -> _ {
    web::serve().expect("Rocket config must succeed")
}
