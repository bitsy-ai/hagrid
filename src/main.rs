#![feature(proc_macro_hygiene, plugin, decl_macro)]
#![recursion_limit = "1024"]

#[macro_use]
extern crate anyhow;
use anyhow::Result as Result;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;

#[cfg(test)]
extern crate regex;

extern crate hagrid_database as database;

use gettext_macros::init_i18n;

#[cfg(debug_assertions)]
init_i18n!("hagrid", en, de, ja);

#[cfg(not(debug_assertions))]
init_i18n!("hagrid", en, de, fr, it, ja, nb, pl, tr, zh_Hans, ko, nl, ru, ar);

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

fn main() {
    if let Err(e) = web::serve() {
        eprint!("{}", e);
        let mut cause = e.source();
        while let Some(c) = cause {
            eprint!(":\n  {}", c);
            cause = c.source();
        }
        eprintln!();

        ::std::process::exit(2);
    }
}
