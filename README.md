Hagrid
======

Hagrid is a verifying OpenPGP key server.

You can find general instructions and an API documentation at the running
instance at [https://keys.openpgp.org](https://keys.openpgp.org).

License
-------

Hagrid is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Hagrid is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
License for more details.

You should have received a copy of the GNU Affero General Public
License along with Hagrid.  If not, see
<https://www.gnu.org/licenses/>.

Quick Start
-----------

Building Hagrid requires a working nightly Rust toolchain. The
easiest way to get the toolchain is to download [rustup](https://rustup.rs).

Additionally, install external dependencies are required. Get them (on Debian or
Ubuntu) with

```bash
sudo apt install gnutls-bin nettle-dev gcc llvm-dev libclang-dev build-essential pkg-config gettext
```

After rustup and all other dependencies are installed, get the nightly compiler and tools, copy the
config file, and simply compile and run:

```bash
cd hagrid
rustup override set nightly-2020-06-01
cp Rocket.toml.dist Rocket.toml
cargo run
```

This will spawn a web server listening on port 8080.

For deployment, a release build should be used (`cargo build --release`). This
will be statically built, and can be copied anywhere. You will also need to
adjust `Rocket.toml` accordingly.  Hagrid uses `sendmail` for mailing, so you
also need a working local mailer setup.

Reverse Proxy
-------------

Hagrid is designed to defer lookups to reverse proxy server like Nginx.
Lookups via `/vks/v1/by-finingerprint`, `/vks/v1/by-keyid`, and
`/vks/v1/by-email` can be handled by a robust and performant HTTP server.
A sample configuration for nginx is part of the repository (`nginx.conf`,
`hagrid-routes.conf`).
Note that we make use of
[ngx_http_lua_module](https://github.com/openresty/lua-nginx-module) to
perform some request rewrites.

Community
---------

We're in `#hagrid` on OFTC IRC, also reachable via Matrix as `#hagrid:stratum0.org`.
