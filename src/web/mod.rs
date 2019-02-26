use rocket;
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status::Custom;
use rocket::response::NamedFile;
use rocket::{Outcome, State};
use rocket_contrib::templates::Template;
use rocket::response::Flash;
use rocket::request::FlashMessage;
use rocket::response::Redirect;

use serde::Serialize;
use handlebars::Handlebars;

use std::path::{Path, PathBuf};

mod upload;

use database::{Database, Polymorphic};
use Result;
use types::{Email, Fingerprint, KeyID};
use Opt;

use std::result;
use std::str::FromStr;

mod queries {
    use std::fmt;
    use types::{Email, Fingerprint, KeyID};

    #[derive(Debug)]
    pub enum Hkp {
        Fingerprint { fpr: Fingerprint, index: bool, machine_readable: bool },
        KeyID { keyid: KeyID, index: bool, machine_readable: bool },
        Email { email: Email, index: bool },
        Invalid{ query: String, },
    }

    impl fmt::Display for Hkp {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                Hkp::Fingerprint{ ref fpr,.. } => write!(f, "{}", fpr.to_string()),
                Hkp::KeyID{ ref keyid,.. } => write!(f, "{}", keyid.to_string()),
                Hkp::Email{ ref email,.. } => write!(f, "{}", email.to_string()),
                Hkp::Invalid{ ref query } => write!(f, "{}", query),
            }
        }
    }
}

#[derive(Responder)]
enum MyResponse {
    #[response(status = 200, content_type = "html")]
    Success(Template),
     #[response(status = 200, content_type = "plain")]
    Plain(String),
    #[response(status = 500, content_type = "html")]
    ServerError(Template),
    NotFound(Flash<Redirect>),
}

impl MyResponse {
    pub fn ok<S: Serialize>(tmpl: &'static str, ctx: S) -> Self {
        MyResponse::Success(Template::render(tmpl, ctx))
    }

    pub fn plain(s: String) -> Self {
        MyResponse::Plain(s)
    }

    pub fn ise(e: failure::Error) -> Self {
        let ctx = templates::FiveHundred{
            error: format!("{}", e),
            version: env!("VERGEN_SEMVER").to_string(),
            commit: env!("VERGEN_SHA_SHORT").to_string(),
        };
        MyResponse::ServerError(Template::render("500", ctx))
    }

    pub fn not_found() -> Self {
        MyResponse::NotFound(Flash::error(Redirect::to("/?"), "Key not found".to_owned()))
    }
}

mod templates {
    #[derive(Serialize)]
    pub struct Verify {
        pub verified: bool,
        pub userid: String,
        pub fpr: String,
        pub domain: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Delete {
        pub token: String,
        pub fpr: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Search {
        pub query: String,
        pub fpr: Option<String>,
        pub armored: Option<String>,
        pub domain: Option<String>,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Confirm {
        pub deleted: bool,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct FiveHundred {
        pub error: String,
        pub commit: String,
        pub version: String,
    }

    #[derive(Serialize)]
    pub struct Index {
        pub error: Option<String>,
        pub commit: String,
        pub version: String,
    }
    #[derive(Serialize)]
    pub struct General {
        pub commit: String,
        pub version: String,
    }
}

struct StaticDir(String);
pub struct Domain(String);
pub struct From(String);
pub struct MailTemplates(Handlebars);

impl<'a, 'r> FromRequest<'a, 'r> for queries::Hkp {
    type Error = ();

    fn from_request(
        request: &'a Request<'r>,
    ) -> request::Outcome<queries::Hkp, ()> {
        use rocket::request::FormItems;
        use std::collections::HashMap;

        let query = request.uri().query().unwrap_or("");
        let fields = FormItems::from(query)
            .map(|item| {
                let (k, v) = item.key_value();

                let key = k.url_decode().unwrap_or_default();
                let value = v.url_decode().unwrap_or_default();
                (key, value)
            })
            .collect::<HashMap<_, _>>();

        if fields.len() >= 2
            && fields
                .get("op")
                .map(|x| x == "get" || x == "index")
                .unwrap_or(false)
        {
            let index = fields.get("op").map(|x| x == "index").unwrap_or(false);
            let machine_readable =
                fields.get("options").map(|x| x.contains("mr"))
                .unwrap_or(false);
            let search = fields.get("search").cloned().unwrap_or_default();
            let maybe_fpr = Fingerprint::from_str(&search);
            let maybe_keyid = KeyID::from_str(&search);

            if let Ok(fpr) = maybe_fpr {
                Outcome::Success(queries::Hkp::Fingerprint {
                    fpr: fpr,
                    index: index,
                    machine_readable: machine_readable,
                })
            } else if let Ok(keyid) = maybe_keyid {
                Outcome::Success(queries::Hkp::KeyID {
                    keyid: keyid,
                    index: index,
                    machine_readable: machine_readable,
                })
            } else {
                match Email::from_str(&search) {
                    Ok(email) => {
                        Outcome::Success(queries::Hkp::Email {
                            email: email,
                            index: index,
                        })
                    }
                    Err(_) => {
                        Outcome::Success(queries::Hkp::Invalid{
                            query: search
                        })
                    }
                }
            }
        } else {
            Outcome::Failure((Status::BadRequest, ()))
        }
    }
}

fn key_to_response<'a>(query: String, domain: String, armored: String,
                       machine_readable: bool) -> MyResponse {
    use sequoia_openpgp::TPK;
    use sequoia_openpgp::parse::Parse;
    use std::convert::TryFrom;

    if machine_readable {
        return MyResponse::plain(armored);
    }

    let key = match TPK::from_bytes(armored.as_bytes()) {
        Ok(key) => key,
        Err(err) => { return MyResponse::ise(err); }
    };
    let fpr = key.primary().fingerprint();
    let context = templates::Search{
        query: query,
        domain: Some(domain),
        fpr: Fingerprint::try_from(fpr).unwrap().to_string().into(),
        armored: armored.into(),
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    MyResponse::ok("found", context)
}

fn key_to_hkp_index<'a>(armored: String) -> MyResponse {
    use sequoia_openpgp::RevocationStatus;
    use sequoia_openpgp::{parse::Parse, TPK};

   let tpk = match TPK::from_bytes(armored.as_bytes()) {
        Ok(tpk) => tpk,
        Err(err) => { return MyResponse::ise(err); }
    };
    let mut out = String::default();
    let p = tpk.primary();

    let ctime = tpk
        .primary_key_signature()
        .and_then(|x| x.signature_creation_time())
        .map(|x| format!("{}", x.to_timespec().sec))
        .unwrap_or_default();
    let extime = tpk
        .primary_key_signature()
        .and_then(|x| x.signature_expiration_time())
        .map(|x| format!("{}", x))
        .unwrap_or_default();
    let is_exp = tpk
        .primary_key_signature()
        .and_then(|x| {
            if x.signature_expired() { "e" } else { "" }.into()
        })
    .unwrap_or_default();
    let is_rev =
        if tpk.revoked(None) != RevocationStatus::NotAsFarAsWeKnow {
            "r"
        } else {
            ""
        };
    let algo: u8 = p.pk_algo().into();

    out.push_str("info:1:1\r\n");
    out.push_str(&format!(
            "pub:{}:{}:{}:{}:{}:{}{}\r\n",
            p.fingerprint().to_string().replace(" ", ""),
            algo,
            p.mpis().bits(),
            ctime,
            extime,
            is_exp,
            is_rev
    ));

    for uid in tpk.userids() {
        let u =
            url::form_urlencoded::byte_serialize(uid.userid().userid())
            .fold(String::default(), |acc, x| acc + x);
        let ctime = uid
            .binding_signature()
            .and_then(|x| x.signature_creation_time())
            .map(|x| format!("{}", x.to_timespec().sec))
            .unwrap_or_default();
        let extime = uid
            .binding_signature()
            .and_then(|x| x.signature_expiration_time())
            .map(|x| format!("{}", x))
            .unwrap_or_default();
        let is_exp = uid
            .binding_signature()
            .and_then(|x| {
                if x.signature_expired() { "e" } else { "" }.into()
            })
        .unwrap_or_default();
        let is_rev = if uid.revoked(None)
            != RevocationStatus::NotAsFarAsWeKnow
            {
                "r"
            } else {
                ""
            };

        out.push_str(&format!(
                "uid:{}:{}:{}:{}{}\r\n",
                u, ctime, extime, is_exp, is_rev
        ));
    }

    MyResponse::plain(out)

}

#[get("/by-fingerprint/<fpr>")]
fn by_fingerprint(db: rocket::State<Polymorphic>, domain: rocket::State<Domain>, fpr: String) -> MyResponse {
    let maybe_key = match Fingerprint::from_str(&fpr) {
        Ok(ref fpr) => db.by_fpr(fpr),
        Err(_) => None,
    };

    match maybe_key {
        Some(armored) => key_to_response(fpr, domain.0.clone(), armored,
                                         true),
        None => MyResponse::not_found(),
    }
}

#[get("/by-email/<email>")]
fn by_email(db: rocket::State<Polymorphic>, domain: rocket::State<Domain>, email: String) -> MyResponse {
    let maybe_key = match Email::from_str(&email) {
        Ok(ref email) => db.by_email(email),
        Err(_) => None,
    };

    match maybe_key {
        Some(armored) => key_to_response(email, domain.0.clone(), armored,
                                         true),
        None => MyResponse::not_found(),

    }
}

#[get("/by-keyid/<kid>")]
fn by_keyid(db: rocket::State<Polymorphic>, domain: rocket::State<Domain>, kid: String) -> MyResponse {
    let maybe_key = match KeyID::from_str(&kid) {
        Ok(ref key) => db.by_kid(key),
        Err(_) => None,
    };

    match maybe_key {
        Some(armored) => key_to_response(kid, domain.0.clone(), armored,
                                         true),
        None => MyResponse::not_found(),
    }
}

#[get("/vks/verify/<token>")]
fn verify(
    db: rocket::State<Polymorphic>, domain: rocket::State<Domain>, token: String,
) -> result::Result<Template, Custom<String>> {
    match db.verify_token(&token) {
        Ok(Some((userid, fpr))) => {
            let context = templates::Verify {
                verified: true,
                domain: domain.0.clone(),
                userid: userid.to_string(),
                fpr: fpr.to_string(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("verify", context))
        }
        Ok(None) | Err(_) => {
            let context = templates::Verify {
                verified: false,
                domain: domain.0.clone(),
                userid: "".into(),
                fpr: "".into(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("verify", context))
        }
    }
}

#[get("/vks/delete/<fpr>")]
fn delete(
    db: rocket::State<Polymorphic>, fpr: String, tmpl: State<MailTemplates>,
    domain: State<Domain>, from: State<From>,
) -> result::Result<Template, Custom<String>> {
    use mail::send_confirmation_mail;

    let fpr = match Fingerprint::from_str(&fpr) {
        Ok(fpr) => fpr,
        Err(_) => {
            return Err(Custom(
                Status::BadRequest,
                "Invalid fingerprint".to_string(),
            ));
        }
    };

    match db.request_deletion(fpr.clone()) {
        Ok((token, uids)) => {
            let context = templates::Delete {
                fpr: fpr.to_string(),
                token: token.clone(),
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            for uid in uids {
                send_confirmation_mail(
                    &uid, &token, &tmpl.0, &domain.0, &from.0,
                )
                .map_err(|err| {
                    Custom(Status::InternalServerError, format!("{:?}", err))
                })?;
            }

            Ok(Template::render("delete", context))
        }
        Err(e) => Err(Custom(Status::InternalServerError, format!("{}", e))),
    }
}

#[get("/vks/confirm/<token>")]
fn confirm(
    db: rocket::State<Polymorphic>, token: String,
) -> result::Result<Template, Custom<String>> {
    match db.confirm_deletion(&token) {
        Ok(true) => {
            let context = templates::Confirm {
                deleted: true,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("confirm", context))
        }
        Ok(false) | Err(_) => {
            let context = templates::Confirm {
                deleted: false,
                version: env!("VERGEN_SEMVER").to_string(),
                commit: env!("VERGEN_SHA_SHORT").to_string(),
            };

            Ok(Template::render("confirm", context))
        }
    }
}

#[get("/assets/<file..>")]
fn files(file: PathBuf, static_dir: State<StaticDir>) -> Option<NamedFile> {
    NamedFile::open(Path::new(&static_dir.0).join("assets").join(file)).ok()
}

#[get("/pks/lookup")]
fn lookup(
    db: rocket::State<Polymorphic>, domain: rocket::State<Domain>, key: Option<queries::Hkp>,
) -> MyResponse {
    let (maybe_key, index, machine_readable) = match key {
        Some(queries::Hkp::Fingerprint { ref fpr, index, machine_readable }) =>
            (db.by_fpr(fpr), index, machine_readable),
        Some(queries::Hkp::KeyID { ref keyid, index, machine_readable }) =>
            (db.by_kid(keyid), index, machine_readable),
        Some(queries::Hkp::Email { ref email, index }) => {
            // XXX: Maybe return 501 Not Implemented if machine_readable
            (db.by_email(email), index, false)
        }
        Some(queries::Hkp::Invalid { query: _ }) => {
            return MyResponse::not_found();
        }
        None => {
            return MyResponse::not_found();
        }
    };
    let query = format!("{}", key.unwrap());

    match maybe_key {
        Some(armored) => {
            if index {
                key_to_hkp_index(armored)
            } else {
                key_to_response(query, domain.0.clone(), armored,
                                machine_readable)
            }
        }
        None => {
            if index {
                MyResponse::plain("info:1:0\r\n".into())
            } else {
                MyResponse::not_found()
            }
        }
    }
}

#[get("/vks/manage")]
fn manage() -> result::Result<Template, Custom<String>> {
    let context = templates::General {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Ok(Template::render("manage", context))
}

fn error_from_flash(flash: &FlashMessage) -> Option<String> {
    if flash.name() == "error" {
        Some(flash.msg().to_owned())
    } else {
        None
    }
}

#[get("/")]
fn root(
    flash: Option<FlashMessage>
) -> Template {
    let context = templates::Index {
        error: flash.and_then(|flash| error_from_flash(&flash)),
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Template::render("index", context)
}

#[get("/about")]
fn about() -> Template {
    let context = templates::General {
        version: env!("VERGEN_SEMVER").to_string(),
        commit: env!("VERGEN_SHA_SHORT").to_string(),
    };

    Template::render("about", context)
}

pub fn serve(opt: &Opt, db: Polymorphic) -> Result<()> {
    use rocket::config::{Config, Environment};
    use std::str::FromStr;

    let (addr, port) = match opt.listen.find(':') {
        Some(p) => {
            let addr = opt.listen[0..p].to_string();
            let port = if p < opt.listen.len() - 1 {
                u16::from_str(&opt.listen[p + 1..]).ok().unwrap_or(8080)
            } else {
                8080
            };

            (addr, port)
        }
        None => (opt.listen.to_string(), 8080),
    };

    let config = Config::build(Environment::Staging)
        .address(addr)
        .port(port)
        .workers(2)
        .root(opt.base.clone())
        .extra(
            "template_dir",
            opt.base
                .join("templates")
                .to_str()
                .ok_or(failure::err_msg("Template path invalid"))?,
        )
        .extra(
            "static_dir",
            opt.base.join("public").to_str()
                .ok_or(failure::err_msg("Static path invalid"))?,
        )
        .extra("domain", opt.domain.clone())
        .extra("from", opt.from.clone())
        .finalize()?;

    rocket_factory(rocket::custom(config), db).launch();
    Ok(())
}

fn rocket_factory(rocket: rocket::Rocket, db: Polymorphic) -> rocket::Rocket {
    let routes = routes![
        // infra
        root,
        manage,
        files,
        // nginx-supported lookup
        by_email,
        by_fingerprint,
        by_keyid,
        // HKP
        lookup,
        upload::vks_publish,
        upload::vks_publish_submit,
        // verification & deletion
        verify,
        delete,
        confirm,
        // about
        about,
    ];

    rocket
        .attach(Template::fairing())
        .attach(AdHoc::on_attach("static_dir", |rocket| {
            let static_dir =
                rocket.config().get_str("static_dir").unwrap().to_string();

            Ok(rocket.manage(StaticDir(static_dir)))
        }))
        .attach(AdHoc::on_attach("domain", |rocket| {
            let domain = rocket.config().get_str("domain").unwrap().to_string();

            Ok(rocket.manage(Domain(domain)))
        }))
        .attach(AdHoc::on_attach("from", |rocket| {
            let from = rocket.config().get_str("from").unwrap().to_string();

            Ok(rocket.manage(From(from)))
        }))
        .attach(AdHoc::on_attach("mail_templates", |rocket| {
            let dir: PathBuf = rocket
                .config()
                .get_str("template_dir")
                .unwrap()
                .to_string()
                .into();
            let confirm_html = dir.join("confirm-email-html.hbs");
            let confirm_txt = dir.join("confirm-email-txt.hbs");
            let verify_html = dir.join("verify-email-html.hbs");
            let verify_txt = dir.join("verify-email-txt.hbs");
            let mut handlebars = Handlebars::new();

            handlebars
                .register_template_file("confirm-html", confirm_html)
                .unwrap();
            handlebars
                .register_template_file("confirm-txt", confirm_txt)
                .unwrap();
            handlebars
                .register_template_file("verify-html", verify_html)
                .unwrap();
            handlebars
                .register_template_file("verify-txt", verify_txt)
                .unwrap();

            Ok(rocket.manage(MailTemplates(handlebars)))
        }))
        .mount("/", routes)
        .manage(db)
}

#[cfg(test)]
mod tests {
    use fs_extra;
    use tempfile::{tempdir, TempDir};
    use super::rocket;
    use rocket::local::Client;
    use rocket::http::Status;
    use rocket::http::ContentType;

    use database::*;
    use super::*;

    /// Creates a configuration and empty state dir for testing purposes.
    ///
    /// Note that you need to keep the returned TempDir alive for the
    /// duration of your test.  To debug the test, mem::forget it to
    /// prevent cleanup.
    fn configuration() -> Result<(TempDir, rocket::Config)> {
        use rocket::config::{Config, Environment};

        let root = tempdir()?;
        fs_extra::copy_items(&vec!["dist/templates"], &root,
                             &fs_extra::dir::CopyOptions::new())?;

        let config = Config::build(Environment::Staging)
            .root(root.path().to_path_buf())
            .extra(
                "template_dir",
                root.path().join("templates").to_str()
                    .ok_or(failure::err_msg("Template path invalid"))?,
            )
            .extra(
                "static_dir",
                root.path().join("public").to_str()
                    .ok_or(failure::err_msg("Static path invalid"))?,
            )
            .extra("domain", "domain")
            .extra("from", "from")
            .finalize()?;
        Ok((root, config))
    }

    #[test]
    fn basics() {
        let (_tmpdir, config) = configuration().unwrap();

        let db = Polymorphic::Filesystem(
            Filesystem::new(config.root().unwrap().to_path_buf()).unwrap());
        let rocket = rocket_factory(rocket::custom(config), db);
        let client = Client::new(rocket).expect("valid rocket instance");

        // Check that we see the landing page.
        let mut response = client.get("/").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Hagrid"));

        // Check that we see the privacy policy.
        let mut response = client.get("/about").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::HTML));
        assert!(response.body_string().unwrap().contains("Public Key Data"));
    }
}
