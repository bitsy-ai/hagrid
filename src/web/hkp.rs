use std::fmt;

use std::time::SystemTime;
use std::collections::HashMap;

use rocket::Data;
use rocket::Outcome;
use rocket::http::{ContentType, Status};
use rocket::request::{self, Request, FromRequest};
use rocket::http::uri::Uri;
use rocket_i18n::I18n;

use crate::database::{Database, Query, KeyDatabase};
use crate::database::types::{Email, Fingerprint, KeyID};

use crate::rate_limiter::RateLimiter;

use crate::tokens;

use crate::web;
use crate::mail;
use crate::web::{HagridState, RequestOrigin, MyResponse, vks_web};
use crate::web::vks::response::UploadResponse;
use crate::web::vks::response::EmailStatus;

#[derive(Debug)]
pub enum Hkp {
    Fingerprint { fpr: Fingerprint, index: bool },
    KeyID { keyid: KeyID, index: bool },
    ShortKeyID { query: String, index: bool },
    Email { email: Email, index: bool },
    Invalid { query: String, },
}

impl fmt::Display for Hkp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hkp::Fingerprint{ ref fpr,.. } => write!(f, "{}", fpr),
            Hkp::KeyID{ ref keyid,.. } => write!(f, "{}", keyid),
            Hkp::Email{ ref email,.. } => write!(f, "{}", email),
            Hkp::ShortKeyID{ ref query,.. } => write!(f, "{}", query),
            Hkp::Invalid{ ref query } => write!(f, "{}", query),
        }
    }
}

impl<'a, 'r> FromRequest<'a, 'r> for Hkp {
    type Error = ();

    fn from_request(request: &'a Request<'r>) -> request::Outcome<Hkp, ()> {
        use std::str::FromStr;
        use rocket::request::FormItems;

        let query = request.uri().query().unwrap_or("");
        let fields = FormItems::from(query)
            .map(|item| {
                let (k, v) = item.key_value();

                let key = k.url_decode().unwrap_or_default();
                let value = v.url_decode().unwrap_or_default();
                (key, value)
            })
            .collect::<HashMap<_, _>>();

        if fields.contains_key("search")
            && fields
            .get("op")
            .map(|x| x == "get" || x == "index")
            .unwrap_or(false)
        {
            let index = fields.get("op").map(|x| x == "index").unwrap_or(false);
            let search = fields.get("search").cloned().unwrap_or_default();
            let maybe_fpr = Fingerprint::from_str(&search);
            let maybe_keyid = KeyID::from_str(&search);

            let looks_like_short_key_id = !search.contains('@') &&
                (search.starts_with("0x") && search.len() < 16 || search.len() == 8);
            if looks_like_short_key_id {
                Outcome::Success(Hkp::ShortKeyID {
                    query: search,
                    index: index,
                })
            } else if let Ok(fpr) = maybe_fpr {
                Outcome::Success(Hkp::Fingerprint {
                    fpr: fpr,
                    index: index,
                })
            } else if let Ok(keyid) = maybe_keyid {
                Outcome::Success(Hkp::KeyID {
                    keyid: keyid,
                    index: index,
                })
            } else {
                match Email::from_str(&search) {
                    Ok(email) => {
                        Outcome::Success(Hkp::Email {
                            email: email,
                            index: index,
                        })
                    }
                    Err(_) => {
                        Outcome::Success(Hkp::Invalid{
                            query: search
                        })
                    }
                }
            }
        } else if fields.get("op").map(|x| x == "vindex"
                                       || x.starts_with("x-"))
            .unwrap_or(false)
        {
            Outcome::Failure((Status::NotImplemented, ()))
        } else {
            Outcome::Failure((Status::BadRequest, ()))
        }
    }
}

#[post("/pks/add", format = "multipart/form-data", data = "<data>")]
pub fn pks_add_form_data(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data,
) -> MyResponse {
    match vks_web::process_post_form_data(db, tokens_stateless, rate_limiter, i18n, cont_type, data) {
        Ok(_) => MyResponse::plain("Ok".into()),
        Err(err) => MyResponse::ise(err),
    }
}

#[post("/pks/add", format = "application/x-www-form-urlencoded", data = "<data>")]
pub fn pks_add_form(
    request_origin: RequestOrigin,
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    mail_service: rocket::State<mail::Service>,
    i18n: I18n,
    data: Data,
) -> MyResponse {
    match vks_web::process_post_form(&db, &tokens_stateless, &rate_limiter, &i18n, data) {
        Ok(UploadResponse::Ok { is_new_key, key_fpr, primary_uid, token, status, .. }) => {
            let msg = pks_add_ok(&request_origin, &mail_service, &rate_limiter, token, status, is_new_key, key_fpr, primary_uid);
            MyResponse::plain(msg)
        }
        Ok(_) => {
            let msg = format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = request_origin.get_base_uri());
            MyResponse::plain(msg)
        }
        Err(err) => MyResponse::ise(err),
    }
}

fn pks_add_ok(
    request_origin: &RequestOrigin,
    mail_service: &mail::Service,
    rate_limiter: &RateLimiter,
    token: String,
    status: HashMap<String, EmailStatus>,
    is_new_key: bool,
    key_fpr: String,
    primary_uid: Option<Email>,
) -> String {
    if primary_uid.is_none() {
        return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = request_origin.get_base_uri())
    }
    let primary_uid = primary_uid.unwrap();

    if is_new_key {
        if send_welcome_mail(&request_origin, &mail_service, key_fpr, &primary_uid, token) {
            rate_limiter.action_perform(format!("hkp-sent-{}", &primary_uid));
            return format!("Upload successful. This is a new key, a welcome email has been sent.");
        }
        return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = request_origin.get_base_uri())
    }

    let has_unverified = status.iter().any(|(_, v)| *v == EmailStatus::Unpublished);
    if !has_unverified {
        return format!("Upload successful.");
    }

    // We send this out on the *second* time the key is uploaded (within one ratelimit period).
    let uploaded_repeatedly = !rate_limiter.action_perform(format!("hkp-upload-{}", &key_fpr));
    if uploaded_repeatedly && rate_limiter.action_perform(format!("hkp-sent-{}", &primary_uid)) {
        if send_upload_mail(&request_origin, &mail_service, key_fpr, &primary_uid, token) {
            return format!("Upload successful. An upload information email has been sent.");
        }
    }
    return format!("Upload successful. Please note that identity information will only be published after verification. See {baseuri}/about/usage#gnupg-upload", baseuri = request_origin.get_base_uri())
}

fn send_upload_mail(
    request_origin: &RequestOrigin,
    mail_service: &mail::Service,
    fpr: String,
    primary_uid: &Email,
    token: String,
) -> bool {
    mail_service.send_upload(request_origin.get_base_uri(), fpr, primary_uid, &token).is_ok()
}

fn send_welcome_mail(
    request_origin: &RequestOrigin,
    mail_service: &mail::Service,
    fpr: String,
    primary_uid: &Email,
    token: String,
) -> bool {
    mail_service.send_welcome(request_origin.get_base_uri(), fpr, primary_uid, &token).is_ok()
}

#[get("/pks/lookup")]
pub fn pks_lookup(
    state: rocket::State<HagridState>,
    db: rocket::State<KeyDatabase>,
    key: Hkp
) -> MyResponse {
    let (query, index) = match key {
        Hkp::Fingerprint { fpr, index } =>
            (Query::ByFingerprint(fpr), index),
        Hkp::KeyID { keyid, index } =>
            (Query::ByKeyID(keyid), index),
        Hkp::Email { email, index } => {
            (Query::ByEmail(email), index)
        }
        Hkp::ShortKeyID { query: _, .. } => {
            return MyResponse::bad_request_plain("Search by short key ids is not supported, sorry!");
        }
        Hkp::Invalid { query: _ } => {
            return MyResponse::bad_request_plain("Invalid search query!");
        }
    };

    if index {
        key_to_hkp_index(db, query)
    } else {
        web::key_to_response_plain(state, db, query)
    }
}

#[get("/pks/internal/index/<query_string>")]
pub fn pks_internal_index(
    db: rocket::State<KeyDatabase>,
    query_string: String,
) -> MyResponse {
    match query_string.parse() {
        Ok(query) => key_to_hkp_index(db, query),
        Err(_) => MyResponse::bad_request_plain("Invalid search query!")
    }
}

fn key_to_hkp_index(db: rocket::State<KeyDatabase>, query: Query)
                        -> MyResponse {
    use sequoia_openpgp::types::RevocationStatus;
    use sequoia_openpgp::policy::StandardPolicy;

    let tpk = match db.lookup(&query) {
        Ok(Some(tpk)) => tpk,
        Ok(None) => return MyResponse::not_found_plain(query.describe_error()),
        Err(err) => { return MyResponse::ise(err); }
    };
    let mut out = String::default();
    let p = tpk.primary_key();

    let ref policy = StandardPolicy::new();

    let ctime = format!("{}", p.creation_time().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs());
    let is_rev =
        if tpk.revocation_status(policy, None) != RevocationStatus::NotAsFarAsWeKnow {
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
            p.mpis().bits().unwrap_or(0),
            ctime,
            "",
            "",
            is_rev
    ));

    for uid in tpk.userids() {
        let uidstr = uid.userid().to_string();
        let u = Uri::percent_encode(&uidstr);
        let ctime = uid
            .binding_signature(policy, None)
            .ok()
            .and_then(|x| x.signature_creation_time())
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|x| format!("{}", x.as_secs()))
            .unwrap_or_default();
        let is_rev = if uid.revocation_status(policy, None)
            != RevocationStatus::NotAsFarAsWeKnow
            {
                "r"
            } else {
                ""
            };

        out.push_str(&format!(
                "uid:{}:{}:{}:{}{}\r\n",
                u, ctime, "", "", is_rev
        ));
    }

    MyResponse::plain(out)
}

#[cfg(test)]
mod tests {
    use rocket::http::Status;
    use rocket::http::ContentType;

    use sequoia_openpgp::serialize::Serialize;

    use crate::web::tests::*;
    use crate::mail::pop_mail;

    #[test]
    fn hkp() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // eprintln!("LEAKING: {:?}", tmpdir);
        // ::std::mem::forget(tmpdir);

        // Generate a key and upload it.
        let tpk = build_cert("foo@invalid.example.com");

        // Prepare to /pks/add
        let mut armored = Vec::new();
        {
            use sequoia_openpgp::armor::{Writer, Kind};
            let mut w = Writer::new(&mut armored, Kind::PublicKey)
                .unwrap();
            tpk.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        let mut post_data = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored) {
            post_data.push_str(enc);
        }

        // Add!
        let mut response = client.post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.body_string().unwrap();
        eprintln!("response: {}", body);

        // Check that we get a welcome mail
        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_some());

        // Add!
        let mut response = client.post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let body = response.body_string().unwrap();
        eprintln!("response: {}", body);

        // No second email right after the welcome one!
        let upload_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(upload_mail.is_none());

        // We should not be able to look it up by email address.
        check_null_responses_by_email(&client, "foo@invalid.example.com");

        // And check that we can get it back via the machine readable
        // interface.
        check_mr_responses_by_fingerprint(&client, &tpk, 0);

        // And check that we can see the human-readable result page.
        check_hr_responses_by_fingerprint(&client, &tpk, 0);

        // Upload the same key again, make sure the welcome mail is not sent again
        let response = client.post("/pks/add")
            .body(post_data.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_none());

        assert_consistency(client.rocket());
    }

    #[test]
    fn hkp_add_two() {
        let (tmpdir, client) = client().unwrap();
        let filemail_into = tmpdir.path().join("filemail");

        // Generate two keys and upload them.
        let tpk_0 = build_cert("foo@invalid.example.com");
        let tpk_1 = build_cert("bar@invalid.example.com");

        // Prepare to /pks/add
        let mut armored_first = Vec::new();
        let mut armored_both = Vec::new();
        {
            use sequoia_openpgp::armor::{Writer, Kind};
            let mut w = Writer::new(&mut armored_both, Kind::PublicKey).unwrap();
            tpk_0.serialize(&mut w).unwrap();
            tpk_1.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        {
            use sequoia_openpgp::armor::{Writer, Kind};
            let mut w = Writer::new(&mut armored_first, Kind::PublicKey).unwrap();
            tpk_0.serialize(&mut w).unwrap();
            w.finalize().unwrap();
        }
        let mut post_data_first = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored_first) {
            post_data_first.push_str(enc);
        }
        let mut post_data_both = String::from("keytext=");
        for enc in url::form_urlencoded::byte_serialize(&armored_both) {
            post_data_both.push_str(enc);
        }

        // Add!
        let response = client.post("/pks/add")
            .body(post_data_both.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        // Check that there is no welcome mail (since we uploaded two)
        let welcome_mail = pop_mail(filemail_into.as_path()).unwrap();
        assert!(welcome_mail.is_none());

        // Add the first again
        let response = client.post("/pks/add")
            .body(post_data_first.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let upload_mail_1 = pop_mail(filemail_into.as_path()).unwrap();
        assert!(upload_mail_1.is_none());

        // Add the first again a second time - we should get an upload mail
        let response = client.post("/pks/add")
            .body(post_data_first.as_bytes())
            .header(ContentType::Form)
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let upload_mail_2 = pop_mail(filemail_into.as_path()).unwrap();
        assert!(upload_mail_2.is_some());

        check_mr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_mr_responses_by_fingerprint(&client, &tpk_1, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_0, 0);
        check_hr_responses_by_fingerprint(&client, &tpk_1, 0);

        assert_consistency(client.rocket());
    }
}
