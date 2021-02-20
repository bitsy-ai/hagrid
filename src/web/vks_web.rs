use crate::Result;

use multipart::server::save::Entries;
use multipart::server::save::SaveResult::*;
use multipart::server::Multipart;

use rocket::http::ContentType;
use rocket::request::Form;
use rocket::Data;
use rocket_i18n::I18n;
use gettext_macros::i18n;

use crate::database::{KeyDatabase, StatefulTokens, Query, Database};
use crate::mail;
use crate::tokens;
use crate::web::{RequestOrigin, MyResponse};
use crate::rate_limiter::RateLimiter;
use crate::i18n_helpers::describe_query_error;

use std::io::Read;
use std::collections::HashMap;

use crate::web::vks;
use crate::web::vks::response::*;

const UPLOAD_LIMIT: u64 = 1024 * 1024; // 1 MiB.

mod forms {
    #[derive(FromForm,Deserialize)]
    pub struct VerifyRequest {
        pub token: String,
        pub address: String,
    }

    #[derive(Deserialize)]
    pub struct UploadRequest {
        pub keytext: String,
    }
}

mod template {
    #[derive(Serialize)]
    pub struct VerifyForm {
        pub token: String,
    }

    #[derive(Serialize)]
    pub struct Verify {
        pub key_fpr: String,
        pub userid: String,
        pub userid_link: String,
    }

    #[derive(Serialize)]
    pub struct Search {
        pub query: String,
        pub fpr: String,
    }

    #[derive(Serialize)]
    pub struct VerificationSent {
        pub key_fpr: String,
        pub key_link: String,
        pub is_revoked: bool,
        pub token: String,
        pub email_published: Vec<String>,
        pub email_unpublished: Vec<UploadUidStatus>,
        pub count_revoked_one: bool,
        pub count_revoked: usize,
        pub count_unparsed_one: bool,
        pub count_unparsed: usize,
    }

    #[derive(Serialize)]
    pub struct UploadOkKey {
        pub key_fpr: String,
        pub key_link: String,
    }

    #[derive(Serialize)]
    pub struct UploadOkMultiple {
        pub keys: Vec<UploadOkKey>,
    }

    #[derive(Serialize)]
    pub struct UploadUidStatus {
        pub address: String,
        pub requested: bool,
    }

}

impl MyResponse {
    fn upload_response_quick(response: UploadResponse, base_uri: &str) -> Self {
        match response {
            UploadResponse::Ok { token, .. } => {
                let uri = uri!(quick_upload_proceed: token);
                let text = format!(
                    "Key successfully uploaded. Proceed with verification here:\n{}{}\n",
                    base_uri,
                    uri
                );
                MyResponse::plain(text)
            },
            UploadResponse::OkMulti { key_fprs } =>
                MyResponse::plain(format!("Uploaded {} keys. For verification, please upload keys individually.\n", key_fprs.len())),
            UploadResponse::Error(error) => MyResponse::bad_request(
                "400-plain", anyhow!(error)),
        }
    }

    fn upload_response(response: UploadResponse) -> Self {
        match response {
            UploadResponse::Ok { token, key_fpr, is_revoked, count_unparsed, status, .. } =>
                Self::upload_ok(token, key_fpr, is_revoked, count_unparsed, status),
            UploadResponse::OkMulti { key_fprs } =>
                Self::upload_ok_multi(key_fprs),
            UploadResponse::Error(error) => MyResponse::bad_request(
                "upload/upload", anyhow!(error)),
        }
    }

    fn upload_ok(
        token: String,
        key_fpr: String,
        is_revoked: bool,
        count_unparsed: usize,
        uid_status: HashMap<String,EmailStatus>,
    ) -> Self {
        let key_link = uri!(search: &key_fpr).to_string();

        let count_revoked = uid_status.iter()
            .filter(|(_,status)| **status == EmailStatus::Revoked)
            .count();

        let mut email_published: Vec<_> = uid_status.iter()
            .filter(|(_,status)| **status == EmailStatus::Published)
            .map(|(email,_)| email.to_string())
            .collect();
        email_published.sort_unstable();

        let mut email_unpublished: Vec<_> = uid_status.into_iter()
            .filter(|(_,status)| *status == EmailStatus::Unpublished ||
                    *status == EmailStatus::Pending)
             .map(|(email,status)|
                 template::UploadUidStatus {
                     address: email.to_string(),
                     requested: status == EmailStatus::Pending,
                 })
            .collect();
        email_unpublished
            .sort_unstable_by(|fst,snd| fst.address.cmp(&snd.address));

        let context = template::VerificationSent {
            is_revoked,
            key_fpr,
            key_link,
            token,
            email_published,
            email_unpublished,
            count_revoked_one: count_revoked == 1,
            count_revoked,
            count_unparsed_one: count_unparsed == 1,
            count_unparsed,
        };
        MyResponse::ok("upload/upload-ok", context)
    }

    fn upload_ok_multi(key_fprs: Vec<String>) -> Self {
        let keys = key_fprs.into_iter()
            .map(|fpr| {
                let key_link = uri!(search: &fpr).to_string();
                template::UploadOkKey {
                    key_fpr: fpr.to_owned(),
                    key_link,
                }
            })
            .collect();

        let context = template::UploadOkMultiple {
            keys,
        };

        MyResponse::ok("upload/upload-ok-multiple", context)
    }
}

#[get("/upload")]
pub fn upload() -> MyResponse {
    MyResponse::ok_bare("upload/upload")
}

#[post("/upload/submit", format = "multipart/form-data", data = "<data>")]
pub fn upload_post_form_data(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data,
) -> MyResponse {
    match process_post_form_data(db, tokens_stateless, rate_limiter, i18n, cont_type, data) {
        Ok(response) => MyResponse::upload_response(response),
        Err(err) => MyResponse::bad_request("upload/upload", err),
    }
}

pub fn process_post_form_data(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    cont_type: &ContentType,
    data: Data,
) -> Result<UploadResponse> {
    // multipart/form-data
    let (_, boundary) = cont_type
        .params()
        .find(|&(k, _)| k == "boundary")
        .ok_or_else(|| anyhow!("`Content-Type: multipart/form-data` \
                                      boundary param not provided"))?;

    process_upload(&db, &tokens_stateless, &rate_limiter, &i18n, data, boundary)
}

#[get("/search?<q>")]
pub fn search(
    db: rocket::State<KeyDatabase>,
    i18n: I18n,
    q: String,
) -> MyResponse {
    match q.parse::<Query>() {
        Ok(query) => key_to_response(db, i18n, q, query),
        Err(e) => MyResponse::bad_request("index", e),
    }
}

fn key_to_response(
    db: rocket::State<KeyDatabase>,
    i18n: I18n,
    query_string: String,
    query: Query,
) -> MyResponse {
    let fp = if let Some(fp) = db.lookup_primary_fingerprint(&query) {
        fp
    } else if query.is_invalid() {
        return MyResponse::bad_request("index", anyhow!(describe_query_error(&i18n, &query)));
    } else {
        return MyResponse::not_found(None, describe_query_error(&i18n, &query));
    };

    let context = template::Search{
        query: query_string,
        fpr: fp.to_string(),
    };

    MyResponse::ok("found", context)
}


#[put("/", data = "<data>")]
pub fn quick_upload(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    request_origin: RequestOrigin,
    data: Data,
) -> MyResponse {
    use std::io::Cursor;

    let mut buf = Vec::default();
    if let Err(error) = std::io::copy(&mut data.open().take(UPLOAD_LIMIT), &mut buf) {
        return MyResponse::bad_request("400-plain", anyhow!(error));
    }

    MyResponse::upload_response_quick(
        vks::process_key(
            &db,
            &i18n,
            &tokens_stateless,
            &rate_limiter,
            Cursor::new(buf)
        ), request_origin.get_base_uri())
}

#[get("/upload/<token>", rank = 2)]
pub fn quick_upload_proceed(
    db: rocket::State<KeyDatabase>,
    request_origin: RequestOrigin,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    token: String,
) -> MyResponse {
    let result = vks::request_verify(
        db, request_origin, token_stateful, token_stateless, mail_service,
        rate_limiter, i18n, token, vec!());
    MyResponse::upload_response(result)
}


#[post("/upload/submit", format = "application/x-www-form-urlencoded", data = "<data>")]
pub fn upload_post_form(
    db: rocket::State<KeyDatabase>,
    tokens_stateless: rocket::State<tokens::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    data: Data,
) -> MyResponse {
    match process_post_form(&db, &tokens_stateless, &rate_limiter, &i18n, data) {
        Ok(response) => MyResponse::upload_response(response),
        Err(err) => MyResponse::bad_request("upload/upload", err),
    }
}

pub fn process_post_form(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    data: Data,
) -> Result<UploadResponse> {
    use rocket::request::FormItems;
    use std::io::Cursor;

    // application/x-www-form-urlencoded
    let mut buf = Vec::default();

    std::io::copy(&mut data.open().take(UPLOAD_LIMIT), &mut buf)?;

    for item in FormItems::from(&*String::from_utf8_lossy(&buf)) {
        let (key, value) = item.key_value();
        let decoded_value = value.url_decode().or_else(|_| {
            Err(anyhow!(
                "`Content-Type: application/x-www-form-urlencoded` \
                    not valid"))
        })?;

        match key.as_str() {
            "keytext" => {
                return Ok(vks::process_key(
                    &db,
                    &i18n,
                    &tokens_stateless,
                    &rate_limiter,
                    Cursor::new(decoded_value.as_bytes())
                ));
            }
            _ => { /* skip */ }
        }
    }

    Err(anyhow!("No keytext found"))
}


fn process_upload(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    data: Data,
    boundary: &str,
) -> Result<UploadResponse> {
    // saves all fields, any field longer than 10kB goes to a temporary directory
    // Entries could implement FromData though that would give zero control over
    // how the files are saved; Multipart would be a good impl candidate though
    match Multipart::with_body(data.open().take(UPLOAD_LIMIT), boundary).save().temp() {
        Full(entries) => {
            process_multipart(db, tokens_stateless, rate_limiter, i18n, entries)
        }
        Partial(partial, _) => {
            process_multipart(db, tokens_stateless, rate_limiter, i18n, partial.entries)
        }
        Error(err) => Err(err.into())
    }
}

fn process_multipart(
    db: &KeyDatabase,
    tokens_stateless: &tokens::Service,
    rate_limiter: &RateLimiter,
    i18n: &I18n,
    entries: Entries,
) -> Result<UploadResponse> {
    match entries.fields.get("keytext") {
        Some(ent) if ent.len() == 1 => {
            let reader = ent[0].data.readable()?;
            Ok(vks::process_key(db, i18n, tokens_stateless, rate_limiter, reader))
        }
        Some(_) => Err(anyhow!("Multiple keytexts found")),
        None => Err(anyhow!("No keytext found")),
    }
}

#[post("/upload/request-verify", format = "application/x-www-form-urlencoded", data="<request>")]
pub fn request_verify_form(
    db: rocket::State<KeyDatabase>,
    request_origin: RequestOrigin,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db, request_origin, token_stateful, token_stateless, mail_service,
        rate_limiter, i18n, token, vec!(address));
    MyResponse::upload_response(result)
}

#[post("/upload/request-verify", format = "multipart/form-data", data="<request>")]
pub fn request_verify_form_data(
    db: rocket::State<KeyDatabase>,
    request_origin: RequestOrigin,
    token_stateful: rocket::State<StatefulTokens>,
    token_stateless: rocket::State<tokens::Service>,
    mail_service: rocket::State<mail::Service>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    request: Form<forms::VerifyRequest>,
) -> MyResponse {
    let forms::VerifyRequest { token, address } = request.into_inner();
    let result = vks::request_verify(
        db, request_origin, token_stateful, token_stateless, mail_service,
        rate_limiter, i18n, token, vec!(address));
    MyResponse::upload_response(result)
}

#[post("/verify/<token>")]
pub fn verify_confirm(
    db: rocket::State<KeyDatabase>,
    token_service: rocket::State<StatefulTokens>,
    rate_limiter: rocket::State<RateLimiter>,
    i18n: I18n,
    token: String,
) -> MyResponse {
    let rate_limit_id = format!("verify-token-{}", &token);
    match vks::verify_confirm(db, &i18n, token_service, token) {
        PublishResponse::Ok { fingerprint, email } => {
            rate_limiter.action_perform(rate_limit_id);
            let userid_link = uri!(search: &email).to_string();
            let context = template::Verify {
                userid: email,
                key_fpr: fingerprint,
                userid_link,
            };

            MyResponse::ok("upload/publish-result", context)
        },
        PublishResponse::Error(error) => {
            let error_msg = if rate_limiter.action_check(rate_limit_id) {
                anyhow!(error)
            } else {
                anyhow!(i18n!(i18n.catalog, "This address has already been verified."))
            };
            MyResponse::bad_request("400", error_msg)
        }
    }
}

#[get("/verify/<token>")]
pub fn verify_confirm_form(
    token: String,
) -> MyResponse {
    MyResponse::ok("upload/verification-form", template::VerifyForm {
        token
    })
}
