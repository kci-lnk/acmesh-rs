use super::*;
use axum::{Form, Router, http::StatusCode, routing::post};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};

const NAME: &str = "_acme-challenge.api.example.co.uk";
const USERNAME: &str = "user+name&=测试";
const KEY: &str = "0123456789abcdef0123456789abcdef";

struct Server {
    endpoint: String,
    requests: Arc<Mutex<Vec<HashMap<String, String>>>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn new(replies: Vec<(StatusCode, String)>) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let capture = requests.clone();
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!(
            "http://{}/API/v2/domain/dns/",
            listener.local_addr().unwrap()
        );
        let app = Router::new().route(
            "/API/v2/domain/dns/",
            post(move |Form(form): Form<HashMap<String, String>>| {
                let capture = capture.clone();
                let replies = replies.clone();
                async move {
                    capture.lock().unwrap().push(form);
                    replies.lock().unwrap().pop_front().unwrap_or((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "unexpected request".into(),
                    ))
                }
            }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            endpoint,
            requests,
            task,
        }
    }

    fn requests(&self) -> Vec<HashMap<String, String>> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn dns() -> Dns {
    Dns::new(
        "dns_west_cn",
        [
            ("WEST_Username".into(), USERNAME.into()),
            ("WEST_Key".into(), KEY.into()),
        ]
        .into(),
        false,
    )
    .unwrap()
}

fn reply(value: Value) -> (StatusCode, String) {
    (StatusCode::OK, value.to_string())
}

fn success() -> (StatusCode, String) {
    reply(json!({"code":200,"msg":"success","body":{}}))
}

fn record(id: Value, hostname: &str, value: &str) -> Value {
    json!({"record_id":id,"hostname":hostname,"record_type":"TXT","record_value":value})
}

#[tokio::test]
async fn adds_form_encoded_txt_without_hashing_the_key_again() {
    let server = Server::new(vec![success()]).await;
    let value = "challenge+value&= with spaces";
    dns()
        .west_cn(true, NAME, value, &server.endpoint)
        .await
        .unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0],
        [
            ("act".into(), "dnsrec.add".into()),
            ("username".into(), USERNAME.into()),
            ("apikey".into(), KEY.into()),
            ("domain".into(), NAME.into()),
            ("hostname".into(), NAME.into()),
            ("record_type".into(), "TXT".into()),
            ("record_value".into(), value.into()),
        ]
        .into()
    );
}

#[tokio::test]
async fn root_and_wildcard_values_coexist_and_cleanup_collects_pages_before_removing() {
    let name = "_acme-challenge.example.com";
    let server = Server::new(vec![
        success(),
        success(),
        reply(json!({"code":200,"body":{"pageno":1,"pagecount":2,"items":[
            record(json!(10), name, "root-token"),
            record(json!(11), name, "wildcard-token"),
            record(json!(12), name, "root-token-extra"),
            record(json!(13), "other.example.com", "root-token"),
            {"record_id":14,"hostname":name,"record_type":"CNAME","record_value":"root-token"}
        ]}})),
        reply(
            json!({"code":"200","body":{"pageno":"2","pagecount":"2","items":[
                record(json!("15"), "_acme-challenge", "root-token"),
                record(json!(10), name, "root-token")
            ]}}),
        ),
        success(),
        success(),
        reply(json!({"code":200,"body":{"pagecount":1,"items":[
            record(json!(11), name, "wildcard-token"),
            record(json!(12), name, "root-token-extra")
        ]}})),
        success(),
    ])
    .await;
    let dns = dns();
    dns.west_cn(true, name, "root-token", &server.endpoint)
        .await
        .unwrap();
    dns.west_cn(true, name, "wildcard-token", &server.endpoint)
        .await
        .unwrap();
    dns.west_cn(false, name, "root-token", &server.endpoint)
        .await
        .unwrap();
    dns.west_cn(false, name, "wildcard-token", &server.endpoint)
        .await
        .unwrap();
    let requests = server.requests();
    assert_eq!(
        requests
            .iter()
            .map(|r| r["act"].as_str())
            .collect::<Vec<_>>(),
        [
            "dnsrec.add",
            "dnsrec.add",
            "dnsrec.list",
            "dnsrec.list",
            "dnsrec.remove",
            "dnsrec.remove",
            "dnsrec.list",
            "dnsrec.remove"
        ]
    );
    assert_eq!(requests[2]["pageno"], "1");
    assert_eq!(requests[3]["pageno"], "2");
    assert_eq!(requests[2]["record_type"], "TXT");
    assert_eq!(requests[2]["limit"], "100");
    assert_eq!(requests[4]["record_id"], "10");
    assert_eq!(requests[5]["record_id"], "15");
    assert_eq!(requests[7]["record_id"], "11");
    for request in &requests {
        assert_eq!(request["domain"], name);
        assert_eq!(request["hostname"], name);
        assert_eq!(request["username"], USERNAME);
        assert_eq!(request["apikey"], KEY);
    }
}

#[tokio::test]
async fn cleanup_is_idempotent_when_no_matching_records_exist() {
    for response in [
        json!({"code":200,"body":{"pagecount":1,"items":[]}}),
        json!({"code":500,"msg":"no records","body":{}}),
        json!({"code":200,"msg":"no records","body":{}}),
        json!({"code":200,"body":{"pagecount":1,"items":[record(json!(1), NAME, "other-token")]}}),
    ] {
        let server = Server::new(vec![reply(response)]).await;
        dns()
            .west_cn(false, NAME, "token", &server.endpoint)
            .await
            .unwrap();
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn rejects_missing_or_empty_credentials_through_provider_dispatch() {
    for field in ["WEST_Username", "WEST_Key"] {
        for missing in [None, Some(""), Some("  ")] {
            let mut dns = dns();
            dns.vars.remove(field);
            if let Some(value) = missing {
                dns.vars.insert(field.into(), value.into());
            }
            for add in [true, false] {
                let error = dns.mutate(add, NAME, "token").await.unwrap_err();
                assert!(error.to_string().contains(field));
                assert!(!error.to_string().contains("unsupported"));
            }
        }
    }
}

#[tokio::test]
async fn reports_http_business_and_json_errors_without_exposing_credentials() {
    let errors = vec![
        ((StatusCode::FORBIDDEN, KEY.into()), "HTTP error"),
        ((StatusCode::OK, format!("not JSON {KEY}")), "invalid JSON"),
        (
            reply(
                json!({"code":500,"msg":format!("Authentication failed: username={USERNAME}&apikey={KEY}; success; no records")}),
            ),
            "API code 500",
        ),
        (reply(json!({"msg":"success"})), "no valid API code"),
        (
            reply(json!({"code":401,"msg":"no records"})),
            "API code 401",
        ),
    ];
    for (response, expected) in errors {
        for add in [true, false] {
            let server = Server::new(vec![response.clone()]).await;
            let error = dns()
                .west_cn(add, NAME, "token", &server.endpoint)
                .await
                .unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(expected), "{message}");
            assert!(!message.contains(KEY));
            assert!(!message.contains(USERNAME));
            assert_eq!(server.requests().len(), 1);
        }
    }
}

#[tokio::test]
async fn malformed_lists_never_trigger_removal() {
    for (body, expected) in [
        (json!({}), "no record array"),
        (
            json!({"items":[record(Value::Null, NAME, "token")]}),
            "no valid record_id",
        ),
        (
            json!({"items":[record(json!(""), NAME, "token")]}),
            "no valid record_id",
        ),
        (json!({"items":[{"record_id":1}]}), "no record_type"),
        (
            json!({"items":[],"pagecount":"invalid"}),
            "invalid pagecount",
        ),
        (json!({"items":[],"pageno":2}), "unexpected page"),
        (
            json!({"items":[],"pagecount":2}),
            "pagination did not complete",
        ),
        (
            json!({"items":[record(json!(1), NAME, "token")],"pagecount":0}),
            "invalid pagecount",
        ),
    ] {
        let server = Server::new(vec![reply(json!({"code":200,"body":body}))]).await;
        let error = dns()
            .west_cn(false, NAME, "token", &server.endpoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn follows_total_or_full_pages_when_pagecount_is_absent() {
    let items = vec![record(json!(1), NAME, "other-token"); 100];
    for body in [
        json!({"items":items,"total":"101"}),
        json!({"items":items}),
        json!({"items":[record(json!(1), NAME, "other-token")],"total":2}),
    ] {
        let server = Server::new(vec![
            reply(json!({"code":200,"body":body})),
            reply(json!({"code":200,"body":{"pagecount":2,"items":[record(json!(2), NAME, "token")]}})),
            success(),
        ])
        .await;
        dns()
            .west_cn(false, NAME, "token", &server.endpoint)
            .await
            .unwrap();
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1]["pageno"], "2");
        assert_eq!(requests[2]["record_id"], "2");
    }
}

#[tokio::test]
async fn removal_failure_is_propagated() {
    let server = Server::new(vec![
        reply(json!({"code":200,"body":{"pagecount":1,"items":[record(json!(1), NAME, "token")]}})),
        reply(json!({"code":500,"msg":"remove failed"})),
    ])
    .await;
    let error = dns()
        .west_cn(false, NAME, "token", &server.endpoint)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("dnsrec.remove failed"));
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn audit_continues_cleanup_after_a_record_fails() {
    let server = Server::new(vec![
        reply(json!({"code":200,"body":{"pagecount":1,"items":[
            record(json!(1), NAME, "token"), record(json!(2), NAME, "token")
        ]}})),
        reply(json!({"code":500,"msg":"remove failed"})),
        success(),
    ])
    .await;
    assert!(
        dns()
            .west_cn(false, NAME, "token", &server.endpoint)
            .await
            .is_err()
    );
    assert_eq!(server.requests().len(), 3);
    assert_eq!(server.requests()[2]["record_id"], "2");
}

#[tokio::test]
async fn audit_does_not_guess_page_size_without_metadata() {
    let server = Server::new(vec![
        reply(json!({"code":200,"body":{"items":[record(json!(1), NAME, "other")]}})),
        reply(json!({"code":200,"body":{"items":[record(json!(2), NAME, "token")]}})),
        reply(json!({"code":200,"body":{"items":[]}})),
        success(),
    ])
    .await;
    dns()
        .west_cn(false, NAME, "token", &server.endpoint)
        .await
        .unwrap();
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[3]["record_id"], "2");
}

#[tokio::test]
async fn audit_rejects_non_numeric_record_ids() {
    for id in [json!("1,2"), json!("-1"), json!(-1), json!(0)] {
        let server = Server::new(vec![
            reply(json!({"code":200,"body":{"pagecount":1,"items":[record(id, NAME, "token")]}})),
            success(),
        ])
        .await;
        assert!(
            dns()
                .west_cn(false, NAME, "token", &server.endpoint)
                .await
                .is_err()
        );
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn audit_does_not_forward_credentials_on_redirect() {
    let target = Server::new(vec![success()]).await;
    let location = target.endpoint.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/", listener.local_addr().unwrap());
    let app = Router::new().route(
        "/",
        post(move || {
            let location = location.clone();
            async move { (StatusCode::TEMPORARY_REDIRECT, [("location", location)]) }
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let result = dns().west_cn(true, NAME, "token", &endpoint).await;
    task.abort();
    assert!(
        target.requests().is_empty(),
        "credentials were forwarded to a different origin"
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn repeated_pages_fail_before_deleting_any_records() {
    let page = reply(json!({"code":200,"body":{"items":[record(json!(1), NAME, "token")]}}));
    let server = Server::new(vec![page.clone(), page]).await;
    let error = dns()
        .west_cn(false, NAME, "token", &server.endpoint)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("pagination did not advance"));
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request["act"] == "dnsrec.list")
    );
}
