use super::*;
use axum::{
    Router,
    body::{Bytes, to_bytes},
    extract::Request,
    http::{HeaderMap, Method},
    routing::any,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, task::JoinHandle};

const KEY: &str = "test-dnshe-key";
const SECRET: &str = "test-dnshe-secret";
const NAME: &str = "_acme-challenge.nested.example.net";
const ZONE_ID: u64 = 123456789012345;
const ROOT_ID: u64 = 234567890123456;
const WILDCARD_ID: u64 = 345678901234567;

struct Call {
    method: Method,
    headers: HeaderMap,
    query: HashMap<String, String>,
    body: Bytes,
}

struct Server {
    url: String,
    calls: Arc<Mutex<Vec<Call>>>,
    task: JoinHandle<()>,
}

impl Server {
    async fn new(replies: Vec<(StatusCode, String)>) -> Self {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let capture = calls.clone();
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/index.php", listener.local_addr().unwrap());
        let app = Router::new().route(
            "/index.php",
            any(move |request: Request| {
                let capture = capture.clone();
                let replies = replies.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let query = reqwest::Url::parse(&format!("http://test{}", parts.uri))
                        .unwrap()
                        .query_pairs()
                        .into_owned()
                        .collect();
                    let body = to_bytes(body, 4096).await.unwrap();
                    capture.lock().unwrap().push(Call {
                        method: parts.method,
                        headers: parts.headers,
                        query,
                        body,
                    });
                    replies
                        .lock()
                        .unwrap()
                        .pop_front()
                        .expect("unexpected DNSHE request")
                }
            }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, calls, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn credentials() -> HashMap<String, String> {
    [
        (API_KEY.into(), KEY.into()),
        (API_SECRET.into(), SECRET.into()),
    ]
    .into()
}

fn dns() -> Dns {
    Dns::new("dns_dnshe", credentials(), false).unwrap()
}

fn reply(data: Value) -> (StatusCode, String) {
    (StatusCode::OK, data.to_string())
}

fn zone() -> (StatusCode, String) {
    reply(json!({
        "success": true, "subdomains": [
            {"id": ZONE_ID.to_string(), "full_domain": "NESTED.EXAMPLE.NET.", "status":"Registered"}
        ]
    }))
}

fn records(records: Vec<Value>) -> (StatusCode, String) {
    reply(json!({"success": true, "records": records}))
}

fn record(id: impl Into<Value>, name: &str, kind: &str, content: &str) -> Value {
    json!({"id": id.into(), "name": name, "type": kind, "content": content})
}

#[tokio::test]
async fn dnshe_lists_all_pages_and_appends_wildcard_txt_at_the_longest_zone() {
    let server = Server::new(vec![
        reply(json!({
            "success": true, "pagination": {"has_more":true},
            "subdomains":[
                {"id":1,"full_domain":"example.net","status":"active"},
                {"id":2,"full_domain":"ested.example.net","status":"active"}
            ]
        })),
        zone(),
        records(vec![record(ROOT_ID, NAME, "TXT", "root-token")]),
        reply(json!({"success":true,"id":WILDCARD_ID})),
    ])
    .await;
    dns()
        .dnshe(true, NAME, "wildcard-token", &server.url)
        .await
        .unwrap();
    let calls = server.calls.lock().unwrap();
    assert_eq!(calls.len(), 4);
    for call in &*calls {
        assert_eq!(call.headers["X-API-Key"], KEY);
        assert_eq!(call.headers["X-API-Secret"], SECRET);
        assert_eq!(call.query["m"], "domain_hub");
        assert!(
            !call
                .query
                .values()
                .any(|value| value == KEY || value == SECRET)
        );
    }
    assert_eq!(calls[1].query["page"], "2");
    assert_eq!(calls[2].query["subdomain_id"], ZONE_ID.to_string());
    assert_eq!(calls[2].method, Method::GET);
    assert_eq!(calls[3].method, Method::POST);
    assert_eq!(calls[3].query["action"], "create");
    assert_eq!(
        serde_json::from_slice::<Value>(&calls[3].body).unwrap(),
        json!({"subdomain_id":ZONE_ID,"type":"TXT","name":"_acme-challenge","content":"wildcard-token"})
    );
}

#[tokio::test]
async fn dnshe_add_and_remove_are_idempotent_and_only_touch_matching_txt() {
    let existing = vec![
        record(
            ROOT_ID.to_string(),
            "_ACME-CHALLENGE",
            "txt",
            "\"root-token\"",
        ),
        record(WILDCARD_ID, NAME, "TXT", "wildcard-token"),
        record(7, NAME, "CNAME", "root-token"),
        record(8, "_acme-challenge.other", "TXT", "root-token"),
        record(9, NAME, "TXT", "root-token-extra"),
    ];
    let server = Server::new(vec![
        zone(),
        records(existing.clone()),
        zone(),
        records(existing),
        (
            StatusCode::NOT_FOUND,
            json!({"success":false,"error_code":"dns_record_not_found"}).to_string(),
        ),
        zone(),
        records(vec![]),
    ])
    .await;
    let dns = dns();
    dns.dnshe(true, NAME, "root-token", &server.url)
        .await
        .unwrap();
    dns.dnshe(false, NAME, "root-token", &server.url)
        .await
        .unwrap();
    dns.dnshe(false, NAME, "root-token", &server.url)
        .await
        .unwrap();
    let calls = server.calls.lock().unwrap();
    let writes = calls
        .iter()
        .filter(|call| call.method == Method::POST)
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0].query["action"], "delete");
    assert_eq!(
        serde_json::from_slice::<Value>(&writes[0].body).unwrap(),
        json!({"id":ROOT_ID})
    );
}

#[tokio::test]
async fn dnshe_refuses_inactive_or_invalid_responses_and_redacts_errors() {
    for (replies, expected) in [
        (
            vec![reply(
                json!({"success":true,"subdomains":[{"id":ZONE_ID,"full_domain":"nested.example.net","status":"expired"}]}),
            )],
            "inactive",
        ),
        (
            vec![(
                StatusCode::UNAUTHORIZED,
                json!({"success":false,"error_code":"auth_invalid_credentials","message":SECRET})
                    .to_string(),
            )],
            "invalid API Key or API Secret",
        ),
        (
            vec![(StatusCode::BAD_GATEWAY, SECRET.into())],
            "invalid JSON",
        ),
        (
            vec![
                zone(),
                records(vec![record(Value::Null, NAME, "TXT", "root-token")]),
            ],
            "no valid id",
        ),
        (
            vec![reply(
                json!({"success":true,"pagination":{"has_more":true},"subdomains":[]}),
            )],
            "empty page",
        ),
    ] {
        let server = Server::new(replies).await;
        let error = dns()
            .dnshe(false, NAME, "root-token", &server.url)
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(KEY));
        assert!(!message.contains(SECRET));
        assert!(
            server
                .calls
                .lock()
                .unwrap()
                .iter()
                .all(|call| call.method == Method::GET)
        );
    }
}

#[test]
fn dnshe_validates_credentials_before_they_can_be_used_as_headers() {
    assert!(validate_credentials(&credentials()).is_ok());
    for value in ["", "two words", "header\r\nInjected: true"] {
        let mut invalid = credentials();
        invalid.insert(API_SECRET.into(), value.into());
        let error = validate_credentials(&invalid).unwrap_err().to_string();
        assert!(error.contains(API_SECRET));
        assert!(!error.contains("Injected"));
    }
}
