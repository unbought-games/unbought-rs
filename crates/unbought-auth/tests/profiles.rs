use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};
use unbought_auth::{ProfileError, PublicProfileClient};

fn server(status: u16, headers: String, body: String) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0; 4096];
            let n = stream.read(&mut bytes).unwrap();
            if n == 0 {
                break;
            }
            request.extend_from_slice(&bytes[..n]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&request[..end]);
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        write!(stream,"HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n{headers}\r\n{body}",body.len()).unwrap();
        String::from_utf8(request).unwrap()
    });
    (origin, handle)
}

#[tokio::test]
async fn http_profiles_and_error_contract() {
    let now = unbought_auth::now();
    let body = serde_json::json!({"issuer":"https://expected.example/api/auth","observed_at":now,
        "profiles":[{"subject":"a","username":"alice","supporter_tier":3,"expires_at":now+30}]})
    .to_string();
    let (origin, handle) = server(200, String::new(), body);
    let client = PublicProfileClient::new(
        &origin,
        "https://expected.example/api/auth",
        "test-service-secret",
    )
    .unwrap();
    let snapshot = client
        .batch(&["a".into(), "b".into(), "a".into()])
        .await
        .unwrap();
    assert_eq!(snapshot.profiles.len(), 1);
    assert_eq!(snapshot.profiles[0].supporter_tier, Some(3));
    let request = handle.join().unwrap();
    assert!(request.starts_with("POST /api/game-profiles/v1/batch HTTP/1.1"));
    assert!(request.contains("authorization: Bearer test-service-secret"));
    let body: serde_json::Value =
        serde_json::from_str(request.split("\r\n\r\n").nth(1).unwrap()).unwrap();
    assert_eq!(body["subjects"].as_array().unwrap().len(), 2);
    for (status, headers, body, expected) in [
        (
            401,
            "",
            "private error detail",
            ProfileError::Unauthenticated,
        ),
        (403, "", "", ProfileError::Forbidden),
        (
            429,
            "Retry-After: 17\r\n",
            "",
            ProfileError::RateLimited {
                retry_after: Duration::from_secs(17),
            },
        ),
        (
            429,
            "Retry-After: tomorrow\r\n",
            "",
            ProfileError::InvalidResponse,
        ),
        (503, "", "database error", ProfileError::Unavailable),
        (502, "", "<html>outage</html>", ProfileError::Unavailable),
        (200, "", "{}", ProfileError::InvalidResponse),
        (200, "", "not json", ProfileError::InvalidResponse),
        (
            200,
            "",
            r#"{"issuer":"wrong","observed_at":0,"profiles":[]}"#,
            ProfileError::InvalidResponse,
        ),
    ] {
        let (origin, handle) = server(status, headers.into(), body.into());
        let client =
            PublicProfileClient::new(&origin, "https://expected.example/api/auth", "secret")
                .unwrap();
        assert_eq!(client.batch(&["a".into()]).await.unwrap_err(), expected);
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn redirects_never_receive_credentials_and_requests_are_bounded() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let (origin, handle) = server(
        302,
        format!(
            "Location: http://{}/steal\r\n",
            destination.local_addr().unwrap()
        ),
        String::new(),
    );
    let client = PublicProfileClient::new(&origin, "https://expected.example", "secret").unwrap();
    assert_eq!(
        client.batch(&["a".into()]).await.unwrap_err(),
        ProfileError::InvalidResponse
    );
    handle.join().unwrap();
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    for subjects in [
        vec![],
        vec!["a".into(); 101],
        vec!["".into()],
        vec!["a".repeat(256)],
    ] {
        assert_eq!(
            client.batch(&subjects).await.unwrap_err(),
            ProfileError::InvalidRequest
        );
    }
    let (origin, handle) = server(200, String::new(), " ".repeat(256 * 1024 + 1));
    let client = PublicProfileClient::new(&origin, "https://expected.example", "secret").unwrap();
    assert_eq!(
        client.batch(&["a".into()]).await.unwrap_err(),
        ProfileError::InvalidResponse
    );
    // The client may close before the fixture finishes writing an oversized body.
    let _ = handle.join();
}
