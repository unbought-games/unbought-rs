use std::{
    future::Future,
    sync::Mutex,
    task::{Context, Poll, Waker},
};
use unbought_auth::{
    Configuration, Error, Identity, LoginStore, LoginTransaction, Logout, RelyingParty,
    replace_identity, require_verified, safe_return_path,
};

fn configuration(issuer: &str, redirect_uri: &str) -> Configuration {
    Configuration {
        issuer: issuer.into(),
        client_id: "game".into(),
        client_secret: "test-only-secret".into(),
        redirect_uri: redirect_uri.into(),
    }
}

fn identity() -> Identity {
    Identity {
        issuer: "https://accounts.example".into(),
        subject: "player-id".into(),
        username: "player".into(),
        email_verified: true,
        session_id: "session-id".into(),
        issued_at: 100,
        expires_at: 200,
    }
}

#[test]
fn production_configuration_requires_https_for_both_endpoints() {
    for (issuer, callback) in [
        ("http://accounts.example", "https://game.example/callback"),
        ("https://accounts.example", "http://game.example/callback"),
        ("ftp://accounts.example", "https://game.example/callback"),
        ("invalid", "https://game.example/callback"),
        ("https://accounts.example", "/callback"),
        (
            "http://localhost.evil.example",
            "https://game.example/callback",
        ),
    ] {
        assert!(matches!(
            RelyingParty::new(configuration(issuer, callback)),
            Err(Error::Invalid)
        ));
    }
    let party = RelyingParty::new(configuration(
        "https://accounts.example",
        "https://game.example/callback",
    ))
    .unwrap();
    assert_eq!(party.configuration().client_id, "game");
}

#[test]
fn loopback_configuration_is_available_without_an_account_service() {
    for origin in [
        "http://localhost:3100",
        "http://127.0.0.1:3100",
        "http://[::1]:3100",
    ] {
        assert!(RelyingParty::new(configuration(origin, &format!("{origin}/callback"))).is_ok());
    }
}

#[test]
fn identity_updates_never_cross_subject_or_issuer() {
    let current = identity();
    let mut other_subject = current.clone();
    other_subject.subject = "another-player".into();
    let mut other_issuer = current.clone();
    other_issuer.issuer = "https://another-provider.example".into();
    for incoming in [other_subject, other_issuer] {
        assert!(matches!(
            replace_identity(&current, incoming),
            Err(Error::AccountChanged)
        ));
    }
}

#[test]
fn identity_updates_preserve_newer_claims_but_accept_newer_provider_changes() {
    let current = identity();
    let mut stale = current.clone();
    stale.issued_at -= 1;
    stale.username = "stale_name".into();
    assert_eq!(replace_identity(&current, stale).unwrap(), current);

    let mut same_time = current.clone();
    same_time.email_verified = false;
    assert_eq!(replace_identity(&current, same_time).unwrap(), current);

    let mut newer = current.clone();
    newer.issued_at += 1;
    newer.email_verified = false;
    newer.session_id = "new-session".into();
    assert_eq!(replace_identity(&current, newer.clone()).unwrap(), newer);
}

#[test]
fn email_verification_is_an_explicit_policy() {
    assert!(require_verified(&identity()).is_ok());
    let mut unverified = identity();
    unverified.email_verified = false;
    assert!(matches!(
        require_verified(&unverified),
        Err(Error::EmailVerificationRequired)
    ));
}

#[test]
fn return_destinations_reject_external_urls_and_header_injection() {
    for path in [
        "",
        "game",
        "https://example.com",
        "//example.com",
        "/\\example.com",
        "/\t/example.com",
        "/game\rLocation: elsewhere",
        "/game\nLocation: elsewhere",
    ] {
        assert!(!safe_return_path(path), "{path:?}");
    }
    for path in ["/", "/game", "/game?tab=fleets#current"] {
        assert!(safe_return_path(path), "{path}");
    }
}

#[test]
fn return_destinations_reject_browser_url_normalization_bypasses() {
    let base = url::Url::parse("https://game.example").unwrap();
    let tab_destination = "/\t/elsewhere.example";
    assert_eq!(
        base.join(tab_destination).unwrap().host_str(),
        Some("elsewhere.example")
    );
    assert!(!safe_return_path(tab_destination));
    for control in (0u8..=31).chain(std::iter::once(127)) {
        assert!(!safe_return_path(&format!(
            "/{}/elsewhere.example",
            char::from(control)
        )));
        assert!(!safe_return_path(&format!(
            "/game?tab={}fleets",
            char::from(control)
        )));
    }
    // Encoded path characters stay encoded when used directly as a Location.
    for path in ["/%09/elsewhere.example", "/game?tab=fleets", "/galaxy/é"] {
        assert!(safe_return_path(path));
        assert_eq!(base.join(path).unwrap().origin(), base.origin());
    }
}

struct LegacyLogin(Mutex<Option<LoginTransaction>>);
impl LoginStore for LegacyLogin {
    async fn insert(&self, _: LoginTransaction) -> unbought_auth::Result<()> {
        panic!("unsafe login must not be saved")
    }
    async fn consume(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: i64,
    ) -> unbought_auth::Result<Option<LoginTransaction>> {
        Ok(self.0.lock().unwrap().take())
    }
}

#[test]
fn unsafe_destinations_are_rejected_before_network_and_after_legacy_consumption() {
    let party = RelyingParty::new(configuration(
        "https://accounts.example",
        "https://game.example/callback",
    ))
    .unwrap();
    let store = LegacyLogin(Mutex::new(Some(LoginTransaction {
        issuer: "https://accounts.example".into(),
        client_id: "game".into(),
        state_hash: "state".into(),
        browser_hash: "browser".into(),
        nonce: "nonce".into(),
        pkce_verifier: "verifier".into(),
        return_path: "/\t/elsewhere.example".into(),
        expected_subject: None,
        expires_at: i64::MAX,
    })));
    let mut context = Context::from_waker(Waker::noop());
    let mut begin = std::pin::pin!(party.begin(&store, "browser", "/\t/elsewhere.example", None));
    assert!(matches!(
        begin.as_mut().poll(&mut context),
        Poll::Ready(Err(Error::Invalid))
    ));
    let mut callback = std::pin::pin!(party.callback(
        &store,
        "browser",
        "state",
        "code",
        "https://accounts.example"
    ));
    assert!(matches!(
        callback.as_mut().poll(&mut context),
        Poll::Ready(Err(Error::Invalid))
    ));
    assert!(
        store.0.lock().unwrap().is_none(),
        "legacy transaction was consumed exactly once"
    );
}

#[test]
fn logout_payloads_reject_nonce_presence_even_when_null() {
    let payload = serde_json::json!({
        "iss": "https://accounts.example", "aud": "game", "sid": "session",
        "jti": "event", "iat": 100, "exp": 200,
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}}
    });
    // Deserialization alone does not verify signatures; callers use logout().
    assert!(serde_json::from_value::<Logout>(payload.clone()).is_ok());
    for nonce in [serde_json::Value::Null, serde_json::json!("nonce")] {
        let mut invalid = payload.clone();
        invalid["nonce"] = nonce;
        assert!(serde_json::from_value::<Logout>(invalid).is_err());
    }
}
