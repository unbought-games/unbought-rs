//! OIDC protocol integration. Consumers own HTTP, cookies, durable transactions and sessions.
#![doc = include_str!("../README.md")]
mod profiles;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openidconnect::{
    AccessTokenHash, AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    HttpRequest, HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, RequestTokenError, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreRequestTokenError},
};
pub use profiles::{ProfileError, ProfileSnapshot, PublicProfile, PublicProfileClient};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Authentication service unavailable")]
    Unavailable,
    #[error("Invalid authentication response")]
    Invalid,
    #[error("Login transaction expired or already used")]
    Transaction,
    #[error("Account changed during authentication")]
    AccountChanged,
    #[error("Email verification required")]
    EmailVerificationRequired,
}
pub type Result<T> = std::result::Result<T, Error>;
/// Optional display claim issued by Accounts. Every recognized tier is a supporter.
pub const SUPPORTER_TIER_CLAIM: &str = "https://unbought.games/supporter_tier";
#[derive(Clone, Serialize, Deserialize)]
pub struct Configuration {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    pub username: String,
    pub email_verified: bool,
    /// Optional supporter display tier (1, 2, or 3), scoped to this identity's issuer.
    /// Missing or unrecognized claims do not restrict authentication or gameplay.
    #[serde(
        default,
        deserialize_with = "deserialize_supporter_tier",
        skip_serializing_if = "Option::is_none"
    )]
    pub supporter_tier: Option<u8>,
    pub session_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Tokens {
    pub client_id: String,
    pub identity: Identity,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub nonce: String,
    pub validated_at: i64,
}
fn supporter_tier(value: &serde_json::Value) -> Option<u8> {
    value
        .as_u64()
        .filter(|tier| (1..=3).contains(tier))
        .map(|tier| tier as u8)
}
fn deserialize_supporter_tier<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u8>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(supporter_tier(&value))
}
#[derive(Clone, Serialize, Deserialize)]
pub struct LoginTransaction {
    pub issuer: String,
    pub client_id: String,
    pub state_hash: String,
    pub browser_hash: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub return_path: String,
    pub expected_subject: Option<String>,
    pub expires_at: i64,
}
/// Implement consumption with one atomic DELETE ... RETURNING (including all predicates).
/// Never return a transaction before committing its deletion.
pub trait LoginStore: Send + Sync {
    fn insert(&self, transaction: LoginTransaction) -> impl Future<Output = Result<()>> + Send;
    fn consume(
        &self,
        issuer: &str,
        client_id: &str,
        state_hash: &str,
        browser_hash: &str,
        now: i64,
    ) -> impl Future<Output = Result<Option<LoginTransaction>>> + Send;
}
#[derive(Clone, Debug, Deserialize)]
pub struct Logout {
    pub iss: String,
    pub aud: serde_json::Value,
    pub sub: Option<String>,
    pub sid: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    pub events: serde_json::Value,
    #[serde(default, deserialize_with = "reject_logout_nonce")]
    pub nonce: Option<String>,
}
fn reject_logout_nonce<'de, D: serde::Deserializer<'de>>(
    _: D,
) -> std::result::Result<Option<String>, D::Error> {
    Err(serde::de::Error::custom(
        "logout tokens cannot contain a nonce",
    ))
}
#[derive(Clone)]
pub struct RelyingParty {
    config: Configuration,
    http: reqwest::Client,
}
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn digest(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}
pub fn random_secret() -> String {
    CsrfToken::new_random().secret().to_owned()
}
pub fn safe_return_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.bytes().any(|byte| byte.is_ascii_control())
}
pub fn require_verified(identity: &Identity) -> Result<()> {
    if identity.email_verified {
        Ok(())
    } else {
        Err(Error::EmailVerificationRequired)
    }
}
pub fn replace_identity(current: &Identity, next: Identity) -> Result<Identity> {
    if current.issuer != next.issuer || current.subject != next.subject {
        return Err(Error::AccountChanged);
    }
    if next.issued_at < current.issued_at {
        return Ok(current.clone());
    }
    if next.issued_at == current.issued_at && current.email_verified && !next.email_verified {
        // Preserve the existing verification safeguard without keeping a tier
        // that a refresh in the same issuance second has removed or changed.
        let mut preserved = current.clone();
        preserved.supporter_tier = next.supporter_tier;
        return Ok(preserved);
    }
    Ok(next)
}
// Inspect HTTP status before OAuth parsing discards it. Accounts throttling has
// a JSON message body, and reverse proxies may return HTML on outages.
fn token_http_response(response: HttpResponse) -> Result<HttpResponse> {
    if response.status().as_u16() == 429 || response.status().is_server_error() {
        Err(Error::Unavailable)
    } else {
        Ok(response)
    }
}

fn token_error(error: CoreRequestTokenError<Error>) -> Error {
    match error {
        RequestTokenError::Request(_) => Error::Unavailable,
        RequestTokenError::ServerResponse(response)
            if matches!(
                response.error().as_ref(),
                "temporarily_unavailable" | "server_error"
            ) =>
        {
            Error::Unavailable
        }
        _ => Error::Invalid,
    }
}

// A concrete adapter keeps the HTTP future's Send bound visible to consumers
// such as Axum, including when callback/refresh are awaited inside a handler.
struct TokenHttpClient<'a>(&'a reqwest::Client);

impl<'c> AsyncHttpClient<'c> for TokenHttpClient<'_> {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse>> + Send + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.0.call(request).await.map_err(|_| Error::Unavailable)?;
            token_http_response(response)
        })
    }
}

impl RelyingParty {
    pub fn new(config: Configuration) -> Result<Self> {
        for value in [&config.issuer, &config.redirect_uri] {
            let url = url::Url::parse(value).map_err(|_| Error::Invalid)?;
            if url.scheme() != "https"
                && !(url.scheme() == "http"
                    && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
            {
                return Err(Error::Invalid);
            }
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::Invalid)?;
        Ok(Self { config, http })
    }
    pub fn configuration(&self) -> &Configuration {
        &self.config
    }
    async fn metadata(&self) -> Result<CoreProviderMetadata> {
        CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.config.issuer.clone()).map_err(|_| Error::Invalid)?,
            &self.http,
        )
        .await
        .map_err(|_| Error::Unavailable)
    }
    pub async fn begin<S: LoginStore>(
        &self,
        store: &S,
        browser_secret: &str,
        return_path: &str,
        expected_subject: Option<String>,
    ) -> Result<String> {
        if !safe_return_path(return_path) {
            return Err(Error::Invalid);
        }
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone()).map_err(|_| Error::Invalid)?,
        );
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("profile".into()))
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("offline_access".into()))
            .set_pkce_challenge(challenge)
            .url();
        store
            .insert(LoginTransaction {
                issuer: self.config.issuer.clone(),
                client_id: self.config.client_id.clone(),
                state_hash: digest(state.secret()),
                browser_hash: digest(browser_secret),
                nonce: nonce.secret().clone(),
                pkce_verifier: verifier.secret().clone(),
                return_path: return_path.into(),
                expected_subject,
                expires_at: now() + 600,
            })
            .await?;
        Ok(url.to_string())
    }
    pub async fn callback<S: LoginStore>(
        &self,
        store: &S,
        browser_secret: &str,
        state: &str,
        code: &str,
        response_issuer: &str,
    ) -> Result<(Tokens, String)> {
        if response_issuer != self.config.issuer {
            return Err(Error::Invalid);
        }
        let transaction = store
            .consume(
                &self.config.issuer,
                &self.config.client_id,
                &digest(state),
                &digest(browser_secret),
                now(),
            )
            .await?
            .ok_or(Error::Transaction)?;
        // Recheck transactions created before a validator upgrade, before any
        // provider request or use of their stored destination in a redirect.
        if !safe_return_path(&transaction.return_path) {
            return Err(Error::Invalid);
        }
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_uri.clone()).map_err(|_| Error::Invalid)?,
        );
        let response = client
            .exchange_code(AuthorizationCode::new(code.into()))
            .map_err(|_| Error::Invalid)?
            .set_pkce_verifier(PkceCodeVerifier::new(transaction.pkce_verifier))
            .request_async(&TokenHttpClient(&self.http))
            .await
            .map_err(token_error)?;
        let id_token = response.id_token().ok_or(Error::Invalid)?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(transaction.nonce.clone()))
            .map_err(|_| Error::Invalid)?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                response.access_token(),
                id_token.signing_alg().map_err(|_| Error::Invalid)?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|_| Error::Invalid)?,
            )
            .map_err(|_| Error::Invalid)?;
            if *expected != actual {
                return Err(Error::Invalid);
            }
        }
        let identity = self.identity(&id_token.to_string())?;
        if transaction
            .expected_subject
            .as_ref()
            .is_some_and(|sub| *sub != identity.subject)
        {
            return Err(Error::AccountChanged);
        }
        Ok((
            Tokens {
                client_id: self.config.client_id.clone(),
                identity,
                access_token: response.access_token().secret().clone(),
                refresh_token: response.refresh_token().map(|v| v.secret().clone()),
                nonce: transaction.nonce,
                validated_at: now(),
            },
            transaction.return_path,
        ))
    }
    // Called only after the protocol library has validated signature, audience, issuer and nonce.
    fn identity(&self, token: &str) -> Result<Identity> {
        let payload = token.split('.').nth(1).ok_or(Error::Invalid)?;
        let value: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::Invalid)?;
        let username = value["preferred_username"].as_str().ok_or(Error::Invalid)?;
        if !(3..=30).contains(&username.len())
            || !username
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(Error::Invalid);
        }
        let flag = value.get("email_verified");
        if flag.is_some_and(|v| !v.is_boolean()) {
            return Err(Error::Invalid);
        }
        Ok(Identity {
            issuer: self.config.issuer.clone(),
            subject: value["sub"].as_str().ok_or(Error::Invalid)?.into(),
            username: username.into(),
            email_verified: flag.and_then(|v| v.as_bool()).unwrap_or(false),
            supporter_tier: value.get(SUPPORTER_TIER_CLAIM).and_then(supporter_tier),
            session_id: value["sid"].as_str().ok_or(Error::Invalid)?.into(),
            issued_at: value["iat"].as_i64().ok_or(Error::Invalid)?,
            expires_at: value["exp"]
                .as_i64()
                .ok_or(Error::Invalid)?
                .min(value["session_expires_at"].as_i64().unwrap_or(i64::MAX)),
        })
    }
    pub async fn refresh(&self, tokens: &Tokens) -> Result<Tokens> {
        let client = CoreClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        );
        let response = client
            .exchange_refresh_token(&RefreshToken::new(
                tokens.refresh_token.clone().ok_or(Error::Invalid)?,
            ))
            .map_err(|_| Error::Invalid)?
            .request_async(&TokenHttpClient(&self.http))
            .await
            .map_err(token_error)?;
        let id_token = response.id_token().ok_or(Error::Invalid)?;
        id_token
            .claims(&client.id_token_verifier(), |nonce: Option<&Nonce>| {
                if nonce.is_some_and(|n| digest(n.secret()) != digest(&tokens.nonce)) {
                    Err("nonce mismatch".into())
                } else {
                    Ok(())
                }
            })
            .map_err(|_| Error::Invalid)?;
        let identity = replace_identity(&tokens.identity, self.identity(&id_token.to_string())?)?;
        Ok(Tokens {
            client_id: self.config.client_id.clone(),
            identity,
            access_token: response.access_token().secret().clone(),
            refresh_token: response
                .refresh_token()
                .map(|r| r.secret().clone())
                .or_else(|| tokens.refresh_token.clone()),
            nonce: tokens.nonce.clone(),
            validated_at: now(),
        })
    }
    /// Revalidate before admitting a command when the authenticated snapshot is 60 seconds old.
    /// A network failure must deny the command; it must never pause the game simulation.
    pub async fn revalidate(&self, tokens: &Tokens) -> Result<Tokens> {
        if tokens.client_id != self.config.client_id
            || tokens.identity.issuer != self.config.issuer
            || tokens.validated_at > now() + 5
        {
            return Err(Error::Invalid);
        }
        if now() - tokens.validated_at < 60 && now() < tokens.identity.expires_at {
            return Ok(tokens.clone());
        }
        self.refresh(tokens).await
    }
    pub async fn logout(&self, token: &str) -> Result<Logout> {
        let header = jsonwebtoken::decode_header(token).map_err(|_| Error::Invalid)?;
        if header.alg != jsonwebtoken::Algorithm::RS256
            || header.typ.as_deref() != Some("logout+jwt")
        {
            return Err(Error::Invalid);
        }
        let metadata = self.metadata().await?;
        let keys: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(metadata.jwks_uri().as_str())
            .send()
            .await
            .map_err(|_| Error::Unavailable)?
            .error_for_status()
            .map_err(|_| Error::Unavailable)?
            .json()
            .await
            .map_err(|_| Error::Invalid)?;
        let key = keys
            .find(header.kid.as_deref().ok_or(Error::Invalid)?)
            .ok_or(Error::Invalid)?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.client_id]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "jti", "sid"]);
        validation.leeway = 5;
        let claims = jsonwebtoken::decode::<Logout>(
            token,
            &jsonwebtoken::DecodingKey::from_jwk(key).map_err(|_| Error::Invalid)?,
            &validation,
        )
        .map_err(|_| Error::Invalid)?
        .claims;
        if claims.nonce.is_some()
            || claims.iat > now() + 5
            || now() - claims.iat > 180
            || claims.sid.is_empty()
            || claims.jti.is_empty()
            || !claims
                .events
                .get("http://schemas.openid.net/event/backchannel-logout")
                .is_some_and(|v| v.as_object().is_some_and(|v| v.is_empty()))
        {
            return Err(Error::Invalid);
        }
        Ok(claims)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_supporter_claims_do_not_gate_identity_parsing() {
        let party = RelyingParty::new(Configuration {
            issuer: "https://self-hosted.example".into(),
            client_id: "game".into(),
            client_secret: "fixture".into(),
            redirect_uri: "https://game.example/callback".into(),
        })
        .unwrap();
        let mut payload = serde_json::json!({
            "sub": "player", "preferred_username": "alice", "email_verified": false,
            "sid": "session", "iat": 100, "exp": 200
        });
        // Exercise the post-validation extraction step only. Public callback and
        // refresh still validate tokens through openidconnect before reaching it.
        let parse = |payload: &serde_json::Value| {
            let token = format!(
                "header.{}.signature",
                URL_SAFE_NO_PAD.encode(payload.to_string())
            );
            party.identity(&token)
        };
        let missing = parse(&payload).unwrap();
        assert_eq!(missing.supporter_tier, None);
        assert_eq!(missing.issuer, "https://self-hosted.example");
        for tier in 1..=3 {
            payload[SUPPORTER_TIER_CLAIM] = serde_json::json!(tier);
            assert_eq!(parse(&payload).unwrap().supporter_tier, Some(tier));
        }
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(4),
            serde_json::json!(-1),
            serde_json::json!(256),
            serde_json::json!(u64::MAX),
            serde_json::json!(1.0),
            serde_json::json!(1.5),
            serde_json::json!("1"),
            serde_json::json!(true),
            serde_json::json!([1]),
            serde_json::json!({"tier": 1}),
        ] {
            payload[SUPPORTER_TIER_CLAIM] = invalid;
            let parsed = parse(&payload).unwrap();
            assert_eq!(parsed.supporter_tier, None);
            assert_eq!(parsed.subject, missing.subject);
            assert_eq!(parsed.email_verified, missing.email_verified);
        }
        // Optional metadata does not relax the required identity contract.
        payload["email_verified"] = serde_json::json!("true");
        assert!(matches!(parse(&payload), Err(Error::Invalid)));
    }
    #[test]
    fn logout_rejects_even_a_null_nonce() {
        let value = serde_json::json!({"iss":"issuer","aud":"client","sid":"session","jti":"event","iat":1,"exp":2,"events":{},"nonce":null});
        assert!(serde_json::from_value::<Logout>(value).is_err());
    }
    #[test]
    fn safe_destinations() {
        for s in ["https://evil.test", "//evil.test", "/\\evil.test", "/\nfoo"] {
            assert!(!safe_return_path(s))
        }
        assert!(safe_return_path("/game?tab=fleet"));
    }
    #[test]
    fn verified_claims_do_not_regress() {
        let i = Identity {
            issuer: "issuer".into(),
            subject: "id".into(),
            username: "alice".into(),
            email_verified: true,
            supporter_tier: None,
            session_id: "session".into(),
            issued_at: 20,
            expires_at: 100,
        };
        let mut old = i.clone();
        old.issued_at = 19;
        old.email_verified = false;
        assert!(replace_identity(&i, old).unwrap().email_verified);
        let mut other = i.clone();
        other.subject = "other".into();
        assert!(replace_identity(&i, other).is_err());
    }
}

#[cfg(test)]
mod token_error_tests {
    use super::*;
    use openidconnect::{StandardErrorResponse, core::CoreErrorResponseType};

    #[test]
    fn throttling_and_outages_are_transient_regardless_of_body() {
        for status in [429, 500, 502, 503, 504] {
            for body in [
                br#"{"message":"Too many requests"}"#.as_slice(),
                b"<html>Unavailable</html>",
                b"",
            ] {
                let response = openidconnect::http::Response::builder()
                    .status(status)
                    .body(body.to_vec())
                    .unwrap();
                assert!(matches!(
                    token_http_response(response),
                    Err(Error::Unavailable)
                ));
            }
        }
        assert!(matches!(
            token_error(RequestTokenError::Request(Error::Unavailable)),
            Error::Unavailable
        ));
    }

    #[test]
    fn credentials_and_account_errors_remain_invalid() {
        for status in [200, 400, 401, 403] {
            let response = openidconnect::http::Response::builder()
                .status(status)
                .body(Vec::new())
                .unwrap();
            assert_eq!(
                token_http_response(response).unwrap().status().as_u16(),
                status
            );
        }
        for code in [
            "invalid_grant",
            "invalid_client",
            "access_denied",
            "account_action_required",
        ] {
            let response: StandardErrorResponse<CoreErrorResponseType> =
                serde_json::from_value(serde_json::json!({"error": code})).unwrap();
            assert!(matches!(
                token_error(RequestTokenError::ServerResponse(response)),
                Error::Invalid
            ));
        }
        for code in ["temporarily_unavailable", "server_error"] {
            let response: StandardErrorResponse<CoreErrorResponseType> =
                serde_json::from_value(serde_json::json!({"error": code})).unwrap();
            assert!(matches!(
                token_error(RequestTokenError::ServerResponse(response)),
                Error::Unavailable
            ));
        }
        assert!(matches!(
            token_error(RequestTokenError::Other("malformed response".into())),
            Error::Invalid
        ));
    }
}
