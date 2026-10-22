//! Public display snapshots, independent of player OAuth tokens.
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, time::Duration};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("Invalid public-profile configuration or request")]
    InvalidRequest,
    #[error("Public-profile credential rejected")]
    Unauthenticated,
    #[error("Public-profile access forbidden")]
    Forbidden,
    #[error("Public-profile rate limit exceeded")]
    RateLimited { retry_after: Duration },
    #[error("Public-profile service unavailable")]
    Unavailable,
    #[error("Invalid public-profile response")]
    InvalidResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicProfile {
    pub subject: String,
    pub username: String,
    #[serde(
        default,
        deserialize_with = "crate::deserialize_supporter_tier",
        skip_serializing_if = "Option::is_none"
    )]
    pub supporter_tier: Option<u8>,
    /// Unix seconds; consumers must stop displaying this snapshot at this time.
    pub expires_at: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileSnapshot {
    pub issuer: String,
    pub observed_at: i64,
    pub profiles: Vec<PublicProfile>,
}

/// Contains a server-only credential. Debug output intentionally omits it.
#[derive(Clone)]
pub struct PublicProfileClient {
    endpoint: url::Url,
    expected_issuer: String,
    credential: reqwest::header::HeaderValue,
    http: reqwest::Client,
}
impl std::fmt::Debug for PublicProfileClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicProfileClient")
            .finish_non_exhaustive()
    }
}
fn safe_url(value: &str) -> Result<url::Url, ProfileError> {
    let url = url::Url::parse(value).map_err(|_| ProfileError::InvalidRequest)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
    {
        return Err(ProfileError::InvalidRequest);
    }
    Ok(url)
}
fn valid_subject(value: &str) -> bool {
    (1..=255).contains(&value.chars().count()) && !value.contains('\0')
}
impl PublicProfileClient {
    /// `api_base_url` is the Accounts origin (optionally with a deployment path
    /// prefix), e.g. `https://accounts.unbought.games`. The issuer is explicit.
    pub fn new(
        api_base_url: &str,
        expected_issuer: &str,
        credential: &str,
    ) -> Result<Self, ProfileError> {
        let mut endpoint = safe_url(api_base_url)?;
        safe_url(expected_issuer)?;
        let path = format!(
            "{}/api/game-profiles/v1/batch",
            endpoint.path().trim_end_matches('/')
        );
        endpoint.set_path(&path);
        if credential.is_empty() || credential.chars().any(char::is_whitespace) {
            return Err(ProfileError::InvalidRequest);
        }
        let mut credential =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {credential}"))
                .map_err(|_| ProfileError::InvalidRequest)?;
        credential.set_sensitive(true);
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| ProfileError::InvalidRequest)?;
        Ok(Self {
            endpoint,
            expected_issuer: expected_issuer.into(),
            credential,
            http,
        })
    }
    pub async fn batch(&self, subjects: &[String]) -> Result<ProfileSnapshot, ProfileError> {
        if !(1..=100).contains(&subjects.len()) || subjects.iter().any(|s| !valid_subject(s)) {
            return Err(ProfileError::InvalidRequest);
        }
        let requested: HashSet<&str> = subjects.iter().map(String::as_str).collect();
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .header(reqwest::header::AUTHORIZATION, self.credential.clone())
            .json(&serde_json::json!({"subjects": requested}))
            .send()
            .await
            .map_err(|_| ProfileError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            401 => return Err(ProfileError::Unauthenticated),
            403 => return Err(ProfileError::Forbidden),
            429 => {
                let value = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .ok_or(ProfileError::InvalidResponse)?;
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(ProfileError::InvalidResponse);
                }
                let delay = value
                    .parse::<u64>()
                    .map_err(|_| ProfileError::InvalidResponse)?;
                return Err(ProfileError::RateLimited {
                    retry_after: Duration::from_secs(delay),
                });
            }
            500..=599 => return Err(ProfileError::Unavailable),
            _ => return Err(ProfileError::InvalidResponse),
        }
        // Limit decoded response memory even if Content-Length is absent or lies.
        const LIMIT: usize = 256 * 1024;
        if response.content_length().is_some_and(|n| n > LIMIT as u64) {
            return Err(ProfileError::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProfileError::Unavailable)?
        {
            if body.len() + chunk.len() > LIMIT {
                return Err(ProfileError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        let snapshot = serde_json::from_slice(&body).map_err(|_| ProfileError::InvalidResponse)?;
        self.validate(snapshot, &requested, crate::now())
    }
    fn validate(
        &self,
        snapshot: ProfileSnapshot,
        requested: &HashSet<&str>,
        now: i64,
    ) -> Result<ProfileSnapshot, ProfileError> {
        if snapshot.issuer != self.expected_issuer
            || snapshot.observed_at < 0
            || snapshot.observed_at > now + 5
            || snapshot.profiles.len() > requested.len()
        {
            return Err(ProfileError::InvalidResponse);
        }
        let mut seen = HashSet::new();
        for p in &snapshot.profiles {
            if !valid_subject(&p.subject)
                || !requested.contains(p.subject.as_str())
                || !seen.insert(&p.subject)
                || p.username.is_empty()
                || p.username.chars().count() > 255
                || p.username.chars().any(char::is_control)
                || p.expires_at <= now
                || p.expires_at <= snapshot.observed_at
                || p.expires_at > snapshot.observed_at.saturating_add(300)
            {
                return Err(ProfileError::InvalidResponse);
            }
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_snapshot_and_redacts_credentials() {
        let client = PublicProfileClient::new(
            "https://accounts.example",
            "https://accounts.example/api/auth",
            "private-service-secret",
        )
        .unwrap();
        assert!(!format!("{client:?}").contains("private-service-secret"));
        let valid = serde_json::json!({"issuer":"https://accounts.example/api/auth", "observed_at":100,
            "profiles":[{"subject":"opaque", "username":"StellarNomad", "supporter_tier":2, "expires_at":130}]});
        let requested = HashSet::from(["opaque"]);
        let check = |v| client.validate(serde_json::from_value(v).unwrap(), &requested, 100);
        assert_eq!(
            check(valid.clone()).unwrap().profiles[0].supporter_tier,
            Some(2)
        );
        for tier in [
            serde_json::json!(4),
            serde_json::json!(null),
            serde_json::json!("2"),
        ] {
            let mut v = valid.clone();
            v["profiles"][0]["supporter_tier"] = tier;
            assert_eq!(check(v).unwrap().profiles[0].supporter_tier, None);
        }
        for (key, value) in [
            ("subject", serde_json::json!("unrequested")),
            ("username", serde_json::json!("")),
            ("expires_at", serde_json::json!(100)),
            ("expires_at", serde_json::json!(401)),
        ] {
            let mut v = valid.clone();
            v["profiles"][0][key] = value;
            assert_eq!(check(v), Err(ProfileError::InvalidResponse));
        }
        let mut v = valid.clone();
        v["issuer"] = serde_json::json!("wrong");
        assert_eq!(check(v), Err(ProfileError::InvalidResponse));
        let mut v = valid.clone();
        v["profiles"]
            .as_array_mut()
            .unwrap()
            .push(valid["profiles"][0].clone());
        assert_eq!(check(v), Err(ProfileError::InvalidResponse));
        let mut v = valid;
        v["profiles"][0].as_object_mut().unwrap().remove("username");
        assert!(serde_json::from_value::<ProfileSnapshot>(v).is_err());
        for url in [
            "http://remote.example",
            "https://user:password@example.com",
            "https://example.com?secret=x",
        ] {
            assert!(matches!(
                PublicProfileClient::new(url, "https://issuer.example", "secret"),
                Err(ProfileError::InvalidRequest)
            ));
        }
    }
}
