//! HTTP-based email delivery for Workers.
//!
//! On Cloudflare Workers we can't open SMTP TCP connections, so every provider
//! must speak HTTPS. We pick the provider per-request from env vars: if
//! `RESEND_API_KEY` is set we use Resend, else if `MAILCHANNELS_DKIM_PRIVATE_KEY`
//! is set we use MailChannels (free for CF Workers, requires DKIM), else we
//! fall back to a `LogProvider` that logs the message and reports success — used
//! for development.
//!
//! All providers share the same `MailMessage` shape: from / to / subject /
//! plaintext + html bodies. Templates live in `templates/` and are rendered
//! via Handlebars.

use serde_json::json;
use worker::Env;

#[derive(Debug, Clone)]
pub struct MailMessage {
    pub from_email: String,
    pub from_name: String,
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

#[derive(Debug)]
pub enum MailError {
    Config(String),
    Network(String),
    Provider(String),
}

impl std::fmt::Display for MailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "mail config: {m}"),
            Self::Network(m) => write!(f, "mail network: {m}"),
            Self::Provider(m) => write!(f, "mail provider: {m}"),
        }
    }
}

impl std::error::Error for MailError {}

#[allow(async_fn_in_trait)]
pub trait MailProvider {
    async fn send(&self, message: &MailMessage) -> Result<(), MailError>;
}

pub struct LogProvider;

impl MailProvider for LogProvider {
    async fn send(&self, m: &MailMessage) -> Result<(), MailError> {
        worker::console_log!(
            "[mail:log] from={} to={} subject={:?}",
            m.from_email,
            m.to,
            m.subject
        );
        Ok(())
    }
}

pub struct ResendProvider {
    pub api_key: String,
}

impl MailProvider for ResendProvider {
    async fn send(&self, m: &MailMessage) -> Result<(), MailError> {
        let body = json!({
            "from": format!("{} <{}>", m.from_name, m.from_email),
            "to": [&m.to],
            "subject": m.subject,
            "text": m.text,
            "html": m.html.clone().unwrap_or_default(),
        });
        let headers = worker::Headers::new();
        headers
            .set("authorization", &format!("Bearer {}", self.api_key))
            .map_err(|e| MailError::Config(e.to_string()))?;
        headers
            .set("content-type", "application/json")
            .map_err(|e| MailError::Config(e.to_string()))?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_headers(headers);
        init.with_body(Some(body.to_string().into()));
        let req = worker::Request::new_with_init("https://api.resend.com/emails", &init)
            .map_err(|e| MailError::Network(e.to_string()))?;
        let mut resp = worker::Fetch::Request(req).send().await.map_err(|e| MailError::Network(e.to_string()))?;
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_default();
            return Err(MailError::Provider(format!("resend {status}: {body}")));
        }
        Ok(())
    }
}

pub struct MailChannelsProvider {
    pub dkim_domain: String,
    pub dkim_selector: String,
    pub dkim_private_key: String,
}

impl MailProvider for MailChannelsProvider {
    async fn send(&self, m: &MailMessage) -> Result<(), MailError> {
        let mut content = vec![json!({"type": "text/plain", "value": m.text})];
        if let Some(html) = &m.html {
            content.push(json!({"type": "text/html", "value": html}));
        }
        let body = json!({
            "personalizations": [{
                "to": [{"email": m.to}],
                "dkim_domain": self.dkim_domain,
                "dkim_selector": self.dkim_selector,
                "dkim_private_key": self.dkim_private_key,
            }],
            "from": {"email": m.from_email, "name": m.from_name},
            "subject": m.subject,
            "content": content,
        });
        let headers = worker::Headers::new();
        headers.set("content-type", "application/json").map_err(|e| MailError::Config(e.to_string()))?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Post);
        init.with_headers(headers);
        init.with_body(Some(body.to_string().into()));
        let req = worker::Request::new_with_init("https://api.mailchannels.net/tx/v1/send", &init)
            .map_err(|e| MailError::Network(e.to_string()))?;
        let mut resp = worker::Fetch::Request(req).send().await.map_err(|e| MailError::Network(e.to_string()))?;
        let status = resp.status_code();
        if !(200..=299).contains(&status) {
            let body = resp.text().await.unwrap_or_default();
            return Err(MailError::Provider(format!("mailchannels {status}: {body}")));
        }
        Ok(())
    }
}

pub enum Provider {
    Log(LogProvider),
    Resend(ResendProvider),
    MailChannels(MailChannelsProvider),
}

impl Provider {
    pub async fn send(&self, message: &MailMessage) -> Result<(), MailError> {
        match self {
            Self::Log(p) => p.send(message).await,
            Self::Resend(p) => p.send(message).await,
            Self::MailChannels(p) => p.send(message).await,
        }
    }
}

pub fn provider_from_env(env: &Env) -> Provider {
    if let Ok(secret) = env.secret("RESEND_API_KEY") {
        return Provider::Resend(ResendProvider { api_key: secret.to_string() });
    }
    if let (Ok(domain), Ok(selector), Ok(key)) = (
        env.var("MAILCHANNELS_DKIM_DOMAIN"),
        env.var("MAILCHANNELS_DKIM_SELECTOR"),
        env.secret("MAILCHANNELS_DKIM_PRIVATE_KEY"),
    ) {
        return Provider::MailChannels(MailChannelsProvider {
            dkim_domain: domain.to_string(),
            dkim_selector: selector.to_string(),
            dkim_private_key: key.to_string(),
        });
    }
    Provider::Log(LogProvider)
}

pub fn from_address(env: &Env) -> (String, String) {
    // SMTP_FROM / SMTP_FROM_NAME may be supplied as either env vars or secrets.
    // Workers exposes both through `env.var()` plus the secret-only API; check
    // both so operators don't need to remember which one they used.
    let lookup = |name: &str| -> Option<String> {
        env.var(name).ok().map(|v| v.to_string()).or_else(|| env.secret(name).ok().map(|v| v.to_string()))
    };
    let email = lookup("SMTP_FROM").unwrap_or_else(|| "noreply@vaultwarden.local".to_owned());
    let name = lookup("SMTP_FROM_NAME").unwrap_or_else(|| "Vaultwarden".to_owned());
    (email, name)
}
