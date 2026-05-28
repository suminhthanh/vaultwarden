//! Compile-time embedded Handlebars templates.
//!
//! Workers has no filesystem so templates ship as `&'static str`. Each template
//! is registered with handlebars; partials match upstream's `{{> email/foo}}`
//! reference path. To add a template: drop it under `src/templates/email/` or
//! `static/admin/templates/`, `include_str!` it, and call `register_template`.

use handlebars::{
    Context, Handlebars, Helper, HelperResult, Output, Renderable, RenderContext, RenderErrorReason,
};
use serde::Serialize;
use std::sync::OnceLock;

static ENGINE: OnceLock<Handlebars<'static>> = OnceLock::new();

pub fn engine() -> &'static Handlebars<'static> {
    ENGINE.get_or_init(build)
}

fn build() -> Handlebars<'static> {
    let mut h = Handlebars::new();
    h.set_strict_mode(false);

    h.register_helper("case", Box::new(case_helper));
    h.register_helper("eq", Box::new(eq_helper));
    h.register_helper("to_json", Box::new(to_json_helper));

    register_partial(&mut h, "email/email_header", include_str!("templates/email/email_header.hbs"));
    register_partial(&mut h, "email/email_footer", include_str!("templates/email/email_footer.hbs"));
    register_partial(&mut h, "email/email_footer_text", include_str!("templates/email/email_footer_text.hbs"));

    register(&mut h, "email/welcome", include_str!("templates/email/welcome.hbs"));
    register(&mut h, "email/welcome.html", include_str!("templates/email/welcome.html.hbs"));
    register(&mut h, "email/verify_email", include_str!("templates/email/verify_email.hbs"));
    register(&mut h, "email/verify_email.html", include_str!("templates/email/verify_email.html.hbs"));

    // Admin panel — `base.hbs` is the layout; the rest are page partials it
    // includes via `{{> (lookup this "page_content") }}`.
    register(&mut h, "admin/base", include_str!("../static/admin/templates/base.hbs"));
    register_partial(&mut h, "admin/login", include_str!("../static/admin/templates/login.hbs"));
    register_partial(&mut h, "admin/users", include_str!("../static/admin/templates/users.hbs"));
    register_partial(&mut h, "admin/organizations", include_str!("../static/admin/templates/organizations.hbs"));
    register_partial(&mut h, "admin/diagnostics", include_str!("../static/admin/templates/diagnostics.hbs"));
    register_partial(&mut h, "admin/settings", include_str!("../static/admin/templates/settings.hbs"));

    h
}

/// `{{#case value a b c}}…{{else}}…{{/case}}` — block helper that renders the
/// inner template if `value` equals *any* of the trailing params. Mirrors
/// upstream's variadic `case_helper`.
fn case_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    r: &'reg Handlebars<'reg>,
    ctx: &'rc Context,
    rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let probe = h
        .param(0)
        .ok_or_else(|| RenderErrorReason::ParamNotFoundForIndex("case", 0))?
        .value();
    let matched = h.params().iter().skip(1).any(|p| p.value() == probe);
    if matched {
        if let Some(t) = h.template() {
            t.render(r, ctx, rc, out)?;
        }
    } else if let Some(t) = h.inverse() {
        t.render(r, ctx, rc, out)?;
    }
    Ok(())
}

/// `{{eq a b}}` — inline equality helper, used as `{{#if (eq name "x")}}`.
fn eq_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    _r: &'reg Handlebars<'reg>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let a = h.param(0).map(|p| p.value()).unwrap_or(&serde_json::Value::Null);
    let b = h.param(1).map(|p| p.value()).unwrap_or(&serde_json::Value::Null);
    out.write(if a == b { "true" } else { "" })?;
    Ok(())
}

/// `{{to_json value}}` — serialize a value as JSON inline. Used by the
/// admin diagnostics page to embed runtime config blobs.
fn to_json_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    _r: &'reg Handlebars<'reg>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let v = h.param(0).map(|p| p.value()).unwrap_or(&serde_json::Value::Null);
    let s = serde_json::to_string(v).map_err(|e| RenderErrorReason::Other(e.to_string()))?;
    out.write(&s)?;
    Ok(())
}

fn register(h: &mut Handlebars<'static>, name: &str, src: &str) {
    if let Err(e) = h.register_template_string(name, src) {
        worker::console_error!("template '{name}' compile error: {e}");
    }
}

fn register_partial(h: &mut Handlebars<'static>, name: &str, src: &str) {
    if let Err(e) = h.register_partial(name, src) {
        worker::console_error!("partial '{name}' compile error: {e}");
    }
}

/// Render a (subject + body) email template pair. Templates whose first non-blank
/// line is followed by `<!---------------->` use that line as the subject; the
/// rest is the body. Matches upstream Vaultwarden's `mail::send_template` shape.
pub fn render_subject_body<T: Serialize>(name: &str, ctx: &T) -> Result<(String, String), String> {
    let rendered = engine().render(name, ctx).map_err(|e| e.to_string())?;
    let mut split = rendered.splitn(2, "<!---------------->");
    let subject = split.next().unwrap_or("").trim().to_owned();
    let body = split.next().unwrap_or("").trim_start_matches('\n').to_owned();
    Ok((subject, body))
}

/// Render an admin page using the `admin/base` layout. `page` is the partial
/// name (without prefix), e.g. "login" → renders the `admin/login` partial
/// inside `admin/base`.
pub fn render_admin(page: &str, ctx: &serde_json::Value) -> Result<String, String> {
    let mut full = ctx.clone();
    if let Some(map) = full.as_object_mut() {
        map.insert("page_content".into(), serde_json::Value::String(format!("admin/{page}")));
    }
    engine().render("admin/base", &full).map_err(|e| e.to_string())
}
