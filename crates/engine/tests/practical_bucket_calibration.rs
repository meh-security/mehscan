use mehscan_core::Capability;
use mehscan_engine::investigation::build_review_inventory;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str, extension: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("mehscan-bucket-{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(format!("app.{extension}")), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn redirect_origin_questions_do_not_override_the_comprehensive_impact_lane() {
    let fixture = Fixture::new(
        "redirect",
        "from django.shortcuts import redirect\ndef navigate(request):\n    return redirect(request.GET['next'])\n",
        "py",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    let redirects = inventory
        .entries
        .iter()
        .filter(|entry| entry.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert!(!redirects.is_empty(), "lost unresolved redirect research");
    assert!(redirects.iter().all(|entry| {
        entry
            .value_hint
            .as_ref()
            .is_some_and(|hint| hint.reason == "medium_impact_relationship")
    }));
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|item| item.capability == Capability::Redirect
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")),
        "the origin question must remain available"
    );
}

#[test]
fn fixed_padding_leaves_both_queues_without_dropping_raw_html_or_formatting() {
    let fixture = Fixture::new(
        "padding",
        r#"from django.utils.safestring import mark_safe
def padding(depth):
    return mark_safe("&nbsp;" * 4 * depth)
def raw(value):
    return mark_safe(value)
def mixed(value, depth):
    return mark_safe(("&nbsp;" + value) * depth)
def interpolated(value):
    return mark_safe(f" {value}")
def formatted(value):
    return mark_safe(" %s" % value)
def escaped_bytes(depth):
    return mark_safe("&nbsp;\x3cscript>" * depth)
"#,
        "py",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert!(inventory.scan.evidence.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("padding")
            && item
                .tags
                .iter()
                .any(|tag| tag == "html-origin:fixed-padding")
    }));
    assert!(
        !inventory
            .entries
            .iter()
            .any(|entry| entry.symbol.as_deref() == Some("padding"))
    );
    for symbol in ["raw", "mixed", "interpolated", "formatted", "escaped_bytes"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput),
            "lost dynamic HTML {symbol}"
        );
    }
}

#[test]
fn jsx_props_are_not_browser_sinks_and_link_research_does_not_defer_unsafe_construction() {
    let fixture = Fixture::new(
        "links",
        r#"import React from 'react';
function Custom(url) { return <SafeLink href={url}/>; }
function Namespaced(url) { return <ui.SafeLink href={url}/>; }
function Ordinary(url) { return <a href={url}>link</a>; }
function Area(url) { return <area href={url}/>; }
function Resource(url) { return <base href={url}/>; }
function Constructed(value) { const url = `javascript:${value}`; return <a href={url}>link</a>; }
function Mutated(url, value) { url = `javascript:${value}`; return <a href={url}>link</a>; }
function Default(value, url = `javascript:${value}`) { return <a href={url}>link</a>; }
function Raw(value) { return <div dangerouslySetInnerHTML={{__html:value}}/>; }
function Input() { return <a href={window.location.hash}>link</a>; }
"#,
        "tsx",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    assert!(!inventory.scan.evidence.iter().any(|item| {
        item.rule_id.ends_with("react-url-attribute-output")
            && matches!(
                item.enclosing_symbol.as_deref(),
                Some("Custom" | "Namespaced")
            )
    }));
    for symbol in ["Ordinary", "Area"] {
        assert!(
            !inventory.entries.iter().any(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.rule_id.ends_with("react-url-attribute-output")
            }),
            "ordinary parameter forwarding is not mandatory research"
        );
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|item| item.enclosing_symbol.as_deref() == Some(symbol)
                    && item.rule_id.ends_with("react-url-attribute-output")),
            "scope exclusion must not pretend this URL is proven safe"
        );
    }
    for symbol in [
        "Resource",
        "Constructed",
        "Mutated",
        "Default",
        "Raw",
        "Input",
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput
            })
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost meaningful boundary {symbol}");
        assert!(
            entries.iter().all(|entry| entry.value_hint.is_none()),
            "unexpected deferral for {symbol}"
        );
    }
}

#[test]
fn frontend_writer_research_defers_links_and_css_without_demoting_raw_html_or_input() {
    let fixture = Fixture::new(
        "frontend-writers",
        r#"import React from 'react';
function StoredLink(record) { return <a href={record.url}>link</a>; }
function StoredArea(record) { return <area href={record.url}/>; }
function Sheet(config) { return <style dangerouslySetInnerHTML={{__html:config.css}}/>; }
function NamedStyle(config) { return <Style dangerouslySetInnerHTML={{__html:config.css}}/>; }
function Markup(record) { return <div dangerouslySetInnerHTML={{__html:record.body}}/>; }
function Active(record) { return <base href={record.url}/>; }
function FromInput() { return <a href={window.location.hash}>link</a>; }
function InputSheet() { return <style dangerouslySetInnerHTML={{__html:window.location.hash}}/>; }
"#,
        "tsx",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for (symbol, reason) in [
        ("StoredLink", "frontend_link_writer_research"),
        ("StoredArea", "frontend_link_writer_research"),
        ("Sheet", "frontend_stylesheet_writer_research"),
    ] {
        let entry = inventory
            .entries
            .iter()
            .find(|e| e.symbol.as_deref() == Some(symbol))
            .unwrap_or_else(|| panic!("lost Comprehensive research {symbol}"));
        assert_eq!(
            entry.value_hint.as_ref().map(|h| h.reason.as_str()),
            Some(reason)
        );
    }
    for symbol in ["NamedStyle", "Markup", "Active", "FromInput", "InputSheet"] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| {
                e.symbol.as_deref() == Some(symbol) && e.capability == Capability::HtmlOutput
            })
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost consequential boundary {symbol}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "demoted {symbol}"
        );
    }
}

#[test]
fn vue_unconnected_html_is_research_without_claiming_static_or_safe() {
    let fixture = Fixture::new(
        "vue-producer-research",
        r#"<template>
<div v-html="art.close"></div>
<div v-html="$t('message')"></div>
<div v-html="record.body"></div>
</template>
<script>export default { data() { return { art: Object.freeze({close:'<svg/>'}), record: {} }; } };</script>"#,
        "vue",
    );
    fs::write(
        fixture.0.join("Input.vue"),
        r#"<template><div v-html="html"></div></template>
<script setup>const html = window.location.hash;</script>"#,
    )
    .unwrap();
    fs::write(
        fixture.0.join("Dom.vue"),
        r#"<template><div ref="preview"></div></template>
<script setup>import { ref, onMounted } from 'vue'; const preview=ref(null);
onMounted(() => { preview.value.innerHTML=window.location.hash; });</script>"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let unresolved = inventory
        .entries
        .iter()
        .filter(|e| e.path == "app.vue")
        .collect::<Vec<_>>();
    assert_eq!(
        unresolved.len(),
        3,
        "all unresolved consumers stay in Comprehensive"
    );
    assert!(unresolved.iter().all(|e| {
        e.value_hint.as_ref().is_some_and(|h| {
            h.reason == "frontend_html_producer_research" && h.depends_on.is_none()
        })
    }));
    assert_eq!(
        inventory
            .scan
            .evidence
            .iter()
            .filter(|e| e.location.path == "app.vue" && e.kind == mehscan_core::EvidenceKind::Sink)
            .count(),
        3
    );
    for path in ["Input.vue", "Dom.vue"] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| e.path == path && e.capability == Capability::HtmlOutput)
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost input-bearing component {path}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "deferred observed input {path}"
        );
    }
}

#[test]
fn framework_consumer_context_keeps_raw_html_and_active_urls_in_value() {
    let fixture = Fixture::new(
        "framework-consumers",
        r#"import React from 'react';
import { h } from 'vue';
import { createSignal } from 'solid-js';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';
import $ from 'jquery';
import { DomSanitizer } from '@angular/platform-browser';
function ReactCss(config) { return React.createElement('style', {dangerouslySetInnerHTML:{__html:config.css}}); }
function ReactHtml(config) { return React.createElement('div', {dangerouslySetInnerHTML:{__html:config.html}}); }
function ReactUnknown(tag, config) { return React.createElement(tag, {dangerouslySetInnerHTML:{__html:config.html}}); }
function VueCss(config) { return h('style', {innerHTML:config.css}); }
function VueHtml(config) { return h('section', {innerHTML:config.html}); }
function VueInputCss() { return h('style', {innerHTML:window.location.hash}); }
function VueUnknown(tag, config) { return h(tag, {innerHTML:config.html}); }
function SolidCss(config) { return <style innerHTML={config.css}/>; }
function SolidHtml(config) { return <section innerHTML={config.html}/>; }
function SolidInputCss() { return <style innerHTML={window.location.hash}/>; }
function LitHtml(config) { return unsafeHTML(config.html); }
function LitInput() { return unsafeHTML(window.location.hash); }
function JqueryHtml(config) { return $(document.querySelector('#preview')).html(config.html); }
function JqueryInput() { return $(document.querySelector('#preview')).html(window.location.hash); }
function DomHtml(config) { document.querySelector('#preview').innerHTML = config.html; }
function AngularUrl(sanitizer: DomSanitizer, config) { return sanitizer.bypassSecurityTrustUrl(config.url); }
function AngularHtml(sanitizer: DomSanitizer, config) { return sanitizer.bypassSecurityTrustHtml(config.html); }
function AngularScript(sanitizer: DomSanitizer, config) { return sanitizer.bypassSecurityTrustScript(config.script); }
function AngularResource(sanitizer: DomSanitizer, config) { return sanitizer.bypassSecurityTrustResourceUrl(config.url); }
function AngularConstructed(sanitizer: DomSanitizer, value) { const url = `javascript:${value}`; return sanitizer.bypassSecurityTrustUrl(url); }
function AngularDirect(sanitizer: DomSanitizer, value) { return sanitizer.bypassSecurityTrustUrl (`javascript:${value}`); }
function AngularMutated(sanitizer: DomSanitizer, url, value) { url = `javascript:${value}`; return sanitizer.bypassSecurityTrustUrl(url); }
function AngularInput(sanitizer: DomSanitizer) { return sanitizer.bypassSecurityTrustUrl(window.location.hash); }
"#,
        "tsx",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for (symbol, reason) in [
        ("ReactCss", "frontend_stylesheet_writer_research"),
        ("VueCss", "frontend_stylesheet_writer_research"),
        ("SolidCss", "frontend_stylesheet_writer_research"),
        ("AngularUrl", "frontend_link_writer_research"),
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput
            })
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "lost context research {symbol}");
        assert!(
            entries.iter().all(|entry| {
                entry
                    .value_hint
                    .as_ref()
                    .is_some_and(|hint| hint.reason == reason)
            }),
            "incorrect context bucket for {symbol}: {entries:#?}"
        );
    }
    for symbol in [
        "ReactHtml",
        "ReactUnknown",
        "VueHtml",
        "VueInputCss",
        "SolidHtml",
        "SolidInputCss",
        "LitHtml",
        "LitInput",
        "JqueryHtml",
        "JqueryInput",
        "DomHtml",
        "AngularHtml",
        "AngularScript",
        "AngularResource",
        "AngularConstructed",
        "AngularDirect",
        "AngularMutated",
        "AngularInput",
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput
            })
            .collect::<Vec<_>>();
        assert!(
            !entries.is_empty(),
            "lost meaningful HTML consumer {symbol}"
        );
        assert!(
            entries.iter().all(|entry| entry.value_hint.is_none()),
            "demoted meaningful HTML consumer {symbol}: {entries:#?}"
        );
    }
    for symbol in ["VueInputCss", "SolidInputCss", "LitInput", "JqueryInput"] {
        assert!(
            inventory.scan.evidence.iter().any(|item| {
                item.enclosing_symbol.as_deref() == Some(symbol)
                    && item.capability == Capability::BrowserInput
            }),
            "discarded connected browser input for {symbol}"
        );
    }
}

#[test]
fn restricted_final_dompurify_control_leaves_both_queues_without_closing_mutated_output() {
    let fixture = Fixture::new(
        "sanitizer",
        r#"import React from 'react';
import purify from 'dompurify';
import { h } from 'vue';
import { createSignal } from 'solid-js';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';
import $ from 'jquery';
function Controlled(value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span','button'],ALLOWED_ATTR:['type','contenteditable','data-field','disabled','class']}); }
function ControlledJsx(value) { return <div dangerouslySetInnerHTML={{__html:purify.sanitize(value, {ALLOWED_TAGS:['b'],ALLOWED_ATTR:[]})}}/>; }
function ControlledVue(value) { return h('div', {innerHTML:purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]})}); }
function ControlledSolid(value) { return <div innerHTML={purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]})}/>; }
function ControlledLit(value) { return unsafeHTML(purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]})); }
function ControlledJquery(value) { return $(document.querySelector('#preview')).html(purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]})); }
function LaterMarkup(value, extra) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]}) + extra; }
function DynamicPolicy(value, policy) { document.querySelector('#preview').innerHTML = purify.sanitize(value, policy); }
function ActiveTags(value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['script'],ALLOWED_ATTR:[]}); }
function ActiveAttributes(value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:['onclick']}); }
function ExtraOptions(value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[],ADD_TAGS:['script']}); }
function Shadowed(purify, value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]}); }
function Css(value) { return <style dangerouslySetInnerHTML={{__html:purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]})}}/>; }
"#,
        "tsx",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for symbol in [
        "Controlled",
        "ControlledJsx",
        "ControlledVue",
        "ControlledSolid",
        "ControlledLit",
        "ControlledJquery",
    ] {
        assert!(
            inventory.scan.evidence.iter().any(|item| {
                item.enclosing_symbol.as_deref() == Some(symbol)
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "html-control:restricted-dompurify")
            }),
            "lost owned final control {symbol}"
        );
        assert!(
            !inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some(symbol)),
            "still scheduling complete output control {symbol}"
        );
    }
    for symbol in [
        "LaterMarkup",
        "DynamicPolicy",
        "ActiveTags",
        "ActiveAttributes",
        "ExtraOptions",
        "Shadowed",
        "Css",
    ] {
        assert!(
            inventory.entries.iter().any(|entry| {
                entry.symbol.as_deref() == Some(symbol)
                    && entry.capability == Capability::HtmlOutput
            }),
            "incorrect sanitizer exclusion {symbol}"
        );
    }
    fs::write(
        fixture.0.join("policy.ts"),
        "import purifier from 'dompurify'; purifier.addHook('afterSanitizeAttributes', mutate);",
    )
    .unwrap();
    let customized = build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["Controlled", "ControlledJsx"] {
        assert!(
            customized
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some(symbol)),
            "custom policy was ignored for {symbol}"
        );
    }
}

#[test]
fn restricted_control_keeps_shadowed_escaped_or_replaced_sanitizer_objects_reviewable() {
    let output = "document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]});";
    for (label, source) in [
        (
            "destructured",
            format!(
                "function Consumer(value, replacement) {{ const {{purify}} = replacement; {output} }}"
            ),
        ),
        (
            "destructured-alias",
            format!(
                "function Consumer(value, replacement) {{ const {{clean:purify}} = replacement; {output} }}"
            ),
        ),
        (
            "array-shadow",
            format!(
                "function Consumer(value, replacement) {{ const [purify] = replacement; {output} }}"
            ),
        ),
        (
            "escaped-call",
            format!("configure(purify); function Consumer(value) {{ {output} }}"),
        ),
        (
            "escaped-default",
            format!(
                "function configure(target = purify) {{ target.sanitize = value => value; }} configure(); function Consumer(value) {{ {output} }}"
            ),
        ),
        (
            "escaped-alias",
            format!(
                "const alias = purify; alias.sanitize = value => value; function Consumer(value) {{ {output} }}"
            ),
        ),
        (
            "escaped-shorthand",
            format!("configure({{purify}}); function Consumer(value) {{ {output} }}"),
        ),
        (
            "exported",
            format!("export {{purify}}; function Consumer(value) {{ {output} }}"),
        ),
        (
            "replacement",
            format!("purify.sanitize = value => value; function Consumer(value) {{ {output} }}"),
        ),
        (
            "computed-replacement",
            format!("purify['sanitize'] = value => value; function Consumer(value) {{ {output} }}"),
        ),
    ] {
        let fixture = Fixture::new(
            &format!("ownership-{label}"),
            &format!("import purify from 'dompurify';\n{source}"),
            "tsx",
        );
        let inventory = build_review_inventory(&fixture.0, false).unwrap();
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some("Consumer")
                    && entry.capability == Capability::HtmlOutput),
            "lost unresolved ownership {label}"
        );
        assert!(
            !inventory.scan.evidence.iter().any(|item| item
                .tags
                .iter()
                .any(|tag| tag == "html-control:restricted-dompurify")),
            "invented complete control {label}"
        );
    }
    for (label, loader) in [
        ("module-require", "const purify = require('dompurify');"),
        (
            "shadow-require",
            "const require = () => ({sanitize: value => value}); const purify = require('dompurify');",
        ),
        (
            "replaced-require",
            "require = () => ({sanitize: value => value}); const purify = require('dompurify');",
        ),
    ] {
        let fixture = Fixture::new(
            &format!("ownership-{label}"),
            &format!("{loader}\nfunction Consumer(value) {{ {output} }}"),
            "js",
        );
        let inventory = build_review_inventory(&fixture.0, false).unwrap();
        assert_eq!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some("Consumer")
                    && entry.capability == Capability::HtmlOutput),
            label != "module-require",
            "incorrect CommonJS ownership: {label}"
        );
    }
}

#[test]
fn shared_import_mutation_cancels_control_exclusion_across_files() {
    let fixture = Fixture::new(
        "shared-control",
        "import purify from 'dompurify';\nfunction Consumer(value) { document.querySelector('#preview').innerHTML = purify.sanitize(value, {ALLOWED_TAGS:['span'],ALLOWED_ATTR:[]}); }",
        "tsx",
    );
    let baseline = build_review_inventory(&fixture.0, false).unwrap();
    assert!(
        !baseline
            .entries
            .iter()
            .any(|entry| entry.symbol.as_deref() == Some("Consumer"))
    );
    for mutation in [
        "import cleaner from 'dompurify'; cleaner.sanitize = value => value;",
        "import cleaner from 'dompurify'; const alias = cleaner; configure(alias);",
        "import cleaner from 'dompurify'; export {cleaner};",
        "import cleaner from 'dompurify'; cleaner\n.addHook('afterSanitizeAttributes', mutate);",
        "import cleaner from 'dompurify'; cleaner\n.setConfig(policy);",
        "import * as cleaner from 'dompurify'; cleaner.default.sanitize = value => value;",
        "import {default as cleaner} from 'dompurify'; cleaner.sanitize = value => value;",
        "export {default} from 'dompurify';",
    ] {
        fs::write(fixture.0.join("policy.ts"), mutation).unwrap();
        let inventory = build_review_inventory(&fixture.0, false).unwrap();
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some("Consumer")
                    && entry.capability == Capability::HtmlOutput),
            "ignored shared instance effect: {mutation}"
        );
    }
}

#[test]
fn django_selector_used_only_to_narrow_a_queryset_is_not_an_authorization_sink() {
    let fixture = Fixture::new(
        "narrowing",
        r#"
def scalar(qs, code):
    locale_id = (
        Locale.objects.filter(language_code=code)
        .values_list('pk', flat=True)
        .get()
    )
    return qs.filter(locale_id=locale_id)
def record(objects, code):
    selected = Locale.objects.get(language_code=code)
    objects = objects.filter(locale=selected)
    return objects
def disclosure(qs, code):
    selected = Page.objects.get(pk=code)
    print(selected.title)
    return qs.filter(parent=selected)
def returned(qs, code):
    selected = Page.objects.get(pk=code)
    return selected
def mutation(qs, code):
    selected = Page.objects.get(pk=code)
    selected.delete()
    return qs.filter(parent=selected)
def selected_receiver(qs, code):
    selected = Page.objects.get(pk=code)
    return selected.children.filter(pk=qs)
def wrapped(qs, code):
    selected = serialize(Page.objects.get(pk=code))
    return qs.filter(parent=selected)
def chained_delete(qs, code):
    selected = Page.objects.get(pk=code)
    return qs.filter(parent=selected).delete()
def later_delete(qs, code):
    selected = Page.objects.get(pk=code)
    qs = qs.filter(parent=selected)
    return qs.delete()
def chained_read(qs, code):
    selected = Page.objects.get(pk=code)
    return qs.filter(parent=selected).first().private_note
def projected_data(qs, code):
    selected = Account.objects.filter(pk=code).values_list('api_key', flat=True).get()
    return qs.filter(access_key=selected)
def requested_tenant(qs, request):
    selected = Tenant.objects.get(pk=request.GET['tenant'])
    return qs.filter(tenant=selected)
def requested_alias(qs, request):
    tenant_id = request.GET['tenant']
    selected_id = tenant_id
    selected = Tenant.objects.get(pk=selected_id)
    return qs.filter(tenant=selected)
"#,
        "py",
    );
    let inventory = build_review_inventory(&fixture.0, false).unwrap();
    for symbol in ["scalar", "record"] {
        assert!(
            !inventory
                .scan
                .evidence
                .iter()
                .any(|item| item.rule_id == "python-django-orm-resource-access"
                    && item.enclosing_symbol.as_deref() == Some(symbol)),
            "unused sink extraction for {symbol}"
        );
    }
    for symbol in [
        "disclosure",
        "returned",
        "mutation",
        "selected_receiver",
        "wrapped",
        "chained_delete",
        "later_delete",
        "chained_read",
        "projected_data",
        "requested_tenant",
        "requested_alias",
    ] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.rule_id == "python-django-orm-resource-access"
                    && entry.symbol.as_deref() == Some(symbol)),
            "lost actual record use {symbol}"
        );
    }
}
