use super::*;

fn repository(files: &[(&str, &str)]) -> RepositorySources {
    RepositorySources {
        root: "fixture".into(),
        files: files
            .iter()
            .map(|(path, source)| {
                (
                    (*path).into(),
                    SourceFile {
                        path: (*path).into(),
                        language: if path.ends_with(".html") {
                            None
                        } else if path.ends_with(".js") {
                            Some(Language::Javascript)
                        } else if path.ends_with(".tsx") {
                            Some(Language::Tsx)
                        } else {
                            Some(Language::Typescript)
                        },
                        source: (*source).into(),
                    },
                )
            })
            .collect(),
    }
}

fn packet(
    sources: &RepositorySources,
    path: &str,
    limit: usize,
) -> (Vec<ReviewNeighborhoodFact>, bool) {
    let file = &sources.files[path];
    let context = fact(
        file,
        0,
        file.source.len(),
        "sink_context",
        "bypassSecurityTrustHtml",
    );
    let result = AngularContext::build(sources).facts(
        sources,
        &BTreeSet::from([path]),
        &[context],
        None,
        limit,
        None,
    );
    for f in &result.0 {
        let original = &sources.files[&f.location.path].source;
        assert_eq!(
            &original[f.location.start.byte_offset..f.location.end.byte_offset],
            f.excerpt,
            "fabricated or mislocated {}",
            f.role
        );
    }
    result
}

const PIPE: &str = "import { Pipe } from '@angular/core'; @Pipe({ name: 'trust' }) export class HtmlPipe { transform(value:string) {return this.s.bypassSecurityTrustHtml(value);} }";

#[test]
fn supported_js_and_tsx_parsers_keep_actual_resource_consumers() {
    for path in ["view.js", "view.tsx"] {
        let sources = repository(&[(
            path,
            "import {Component} from '@angular/core'; @Component({template:'<iframe [src]=\"url\"></iframe>'}) class View {show(v){this.url=this.s.bypassSecurityTrustResourceUrl(v);}}",
        )]);
        let (facts, cut) = packet(&sources, path, 8);
        assert!(!cut, "{path}: {facts:#?}");
        assert!(
            facts
                .iter()
                .any(|f| f.role == "frontend_template_binding_context"
                    && f.excerpt.contains("iframe [src]"))
        );
    }
}

#[test]
fn standalone_pipes_require_registration_and_resolve_import_aliases() {
    let sources = repository(&[
        ("pipe.ts", PIPE),
        (
            "host.ts",
            "import { Component } from '@angular/core'; import { HtmlPipe as Trust } from './pipe'; @Component({imports:[Trust],template:'<div [innerHTML]=\"value | trust\"></div>'}) export class Host {}",
        ),
        (
            "unused.ts",
            "import { Component } from '@angular/core'; import { HtmlPipe } from './pipe'; @Component({template:'<div [innerHTML]=\"value | trust\"></div>'}) export class Unused {}",
        ),
        (
            "foreign.ts",
            "import { Component } from 'another'; import { HtmlPipe } from './pipe'; @Component({imports:[HtmlPipe],template:'<div [innerHTML]=\"value | trust\"></div>'}) export class Foreign {}",
        ),
    ]);
    let (facts, cut) = packet(&sources, "pipe.ts", 8);
    assert!(!cut, "{facts:#?}");
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_pipe_implementation_context"
                && f.excerpt.contains("transform(value"))
    );
    let consumers: Vec<_> = facts
        .iter()
        .filter(|f| f.role == "frontend_pipe_consumer_context")
        .collect();
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0].location.path, "host.ts");
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_import_binding_context" && f.excerpt.contains("as Trust"))
    );
}

#[test]
fn ngmodule_scope_uses_exports_and_keeps_private_pipes_private() {
    for exported in [false, true] {
        let module = format!(
            "import {{NgModule}} from '@angular/core'; import {{HtmlPipe}} from './pipe'; @NgModule({{declarations:[HtmlPipe],exports:[{}]}}) export class Shared {{}}",
            if exported { "HtmlPipe" } else { "" }
        );
        let sources = repository(&[
            ("pipe.ts", PIPE),
            ("shared.ts", &module),
            (
                "host.ts",
                "import {Component} from '@angular/core'; import {Shared} from './shared'; @Component({imports:[Shared],template:'<div [innerHTML]=\"message | trust\"></div>'}) export class Host {}",
            ),
        ]);
        let (facts, cut) = packet(&sources, "pipe.ts", 8);
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_pipe_consumer_context"),
            exported,
            "{facts:#?}"
        );
        assert_eq!(cut, !exported);
        if exported {
            assert!(
                facts
                    .iter()
                    .any(|f| f.role == "frontend_module_registration_context")
            );
        }
    }
    let sources = repository(&[(
        "app.ts",
        "import {Component,Pipe,NgModule} from '@angular/core'; @Pipe({name:'trust',standalone:false}) class HtmlPipe {transform(value:any){return this.s.bypassSecurityTrustHtml(value)}} @Component({standalone:false,template:'<p>{{ value | trust }}</p>'}) class Host {} @NgModule({declarations:[Host,HtmlPipe]}) class App {}",
    )]);
    let (facts, cut) = packet(&sources, "app.ts", 8);
    assert!(!cut);
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_pipe_consumer_context" && f.excerpt.starts_with("{{"))
    );
}

#[test]
fn same_named_pipes_in_different_modules_do_not_bind_to_each_other() {
    let sources = repository(&[
        ("pipe.ts", PIPE),
        (
            "other.ts",
            "import {Pipe} from '@angular/core'; @Pipe({name:'trust'}) export class Other {transform(v:any){return v}}",
        ),
        (
            "host.ts",
            "import {Component} from '@angular/core'; import {Other} from './other'; @Component({imports:[Other],template:'<div [innerHTML]=\"value | trust\"></div>'}) class Host {}",
        ),
    ]);
    let (facts, cut) = packet(&sources, "pipe.ts", 8);
    assert!(cut);
    assert!(
        facts
            .iter()
            .all(|f| f.role != "frontend_pipe_consumer_context")
    );
}

#[test]
fn component_handoffs_handle_decorator_signal_and_two_way_input_aliases() {
    for (imports, input, binding) in [
        (
            "Component,Input",
            "@Input('markup') content:any;",
            "[markup]",
        ),
        (
            "Component,Input",
            "@Input({alias:'markup'}) content:any;",
            "[markup]",
        ),
        (
            "Component,input as accept",
            "content=accept.required<any>({alias:'markup'});",
            "[markup]",
        ),
        (
            "Component,model",
            "content=model<any>(null,{alias:'markup'});",
            "[(markup)]",
        ),
    ] {
        let child = format!(
            "import {{{imports}}} from '@angular/core'; @Component({{selector:'child-view',template:'<p [innerHTML]=\"content\"></p>'}}) export class Child {{{input}}}"
        );
        let parent = format!(
            "import {{Component}} from '@angular/core'; import {{Child as Render}} from './child'; @Component({{imports:[Render],template:'<child-view {binding}=\"html\"></child-view>'}}) class Parent {{show(v:any){{this.html=this.s.bypassSecurityTrustHtml(v);}}}}"
        );
        let sources = repository(&[("child.ts", &child), ("parent.ts", &parent)]);
        let (facts, cut) = packet(&sources, "parent.ts", 8);
        assert!(!cut, "{input}: {facts:#?}");
        assert!(
            facts
                .iter()
                .any(|f| f.role == "frontend_component_input_context"
                    && f.excerpt.contains(input.trim_end_matches(';')))
        );
        assert!(
            facts
                .iter()
                .any(|f| f.role == "frontend_component_handoff_context")
        );
        assert!(facts.iter().any(
            |f| f.role == "frontend_template_binding_context" && f.location.path == "child.ts"
        ));
    }
}

#[test]
fn input_initial_object_is_not_options_and_dynamic_aliases_do_not_bind() {
    for (input, binding, expected) in [
        ("content=input({alias:'initialValue'});", "content", true),
        (
            "content=input.required({alias:computeAlias()});",
            "content",
            false,
        ),
        (
            "@Input({alias:computeAlias()}) content:any;",
            "content",
            false,
        ),
        (
            "content=input.required({...options,alias:'markup'});",
            "markup",
            false,
        ),
    ] {
        let child = format!(
            "import {{Component,input,Input}} from '@angular/core'; @Component({{selector:'child-view',template:'<p [innerHTML]=\"content()\"></p>'}}) export class Child {{{input}}}"
        );
        let parent = format!(
            "import {{Component}} from '@angular/core'; import {{Child}} from './child'; @Component({{imports:[Child],template:'<child-view [{binding}]=\"html\"></child-view>'}}) class Parent {{show(v:any){{this.html=this.s.bypassSecurityTrustHtml(v);}}}}"
        );
        let sources = repository(&[("parent.ts", &parent), ("child.ts", &child)]);
        let (facts, _) = packet(&sources, "parent.ts", 8);
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_component_handoff_context"),
            expected,
            "{input}: {facts:#?}"
        );
    }
}

#[test]
fn projected_member_does_not_turn_other_fields_into_html_consumers() {
    let sources = repository(&[
        (
            "parent.ts",
            "import {Component} from '@angular/core'; import {Child} from './child'; @Component({imports:[Child],template:'<child-view [item]=\"item\"></child-view>'}) class Parent {show(item:any){item.description=this.s.bypassSecurityTrustHtml(item.description);}}",
        ),
        (
            "child.ts",
            "import {Component,input} from '@angular/core'; @Component({selector:'child-view',template:'@let product = item(); <img [src]=\"product.image\"><p [innerHTML]=\"product.description\"></p>'}) export class Child {item=input.required<any>();}",
        ),
    ]);
    let (facts, cut) = packet(&sources, "parent.ts", 8);
    assert!(!cut, "{facts:#?}");
    let consumers: Vec<_> = facts
        .iter()
        .filter(|f| f.role == "frontend_template_binding_context")
        .collect();
    assert_eq!(consumers.len(), 1);
    assert!(consumers[0].excerpt.contains("product.description"));
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_template_alias_context")
    );
}

#[test]
fn aliases_inside_comments_attributes_and_interpolation_do_not_create_edges() {
    let sources = repository(&[(
        "view.ts",
        "import {Component} from '@angular/core'; @Component({template:`<!-- @let fake = html; --><p title=\"@let other = html;\">{{ '@let quoted = html;' }}</p><div [innerHTML]=\"fake\"></div><div [innerHTML]=\"other\"></div><div [innerHTML]=\"quoted\"></div>`}) class View {show(v:any){this.html=this.s.bypassSecurityTrustHtml(v);}}",
    )]);
    let (facts, partial) = packet(&sources, "view.ts", 8);
    assert!(partial);
    assert!(facts.iter().all(|f| !matches!(
        f.role.as_str(),
        "frontend_template_alias_context" | "frontend_template_binding_context"
    )));
}

#[test]
fn static_core_forwardref_is_registration_but_foreign_lookalike_is_not() {
    for module in ["@angular/core", "foreign"] {
        let host = format!(
            "import {{Component}} from '@angular/core'; import {{forwardRef as later}} from '{module}'; import {{HtmlPipe}} from './pipe'; @Component({{imports:[later(()=>HtmlPipe)],template:'<p [innerHTML]=\"value | trust\"></p>'}}) class Host {{}}"
        );
        let sources = repository(&[("pipe.ts", PIPE), ("host.ts", &host)]);
        let (facts, _) = packet(&sources, "pipe.ts", 8);
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_pipe_consumer_context"),
            module == "@angular/core"
        );
    }
}

#[test]
fn foreign_or_unregistered_inputs_and_selectors_are_not_handoffs() {
    for registered in [false, true] {
        let parent = format!(
            "import {{Component}} from '@angular/core'; import {{Child}} from './child'; @Component({{imports:[{}],template:'<child-view [markup]=\"html\"></child-view>'}}) class Parent {{show(v:any){{this.html=this.s.bypassSecurityTrustHtml(v);}}}}",
            if registered { "Child" } else { "" }
        );
        let child = "import {Component} from '@angular/core'; import {input} from 'foreign'; @Component({selector:'child-view',template:'<p [innerHTML]=\"content()\"></p>'}) export class Child {content=input(null,{alias:'markup'});}";
        let sources = repository(&[("parent.ts", &parent), ("child.ts", child)]);
        let (facts, cut) = packet(&sources, "parent.ts", 8);
        assert!(cut);
        assert!(
            facts
                .iter()
                .all(|f| f.role != "frontend_component_handoff_context")
        );
    }
}

#[test]
fn static_template_constants_namespace_imports_and_cooked_source_stay_queryable() {
    let sources = repository(&[(
        "view.ts",
        r#"import * as ng from '@angular/core'; const VIEW = '<p [innerHTML]=\"html\"></p>'; @ng.Component({template:VIEW}) class View {show(v:any){this.html=this.s.bypassSecurityTrustHtml(v);}}"#,
    )]);
    let (facts, cut) = packet(&sources, "view.ts", 8);
    assert!(!cut, "{facts:#?}");
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_template_constant_context")
    );
    assert!(facts.iter().any(
        |f| f.role == "frontend_template_binding_context" && f.excerpt.contains(r#"\"html\""#)
    ));
}

#[test]
fn local_library_object_key_handoff_supplies_both_expressions_without_runtime_proof() {
    let sources = repository(&[(
        "view.ts",
        "import {Component} from '@angular/core'; @Component({template:'<figure [innerHTML]=\"entry.args\"></figure>'}) class View {show(feedback:any){feedback.comment=this.s.bypassSecurityTrustHtml(feedback.comment);this.gallery.addImage({args:feedback.comment});}}",
    )]);
    let (facts, cut) = packet(&sources, "view.ts", 8);
    assert!(!cut);
    assert!(facts.iter().any(
        |f| f.role == "frontend_value_handoff_context" && f.excerpt == "args:feedback.comment"
    ));
    assert!(
        facts
            .iter()
            .any(|f| f.role == "frontend_template_binding_context"
                && f.excerpt.contains("entry.args"))
    );
    let (bounded, cut) = packet(&sources, "view.ts", 1);
    assert!(cut);
    assert_eq!(bounded.len(), 1);
}

#[test]
fn host_metadata_and_hostbinding_decorators_expose_real_contexts() {
    for (decorator, field) in [
        (
            "@Component({template:'',host:{'[href]':'url'}})",
            "url:any;",
        ),
        (
            "@Directive({selector:'[rich]'})",
            "@HostBinding('href') url:any;",
        ),
    ] {
        let source = format!(
            "import {{Component,Directive,HostBinding}} from '@angular/core'; {decorator} class View {{{field}show(v:any){{this.url=this.s.bypassSecurityTrustUrl(v);}}}}"
        );
        let sources = repository(&[("view.ts", &source)]);
        let (facts, cut) = packet(&sources, "view.ts", 8);
        assert!(!cut, "{facts:#?}");
        assert!(
            facts
                .iter()
                .any(|f| f.role == "frontend_host_binding_context" && f.excerpt.contains("href"))
        );
    }
}

#[test]
fn metadata_input_aliases_and_text_controls_remain_navigation_not_new_sinks() {
    let sources = repository(&[
        (
            "parent.ts",
            "import {Component} from '@angular/core'; import {Child} from './child'; @Component({imports:[Child],template:'<child-view [markup]=\"html\"></child-view>'}) class Parent {show(v:any){this.html=this.s.bypassSecurityTrustHtml(v);}}",
        ),
        (
            "child.ts",
            "import {Component} from '@angular/core'; @Component({selector:'child-view',inputs:['content:markup'],template:'<p [textContent]=\"content\"></p>'}) export class Child {content:any;}",
        ),
    ]);
    let (facts, cut) = packet(&sources, "parent.ts", 8);
    assert!(!cut);
    assert!(facts.iter().any(
        |f| f.role == "frontend_template_binding_context" && f.excerpt.contains("textContent")
    ));
}

#[test]
fn material_dialog_data_requires_owned_receiver_and_token() {
    for module in ["@angular/material/dialog", "foreign"] {
        let opener = format!(
            "import {{Component,inject}} from '@angular/core'; import {{MatDialog}} from '{module}'; import {{Dialog}} from './dialog'; @Component({{template:''}}) class View {{dialog=inject(MatDialog); show(v:any){{const html=this.s.bypassSecurityTrustHtml(v);this.dialog.open(Dialog,{{data:html}});}}}}"
        );
        let sources = repository(&[
            ("view.ts", &opener),
            (
                "dialog.ts",
                "import {Component,inject} from '@angular/core'; import {MAT_DIALOG_DATA} from '@angular/material/dialog'; @Component({template:'<p [innerHTML]=\"data\"></p>'}) export class Dialog {data=inject(MAT_DIALOG_DATA);}",
            ),
        ]);
        let (facts, cut) = packet(&sources, "view.ts", 8);
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_dialog_handoff_context"),
            module != "foreign",
            "{facts:#?}"
        );
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_template_binding_context"),
            module != "foreign"
        );
        if module != "foreign" {
            assert!(
                facts
                    .iter()
                    .any(|f| f.role == "frontend_dialog_data_context")
            );
        } else {
            assert!(cut);
        }
    }
}

#[test]
fn constructor_material_injection_requires_parameter_properties() {
    for property in ["private ", ""] {
        let opener = format!(
            "import {{Component}} from '@angular/core'; import {{MatDialog as DialogService}} from '@angular/material/dialog'; import {{Dialog}} from './dialog'; @Component({{template:''}}) class View {{constructor({property}dialog:DialogService){{}} show(v:any){{const html=this.s.bypassSecurityTrustHtml(v);this.dialog.open(Dialog,{{data:html}});}}}}"
        );
        let sources = repository(&[
            ("view.ts", &opener),
            (
                "dialog.ts",
                "import {Component,Inject} from '@angular/core'; import {MAT_DIALOG_DATA as DATA} from '@angular/material/dialog'; @Component({template:'<p [innerHTML]=\"data\"></p>'}) export class Dialog {constructor(@Inject(DATA) public data:any){}}",
            ),
        ]);
        let (facts, _) = packet(&sources, "view.ts", 8);
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "frontend_template_binding_context"),
            !property.is_empty(),
            "{facts:#?}"
        );
    }
}
