using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

internal static partial class Program
{
    // Deliberately local: a conditional/earlier assignment, intervening call,
    // different response, or missing framework binding does not close HTML.
    private static bool NonHtmlResponse(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, List<Fact> facts, Diagnostic[] errors)
    {
        if (action is not InvocationExpressionSyntax write
            || model.GetOperation(write) is not IInvocationOperation call
            || call.TargetMethod.Name != "WriteAsync"
            || !AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Http.HttpResponseWritingExtensions")
            || write.Expression is not MemberAccessExpressionSyntax member
            || write.Parent is not AwaitExpressionSyntax awaitWrite
            || awaitWrite.Parent is not ExpressionStatementSyntax statement
            || statement.Parent is not BlockSyntax block) return false;
        var index = block.Statements.IndexOf(statement);
        if (index < 1 || block.Statements[index - 1] is not ExpressionStatementSyntax previous
            || previous.Expression is not AssignmentExpressionSyntax assignment
            || !assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)
            || model.GetOperation(assignment.Left) is not IPropertyReferenceOperation property
            || property.Property.Name != "ContentType"
            || !AspNetApi(property.Property, "Microsoft.AspNetCore.Http.HttpResponse")) return false;
        ISymbol[]? Receiver(IOperation? value)
        {
            while (value is IConversionOperation conversion) value = conversion.Operand;
            if (value is IParameterReferenceOperation parameter) return [parameter.Parameter];
            if (value is ILocalReferenceOperation local) return [local.Local];
            if (value is IPropertyReferenceOperation response && response.Property.Name == "Response"
                && AspNetApi(response.Property, "Microsoft.AspNetCore.Http.HttpContext")
                && Receiver(response.Instance) is { } owner) return [.. owner, response.Property];
            return null;
        }
        var written = Receiver(model.GetOperation(member.Expression));
        var configured = Receiver(property.Instance);
        if (written == null || configured == null || written.Length != configured.Length
            || !written.Zip(configured).All(p => SymbolEqualityComparer.Default.Equals(p.First, p.Second))
            || errors.Any(e => e.Location.IsInSource && e.Location.SourceTree == write.SyntaxTree
                && (e.Location.SourceSpan.IntersectsWith(previous.Span) || e.Location.SourceSpan.IntersectsWith(statement.Span)))) return false;
        // Content evaluation must not receive the context/response binding and
        // thereby change the MIME before the extension consumes it.
        if (write.ArgumentList.DescendantNodes().OfType<IdentifierNameSyntax>().Any(n =>
            SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, written[0]))) return false;
        if (model.GetConstantValue(assignment.Right) is not { HasValue: true, Value: string mime }) return false;
        mime = mime.Split(';')[0].Trim().ToLowerInvariant();
        if (mime is not ("application/json" or "text/plain")) return false;
        facts.Add(new("content", "non_html_response", query.Operand, operand.ToString(), ["explicit_non_html_response"]));
        return true;
    }

    private static bool AspNetApi(ISymbol symbol, string type) => !ErrorType(symbol)
        && symbol.ContainingType.ToDisplayString() == type
        && symbol.DeclaringSyntaxReferences.Length == 0
        && symbol.ContainingAssembly.Identity.PublicKeyToken.Length > 0
        && symbol.ContainingAssembly.Name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal);

    private static bool HtmlSink(ISymbol? symbol) => symbol != null && (
        symbol is IMethodSymbol { MethodKind: MethodKind.Constructor }
            && AspNetApi(symbol, "Microsoft.AspNetCore.Html.HtmlString")
        || symbol.Name == "AppendHtml" && (
            AspNetApi(symbol, "Microsoft.AspNetCore.Html.HtmlContentBuilder")
            || AspNetApi(symbol, "Microsoft.AspNetCore.Html.IHtmlContentBuilder"))
        || symbol.Name == "Raw" && (
            AspNetApi(symbol, "Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper")
            || AspNetApi(symbol, "Microsoft.AspNetCore.Mvc.ViewFeatures.HtmlHelper")));

    // HTML-text only. No blanket trust for IHtmlContent, cached markup, JSON,
    // encoders supplied by application subclasses, or arbitrary render helpers.
    private static bool HtmlShape(SemanticModel model, SyntaxNode operand, SyntaxNode? action,
        Query query, SortedDictionary<string, Source> sources, List<Fact> facts, Diagnostic[] errors)
    {
        bool HasError(SyntaxNode node) => errors.Any(d => d.Location.IsInSource
            && d.Location.SourceTree == node.SyntaxTree && d.Location.SourceSpan.IntersectsWith(node.Span));
        if (action == null || !HtmlSink(Target(model.GetOperation(action))) || HasError(action)
            || operand is not ExpressionSyntax selected) return false;
        var owner = operand.Ancestors().FirstOrDefault(IsCallable);
        var visiting = new HashSet<ISymbol>(SymbolEqualityComparer.Default);
        bool DefaultEncoder(IOperation? instance)
        {
            while (instance is IConversionOperation conversion) instance = conversion.Operand;
            return instance is IPropertyReferenceOperation encoder && encoder.Property.Name == "Default" && encoder.Property.IsStatic
                && encoder.Property.ContainingType.ToDisplayString() == "System.Text.Encodings.Web.HtmlEncoder";
        }
        bool Safe(ExpressionSyntax value, int depth)
        {
            if (depth > 6 || HasError(value)) return false;
            if (value is ParenthesizedExpressionSyntax parenthesized) return Safe(parenthesized.Expression, depth + 1);
            if (model.GetConstantValue(value) is { HasValue: true, Value: string }) return true;
            // HtmlString stores an immutable string; this establishes its exact
            // producer, not blanket trust for IHtmlContent or mutable builders.
            if (model.GetOperation(value) is IObjectCreationOperation html
                && html.Constructor != null && AspNetApi(html.Constructor, "Microsoft.AspNetCore.Html.HtmlString")
                && html.Initializer == null && html.Arguments.Length == 1
                && html.Arguments[0].Syntax is ArgumentSyntax htmlArgument)
                return Safe(htmlArgument.Expression, depth + 1);
            if (model.GetOperation(value) is IFieldReferenceOperation field)
            {
                if (field.Field.Name == "Empty" && field.Field.IsStatic && field.Field.IsReadOnly
                    && AspNetApi(field.Field, "Microsoft.AspNetCore.Html.HtmlString")) return true;
                if (!field.Field.IsReadOnly || !Immutable(field.Field.Type)
                    || field.Field.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is not VariableDeclaratorSyntax declaration
                    || declaration.Initializer?.Value is not ExpressionSyntax initial
                    || declaration.SyntaxTree != model.SyntaxTree
                    || declaration.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault() is not { } type
                    || type.Span.Length > 32768 || type.Modifiers.Any(SyntaxKind.PartialKeyword)
                    || !visiting.Add(field.Field)) return false;
                try
                {
                    // Readonly can still be assigned in constructors or passed
                    // by ref there. Inspect the complete declaring type.
                    if (type.DescendantNodes().OfType<ExpressionSyntax>().Any(n =>
                        SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, field.Field)
                        && (n.Parent is AssignmentExpressionSyntax a && a.Left == n
                            || n.Parent is RefExpressionSyntax
                            || n.Parent is ArgumentSyntax arg && !arg.RefKindKeyword.IsKind(SyntaxKind.None)))) return false;
                    return Safe(initial, depth + 1);
                }
                finally { visiting.Remove(field.Field); }
            }
            if (model.GetOperation(value) is IInvocationOperation encoded && FrameworkMethod(encoded.TargetMethod)
                && encoded.TargetMethod.ContainingType.ToDisplayString() is "System.Text.Encodings.Web.HtmlEncoder" or "System.Text.Encodings.Web.TextEncoder"
                && encoded.TargetMethod.Name == "Encode" && encoded.Arguments.Length == 1
                && encoded.TargetMethod.ReturnType.SpecialType == SpecialType.System_String
                && DefaultEncoder(encoded.Instance)) return true;
            if (owner == null || owner.Span.Length > 32768
                || value is not IdentifierNameSyntax name
                || model.GetSymbolInfo(name).Symbol is not ILocalSymbol local || !visiting.Add(local)) return false;
            try
            {
                var declaration = local.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() as VariableDeclaratorSyntax;
                if (declaration?.Initializer?.Value is not ExpressionSyntax initial
                    || initial.Ancestors().FirstOrDefault(IsCallable) != owner
                    || initial.Span.End > value.SpanStart) return false;
                var uses = owner.DescendantNodes().OfType<IdentifierNameSyntax>()
                    .Where(n => n.Identifier.ValueText == name.Identifier.ValueText
                        && SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(n).Symbol, local)).ToArray();
                if (uses.Length > 128 || uses.Any(n => n.Ancestors().FirstOrDefault(IsCallable) != owner
                    || n.Parent is RefExpressionSyntax
                    || n.Parent is ArgumentSyntax a && !a.RefKindKeyword.IsKind(SyntaxKind.None)
                    || n.Ancestors().OfType<AssignmentExpressionSyntax>().Any(a => a.Left == n))) return false;
                if (model.GetOperation(initial) is not IObjectCreationOperation builder
                    || builder.Constructor == null || !AspNetApi(builder.Constructor, "Microsoft.AspNetCore.Mvc.Rendering.TagBuilder"))
                    return Immutable(local.Type) && Safe(initial, depth + 1);
                if (builder.Initializer != null || builder.Arguments.Length != 1
                    || builder.Arguments[0].Value.ConstantValue is not { HasValue: true, Value: string tag }
                    || !new[] { "div", "span", "p", "ul", "ol", "li", "a", "button", "i", "b", "strong", "h1", "h2", "h3", "h4", "h5", "h6" }.Contains(tag)) return false;
                foreach (var use in uses)
                {
                    if (HasError(use)) return false;
                    if (use == value) continue;
                    if (use.Parent is ArgumentSyntax argument && argument.Parent?.Parent is ExpressionSyntax consumer
                        && HtmlSink(Target(model.GetOperation(consumer)))) continue;
                    if (use.Parent is not MemberAccessExpressionSyntax member || member.Expression != use) return false;
                    if (member.Name.Identifier.ValueText == "Attributes" && member.Parent is ElementAccessExpressionSyntax attribute
                        && attribute.Parent is AssignmentExpressionSyntax assignment && assignment.Left == attribute
                        && assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)
                        && attribute.ArgumentList.Arguments.Count == 1
                        && model.GetConstantValue(attribute.ArgumentList.Arguments[0].Expression) is { HasValue: true, Value: string key })
                    {
                        if (HasError(assignment)) return false;
                        key = key.ToLowerInvariant();
                        if (key == "href") { if (!Fragment(assignment.Right)) return false; }
                        else if (!new[] { "class", "id", "title", "role", "name", "value", "type", "disabled", "selected", "tabindex" }.Contains(key)
                            && !key.StartsWith("aria-", StringComparison.Ordinal)
                            && !key.StartsWith("data-", StringComparison.Ordinal)) return false;
                        continue; // TagBuilder encodes ordinary attribute values.
                    }
                    var invocation = member.AncestorsAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                    if (invocation == null || model.GetOperation(invocation) is not IInvocationOperation call) return false;
                    if (call.TargetMethod.Name == "AddCssClass" && AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Mvc.Rendering.TagBuilder")) continue;
                    if (member.Name.Identifier.ValueText != "InnerHtml" || call.Arguments.Length != 1) return false;
                    if (call.TargetMethod.Name == "Append" && (
                        AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Html.IHtmlContentBuilder")
                        || AspNetApi(call.TargetMethod, "Microsoft.AspNetCore.Html.HtmlContentBuilder"))) continue;
                    if (!HtmlSink(call.TargetMethod) || call.Arguments[0].Syntax is not ArgumentSyntax child
                        || !Safe(child.Expression, depth + 1)) return false;
                }
                return true;
            }
            finally { visiting.Remove(local); }
        }
        bool Immutable(ITypeSymbol type) => type.SpecialType == SpecialType.System_String
            || type.ToDisplayString() == "Microsoft.AspNetCore.Html.HtmlString"
                && type.DeclaringSyntaxReferences.Length == 0
                && type.ContainingAssembly.Identity.PublicKeyToken.Length > 0
                && type.ContainingAssembly.Name.StartsWith("Microsoft.AspNetCore.", StringComparison.Ordinal);
        bool Fragment(ExpressionSyntax expression)
        {
            if (model.GetConstantValue(expression) is { HasValue: true, Value: string text })
                return text.StartsWith('#');
            return expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression)
                && model.GetConstantValue(binary.Left) is { HasValue: true } prefix
                && (prefix.Value is char c && c == '#' || prefix.Value is string s && s.StartsWith('#'));
        }
        if (!Safe(selected, 0)) return false;
        facts.Add(new("content", "encoded_html_operand", query.Operand, selected.ToString(),
            ["html_text_context_only"]));
        return true;
    }
}
