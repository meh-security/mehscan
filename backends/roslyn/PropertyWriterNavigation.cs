using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

internal static partial class Program
{
    // Candidate writes to exact source properties consumed by a bound helper's
    // return. No receiver alias, runtime writer completeness or taint inference.
    private sealed class PropertyWriterNavigation(SemanticModel[] models,
        SortedDictionary<string, Source> sources)
    {
        private readonly Dictionary<string, List<Fact>> cache = new();
        private (SemanticModel Model, AssignmentExpressionSyntax Node)[]? assignments;

        private static string? Key(IPropertySymbol property)
        {
            var declared = property.OriginalDefinition.DeclaringSyntaxReferences;
            if (declared.Length != 1 || property.Type.SpecialType != SpecialType.System_String) return null;
            return $"{property.ContainingAssembly.Identity}:{declared[0].SyntaxTree.FilePath}:{declared[0].Span.Start}:{declared[0].Span.End}";
        }

        public void AddReturnWriters(SyntaxNode declaration, List<Fact> facts)
        {
            if (declaration is not MethodDeclarationSyntax method || method.Span.Length > 8192) return;
            var model = models.FirstOrDefault(m => m.SyntaxTree == declaration.SyntaxTree);
            if (model == null) return;
            var returns = method.ExpressionBody != null ? new[] { method.ExpressionBody.Expression }
                : method.DescendantNodes().OfType<ReturnStatementSyntax>()
                    .Where(r => r.Ancestors().FirstOrDefault(IsCallable) == method)
                    .Select(r => r.Expression).OfType<ExpressionSyntax>().ToArray();
            var properties = returns.SelectMany(r => r.DescendantNodesAndSelf())
                .OfType<MemberAccessExpressionSyntax>()
                .Select(n => model.GetOperation(n) is IPropertyReferenceOperation p ? p.Property : null)
                .OfType<IPropertySymbol>().Select(p => (Property:p, Key:Key(p)))
                .Where(p => p.Key != null).DistinctBy(p => p.Key).Take(4);
            foreach (var (property, key) in properties)
            {
                if (!cache.TryGetValue(key!, out var writes))
                {
                    assignments ??= models.SelectMany(m => m.SyntaxTree.GetRoot().DescendantNodes()
                        .OfType<AssignmentExpressionSyntax>().Select(n => (m,n))).ToArray();
                    writes = new();
                    foreach (var (writerModel, assignment) in assignments)
                    {
                        var name = assignment.Left switch {
                            IdentifierNameSyntax id => id.Identifier.ValueText,
                            MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
                            _ => null
                        };
                        if (name != property.Name || !sources.TryGetValue(assignment.SyntaxTree.FilePath, out var source)
                            || writerModel.GetOperation(assignment.Left) is not IPropertyReferenceOperation target
                            || Key(target.Property) != key) continue;
                        var location = Location(source, assignment.Right.Span);
                        if (writes.Any(f => f.Location == location)) continue;
                        if (writes.Count == 8)
                        {
                            writes.Add(new("property_writer", "operand_boundary", location,
                                $"More than eight candidate source writes to {property.ToDisplayString()}; inspect remaining writers",
                                ["remaining_property_writers", "supplied_compiled_sources_only", "writer_reachability_and_authority"]));
                            break;
                        }
                        // Large RHS expressions stay locations, not packet payload.
                        writes.Add(new("property_writer", assignment.Right.Span.Length <= 512 ? "local_operand_origin" : "operand_boundary", location,
                            assignment.Right.Span.Length <= 512 ? assignment.Right.ToString() : $"Large candidate assigned expression for {property.ToDisplayString()}",
                            ["same_resource_instance_and_persistence", "writer_reachability_and_authority",
                             "supplied_compiled_sources_only", "other_writers_and_runtime_overrides", $"property:{property.ToDisplayString()}"]));
                    }
                    cache[key!] = writes;
                }
                foreach (var write in writes)
                    if (!facts.Any(f => f.Role == write.Role && f.Location == write.Location && f.Value == write.Value)) facts.Add(write);
            }
        }
    }
}
