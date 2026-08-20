// analyze: enumerate types / methods / fields from Cecil metadata.
// Never reflection-loads the assembly types.

namespace IlTool;

using Mono.Cecil;

internal static class AnalyzeCommand
{
    public static Dictionary<string, object?> Run(Request req)
    {
        using var asm = Assemblies.OpenRead(req.Assembly);

        var filter = req.Args.GetString("filter");
        var maxTypes = req.Args.GetInt("max_types", 0);

        var types = new List<Dictionary<string, object?>>();
        int methodCount = 0, fieldCount = 0;

        foreach (var type in Assemblies.AllTypes(asm))
        {
            if (filter != null &&
                !type.FullName.Contains(filter, StringComparison.OrdinalIgnoreCase))
                continue;

            var methods = new List<Dictionary<string, object?>>();
            foreach (var m in type.Methods)
            {
                methodCount++;
                methods.Add(new Dictionary<string, object?>
                {
                    ["name"] = m.Name,
                    ["full_name"] = m.FullName,
                    ["rva_hex"] = "0x" + m.RVA.ToString("X"),
                    ["static"] = m.IsStatic,
                    ["virtual"] = m.IsVirtual,
                    ["return_type"] = m.ReturnType.FullName,
                    ["il_bytes"] = m.HasBody ? m.Body.CodeSize : 0,
                });
            }

            var fields = new List<Dictionary<string, object?>>();
            foreach (var f in type.Fields)
            {
                fieldCount++;
                fields.Add(new Dictionary<string, object?>
                {
                    ["name"] = f.Name,
                    ["field_type"] = f.FieldType.FullName,
                    ["static"] = f.IsStatic,
                    ["literal"] = f.IsLiteral,
                });
            }

            types.Add(new Dictionary<string, object?>
            {
                ["name"] = type.Name,
                ["full_name"] = type.FullName,
                ["namespace"] = type.Namespace,
                ["is_class"] = type.IsClass,
                ["is_value_type"] = type.IsValueType,
                ["methods"] = methods,
                ["fields"] = fields,
            });

            if (maxTypes > 0 && types.Count >= maxTypes)
                break;
        }

        return new Dictionary<string, object?>
        {
            ["assembly"] = asm.FullName,
            ["type_count"] = types.Count,
            ["method_count"] = methodCount,
            ["field_count"] = fieldCount,
            ["truncated"] = maxTypes > 0 && types.Count >= maxTypes,
            ["types"] = types,
        };
    }
}
