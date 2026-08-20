// index: full type/method index JSON (consumed by mono_dump / mono_symbol flows).

namespace IlTool;

internal static class IndexCommand
{
    public static Dictionary<string, object?> Run(Request req)
    {
        using var asm = Assemblies.OpenRead(req.Assembly);

        int typeCount = 0, methodCount = 0, fieldCount = 0;
        var namespaces = new Dictionary<string, List<Dictionary<string, object?>>>(StringComparer.Ordinal);

        foreach (var type in Assemblies.AllTypes(asm))
        {
            typeCount++;
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
                });
            }

            var entry = new Dictionary<string, object?>
            {
                ["full_name"] = type.FullName,
                ["methods"] = methods,
                ["fields"] = fields,
            };

            var ns = string.IsNullOrEmpty(type.Namespace) ? "<global>" : type.Namespace;
            if (!namespaces.TryGetValue(ns, out var list))
                namespaces[ns] = list = new List<Dictionary<string, object?>>();
            list.Add(entry);
        }

        return new Dictionary<string, object?>
        {
            ["assembly"] = asm.FullName,
            ["type_count"] = typeCount,
            ["method_count"] = methodCount,
            ["field_count"] = fieldCount,
            ["namespaces"] = namespaces
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .ToDictionary(kv => kv.Key, kv => (object?)kv.Value),
        };
    }
}
