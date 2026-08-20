// Shared helpers: JsonElement accessors, assembly opening, method resolution.

using System.Text.Json;
using Mono.Cecil;

namespace IlTool;

internal static class JsonEl
{
    public static string? GetString(this JsonElement el, string key) =>
        el.ValueKind == JsonValueKind.Object &&
        el.TryGetProperty(key, out var v) &&
        v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    public static string RequireString(this JsonElement el, string key, string context)
    {
        var s = el.GetString(key);
        if (string.IsNullOrEmpty(s))
            throw new IlToolException(Codes.BadRequest, $"missing '{key}' in {context}");
        return s;
    }

    public static int GetInt(this JsonElement el, string key, int fallback)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i))
                return i;
        }
        return fallback;
    }

    public static double GetDouble(this JsonElement el, string key, double fallback)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(key, out var v))
        {
            if (v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d))
                return d;
        }
        return fallback;
    }

    public static bool GetBool(this JsonElement el, string key, bool fallback)
    {
        if (el.ValueKind == JsonValueKind.Object && el.TryGetProperty(key, out var v))
        {
            if (v.ValueKind is JsonValueKind.True or JsonValueKind.False)
                return v.GetBoolean();
        }
        return fallback;
    }

    public static List<string> GetStringList(this JsonElement el, string key)
    {
        var list = new List<string>();
        if (el.ValueKind == JsonValueKind.Object &&
            el.TryGetProperty(key, out var v) &&
            v.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in v.EnumerateArray())
                if (item.ValueKind == JsonValueKind.String)
                    list.Add(item.GetString() ?? "");
        }
        return list;
    }
}

internal static class Assemblies
{
    public static void RequireExists(string path)
    {
        if (string.IsNullOrEmpty(path))
            throw new IlToolException(Codes.BadRequest, "missing 'assembly' path");
        if (!File.Exists(path))
            throw new IlToolException(Codes.AssemblyNotFound, $"assembly not found: {path}",
                new Dictionary<string, object?> { ["assembly"] = path });
    }

    /// Resolver that can also find referenced assemblies next to the target
    /// (Unity games keep UnityEngine.* and mscorlib in the same Managed
    /// directory). Without this, Cecil's write path fails with
    /// "Failed to resolve assembly: 'UnityEngine.CoreModule'" because the
    /// default resolver only probes the process directory and the GAC.
    private static IAssemblyResolver ResolverFor(string path)
    {
        var resolver = new DefaultAssemblyResolver();
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir))
            resolver.AddSearchDirectory(dir);
        return resolver;
    }

    public static AssemblyDefinition OpenRead(string path)
    {
        RequireExists(path);
        try
        {
            return AssemblyDefinition.ReadAssembly(path, new ReaderParameters
            {
                ReadSymbols = false,
                AssemblyResolver = ResolverFor(path),
            });
        }
        catch (Exception ex)
        {
            throw new IlToolException(Codes.Unsupported, $"cannot parse assembly: {ex.Message}",
                new Dictionary<string, object?> { ["assembly"] = path });
        }
    }

    public static AssemblyDefinition OpenReadWrite(string path)
    {
        RequireExists(path);
        try
        {
            // Plain read (not Cecil's ReadWrite mode): writing back in place
            // conflicts with the reader's own file stream ("being used by
            // another process" - the process is ourselves). The caller writes
            // to a temp file and atomically replaces instead.
            return AssemblyDefinition.ReadAssembly(path, new ReaderParameters
            {
                ReadSymbols = false,
                AssemblyResolver = ResolverFor(path),
            });
        }
        catch (Exception ex)
        {
            throw new IlToolException(Codes.Unsupported, $"cannot open assembly for patching: {ex.Message}",
                new Dictionary<string, object?> { ["assembly"] = path });
        }
    }

    public static IEnumerable<TypeDefinition> AllTypes(AssemblyDefinition asm)
    {
        foreach (var module in asm.Modules)
            foreach (var type in module.Types)
                foreach (var t in Walk(type))
                    yield return t;
    }

    private static IEnumerable<TypeDefinition> Walk(TypeDefinition type)
    {
        yield return type;
        foreach (var nested in type.NestedTypes)
            foreach (var t in Walk(nested))
                yield return t;
    }

    public static IEnumerable<MethodDefinition> AllMethods(AssemblyDefinition asm) =>
        AllTypes(asm).SelectMany(t => t.Methods);
}

internal static class MethodLocator
{
    /// <summary>
    /// Resolve a method by <c>args.method</c> (exact full name wins, then a
    /// case-insensitive substring match) with an optional <c>args.type</c>
    /// declaring-type filter.
    /// </summary>
    public static MethodDefinition Find(AssemblyDefinition asm, JsonElement args)
    {
        var wanted = args.RequireString("method", "args");
        var typeFilter = args.GetString("type");

        var candidates = new List<MethodDefinition>();
        foreach (var m in Assemblies.AllMethods(asm))
        {
            if (typeFilter != null &&
                !(m.DeclaringType?.FullName ?? "").Contains(typeFilter, StringComparison.OrdinalIgnoreCase))
                continue;
            if (m.FullName.Equals(wanted, StringComparison.Ordinal))
                return m; // exact hit short-circuits
            if (m.FullName.Contains(wanted, StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains(wanted, StringComparison.OrdinalIgnoreCase))
                candidates.Add(m);
        }

        if (candidates.Count == 0)
            throw new IlToolException(Codes.MethodNotFound, $"no method matching '{wanted}'",
                new Dictionary<string, object?> { ["method"] = wanted, ["type"] = typeFilter });
        // Deterministic pick: shortest full name (most specific overload first).
        return candidates.OrderBy(c => c.FullName.Length).First();
    }

    public static List<MethodDefinition> FindAll(AssemblyDefinition asm, JsonElement args)
    {
        var wanted = args.RequireString("method", "args");
        var typeFilter = args.GetString("type");

        var found = new List<MethodDefinition>();
        foreach (var m in Assemblies.AllMethods(asm))
        {
            if (typeFilter != null &&
                !(m.DeclaringType?.FullName ?? "").Contains(typeFilter, StringComparison.OrdinalIgnoreCase))
                continue;
            if (m.FullName.Contains(wanted, StringComparison.OrdinalIgnoreCase) ||
                m.Name.Contains(wanted, StringComparison.OrdinalIgnoreCase))
                found.Add(m);
        }
        return found;
    }
}
