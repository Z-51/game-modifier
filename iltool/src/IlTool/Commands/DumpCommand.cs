// dump: method body IL instruction stream with resolved operands.

namespace IlTool;

using Mono.Cecil;
using Mono.Cecil.Cil;

internal static class IlRender
{
    /// <summary>Human-readable operand for one instruction (metadata refs resolved).</summary>
    public static string Operand(Instruction ins)
    {
        switch (ins.Operand)
        {
            case null:
                return "";
            case MethodReference m:
                return m.FullName;
            case FieldReference f:
                return f.FullName;
            case TypeReference t:
                return t.FullName;
            case string s:
                return "\"" + s + "\"";
            case Instruction target:
                return "IL_" + target.Offset.ToString("X4");
            case Instruction[] targets:
                return "[" + string.Join(", ", targets.Select(t => "IL_" + t.Offset.ToString("X4"))) + "]";
            case sbyte or byte or short or ushort or int or uint or long or ulong or float or double:
                return Convert.ToString(ins.Operand, System.Globalization.CultureInfo.InvariantCulture) ?? "";
            default:
                return ins.Operand.ToString() ?? "";
        }
    }

    /// <summary>Serialise one instruction to a stable dictionary row.</summary>
    public static Dictionary<string, object?> Row(Instruction ins) => new()
    {
        ["offset"] = "0x" + ins.Offset.ToString("X4"),
        ["opcode"] = ins.OpCode.Name,
        ["operand"] = Operand(ins),
    };

    public static List<Dictionary<string, object?>> Body(MethodDefinition method)
    {
        var rows = new List<Dictionary<string, object?>>();
        if (!method.HasBody)
            return rows;
        foreach (var ins in method.Body.Instructions)
            rows.Add(Row(ins));
        return rows;
    }

    /// <summary>Lower-cased opcode name sequence (verify compares these).</summary>
    public static List<string> OpcodeSequence(MethodDefinition method)
    {
        var seq = new List<string>();
        if (!method.HasBody)
            return seq;
        foreach (var ins in method.Body.Instructions)
            seq.Add(ins.OpCode.Name.ToLowerInvariant());
        return seq;
    }
}

internal static class DumpCommand
{
    public static Dictionary<string, object?> Run(Request req)
    {
        using var asm = Assemblies.OpenRead(req.Assembly);
        var method = MethodLocator.Find(asm, req.Args);
        var rows = IlRender.Body(method);

        return new Dictionary<string, object?>
        {
            ["method"] = method.FullName,
            ["declaring_type"] = method.DeclaringType?.FullName,
            ["rva_hex"] = "0x" + method.RVA.ToString("X"),
            ["max_stack"] = method.HasBody ? method.Body.MaxStackSize : 0,
            ["local_count"] = method.HasBody && method.Body.HasVariables ? method.Body.Variables.Count : 0,
            ["instruction_count"] = rows.Count,
            ["instructions"] = rows,
        };
    }
}
