// IPatchOp registry: deterministic, stack-valid IL rewrites.
//
// Registered ops (patch payload: {"op": <name>, "value": <number>, ...}):
//   replace_body       body := ldc(value); ret (void methods: ret only).
//   mul_before_ret     before every ret: ldc(value); mul   (scale return value).
//   insert_before_ret  before every ret of a non-void method: pop; ldc(value)
//                      (force the constant as the return value).
//   insert_after_call  after every call/callvirt whose target matches
//                      patch.target: ldc(value); mul        (scale call result).

using System.Text.Json;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace IlTool.Patch;

public interface IPatchOp
{
    string Name { get; }

    /// <summary>Apply the rewrite in place; throw IlToolException on refusal.</summary>
    void Apply(MethodDefinition method, JsonElement patch);
}

public static class PatchOps
{
    private static readonly Dictionary<string, IPatchOp> Registry = new(StringComparer.OrdinalIgnoreCase)
    {
        ["replace_body"] = new ReplaceBodyOp(),
        ["mul_before_ret"] = new MulBeforeRetOp(),
        ["insert_before_ret"] = new InsertBeforeRetOp(),
        ["insert_after_call"] = new InsertAfterCallOp(),
    };

    public static IReadOnlyCollection<string> Names => Registry.Keys;

    public static IPatchOp Get(string name)
    {
        if (!Registry.TryGetValue(name, out var op))
            throw new IlToolException(Codes.PatchFailed,
                $"unknown patch op '{name}' (known: {string.Join(", ", Registry.Keys)})",
                new Dictionary<string, object?> { ["op"] = name, ["known"] = Registry.Keys.ToList() });
        return op;
    }

    // ------------------------------------------------------------- shared IL

    /// <summary>Emit ldc for <paramref name="type"/>; false when unsupported.</summary>
    internal static bool TryEmitLoadConst(ILProcessor il, Instruction anchor, TypeReference type,
        double value, bool before)
    {
        Instruction? ins = type.MetadataType switch
        {
            MetadataType.Single => Instruction.Create(OpCodes.Ldc_R4, (float)value),
            MetadataType.Double => Instruction.Create(OpCodes.Ldc_R8, value),
            MetadataType.Int32 or MetadataType.Boolean or MetadataType.Int16 or
            MetadataType.Byte or MetadataType.SByte or MetadataType.UInt16 or
            MetadataType.Char or MetadataType.UInt32 => Instruction.Create(OpCodes.Ldc_I4, unchecked((int)(long)value)),
            MetadataType.Int64 or MetadataType.UInt64 => Instruction.Create(OpCodes.Ldc_I8, (long)value),
            _ => null,
        };
        if (ins == null)
            return false;
        if (before)
            il.InsertBefore(anchor, ins);
        else
            il.InsertAfter(anchor, ins);
        return true;
    }

    internal static bool IsNumeric(TypeReference type) => type.MetadataType switch
    {
        MetadataType.Single or MetadataType.Double or MetadataType.Int32 or
        MetadataType.Int64 or MetadataType.UInt32 or MetadataType.UInt64 or
        MetadataType.Int16 or MetadataType.UInt16 or MetadataType.Byte or
        MetadataType.SByte or MetadataType.Char or MetadataType.Boolean => true,
        _ => false,
    };
}

// ------------------------------------------------------------------ the ops

internal sealed class ReplaceBodyOp : IPatchOp
{
    public string Name => "replace_body";

    public void Apply(MethodDefinition method, JsonElement patch)
    {
        if (!method.HasBody)
            throw new IlToolException(Codes.PatchFailed, "method has no IL body to replace");

        var value = patch.GetDouble("value", 0.0);
        var il = method.Body.GetILProcessor();
        method.Body.Instructions.Clear();
        method.Body.Variables.Clear();
        method.Body.ExceptionHandlers.Clear();
        method.Body.MaxStackSize = 8;

        var ret = Instruction.Create(OpCodes.Ret);
        il.Append(ret);
        if (method.ReturnType.MetadataType != MetadataType.Void)
        {
            if (!PatchOps.TryEmitLoadConst(il, ret, method.ReturnType, value, before: true))
                throw new IlToolException(Codes.PatchFailed,
                    $"replace_body: unsupported return type {method.ReturnType.FullName}");
        }
    }
}

internal sealed class MulBeforeRetOp : IPatchOp
{
    public string Name => "mul_before_ret";

    public void Apply(MethodDefinition method, JsonElement patch)
    {
        if (!method.HasBody)
            throw new IlToolException(Codes.PatchFailed, "method has no IL body");
        if (!PatchOps.IsNumeric(method.ReturnType))
            throw new IlToolException(Codes.PatchFailed,
                $"mul_before_ret: return type {method.ReturnType.FullName} is not numeric");

        var value = patch.GetDouble("value", 1.0);
        var il = method.Body.GetILProcessor();
        int patched = 0;
        foreach (var ret in method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ret).ToList())
        {
            if (!PatchOps.TryEmitLoadConst(il, ret, method.ReturnType, value, before: true))
                throw new IlToolException(Codes.PatchFailed,
                    $"mul_before_ret: cannot load constant for {method.ReturnType.FullName}");
            il.InsertBefore(ret, Instruction.Create(OpCodes.Mul));
            patched++;
        }
        if (patched == 0)
            throw new IlToolException(Codes.PatchFailed, "no ret instruction found");
    }
}

internal sealed class InsertBeforeRetOp : IPatchOp
{
    public string Name => "insert_before_ret";

    public void Apply(MethodDefinition method, JsonElement patch)
    {
        if (!method.HasBody)
            throw new IlToolException(Codes.PatchFailed, "method has no IL body");
        if (method.ReturnType.MetadataType == MetadataType.Void)
            throw new IlToolException(Codes.PatchFailed,
                "insert_before_ret: method returns void (nothing to override)");

        var value = patch.GetDouble("value", 0.0);
        var il = method.Body.GetILProcessor();
        int patched = 0;
        foreach (var ret in method.Body.Instructions.Where(i => i.OpCode.Code == Code.Ret).ToList())
        {
            // Replace the computed value on the stack with the constant.
            il.InsertBefore(ret, Instruction.Create(OpCodes.Pop));
            if (!PatchOps.TryEmitLoadConst(il, ret, method.ReturnType, value, before: true))
                throw new IlToolException(Codes.PatchFailed,
                    $"insert_before_ret: cannot load constant for {method.ReturnType.FullName}");
            patched++;
        }
        if (patched == 0)
            throw new IlToolException(Codes.PatchFailed, "no ret instruction found");
    }
}

internal sealed class InsertAfterCallOp : IPatchOp
{
    public string Name => "insert_after_call";

    public void Apply(MethodDefinition method, JsonElement patch)
    {
        if (!method.HasBody)
            throw new IlToolException(Codes.PatchFailed, "method has no IL body");
        var target = patch.GetString("target")
            ?? throw new IlToolException(Codes.PatchFailed, "insert_after_call: missing patch.target");
        var value = patch.GetDouble("value", 1.0);

        var il = method.Body.GetILProcessor();
        int patched = 0;
        foreach (var ins in method.Body.Instructions.ToList())
        {
            if (ins.OpCode.Code is not (Code.Call or Code.Callvirt))
                continue;
            if (ins.Operand is not MethodReference mr)
                continue;
            if (!mr.FullName.Contains(target, StringComparison.OrdinalIgnoreCase) &&
                !mr.Name.Contains(target, StringComparison.OrdinalIgnoreCase))
                continue;
            if (!PatchOps.IsNumeric(mr.ReturnType))
                continue; // nothing to scale

            // anchor stays the call; insert ldc then mul directly after it.
            if (!PatchOps.TryEmitLoadConst(il, ins, mr.ReturnType, value, before: false))
                continue;
            var ldc = ins.Next!; // the constant we just inserted
            il.InsertAfter(ldc, Instruction.Create(OpCodes.Mul));
            patched++;
        }
        if (patched == 0)
            throw new IlToolException(Codes.PatchFailed,
                $"insert_after_call: no call site with numeric return matched '{target}'",
                new Dictionary<string, object?> { ["target"] = target });
    }
}
