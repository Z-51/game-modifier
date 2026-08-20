// callers: full-assembly scan for call / callvirt / ldftn references to a target.

namespace IlTool;

using Mono.Cecil;
using Mono.Cecil.Cil;

internal static class CallersCommand
{
    private static readonly Code[] RefCodes =
    {
        Code.Call, Code.Callvirt, Code.Ldftn,
    };

    public static Dictionary<string, object?> Run(Request req)
    {
        using var asm = Assemblies.OpenRead(req.Assembly);
        var target = req.Args.RequireString("target", "args");
        var maxResults = req.Args.GetInt("max_results", 0);

        var callers = new List<Dictionary<string, object?>>();
        int scannedMethods = 0;

        foreach (var caller in Assemblies.AllMethods(asm))
        {
            scannedMethods++;
            if (!caller.HasBody)
                continue;
            foreach (var ins in caller.Body.Instructions)
            {
                if (Array.IndexOf(RefCodes, ins.OpCode.Code) < 0)
                    continue;
                if (ins.Operand is not MethodReference mr)
                    continue;
                if (!mr.FullName.Contains(target, StringComparison.OrdinalIgnoreCase) &&
                    !mr.Name.Contains(target, StringComparison.OrdinalIgnoreCase))
                    continue;

                callers.Add(new Dictionary<string, object?>
                {
                    ["caller"] = caller.FullName,
                    ["declaring_type"] = caller.DeclaringType?.FullName,
                    ["opcode"] = ins.OpCode.Name,
                    ["offset"] = "0x" + ins.Offset.ToString("X4"),
                    ["target"] = mr.FullName,
                });

                if (maxResults > 0 && callers.Count >= maxResults)
                    break;
            }
            if (maxResults > 0 && callers.Count >= maxResults)
                break;
        }

        return new Dictionary<string, object?>
        {
            ["target"] = target,
            ["scanned_methods"] = scannedMethods,
            ["caller_count"] = callers.Count,
            ["truncated"] = maxResults > 0 && callers.Count >= maxResults,
            ["callers"] = callers,
        };
    }
}
