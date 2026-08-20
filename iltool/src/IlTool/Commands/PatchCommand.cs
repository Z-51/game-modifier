// patch: apply a registered PatchOp and write the modified assembly.

namespace IlTool;

using IlTool.Patch;
using Mono.Cecil;

internal static class PatchCommand
{
    public static Dictionary<string, object?> Run(Request req)
    {
        if (req.Patch.ValueKind != System.Text.Json.JsonValueKind.Object)
            throw new IlToolException(Codes.BadRequest, "patch command requires a 'patch' object");

        var opName = req.Patch.GetString("op")
            ?? throw new IlToolException(Codes.BadRequest, "missing patch.op");
        var op = PatchOps.Get(opName);

        using var asm = Assemblies.OpenReadWrite(req.Assembly);
        var method = MethodLocator.Find(asm, req.Args);

        try
        {
            op.Apply(method, req.Patch);
        }
        catch (IlToolException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new IlToolException(Codes.PatchFailed, $"op '{opName}' failed: {ex.Message}",
                new Dictionary<string, object?> { ["op"] = opName, ["method"] = method.FullName });
        }

        // args.out_assembly redirects the patched image elsewhere. The default
        // writes back in place via a temp file + atomic replace: Cecil's
        // ReadWrite mode cannot write to the same path it is reading from
        // (the reader stream holds the file), and the game process also locks
        // the DLL while running - replacing needs the game closed anyway.
        var dest = req.Args.GetString("out_assembly") ?? req.Assembly;
        try
        {
            if (string.Equals(dest, req.Assembly, StringComparison.OrdinalIgnoreCase))
            {
                var tmp = dest + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
                asm.Write(tmp);
                // Release the source file's read handle (Cecil holds it with
                // FileShare.Read) BEFORE replacing, or the copy below fails
                // with "being used by another process" (the process is us).
                asm.Dispose();
                File.Copy(tmp, dest, overwrite: true);
                File.Delete(tmp);
            }
            else
            {
                asm.Write(dest);
            }
        }
        catch (Exception ex)
        {
            throw new IlToolException(Codes.PatchFailed, $"cannot write patched assembly: {ex.Message}",
                new Dictionary<string, object?> { ["out_assembly"] = dest });
        }

        return new Dictionary<string, object?>
        {
            ["op"] = opName,
            ["method"] = method.FullName,
            ["out_assembly"] = dest,
            ["instruction_count"] = method.HasBody ? method.Body.Instructions.Count : 0,
        };
    }
}
