// verify: re-read the IL and compare the opcode sequence against an expected
// pattern (used as the read-back gate after a patch).

namespace IlTool;

internal static class VerifyCommand
{
    public static Dictionary<string, object?> Run(Request req)
    {
        using var asm = Assemblies.OpenRead(req.Assembly);
        var method = MethodLocator.Find(asm, req.Args);

        var expected = req.Args.GetStringList("expected")
            .Select(s => s.ToLowerInvariant())
            .ToList();
        if (expected.Count == 0)
            throw new IlToolException(Codes.BadRequest, "verify: args.expected must list opcode names");

        var actual = IlRender.OpcodeSequence(method);
        var exact = req.Args.GetBool("exact", false);

        bool matched = exact
            ? actual.SequenceEqual(expected)
            : ContainsContiguous(actual, expected);

        if (!matched)
        {
            throw new IlToolException(Codes.VerifyFailed,
                exact
                    ? "opcode sequence does not equal the expected pattern"
                    : "expected opcode pattern not found in method body",
                new Dictionary<string, object?>
                {
                    ["method"] = method.FullName,
                    ["expected"] = expected,
                    ["actual"] = actual,
                });
        }

        return new Dictionary<string, object?>
        {
            ["method"] = method.FullName,
            ["matched"] = true,
            ["exact"] = exact,
            ["expected"] = expected,
            ["instruction_count"] = actual.Count,
            ["sequence"] = actual,
        };
    }

    private static bool ContainsContiguous(List<string> haystack, List<string> needle)
    {
        if (needle.Count > haystack.Count)
            return false;
        for (int i = 0; i + needle.Count <= haystack.Count; i++)
        {
            bool ok = true;
            for (int j = 0; j < needle.Count; j++)
            {
                if (!haystack[i + j].Equals(needle[j], StringComparison.Ordinal))
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
                return true;
        }
        return false;
    }
}
