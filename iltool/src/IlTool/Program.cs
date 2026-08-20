// il-tool: single-shot subprocess for Unity Mono assembly inspection/patching.
//
// Protocol (isomorphic to the game-modifier JSON envelope):
//   request  (stdin, exactly one line):
//     {"v":1,"command":"analyze|dump|callers|patch|verify|index",
//      "assembly":"<path>","args":{...},
//      "patch":{"op":"mul_before_ret","value":4.0},
//      "out":"<optional large-output sink path>"}
//   response (stdout, exactly one line):
//     {"ok":true,"command":"...","data":{...}}
//     {"ok":false,"error":{"code":"E_IL_...","message":"...","details":{...}}}
//   stderr  : diagnostics only (never parsed by the host).
//   exit 0  : the envelope on stdout is authoritative (even for ok:false);
//   exit !=0: transport-layer failure (host must NOT parse stdout).
//
// Modes:
//   (default)   single-shot: read one request line, answer, exit.
//   --serve/-s  keep-alive: loop reading request lines and answering one
//               envelope per line until EOF; blank lines are ignored
//               (keep-alive pings). One bad request never kills the loop -
//               it answers with an error envelope and continues. Mono.Cecil
//               assemblies are re-read per request, so a patched file is
//               picked up by the next request without a restart.
//
// Metadata handling uses Mono.Cecil only - types are never reflection-loaded.

using System.Text;
using System.Text.Json;

namespace IlTool;

internal static class Program
{
    public const string ToolVersion = "1.0.0";

    private static int Main(string[] argv)
    {
        try { Console.InputEncoding = Encoding.UTF8; } catch { /* redirected pipes may refuse */ }
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        if (argv.Length > 0 && argv[0] is "--version" or "-V")
        {
            Console.WriteLine($"il-tool {ToolVersion}");
            return 0;
        }

        if (argv.Length > 0 && argv[0] is "--serve" or "-s")
            return ServeLoop();

        string? line;
        try
        {
            line = Console.In.ReadLine();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"il-tool: cannot read stdin: {ex.Message}");
            return 2; // transport failure
        }

        if (string.IsNullOrWhiteSpace(line))
        {
            Console.Error.WriteLine("il-tool: empty request on stdin");
            return 2;
        }

        HandleOne(line);
        return 0;
    }

    /// <summary>
    /// Keep-alive loop: one request line in, one envelope line out, until the
    /// host closes stdin (EOF). Errors are answered with an error envelope;
    /// the loop only dies on transport-level stdin failures.
    /// </summary>
    private static int ServeLoop()
    {
        while (true)
        {
            string? line;
            try
            {
                line = Console.In.ReadLine();
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"il-tool: cannot read stdin: {ex.Message}");
                return 2; // transport failure
            }
            if (line is null)
                return 0; // EOF: host closed the pipe - clean shutdown
            if (string.IsNullOrWhiteSpace(line))
                continue;   // keep-alive ping: ignore
            HandleOne(line);
            Console.Out.Flush();
        }
    }

    /// <summary>Handle one request line and emit exactly one envelope line.</summary>
    private static void HandleOne(string line)
    {
        string command = "unknown";
        try
        {
            var req = Request.Parse(line);
            command = req.Command;
            Dictionary<string, object?> data = Dispatch(req);
            data = MaybeSpillToFile(req, data);
            Emit(new Dictionary<string, object?>
            {
                ["ok"] = true,
                ["command"] = req.Command,
                ["data"] = data,
            });
        }
        catch (IlToolException ex)
        {
            // Business error: envelope is still authoritative -> exit 0.
            Console.Error.WriteLine($"il-tool: {ex.Code}: {ex.Message}");
            Emit(Error.Envelope(command, ex.Code, ex.Message, ex.Details));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            Emit(Error.Envelope(command, Codes.Internal, ex.Message, null));
        }
    }

    private static Dictionary<string, object?> Dispatch(Request req)
    {
        if (req.Version != 1)
            throw new IlToolException(Codes.BadRequest, $"unsupported protocol version {req.Version} (expected 1)");

        return req.Command switch
        {
            "analyze" => AnalyzeCommand.Run(req),
            "dump" => DumpCommand.Run(req),
            "callers" => CallersCommand.Run(req),
            "patch" => PatchCommand.Run(req),
            "verify" => VerifyCommand.Run(req),
            "index" => IndexCommand.Run(req),
            _ => throw new IlToolException(Codes.BadRequest, $"unknown command '{req.Command}'"),
        };
    }

    /// <summary>
    /// Large outputs (full enumeration / instruction streams / caller tables)
    /// go to the requested <c>out</c> file; stdout then only carries the path
    /// plus the *_count summary fields.
    /// </summary>
    private static Dictionary<string, object?> MaybeSpillToFile(Request req, Dictionary<string, object?> data)
    {
        if (string.IsNullOrEmpty(req.Out))
            return data;

        try
        {
            var dir = Path.GetDirectoryName(Path.GetFullPath(req.Out));
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
            File.WriteAllText(req.Out, Json.Serialize(data), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            throw new IlToolException(Codes.Internal, $"cannot write out file '{req.Out}': {ex.Message}");
        }

        var summary = new Dictionary<string, object?> { ["out_file"] = req.Out };
        foreach (var kv in data)
            if (kv.Key.EndsWith("_count", StringComparison.Ordinal))
                summary[kv.Key] = kv.Value;
        return summary;
    }

    private static void Emit(Dictionary<string, object?> envelope)
    {
        // Exactly one line on stdout - no pretty printing, no trailing noise.
        Console.WriteLine(Json.Serialize(envelope));
    }
}

/// <summary>Stable E_IL_* codes emitted by this tool.</summary>
internal static class Codes
{
    public const string BadRequest = "E_IL_BAD_REQUEST";
    public const string AssemblyNotFound = "E_IL_ASSEMBLY_NOT_FOUND";
    public const string MethodNotFound = "E_IL_METHOD_NOT_FOUND";
    public const string PatchFailed = "E_IL_PATCH_FAILED";
    public const string VerifyFailed = "E_IL_VERIFY_FAILED";
    public const string Unsupported = "E_IL_UNSUPPORTED";
    public const string Internal = "E_IL_INTERNAL";
}

/// <summary>Business failure carrying an E_IL_* code and optional details.</summary>
internal sealed class IlToolException : Exception
{
    public string Code { get; }
    public Dictionary<string, object?>? Details { get; }

    public IlToolException(string code, string message, Dictionary<string, object?>? details = null)
        : base(message)
    {
        Code = code;
        Details = details;
    }
}

/// <summary>Envelope construction helpers.</summary>
internal static class Error
{
    public static Dictionary<string, object?> Envelope(
        string command, string code, string message, Dictionary<string, object?>? details)
    {
        var error = new Dictionary<string, object?>
        {
            ["code"] = code,
            ["message"] = message,
        };
        if (details is { Count: > 0 })
            error["details"] = details;
        return new Dictionary<string, object?>
        {
            ["ok"] = false,
            ["command"] = command,
            ["error"] = error,
        };
    }
}

/// <summary>Parsed single-line request from stdin.</summary>
internal sealed class Request
{
    public int Version { get; private set; } = 1;
    public string Command { get; private set; } = "";
    public string Assembly { get; private set; } = "";
    public JsonElement Args { get; private set; }
    public JsonElement Patch { get; private set; }
    public string? Out { get; private set; }

    public static Request Parse(string line)
    {
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(line);
        }
        catch (JsonException ex)
        {
            throw new IlToolException(Codes.BadRequest, $"request is not valid JSON: {ex.Message}");
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                throw new IlToolException(Codes.BadRequest, "request must be a JSON object");

            var req = new Request
            {
                Version = root.GetInt("v", 1),
                Command = root.GetString("command") ?? "",
                Assembly = root.GetString("assembly") ?? "",
                Out = root.GetString("out"),
            };

            if (string.IsNullOrEmpty(req.Command))
                throw new IlToolException(Codes.BadRequest, "missing 'command'");
            if (root.TryGetProperty("args", out var args))
                req.Args = args.Clone();
            if (root.TryGetProperty("patch", out var patch))
                req.Patch = patch.Clone();
            return req;
        }
    }
}

/// <summary>Minimal JSON serialiser over Dictionary/list/scalar trees.</summary>
internal static class Json
{
    public static string Serialize(object? value) =>
        JsonSerializer.Serialize(value, new JsonSerializerOptions
        {
            WriteIndented = false,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });
}
