using System.Diagnostics;
using System.Text.Json;

namespace BaumSecure.Services;

/// <summary>
/// Checks the GitHub Releases API for a newer version of BaumSecure.
/// If a newer version is available, downloads the installer silently and
/// relaunches the app through it — no user interaction required.
/// </summary>
internal static class UpdateService
{
    public static readonly string CurrentVersion = GetCurrentVersion();

    private static string GetCurrentVersion()
    {
        var asm  = System.Reflection.Assembly.GetExecutingAssembly();
        var attr = System.Reflection.CustomAttributeExtensions
                        .GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm);
        var info = attr?.InformationalVersion ?? "";
        // Strip build metadata suffix (+abc1234) appended by the .NET SDK
        var plus = info.IndexOf('+');
        if (plus >= 0) info = info[..plus];
        if (!string.IsNullOrWhiteSpace(info)) return info;
        return asm.GetName().Version?.ToString(3) ?? "0.0.0";
    }

    private const string ApiLatest =
        "https://api.github.com/repos/Bruiserbaum/BaumSecure/releases/latest";

    /// <summary>
    /// Checks GitHub for a newer release.  If one is found, downloads the installer
    /// to %TEMP%, launches a PowerShell helper that waits for this process to exit
    /// then runs the installer silently and relaunches the app, then exits immediately.
    /// Returns without doing anything if already up-to-date or the check fails.
    /// </summary>
    public static async Task CheckAndApplyAsync()
    {
        try
        {
            using var http = new System.Net.Http.HttpClient
            {
                Timeout = TimeSpan.FromSeconds(12)
            };
            http.DefaultRequestHeaders.Add("User-Agent", $"BaumSecure/{CurrentVersion}");

            var json = await http.GetStringAsync(ApiLatest);
            using var doc  = JsonDocument.Parse(json);
            var root = doc.RootElement;

            string tag     = root.TryGetProperty("tag_name", out var t) ? t.GetString() ?? "" : "";
            string version = tag.TrimStart('v');

            if (!IsNewer(version, CurrentVersion)) return;

            // Find the .exe installer asset
            string downloadUrl = "";
            if (root.TryGetProperty("assets", out var assets))
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    string name = asset.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                    if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        downloadUrl = asset.TryGetProperty("browser_download_url", out var u)
                            ? u.GetString() ?? "" : "";
                        break;
                    }
                }
            }

            if (string.IsNullOrEmpty(downloadUrl)) return;

            // Download installer to %TEMP%
            var installerPath = Path.Combine(Path.GetTempPath(), $"BaumSecure-Setup-{version}.exe");
            using var response = await http.GetAsync(
                downloadUrl, System.Net.Http.HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            await using var src = await response.Content.ReadAsStreamAsync();
            await using var dst = File.Create(installerPath);
            await src.CopyToAsync(dst);
            dst.Close();

            // PowerShell helper: wait for this process to exit, run installer silently,
            // then relaunch the app from its install location.
            int    pid        = Process.GetCurrentProcess().Id;
            string appPath    = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Programs", "BaumSecure", "BaumSecure.exe");
            var ps1Path       = Path.Combine(Path.GetTempPath(), "baumsecure-update.ps1");
            var escapedInst   = installerPath.Replace("'", "''");
            var escapedApp    = appPath.Replace("'", "''");

            var script =
                "# Wait for BaumSecure to fully exit\n" +
                "$proc = Get-Process -Id " + pid + " -ErrorAction SilentlyContinue\n" +
                "if ($proc) { $proc.WaitForExit(15000) | Out-Null }\n" +
                "Start-Sleep -Milliseconds 600\n" +
                "# Install silently\n" +
                "Start-Process -FilePath '" + escapedInst + "' -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait\n" +
                "Start-Sleep -Milliseconds 800\n" +
                "# Relaunch\n" +
                "if (Test-Path '" + escapedApp + "') {\n" +
                "    Start-Process -FilePath '" + escapedApp + "'\n" +
                "}\n";

            File.WriteAllText(ps1Path, script);

            Process.Start(new ProcessStartInfo
            {
                FileName        = "powershell.exe",
                Arguments       = $"-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{ps1Path}\"",
                UseShellExecute = true,
            });

            // Exit so the installer can replace the running executable
            Environment.Exit(0);
        }
        catch
        {
            // Update check failure is always silent — the app starts normally
        }
    }

    private static bool IsNewer(string latest, string current)
    {
        static string Strip(string v) => v.Contains('-') ? v[..v.IndexOf('-')] : v;

        if (Version.TryParse(Strip(latest),  out var v1) &&
            Version.TryParse(Strip(current), out var v2))
            return v1 > v2;

        return string.Compare(Strip(latest), Strip(current),
                              StringComparison.OrdinalIgnoreCase) > 0;
    }
}
