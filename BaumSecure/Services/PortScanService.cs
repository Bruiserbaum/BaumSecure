using System.Net.Sockets;
using System.Text;
using BaumSecure.Models;

namespace BaumSecure.Services;

public sealed class ScanProgressArgs(int completed, int total, SecurityFinding? latest) : EventArgs
{
    public int              Completed { get; } = completed;
    public int              Total     { get; } = total;
    public SecurityFinding? Latest    { get; } = latest;
    public int              Percent   => Total == 0 ? 0 : (int)(100.0 * Completed / Total);
}

public sealed class PortScanService
{
    private const int ConnectTimeoutMs = 2500;
    private const int BannerTimeoutMs  = 800;
    private const int MaxConcurrency   = 64;

    public event EventHandler<ScanProgressArgs>? Progress;

    public async Task<ScanResult> ScanAsync(
        string      targetIp,
        ScanProfile profile,
        CancellationToken ct = default)
    {
        var rules   = SecurityAnalyzer.GetRulesForProfile(profile).ToList();
        var result  = new ScanResult { TargetIp = targetIp, PortsChecked = rules.Count };
        var sw      = System.Diagnostics.Stopwatch.StartNew();

        int completed = 0;
        var sem = new SemaphoreSlim(MaxConcurrency);

        var tasks = rules.Select(async rule =>
        {
            await sem.WaitAsync(ct);
            try
            {
                ct.ThrowIfCancellationRequested();
                bool   isOpen = await IsTcpOpenAsync(targetIp, rule.Port, ct);
                string? banner = isOpen ? await TryGrabBannerAsync(targetIp, rule.Port) : null;
                var finding = SecurityAnalyzer.Analyze(rule, isOpen, banner);

                int done = Interlocked.Increment(ref completed);
                Progress?.Invoke(this, new ScanProgressArgs(done, rules.Count, isOpen ? finding : null));
                return finding;
            }
            finally { sem.Release(); }
        });

        var findings = await Task.WhenAll(tasks);
        result.Findings.AddRange(
            findings.OrderByDescending(f => f.IsOpen)
                    .ThenBy(f => f.Severity)
                    .ThenBy(f => f.Port));

        result.Duration = sw.Elapsed;
        return result;
    }

    private static async Task<bool> IsTcpOpenAsync(string host, int port, CancellationToken ct)
    {
        using var tcp = new TcpClient();
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(ConnectTimeoutMs);
            await tcp.ConnectAsync(host, port, timeoutCts.Token);
            return true;
        }
        catch { return false; }
    }

    private static async Task<string?> TryGrabBannerAsync(string host, int port)
    {
        try
        {
            using var tcp = new TcpClient();
            using var cts = new CancellationTokenSource(BannerTimeoutMs);
            await tcp.ConnectAsync(host, port, cts.Token);

            var stream = tcp.GetStream();
            stream.ReadTimeout = BannerTimeoutMs;

            // Some services (HTTP) need a prompt
            if (port is 80 or 8080 or 8443 or 8888)
            {
                var req = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n");
                await stream.WriteAsync(req, cts.Token);
            }

            var buf = new byte[256];
            int n = await stream.ReadAsync(buf, cts.Token);
            if (n <= 0) return null;

            return Encoding.ASCII.GetString(buf, 0, n)
                .Replace("\r", " ").Replace("\n", " ").Trim();
        }
        catch { return null; }
    }
}
