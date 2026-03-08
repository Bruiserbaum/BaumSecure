namespace BaumSecure.Services;

public static class ExternalIpService
{
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    // Try multiple providers in order so one outage doesn't break detection
    private static readonly string[] _providers =
    [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];

    public static async Task<string?> GetExternalIpAsync()
    {
        foreach (var url in _providers)
        {
            try
            {
                var response = await _http.GetStringAsync(url);
                var ip = response.Trim();
                if (IsValidIpv4(ip)) return ip;
            }
            catch { /* try next */ }
        }
        return null;
    }

    private static bool IsValidIpv4(string s)
    {
        var parts = s.Split('.');
        if (parts.Length != 4) return false;
        return parts.All(p => byte.TryParse(p, out _));
    }
}
