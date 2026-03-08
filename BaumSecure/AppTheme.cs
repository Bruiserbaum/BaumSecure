using System.Runtime.InteropServices;

namespace BaumSecure;

public static class AppTheme
{
    // ── Colours ────────────────────────────────────────────────────────────────
    public static readonly Color BgDark    = Color.FromArgb(13,  17,  23);   // deepest bg
    public static readonly Color BgCard    = Color.FromArgb(22,  27,  34);   // panel bg
    public static readonly Color BgHover   = Color.FromArgb(33,  38,  45);
    public static readonly Color Border    = Color.FromArgb(48,  54,  61);
    public static readonly Color TextPrim  = Color.FromArgb(230, 237, 243);
    public static readonly Color TextMuted = Color.FromArgb(139, 148, 158);
    public static readonly Color Accent    = Color.FromArgb(31,  111, 235);

    // Severity colours
    public static readonly Color Critical  = Color.FromArgb(218, 54,  51);
    public static readonly Color High      = Color.FromArgb(210, 153, 34);
    public static readonly Color Medium    = Color.FromArgb(88,  166, 255);
    public static readonly Color Low       = Color.FromArgb(86,  211, 100);
    public static readonly Color Info      = Color.FromArgb(110, 118, 129);

    // ── Fonts ──────────────────────────────────────────────────────────────────
    public static readonly Font FontTitle  = new("Segoe UI",  14f, FontStyle.Bold);
    public static readonly Font FontH2     = new("Segoe UI",  10f, FontStyle.Bold);
    public static readonly Font FontBody   = new("Segoe UI",   9f, FontStyle.Regular);
    public static readonly Font FontMono   = new("Consolas",   8.5f, FontStyle.Regular);
    public static readonly Font FontSmall  = new("Segoe UI",   8f, FontStyle.Regular);

    // ── Dark scrollbars ────────────────────────────────────────────────────────
    [DllImport("uxtheme.dll", ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string? pszSubIdList);

    public static void ApplyDarkScrollBar(Control control)
    {
        void Apply(IntPtr hwnd) => SetWindowTheme(hwnd, "DarkMode_Explorer", null);
        if (control.IsHandleCreated) Apply(control.Handle);
        else control.HandleCreated += (s, _) => Apply(((Control)s!).Handle);
    }

    // ── Severity helpers ───────────────────────────────────────────────────────
    public static Color SeverityColor(Models.Severity s) => s switch
    {
        Models.Severity.Critical => Critical,
        Models.Severity.High     => High,
        Models.Severity.Medium   => Medium,
        Models.Severity.Low      => Low,
        _                        => Info,
    };

    public static string SeverityLabel(Models.Severity s) => s switch
    {
        Models.Severity.Critical => "CRITICAL",
        Models.Severity.High     => "HIGH",
        Models.Severity.Medium   => "MEDIUM",
        Models.Severity.Low      => "LOW",
        _                        => "INFO",
    };
}
