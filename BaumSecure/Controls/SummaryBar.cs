using BaumSecure.Models;

namespace BaumSecure.Controls;

/// <summary>
/// Horizontal bar showing counts per severity after a scan completes.
/// </summary>
public sealed class SummaryBar : Control
{
    private ScanResult? _result;

    public SummaryBar()
    {
        Height = 64;
        DoubleBuffered = true;
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer, true);
    }

    public void SetResult(ScanResult result)
    {
        _result = result;
        Invalidate();
    }

    public void Clear()
    {
        _result = null;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g  = e.Graphics;
        var rc = ClientRectangle;
        using var bg = new SolidBrush(AppTheme.BgDark);
        g.FillRectangle(bg, rc);

        // Always render all 4 tiles; dimmed when no scan has run yet
        bool hasScan = _result != null;

        var items = new[]
        {
            ("CRITICAL", _result?.CriticalCount ?? 0, AppTheme.Critical),
            ("HIGH",     _result?.HighCount     ?? 0, AppTheme.High),
            ("MEDIUM",   _result?.MediumCount   ?? 0, AppTheme.Medium),
            ("LOW",      _result?.LowCount      ?? 0, AppTheme.Low),
        };

        int tileW = rc.Width / items.Length;
        int x = 0;
        var sfC = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };

        foreach (var (label, count, color) in items)
        {
            bool active = hasScan && count > 0;

            // Tile bg/border: brighter when active, very dim before any scan
            int bgAlpha     = active ? 40 : (hasScan ? 15 : 10);
            int borderAlpha = active ? 100 : (hasScan ? 40 : 25);

            var tile = new Rectangle(x + 4, 4, tileW - 8, rc.Height - 8);
            using var tileBg = new SolidBrush(Color.FromArgb(bgAlpha, color));
            g.FillRectangle(tileBg, tile);
            using var tileBorder = new Pen(Color.FromArgb(borderAlpha, color));
            g.DrawRectangle(tileBorder, tile);

            // Count: bright when active, muted otherwise
            var countColor = active ? color : Color.FromArgb(hasScan ? 70 : 45, AppTheme.TextMuted);
            using var countBrush = new SolidBrush(countColor);
            var countRect = new Rectangle(x + 4, 4, tileW - 8, 36);
            string countText = hasScan ? count.ToString() : "—";
            g.DrawString(countText, AppTheme.FontTitle, countBrush, countRect, sfC);

            // Label
            int labelAlpha = active ? 180 : (hasScan ? 100 : 60);
            using var labelBrush = new SolidBrush(Color.FromArgb(labelAlpha, AppTheme.TextMuted));
            var labelRect = new Rectangle(x + 4, 38, tileW - 8, 22);
            g.DrawString(label, AppTheme.FontSmall, labelBrush, labelRect, sfC);

            x += tileW;
        }
    }
}
