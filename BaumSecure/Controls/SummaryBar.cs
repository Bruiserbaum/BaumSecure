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

        if (_result == null) return;

        var items = new[]
        {
            ("CRITICAL", _result.CriticalCount, AppTheme.Critical),
            ("HIGH",     _result.HighCount,     AppTheme.High),
            ("MEDIUM",   _result.MediumCount,   AppTheme.Medium),
            ("LOW",      _result.LowCount,       AppTheme.Low),
        };

        int tileW = rc.Width / items.Length;
        int x = 0;
        var sfC = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };

        foreach (var (label, count, color) in items)
        {
            var tile = new Rectangle(x + 4, 4, tileW - 8, rc.Height - 8);
            using var tileBg = new SolidBrush(Color.FromArgb(30, color));
            g.FillRectangle(tileBg, tile);
            using var tileBorder = new Pen(Color.FromArgb(80, color));
            g.DrawRectangle(tileBorder, tile);

            // Count number
            using var countBrush = new SolidBrush(count > 0 ? color : AppTheme.TextMuted);
            var countRect = new Rectangle(x + 4, 4, tileW - 8, 36);
            g.DrawString(count.ToString(), AppTheme.FontTitle, countBrush, countRect, sfC);

            // Label
            using var labelBrush = new SolidBrush(AppTheme.TextMuted);
            var labelRect = new Rectangle(x + 4, 38, tileW - 8, 22);
            g.DrawString(label, AppTheme.FontSmall, labelBrush, labelRect, sfC);

            x += tileW;
        }
    }
}
