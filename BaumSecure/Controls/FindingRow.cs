using BaumSecure.Models;

namespace BaumSecure.Controls;

/// <summary>
/// Single owner-drawn row in the findings list.
/// </summary>
public sealed class FindingRow : Control
{
    private const int RowH       = 58;
    private const int BadgeW     = 70;
    private const int PortW      = 52;
    private const int ServiceW   = 110;
    private const int ChevronW   = 24;

    private readonly SecurityFinding _finding;
    private bool _expanded;
    private bool _hovered;

    public event EventHandler? ExpandedChanged;

    public FindingRow(SecurityFinding finding)
    {
        _finding   = finding;
        Height     = RowH;
        Cursor     = Cursors.Hand;
        DoubleBuffered = true;
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.OptimizedDoubleBuffer, true);
    }

    public bool IsExpanded
    {
        get => _expanded;
        set
        {
            if (_expanded == value) return;
            _expanded = value;
            Height = _expanded ? RowH + 80 : RowH;
            Invalidate();
            ExpandedChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    protected override void OnMouseEnter(EventArgs e) { _hovered = true;  Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { _hovered = false; Invalidate(); }
    protected override void OnClick(EventArgs e)      { IsExpanded = !IsExpanded; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g   = e.Graphics;
        var rc  = ClientRectangle;
        Color bg = _hovered ? AppTheme.BgHover : AppTheme.BgCard;
        using var bgBrush = new SolidBrush(bg);
        g.FillRectangle(bgBrush, rc);

        // Bottom border
        using var borderPen = new Pen(AppTheme.Border);
        g.DrawLine(borderPen, 0, rc.Height - 1, rc.Width - 1, rc.Height - 1);

        if (!_finding.IsOpen)
        {
            // Dim closed ports
            using var dimBrush = new SolidBrush(AppTheme.TextMuted);
            using var dimFont = new Font(AppTheme.FontMono.FontFamily, 8f);
            g.DrawString($"  ✓  {_finding.Port,-6} {_finding.ServiceName}", dimFont, dimBrush, 8, 20);
            return;
        }

        Color sev    = AppTheme.SeverityColor(_finding.Severity);
        string label = AppTheme.SeverityLabel(_finding.Severity);
        int x = 8;

        // Severity badge
        var badgeRect = new Rectangle(x, 16, BadgeW, 20);
        using (var badgeBrush = new SolidBrush(Color.FromArgb(40, sev)))
            g.FillRectangle(badgeBrush, badgeRect);
        using (var badgePen = new Pen(Color.FromArgb(120, sev)))
            g.DrawRectangle(badgePen, badgeRect);
        using var sevBrush = new SolidBrush(sev);
        var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
        g.DrawString(label, AppTheme.FontSmall, sevBrush, badgeRect, sf);
        x += BadgeW + 10;

        // Port
        using var mutedBrush = new SolidBrush(AppTheme.TextMuted);
        using var primBrush  = new SolidBrush(AppTheme.TextPrim);
        g.DrawString($":{_finding.Port}", AppTheme.FontMono, mutedBrush, x, 10);
        g.DrawString(_finding.Protocol,   AppTheme.FontSmall, mutedBrush, x, 28);
        x += PortW + 8;

        // Service name
        g.DrawString(_finding.ServiceName, AppTheme.FontH2,  primBrush, x, 10);
        x += ServiceW;

        // Title
        g.DrawString(_finding.Title, AppTheme.FontBody, primBrush, x, 10);

        // Banner (if any)
        if (_finding.Banner is { } banner && banner.Length > 0)
        {
            string trimmed = banner.Length > 80 ? banner[..80] + "…" : banner;
            g.DrawString(trimmed, AppTheme.FontMono, mutedBrush, x, 28);
        }

        // Chevron
        using var chevBrush = new SolidBrush(AppTheme.TextMuted);
        g.DrawString(_expanded ? "▲" : "▼", AppTheme.FontSmall, chevBrush,
            rc.Width - ChevronW - 4, 20);

        // Expanded detail
        if (_expanded)
        {
            int dy = RowH + 4;
            using var indentPen = new Pen(Color.FromArgb(60, sev), 2f);
            g.DrawLine(indentPen, 16, dy, 16, rc.Height - 8);

            int tx = 28;
            g.DrawString("Description", AppTheme.FontH2, sevBrush, tx, dy);
            dy += 16;
            DrawWrapped(g, _finding.Description, AppTheme.FontBody, mutedBrush, tx, ref dy, rc.Width - tx - 8);
            dy += 6;
            g.DrawString("Recommendation", AppTheme.FontH2, new SolidBrush(AppTheme.Low), tx, dy);
            dy += 16;
            DrawWrapped(g, _finding.Recommendation, AppTheme.FontBody, primBrush, tx, ref dy, rc.Width - tx - 8);
        }
    }

    private static void DrawWrapped(Graphics g, string text, Font font, Brush brush,
        int x, ref int y, int maxWidth)
    {
        var sz = g.MeasureString(text, font, maxWidth);
        g.DrawString(text, font, brush, new RectangleF(x, y, maxWidth, sz.Height));
        y += (int)sz.Height;
    }

    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        Invalidate();
    }
}
