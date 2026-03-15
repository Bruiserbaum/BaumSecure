using BaumSecure.Controls;
using BaumSecure.Models;
using BaumSecure.Services;

namespace BaumSecure;

public sealed class MainForm : Form
{
    // ── Services ───────────────────────────────────────────────────────────────
    private readonly PortScanService _scanner = new();
    private CancellationTokenSource? _cts;

    // ── Controls ───────────────────────────────────────────────────────────────
    private readonly TextBox    _ipBox;
    private readonly ComboBox   _profileBox;
    private readonly Button     _scanBtn;
    private readonly Button     _cancelBtn;
    private readonly ProgressBar _progress;
    private readonly Label      _statusLabel;
    private readonly SummaryBar _summaryBar;
    private readonly Panel      _findingsScroll;
    private readonly Label      _externalIpLabel;
    private readonly CheckBox   _showClosedChk;

    private ScanResult? _lastResult;

    public MainForm()
    {
        Text            = "BaumSecure — Home Lab Security Analyzer";
        ClientSize      = new Size(900, 700);
        MinimumSize     = new Size(760, 580);
        BackColor       = AppTheme.BgDark;
        ForeColor       = AppTheme.TextPrim;
        Font            = AppTheme.FontBody;
        StartPosition   = FormStartPosition.CenterScreen;

        // ── Header ─────────────────────────────────────────────────────────────
        var header = new Panel
        {
            Dock      = DockStyle.Top,
            Height    = 56,
            BackColor = AppTheme.BgCard,
        };
        header.Paint += (_, e) =>
        {
            e.Graphics.DrawLine(new Pen(AppTheme.Border), 0, header.Height - 1, header.Width - 1, header.Height - 1);
            e.Graphics.DrawString("BaumSecure", AppTheme.FontTitle, new SolidBrush(AppTheme.Accent), 16, 14);
        };

        _externalIpLabel = new Label
        {
            AutoSize  = false,
            Width     = 260,
            Height    = 56,
            TextAlign = ContentAlignment.MiddleRight,
            ForeColor = AppTheme.TextMuted,
            Font      = AppTheme.FontBody,
            Text      = "Detecting external IP…",
            Dock      = DockStyle.Right,
        };
        header.Controls.Add(_externalIpLabel);
        Controls.Add(header);

        // ── Config bar ─────────────────────────────────────────────────────────
        var configBar = new Panel
        {
            Dock      = DockStyle.Top,
            Height    = 52,
            BackColor = AppTheme.BgDark,
            Padding   = new Padding(12, 10, 12, 0),
        };
        configBar.Paint += (_, e) =>
            e.Graphics.DrawLine(new Pen(AppTheme.Border), 0, configBar.Height - 1, configBar.Width - 1, configBar.Height - 1);

        var ipLabel = new Label { Text = "Target IP:", AutoSize = true, ForeColor = AppTheme.TextMuted, Top = 16, Left = 12 };

        _ipBox = new TextBox
        {
            Width     = 160,
            Left      = 90,
            Top       = 13,
            BackColor = AppTheme.BgCard,
            ForeColor = AppTheme.TextPrim,
            BorderStyle = BorderStyle.FixedSingle,
            Font      = AppTheme.FontMono,
        };

        var profileLabel = new Label { Text = "Profile:", AutoSize = true, ForeColor = AppTheme.TextMuted, Top = 16, Left = 264 };

        _profileBox = new ComboBox
        {
            Width         = 90,
            Left          = 320,
            Top           = 13,
            DropDownStyle = ComboBoxStyle.DropDownList,
            BackColor     = AppTheme.BgCard,
            ForeColor     = AppTheme.TextPrim,
            FlatStyle     = FlatStyle.Flat,
        };
        _profileBox.Items.AddRange(["Quick (critical + high)", "Full (all rules)"]);
        _profileBox.SelectedIndex = 0;

        _showClosedChk = new CheckBox
        {
            Text      = "Show closed ports",
            Left      = 422,
            Top       = 15,
            Width     = 140,
            ForeColor = AppTheme.TextMuted,
            BackColor = Color.Transparent,
        };
        _showClosedChk.CheckedChanged += (_, _) => RebuildFindingsList(_lastResult);

        _scanBtn = MakeButton("Scan", 574, 12, 80, AppTheme.Accent);
        _cancelBtn = MakeButton("Cancel", 662, 12, 70, AppTheme.Critical);
        _cancelBtn.Visible = false;

        _scanBtn.Click   += OnScanClick;
        _cancelBtn.Click += OnCancelClick;

        configBar.Controls.AddRange([ipLabel, _ipBox, profileLabel, _profileBox, _showClosedChk, _scanBtn, _cancelBtn]);
        Controls.Add(configBar);

        // ── Progress bar ───────────────────────────────────────────────────────
        var progressPanel = new Panel { Dock = DockStyle.Top, Height = 28, BackColor = AppTheme.BgDark, Padding = new Padding(12, 6, 12, 0) };
        _progress = new ProgressBar
        {
            Dock    = DockStyle.Fill,
            Style   = ProgressBarStyle.Continuous,
            Minimum = 0,
            Maximum = 100,
            Value   = 0,
        };
        _statusLabel = new Label
        {
            Dock      = DockStyle.Right,
            Width     = 280,
            ForeColor = AppTheme.TextMuted,
            TextAlign = ContentAlignment.MiddleRight,
            Font      = AppTheme.FontSmall,
        };
        progressPanel.Controls.AddRange([_progress, _statusLabel]);
        Controls.Add(progressPanel);

        // ── Summary bar ────────────────────────────────────────────────────────
        _summaryBar = new SummaryBar { Dock = DockStyle.Top };
        Controls.Add(_summaryBar);

        // ── Findings scroll panel ──────────────────────────────────────────────
        _findingsScroll = new Panel
        {
            Dock            = DockStyle.Fill,
            AutoScroll      = true,
            BackColor       = AppTheme.BgDark,
        };
        AppTheme.ApplyDarkScrollBar(_findingsScroll);
        Controls.Add(_findingsScroll);

        _ = DetectExternalIpAsync();
        _scanner.Progress += OnScanProgress;
    }

    // ── External IP detection ──────────────────────────────────────────────────
    private async Task DetectExternalIpAsync()
    {
        var ip = await ExternalIpService.GetExternalIpAsync();
        if (IsDisposed) return;
        Invoke(() =>
        {
            if (ip != null)
            {
                _ipBox.Text          = ip;
                _externalIpLabel.Text = $"External IP: {ip}  ";
                _externalIpLabel.ForeColor = AppTheme.TextPrim;
            }
            else
            {
                _externalIpLabel.Text      = "Could not detect external IP  ";
                _externalIpLabel.ForeColor = AppTheme.High;
            }
        });
    }

    // ── Scan ───────────────────────────────────────────────────────────────────
    private async void OnScanClick(object? sender, EventArgs e)
    {
        var ip = _ipBox.Text.Trim();
        if (string.IsNullOrEmpty(ip)) { MessageBox.Show("Enter a target IP.", "BaumSecure", MessageBoxButtons.OK, MessageBoxIcon.Warning); return; }

        _cts = new CancellationTokenSource();
        _scanBtn.Enabled   = false;
        _cancelBtn.Visible = true;
        _progress.Value    = 0;
        _summaryBar.Clear();
        _findingsScroll.Controls.Clear();
        _statusLabel.Text  = "Starting scan…";

        var profile = _profileBox.SelectedIndex == 0 ? ScanProfile.Quick : ScanProfile.Full;

        try
        {
            var result = await _scanner.ScanAsync(ip, profile, _cts.Token);
            _lastResult = result;
            _summaryBar.SetResult(result);
            RebuildFindingsList(result);
            _statusLabel.Text = $"Done — {result.OpenCount} open / {result.PortsChecked} checked  ({result.Duration.TotalSeconds:F1}s)";
            _progress.Value   = 100;
        }
        catch (OperationCanceledException)
        {
            _statusLabel.Text = "Scan cancelled.";
        }
        finally
        {
            _scanBtn.Enabled   = true;
            _cancelBtn.Visible = false;
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void OnCancelClick(object? sender, EventArgs e) => _cts?.Cancel();

    private void OnScanProgress(object? sender, ScanProgressArgs args)
    {
        if (IsDisposed) return;
        Invoke(() =>
        {
            _progress.Value   = args.Percent;
            _statusLabel.Text = $"Checked {args.Completed} / {args.Total}…";
            if (args.Latest is { IsOpen: true } f)
                _statusLabel.Text += $"  ⚠ {f.Port} open";
        });
    }

    // ── Findings list ──────────────────────────────────────────────────────────
    private void RebuildFindingsList(ScanResult? result)
    {
        _findingsScroll.Controls.Clear();
        if (result == null) return;

        var findings = _showClosedChk.Checked
            ? result.Findings
            : result.Findings.Where(f => f.IsOpen).ToList();

        int y = 0;
        int w = _findingsScroll.ClientSize.Width - SystemInformation.VerticalScrollBarWidth;

        foreach (var finding in findings)
        {
            var row = new FindingRow(finding)
            {
                Top    = y,
                Left   = 0,
                Width  = w,
                Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
            };
            row.ExpandedChanged += (_, _) =>
            {
                // Re-stack rows below after expand/collapse
                int ry = 0;
                foreach (FindingRow r in _findingsScroll.Controls.OfType<FindingRow>())
                { r.Top = ry; ry += r.Height; }
                _findingsScroll.AutoScrollMinSize = new Size(1, ry);
            };
            _findingsScroll.Controls.Add(row);
            y += row.Height;
        }

        _findingsScroll.AutoScrollMinSize = new Size(1, y);

        if (!findings.Any())
        {
            var empty = new Label
            {
                Text      = findings.Count == 0 && result.OpenCount == 0
                    ? "No open ports detected — your external surface looks clean."
                    : "No findings to display. Enable 'Show closed ports' to see all checked ports.",
                AutoSize  = false,
                Width     = w,
                Height    = 60,
                TextAlign = ContentAlignment.MiddleCenter,
                ForeColor = AppTheme.TextMuted,
                Font      = AppTheme.FontBody,
            };
            _findingsScroll.Controls.Add(empty);
        }
    }

    // ── Resize ─────────────────────────────────────────────────────────────────
    protected override void OnResize(EventArgs e)
    {
        base.OnResize(e);
        if (_findingsScroll == null) return;
        int w = _findingsScroll.ClientSize.Width - SystemInformation.VerticalScrollBarWidth;
        foreach (FindingRow row in _findingsScroll.Controls.OfType<FindingRow>())
            row.Width = w;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    private static Button MakeButton(string text, int x, int y, int w, Color bg)
    {
        return new Button
        {
            Text      = text,
            Left      = x,
            Top       = y,
            Width     = w,
            Height    = 28,
            BackColor = bg,
            ForeColor = Color.White,
            FlatStyle = FlatStyle.Flat,
            Cursor    = Cursors.Hand,
            Font      = AppTheme.FontBody,
        };
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _cts?.Cancel(); _cts?.Dispose(); }
        base.Dispose(disposing);
    }
}
