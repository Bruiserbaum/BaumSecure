namespace BaumSecure.Models;

public sealed class ScanResult
{
    public string          TargetIp   { get; init; } = "";
    public DateTime        ScannedAt  { get; init; } = DateTime.UtcNow;
    public TimeSpan        Duration   { get; set; }
    public int             PortsChecked { get; set; }
    public List<SecurityFinding> Findings { get; init; } = new();

    public int CountBySeverity(Severity s) =>
        Findings.Count(f => f.IsOpen && f.Severity == s);

    public int OpenCount    => Findings.Count(f => f.IsOpen);
    public int CriticalCount => CountBySeverity(Severity.Critical);
    public int HighCount     => CountBySeverity(Severity.High);
    public int MediumCount   => CountBySeverity(Severity.Medium);
    public int LowCount      => CountBySeverity(Severity.Low);
}
