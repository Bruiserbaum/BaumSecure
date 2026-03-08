namespace BaumSecure.Models;

public sealed record SecurityFinding(
    SecurityRule Rule,
    bool         IsOpen,
    string?      Banner       // optional grabbed banner text
)
{
    public int      Port        => Rule.Port;
    public string   Protocol    => Rule.Protocol;
    public string   ServiceName => Rule.ServiceName;
    public Severity Severity    => IsOpen ? Rule.Severity : Severity.Info;
    public string   Title       => Rule.Title;
    public string   Description => Rule.Description;
    public string   Recommendation => Rule.Recommendation;
}
