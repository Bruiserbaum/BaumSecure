namespace BaumSecure.Models;

public enum Severity { Critical, High, Medium, Low, Info }
public enum ScanProfile { Quick, Full, Custom }

public sealed record SecurityRule(
    int         Port,
    string      Protocol,       // "TCP" or "UDP"
    string      ServiceName,
    Severity    Severity,
    string      Title,
    string      Description,
    string      Recommendation
);
