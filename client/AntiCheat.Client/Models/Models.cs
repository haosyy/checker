namespace AntiCheat.Client.Models;

public sealed class Rules
{
    public string RulesVersion { get; set; } = "1.1.0";
    public string ReportApiUrl { get; set; } = "";
    public string GameDirectory { get; set; } = "";
    public List<string> GameProcessNames { get; set; } = [];
    public List<string> BlockedProcessNames { get; set; } = [];
    public List<string> SuspiciousKeywords { get; set; } = [];
    public List<string> SuspiciousDirectories { get; set; } = [];
    public List<string> HostBlockedDomains { get; set; } = [];
    public List<string> ScanRoots { get; set; } = [];
    public List<string> ScanFileExtensions { get; set; } = [];
    public List<GameFileRule> ExpectedGameFiles { get; set; } = [];
}

public sealed class GameFileRule
{
    public string RelativePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
}

public sealed class Finding
{
    public string Type { get; set; } = "";
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public string Severity { get; set; } = "low";
    public string? Location { get; set; }
}

public sealed class CheckReport
{
    public string CheckId { get; set; } = Guid.NewGuid().ToString("N")[..12].ToUpperInvariant();
    public string CheckerVersion { get; set; } = "1.1.0";
    public string RulesVersion { get; set; } = "";
    public string Computer { get; set; } = Environment.MachineName;
    public string User { get; set; } = Environment.UserName;
    public DateTime Time { get; set; } = DateTime.UtcNow;
    public bool GameRunning { get; set; }
    public string Status { get; set; } = "clean";
    public List<Finding> Found { get; set; } = [];
    public List<string> ScanErrors { get; set; } = [];
    public List<string> Checks { get; set; } = [];
}
