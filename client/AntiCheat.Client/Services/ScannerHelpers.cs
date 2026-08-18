using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ScannerHelpers
{
    public static string ExpandPath(string path) => Environment.ExpandEnvironmentVariables(path.Trim());

    public static string? FirstKeywordMatch(string value, IEnumerable<string> keywords)
    {
        return keywords.FirstOrDefault(keyword =>
            !string.IsNullOrWhiteSpace(keyword) &&
            value.Contains(keyword.Trim(), StringComparison.OrdinalIgnoreCase));
    }

    public static void AddFinding(CheckReport report, string type, string name, string description, string severity, string? location = null)
    {
        var exists = report.Found.Any(f =>
            f.Type.Equals(type, StringComparison.OrdinalIgnoreCase) &&
            f.Name.Equals(name, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(f.Location ?? "", location ?? "", StringComparison.OrdinalIgnoreCase));

        if (exists) return;

        report.Found.Add(new Finding
        {
            Type = type,
            Name = name,
            Description = description,
            Severity = severity,
            Location = location
        });
    }

    public static void AddScanError(CheckReport report, string message)
    {
        if (!report.ScanErrors.Contains(message, StringComparer.OrdinalIgnoreCase)) report.ScanErrors.Add(message);
    }
}
