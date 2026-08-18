using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class HostsScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (rules.HostBlockedDomains.Count == 0) return;

        var hostsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");
        if (!File.Exists(hostsPath)) return;

        try
        {
            foreach (var line in File.ReadLines(hostsPath))
            {
                var content = line.Split('#')[0].Trim();
                if (string.IsNullOrWhiteSpace(content)) continue;

                var match = ScannerHelpers.FirstKeywordMatch(content, rules.HostBlockedDomains);
                if (match is null) continue;

                ScannerHelpers.AddFinding(report, "hosts_entry", match,
                    "В файле HOSTS найдено правило, связанное с игровым доменом.", "low", hostsPath);
            }
        }
        catch (Exception ex)
        {
            ScannerHelpers.AddScanError(report, $"Не удалось прочитать HOSTS: {ex.Message}");
        }
    }
}
