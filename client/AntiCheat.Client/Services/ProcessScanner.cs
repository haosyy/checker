using System.Diagnostics;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ProcessScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        var blocked = new HashSet<string>(
            rules.BlockedProcessNames.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        var keywords = rules.SuspiciousKeywords
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToList();

        var gameNames = new HashSet<string>(
            rules.GameProcessNames.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()),
            StringComparer.OrdinalIgnoreCase);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var name = process.ProcessName;
                if (gameNames.Contains(name)) report.GameRunning = true;

                if (blocked.Contains(name))
                {
                    Add(report, "process", name, "Точное совпадение с процессом из списка правил.", "high", $"PID {process.Id}");
                    continue;
                }

                var keyword = keywords.FirstOrDefault(k => name.Contains(k, StringComparison.OrdinalIgnoreCase));
                if (keyword is not null)
                {
                    Add(report, "process_keyword", name, $"Имя процесса содержит ключевое слово правила: {keyword}.", "low", $"PID {process.Id}");
                }
            }
            catch { }
            finally { process.Dispose(); }
        }
    }

    private static void Add(CheckReport report, string type, string name, string description, string severity, string location)
    {
        if (report.Found.Any(f => f.Type.Equals(type, StringComparison.OrdinalIgnoreCase) && f.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && f.Location == location)) return;
        report.Found.Add(new Finding { Type = type, Name = name, Description = description, Severity = severity, Location = location });
    }
}
