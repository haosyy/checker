using System.Diagnostics;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ProcessScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        var blocked = new HashSet<string>(rules.BlockedProcessNames.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()), StringComparer.OrdinalIgnoreCase);
        var keywords = rules.SuspiciousKeywords.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()).ToList();
        var gameNames = new HashSet<string>(rules.GameProcessNames.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x.Trim()), StringComparer.OrdinalIgnoreCase);

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var name = process.ProcessName;
                if (gameNames.Contains(name)) report.GameRunning = true;

                if (blocked.Contains(name))
                {
                    ScannerHelpers.AddFinding(report, "process", name, "Точное совпадение с процессом из списка правил.", "high", $"PID {process.Id}");
                    continue;
                }

                var keyword = ScannerHelpers.FirstKeywordMatch(name, keywords);
                if (keyword is not null)
                {
                    ScannerHelpers.AddFinding(report, "process_keyword", name, $"Имя процесса содержит ключевое слово правила: {keyword}.", "low", $"PID {process.Id}");
                }

                try
                {
                    var path = process.MainModule?.FileName;
                    if (!string.IsNullOrWhiteSpace(path))
                    {
                        keyword = ScannerHelpers.FirstKeywordMatch(path, keywords);
                        if (keyword is not null)
                        {
                            ScannerHelpers.AddFinding(report, "process_path", name, $"Путь процесса содержит ключевое слово правила: {keyword}.", "low", path);
                        }
                    }
                }
                catch { }
            }
            catch { }
            finally { process.Dispose(); }
        }
    }
}
