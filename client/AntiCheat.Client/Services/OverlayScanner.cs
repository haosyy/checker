using System.Diagnostics;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class OverlayScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (rules.OverlayKeywords.Count == 0) return;

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var title = process.MainWindowTitle;
                if (string.IsNullOrWhiteSpace(title)) continue;

                var match = rules.OverlayKeywords.FirstOrDefault(keyword =>
                    title.Contains(keyword, StringComparison.OrdinalIgnoreCase));
                if (match == null) continue;

                report.Found.Add(new Finding
                {
                    Type = "overlay",
                    Name = process.ProcessName,
                    Description = $"Окно процесса содержит ключевое слово '{match}'.",
                    Severity = "review",
                    Location = title
                });
            }
            catch
            {
                // Некоторые системные процессы недоступны для чтения заголовка окна.
            }
            finally
            {
                process.Dispose();
            }
        }
    }
}