using Microsoft.Win32;
using System.Diagnostics;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class StartupScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        var keywords = rules.SuspiciousKeywords.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
        if (keywords.Count == 0) return;

        var registryKeys = new (RegistryKey Root, string Path, string Label)[]
        {
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (Registry.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce")
        };

        foreach (var item in registryKeys)
        {
            try
            {
                using var key = item.Root.OpenSubKey(item.Path, false);
                if (key is null) continue;

                foreach (var valueName in key.GetValueNames())
                {
                    var value = key.GetValue(valueName)?.ToString() ?? "";
                    var match = ScannerHelpers.FirstKeywordMatch($"{valueName} {value}", keywords);
                    if (match is null) continue;
                    ScannerHelpers.AddFinding(report, "startup_entry", valueName,
                        $"Запись автозапуска содержит ключевое слово правила: {match}.", "low", item.Label);
                }
            }
            catch (Exception ex)
            {
                ScannerHelpers.AddScanError(report, $"Не удалось проверить {item.Label}: {ex.Message}");
            }
        }

        try
        {
            var start = new ProcessStartInfo("schtasks.exe", "/Query /FO CSV /V")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var process = Process.Start(start);
            if (process is null) throw new InvalidOperationException("Не удалось запустить schtasks.exe.");
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(15000);

            var match = ScannerHelpers.FirstKeywordMatch(output, keywords);
            if (match is not null)
            {
                ScannerHelpers.AddFinding(report, "scheduled_task", match,
                    $"В данных планировщика задач найдено ключевое слово правила: {match}.", "low", "Task Scheduler");
            }
        }
        catch (Exception ex)
        {
            ScannerHelpers.AddScanError(report, $"Не удалось проверить задачи планировщика: {ex.Message}");
        }
    }
}
