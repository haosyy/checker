using System.Diagnostics;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ModuleScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (rules.SuspiciousModuleNames.Count == 0) return;

        foreach (var gameProcess in rules.GameProcessNames)
        {
            foreach (var process in Process.GetProcessesByName(gameProcess))
            {
                try
                {
                    foreach (ProcessModule module in process.Modules)
                    {
                        var match = rules.SuspiciousModuleNames.FirstOrDefault(name =>
                            module.ModuleName.Contains(name, StringComparison.OrdinalIgnoreCase) ||
                            module.FileName.Contains(name, StringComparison.OrdinalIgnoreCase));

                        if (match == null) continue;

                        report.Found.Add(new Finding
                        {
                            Type = "module",
                            Name = module.ModuleName,
                            Description = $"Игровой процесс загрузил модуль по правилу '{match}'.",
                            Severity = "high",
                            Location = module.FileName
                        });
                    }
                }
                catch (Exception ex)
                {
                    ScannerHelpers.AddScanError(report, $"Не удалось прочитать модули '{gameProcess}': {ex.Message}");
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
    }
}