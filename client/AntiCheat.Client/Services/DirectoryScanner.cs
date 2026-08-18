using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class DirectoryScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        foreach (var template in rules.SuspiciousDirectories.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var path = ScannerHelpers.ExpandPath(template);
            try
            {
                if (!Directory.Exists(path)) continue;
                var name = Path.GetFileName(path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
                ScannerHelpers.AddFinding(report, "directory", string.IsNullOrWhiteSpace(name) ? path : name,
                    "Найдена папка из точного списка правил.", "medium", path);
            }
            catch (Exception ex)
            {
                ScannerHelpers.AddScanError(report, $"Не удалось проверить папку: {path} ({ex.Message})");
            }
        }
    }
}
