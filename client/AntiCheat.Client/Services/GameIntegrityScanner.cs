using System.Security.Cryptography;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class GameIntegrityScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (string.IsNullOrWhiteSpace(rules.GameDirectory) || rules.ExpectedGameFiles.Count == 0) return;
        var gameDirectory = ScannerHelpers.ExpandPath(rules.GameDirectory);

        foreach (var rule in rules.ExpectedGameFiles)
        {
            if (string.IsNullOrWhiteSpace(rule.RelativePath)) continue;
            var path = Path.Combine(gameDirectory, rule.RelativePath);

            try
            {
                if (!File.Exists(path))
                {
                    ScannerHelpers.AddFinding(report, "game_file_missing", rule.RelativePath,
                        "Не найден игровой файл, явно заданный в правилах.", "medium", path);
                    continue;
                }

                if (string.IsNullOrWhiteSpace(rule.Sha256)) continue;
                using var stream = File.OpenRead(path);
                var hash = Convert.ToHexString(SHA256.HashData(stream));
                if (!hash.Equals(rule.Sha256.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    ScannerHelpers.AddFinding(report, "game_file_hash", rule.RelativePath,
                        "SHA-256 игрового файла не совпал с явно заданным правилом.", "high", path);
                }
            }
            catch (Exception ex)
            {
                ScannerHelpers.AddScanError(report, $"Не удалось проверить игровой файл {rule.RelativePath}: {ex.Message}");
            }
        }
    }
}
