using System.Text.Json;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class IndicatorLoader
{
    public static IndicatorDatabase Load(string path, JsonSerializerOptions options, CheckReport report)
    {
        if (!File.Exists(path))
        {
            ScannerHelpers.AddScanError(report, "Файл indicators.json не найден. Проверка выполнена только по rules.json.");
            return new IndicatorDatabase();
        }

        try
        {
            return JsonSerializer.Deserialize<IndicatorDatabase>(File.ReadAllText(path), options) ?? new IndicatorDatabase();
        }
        catch (Exception ex)
        {
            ScannerHelpers.AddScanError(report, $"Не удалось прочитать indicators.json: {ex.Message}");
            return new IndicatorDatabase();
        }
    }

    public static void ApplyToRules(IndicatorDatabase database, Rules rules)
    {
        foreach (var indicator in database.Indicators)
        {
            if (string.IsNullOrWhiteSpace(indicator.Type) || string.IsNullOrWhiteSpace(indicator.Value)) continue;

            switch (indicator.Type.Trim().ToLowerInvariant())
            {
                case "process":
                    AddUnique(rules.BlockedProcessNames, indicator.Value);
                    break;
                case "directory":
                    AddUnique(rules.SuspiciousDirectories, indicator.Value);
                    break;
                case "keyword":
                    AddUnique(rules.SuspiciousKeywords, indicator.Value);
                    break;
            }
        }
    }

    private static void AddUnique(List<string> values, string value)
    {
        if (!values.Contains(value, StringComparer.OrdinalIgnoreCase)) values.Add(value);
    }
}
