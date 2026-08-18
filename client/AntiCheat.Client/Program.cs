using System.Text;
using System.Text.Json;
using AntiCheat.Client.Models;
using AntiCheat.Client.Services;

const string checkerVersion = "1.0.0";
Console.Title = "Anti-Cheat Checker";
Console.WriteLine("ANTI-CHEAT CHECKER");
Console.WriteLine("Проверяются только настроенные правила. Личные документы не читаются.");
Console.WriteLine();

var baseDir = AppContext.BaseDirectory;
var rulesPath = Path.Combine(baseDir, "rules.json");
var resultPath = Path.Combine(baseDir, "result.json");
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, WriteIndented = true };

if (!File.Exists(rulesPath))
{
    Console.Error.WriteLine("Файл rules.json не найден.");
    Environment.Exit(1);
}

var rules = JsonSerializer.Deserialize<Rules>(await File.ReadAllTextAsync(rulesPath), options) ?? new Rules();
var report = new CheckReport
{
    CheckerVersion = checkerVersion,
    RulesVersion = rules.RulesVersion,
    Checks = ["processes", "game_processes"]
};

Console.WriteLine("[1/1] Проверка процессов...");
ProcessScanner.Scan(rules, report);
report.Status = report.Found.Count == 0 ? "clean" : report.Found.Any(f => f.Severity == "high") ? "suspicious" : "review";
report.Time = DateTime.UtcNow;

var reportJson = JsonSerializer.Serialize(report, options);
await File.WriteAllTextAsync(resultPath, reportJson, Encoding.UTF8);

var token = Environment.GetEnvironmentVariable("REPORT_API_TOKEN");
if (string.IsNullOrWhiteSpace(rules.ReportApiUrl))
{
    Console.WriteLine("reportApiUrl пуст: отчёт сохранён локально.");
}
else if (string.IsNullOrWhiteSpace(token))
{
    Console.WriteLine("REPORT_API_TOKEN не передан: отчёт сохранён локально.");
}
else
{
    try
    {
        using var client = new HttpClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var content = new StringContent(reportJson, Encoding.UTF8, "application/json");
        using var response = await client.PostAsync(rules.ReportApiUrl, content);
        var body = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode) throw new Exception($"{(int)response.StatusCode}: {body}");
        Console.WriteLine("Отчёт отправлен проверяющему.");
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Не удалось отправить отчёт: {ex.Message}");
    }
}

Console.WriteLine($"Статус: {report.Status}");
Console.WriteLine($"Совпадений: {report.Found.Count}");
Console.WriteLine($"Локальный отчёт: {resultPath}");
Console.WriteLine("Нажмите Enter для выхода.");
Console.ReadLine();
