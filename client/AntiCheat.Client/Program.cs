using System.Text;
using System.Text.Json;
using AntiCheat.Client.Models;
using AntiCheat.Client.Services;

const string checkerVersion = "1.1.0";
Console.Title = "Anti-Cheat Checker";
Console.WriteLine("ANTI-CHEAT CHECKER");
Console.WriteLine("Проверяются только категории, перечисленные в rules.json.");
Console.WriteLine("Содержимое личных документов, пароли и браузерные данные не читаются.");
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
    Checks = ["processes", "configured_directories", "startup_entries", "scheduled_tasks", "hosts_entries", "configured_file_locations", "game_file_integrity"]
};

var scans = new (string Label, Action Run)[]
{
    ("Проверка процессов", () => ProcessScanner.Scan(rules, report)),
    ("Проверка заданных папок", () => DirectoryScanner.Scan(rules, report)),
    ("Проверка автозапуска и задач", () => StartupScanner.Scan(rules, report)),
    ("Проверка HOSTS", () => HostsScanner.Scan(rules, report)),
    ("Проверка имён файлов", () => FileScanner.Scan(rules, report)),
    ("Проверка целостности игровых файлов", () => GameIntegrityScanner.Scan(rules, report))
};

for (var index = 0; index < scans.Length; index++)
{
    Console.WriteLine($"[{index + 1}/{scans.Length}] {scans[index].Label}...");
    try { scans[index].Run(); }
    catch (Exception ex) { ScannerHelpers.AddScanError(report, $"Ошибка этапа '{scans[index].Label}': {ex.Message}"); }
}

report.Status = report.Found.Count == 0
    ? "clean"
    : report.Found.Any(f => f.Severity == "high")
        ? "suspicious"
        : "review";
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
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("Отчёт отправлен проверяющему.");
        Console.ResetColor();
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine($"Не удалось отправить отчёт: {ex.Message}");
        Console.ResetColor();
    }
}

Console.WriteLine();
Console.WriteLine($"Статус: {report.Status}");
Console.WriteLine($"Совпадений: {report.Found.Count}");
Console.WriteLine($"Ошибок сканирования: {report.ScanErrors.Count}");
Console.WriteLine($"Локальный отчёт: {resultPath}");
Console.WriteLine("Нажмите Enter для выхода.");
Console.ReadLine();
