using System.Text;
using System.Text.Json;
using AntiCheat.Client.Models;
using AntiCheat.Client.Services;

namespace AntiCheat.Client.UI;

public sealed class MainWindow : Form
{
    private const string CheckerVersion = "2.0.0";

    private readonly Label _title = new();
    private readonly Label _subtitle = new();
    private readonly Button _startButton = new();
    private readonly ProgressBar _progress = new();
    private readonly Label _stateLabel = new();
    private readonly ListBox _results = new();
    private readonly Button _closeButton = new();
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private bool _running;

    public MainWindow()
    {
        InitializeUi();
    }

    private void InitializeUi()
    {
        Text = "Anti-Cheat Checker";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(560, 540);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;
        BackColor = Color.FromArgb(15, 17, 21);

        _title.Text = "Anti-Cheat Checker";
        _title.Font = new Font("Segoe UI", 18F, FontStyle.Bold);
        _title.ForeColor = Color.White;
        _title.AutoSize = true;
        _title.Location = new Point(32, 28);

        _subtitle.Text = "Добровольная проверка.\nЛичные документы, пароли и браузерные данные не читаются.";
        _subtitle.Font = new Font("Segoe UI", 9.5F);
        _subtitle.ForeColor = Color.FromArgb(150, 158, 170);
        _subtitle.Location = new Point(34, 72);
        _subtitle.Size = new Size(490, 48);

        _startButton.Text = "Начать проверку";
        _startButton.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
        _startButton.ForeColor = Color.White;
        _startButton.BackColor = Color.FromArgb(79, 140, 255);
        _startButton.FlatStyle = FlatStyle.Flat;
        _startButton.FlatAppearance.BorderSize = 0;
        _startButton.Size = new Size(494, 48);
        _startButton.Location = new Point(33, 134);
        _startButton.Cursor = Cursors.Hand;
        _startButton.Click += async (_, _) => await RunCheckAsync();

        _progress.Style = ProgressBarStyle.Continuous;
        _progress.Size = new Size(494, 8);
        _progress.Location = new Point(33, 198);

        _stateLabel.Text = "Готово к проверке";
        _stateLabel.Font = new Font("Segoe UI", 10F);
        _stateLabel.ForeColor = Color.FromArgb(190, 196, 205);
        _stateLabel.Location = new Point(34, 218);
        _stateLabel.AutoSize = true;

        _results.Font = new Font("Consolas", 9.5F);
        _results.BackColor = Color.FromArgb(23, 26, 32);
        _results.ForeColor = Color.FromArgb(220, 224, 230);
        _results.BorderStyle = BorderStyle.None;
        _results.Size = new Size(494, 230);
        _results.Location = new Point(33, 250);
        _results.HorizontalScrollbar = true;

        _closeButton.Text = "Закрыть";
        _closeButton.Font = new Font("Segoe UI", 10F);
        _closeButton.ForeColor = Color.White;
        _closeButton.BackColor = Color.FromArgb(38, 43, 52);
        _closeButton.FlatStyle = FlatStyle.Flat;
        _closeButton.FlatAppearance.BorderSize = 0;
        _closeButton.Size = new Size(494, 40);
        _closeButton.Location = new Point(33, 492);
        _closeButton.Cursor = Cursors.Hand;
        _closeButton.Click += (_, _) => Close();

        Controls.AddRange([_title, _subtitle, _startButton, _progress, _stateLabel, _results, _closeButton]);
    }

    private async Task RunCheckAsync()
    {
        if (_running) return;
        _running = true;
        _startButton.Enabled = false;
        _results.Items.Clear();
        _progress.Value = 0;
        SetState("Подготовка проверки…", Color.FromArgb(190, 196, 205));

        var report = new CheckReport { CheckerVersion = CheckerVersion };
        var baseDir = AppContext.BaseDirectory;
        var rulesPath = Path.Combine(baseDir, "rules.json");
        var indicatorsPath = Path.Combine(baseDir, "indicators.json");

        try
        {
            if (!File.Exists(rulesPath))
                throw new FileNotFoundException("Файл rules.json не найден.");

            var rules = JsonSerializer.Deserialize<Rules>(await File.ReadAllTextAsync(rulesPath), _jsonOptions)
                ?? new Rules();
            report.RulesVersion = rules.RulesVersion;
            report.Checks =
            [
                "indicator_database", "processes", "configured_directories", "startup_entries",
                "scheduled_tasks", "hosts_entries", "configured_file_locations", "game_file_integrity",
                "game_modules", "windows_services", "system_proxy", "overlay_windows"
            ];

            var indicators = IndicatorLoader.Load(indicatorsPath, _jsonOptions, report);
            IndicatorLoader.ApplyToRules(indicators, rules);

            var scans = new (string Label, Action Run)[]
            {
                ("Проверка процессов", () => ProcessScanner.Scan(rules, report)),
                ("Проверка папок", () => DirectoryScanner.Scan(rules, report)),
                ("Проверка автозапуска и задач", () => StartupScanner.Scan(rules, report)),
                ("Проверка HOSTS", () => HostsScanner.Scan(rules, report)),
                ("Проверка файлов", () => FileScanner.Scan(rules, report)),
                ("Проверка игровых файлов", () => GameIntegrityScanner.Scan(rules, report)),
                ("Проверка модулей игры", () => ModuleScanner.Scan(rules, report)),
                ("Проверка служб", () => ServiceScanner.Scan(rules, report)),
                ("Проверка прокси", () => ProxyScanner.Scan(rules, report)),
                ("Проверка оверлеев", () => OverlayScanner.Scan(rules, report))
            };

            report.GameRunning = rules.GameProcessNames
                .Any(name => System.Diagnostics.Process.GetProcessesByName(name).Length > 0);

            for (var i = 0; i < scans.Length; i++)
            {
                var scan = scans[i];
                var percent = (i + 1) * 100 / scans.Length;
                SetState(scan.Label + "…", Color.FromArgb(190, 196, 205));
                await Task.Run(() =>
                {
                    try { scan.Run(); }
                    catch (Exception ex)
                    {
                        ScannerHelpers.AddScanError(report, $"Ошибка этапа '{scan.Label}': {ex.Message}");
                    }
                });
                _progress.Value = percent;
            }

            report.Status = report.Found.Count == 0
                ? "clean"
                : report.Found.Any(f => f.Severity == "high") ? "suspicious" : "review";
            report.Time = DateTime.UtcNow;

            ShowResult(report);
            await SendReportAsync(rules, report);
        }
        catch (Exception ex)
        {
            ScannerHelpers.AddScanError(report, ex.Message);
            SetState("Проверка завершена с ошибкой", Color.FromArgb(255, 99, 99));
            _results.Items.Add(ex.Message);
        }
        finally
        {
            _startButton.Enabled = true;
            _startButton.Text = "Повторить проверку";
            _running = false;
        }
    }

    private void ShowResult(CheckReport report)
    {
        if (report.Status == "clean")
            SetState("Проверка завершена: чисто", Color.FromArgb(70, 200, 130));
        else if (report.Status == "suspicious")
            SetState("Проверка завершена: подозрительно", Color.FromArgb(255, 99, 99));
        else
            SetState("Проверка завершена: требуется проверка", Color.FromArgb(255, 190, 80));

        if (report.Found.Count == 0)
            _results.Items.Add("Подозрительных совпадений не найдено.");
        else
            foreach (var finding in report.Found)
                _results.Items.Add($"[{finding.Severity.ToUpperInvariant()}] {finding.Type}: {finding.Name}");

        foreach (var error in report.ScanErrors)
            _results.Items.Add($"[ERROR] {error}");
    }

    private async Task SendReportAsync(Rules rules, CheckReport report)
    {
        var apiUrl = rules.ReportApiUrl;
        var token = Environment.GetEnvironmentVariable("REPORT_API_TOKEN");

        if (string.IsNullOrWhiteSpace(apiUrl) || string.IsNullOrWhiteSpace(token))
        {
            _results.Items.Add("[WARN] Отчёт не отправлен: не настроен API URL или токен.");
            return;
        }

        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            using var content = new StringContent(
                JsonSerializer.Serialize(report, _jsonOptions), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(apiUrl, content);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new Exception($"{(int)response.StatusCode}: {body}");
            }

            _results.Items.Add("Отчёт отправлен проверяющему.");
        }
        catch (Exception ex)
        {
            _results.Items.Add($"[ERROR] Не удалось отправить отчёт: {ex.Message}");
        }
    }

    private void SetState(string text, Color color)
    {
        if (InvokeRequired)
        {
            BeginInvoke(() =>
            {
                _stateLabel.Text = text;
                _stateLabel.ForeColor = color;
            });
            return;
        }

        _stateLabel.Text = text;
        _stateLabel.ForeColor = color;
    }
}