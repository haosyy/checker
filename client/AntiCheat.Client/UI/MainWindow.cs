using System.Text;
using System.Text.Json;
using AntiCheat.Client.Models;
using AntiCheat.Client.Services;

namespace AntiCheat.Client.UI;

public sealed class MainWindow : Form
{
    private const string CheckerVersion = "2.1.0";
    private readonly Panel _titleBar = new();
    private readonly Label _titleLabel = new();
    private readonly Button _closeButton = new();
    private readonly Label _stateLabel = new();
    private readonly ProgressBar _progress = new();
    private readonly ListBox _results = new();
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };
    private readonly JsonSerializerOptions _reportJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };
    private bool _dragging;
    private Point _dragOffset;

    public MainWindow()
    {
        InitializeUi();
        Shown += async (_, _) => await RunCheckAsync();
    }

    private void InitializeUi()
    {
        Text = "Cheat Checker";
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(420, 320);
        FormBorderStyle = FormBorderStyle.None;
        MaximizeBox = false;
        MinimizeBox = false;
        TopMost = true;
        BackColor = Color.FromArgb(18, 18, 20);
        ShowInTaskbar = true;
        _titleBar.Height = 34;
        _titleBar.Dock = DockStyle.Top;
        _titleBar.BackColor = Color.FromArgb(10, 10, 12);
        _titleBar.MouseDown += TitleBarMouseDown;
        _titleBar.MouseMove += TitleBarMouseMove;
        _titleBar.MouseUp += TitleBarMouseUp;
        _titleLabel.Text = "Cheat Checker";
        _titleLabel.Font = new Font("Segoe UI", 9F);
        _titleLabel.ForeColor = Color.FromArgb(190, 190, 195);
        _titleLabel.AutoSize = true;
        _titleLabel.Location = new Point(14, 9);
        _titleLabel.MouseDown += TitleBarMouseDown;
        _titleLabel.MouseMove += TitleBarMouseMove;
        _titleLabel.MouseUp += TitleBarMouseUp;
        _closeButton.Text = "✕";
        _closeButton.Font = new Font("Segoe UI", 9F);
        _closeButton.ForeColor = Color.FromArgb(170, 170, 175);
        _closeButton.BackColor = Color.FromArgb(10, 10, 12);
        _closeButton.FlatStyle = FlatStyle.Flat;
        _closeButton.FlatAppearance.BorderSize = 0;
        _closeButton.Size = new Size(38, 34);
        _closeButton.Dock = DockStyle.Right;
        _closeButton.Cursor = Cursors.Hand;
        _closeButton.Click += (_, _) => Close();
        _stateLabel.Text = "Подготовка проверки…";
        _stateLabel.Font = new Font("Segoe UI", 11F, FontStyle.Bold);
        _stateLabel.ForeColor = Color.White;
        _stateLabel.AutoSize = true;
        _stateLabel.Location = new Point(28, 68);
        _progress.Style = ProgressBarStyle.Continuous;
        _progress.Size = new Size(364, 5);
        _progress.Location = new Point(28, 104);
        _results.Font = new Font("Segoe UI", 9F);
        _results.BackColor = Color.FromArgb(24, 24, 27);
        _results.ForeColor = Color.FromArgb(215, 215, 220);
        _results.BorderStyle = BorderStyle.None;
        _results.Size = new Size(364, 170);
        _results.Location = new Point(28, 126);
        _results.HorizontalScrollbar = true;
        _titleBar.Controls.Add(_titleLabel);
        _titleBar.Controls.Add(_closeButton);
        Controls.Add(_results);
        Controls.Add(_progress);
        Controls.Add(_stateLabel);
        Controls.Add(_titleBar);
    }

    private void TitleBarMouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left) return;
        _dragging = true;
        _dragOffset = new Point(e.X, e.Y);
    }

    private void TitleBarMouseMove(object? sender, MouseEventArgs e)
    {
        if (!_dragging) return;
        var screenPoint = PointToScreen(new Point(e.X, e.Y));
        Location = new Point(screenPoint.X - _dragOffset.X, screenPoint.Y - _dragOffset.Y);
    }

    private void TitleBarMouseUp(object? sender, MouseEventArgs e)
    {
        _dragging = false;
    }

    private async Task RunCheckAsync()
    {
        _results.Items.Clear();
        _progress.Value = 0;
        SetState("Проверка запущена", Color.White);
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
                ("Процессы", () => ProcessScanner.Scan(rules, report)),
                ("Папки", () => DirectoryScanner.Scan(rules, report)),
                ("Автозапуск", () => StartupScanner.Scan(rules, report)),
                ("HOSTS", () => HostsScanner.Scan(rules, report)),
                ("Файлы", () => FileScanner.Scan(rules, report)),
                ("Игровые файлы", () => GameIntegrityScanner.Scan(rules, report)),
                ("Модули игры", () => ModuleScanner.Scan(rules, report)),
                ("Службы", () => ServiceScanner.Scan(rules, report)),
                ("Прокси", () => ProxyScanner.Scan(rules, report)),
                ("Оверлеи", () => OverlayScanner.Scan(rules, report))
            };
            report.GameRunning = rules.GameProcessNames
                .Any(name => System.Diagnostics.Process.GetProcessesByName(name).Length > 0);
            for (var i = 0; i < scans.Length; i++)
            {
                var scan = scans[i];
                SetState(scan.Label, Color.FromArgb(200, 200, 205));
                await Task.Run(() =>
                {
                    try { scan.Run(); }
                    catch (Exception ex)
                    {
                        ScannerHelpers.AddScanError(report, $"Ошибка этапа '{scan.Label}': {ex.Message}");
                    }
                });
                _progress.Value = (i + 1) * 100 / scans.Length;
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
            SetState("Ошибка проверки", Color.FromArgb(255, 105, 105));
            _results.Items.Add(ex.Message);
        }
    }

    private void ShowResult(CheckReport report)
    {
        if (report.Status == "clean")
            SetState("Чисто", Color.FromArgb(80, 210, 140));
        else if (report.Status == "suspicious")
            SetState("Подозрительно", Color.FromArgb(255, 105, 105));
        else
            SetState("Требует проверки", Color.FromArgb(255, 190, 90));
        if (report.Found.Count == 0)
            _results.Items.Add("Подозрительных совпадений не найдено.");
        else
            foreach (var finding in report.Found)
                _results.Items.Add($"{finding.Type}: {finding.Name}");
        foreach (var error in report.ScanErrors)
            _results.Items.Add($"Ошибка: {error}");
    }

    private async Task SendReportAsync(Rules rules, CheckReport report)
    {
        var apiUrl = rules.ReportApiUrl;
        var token = Environment.GetEnvironmentVariable("REPORT_API_TOKEN");
        if (string.IsNullOrWhiteSpace(apiUrl))
        {
            _results.Items.Add("Отчёт не отправлен: reportApiUrl пуст в rules.json.");
            return;
        }
        if (string.IsNullOrWhiteSpace(token))
        {
            _results.Items.Add("Отчёт не отправлен: процесс не получил REPORT_API_TOKEN.");
            return;
        }
        try
        {
            using var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            using var content = new StringContent(
                JsonSerializer.Serialize(report, _reportJsonOptions), Encoding.UTF8, "application/json");
            using var response = await client.PostAsync(apiUrl, content);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new Exception($"{(int)response.StatusCode}: {body}");
            }
            _results.Items.Add("Отчёт отправлен.");
        }
        catch (Exception ex)
        {
            _results.Items.Add($"Не удалось отправить отчёт: {ex.Message}");
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
