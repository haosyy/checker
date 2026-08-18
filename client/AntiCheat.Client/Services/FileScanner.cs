using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class FileScanner
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".js", ".vbs", ".msi"
    };

    private static readonly HashSet<string> DocumentLikeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".zip", ".rar"
    };

    public static void Scan(Rules rules, CheckReport report)
    {
        var keywords = rules.SuspiciousKeywords.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
        var extensions = new HashSet<string>(rules.ScanFileExtensions.Where(x => !string.IsNullOrWhiteSpace(x)), StringComparer.OrdinalIgnoreCase);

        foreach (var rootTemplate in rules.ScanRoots.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            var root = ScannerHelpers.ExpandPath(rootTemplate);
            if (!Directory.Exists(root)) continue;

            try
            {
                foreach (var file in EnumerateFilesSafely(root))
                {
                    if (extensions.Count > 0 && !extensions.Contains(Path.GetExtension(file))) continue;

                    var name = Path.GetFileName(file);
                    var keyword = ScannerHelpers.FirstKeywordMatch(name, keywords);
                    if (keyword is not null)
                    {
                        ScannerHelpers.AddFinding(report, "file_name", name,
                            $"Имя файла содержит ключевое слово правила: {keyword}.", "low", file);
                    }

                    if (HasDoubleExtension(name))
                    {
                        ScannerHelpers.AddFinding(report, "double_extension", name,
                            "Исполняемый файл имеет двойное расширение, похожее на маскировку имени.", "low", file);
                    }
                }
            }
            catch (Exception ex)
            {
                ScannerHelpers.AddScanError(report, $"Не удалось полностью проверить {root}: {ex.Message}");
            }
        }
    }

    private static IEnumerable<string> EnumerateFilesSafely(string root)
    {
        var pending = new Stack<string>();
        pending.Push(root);

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(current); }
            catch { continue; }
            foreach (var file in files) yield return file;

            IEnumerable<string> directories;
            try { directories = Directory.EnumerateDirectories(current); }
            catch { continue; }

            foreach (var directory in directories)
            {
                try
                {
                    var attributes = File.GetAttributes(directory);
                    if ((attributes & FileAttributes.ReparsePoint) != 0) continue;
                    pending.Push(directory);
                }
                catch { }
            }
        }
    }

    private static bool HasDoubleExtension(string fileName)
    {
        var finalExtension = Path.GetExtension(fileName);
        if (!ExecutableExtensions.Contains(finalExtension)) return false;
        var withoutFinal = fileName[..^finalExtension.Length];
        var previousExtension = Path.GetExtension(withoutFinal);
        return DocumentLikeExtensions.Contains(previousExtension);
    }
}
