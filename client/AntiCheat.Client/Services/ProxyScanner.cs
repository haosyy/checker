using Microsoft.Win32;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ProxyScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (rules.ProxyBlockedDomains.Count == 0) return;

        using var key = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
        if (key == null) return;

        var enabled = key.GetValue("ProxyEnable");
        var server = key.GetValue("ProxyServer") as string;
        if (enabled is not int value || value != 1 || string.IsNullOrWhiteSpace(server)) return;

        var match = rules.ProxyBlockedDomains.FirstOrDefault(domain =>
            server.Contains(domain, StringComparison.OrdinalIgnoreCase));
        if (match == null) return;

        report.Found.Add(new Finding
        {
            Type = "proxy",
            Name = server,
            Description = $"Системный прокси содержит домен из правила '{match}'.",
            Severity = "review",
            Location = "HKCU\\...\\Internet Settings"
        });
    }
}