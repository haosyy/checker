using System.ServiceProcess;
using AntiCheat.Client.Models;

namespace AntiCheat.Client.Services;

public static class ServiceScanner
{
    public static void Scan(Rules rules, CheckReport report)
    {
        if (rules.BlockedServiceNames.Count == 0) return;

        foreach (var service in ServiceController.GetServices())
        {
            try
            {
                var match = rules.BlockedServiceNames.FirstOrDefault(name =>
                    service.ServiceName.Contains(name, StringComparison.OrdinalIgnoreCase) ||
                    service.DisplayName.Contains(name, StringComparison.OrdinalIgnoreCase));

                if (match == null) continue;

                report.Found.Add(new Finding
                {
                    Type = "service",
                    Name = service.ServiceName,
                    Description = $"Служба совпала с правилом '{match}'.",
                    Severity = "review",
                    Location = service.DisplayName
                });
            }
            finally
            {
                service.Dispose();
            }
        }
    }
}