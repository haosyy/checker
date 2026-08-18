namespace AntiCheat.Client.Models;

public sealed class IndicatorDatabase
{
    public string Version { get; set; } = "1.0.0";
    public List<Indicator> Indicators { get; set; } = [];
}

public sealed class Indicator
{
    public string Id { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Severity { get; set; } = "low";
    public string Source { get; set; } = "";
    public string Reason { get; set; } = "";
}
