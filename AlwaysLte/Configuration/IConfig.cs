namespace AlwaysLte.Configuration
{
    public interface IConfig
    {
        string Login { get; }
        string Password { get; }
        string BaseUrl { get; }
        int MonitorIntervalSeconds { get; }
    }
}