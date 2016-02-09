using System;
using System.Configuration;

namespace AlwaysLte.Configuration
{
    public class Config : IConfig
    {
        public string Login
        {
            get { return ConfigurationManager.AppSettings["login"]; }
        }

        public string Password
        {
            get { return ConfigurationManager.AppSettings["password"]; }
        }

        public string BaseUrl
        {
            get { return ConfigurationManager.AppSettings["baseUrl"]; }
        }

        public int MonitorIntervalSeconds
        {
            get { return Int32.Parse(ConfigurationManager.AppSettings["monitorIntervalSeconds"]); }
        }
    }
}