using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using AlwaysLte.Configuration;
using AlwaysLte.Router;
using Jurassic;
using Jurassic.Library;
using NLog;

namespace AlwaysLte
{
    class Program
    {
        public class log4javascript : ObjectInstance
        {
            public log4javascript(ScriptEngine engine)
                : base(engine.Global)
            {
                this.PopulateFunctions();
            }

            [JSFunction(Name = "getNullLogger")]
            public static object GetNullLogger()
            {
                return new object();
            }
        }

        public class nullLogger : ObjectInstance
        {
            public nullLogger(ScriptEngine engine) : base(engine.Global)
            {
                this.PopulateFunctions();
            }

            [JSFunction(Name = "setLevel")]
            public static void SetLevel(string level)
            {
            }
        }

        static void Main(string[] args)
        {
            var logger = NLog.LogManager.GetCurrentClassLogger();
            var configuration = new Config();

            logger.Info("Starting");
            logger.Trace("Seeking interval is {0} seconds in config", configuration.MonitorIntervalSeconds);

            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
            CancellationToken ct = cancellationTokenSource.Token;
            
            // Start watching periodically
            Task.Factory.StartNew(() =>
            {
                RouterManager rm = new RouterManager();

                var isInitialized = false;
                Stopwatch sw = new Stopwatch();
                sw.Start();

                while (true)
                {
                    try
                    {
                        if (ct.IsCancellationRequested)
                        {
                            logger.Trace("Requested cancellation. Exiting...");
                            break;
                        }
                        Thread.Sleep(500);

                        if (sw.Elapsed.Seconds > configuration.MonitorIntervalSeconds || !isInitialized)
                        {
                            MonitorHealth(rm, isInitialized, logger);

                            // Reset and start timer for next cycle
                            sw.Reset();
                            sw.Start();
                            isInitialized = true;
                        }
                    }
                    catch (Exception e)
                    {
                        logger.Error("Unexpected error inside execution: " + e);
                    }
                }
            }, ct);

            logger.Info("Started");
            
            // User can press any key to exit now
            Console.ReadLine();
            cancellationTokenSource.Cancel();
            
            logger.Info("Exit completed.");
        }

        private static void MonitorHealth(RouterManager rm, bool isInitialized, ILogger logger)
        {
            string connectionType = rm.GetConnectionType();
            if (!isInitialized)
            {
                logger.Info("Current connection type is {0}. Monitoring...", RouterManager.ConnectionStatusType.Parse(connectionType));
            }
            if (connectionType != RouterManager.ConnectionStatusType.LTE)
            {
                logger.Info("Connection dropped to {0}. Switching.", RouterManager.ConnectionStatusType.Parse(connectionType));
                // Switch to LTE
                if (rm.Login())
                {
                    rm.SwitchConnectionType(RouterManager.ConnectionSwitchType.LTE);
                    rm.SwitchConnectionType(RouterManager.ConnectionSwitchType.Auto);
                }
                logger.Info("Switching... Done!");
            }
        }
    }
}
