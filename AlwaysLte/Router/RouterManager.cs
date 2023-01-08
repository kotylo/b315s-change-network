using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using AlwaysLte.Configuration;
using Jurassic;
using NLog;
using PostEmDown.WebsiteManager;
using PostEmDown.WebsiteManager.Post;

namespace AlwaysLte.Router
{
    public class RouterManager
    {
        private IConfig _config;
        private ILogger _logger;

        private string _homePageUrl;
        private string _publicRsaKeyUrl;
        private string _loginPageUrl;
        private string _networkChangeUrl;
        private string _rebootUrl;
        private string _connectionStatusUrl;

        private string _encpubkeyN;
        private string _encpubkeyE;
        private string _firstCsrf;
        private DateTime _runAtDay;
        private bool hasPublicKeys = false;

        private Encoding _encoding = ASCIIEncoding.ASCII;
        private Jurassic.ScriptEngine _engine;
        private IWebSite _website;

        public RouterManager()
        {
            _logger = LogManager.GetCurrentClassLogger();
            _logger.Trace("Creating RouteManager");
            
            _config = new Config();

            _homePageUrl = _config.BaseUrl + "/html/home.html";
            _publicRsaKeyUrl = _config.BaseUrl + "/api/webserver/publickey";
            _loginPageUrl = _config.BaseUrl + "/api/user/login";
            _networkChangeUrl = _config.BaseUrl + "/api/net/net-mode";
            _rebootUrl = _config.BaseUrl + "/api/device/control";
            _connectionStatusUrl = _config.BaseUrl + "/api/monitoring/status";

            _logger.Trace("Initializing JS engine");
            InitJsEngine();
            _logger.Trace("Initializing JS engine... Done");

            _website = new WebSite();

            if (_config.RebootAt.HasValue)
            {
                _runAtDay = FindNextRunDay();
            }

            _logger.Trace("Creating RouteManager... Done");

            IsInitialized = true;
        }

        public bool IsInitialized { get; private set; }
        public bool Rebooted { get; internal set; }

        public DateTime? RebootAtDateTime => _config.RebootAt.HasValue ? _runAtDay + _config.RebootAt.Value : (DateTime?) null;

        private DateTime FindNextRunDay()
        {
            return DateTime.Now > DateTime.Today + _config.RebootAt.Value ? DateTime.Today.AddDays(1) : DateTime.Today;
        }

        private void InitJsEngine()
        {
            _engine = new ScriptEngine();
            var location = new Location(_engine, _homePageUrl);
            _engine.Global.SetPropertyValue("location", location, true);
            _engine.SetGlobalValue("window", _engine.Global);
            _engine.SetGlobalValue("console", new Jurassic.Library.FirebugConsole(_engine));
            _engine.EnableDebugging = true;
            _engine.ForceStrictMode = false;
        }

        public string EncodeData(string data)
        {
            if (!hasPublicKeys)
            {
                throw new NotSupportedException("You need to load keys first");
            }

            var rsa = new RsaEncryptor(_encpubkeyN, _encpubkeyE);
            var encString = Convert.ToBase64String(_encoding.GetBytes(data));
            var num = (double)encString.Length / 245;
            var resTotal = string.Empty;
            for (int i = 0; i < num; i++)
            {
                var index = i * 245;
                var length = 245;
                if (index + 245 > encString.Length)
                {
                    length = encString.Length - index;
                }
                var encData = encString.Substring(index, length);
                var res = rsa.EncryptData(encData);
                resTotal += res;
            }
            return resTotal;
        }

        public string GetConnectionType()
        {
            LoadCookiesIfNeeded();
            var status = _website.LoadPage(_connectionStatusUrl);
            var match = Regex.Match(status, "<CurrentNetworkType>(?<mode>\\d+)</CurrentNetworkType>");
            if (match.Success)
            {
                var mode = match.Groups["mode"].Value;
                return mode;
            }

            if (status.Contains("timed out"))
            {
                _logger.Warn("Response from server timed out.");
            }
            else if (status.Contains("125002"))
            {
                _logger.Warn("Probably router rebooted or Session Lost. Trying to load home page to get cookies again... ");
                
                hasPublicKeys = false;
                _website.LoadPage(_homePageUrl);
            }
            else
            {
                _logger.Warn("Couldn't get proper connection type (<CurrentNetworkType> tag). Response was: {0}", status);
            }
            
            return string.Empty;
        }

        private void LoadCookiesIfNeeded(bool force = false)
        {
            var cookie = _website.GetCookies().Get("SessionID");
            if (cookie == null || force)
            {
                var rootPage = _website.LoadPage(_config.BaseUrl);
                var loadedPage = _website.LoadPage(_homePageUrl);
                GetPublicKeys();
            }
        }

        public bool Login()
        {
            GetPublicKeys();

            var result = DoLogin();
            return result;
        }

        private bool DoLogin()
        {
            _logger.Debug("Login");

            LoadHomePageWithCsrf();

            _engine.Evaluate(string.Format("var name = '{0}';", _config.Login));
            _engine.Evaluate(string.Format("var password = '{0}';", _config.Password));
            _engine.Evaluate(string.Format("var g_password_type = '4';"));

            var jsResult =
                _engine.Evaluate(
                    "psd = base64encode(SHA256(name + base64encode(SHA256(password)) + g_requestVerificationToken[0]));");

            //_engine.Evaluate("console.log(psd);");

            var requestJs = @"
var request = {
Username: name,
Password: psd,
password_type: g_password_type
};
var xmlDate = object2xml('request', request);";

            _engine.Evaluate(requestJs);

            var data = _engine.Evaluate("xmlDate").ToString();
            var postData = new PostData(data)
                .AddHeader("__RequestVerificationToken", _firstCsrf);

            var postResult = _website.PostPage(_loginPageUrl, postData);
            if (postResult.Contains("OK"))
            {
                _logger.Debug("Login... Done!");
                return true;
            }

            var errorMessage = ProcessErrorMessages(postResult);
            _logger.Error("Logging in failed: {0}", errorMessage);

            return false;
        }

        internal bool ShouldReboot()
        {
            if (_config.RebootAt == null)
            {
                return false;
            }

            if (DateTime.Now > RebootAtDateTime.Value && DateTime.Now <= RebootAtDateTime.Value.AddSeconds(_config.MonitorIntervalSeconds*2))
            {
                _runAtDay = DateTime.Today.AddDays(1);
                return true;
            }
            return false;
        }

        private string ProcessErrorMessages(string postResult)
        {
            if (postResult.Contains("108006"))
            {
                return "Either username or password was incorrect. Check them in App.config";
            }
            if (postResult.Contains("100008"))
            {
                return "Some unknown error 100008 happened. Not sure why this happens yet. The application will probably try to login and fail all the time, until restarted.";
            }
            return postResult;
        }

        private void GetPublicKeys()
        {
            if (hasPublicKeys)
            {
                _logger.Trace("We already have public keys, not loading them.");
                return;
            }

            _logger.Info("Getting PublicKeys");
            var rsaPage = _website.LoadPage(_publicRsaKeyUrl);
            var rsaXmlObject = XDocument.Parse(rsaPage);
            var rsaXmlResponse = rsaXmlObject.Element("response");
            if (rsaXmlResponse == null)
            {
                _logger.Warn($"Got wrong xml while getting public keys: {rsaPage}. Try loading the page in browser manually?");
            }
            _encpubkeyE = rsaXmlResponse.Element("encpubkeye").Value;
            _encpubkeyN = rsaXmlResponse.Element("encpubkeyn").Value;
            _logger.Trace("Public Key E: {0}, N: {1}", _encpubkeyE, _encpubkeyN.Remove(4) + "..." + _encpubkeyN.Substring(_encpubkeyN.Length-4));

            Jurassic.ScriptSource scriptSource = new FileScriptSource("js/main.js");
            var jsResult = _engine.Evaluate(scriptSource);

            _engine.Evaluate(string.Format("g_encPublickey.e = '{0}'; g_encPublickey.n = '{1}';", _encpubkeyE, _encpubkeyN));
            
            LoadHomePageWithCsrf();

            hasPublicKeys = true;
            _logger.Info("Getting PublicKeys... Done!");
        }

        private void LoadHomePageWithCsrf()
        {
            var result = _website.LoadPage(_homePageUrl);
            var matches = Regex.Matches(result, "name=\"csrf_token\" content=\"(?<data>[^\"]*)\"", RegexOptions.Singleline);
            _firstCsrf = string.Empty;
            string secondCsrf = string.Empty;
            if (matches.Count == 2)
            {
                _firstCsrf = matches[0].Groups["data"].Value;
                secondCsrf = matches[1].Groups["data"].Value;

                _engine.Evaluate(string.Format("g_requestVerificationToken = ['{0}', '{1}']", _firstCsrf, secondCsrf));
            }
        }

        public class ConnectionSwitchType
        {
            public static string LTE = "03";
            public static string Auto = "00";

            public static string Parse(string numeric)
            {
                if (numeric == LTE)
                {
                    return "LTE";
                }
                if (numeric == Auto)
                {
                    return "Auto";
                }
                return "Unknown";
            }
        }

        public class ConnectionStatusType
        {
            public static string LTE = "19";
            public static string ThreeG = "9";
            public static string NoService = "0";

            public static string Parse(string connectionTypeNumber)
            {
                if (ConnectionStatusType.LTE == connectionTypeNumber)
                {
                    return "LTE";
                }
                if (ConnectionStatusType.ThreeG == connectionTypeNumber)
                {
                    return "3G";
                }
                if (ConnectionStatusType.NoService == connectionTypeNumber)
                {
                    return "No Service";
                }
                return string.Format("Unknown (#{0})", connectionTypeNumber);
            }
        }

        /// <summary>
        /// Switches to LTE or 3G
        /// </summary>
        /// <param name="connectionType">Numeric value of the dropdown field in the Web UI</param>
        /// <returns>true if OK was found in response</returns>
        public bool SwitchConnectionType(string connectionType)
        {
            LoadHomePageWithCsrf();

            string verboseType = ConnectionSwitchType.Parse(connectionType);
            _logger.Info("Switching to {0}", verboseType);
            var dataToSend =
                string.Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><NetworkMode>{0}</NetworkMode><NetworkBand>3FFFFFFF</NetworkBand><LTEBand>7FFFFFFFFFFFFFFF</LTEBand></request>", connectionType);
            var result = _website.PostPage(_networkChangeUrl, new PostData(dataToSend).AddHeader("__RequestVerificationToken", _firstCsrf));
            if (result.Contains("OK"))
            {
                _logger.Info("Switching to {0}... OK!", verboseType);
                return true;
            }

            _logger.Error("Switching to {0}... Failed!", verboseType);
            _logger.Error("Response was: {0}", result);

            return false;
        }

        /// <summary>
        /// Reboots router
        /// </summary>
        internal bool Reboot()
        {
            LoadHomePageWithCsrf();

            _logger.Info("Rebooting");
            var dataToSend = string.Format("<?xml version=\"1.0\" encoding=\"UTF-8\"?><request><Control>1</Control></request>");
            var result = _website.PostPage(_rebootUrl, new PostData(dataToSend).AddHeader("__RequestVerificationToken", _firstCsrf));
            if (result.Contains("OK"))
            {
                _logger.Info("Rebooting... Done!");
                Rebooted = true;
                return true;
            }
            return false;
        }
    }
}