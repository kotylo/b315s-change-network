using Jurassic;
using Jurassic.Library;

namespace AlwaysLte.Router
{
    public class Location : ObjectInstance
    {
        public Location(ScriptEngine engine, string href)
            : base(engine)
        {
            this["href"] = href;
            this["search"] = "";
        }
    }
}