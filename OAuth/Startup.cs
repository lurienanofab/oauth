using LNF;
using LNF.Impl.DependencyInjection.Web;
using Owin;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Routing;

namespace OAuth
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);

            // Code that runs on application startup
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
        }
    }
}