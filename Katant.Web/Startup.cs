using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Katant.Web.Startup))]
namespace Katant.Web
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
