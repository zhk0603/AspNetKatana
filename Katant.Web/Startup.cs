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

            app.Map("/home/index", map => { map.Run(contect => contect.Response.WriteAsync("owin context")); });
        }
    }
}
