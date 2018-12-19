using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Katant.Web.Models;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;

namespace Katant.Web
{
    public partial class Startup
    {
        // 有关配置身份验证的详细信息，请访问 https://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // 配置数据库上下文、用户管理器和登录管理器，以便为每个请求使用单个实例
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // 使应用程序可以使用 Cookie 来存储已登录用户的信息
            // 并使用 Cookie 来临时存储有关使用第三方登录提供程序登录的用户的信息
            // 配置登录 Cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // 当用户登录时使应用程序可以验证安全戳。
                    // 这是一项安全功能，当你更改密码或者向帐户添加外部登录名时，将使用此功能。
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            // 使应用程序可以在双重身份验证过程中验证第二因素时暂时存储用户信息。
            app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));

            // 使应用程序可以记住第二登录验证因素，例如电话或电子邮件。
            // 选中此选项后，登录过程中执行的第二个验证步骤将保存到你登录时所在的设备上。
            // 此选项类似于在登录时提供的“记住我”选项。
            app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);


            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true, // 允许不安全的 http 请求。
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(2),
                AuthorizeEndpointPath = new PathString("/oauth2/authorize"),
                TokenEndpointPath = new PathString("/oauth2/token"),
                Provider = new OAuthAuthorizationServerProvider
                {
                    OnValidateClientAuthentication = ValidateClientAuthentication,
                    OnValidateClientRedirectUri = ValidateClientRedirectUri,
                    OnGrantClientCredentials = GrantClientCredentials,
                    OnGrantResourceOwnerCredentials = GrantResourceOwnerCredentials
                },
                AuthorizationCodeProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateAuthenticationCode,
                    OnReceive = ReceiveAuthenticationCode
                },
                RefreshTokenProvider = new AuthenticationTokenProvider
                {
                    OnCreate = CreateRefreshToken,
                    OnReceive = ReceiveRefreshToken
                }
            });

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            // 取消注释以下行可允许使用第三方登录提供程序登录
            //app.UseMicrosoftAccountAuthentication(
            //    clientId: "",
            //    clientSecret: "");

        }



        #region OAuth Authorization Provider

        private Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId;
            string clientSecret;
            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id is not set");
                return Task.FromResult(0);
            }

            if (!string.IsNullOrEmpty(clientSecret))
            {
                context.OwinContext.Set("clientSecret", clientSecret);
            }

            if (clientSecret != null && (clientId.Equals("client1") && clientSecret.Equals("abc")))
            {
                context.Validated();
            }
            else
            {
                context.SetError("invalid_clientId", string.Format("Invalid client_id '{0}'", context.ClientId));
                return Task.FromResult(0);
            }

            return Task.FromResult(0);
        }

        private Task ValidateClientRedirectUri(OAuthValidateClientRedirectUriContext context)
        {
            if (context.ClientId == "client1")
            {
                context.Validated("/home");
            }

            return Task.FromResult(0);
        }

        private Task GrantClientCredentials(OAuthGrantClientCredentialsContext context)
        {
            if (context.ClientId == "client1")
            {
                var identity = new ClaimsIdentity(
                    new GenericIdentity(context.ClientId,
                        OAuthDefaults.AuthenticationType),
                    context.Scope.Select(x => new Claim("urn:oauth:scope", x)));
                context.Validated(identity);
            }

            return Task.FromResult(0);
        }

        private Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            if (context.UserName != "admin" || context.Password != "123456")
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
                return Task.FromResult(0);
            }
            var identity = new ClaimsIdentity(
                new GenericIdentity(context.UserName,
                    OAuthDefaults.AuthenticationType),
                context.Scope.Select(x => new Claim("urn:oauth:scope", x)));
            context.Validated(identity);

            return Task.FromResult(0);
        }

        #endregion

        #region Authorization Code Provider

        private readonly ConcurrentDictionary<string, string> _authenticationCodes =
            new ConcurrentDictionary<string, string>(StringComparer.Ordinal);


        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));
            _authenticationCodes[context.Token] = context.SerializeTicket();
        }

        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            if (_authenticationCodes.TryRemove(context.Token, out var value))
            {
                context.DeserializeTicket(value);
            }
        }

        #endregion

        #region Refresh Token Provider

        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            context.SetToken(context.SerializeTicket());
        }

        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            context.DeserializeTicket(context.Token);
        }

        #endregion
    }
}