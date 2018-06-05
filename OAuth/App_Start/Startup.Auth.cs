using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace OAuth
{
    public partial class Startup
    {
        public static OAuthAuthorizationServerOptions OAuthOptions { get; private set; }

        static Startup()
        {
            OAuthOptions = new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/authorize"),
                TokenEndpointPath = new PathString("/token"),
                ApplicationCanDisplayErrors = true,
                Provider = new OAuthProvider(),
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(2),
                AllowInsecureHttp = AllowInsecure()
            };
        }

        public void ConfigureAuth(IAppBuilder app)
        {
            // Enable Application Sign In Cookie
            //app.UseCookieAuthentication(new CookieAuthenticationOptions
            //{
            //    AuthenticationType = "Application",
            //    AuthenticationMode = AuthenticationMode.Passive,
            //    LoginPath = new PathString("/login"),
            //    LogoutPath = new PathString("/logout"),
            //    SlidingExpiration = true
            //});

            // Also use oauth2 bearer authentication to authorize api requests
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());

            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
            {
                AuthorizeEndpointPath = new PathString("/authorize"),
                TokenEndpointPath = new PathString("/token"),
                ApplicationCanDisplayErrors = true,
                AllowInsecureHttp = AllowInsecure(),
                AccessTokenExpireTimeSpan = TimeSpan.FromDays(90),

                // Authorization server provider which controls the lifecycle of Authorization Server
                Provider = new OAuthProvider(),

                // Authorization code provider which creates and receives the authorization code.
                AuthorizationCodeProvider = new OAuthAuthorizationCodeProvider(),

                // Refresh token provider which creates and receives refresh token.
                RefreshTokenProvider = new OAuthRefreshTokenProvider(),
            });
        }

        private static bool AllowInsecure()
        {
#if DEBUG
            return true;
#else
            return false;
#endif
        }
    }
}