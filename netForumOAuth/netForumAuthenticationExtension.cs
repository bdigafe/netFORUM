using System;

namespace Owin.Security.Providers.netForum
{
    public static class netForumAuthenticationExtensions
    {
        public static IAppBuilder UsenetForumAuthentication(this IAppBuilder app,
           netForumAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");

            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(netForumAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UsenetForumAuthentication(this IAppBuilder app, string xWebUserId, string xWebPassword, string SiteUrl)
        {
            return app.UsenetForumAuthentication(new netForumAuthenticationOptions
            {
                xWebUserName = xWebUserId,
                xWebUserPassword = xWebPassword,
                netForumSite = SiteUrl
            });
        }
    }
}
