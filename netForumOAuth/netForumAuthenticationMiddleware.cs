using System;
using System.Globalization;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;


namespace Owin.Security.Providers.netForum
{
    public class netForumAuthenticationMiddleware : AuthenticationMiddleware<netForumAuthenticationOptions>
    {
        private readonly HttpClient httpClient;
        private readonly ILogger logger;

        public netForumAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            netForumAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.xWebUserName))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided."));

            if (String.IsNullOrWhiteSpace(Options.xWebUserPassword))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided."));

            if (String.IsNullOrWhiteSpace(Options.netForumSite))
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, "The '{0}' option must be provided."));

            logger = app.CreateLogger<netForumAuthenticationMiddleware>();

            if (Options.Provider == null)
                Options.Provider = new netForumAuthenticationProvider();

            if (Options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(
                    typeof(netForumAuthenticationMiddleware).FullName,
                    Options.AuthenticationType, "v1");
                Options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (String.IsNullOrEmpty(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();

            httpClient = new HttpClient(ResolveHttpMessageHandler(Options))
            {
                Timeout = Options.BackchannelTimeout,
                MaxResponseContentBufferSize = 1024 * 1024 * 10
            };
        }

        /// <summary>
        ///     Provides the <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> object for processing
        ///     authentication-related requests.
        /// </summary>
        /// <returns>
        ///     An <see cref="T:Microsoft.Owin.Security.Infrastructure.AuthenticationHandler" /> configured with the
        ///     <see cref="T:Owin.Security.Providers.netForum.netForumAuthenticationOptions" /> supplied to the constructor.
        /// </returns>
        protected override AuthenticationHandler<netForumAuthenticationOptions> CreateHandler()
        {
            return new netForumAuthenticationHandler(httpClient, logger);
        }

        private HttpMessageHandler ResolveHttpMessageHandler(netForumAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            // If they provided a validator, apply it or fail.
            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("An ICertificateValidator cannot be specified at the same time as an HttpMessageHandler unless it is a WebRequestHandler.");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }
    }
}