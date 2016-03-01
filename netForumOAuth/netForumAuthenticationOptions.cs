using System;
using System.Net.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace Owin.Security.Providers.netForum
{
    public class netForumAuthenticationOptions : AuthenticationOptions
    {
        /// <summary>
        ///     Gets or sets the a pinned certificate validator to use to validate the endpoints used
        ///     in back channel communications belong to netForum
        /// </summary>
        /// <value>
        ///     The pinned certificate validator.
        /// </value>
        /// <remarks>
        ///     If this property is null then the default certificate checks are performed,
        ///     validating the subject name and if the signing chain is a trusted party.
        /// </remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        ///     The HttpMessageHandler used to communicate withnetForum.
        ///     This cannot be set at the same time as BackchannelCertificateValidator unless the value
        ///     can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        ///     Gets or sets timeout value in milliseconds for back channel communications with netForum.
        /// </summary>
        /// <value>
        ///     The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        ///     The request path within the application's base path where the user-agent will be returned.
        ///     The middleware will process this request when it arrives.
        ///     Default value is "/signin-netforum".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        ///     Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        ///     Gets or sets the netForum site
        /// </summary>
        public string netForumSite { get; set; }

        /// <summary>
        ///     Gets or sets the netForum eWeb site code
        /// </summary>
        public string netForumeWebSiteCode { get; set; }

        /// <summary>
        ///     Gets or sets the netForum supplied Client ID
        /// </summary>
        public string xWebUserName { get; set; }

        /// <summary>
        ///     Gets or sets the netForum xWeb User Password
        /// </summary>
        public string xWebUserPassword { get; set; }

        /// <summary>
        ///     Gets or sets the path of the netForum xWeb Rest resource to get the information of the authenticated user 
        /// </summary>
        public string xWebRestGetUserPath { get; set; }


        /// <summary>
        ///     Gets or sets the <see cref="InetForumAuthenticationProvider" /> used in the authentication events
        /// </summary>
        public InetForumAuthenticationProvider Provider { get; set; }

        /// <summary>
        ///     Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user
        ///     <see cref="System.Security.Claims.ClaimsIdentity" />.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        ///     Initializes a new <see cref="netForumAuthenticationOptions" />
        /// </summary>
        public netForumAuthenticationOptions()
            : base("netForum")
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-netforum");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
        }
    }
}