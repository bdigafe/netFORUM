using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

namespace Owin.Security.Providers.netForum
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class netForumAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="netForumAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">netForum Access token</param>
        public netForumAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "customer_key");
            Name = TryGetValue(user, "sort_name");
            Email = TryGetValue(user, "email");
            UserData = JsonConvert.SerializeObject(user);
        }

        /// <summary>
        /// The email address of the user
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the netForum user obtained from the endpoint https://netForumSite/xweb/secure/rest/ws/token_info
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the netForum OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the netForum access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the netForum user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// The netFORUM customer sort name
        /// </summary>
        public string Name { get; private set; }


        /// <summary>
        /// Json-string of user information
        /// </summary>
        public string UserData { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}