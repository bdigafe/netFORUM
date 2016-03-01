using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.netForum
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class netForumReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public netForumReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket) : base(context, ticket)
        {
        }
    }
}