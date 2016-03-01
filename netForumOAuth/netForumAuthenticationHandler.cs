using System;
using System.Text;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.netForum
{
    public class netForumAuthenticationHandler : AuthenticationHandler<netForumAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string eWebLoginRelativeUrl = "/eweb/DynamicPage.aspx?webcode=LoginRequired";
        private const string getApiTokenRelativeEndPoint = "/xweb/secure/rest/session";
        //private const string getIndividualInfoRelativeEndPoint = "/xweb/secure/rest/co/individual";
        private const string getIndividualInfoRelativeEndPoint = "/xweb/secure/rest/ws/token_info";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public netForumAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        #region Core authentication routines
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                #region Read eWeb authentication response: Token and CSFR (State)
                IReadableStringCollection query = Request.Query;
                string accessToken = GetParameterValue("token", query);
                string state = GetParameterValue("state", query);

                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null || accessToken == null)
                {
                    return null;
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, logger))
                {
                    return new AuthenticationTicket(null, properties);
                }
                #endregion

                #region Get Rest authorization code
                string szAuthenticateUrl = Options.netForumSite + getApiTokenRelativeEndPoint;
                HttpRequestMessage apiRequest = new HttpRequestMessage(HttpMethod.Post, szAuthenticateUrl);
                apiRequest.Headers.Add("User-Agent", "OWIN OAuth Provider");
                apiRequest.Headers.Add("Authorization", "Basic " + Base64(Options.xWebUserName + ":" + Options.xWebUserPassword));
                apiRequest.Headers.Add("Accept", "application/json");

                // Post request          
                HttpResponseMessage graphResponse = await httpClient.SendAsync(apiRequest);
                graphResponse.EnsureSuccessStatusCode();
                string response = await graphResponse.Content.ReadAsStringAsync();

                // Parse authentication response
                JObject authentication = JObject.Parse(response);
                string apiTokenType = authentication["token_type"].ToString();
                string apiToken = authentication["access_token"].ToString();
                #endregion

                #region Get Individual Info
                string szOptionRestUrl = string.IsNullOrEmpty(Options.xWebRestGetUserPath) ? getIndividualInfoRelativeEndPoint : Options.xWebRestGetUserPath;
                string szUserInfoUrl = Options.netForumSite + szOptionRestUrl + "/" + accessToken;
                HttpRequestMessage userRequest = new HttpRequestMessage(HttpMethod.Get, szUserInfoUrl);
                userRequest.Headers.Add("User-Agent", "OWIN OAuth Provider");
                userRequest.Headers.Add("Authorization", apiTokenType + " " + apiToken);
                userRequest.Headers.Add("Accept", "application/json");

                // Send GET request
                HttpResponseMessage userResponse = await httpClient.SendAsync(userRequest);
                userResponse.EnsureSuccessStatusCode();
                response = await userResponse.Content.ReadAsStringAsync();
                
                // Parse and process relevant nodes
                JObject userInfo = JObject.Parse(response);
                JObject user = new JObject();
                user.Add("access_token", accessToken);
                AddProperty("customer_key", userInfo, "customer_key", user);
                AddProperty("record_number", userInfo, "record_number", user);
                AddProperty("primary_email", userInfo, "email", user);
                AddProperty("first_name", userInfo, "first_name", user);
                AddProperty("last_name", userInfo, "last_name", user);
                AddProperty("sort_name", userInfo, "sort_name", user);
                AddProperty("member_flag", userInfo, "member_flag", user);
                AddProperty("organization_name", userInfo, "organization_name", user);
                #endregion

                #region Set authentication context
                var context = new netForumAuthenticatedContext(Context, user, accessToken);
                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
              
        
                // Add Claim: ID
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }

                // Add Claim: Name
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString, Options.AuthenticationType));
                }

                // Add Claim: Email
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString, Options.AuthenticationType));
                
                    // Store user object as UserData claim
                    context.Identity.AddClaim(new Claim(ClaimTypes.UserData, context.UserData, XmlSchemaString, Options.AuthenticationType));
                }

                context.Properties = properties;
                                
                await Options.Provider.Authenticated(context);
                #endregion

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);
                string state = Options.StateDataFormat.Protect(properties);

                // Redirect to eWeb Login Page
                Response.Redirect(GeteWebLoginUrl(redirectUri, state));
            }

            return Task.FromResult<object>(null);
        }
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }
        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new netForumReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
        #endregion

        #region Helper methods
        private string GeteWebLoginUrl(string redirectUri, string state)
        {
            return Options.netForumSite + 
                    eWebLoginRelativeUrl + 
                    "&site=" + Options.netForumeWebSiteCode +
                    "&url_success=" + Uri.EscapeDataString(redirectUri + "?token={token}&state=" + state);
        }
        private string Base64(string input)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(input);
            return System.Convert.ToBase64String(plainTextBytes);
        }
        private void AddProperty(string sourceID, JObject source, string destID, JObject dest)
        {
            try
            {
                dest.Add(destID, source[sourceID].ToString());
            }
            catch
            {
                logger.WriteError(string.Format("Property {0} does not exist", sourceID));
            }
        }
        private string GetParameterValue(string paramID, IReadableStringCollection query)
        {
            IList<string> values = query.GetValues(paramID);
            if (values != null && values.Count == 1)
            {
                return values[0];
            }

            return string.Empty;
        }
        #endregion

    }
}