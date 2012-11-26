using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ServiceStack.ServiceInterface.Auth;
using ServiceStack.Configuration;
using Microsoft.IdentityModel.Web;
using Microsoft.IdentityModel.Protocols.WSFederation;
using System.Globalization;
using System.Text;
using System.Collections.Specialized;
using Microsoft.IdentityModel.Claims;
using ServiceStack.ServiceModel;
using System.Net;
using ServiceStack.Common;
using ServiceStack.WebHost.Endpoints;

namespace ServiceStack.ServiceInterface.Auth
{
    public class StsAuthProvider : OAuthProvider
    {
        public const string Name = "sts";
        public static string Realm = "https://sts.longscale.com/";  //StsConfigSection.Settings.ProviderRealm; // "https://marketplace.longscale.com/";

        private IResourceManager appSettings;

        public StsAuthProvider(IResourceManager appSettings)
            :base(appSettings, Realm, Name)
        {
            // TODO: Complete member initialization
            this.appSettings = appSettings;
        }

        public bool IsAuthorizedBySts(IAuthSession session, IOAuthTokens tokens, Auth request = null)
        {
            // TODO: For now...
            return (System.Threading.Thread.CurrentPrincipal != null && System.Threading.Thread.CurrentPrincipal.Identity != null && System.Threading.Thread.CurrentPrincipal.Identity.IsAuthenticated);
        }

        protected IOAuthTokens Init(IServiceBase authService, ref IAuthSession session, Auth request)
        {
            if (request != null && !LoginMatchesSession(session, request.UserName))
            {
                //authService.RemoveSession();
                //session = authService.GetSession();
            }

            var requestUri = authService.RequestContext.AbsoluteUri;
            if (this.CallbackUrl.IsNullOrEmpty())
                this.CallbackUrl = requestUri;

            if (session.ReferrerUrl.IsNullOrEmpty())
                session.ReferrerUrl = (request != null ? request.Continue : null)
                    ?? authService.RequestContext.GetHeader("Referer");
            
            //TODO: This section needs to be changed 
            if (session.ReferrerUrl.IsNullOrEmpty()
                || session.ReferrerUrl.IndexOf("/auth", StringComparison.OrdinalIgnoreCase) >= 0)
                session.ReferrerUrl = this.RedirectUrl
                    ?? ServiceStackHttpHandlerFactory.GetBaseUrl()
                    ?? requestUri.Substring(0, requestUri.IndexOf("/", "https://".Length + 1, StringComparison.Ordinal));

            var tokens = session.ProviderOAuthAccess.FirstOrDefault(x => x.Provider == Provider);
            if (tokens == null)
                session.ProviderOAuthAccess.Add(tokens = new OAuthTokens { Provider = Provider });

            return tokens;
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Auth request)
        {
            var tokens = Init(authService, ref session, request);

            //TODO: For now, later check for incoming URL to see from where it comes and decide...
            bool isAuthenticated = this.IsAuthorizedBySts(session, null, request);

            if (!isAuthenticated)
            {
               authService.SaveSession(session, SessionExpiry);
               return  AuthenticateWithSTS(authService, session, request);
            }

            return CompleteAuthentication(authService, session, request, tokens);
        }

        private object CompleteAuthentication(IServiceBase authService, IAuthSession session, Auth request, IOAuthTokens tokens)
        {
            try
            {
                NameValueCollection claims = ExtractClaims();
                // TODO: Probably recheck claims before making IsAuthenticaed = true...
                session.IsAuthenticated = true;
                authService.SaveSession(session, SessionExpiry);
                OnAuthenticated(authService, session, tokens, claims.ToDictionary());

                //Haz access!
                return authService.Redirect(session.ReferrerUrl.AddHashParam("s", "1"));

            }
            catch (WebException we)
            {
                var statusCode = ((HttpWebResponse)we.Response).StatusCode;
                if (statusCode == HttpStatusCode.BadRequest)
                {
                    return authService.Redirect(session.ReferrerUrl.AddHashParam("f", "AccessTokenFailed"));
                }
            }
            catch (Exception ex)
            {
                return authService.Redirect(session.ReferrerUrl.AddHashParam("f", "Unknown Error"));
            }

            return null;
        }

        private NameValueCollection ExtractClaims()
        {
            NameValueCollection collection = new NameValueCollection();

            var principal = System.Threading.Thread.CurrentPrincipal;
            if (principal != null && principal.Identity != null)
            {
                var identity = principal.Identity as IClaimsIdentity;
                if (identity != null && identity.Claims.Count > 0)
                {
                    foreach (var claim in identity.Claims)
                    {
                        collection.Add(claim.ClaimType, claim.Value);
                    }
                }
            }

            return collection;
        }

        private object AuthenticateWithSTS(IServiceBase authService, IAuthSession session, Auth request)
        {
            // First just try to redirect...
            string homeRealm = null;// this.Request["whr"];
            string issuer;
            string realm;

            if (string.IsNullOrWhiteSpace(homeRealm))
            {
                homeRealm = StsConfigSection.Settings.Issuer.Identifier;  //"http://cloudsts.longscale.com/trust"; // AppSTSSection.Instance.Issuer.Identifier;
            }

            if (homeRealm == StsConfigSection.Settings.Issuer.Identifier) // "http://cloudsts.longscale.com/trust")
            {
                issuer = StsConfigSection.Settings.Issuer.Location; // "https://local.longscale.com/idsrv/issue/wsfed"; //AppSTSSection.Instance.Issuer.Location;
                realm = FederatedAuthentication.WSFederationAuthenticationModule.Realm; //"https://marketplace.longscale.com/";
            }
            else
            {
                throw new InvalidOperationException("The home realm is not trusted for federation." + homeRealm);
                //throw new InvalidOperationException("The home realm is not trusted for federation." + homeRealm + "-" + AppSTSSection.Instance.Issuer.Identifier);
            }

            //var contextId = AppSTSSection.Instance.IssuerUri + "-" + Guid.NewGuid().ToString();
            var contextId = StsConfigSection.Settings.IssuerUri + "-" + Guid.NewGuid().ToString(); // "http://appsts.longscale.com/trust" + "-" + Guid.NewGuid().ToString();

            //this.CreateContextCookie(contextId, this.Request.Url.AbsoluteUri);

            var message = new SignInRequestMessage(new Uri(issuer), realm)
            {
                CurrentTime = DateTime.UtcNow.ToString("s", CultureInfo.InvariantCulture) + "Z",
                Reply = GetReplyUrl(),  // For Azure environment...
                Context = contextId
            };

            // HACK: to solve the issue with User not populated correctly with the informaiton
            // had to remove FedAuth cookies

            //FederatedAuthentication.SessionAuthenticationModule.CookieHandler.Delete();
            //FederatedAuthentication.SessionAuthenticationModule.DeleteSessionTokenCookie();

            return authService.Redirect(message.RequestUrl);
            //            this.Response.Redirect(message.RequestUrl, false);
        }
        

        private string GetReplyUrl()
        {
            HttpRequest request = HttpContext.Current.Request;
            Uri requestUrl = request.Url;
            StringBuilder wreply = new StringBuilder();

            wreply.Append(requestUrl.Scheme);     // e.g. "http" or "https"
            wreply.Append("://");
            wreply.Append(request.Headers["Host"] ?? requestUrl.Authority);
            wreply.Append(request.ApplicationPath);

            if (!request.ApplicationPath.EndsWith("/"))
                wreply.Append("/");
            //http://local.longscale.com/SocialBootstrapApi/api/auth/facebook
            wreply.Append("api/auth/sts");

            return wreply.ToString();
       
        }


        protected override void LoadUserAuthInfo(AuthUserSession userSession, IOAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            var claims = StsConfigSection.Settings.Claims;

            tokens.UserId = authInfo[claims["id"].ClaimUri];
            tokens.UserName = authInfo[claims["username"].ClaimUri];
            tokens.FirstName = authInfo[claims["first_name"].ClaimUri];
            tokens.LastName = authInfo[claims["last_name"].ClaimUri];
            tokens.Email = authInfo[claims["email"].ClaimUri];
            tokens.DisplayName = !string.IsNullOrWhiteSpace(tokens.FirstName) && !string.IsNullOrWhiteSpace(tokens.LastName) ?
                string.Format("{0} {1}", tokens.FirstName, tokens.LastName) : authInfo[claims["name"].ClaimUri];

            LoadUserOAuthProvider(userSession, tokens);
            
        }

        public override void LoadUserOAuthProvider(IAuthSession authSession, IOAuthTokens tokens)
        {
            var userSession = authSession as AuthUserSession;
            if (userSession == null) return;

            userSession.DisplayName = tokens.DisplayName ?? userSession.DisplayName;
            userSession.FirstName = tokens.FirstName ?? userSession.FirstName;
            userSession.LastName = tokens.LastName ?? userSession.LastName;
            userSession.PrimaryEmail = tokens.Email ?? userSession.PrimaryEmail ?? userSession.Email;
        }
    }
}