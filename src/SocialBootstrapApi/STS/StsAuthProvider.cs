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

namespace ServiceStack.ServiceInterface.Auth
{
    public class StsAuthProvider : OAuthProvider
    {
        public const string Name = "sts";
        public static string Realm = "https://marketplace.longscale.com/";

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

        public override object Authenticate(IServiceBase authService, IAuthSession session, Auth request)
        {
            var tokens = Init(authService, ref session, request);

            //TODO: For now, later check for incoming URL to see from where it comes and decide...
            bool isAuthenticated = this.IsAuthorizedBySts(session, null, request);

            if (!isAuthenticated)
            {
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
                homeRealm = "http://cloudsts.longscale.com/trust"; // AppSTSSection.Instance.Issuer.Identifier;
            }

            if (homeRealm == "http://cloudsts.longscale.com/trust")
            {
                issuer = "https://local.longscale.com/idsrv/issue/wsfed"; //AppSTSSection.Instance.Issuer.Location;
                realm = FederatedAuthentication.WSFederationAuthenticationModule.Realm; //"https://marketplace.longscale.com/";
            }
            else
            {
                throw new InvalidOperationException("The home realm is not trusted for federation." + homeRealm);
                //throw new InvalidOperationException("The home realm is not trusted for federation." + homeRealm + "-" + AppSTSSection.Instance.Issuer.Identifier);
            }

            //var contextId = AppSTSSection.Instance.IssuerUri + "-" + Guid.NewGuid().ToString();
            var contextId = "http://appsts.longscale.com/trust" + "-" + Guid.NewGuid().ToString();

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


            base.LoadUserAuthInfo(userSession, tokens, authInfo);
        }


    }
}