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

namespace ServiceStack.ServiceInterface.Auth
{
    public class StsAuthProvider : AuthProvider
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


        public override bool IsAuthorized(IAuthSession session, IOAuthTokens tokens, Auth request = null)
        {
            // TODO: For now...
            return false;
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Auth request)
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
                realm = "https://marketplace.longscale.com/"; // FederatedAuthentication.WSFederationAuthenticationModule.Realm;
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
                //Reply = this.Request.Url.AbsoluteUri.Remove(this.Request.Url.AbsoluteUri.IndexOf(this.Request.Url.Query, StringComparison.OrdinalIgnoreCase)),
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

            wreply.Append("Federation/Federation.aspx");

            return wreply.ToString();
       
        }



    }
}