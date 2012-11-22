using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using ServiceStack.ServiceInterface.Auth;
using ServiceStack.Configuration;

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
            throw new NotImplementedException();
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Auth request)
        {
            throw new NotImplementedException();
        }
    }
}