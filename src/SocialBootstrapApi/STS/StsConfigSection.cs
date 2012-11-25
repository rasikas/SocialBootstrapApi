using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Configuration;

namespace ServiceStack.ServiceInterface.Auth
{
    public class StsConfigSection : ConfigurationSection
    {
        private static StsConfigSection settings
            = ConfigurationManager.GetSection("STSSection") as StsConfigSection;

        public static StsConfigSection Settings
        {
            get
            {
                return settings;
            }
        }


        private const string IssuerSectionName = "issuer";

        // Properties
        private const string IssuerUriProperty = "issuerUri";
        private const string SiteNameProperty = "siteName";
        private const string IssuerNameProperty = "issuerName";
        private const string RealmProperty = "providerRealm";

        [ConfigurationProperty(IssuerUriProperty, IsRequired = true)]
        public string IssuerUri
        {
            get
            {
                return (string)base[IssuerUriProperty];
            }
            set
            {
                base[IssuerUriProperty] = value;
            }
        }

        [ConfigurationProperty(RealmProperty, IsRequired = true)]
        public string ProviderRealm
        {
            get
            {
                return (string)base[RealmProperty];
            }
            set
            {
                base[RealmProperty] = value;
            }
        }

        [ConfigurationProperty(IssuerSectionName, IsRequired = true)]
        public IssuerSection Issuer
        {
            get
            {
                return (IssuerSection)base[IssuerSectionName];
            }
            set
            {
                base[IssuerSectionName] = value;
            }
        }

    }

    public class IssuerSection : ConfigurationElement
    {
        private const string IdentifierProperty = "identifier";
        private const string LocationProperty = "location";

        [ConfigurationProperty(IdentifierProperty, IsRequired = true)]
        public string Identifier
        {
            get { return (string)base[IdentifierProperty]; }
            set { base[IdentifierProperty] = value; }
        }

        [ConfigurationProperty(LocationProperty, IsRequired = true)]
        public string Location
        {
            get { return (string)base[LocationProperty]; }
            set { base[LocationProperty] = value; }
        }

    }
}