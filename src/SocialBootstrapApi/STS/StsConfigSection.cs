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
        private const string ClaimsSectionName = "claims";
        

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

        //[ConfigurationProperty(ClaimsSectionName, IsRequired = true)]
        //public ClaimsSection Issuer
        //{
        //    get
        //    {
        //        return (ClaimsSection)base[ClaimsSectionName];
        //    }
        //    set
        //    {
        //        base[ClaimsSectionName] = value;
        //    }
        //}

        [ConfigurationProperty(ClaimsSectionName, IsDefaultCollection = false)]
        public ClaimsCollection Claims
        {
            get
            {
                ClaimsCollection urlsCollection = (ClaimsCollection)base[ClaimsSectionName];
                return urlsCollection;
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

    //public class ClaimsSection : ConfigurationElement
    //{

    //}


    public class ClaimsCollection : ConfigurationElementCollection
    {
        public ClaimsCollection()
        {
            // Add one url to the collection.  This is 
            // not necessary; could leave the collection  
            // empty until items are added to it outside 
            // the constructor.
            ClaimConfigElement url =
                (ClaimConfigElement)CreateNewElement();
            Add(url);
        }

        public override
            ConfigurationElementCollectionType CollectionType
        {
            get
            {
                return

                    ConfigurationElementCollectionType.AddRemoveClearMap;
            }
        }

        protected override ConfigurationElement CreateNewElement()
        {
            return new ClaimConfigElement();
        }


        protected override Object GetElementKey(ConfigurationElement element)
        {
            return ((ClaimConfigElement)element).ClaimType;
        }


        public new string AddElementName
        {
            get
            { return base.AddElementName; }

            set
            { base.AddElementName = value; }

        }

        public new string ClearElementName
        {
            get
            { return base.ClearElementName; }

            set
            { base.ClearElementName = value; }

        }

        public new string RemoveElementName
        {
            get
            { return base.RemoveElementName; }
        }

        public new int Count
        {
            get { return base.Count; }
        }


        public ClaimConfigElement this[int index]
        {
            get
            {
                return (ClaimConfigElement)BaseGet(index);
            }
            set
            {
                if (BaseGet(index) != null)
                {
                    BaseRemoveAt(index);
                }
                BaseAdd(index, value);
            }
        }

        new public ClaimConfigElement this[string type]
        {
            get
            {
                return (ClaimConfigElement)BaseGet(type);
            }
        }

        public int IndexOf(ClaimConfigElement claim)
        {
            return BaseIndexOf(claim);
        }

        public void Add(ClaimConfigElement claim)
        {
            BaseAdd(claim);
            // Add custom code here.
        }

        protected override void BaseAdd(ConfigurationElement element)
        {
            BaseAdd(element, false);
            // Add custom code here.
        }

        public void Remove(ClaimConfigElement claim)
        {
            if (BaseIndexOf(claim) >= 0)
                BaseRemove(claim.ClaimType);
        }

        public void RemoveAt(int index)
        {
            BaseRemoveAt(index);
        }

        public void Remove(string type)
        {
            BaseRemove(type);
        }

        public void Clear()
        {
            BaseClear();
            // Add custom code here.
        }
    }


    public class ClaimConfigElement : ConfigurationElement
    {
        // Constructor allowing name, url, and port to be specified. 
        public ClaimConfigElement(String type,String uri)            
        {
            ClaimType = type;
            ClaimUri = uri;
        }

        // Default constructor, will use default values as defined 
        // below. 
        public ClaimConfigElement()
        {
        }


        [ConfigurationProperty("type",
            IsRequired = true,
            IsKey = true)]
        public string ClaimType
        {
            get
            {
                return (string)this["type"];
            }
            set
            {
                this["type"] = value;
            }
        }

        [ConfigurationProperty("uri",
            IsRequired = true)]
        public string ClaimUri
        {
            get
            {
                return (string)this["uri"];
            }
            set
            {
                this["uri"] = value;
            }
        }
    }
}