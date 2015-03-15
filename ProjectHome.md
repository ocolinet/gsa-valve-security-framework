Strategic and secure information sources are naturally becoming key repositories that customers want to make searchable. Since search is a platform and not just an application commodity, it is a pre-requisite to cope with heterogeneous security systems in order to seamlessly roll-out an Enterprise-wide secure search capability.

The search appliance can nicely integrate with popular single sign-on (SSO) systems, forms-based authentication systems and negotiate HTTP Basic and NTLM authentications/authorizations. However, it can’t substitute the need for a unified authentication process across all secure sources. Heterogeneous sources may require different sets of credentials which make the search experience painful for the end-user, having to authenticate multiple times when querying.

Additionally, the appliance may not be able in certain cases to cope with complex and non-standard authentication and/or authorization processes which may put at risk the deployment of search technology.

The GSA (Google Search Appliance) Valve Security Framework was designed to answer both of these issues. It exposes a global authentication capability to the search user and then loads transparently the sets of credentials that are relevant to each indexed sources. It is a framework that can easily be extended to support the specifics of new repositories in terms of authentication and authorization processes.

This authentication and authorization framework acts as a content proxy and can be considered as a quick, simple and low-cost alternative to a single sign-on (SSO) system. It can be integrated as well with third-party SSO solutions in those situations where the corporate SSO doesn’t secure all the searchable applications.

It offers two different interfaces to be integrated with the appliance: Forms Based and SAML. You can use any of them using the GSA integration features.

You can use Authentication/Authorization modules created by third party contributors. There is a file in the download area that includes the current ones, like the Oracle Portal module. These modules don't have anything to do with the connectors provided with the GSA Connector Manager < http://code.google.com/p/google-enterprise-connector-manager/ > as they have different purposes.

Last Version: 2.0 (June 20 2008)

<b>Important note:</b> most of the features provided by this tool have been now incorporated into the GSA. Check out GSA capabilities can let you model the security part of your Enterprise Search project. <b>It's highly recommended use those out of the box capabilities included in the GSA instead of the Valve project.</b>