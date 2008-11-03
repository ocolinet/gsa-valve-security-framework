Web frontends - README
########################################################

The GSA Valve Security Framework provides different customizable JSP pages that support multiple scenarions.
Not all of them are needed at the same time, so that it's recommended to delete those that are not being used in your deployment scenario.
The names used here are just samples ones that can be changed just updating the config file accordingly.
Here it's a brief description on each web frontend:

* login.jsp: this is the default JSP login form when using Security Framework's Forms Based interface.

* loginkrb.jsp: this is used to collect up additional user credential when Kerberos silent authentication is being used with Forms Based interface.

* logincrawlerkrb: if you are using the Forms Based interface with Kerberos silent authentication and would like to crawl through the Security Framework (krbUsrPwdCrawler="true"), this is the crawling login form page

* loginSAML.jsp: this is the default JSP login form when using Security Framework's SAML interface. This is equivalent to login.jsp for SAML.

* loginkrbSAML.jsp: this is used for getting additional username and password when Kerberos silent authentication is in place using the SAML interface. This is equivalent to loginkrb.jsp for SAML.

* test.html: this is a sample Security Framework's internal URL. There has to be at least one internal URL like this to be set up at testFormsCrawlUrl config parameter. 

You have more information on the Security Framework's Scenario Guide.