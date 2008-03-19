 /**
  * Copyright (C) 2008 Google - Enterprise EMEA SE
  *
  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
  * use this file except in compliance with the License. You may obtain a copy of
  * the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
  * License for the specific language governing permissions and limitations under
  * the License.
  */

package com.google.gsa.valve.configuration;


import java.io.File;
import java.io.IOException;

import org.apache.commons.digester.Digester;
import org.apache.log4j.Logger;
import org.xml.sax.SAXException;

public class ValveConfigurationDigester {

	private static Logger logger = null;
	
	public ValveConfigurationDigester() {
		logger = Logger.getLogger(ValveConfigurationDigester.class);
		logger.debug("Initilise valve configuration digester");
	}
	
	public static void main(String[] args) {

	}
	
	
	/**
	 * @param args
	 */
	public ValveConfiguration run(String configurationFile) {
		
		//Valve Config definition
		ValveConfiguration valveConfig = null;

		try {
			Digester digester = new Digester();
			digester.setValidating( false );

			digester.addObjectCreate( "GSAValveConfiguration", ValveConfiguration.class );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authCookieDomain", "authCookieDomain" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authenticationProcessImpl", "authenticationProcessImpl" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authenticationProcessImpl", "authenticationProcessImpl" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authorizationProcessImpl", "authorizationProcessImpl" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authenticateServletPath", "authenticateServletPath" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authCookiePath", "authCookiePath" );
			digester.addBeanPropertySetter( "GSAValveConfiguration/authMaxAge", "authMaxAge" );
                        digester.addBeanPropertySetter( "GSAValveConfiguration/authCookieName", "authCookieName" );		    
			digester.addBeanPropertySetter( "GSAValveConfiguration/loginUrl", "loginUrl" );
                        digester.addBeanPropertySetter( "GSAValveConfiguration/maxConnectionsPerHost", "maxConnectionsPerHost" );
                        digester.addBeanPropertySetter( "GSAValveConfiguration/maxTotalConnections", "maxTotalConnections" );
                        digester.addBeanPropertySetter( "GSAValveConfiguration/testFormsCrawlUrl", "testFormsCrawlUrl" );                       
                        digester.addBeanPropertySetter( "GSAValveConfiguration/errorLocation", "errorLocation" );
			
                        //Call Method addSearchHost that takes a single parameter
                        digester.addCallMethod("GSAValveConfiguration/searchHost","addSearchHost", 1);

                        //Set value of the parameter for the addSearchHost method
                        digester.addCallParam("GSAValveConfiguration/searchHost", 0);
                        
                        //CLAZARO: new vars for Krb and Sessions
                        digester.addObjectCreate("GSAValveConfiguration/kerberos", ValveKerberosConfiguration.class );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "isKerberos", "isKerberos" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "isNegotiate", "isNegotiate" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "krbini", "krbini" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "krbconfig", "krbconfig" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "KrbAdditionalAuthN", "KrbAdditionalAuthN" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "KrbLoginUrl", "KrbLoginUrl" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "KrbUsrPwdCrawler", "KrbUsrPwdCrawler" );
                        digester.addSetProperties("GSAValveConfiguration/kerberos", "KrbUsrPwdCrawlerUrl", "KrbUsrPwdCrawlerUrl" );
                        digester.addSetNext( "GSAValveConfiguration/kerberos", "setKrbConfig" );
                        
                        
                        digester.addObjectCreate("GSAValveConfiguration/sessions", 
                                     ValveSessionConfiguration.class );
                        digester.addSetProperties("GSAValveConfiguration/sessions", "isSessionEnabled", "isSessionEnabled" );
                        digester.addSetProperties("GSAValveConfiguration/sessions", "sessionTimeout", "sessionTimeout" );
                        digester.addSetProperties("GSAValveConfiguration/sessions", "sessionCleanup", "sessionCleanup" );
                        digester.addSetProperties("GSAValveConfiguration/sessions", "sendCookies", "sendCookies" );                                                
                        digester.addSetNext( "GSAValveConfiguration/sessions", "setSessionConfig" );                                                

			
			digester.addObjectCreate( "GSAValveConfiguration/repository", 
                                     ValveRepositoryConfiguration.class );
			digester.addSetProperties("GSAValveConfiguration/repository", "id", "id" );
			digester.addSetProperties( "GSAValveConfiguration/repository", "pattern", "pattern" );
			digester.addSetProperties( "GSAValveConfiguration/repository", "authN", "authN" );
			digester.addSetProperties( "GSAValveConfiguration/repository", "authZ", "authZ" );
			digester.addSetProperties( "GSAValveConfiguration/repository", "failureAllow", "failureAllow" );
			
			digester.addObjectCreate( "GSAValveConfiguration/repository/P", 
                                     ValveRepositoryParameter.class );
			digester.addSetProperties("GSAValveConfiguration/repository/P", "N", "name" );
			digester.addSetProperties("GSAValveConfiguration/repository/P", "V", "value" );
			digester.addSetNext( "GSAValveConfiguration/repository/P", "addParameter" );
			
			digester.addSetNext( "GSAValveConfiguration/repository", "addRepository" );
			
			File inputFile = new File( configurationFile );
			valveConfig = (ValveConfiguration)digester.parse( inputFile );
			 
			//Logging out
                        //valveConfig.logValveConfiguration();
			
		} catch (IOException ioexp) {
			logger.error("Failed to read from configuration file: " + configurationFile, ioexp);
			
		} catch (SAXException e) {
			logger.error("SAX Exception when reading configuration file: "+e.getMessage(),e);
			e.printStackTrace();
		}
		return valveConfig;
		
		
	}

}
