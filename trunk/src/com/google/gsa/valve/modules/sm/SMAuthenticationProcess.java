 /**
  * Copyright (C) 2008 Sword & Persistent
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


  package com.google.gsa.valve.modules.sm;

  import com.google.gsa.AuthenticationProcessImpl;
  import com.google.gsa.Credential;
  import com.google.gsa.Credentials;
  import com.google.gsa.RequestType;
  import com.google.gsa.WebProcessor;
  import com.google.gsa.valve.configuration.ValveConfiguration;

  import java.io.IOException;
  import java.util.Hashtable;
  import java.util.Vector;

  import javax.servlet.http.Cookie;
  import javax.servlet.http.HttpServletRequest;
  import javax.servlet.http.HttpServletResponse;


  import org.apache.commons.httpclient.Header;
  import org.apache.commons.httpclient.HttpException;
  import org.apache.commons.httpclient.HttpMethodBase;
  import org.apache.commons.httpclient.UsernamePasswordCredentials;
  import org.apache.log4j.Logger;

  /**
   * 
   * <Nikhil>: Modified SMAuthentication Class to integrate with SM
   * The same code would be used for AuthN and AuthZ with two Headers changing.
   *
   */
  public class SMAuthenticationProcess implements AuthenticationProcessImpl {

          // Number of auth cookies expected for this Authentication class, used as a check validation check
          private static final int NB_AUTH_COOKIES = 1;
          //private static Hashtable<String, WebProcessor> webProcessors = new Hashtable<String, WebProcessor>();
          private static Hashtable<String, WebProcessor> webProcessors = new Hashtable<String, WebProcessor>();

          private Logger logger = null;

          private ValveConfiguration valveConf = null;
  //      private boolean isNegotiate;

          public SMAuthenticationProcess() {
                  //Instantiate logger
                  logger = Logger.getLogger(SMAuthenticationProcess.class);

          }

          private static WebProcessor getWebProcessorInstance(Logger logger) {

                  String threadName = null;
                  WebProcessor webProcessor = null;

                  // Read thread name
                  threadName = Thread.currentThread().getName();

                  // Retrieve Web processor
                  webProcessor = (WebProcessor) webProcessors.get(threadName);

                  // Protection
                  if (webProcessor == null) {

                          // Instantiate new Web processor
                          webProcessor = new WebProcessor();

                          // Set logger
                          //webProcessor.setLogger(logger);

                          // Register instance
                          webProcessors.put(threadName, webProcessor);

                  }

                  // Return instance
                  return webProcessor;

          }

          public void setValveConfiguration(ValveConfiguration valveConf) {
                  this.valveConf = valveConf;

          }

          public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> reusableCookies, String url, Credentials creds, String id) throws HttpException, IOException {
                  WebProcessor webProcessor = null;
                  Cookie[] cookies = null;

                  //Use a fixed document URL that all user's have read access to so that their credentials can be validated.
                  //The authZ process does not require anything from this stage as a document can be authorized using just a username against the Persistent SM
                  String AuthUrl = valveConf.getRepository(id).getParameterValue("SMAuthUrl");
                  if (AuthUrl != null) {
                          logger.debug("URL: "+ AuthUrl); 
                  } else {
                          logger.error("No url to perform AUTHN against");
                          return HttpServletResponse.SC_UNAUTHORIZED;
                  }


                   UsernamePasswordCredentials credentials = null;
                   Credential notesCred = null;
                   try {
                           notesCred = creds.getCredential(id);
                   } catch (NullPointerException npe) {
                           logger.error("NPE while reading credentials of ID: " + id);
                   }               
                   if (notesCred != null) {
                           credentials = new UsernamePasswordCredentials(notesCred.getUsername(), notesCred.getPassword());
                   } else {
                           logger.debug("HttpBasic: trying to get creds from repository \"root\"");
                           notesCred = creds.getCredential("root");
                           if (notesCred != null) {
                                   logger.info("Trying with root credentails");
                                   credentials = new UsernamePasswordCredentials(notesCred.getUsername(), notesCred.getPassword());
                           }
                   }



                  // Set counter
                  int nbCookies = 0;

                  // Initialize status code
                  int statusCode = HttpServletResponse.SC_UNAUTHORIZED;

                  // Read cookies
                  cookies = request.getCookies();

                  // Debug
                  logger.debug("SM authentication start");



                  //First check if gsa_sm_auth cookie exisits, if it does that assume still authenticated and return

                  // Protection
                  if (cookies != null) {

                          // Check if the authentication process already happened by looking at the existing cookies      
                          for (int i = 0; i < cookies.length; i++) {

                                  // Check cookie name
                                  if ((cookies[i].getName()).equals("gsa_sm_auth") ) {

                                          // Increment counter
                                          nbCookies++;                                    
                                  }
                          }
                  }

                  // Protection

                  if (nbCookies == NB_AUTH_COOKIES) {

                          logger.debug("Already Authenticated");

                          // Set status code
                          statusCode = HttpServletResponse.SC_OK;

                          // Return
                          return statusCode;

                  }


                  //If the required cookie was not found need to authenticate.


                  logger.debug("Authenticating");
                  Header[] headers = null;
                  HttpMethodBase method = null;


                  // Retrieve Web processor
                  webProcessor = getWebProcessorInstance(logger);

                  //
                  // Launch the authentication process
                  //

                  // Protection
                  try {

                          // Set HTTP headers

                          // <Nikhil>: add two more headers..
                          headers = new Header[2];

                          // Set User-Agent
                          headers[0] = new Header("authn-skip","false");
                          headers[1] = new Header("authz-skip","true");

                          // Request page, testing if credentials are valid
                          //Should use a URL for this test that all valid user's have access to
                          if (credentials != null){
                                  logger.debug("Username: " + credentials.getUserName());
                                  //logger.debug("Password: " + credentials.getPassword());
                          }

                          // send the request to SM URL
                          method = webProcessor.sendRequest(credentials, RequestType.GET_REQUEST, headers, null, AuthUrl);

                          logger.debug("status code: "+method.getStatusCode());

                          //Read the auth header and store in the cookie, the authZ class will use this later
                          headers = method.getRequestHeaders();

                          // ************** commented **************
                          Header authHeader = null;
                          authHeader = method.getRequestHeader("Authorization");

                          // Cache status code
                          if (method != null) {
                                  statusCode = method.getStatusCode();
                          }
                          logger.debug("AuthN status code: " + method.getStatusCode());

                          if (statusCode == HttpServletResponse.SC_OK) {
                                  //Authentication worked, so create the auth cookie to indicate it has worked
                                  Cookie extAuthCookie = null;
                                  extAuthCookie = new Cookie("gsa_sm_auth","");

                                  if (authHeader != null) {

                                          //extAuthCookie.setValue(authHeader.getValue());                                          
                                          extAuthCookie.setValue(credentials.getUserName());

                                  }
                                  String authCookieDomain = null;
                                  String authCookiePath = null;
                                  int authMaxAge = -1;

                                  // Cache cookie properties
                                  //authCookieDomain = (request.getAttribute("authCookieDomain")).toString();
                                  //authCookiePath = (request.getAttribute("authCookiePath")).toString();
                                  authCookieDomain = valveConf.getAuthCookieDomain();
                                  authCookiePath = valveConf.getAuthCookiePath();
                                  try { 
                                    authMaxAge = Integer.parseInt(valveConf.getAuthMaxAge());                
                                  } catch(NumberFormatException nfe) {
                                    logger.error ("Configuration error: check the configuration file as the number set for authMaxAge is not OK:");
                                  }

                                  // Set extra cookie parameters
                                  extAuthCookie.setDomain(authCookieDomain);
                                  extAuthCookie.setPath(authCookiePath);
                                  extAuthCookie.setMaxAge(authMaxAge);

                                  // Log info
                                  if (logger.isDebugEnabled()) logger.debug("Adding gsa_sm_auth cookie: " + extAuthCookie.getName() + ":" + extAuthCookie.getValue() 
                                                  + ":" + extAuthCookie.getPath() + ":" + extAuthCookie.getDomain() + ":" + extAuthCookie.getSecure());

                                  // Add authentication cookie
                                  response.addCookie(extAuthCookie);
                                  //response.addCookie(gsaAuthCookie);
                                  // prepare another Cookie for SM: sm_cookie
                                  /*Cookie smCookie = new Cookie("sm_cookie", credentials.getUserName());
                                  response.addCookie(smCookie);
                                  logger.debug("sm cookie added");*/
                          }

                          // Clear webProcessor cookies
                          webProcessor.clearCookies();

                  } catch(Exception e) {

                          // Log error
                          logger.error("SM authentication failure: ",e);

                          // Garbagge collect
                          method = null;

                          // Reset Web processor
                          logger.debug("in catch exception BEFORE webprocessors PUT");
                          webProcessors.put(Thread.currentThread().getName(), null);
                          logger.debug("in catch exception AFTER webprocessors PUT");
                          // Update status code
                          statusCode = HttpServletResponse.SC_UNAUTHORIZED;

                  }

                  //
                  // End of the authentication process
                  //

                  // Set logger level
                  //logger.setLevel(Level.DEBUG);

                  // Debug
                  logger.debug("SMAuthenticationfs completed (" + statusCode + ")");



                  // Return status code
                  return statusCode;
          }
        

  }
