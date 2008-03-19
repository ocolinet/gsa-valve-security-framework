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


  import java.io.IOException;
  import java.io.OutputStream;
  import java.io.UnsupportedEncodingException;

  import javax.servlet.http.Cookie;
  import javax.servlet.http.HttpServletRequest;
  import javax.servlet.http.HttpServletResponse;

  import org.apache.commons.httpclient.Header;
  import org.apache.commons.httpclient.HttpException;
  import org.apache.commons.httpclient.HttpMethodBase;
  import org.apache.log4j.Logger;

  import com.google.gsa.AuthorizationProcessImpl;
  import com.google.gsa.Credentials;
  import com.google.gsa.RequestType;
  import com.google.gsa.WebProcessor;
  import com.google.gsa.valve.configuration.ValveConfiguration;

  import java.net.URLEncoder;


public class SMAuthorizationProcess implements AuthorizationProcessImpl {
          
          private Logger logger = null;
          
          private static WebProcessor webProcessor = null;
          //Max Connections
          private int maxConnectionsPerHost = -1;
          private int maxTotalConnections = -1;
          
          private ValveConfiguration valveConf = null;
          
          public SMAuthorizationProcess() {
                  //Instantiate logger
                  logger = Logger.getLogger(SMAuthorizationProcess.class);
          }
          
          public void setLogger(Logger logger) {
                  // Cache local logger
                  //this.logger = logger;
          }
          
          public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException {
                  logger.debug("URL from the : "+ url);
                  Header[] headers = null;
                  HttpMethodBase method = null;
                  
                  String userAgent = request.getHeader("User-Agent");
                  
                  logger.debug("User-Agent = "+userAgent);
                  logger.debug("Authorizing [" + request.getMethod() + "]");
                  logger.debug("in SM AuthZ: URL: "+url);
                  
                  //Get the http AuthZ header
                  Cookie[] requestCookies = null;
                  requestCookies = request.getCookies();
                  
                  
                  //Get Max connections
                  maxConnectionsPerHost = new Integer (valveConf.getMaxConnectionsPerHost()).intValue();                                
                  maxTotalConnections = (new Integer (valveConf.getMaxTotalConnections())).intValue();
                              
                  logger.debug("HttpBasic AuthZ maxConnectionsPerHost: "+maxConnectionsPerHost);
                  logger.debug("HttpBasic AuthZ maxTotalConnections: "+maxTotalConnections);
                  
                  // Protection
                  if (webProcessor == null) {
                    // Instantiate Web processor
                    if ((maxConnectionsPerHost != -1)&&(maxTotalConnections!=-1)) {
                      webProcessor = new WebProcessor(maxConnectionsPerHost, maxTotalConnections);
                    } else {
                      webProcessor = new WebProcessor();
                    }
                  }
                  
                  String userName = null;
                  
                  // Protection
                  if (requestCookies != null) {
                          // Check if the authentication process already happened by looking at the existing cookie
                          // The gsa_sm_auth cookie contains the HTTP Basic AuthZ header
                          for (int i = 0; i < requestCookies.length; i++) {
                                  if ((requestCookies[i].getName()).equals("gsa_sm_auth") ) {
                                          if (requestCookies[i].getValue() != null) {
                                                  userName = requestCookies[i].getValue();
                                          }
                                  }
                          }
                  }
                  
                  
                  //
                  // Launch the authorization process
                  //
                  
                  // Initialize status code
                  int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                  
                  //Set HTTP headers
                  headers = new Header[4];
                  // Set User-Agent
                  //The Persistent SM uses a header to control how it is used. With authN-skip set to true it does not need to authenticate the user, it just requires the 
                  // user username, as set in sm_cookie
                  headers[0] = new Header("authn-skip","true");
                  headers[1] = new Header("authz-skip","false");                  
                  //headers[2] = new Header("ssocookie","sm_cookie");
                  headers[2] = new Header("cookieValue","sm_cookie");
                  logger.debug("Adding header: sm_cookie=" + userName);
                  headers[3] = new Header("Cookie","sm_cookie="+userName);
                  
                  String finalRedirectedURL = null;
                  
                  // Protection
                  try {
                  
                          url = processURL (url);
                          
                          logger.debug("New Url: "+url);
                          
                          url = refineURL(url);
                          
                          logger.debug("authZ request to SM [" + url + "]");
                          
                          //SwpHttpClient cl = new SwpHttpClient();
                          logger.debug("HttpClient instantiated");
                          //cl.setLogger(this.logger);
                          logger.debug("Logger set");
                          //method = cl.process("GET",headers,null,url,null,false);
                          method = webProcessor.sendRequest(null, RequestType.GET_REQUEST, headers, null, url);
                          logger.debug("Process commpleted");
                          if (method == null) {logger.error("c nul");}
                          
                          // Protection
                          if (method != null) {

                                  logger.debug("method != null: "+method.getStatusCode());
                                  if (method.getStatusCode() == HttpServletResponse.SC_OK) 
                                  {
                                          logger.debug("AuthZ successful: 200");
                                          statusCode = HttpServletResponse.SC_OK;
                                          
                                          //Serving request. Head requests for AuthZ does not need to redirect anyone.
                                          String resp = method.getResponseBodyAsString();
                                          logger.debug("Parsing response.");
                                          if (resp==null) {
                                                  statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                                          } else {
                                                  logger.debug("Parsing : "+resp);
                                                  finalRedirectedURL = resp;
                                          }
                                          
                                  } else 
                                  {
                                          logger.debug("AuthZ unsuccessful");
                                          statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                                  }
                                  
                                  
                          } else {
                                  logger.debug("AuthZ unsuccessful");
                                  statusCode = HttpServletResponse.SC_UNAUTHORIZED;
                                  return statusCode;
                          }
                          
                          // Garbagge collect
                          
  //                      method.releaseConnection();
                          method = null;
                          
                  } catch(Exception e) {
                          
                          // Log error
                          logger.error("authorization failure: " +  e.getMessage());                              
                          //method.releaseConnection();
                          method = null;          
                  }
                  
                  //
                  // End of the authorization process
                  //
                  // Return status code
                  //JPN: To change. Must get the notes://... URL the WebProc was redirected to if serving non HTTP otherwise return only status code.
                  if (!(userAgent.startsWith("gsa-crawler") && userAgent.indexOf("(Enterprise") == -1 && userAgent.indexOf("RPT") == -1)) {
                          //Serving => redirect toward actual URL (printing the content of the response is not enough)
                          OutputStream os = response.getOutputStream();
  //                      os.write("Authorization successful. Opening the document in client.".getBytes());
  //                      logger.info("Redirecting user to : "+finalRedirectedURL);
  //                      response.sendRedirect(finalRedirectedURL);//Does not work...
                          //Using the onload() JS returned by the SM instead
                          os.write(finalRedirectedURL.getBytes());
                          statusCode=200;
                          os.flush();
                          os.close();
                          
                          //notes://swp-vm-lotusR7/__C12573450054F09D.nsf?OpenDatabase
  //                      String[] cmd = {"cmd","/c",valveConfig.getProperty("browserPath"),finalRedirectedURL};
  //                      if (logger.isDebugEnabled()) {
  //                      for (int i=0 ; i<cmd.length ; i++) {
  //                      logger.debug("Arg "+i+" : "+cmd[i]);
  //                      }
  //                      }
  //                      try {
  //                      Runtime.getRuntime().exec(cmd);
  //                      } catch (IOException z) {
  //                      logger.error("Could not launch notes client.",z);
  //                      }
                          
                          
                          
                  } else {
                          //Nothing, status code is enough
                  }
                  
                  return statusCode;
                  
          }
          
          private String refineURL(String url) {
                  String[] pairs = url.split("&");
                  StringBuffer goodURL = new StringBuffer(pairs[0]);
                  goodURL.append("&");
                  for (int i=1 ; i<pairs.length ; i++) {
                          int ind = pairs[i].indexOf("=");
                          String tmpStr = pairs[i].substring(ind+1);
                          String repl = tmpStr.replaceAll("=","%3D");
                          
                          goodURL.append(pairs[i].substring(0,ind+1)+repl);
                          if (i!=pairs.length-1) {
                                  goodURL.append("&");
                          }
                  }
                  byte[] what = goodURL.toString().getBytes();
                  logger.error("Getting bytes.");
                  for (int i=what.length ; i>0 ; i--) {
                          if (what[i-1]==13 || what[i-1]==10) {
                                  goodURL.replace(i-1,i,"");
                          }
                  }
                  return goodURL.toString();
          }
          
          private String processURL (String url) {
              
              String processedUrl = url;
              
              try {
                  String mainUrl = url.substring(0, url.lastIndexOf("&rurl=")+"&rurl=".length());
                  String rurl = url.substring (url.lastIndexOf("&rurl=")+"&rurl=".length());
                  rurl = URLEncoder.encode(rurl,"UTF-8");
                  processedUrl = mainUrl + rurl;
              }
              catch (UnsupportedEncodingException e) {
                  logger.error("Encoding error "+e);
                  processedUrl = url;
              }
              return processedUrl;
          }

          public void setCredentials(Credentials creds) {
          }

          public void setValveConfiguration(ValveConfiguration valveConf) {
            this.valveConf = valveConf;                                        
          }
  }
