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


package com.google.gsa;

import java.io.IOException;

import org.apache.commons.httpclient.HttpException;
import com.google.gsa.valve.configuration.ValveConfiguration;

import com.google.gsa.sessions.nonValidSessionException;
import com.google.krb5.Krb5Credentials;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Authorization process interface
 * <p>
 * Authorization modules have to implement it
 * 
 */
public interface AuthorizationProcessImpl {
	
	//version 1.2 and before
	//public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, Properties valveConfig, String id) throws HttpException, IOException;
	
	//version 1.3 and up (using new full xml configuration)
	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] authCookies, String url, String id) throws HttpException, IOException, nonValidSessionException;

	public void setValveConfiguration(ValveConfiguration valveConf);

        public void setCredentials (Credentials creds);
}
