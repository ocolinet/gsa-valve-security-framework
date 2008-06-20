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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;

import com.google.gsa.valve.configuration.ValveConfiguration;

import java.util.Vector;

/**
 * Authentication Process Interface
 * <p>
 * Authentication modules have to implement it
 * 
 */
public interface AuthenticationProcessImpl {
	
	
	//version 1.2 and before
	//public int authenticate(HttpServletRequest request, HttpServletResponse response, Cookie authCookie, String url, Properties valveConfig, Credentials creds, String id) throws HttpException, IOException;
	
	//version 1.3 and up (using new full xml configuration)
	public int authenticate(HttpServletRequest request, HttpServletResponse response, Vector<Cookie> cookies, String url, Credentials creds, String id) throws HttpException, IOException;
	
        public void setValveConfiguration(ValveConfiguration valveConf);
	
}
