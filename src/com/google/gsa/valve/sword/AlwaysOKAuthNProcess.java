 /**
  * Copyright (C) 2008 Sword
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

package com.google.gsa.valve.sword;

import java.io.IOException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

import com.google.gsa.AuthenticationProcessImpl;
import com.google.gsa.Credential;
import com.google.gsa.Credentials;
import com.google.gsa.valve.configuration.ValveConfiguration;

import java.util.Vector;

public class AlwaysOKAuthNProcess implements AuthenticationProcessImpl {
	
	

	private ValveConfiguration conf;
	private Logger logger = null;
        
        public void setIsNegotiate (boolean isNegotiate) { 
            //do nothing
        }
        
        public void setValveConfiguration(ValveConfiguration valveConf) {
            this.conf = valveConf;
                             
        }

	public int authenticate(HttpServletRequest request,
			HttpServletResponse response, Vector<Cookie> authCookies, String url,
			Credentials creds, String id) throws HttpException, IOException {
                //CLAZARO: set config
                //conf = ValveConfiguration.getInstance();
                //CLAZARO: end set config
                logger = Logger.getLogger(this.getClass());
		String[] ids = this.conf.getRepositoryIds();
		logger.debug("Adding credentials to "+ids.length+" repositories.");
		Credential curCred = null;
		for (int i=0 ; i<ids.length ; i++) {
			logger.debug(ids[i]);
			if (!ids[i].equals("root")) {
				curCred = new Credential(ids[i]);
				curCred.setUsername(creds.getCredential("root").getUsername());
				curCred.setPassword(creds.getCredential("root").getPassword());
				creds.add(curCred);
			}
		}
		return 200;
	}

}
