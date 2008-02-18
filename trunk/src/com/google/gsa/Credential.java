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

import javax.security.auth.Subject;

import org.apache.log4j.Logger;

public class Credential {

	private String id = null;
	private String username = null;
	private String password = null;
	private String domain = null;
	private String ticket = null;
        private Subject krbSubject = null;	
	
	private static Logger logger = null;
	
	
	public Credential(String id) {
		logger = Logger.getLogger(Credential.class);
		
		setId(id);
		
	}
	
	public String getDomain() {
		return domain;
	}
	public void setDomain(String domain) {
		this.domain = domain;
	}
	public String getId() {
		return id;
	}
	private void setId(String id) {
		this.id = id;
		logger.trace("Adding id [" + id);
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
		logger.trace("Adding password");
	}
	public String getTicket() {
		return ticket;
	}
	public void setTicket(String ticket) {
		this.ticket = ticket;
		logger.trace("Adding ticket [" + ticket);
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
		logger.trace("Adding username [" + username);
	}
        
        public Subject getSubject() {
            return krbSubject;
        }
        
        public void setKrbSubject(Subject krbSubject) {        
            this.krbSubject = krbSubject;
            logger.trace("Adding Krb Subject");
        }
	
}
