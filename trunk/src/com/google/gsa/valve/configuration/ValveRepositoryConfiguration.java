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


import java.util.Vector;

public class ValveRepositoryConfiguration  {

	private String id;
	private String pattern;
	private String authN;
	private String authZ;
	private boolean failureAllow;
	
	private Vector<ValveRepositoryParameter>parameters;
	
	public ValveRepositoryConfiguration() {
		parameters = new Vector<ValveRepositoryParameter>();
	}
	
	public void addParameter(ValveRepositoryParameter parameter) {
		parameters.addElement(parameter);
	}
	
	public String getParameterValue(String name) {
		String parameterValue = null;
		if (parameters == null) {
			System.out.println("parameters are null");
			return null;
		} else {
			for (int i = 0; i < parameters.size(); i++) {
				if (parameters.elementAt(i).getName().equals(name)) {
					parameterValue = parameters.elementAt(i).getValue();
				}
			}
			return parameterValue;
		}
	}
	
	public String getAuthN() {
		return authN;
	}
	public void setAuthN(String authN) {
		this.authN = authN;
	}
	public String getAuthZ() {
		return authZ;
	}
	public void setAuthZ(String authZ) {
		this.authZ = authZ;
	}
	public boolean isFailureAllow() {
		return failureAllow;
	}
	public void setFailureAllow(boolean failureAllow) {
		this.failureAllow = failureAllow;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getPattern() {
		return pattern;
	}
	public void setPattern(String pattern) {
		this.pattern = pattern;
	}
}
