package com.google.gsa.valve.configuration;

import java.util.Vector;

public class ValveRespositoryConfiguration  {

	private String id;
	private String pattern;
	private String authN;
	private String authZ;
	private boolean failureAllow;
	
	private Vector <ValveRepositoryParameter>parameters;
	
	public ValveRespositoryConfiguration() {
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
