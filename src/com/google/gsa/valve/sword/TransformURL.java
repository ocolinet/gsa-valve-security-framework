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

import org.apache.log4j.Logger;



public class TransformURL{
	
	String webtopServletPath = null;
	String authzServletPath = null;
	
	Logger logger = null; 
	
	public TransformURL(String wtPath, String authzSP) {
		logger = Logger.getLogger(DCTMAuthorizationProcess.class);
		if (!(wtPath==null || wtPath.equals(""))){
			this.webtopServletPath = wtPath;
		}
		if (!(authzSP==null || authzSP.equals(""))){
			this.authzServletPath = authzSP;
		}
		logger.debug("[TransformURL] Initialized with parameters: " + this.webtopServletPath + ", " + this.authzServletPath);
	}
	
	public String transform(String method, String url, String userAgent){
		String[] tabPartUrl = url.split("/");
		
		String result=null;

		if(url.startsWith(this.webtopServletPath) && 
				method.equals("GET") && 
				(userAgent.indexOf("gsa-crawler")!=-1)){
			
			result= this.authzServletPath + "/DocAccess/"+tabPartUrl[4]+"/"+tabPartUrl[5]+"/"+tabPartUrl[6];
			logger.debug("URL to crawl : " + result);
			
        }else if(url.startsWith(this.webtopServletPath) && method.equals("GET")){
        	
        	///component/getcontent?objectId= OR /drl/objectId/
        	result= this.webtopServletPath+"/drl/objectId/"+tabPartUrl[6];
        	logger.debug("URL to serve : " + result);
        	
		}else{
			
		    result=url;
        	logger.debug("Unknown use URL : " + result);
        	
		}
		
		return result;
	}
}