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


public class TransformURLOld{
	
	public static String transform(String method, String URL, String userAgent){
		String[] tabPartUrl = URL.split("/");
		String result=null;
		
		/*A VOIR
		if((tabPartUrl[3].equals("webtop")&&(tabPartUrl[4].equals("objectID")))){
		    result=URL;
		*/
		
		///cas transformation pour demande d'autorisation    
		///a priori plus utilisé car l'url d'autorisation est entierement gérée par la servlet Authorise
		/*    
		}else if(tabPartUrl[3].equals("webtop")&& method.equals("GET") && (userAgent.indexOf("Authorization")!=-1)){
			result = "http://"+tabPartUrl[2]+"/gsaDctmCrawl/Authorise";
		}else if(tabPartUrl[3].equals("gsaDctmCrawl")  && method.equals("GET") && (userAgent.indexOf("Authorization")!=-1)){
			result = "http://"+tabPartUrl[2]+"/gsaDctmCrawl/Authorise";
		}
		///
		*/	
		    
		    
		// Crawling 
		///cas du Crawling
        if(tabPartUrl[3].equals("webtop") && method.equals("GET") && (userAgent.indexOf("gsa-crawler")!=-1)){
			result= "http://"+tabPartUrl[2]+"/gsaDctmCrawl/DocAccess/"+tabPartUrl[4]+"/"+tabPartUrl[5]+"/"+tabPartUrl[6];
			System.out.println("valeur page crawling " + result);
		///cas ou clic sur un document dans la liste de résultats du gsa (urls avec docbase)
		///}else if(tabPartUrl[3].equals("webtop") && method.equals("GET") && (userAgent.indexOf("gsa-crawler")==-1)){
        }else if(tabPartUrl[3].equals("webtop") && method.equals("GET")){
			result= "http://"+tabPartUrl[2]+"/webtop/drl/objectId"+"/"+tabPartUrl[6];
		}else{
		    result=URL;
		}
		return result;
	}
}