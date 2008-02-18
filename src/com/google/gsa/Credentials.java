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

import java.util.Vector;

import org.apache.log4j.Logger;



public class Credentials {

        Vector<Credential> credentials = new Vector<Credential>();

	private Logger logger = null;
	
        public Credentials() {

            logger = Logger.getLogger(Credentials.class);
            credentials = new Vector<Credential>();
                        
        }        
	
         public Credential getCredential(String id) {
                 Credential cred = null;
                 logger.debug("Getting credentials for " + id);
                 
                 try  {
                    for (int i=0; i<credentials.size(); i++) {
                        Credential credInd = credentials.elementAt(i);
                        if (credInd!=null) {
                            if (credInd.getId().equals(id)) {
                                cred = credInd;
                                logger.debug("Credential found");
                                break;
                            }
                        }
                    }
                 } catch (Exception ex)  {
                   logger.error ("Error found getting credential: "+ex.getMessage(),ex);  
                 } 
                                  
                 return cred;                 
         }
         
         public Credential getCredential(int index) {
            Credential cred = null;
            logger.debug("Getting credentials at " + index);
            
            try {
                if ((index>=0)&&(index<credentials.size())) {
                    cred = credentials.elementAt(index);
                }
            }
            catch (Exception e) {
                logger.error ("Error found getting credential: "+e.getMessage(),e);  
            }
            
            return cred;
            
         }
         
         public void add(Credential cred) {              
            
            if (cred == null) {
                throw new NullPointerException ("Credential is null");
            }
            
            try {
                if (doesCredentialExist(cred)) {
                    logger.debug ("Credential "+cred.getId()+" already exists");
                } else {
                    credentials.add(cred);
                }
            } catch (Exception exp) {
                logger.error("Exception occured adding credentials: " + exp.getMessage(),exp);
            }
                 
         }
         
         public boolean doesCredentialExist (Credential cred) {
             boolean exists = false;
             if (credentials.contains(cred)) {
                 exists = true;
             }
             return exists;
         }
         
         public int getSize () {
             return credentials.size();
         }
	

}
