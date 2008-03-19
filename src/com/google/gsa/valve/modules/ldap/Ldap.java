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

package com.google.gsa.valve.modules.ldap;

import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.DirContext;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.ModificationItem;
import javax.naming.NamingException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.httpclient.HttpException;
import org.apache.log4j.Logger;

public class Ldap {
    
    //ldap vars: this should be define in the config files
    private static String baseuser = null;//Format: "dc=enterprise,dc=google,dc=com"
    private static String host= null; //Format: "ldap://ldapserver.google.com:389";
    private static String emailDomain= null; //Format: "@enterprise.google.com";
    private static String rdnAttr = "cn";
    
    //User and password. They have to be sent in the login process
    private String user_acceso = ""; //user
    private String passwd = ""; //password    
    private String userID = null;
    
        
    private static Logger logger = null;
    
    
    public Ldap() {
    	logger = Logger.getLogger(Ldap.class);
    }
    
    public Ldap(String host,String useracceso,String password,String baseuser,String emaildomain, String rdnAttr) {
    	logger = Logger.getLogger(Ldap.class);
    	      
        this.setHost(host);
        this.setUser_acceso(useracceso);
        this.setPasswd(password);
        this.setBaseuser(baseuser);
        this.setEmailDomain(emaildomain);
        this.setRdnAttr(rdnAttr);
        this.defineUserID();
    }
    
    public void setBaseuser(String baseuser) {
        this.baseuser = baseuser;
    }

    public String getBaseuser() {
        return baseuser;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public String getHost() {
        return host;
    }

    public void setUser_acceso(String user_acceso) {
        this.user_acceso = user_acceso;
    }

    public String getUser_acceso() {
        return user_acceso;
    }

    public void setPasswd(String passwd) {
        this.passwd = passwd;
    }

    public String getPasswd() {
        return passwd;
    }

    public void setEmailDomain(String emailDomain) {
        this.emailDomain = emailDomain;
    }

    public String getEmailDomain() {
        return emailDomain;
    }
    
    public void setRdnAttr(String rdnAttr) {
        this.rdnAttr = rdnAttr;
    }

    public String getRdnAttr() {
        return rdnAttr;
    }
    
    public void setUserID(String userID) {
        this.userID = userID;
    }
    
    public String getUserID() {
        return userID;
    }

    public void defineUserID() {
        if (userID == null) {
            userID = createUserID ();
        }
    }
    
    public String createUserID () {
        String userID = null;
        if (emailDomain == null) {
            userID = rdnAttr+"="+user_acceso+","+baseuser;
        } else {
            userID = user_acceso + emailDomain;
        }
        logger.debug("LDAP User ID is: "+userID);
        return userID;
    }
  
  public DirContext openConnection () {   
    Hashtable env = new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.SECURITY_AUTHENTICATION,"simple");
    env.put(Context.PROVIDER_URL, host);
    env.put(Context.SECURITY_PRINCIPAL, userID);
    env.put(Context.SECURITY_CREDENTIALS, passwd);
    DirContext ctx = null;
    try {      
      ctx = new InitialDirContext(env);
    } catch (AuthenticationException ex) {
      logger.debug ("Username/password invalid"); 
    } catch (NamingException ne) {
      logger.error ("NamingException: Cannot connect to LDAP: "+ne.getMessage(),ne);
    } catch (Exception e) {
      logger.error ("Exception: Cannot connect to LDAP: "+e.getMessage(),e);      
    }
    // Return connection
    return ctx;
  }

  public void closeConnection (DirContext ctxcl) {
    // close connection
    try {
      if (ctxcl != null)
        ctxcl.close();
    }
    catch (Exception e) {
      logger.error("Exception: LDAP connection close error: "+e.getMessage(),e);
      e.printStackTrace();
    }
  }
  
  
    /*
     * Method: userExists
     * Vars: cn (this is the user's cn)
     * Vars: password (this is the user's password)
     * Vars: ctx (LDAP connection)
     * Just checks if the user exists
     */
  public boolean userExists(String cn, String password, DirContext ctx)
  {
    boolean resultado=true;
    //Prepare connection against LDAP server
    Hashtable env = new Hashtable();
    env.put(Context.INITIAL_CONTEXT_FACTORY,"com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, host);
    env.put(Context.SECURITY_PRINCIPAL, userID);
    env.put(Context.SECURITY_CREDENTIALS, password);
    try {      
      ctx = new InitialDirContext(env);
    }
    catch (NamingException ne) {
      logger.error ("NamingException: Couldn't connect to the LDAP: "+ne.getMessage(),ne);
      resultado=false;
    } catch (Exception e) {
      logger.error ("NamingException: Couldn't connect to the LDAP: "+e.getMessage(),e);
      resultado=false;
    }
    return resultado;
  }
  
    /*
     * Method: getDN
     * Vars: userid (this is the user id for one of the backend app for the user logged in)
     * Vars: ctx (LDAP connection)
     * This method returns the Disthinguished Name of a user
     */
    public String getDN (String userid, DirContext ctx) throws Exception {

        String attr = null;
        
        boolean userExists = false;
        SearchControls l_searchControls = new SearchControls();
        l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);          
        String strFiltro = baseuser;
        String attruser = "userPrincipalName="+userID;
        
        try  {
            NamingEnumeration l_results = ctx.search(strFiltro,attruser,l_searchControls);      
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {                  
                if (l_results.hasMore()) { 
                    userExists = true;
                    resultado = (SearchResult)l_results.next();                   
                    lAttrs = resultado.getAttributes();
                                        
                    //get the AD attribute                                                            
                    if (lAttrs.get("distinguishedName")!= null) {
                        attr = (String) lAttrs.get("distinguishedName").get();                    
                    } else {
                        logger.error ("The user "+userID+" doesn't have the attribute DistinguishedName");
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }
            
        } catch (Exception ex)  {
            logger.error("Error getting User DistinguishedName");
            logger.error("Exception Message: " + ex.getMessage(),ex);
        } finally  {
        }
        return attr;
    }
    
    /*
     * Method: getAttributeByDN
     * Vars: LDAPAttribute (this is the attribute name used in the LDAP for the application)
     * Vars: userid (this is the user id for one of the backend app for the user logged in)
     * Vars: ctx (LDAP connection)
     * Once the user is connected, his/her userid is retrieved from the AD to connect to the backend app
     */
    public String getAttributeByDN (String ldapAttribute, String userDName, DirContext ctx) throws Exception {

        String attr = null;
        try  {
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);          
            String strFiltro = userDName;
            String attruser = "objectclass=*";
            NamingEnumeration l_results = ctx.search(strFiltro,attruser,l_searchControls);      
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {                  
                if (l_results.hasMore()) { 
                    userExists = true;
                    resultado = (SearchResult)l_results.next();                   
                    lAttrs = resultado.getAttributes();
                    
                    //get the AD attribute                                                            
                    if (lAttrs.get(ldapAttribute)!= null) {
                        attr = (String) lAttrs.get(ldapAttribute).get();                    
                    } else {
                        logger.error ("The user "+userDName+" doesn't have the attribute "+ldapAttribute);
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }
            
        } catch (Exception ex)  {
            logger.error("Error retrieving an attribute by User's DistinguishedName: "+ex.getMessage(),ex);
        } finally  {
        }
        return attr;
    }
  
    /*
     * Method: getUsernameApp
     * Vars: ldapAttribute (this is the attribute name used in the LDAP for the application)
     * Vars: userid (this is the user id for one of the backend app for the user logged in)
     * Vars: ctx (LDAP connection)
     * Once the user is connected, his/her userid is retrieved from the the LDAP to connect to the backend app
     */
    public String getUsernameApp (String ldapAttribute, String userid, DirContext ctx) throws Exception {

        String attr = null;
        try  {
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);          
            String strFiltro = baseuser;
            String attruser = "userPrincipalName="+userID;
            NamingEnumeration l_results = ctx.search(strFiltro,attruser,l_searchControls);      
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {                  
                if (l_results.hasMore()) { 
                    userExists = true;
                    resultado = (SearchResult)l_results.next();                   
                    lAttrs = resultado.getAttributes();
                    
                    //get the AD attribute                                                            
                    if (lAttrs.get(ldapAttribute)!= null) {
                        attr = (String) lAttrs.get(ldapAttribute).get();                    
                    } else {
                        logger.debug ("The user "+userID+" doesn't have the attribute "+ldapAttribute);
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }
            
        } catch (Exception ex)  {
            logger.error ("Exception trying to get Username attribute: "+ex.getMessage(),ex);
        } finally  {
        }
        return attr;
    }
    
    /*
     * Method: getPasswordApp
     * Vars: ldapAttribute (this is the attribute name used in the LDAP for the application)
     * Vars: pwd (this is the password for one of the backend app for the user logged in)
     * Vars: ctx (LDAP connection)
     * Once the user is connected, his/her password is retrieved from the LDAP to connect to the backend app
     * This method can be only used when the password is not encrypted
     * It is the same method as the previous one but just for password. In fact this method invokes it
     */
    public String getPasswordApp (String ldapAttribute, String pwd, DirContext ctx) throws Exception {
        String attr = getUsernameApp (ldapAttribute, pwd, ctx);
        return attr;
    }    
    
    /*
     * Method: checkAttributeExists
     * Vars: attrb (this is the attribute name that is going to be checked if it exists)
     * Vars: userid (this is the LDAP user entry)
     * Vars: ctx (LDAP connection)
     * Check if the user has this attribute in AD
     */
    public boolean checkAttributeExists (String attrb, String userid, DirContext ctx) throws Exception {

        boolean attributeExists = false;
        try  {            
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);          
            String strFiltro = baseuser;
            String attruser = "userPrincipalName="+userID;
            NamingEnumeration l_results = ctx.search(strFiltro,attruser,l_searchControls);      
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {                  
                if (l_results.hasMore()) { 
                    userExists = true;
                    resultado = (SearchResult)l_results.next();                   
                    lAttrs = resultado.getAttributes();
                    
                    //get the AD attribute                                                            
                    if (lAttrs.get(attrb)!= null) {
                        attributeExists = true;                    
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }
            
        } catch (Exception ex)  {
            logger.error ("Exception verifying if the attribute exists: "+ex.getMessage(),ex);
        } finally  {
        }
        return attributeExists;
    }
    
    /*
     * Method: changeAttribute
     * Vars: attrb (this is the attribute name that is going to be changed)
     * Vars: userid (this is the LDAP user entry)
     * Vars: newValue (this is the new attribute value)
     * Vars: ctx (LDAP connection)
     * Change this attribute at the user entry in AD. This method can only be invoked if the attribute already exits
     */
    public boolean changeAttribute (String attrb, String userid,String newValue, DirContext ctx) throws Exception
      {
        boolean result=true;
                    
        if (ctx != null) {
          try {                    
            //check if the user has such attribute
            boolean attrExists = checkAttributeExists(attrb,userid,ctx);
            if (attrExists) {
                //Get User DistinguishedName
                String userDName = getUsernameApp("distinguishedName",userid,ctx);
                //We specify the changes to be done
                ModificationItem[] mods = new ModificationItem[1];
                // Attribute replacement
                mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                new BasicAttribute(attrb,newValue));
                //AD update
                ctx.modifyAttributes (userDName, mods);
            } else {
                result = false;
                throw new Exception ("Atribute ("+attrb+") doesn't exist");
            }
          }
          catch (Exception e) {
            logger.error("Error when changing the attribute: "+e.getMessage(),e);
            result=false;
          }            
        }  
        return result;
      }
      
    
    /*
     * Method: addAttribute
     * Vars: attrb (this is the attribute name that is going to be added)
     * Vars: userid (this is the LDAP user entry)
     * Vars: newValue (this is the attribute value)
     * Vars: ctx (LDAP connection)
     * Add this attribute at the user entry in AD. This method can only be invoked if the attribute doesn't have a value
     */  
    public boolean addAttribute (String attrb, String userid,String value, DirContext ctx) throws Exception
      {
        boolean result=true;
        
        if (ctx != null) {
          try {
            //check if the user has such attribute
            boolean attrExists = checkAttributeExists(attrb,userid,ctx);
            if (!attrExists) {
                //Get User DistinguishedName
                String userDName = getUsernameApp("distinguishedName",userid,ctx);
                //We specify the changes to be done
                ModificationItem[] mods = new ModificationItem[1];
                // Attribute replacement
                mods[0] = new ModificationItem(DirContext.ADD_ATTRIBUTE,
                new BasicAttribute(attrb,value));
                //AD update
                ctx.modifyAttributes (userDName, mods);
            } else {
                result = false;
                throw new Exception ("Atribute ("+attrb+") already exists. You only can modify it");
            }
          }
          catch (Exception e) {
            logger.error("Error when adding the attribute: "+e.getMessage(),e);
            result=false;
          }            
        }  
        return result;
      }
    
}
