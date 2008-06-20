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

import org.apache.log4j.Logger;

/**
 * Offers several methods that do operations against a standard LDAP server. 
 * It opens an LDAP connection, checking the authentication credentials 
 * against the server. It does other operations like attribute search, modify 
 * attributes or delete an existing attribute.
 * <p>
 * These operations are mainly used by the security framework for security 
 * purposes.
 * 
 * @see LDAPSSO
 * @see LDAPUniqueCreds
 * 
 */
public class Ldap {

    //ldap vars: this should be define in the config files
    private static String baseuser = 
        null; //Format: "dc=enterprise,dc=google,dc=com"
    private static String host = 
        null; //Format: "ldap://ldapserver.google.com:389";
    private static String emailDomain = 
        null; //Format: "@enterprise.google.com";
    private static String rdnAttr = "cn";

    //User and password. They have to be sent in the login process
    private String user_acceso = ""; //user
    private String passwd = ""; //password    
    private String userID = null;

    //logger    
    private static Logger logger = null;

    /**
     * Class constructor - default
     */
    public Ldap() {
        logger = Logger.getLogger(Ldap.class);
    }

    /**
     * Class constructor
     * <p>
     * It sends all the parameters needed to open an LDAP connection
     * 
     * @param host hostname
     * @param useracceso user name 
     * @param password user's password
     * @param baseuser base LDAP entry
     * @param emaildomain corporate domain (usually for Windows)
     * @param rdnAttr relative Distinghised Name attribute (usually cn)
     */
    public Ldap(String host, String useracceso, String password, 
                String baseuser, String emaildomain, String rdnAttr) {
        logger = Logger.getLogger(Ldap.class);

        this.setHost(host);
        this.setUser_acceso(useracceso);
        this.setPasswd(password);
        this.setBaseuser(baseuser);
        this.setEmailDomain(emaildomain);
        this.setRdnAttr(rdnAttr);
        this.defineUserID();
    }

    /**
     * Sets the LDAP base entry to search users from there
     * 
     * @param baseuser the LDAP base entry
     */
    public void setBaseuser(String baseuser) {
        this.baseuser = baseuser;
    }

    /**
     * Gets the LDAP base entry to search users from there
     * 
     * @return the LDAP base entry
     */
    public String getBaseuser() {
        return baseuser;
    }

    /**
     * Sets the LDAP hostname or IP address
     * 
     * @param host hostname or IP address
     */
    public void setHost(String host) {
        this.host = host;
    }

    /**
     * Gets the LDAP hostname or IP address
     * 
     * @return hostname or IP address
     */
    public String getHost() {
        return host;
    }

    /**
     * Sets the username to create the LDAP connection
     *
     * @param user_acceso username
     */
    public void setUser_acceso(String user_acceso) {
        this.user_acceso = user_acceso;
    }

    /**
     * Gets the username to create the LDAP connection
     * 
     * @return username
     */
    public String getUser_acceso() {
        return user_acceso;
    }

    /**
     * Sets user's password to create the LDAP connection
     * 
     * @param passwd user's password
     */
    public void setPasswd(String passwd) {
        this.passwd = passwd;
    }

    /**
     * Gets user's password to create the LDAP connection
     * 
     * @return user's password
     */
    public String getPasswd() {
        return passwd;
    }

    /**
     * Gets the corporate domain (mainly for Windows - Active Directory)
     * 
     * @param emailDomain corporate domain
     */
    public void setEmailDomain(String emailDomain) {
        this.emailDomain = emailDomain;
    }

    /**
     * Sets the corporate domain (mainly for Windows - Active Directory)
     * 
     * @return corporate domain
     */
    public String getEmailDomain() {
        return emailDomain;
    }

    /**
     * Sets the relative Distinghised Name attribute used to identify users in 
     * the LDAP directory
     * 
     * @param rdnAttr relative Distinghised Name attribute
     */
    public void setRdnAttr(String rdnAttr) {
        this.rdnAttr = rdnAttr;
    }

    /**
     * Gets the relative Distinghised Name attribute used to identify users in 
     * the LDAP directory
     * 
     * @return relative Distinghised Name attribute
     */
    public String getRdnAttr() {
        return rdnAttr;
    }

    /**
     * Gets user's identifier (DN)
     * 
     * @param userID user's identifier
     */
    public void setUserID(String userID) {
        this.userID = userID;
    }

    /**
     * Sets user's identifier (DN)
     * 
     * @return user's identifier
     */
    public String getUserID() {
        return userID;
    }

    /**
     * Creates the user ID if it does not exist yet
     * 
     */
    public void defineUserID() {
        if (userID == null) {
            userID = createUserID();
        }
    }

    /**
     * Builds the user ID based on the configuration information
     * 
     * @return user ID (DN)
     */
    public String createUserID() {
        String userID = null;
        if (emailDomain == null) {
            userID = rdnAttr + "=" + user_acceso + "," + baseuser;
        } else {
            userID = user_acceso + emailDomain;
        }
        logger.debug("LDAP User ID is: " + userID);
        return userID;
    }

    /**
     * Opens a new LDAP connection
     * 
     * @return directory context
     */
    public DirContext openConnection() {
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, 
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.PROVIDER_URL, host);
        env.put(Context.SECURITY_PRINCIPAL, userID);
        env.put(Context.SECURITY_CREDENTIALS, passwd);
        DirContext ctx = null;
        try {
            ctx = new InitialDirContext(env);
        } catch (AuthenticationException ex) {
            logger.debug("Username/password invalid");
        } catch (NamingException ne) {
            logger.error("NamingException: Cannot connect to LDAP: " + 
                         ne.getMessage(), ne);
        } catch (Exception e) {
            logger.error("Exception: Cannot connect to LDAP: " + 
                         e.getMessage(), e);
        }
        // Return connection
        return ctx;
    }

    /**
     * Closes an existing connection
     * 
     * @param ctxcl directory context
     */
    public void closeConnection(DirContext ctxcl) {
        // close connection
        try {
            if (ctxcl != null)
                ctxcl.close();
        } catch (Exception e) {
            logger.error("Exception: LDAP connection close error: " + 
                         e.getMessage(), e);
            e.printStackTrace();
        }
    }


    /**
     * Checks if the user exists
     * 
     * @param cn user's cn
     * @param password user's password
     * @param ctx
     * 
     * @return LDAP connection
     */
    public boolean userExists(String cn, String password, DirContext ctx) {
        boolean resultado = true;
        //Prepare connection against LDAP server
        Hashtable env = new Hashtable();
        env.put(Context.INITIAL_CONTEXT_FACTORY, 
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, host);
        env.put(Context.SECURITY_PRINCIPAL, userID);
        env.put(Context.SECURITY_CREDENTIALS, password);
        try {
            ctx = new InitialDirContext(env);
        } catch (NamingException ne) {
            logger.error("NamingException: Couldn't connect to the LDAP: " + 
                         ne.getMessage(), ne);
            resultado = false;
        } catch (Exception e) {
            logger.error("NamingException: Couldn't connect to the LDAP: " + 
                         e.getMessage(), e);
            resultado = false;
        }
        return resultado;
    }

    /**
     * This method gets the Disthinguished Name of a user
     * 
     * @param userid user id for one of the backend app for the user logged in
     * @param ctx LDAP connection
     * 
     * @return the Disthinguished Name of a user
     * 
     * @throws Exception
     */
    public String getDN(String userid, DirContext ctx) throws Exception {

        String attr = null;

        boolean userExists = false;
        SearchControls l_searchControls = new SearchControls();
        l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String strFiltro = baseuser;
        String attruser = "userPrincipalName=" + userID;

        try {
            NamingEnumeration l_results = 
                ctx.search(strFiltro, attruser, l_searchControls);
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {
                if (l_results.hasMore()) {
                    userExists = true;
                    resultado = (SearchResult)l_results.next();
                    lAttrs = resultado.getAttributes();

                    //get the AD attribute                                                            
                    if (lAttrs.get("distinguishedName") != null) {
                        attr = (String)lAttrs.get("distinguishedName").get();
                    } else {
                        logger.error("The user " + userID + 
                                     " doesn't have the attribute DistinguishedName");
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }

        } catch (Exception ex) {
            logger.error("Error getting User DistinguishedName");
            logger.error("Exception Message: " + ex.getMessage(), ex);
        } finally {
        }
        return attr;
    }

    /**
     * Once the user is connected, his/her userid is retrieved from the AD to 
     * connect to the backend app
     * 
     * @param ldapAttribute the attribute name used in the LDAP for the application
     * @param userDName user id for one of the backend app for the user logged in
     * @param ctx LDAP connection
     * 
     * @return the LDAP attribute's value
     * 
     * @throws Exception
     */
    public String getAttributeByDN(String ldapAttribute, String userDName, 
                                   DirContext ctx) throws Exception {

        String attr = null;
        try {
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);
            String strFiltro = userDName;
            String attruser = "objectclass=*";
            NamingEnumeration l_results = 
                ctx.search(strFiltro, attruser, l_searchControls);
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {
                if (l_results.hasMore()) {
                    userExists = true;
                    resultado = (SearchResult)l_results.next();
                    lAttrs = resultado.getAttributes();

                    //get the AD attribute                                                            
                    if (lAttrs.get(ldapAttribute) != null) {
                        attr = (String)lAttrs.get(ldapAttribute).get();
                    } else {
                        logger.error("The user " + userDName + 
                                     " doesn't have the attribute " + 
                                     ldapAttribute);
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }

        } catch (Exception ex) {
            logger.error("Error retrieving an attribute by User's DistinguishedName: " + 
                         ex.getMessage(), ex);
        } finally {
        }
        return attr;
    }

    /**
     * Once the user is connected, his/her userid is retrieved from the LDAP 
     * to connect to the backend app
     * 
     * @param ldapAttribute attribute name used in the LDAP for the application
     * @param userid user id for one of the backend app for the user logged in
     * @param ctx LDAP connection
     * 
     * @return the application's username that is kept in the attribute
     * 
     * @throws Exception
     */
    public String getUsernameApp(String ldapAttribute, String userid, 
                                 DirContext ctx) throws Exception {

        String attr = null;
        try {
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String strFiltro = baseuser;
            String attruser = "userPrincipalName=" + userID;
            NamingEnumeration l_results = 
                ctx.search(strFiltro, attruser, l_searchControls);
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {
                if (l_results.hasMore()) {
                    userExists = true;
                    resultado = (SearchResult)l_results.next();
                    lAttrs = resultado.getAttributes();

                    //get the AD attribute                                                            
                    if (lAttrs.get(ldapAttribute) != null) {
                        attr = (String)lAttrs.get(ldapAttribute).get();
                    } else {
                        logger.debug("The user " + userID + 
                                     " doesn't have the attribute " + 
                                     ldapAttribute);
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }

        } catch (Exception ex) {
            logger.error("Exception trying to get Username attribute: " + 
                         ex.getMessage(), ex);
        } finally {
        }
        return attr;
    }

    /**
     * Once the user is connected, his/her password is retrieved from the LDAP 
     * to connect to the backend app
     * This method can be only used when the password is not encrypted
     * It is the same method as the previous one but just for password. In fact 
     * this method invokes it
     * 
     * @param ldapAttribute attribute name used in the LDAP for the application
     * @param pwd the password for one of the backend app for the user logged in
     * @param ctx LDAP connection
     * 
     * @return the application's password that is kept in the attribute
     * 
     * @throws Exception
     */
    public String getPasswordApp(String ldapAttribute, String pwd, 
                                 DirContext ctx) throws Exception {
        String attr = getUsernameApp(ldapAttribute, pwd, ctx);
        return attr;
    }

    /**
     * Checks if the user has this attribute in AD
     * 
     * @param attrb the attribute name that is going to be checked if it exists
     * @param userid LDAP user entry
     * @param ctx LDAP connection
     * 
     * @return boolean - "true" if the attributes exists
     * 
     * @throws Exception
     */
    public boolean checkAttributeExists(String attrb, String userid, 
                                        DirContext ctx) throws Exception {

        boolean attributeExists = false;
        try {
            boolean userExists = false;
            SearchControls l_searchControls = new SearchControls();
            l_searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String strFiltro = baseuser;
            String attruser = "userPrincipalName=" + userID;
            NamingEnumeration l_results = 
                ctx.search(strFiltro, attruser, l_searchControls);
            SearchResult resultado = null;
            Attributes lAttrs = null;
            if (l_results != null) {
                if (l_results.hasMore()) {
                    userExists = true;
                    resultado = (SearchResult)l_results.next();
                    lAttrs = resultado.getAttributes();

                    //get the AD attribute                                                            
                    if (lAttrs.get(attrb) != null) {
                        attributeExists = true;
                    }
                }
            }
            if (!userExists) {
                throw new Exception("The user does not exist");
            }

        } catch (Exception ex) {
            logger.error("Exception verifying if the attribute exists: " + 
                         ex.getMessage(), ex);
        } finally {
        }
        return attributeExists;
    }

    /**
     * Change this attribute at the user entry in AD. This method can only be 
     * invoked if the attribute already exits
     * 
     * @param attrb the attribute name that is going to be changed
     * @param userid LDAP user entry
     * @param newValue new attribute value
     * @param ctx LDAP connection
     * 
     * @return boolean - if the change was done OK
     * 
     * @throws Exception
     */
    public boolean changeAttribute(String attrb, String userid, 
                                   String newValue, 
                                   DirContext ctx) throws Exception {
        boolean result = true;

        if (ctx != null) {
            try {
                //check if the user has such attribute
                boolean attrExists = checkAttributeExists(attrb, userid, ctx);
                if (attrExists) {
                    //Get User DistinguishedName
                    String userDName = 
                        getUsernameApp("distinguishedName", userid, ctx);
                    //We specify the changes to be done
                    ModificationItem[] mods = new ModificationItem[1];
                    // Attribute replacement
                    mods[0] = 
                            new ModificationItem(DirContext.REPLACE_ATTRIBUTE, 
                                                 new BasicAttribute(attrb, 
                                                                    newValue));
                    //AD update
                    ctx.modifyAttributes(userDName, mods);
                } else {
                    result = false;
                    throw new Exception("Atribute (" + attrb + 
                                        ") doesn't exist");
                }
            } catch (Exception e) {
                logger.error("Error when changing the attribute: " + 
                             e.getMessage(), e);
                result = false;
            }
        }
        return result;
    }

    /**
     * Adds this attribute at the user entry in AD. This method can only be 
     * invoked if the attribute doesn't have a value
     * 
     * @param attrb the attribute name that is going to be added
     * @param userid LDAP user entry
     * @param value attribute value
     * @param ctx LDAP connection
     * 
     * @return boolean - if the attribute was added OK
     * 
     * @throws Exception
     */
    public boolean addAttribute(String attrb, String userid, String value, 
                                DirContext ctx) throws Exception {
        boolean result = true;

        if (ctx != null) {
            try {
                //check if the user has such attribute
                boolean attrExists = checkAttributeExists(attrb, userid, ctx);
                if (!attrExists) {
                    //Get User DistinguishedName
                    String userDName = 
                        getUsernameApp("distinguishedName", userid, ctx);
                    //We specify the changes to be done
                    ModificationItem[] mods = new ModificationItem[1];
                    // Attribute replacement
                    mods[0] = 
                            new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(attrb, 
                                                                                              value));
                    //AD update
                    ctx.modifyAttributes(userDName, mods);
                } else {
                    result = false;
                    throw new Exception("Atribute (" + attrb + 
                                        ") already exists. You only can modify it");
                }
            } catch (Exception e) {
                logger.error("Error when adding the attribute: " + 
                             e.getMessage(), e);
                result = false;
            }
        }
        return result;
    }

}
