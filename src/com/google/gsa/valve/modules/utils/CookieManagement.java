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


package com.google.gsa.valve.modules.utils;

import java.util.Calendar;
import java.util.Date;

import org.apache.log4j.Logger;

/**
 * This class provides the utils to manage multiple cookies. As the Apache HTTP 
 * client library uses Cookie classes that are completely different than the 
 * ones managed by the HTTP servlet request and response objects, the methods 
 * included here are able to do the mappings.
 * 
 */
public class CookieManagement {

    //logger
    private static Logger logger = Logger.getLogger(CookieManagement.class);

    /**
     * Class constructor
     * 
     */
    public CookieManagement() {

    }

    /**
     * Transforms Apache cookies into Servlet Cookies
     * 
     * @param apacheCookie apache cookie 
     * 
     * @return servlet cookie
     */
    public static javax.servlet.http.Cookie transformApacheCookie(org.apache.commons.httpclient.Cookie apacheCookie) {

        javax.servlet.http.Cookie newCookie = null;

        if (apacheCookie != null) {
            Date expire = apacheCookie.getExpiryDate();
            int maxAge = -1;

            if (expire == null) {
                maxAge = -1;
            } else {
                Date now = Calendar.getInstance().getTime();
                // Convert milli-second to second
                Long second = 
                    new Long((expire.getTime() - now.getTime()) / 1000);
                maxAge = second.intValue();
            }

            newCookie = 
                    new javax.servlet.http.Cookie(apacheCookie.getName(), apacheCookie.getValue());
            //Hardcoding the domain
            newCookie.setDomain(apacheCookie.getDomain());
            newCookie.setPath(apacheCookie.getPath());
            newCookie.setMaxAge(maxAge);
            newCookie.setSecure(apacheCookie.getSecure());
        }
        return newCookie;
    }

    /**
     * Transforms Servlet cookies into Apache Cookies
     * 
     * @param servletCookie servlet cookie
     * 
     * @return apache cookie
     */
    public static org.apache.commons.httpclient.Cookie transformServletCookie(javax.servlet.http.Cookie servletCookie) {

        org.apache.commons.httpclient.Cookie newCookie = null;

        if (servletCookie != null) {
            newCookie = 
                    new org.apache.commons.httpclient.Cookie(servletCookie.getDomain(), 
                                                             servletCookie.getName(), 
                                                             servletCookie.getValue(), 
                                                             servletCookie.getPath() != 
                                                             null ? 
                                                             servletCookie.getPath() : 
                                                             "/", 
                                                             servletCookie.getMaxAge(), 
                                                             servletCookie.getSecure());
        }
        return newCookie;
    }
}
