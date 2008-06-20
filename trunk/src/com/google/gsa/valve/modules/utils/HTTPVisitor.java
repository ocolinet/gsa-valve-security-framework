 /**
  * Copyright (C) 2008 Google - Enterprise EMEA SE
  * Other contributors: Salvatore di Taranto
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import org.htmlparser.Node;
import org.htmlparser.Tag;
import org.htmlparser.tags.CompositeTag;
import org.htmlparser.tags.FrameTag;
import org.htmlparser.tags.ImageTag;
import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.visitors.NodeVisitor;

/**
 * This is the class that does the main HTML processing when URLs have to be 
 * rewritten. This process can happens when just Forms Based interface is in 
 * place and only when we're crawling through the Security Framework or we want 
 * users to access to the content through it.
 * 
 */
public class HTTPVisitor extends NodeVisitor {

    private StringBuffer modifiedHTML = null;
    private String sourceUrl = null;
    private String hostHref = null;
    private String loginUrl = null;
    private String basehref = null;

    //logger
    private Logger logger = null;

    /**
     * Class constructor
     * 
     * @param sourceUrl this is the original url
     * @param loginUrl login url to be included when rewriting
     */
    public HTTPVisitor(String sourceUrl, String loginUrl) {

        // Call parent constructor
        super(true, true);

        logger = Logger.getLogger(HTTPVisitor.class);


        // Instantiate buffer
        modifiedHTML = new StringBuffer();
        this.sourceUrl = sourceUrl;
        this.loginUrl = loginUrl;
        logger.debug("Source URL:" + sourceUrl);


        //      Get the basehref for this URL, required to fix some the links in pages
        if (this.sourceUrl.endsWith("/")) {
            basehref = this.sourceUrl;
        } else {
            basehref = this.sourceUrl + "/";
        }

        try {
            // Work out the base for this URL. Everything upto the last /, but after the https(s):// part
            //end of protocol
            int afterProcotol = sourceUrl.indexOf("//") + 2;
            //workout for double "//"
            String strTail = 
                sourceUrl.substring(afterProcotol, sourceUrl.length());
            String strHead = sourceUrl.substring(0, afterProcotol);
            strTail = strTail.replaceAll("//", "/");
            sourceUrl = strHead + strTail;
            logger.debug("MYSource URL:" + sourceUrl);
            //position of last slash - after the protocol //
            int lastSlash = 
                sourceUrl.substring(afterProcotol).lastIndexOf("/");

            // If this is -1 no / was found, so the URL is the base
            //logger.debug("last Slash: " + lastSlash + ":" + afterProcotol);
            if (lastSlash < 0) {
                basehref = sourceUrl;
            } else {
                basehref = 
                        sourceUrl.substring(0, lastSlash + afterProcotol + 1);
            }
            if (!basehref.endsWith("/")) {
                basehref = basehref + "/";
            }

        } catch (Exception e) {
            logger.debug("Some error with basehref: " + e.getMessage(), e);
        }
        logger.debug("Base: " + basehref);


        //Also set the hostURL. Currently dealing with two types of URL
        //Absolute without the hostname, starts with a /
        //Relative, no leading / so the basehref is need

        // http(s)://hostname:port

        logger.debug("Matching on: " + basehref);

        Pattern urlPattern = Pattern.compile("(http[s]*:\\/\\/.*?)\\/");

        Matcher match = urlPattern.matcher(basehref);
        if (match.find()) {
            hostHref = match.group(1);
            logger.debug("MYSource URL:" + hostHref);

        } else {
            hostHref = basehref;
            logger.error("Can't match url to find host");
        }


        //if (match.find()) {
        //      hostHref = match.group(1);
        //	if (!(hostHref.endsWith("/"))){
        //       hostHref = hostHref +"/"; 
        // }    
        //}         


    }

    /**
     * It reads the HTML tag and processes it accordingly 
     * 
     * @param tag HTML tag
     */
    public void visitTag(Tag tag) {

        //protection
        if (tag == null) {
            return;
        }

        if (tag instanceof LinkTag) {

            String link = null;

            // Cache link
            link = ((LinkTag)tag).getLink();
            String lsource = null;
            lsource = tag.getAttribute("href");
            // Protection
            if (link != null) {

                logger.trace("Link: " + link);

                if (!link.startsWith("http")) {
                    try {
                        //protection. Avoid NPE
                        if (lsource == null) {
                            lsource = "";
                        }

                        if (lsource.startsWith("mailto") || 
                            lsource.startsWith("javascript")) {
                            ((LinkTag)tag).setLink(lsource);

                        } else if (link.startsWith("/")) {
                            String strBrowseUrl = hostHref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            ((LinkTag)tag).setLink(loginUrl + "?returnPath=" + 
                                                   strBrowseUrl);
                            logger.debug(sourceUrl + 
                                         " (relative) rewritten URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);

                        } else {
                            String strBrowseUrl = basehref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            ((LinkTag)tag).setLink(loginUrl + "?returnPath=" + 
                                                   strBrowseUrl);
                            logger.debug(sourceUrl + " (absolute)  URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);
                        }


                    } //catch (UnsupportedEncodingException e) {
                    catch (Exception e) {
                        logger.debug("Exception Visiting Tag (LinkTag): " + 
                                     e.getMessage(), e);
                    }
                } else {
                    // Check is http://THIS REPOSITORY
                    if (link.startsWith(basehref)) {
                        ((LinkTag)tag).setLink(loginUrl + "?returnPath=" + 
                                               link);

                    }
                }
            }

        } else if (tag instanceof ImageTag) {

            String url = null;

            // Cache url
            url = ((ImageTag)tag).getImageURL();

            // Protection
            if (url != null) {
                if (!url.startsWith("http")) {

                    if (url.startsWith("/")) {
                        ((ImageTag)tag).setImageURL(loginUrl + "?returnPath=" + 
                                                    hostHref + url);
                        //   logger.debug(sourceUrl + " (img absolute)  URL: "+hostHref + url.substring(1));

                    } else {
                        ((ImageTag)tag).setImageURL(loginUrl + "?returnPath=" + 
                                                    basehref + url);
                        // logger.debug(sourceUrl + " (imgrelativo)  URL: " + basehref + url);

                    }

                }
            }

        } else if (tag instanceof ScriptTag) {

            String url = null;

            // Cache url
            url = ((ScriptTag)tag).getAttribute("src");

            // Protection
            if ((url != null) && (url.startsWith("/")))
                ((ScriptTag)tag).setAttribute("src", hostHref + "/" + url);

        } else if (tag instanceof FrameTag) {

            String link = null;

            // Cache link
            link = ((FrameTag)tag).getAttribute("src");
            logger.trace("Link: " + link);
            // Protection
            if (link != null) {
                if (!link.startsWith("http")) {
                    try {
                        if (link.startsWith("/")) {
                            String strBrowseUrl = hostHref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            ((FrameTag)tag).setAttribute("src", 
                                                         loginUrl + "?returnPath=" + 
                                                         strBrowseUrl);

                            logger.debug(sourceUrl + 
                                         " (relative) rewritten URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);

                        } else {
                            String strBrowseUrl = basehref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            ((FrameTag)tag).setAttribute("src", 
                                                         loginUrl + "?returnPath=" + 
                                                         strBrowseUrl);
                            logger.debug(sourceUrl + " (absolute)  URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);
                        }

                    } //catch (UnsupportedEncodingException e) {
                    catch (Exception e) {
                        logger.debug("Exception at Frame Tag: " + 
                                     e.getMessage(), e);
                    }
                } else {
                    // Check is http://THIS REPOSITORY
                    if (link.startsWith(basehref)) {
                        ((FrameTag)tag).setAttribute("src", 
                                                     loginUrl + "?returnPath=" + 
                                                     link);


                    }
                }
            }

        } else if (((String)tag.getTagName()).equals("IFRAME")) {
            logger.debug("Tag name " + tag.getTagName());

            String link = null;

            // Cache link
            link = tag.getAttribute("src");
            logger.debug("Link: " + link);
            // Protection
            if (link != null) {
                if (!link.startsWith("http")) {
                    try {
                        if (link.startsWith("/")) {
                            String strBrowseUrl = hostHref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("src", 
                                             loginUrl + "?returnPath=" + strBrowseUrl);

                            logger.debug(sourceUrl + 
                                         " (relative) rewritten URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);

                        } else {
                            String strBrowseUrl = basehref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("src", 
                                             loginUrl + "?returnPath=" + strBrowseUrl);
                            logger.debug(sourceUrl + " (absolute)  URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);
                        }

                    } //catch (UnsupportedEncodingException e) {
                    catch (Exception e) {
                        logger.debug("Exception at IFrame: " + e.getMessage(), 
                                     e);
                    }
                } else {
                    // Check is http://THIS REPOSITORY
                    if (link.startsWith(basehref)) {
                        tag.setAttribute("src", 
                                         loginUrl + "?returnPath=" + link);
                    } else {
                        tag.setAttribute("src", "");
                    }
                }
            }

        } else if (((String)tag.getTagName()).equals("LINK")) {
            String link = null;

            // Cache link
            link = tag.getAttribute("href");
            logger.debug("Link: " + link);
            // Protection
            if (link != null) {
                if (!link.startsWith("http")) {
                    try {
                        if (link.startsWith("/")) {
                            String strBrowseUrl = hostHref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("href", 
                                             loginUrl + "?returnPath=" + 
                                             strBrowseUrl);

                            logger.debug(sourceUrl + 
                                         " (relative) rewritten URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);

                        } else {
                            String strBrowseUrl = basehref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("href", 
                                             loginUrl + "?returnPath=" + 
                                             strBrowseUrl);
                            logger.debug(sourceUrl + " (absolute)  URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);
                        }

                    } //catch (UnsupportedEncodingException e) {
                    catch (Exception e) {
                        logger.debug("Exception at Link: " + e.getMessage(), 
                                     e);
                    }
                } else {
                    // Check is http://THIS REPOSITORY
                    if (link.startsWith(basehref)) {
                        tag.setAttribute("href", 
                                         loginUrl + "?returnPath=" + link);
                    } else {
                        tag.setAttribute("href", "");
                    }
                }
            }

        } else if (((String)tag.getTagName()).equals("LINK")) {
            String link = null;

            // Cache link
            link = tag.getAttribute("href");
            logger.debug("Link: " + link);
            // Protection
            if (link != null) {
                if (!link.startsWith("http")) {
                    try {
                        if (link.startsWith("/")) {
                            String strBrowseUrl = hostHref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strTail = strTail.replaceAll("./", "");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("href", 
                                             loginUrl + "?returnPath=" + 
                                             strBrowseUrl);

                            logger.debug(sourceUrl + 
                                         " (relative) rewritten URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);

                        } else {
                            String strBrowseUrl = basehref + link;
                            int afterProcotol = strBrowseUrl.indexOf("//") + 2;
                            String strTail = 
                                strBrowseUrl.substring(afterProcotol, 
                                                       strBrowseUrl.length());
                            String strHead = 
                                strBrowseUrl.substring(0, afterProcotol);
                            strTail = strTail.replaceAll("//", "/");
                            strBrowseUrl = strHead + strTail;
                            tag.setAttribute("href", 
                                             loginUrl + "?returnPath=" + 
                                             strBrowseUrl);
                            logger.debug(sourceUrl + " (absolute)  URL: " + 
                                         loginUrl + "?returnPath=" + 
                                         strBrowseUrl);
                        }

                    } //catch (UnsupportedEncodingException e) {
                    catch (Exception e) {
                        logger.debug("Exception at LINK: " + e.getMessage(), 
                                     e);
                    }
                } else {
                    // Check is http://THIS REPOSITORY
                    if (link.startsWith(basehref)) {
                        tag.setAttribute("href", 
                                         loginUrl + "?returnPath=" + link);
                    } else {
                        tag.setAttribute("href", "");
                    }
                }
            }

        }
        // else{
        // logger.debug( "Visiting TAG = "+tag.getTagName());
        // }

        // Handle HTML parent node
        if ((tag.getParent() == null) && 
            (!(tag instanceof CompositeTag) || (((CompositeTag)tag).getEndTag() == 
                                                null)))
            modifiedHTML.append(tag.toHtml());

    }

    /**
     * Checks when the tag ends
     * 
     * @param tag HTML tag
     */
    public void visitEndTag(Tag tag) {

        Node parent;

        // Get parent tag
        parent = tag.getParent();

        // Process orphan end tags
        if (parent == null)
            modifiedHTML.append(tag.toHtml());

        // Process top level tag with no parents
        else if (parent.getParent() == null)
            modifiedHTML.append(parent.toHtml());

    }

    public String getModifiedHTML() {
        return modifiedHTML.toString();
    }

}
