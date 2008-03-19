package com.google.gsa.valve.utils;

import java.net.URL;

import org.apache.log4j.Logger;

/**
 * Provides a method to encode any string into a URL-safe
 * form.
 * Non-ASCII characters are first encoded as sequences of
 * two or three bytes, using the UTF-8 algorithm, before being
 * encoded as %HH escapes.
 *
 * Created: 17 April 1997
 * Author: Bert Bos <bert@w3.org>
 *
 * URLUTF8Encoder: http://www.w3.org/International/URLUTF8Encoder.java
 *
 * Copyright � 1997 World Wide Web Consortium, (Massachusetts
 * Institute of Technology, European Research Consortium for
 * Informatics and Mathematics, Keio University). All Rights Reserved.
 * This work is distributed under the W3C� Software License [1] in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.
 *
 * [1] http://www.w3.org/Consortium/Legal/2002/copyright-software-20021231
 *
 * CLAZARO: Some changes added to support IIS URLs
 * Some other method added to do the whole encoding on it both using java.net.URL
 * classes or String instances to represent Urls
 * 
 * Salvatore di Taranto: add support to URL parameters
 */

public class URLUTF8Encoder
{
 private Logger logger = null;

 public URLUTF8Encoder () {
     //Instantiate logger
     logger = Logger.getLogger(URLUTF8Encoder.class);
 }

 final static String[] hex = {
   "%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07",
   "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
   "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17",
   "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f",
   "%20", "%21", "%22", "%23", "%24", "%25", "%26", "%27",
   "%28", "%29", "%2a", "%2b", "%2c", "%2d", "%2e", "%2f",
   "%30", "%31", "%32", "%33", "%34", "%35", "%36", "%37",
   "%38", "%39", "%3a", "%3b", "%3c", "%3d", "%3e", "%3f",
   "%40", "%41", "%42", "%43", "%44", "%45", "%46", "%47",
   "%48", "%49", "%4a", "%4b", "%4c", "%4d", "%4e", "%4f",
   "%50", "%51", "%52", "%53", "%54", "%55", "%56", "%57",
   "%58", "%59", "%5a", "%5b", "%5c", "%5d", "%5e", "%5f",
   "%60", "%61", "%62", "%63", "%64", "%65", "%66", "%67",
   "%68", "%69", "%6a", "%6b", "%6c", "%6d", "%6e", "%6f",
   "%70", "%71", "%72", "%73", "%74", "%75", "%76", "%77",
   "%78", "%79", "%7a", "%7b", "%7c", "%7d", "%7e", "%7f",
   "%80", "%81", "%82", "%83", "%84", "%85", "%86", "%87",
   "%88", "%89", "%8a", "%8b", "%8c", "%8d", "%8e", "%8f",
   "%90", "%91", "%92", "%93", "%94", "%95", "%96", "%97",
   "%98", "%99", "%9a", "%9b", "%9c", "%9d", "%9e", "%9f",
   "%a0", "%a1", "%a2", "%a3", "%a4", "%a5", "%a6", "%a7",
   "%a8", "%a9", "%aa", "%ab", "%ac", "%ad", "%ae", "%af",
   "%b0", "%b1", "%b2", "%b3", "%b4", "%b5", "%b6", "%b7",
   "%b8", "%b9", "%ba", "%bb", "%bc", "%bd", "%be", "%bf",
   "%c0", "%c1", "%c2", "%c3", "%c4", "%c5", "%c6", "%c7",
   "%c8", "%c9", "%ca", "%cb", "%cc", "%cd", "%ce", "%cf",
   "%d0", "%d1", "%d2", "%d3", "%d4", "%d5", "%d6", "%d7",
   "%d8", "%d9", "%da", "%db", "%dc", "%dd", "%de", "%df",
   "%e0", "%e1", "%e2", "%e3", "%e4", "%e5", "%e6", "%e7",
   "%e8", "%e9", "%ea", "%eb", "%ec", "%ed", "%ee", "%ef",
   "%f0", "%f1", "%f2", "%f3", "%f4", "%f5", "%f6", "%f7",
   "%f8", "%f9", "%fa", "%fb", "%fc", "%fd", "%fe", "%ff"
 };

 /**
  * Encode a string to the "x-www-form-urlencoded" form, enhanced
  * with the UTF-8-in-URL proposal. This is what happens:
  *
  * <ul>
  * <li><p>The ASCII characters 'a' through 'z', 'A' through 'Z',
  *        and '0' through '9' remain the same.
  *
  * <li><p>The unreserved characters - _ . ! ~ * ' ( ) remain the same.
  *
  * <li><p>The space character ' ' is converted into a plus sign '+'.
  * CLAZARO: this has been changed to %20
  *
  * <li><p>All other ASCII characters are converted into the
  *        3-character string "%xy", where xy is
  *        the two-digit hexadecimal representation of the character
  *        code
  *
  * <li><p>All non-ASCII characters are encoded in two steps: first
  *        to a sequence of 2 or 3 bytes, using the UTF-8 algorithm;
  *        secondly each of these bytes is encoded as "%xx".
  * </ul>
  *
  * @param s The string to be encoded
  * @return The encoded string
  */
 public static String encode(String s)
 {
   StringBuffer sbuf = new StringBuffer();
   int len = s.length();
   for (int i = 0; i < len; i++) {
     int ch = s.charAt(i);
     if ('A' <= ch && ch <= 'Z') {             // 'A'..'Z'
       sbuf.append((char)ch);
     } else if ('a' <= ch && ch <= 'z') {      // 'a'..'z'
              sbuf.append((char)ch);
     } else if ('0' <= ch && ch <= '9') {      // '0'..'9'
              sbuf.append((char)ch);
     } else if (ch == ' ') {                   // space
              sbuf.append("%20");
     } else if (ch == '-' || ch == '_'         // unreserved and others like / + (CLAZARO)
         || ch == '.' || ch == '!'
         || ch == '~' || ch == '*'
         || ch == '\'' || ch == '(' || ch == '+'
         || ch == '/'|| ch == ')') {
       sbuf.append((char)ch);
     } else if (ch <= 0x007f) {                // other ASCII
              sbuf.append(hex[ch]);
     } else if (ch <= 0x07FF) {                // non-ASCII <= 0x7FF
              sbuf.append(hex[0xc0 | (ch >> 6)]);
              sbuf.append(hex[0x80 | (ch & 0x3F)]);
     } else {                                  // 0x7FF < ch <= 0xFFFF
              sbuf.append(hex[0xe0 | (ch >> 12)]);
              sbuf.append(hex[0x80 | ((ch >> 6) & 0x3F)]);
              sbuf.append(hex[0x80 | (ch & 0x3F)]);
     }
   }
   return sbuf.toString();
 }

   /* Method: encodeURL
    * Parameter: URL, the URL object
    * Returns: String, the encoded Url
    * Description: This is the encoding method for java.net.URL classes
    * Important Note: if the URL contains an #, the URL class treats it as a reference (i.e. a link inside the page)
    * f.e. the following path /pathwhatever#1/index.html will manage the following way
    *     * Path: /pathwhatever
    *     * Ref: #1/index.html
    * So if the URL contains # chars in the middle somehow, avoid to use this method and pass a String over instead
    */
   public String encodeURL (URL url) {

       logger.debug("Encoding URL (java.net.URL)... "+ url);
       //encode just the Path
       String path = new String (url.getPath());

       try {
           path = encode(path);
           logger.debug ("Path after encoding: "+ path);
       } catch (Exception e) {
           logger.error("Error encoding path: "+e.getMessage(),e);
           return null;
       }

       //check if it's using non default ports
       String port = null;
       int portNum = url.getPort();
       boolean isPort = true;

       if (portNum == -1) {
           isPort = false;
       } else {
           port = ":" + portNum;
       }

       //check if there's a reference (#)
        String ref = url.getRef();
        boolean isRef = true;

        if (ref==null) {
            isRef=false;
        } else {
            ref = encode (ref);
        }

       String quer = url.getQuery();
       boolean isQuer = true;
       if (quer==null) {
           isQuer=false;
       }

       //return URL
       String encodedURL = url.getProtocol()+"://" + url.getHost();
       if (isPort) {
           encodedURL = encodedURL + port;
       }
       encodedURL = encodedURL  + path;

       if (isQuer) {
           encodedURL = encodedURL + "?" + quer;
       }

       if (isRef) {
           encodedURL = encodedURL + "#" + ref;
       }

       logger.debug ("The encoded URL is... "+encodedURL);

       return (encodedURL);
   }

     /* Method: encodeURL
      * Parameter: String, the Url chain
      * Returns: String, the encoded Url
      * Description: This is the encoding method for String-based Url
      * Important Note: if the URL contains an reference (internal page link)
      * the # char that defines the reference is encoded as well and the URL cannot be
      * found then by the IIS webserver
      * f.e. the following path /pathwhatever#1/index.html#reference will manage the following way
      *     * The first # is encoded: OK
      *     * The second one (the reference) is encoded as well: NO OK
      */
     public String encodeURL (String url) {

         logger.debug ("Encoding URL (String)... ");

         //Get protocol
         String protocol = url.substring(0,url.lastIndexOf("://"));
         logger.debug ("Protocol is... "+protocol);

         //URL without protocol is:
         String globalURL = url.substring(url.lastIndexOf("://")+3);
         logger.debug ("Global URL is... "+globalURL);

         //Host and port are:
         String host = null;
         String port = null;
         StringBuffer sbufHost = new StringBuffer();
         StringBuffer sbufPort = new StringBuffer();
         boolean isHost = true;
         boolean isPort = true;
         boolean containsPort = false;
         boolean containsSlash = false;
         int i = 0;
         while (isHost || isPort) {
            char ch = globalURL.charAt(i);
            if (isHost) {
             if (ch == '/') {
                 isHost = false;
                 isPort = false;
                 containsSlash = true;
             } else {
               if ((ch == ':')) {
                   isHost = false;
               } else {
                   sbufHost.append(ch);
               }
             }
            } else { //either port is true or not
             if (isPort) {
                 if (ch == '/') {
                     isPort = false;
                     containsSlash = true;
                 } else {
                     sbufPort.append(ch);
                     if (!containsPort) {
                         containsPort = true;
                     }
                 }
             }
            }
            i++;
            //check if it's the end of the URL
            if (i==globalURL.length()) {
                isHost = false;
                isPort = false;
            }
         } //end while

         //Host and Port values
         host = sbufHost.toString();
         String hostPort = host;
         if (containsPort) {
             port = sbufPort.toString();
             hostPort = hostPort + ":" + port;
         } else {
             port = "";
         }
         logger.debug ("Host is... "+host);
         logger.debug ("Port is... "+port);
         logger.debug ("Host&Port is... "+hostPort);


         //Get the Path
         String path = globalURL.substring(hostPort.length());
         logger.debug ("Path is... "+path);

         //encode Path
         path = encode (path);

         String encodedURL = protocol + "://" + hostPort;
         if ((path == "")&&(containsSlash)) {
             encodedURL = encodedURL + "/";
         } else {
             encodedURL = encodedURL + path;
         }

         logger.debug ("The encoded URL is... "+encodedURL);

         return encodedURL;

     }

}