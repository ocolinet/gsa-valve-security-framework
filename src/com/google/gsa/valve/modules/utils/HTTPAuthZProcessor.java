 /**
  * Copyright (C) 2008 Google - Enterprise EMEA SE
  * Other contributors: Jérémy Pasquon, Emilie Bouvier
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

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;

import java.net.URL;
import java.net.URLDecoder;

import org.htmlparser.Parser;
import org.htmlparser.visitors.NodeVisitor;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.log4j.Logger;

import org.htmlparser.util.ParserException;

public class HTTPAuthZProcessor {

    //logger
    private static Logger logger = null;
    
    //Content-Type
    private static String contentType = null;
    
    //Buffer size. Tune this value if you see bad performance
    private static final int BUFFER_BLOCK_SIZE = 4096; 
    
    public HTTPAuthZProcessor() {
        //set logger
        setLogger ();
    }
    
    public static void setLogger () {
        //set logger
        if (logger == null) {
            logger = Logger.getLogger(HTTPAuthZProcessor.class);
        }
    }
    
    public static void processResponse (HttpServletResponse response, HttpMethodBase method, String url, String loginUrl) {
        
        setLogger ();
        
        logger.debug("Processing Response");                
        contentType = method.getResponseHeader("Content-Type").getValue();
        logger.debug("Content Type is... "+contentType);
        if (contentType != null) {            
            if (contentType.startsWith ("text/html")) {
                //content Type is HTML
                try {
                    //process HTML document
                    logger.debug("Document is HTML. Processing");
                    processHTML (response, method, url, loginUrl);
                } catch (IOException e) {
                    logger.error("I/O Error processing HTML document: "+e.getMessage(),e);
                } catch (ParserException e) {
                    logger.error("Parsering Error processing HTML document: "+e.getMessage(),e);                
                } catch (Exception e) {
                    logger.error("Error processing HTML document: "+e.getMessage(),e);
                }
            } else { //non html document type
                //content Type is NOT HTML                                                                                                                                                                                                                                                                                            
                try {
                    logger.debug("Document is not HTML. Processing");
                    //Set document's name
                    setDocumentName (response, method);
                    //process non HTML document
                    processNonHTML (response, method);
                } catch (IOException e) {
                    logger.error("I/O Error processing NON HTML document: "+e.getMessage(),e);
                } catch (Exception e) {
                    logger.error("Error processing NON HTML document: "+e.getMessage(),e);
                }
            }                                                                                                                    
        } // End contenttype check not null                                                                
    }
    
    public static void setDocumentName (HttpServletResponse response, HttpMethodBase method) {
        response.setHeader("Content-Type", contentType);
        //Set the file name properly
        String []tabpath=(method.getPath()).split("/");
        String fileName=tabpath[tabpath.length-1];
        String decodeFileName = null;
        try {
            decodeFileName = URLDecoder.decode(fileName, "UTF-8");            
        } catch (Exception e) {
            logger.error("Exception decoding URL: "+e);
            decodeFileName = fileName;
        }
        response.setHeader("Content-Disposition","inline; filename=" + decodeFileName);
    }
    
    public static void processHTML (HttpServletResponse response, HttpMethodBase method, String url, String loginUrl) throws IOException, 
                                                    ParserException {
        logger.debug("Processing an HTML document");
        
        String stream = null;
        Parser parser = null;
        NodeVisitor visitor = null;
        
        // Retrieve HTML stream
        stream = readFully(new InputStreamReader(method.getResponseBodyAsStream()));
        
        // Protection
        if (stream != null) {
            logger.debug("Stream content size: " + stream.length());
            // Parse HTML stream to replace any links to include the path to the valve
            parser = Parser.createParser(stream, null);
        
            // Instantiate visitor
            visitor = new HTTPVisitor(url, loginUrl);
            // Parse nodes
            parser.visitAllNodesWith(visitor);
        
            // Get writer
            PrintWriter out = response.getWriter();
        
            // Push HTML content
            if (out != null) {
                out.flush();
                out.print(((HTTPVisitor) visitor).getModifiedHTML());
                out.close();
                logger.debug("Wrote: " + ((HTTPVisitor) visitor).getModifiedHTML().length());
            }
            //  Garbagge collect
            stream = null;
        }
    }
    
    public static void processNonHTML (HttpServletResponse response, HttpMethodBase method) throws IOException {
        
        logger.debug("Processing a non HTML document");                        

        InputStream is = new BufferedInputStream(method.getResponseBodyAsStream());
         
        //HTTP Output
        OutputStream os = response.getOutputStream();              
         
         byte[] buffer = new byte[BUFFER_BLOCK_SIZE];
         int read = is.read(buffer);
         while (read >= 0) {
             if (read > 0)    {
                 os.write(buffer, 0, read);
             }
             read = is.read(buffer);
         }

         is.close();
         os.close();
    }
    
    public static String readFully(Reader input) throws IOException {
        BufferedReader bufferedReader = input instanceof BufferedReader 
           ? (BufferedReader) input
           : new BufferedReader(input);
        StringBuffer result = new StringBuffer();
        char[] buffer = new char[BUFFER_BLOCK_SIZE];        
        int charsRead;
        while ((charsRead = bufferedReader.read(buffer)) != -1) {
            result.append(buffer, 0, charsRead);
        }              
        return result.toString();
    }        
     
}
