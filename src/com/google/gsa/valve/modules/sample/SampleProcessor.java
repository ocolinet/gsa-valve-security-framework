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


package com.google.gsa.valve.modules.sample;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;


import org.apache.commons.httpclient.Credentials;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.commons.httpclient.NameValuePair;

import org.apache.log4j.Logger;

import org.apache.commons.collections.buffer.BoundedFifoBuffer;
import org.htmlparser.Node;
import org.htmlparser.Parser;
import org.htmlparser.Tag;
import org.htmlparser.tags.CompositeTag;
import org.htmlparser.tags.ImageTag;
import org.htmlparser.tags.LinkTag;
import org.htmlparser.tags.ScriptTag;
import org.htmlparser.visitors.NodeVisitor;

import com.google.gsa.RequestType;
import com.google.gsa.WebProcessor;


public class SampleProcessor extends Thread {

	
	private static SampleProcessor sampleProcessor = null;
	
	private Logger logger = null;
	private BoundedFifoBuffer queue = null;
	private WebProcessor webProcessor = null;
	
	private Object lock = new Object();
	
	private SampleProcessor(Logger logger) {
		
		// Invoke parent constructor
		super("Sample Processor Thread");
		
		// Instantiate queue
		queue = new BoundedFifoBuffer(250);

//		Instantiate logger
		this.logger = Logger.getLogger(SampleProcessor.class);


		// Start Sample processor thread
		this.start();

		// Wait until the Web processor thread starts
        synchronized (lock) {
            try { lock.wait(); } catch (InterruptedException ie) {}
        }

        // Cache Sample processor instance
        sampleProcessor = this;
        
		// Debug info
		if (logger.isDebugEnabled()) logger.debug("Sample processor launched successfully");

	}
	
	public static SampleProcessor getInstance(Logger logger) {

		// Start the Sample request processor
		if (sampleProcessor == null) {
			
			// Instantiate Sample processor
			sampleProcessor = new SampleProcessor(logger);

		}
		
		// Return instance
		return sampleProcessor;
		
	}
	
	public void run() {
		
		Request request = null;
		int statusCode = 0;
		
		try {

		    // Tell the master thread that the Web processor is started
			synchronized (lock) { lock.notify(); }
			
          	// Wait for incoming status messages
           	while (true) {

              	synchronized(queue) {

                  // Wait for queue to become non-empty
                  if (queue.isEmpty()) queue.wait();

                  // Exit loop
                  if (queue.isEmpty()) break;

                  // Retrieve request
    			  request = (Request) queue.remove();
    			  
				  // Debug info
				  if (logger.isDebugEnabled()) logger.debug("Sample processor processing url: " + request.getUrl());

    			  // Initialize status code
    			  statusCode = HttpServletResponse.SC_UNAUTHORIZED;
    			  			  
				  try {

        			  // Authorize URL
        			  statusCode = authorize(request.getRequest(), request.getResponse(), request.getResponseCookies(), request.getUrl());  
				
    			  } catch (HttpException he) {
    				  logger.error(he.getMessage());
    			  } catch (IOException ioe) {
    				  logger.error(ioe.getMessage());
    			  } 
    			  
    			  // Update status code
    			  synchronized (request) {
    				  request.setStatusCode(statusCode);
    			  }

				  // Debug info
				  if (logger.isDebugEnabled()) logger.debug("Sample processor completed processing url: " + request.getUrl());

				  // Wake up parent thread
				  synchronized (request) {
					  request.notify();
				  }

              	}

           	}
           	
    	} catch(InterruptedException ie) {
        } finally {

          // The message thread is killed
          synchronized(queue) {
            
            // Clear stack
            queue.clear();
            
          }
          
        }  

		// Garbagge collect
		queue = null;
		
	}
	
	public void processRequest(Request request) {
	    
	    synchronized(queue) {
        	
    		// Push request on stack
    	    queue.add(request);
    	    
    	    // Notify console
    	    queue.notify();

    	}
	    
	}

	public int authorize(HttpServletRequest request, HttpServletResponse response, Cookie[] responseCookies, String url) throws HttpException, IOException {

		Header[] headers = null;
		
		HttpMethodBase method = null;

		
		logger.debug("Authorizing in SampleProcessor");
		// Protection
		if (webProcessor == null) {
			
			// Instantiate Web processor
			webProcessor = new WebProcessor();
			//webProcessor.setLogger(logger);
			
		}
						
		
		org.apache.commons.httpclient.Cookie[] cookies = webProcessor.getResponseCookies();
		
//		 Set HTTP headers
		headers = new Header[1];
		
		// Set User-Agent
		headers[0] = new Header("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1) Gecko/20061010 Firefox/2.0");
		
		// Protection
		if (cookies != null) {
			
			// Look for any cookies that might be needed for authorizatiob
			for (int i = 0; i < cookies.length; i++) {
				
				//Add any required cookies to the headers
			
			}
		
		}
		
		
		
		//
		// Launch the authorization process
		//
		
		// Initialize status code
		int statusCode = HttpServletResponse.SC_UNAUTHORIZED;
		
		// Protection
		if (webProcessor != null) {
			
			// Protection
			try {

				// Process authz request
				
				
				method = webProcessor.sendRequest(null, RequestType.GET_REQUEST, headers, null, url);

				// Protection
				if (method != null) {
					
			        // Cache status code
			        statusCode = method.getStatusCode();

			        String stream = null;
			        Parser parser = null;
			        NodeVisitor visitor = null;
			        
			      
			        stream = readFully(new InputStreamReader(method.getResponseBodyAsStream()));
			        // Retrieve HTML stream
			       // stream = method.getResponseBodyAsString();

	    			// Protection
	    			if (stream != null) {

				        // Parse HTML stream
				        parser = Parser.createParser(stream, null);
				        
				        //Get the basehref for this URL, required to fix some the links in pages
				        String baseHref = "";
				        baseHref = url;

				        try {
				        	// Work out the base for this URL. Everything upto the last /, but after the https(s):// part
				        	//end of protocol
				        	int afterProcotol = url.indexOf("//")+2;
				        	
				        	//position of last slash - after the protocol //
				        	int lastSlash =url.substring(afterProcotol).lastIndexOf("/");
				        	
				        	// If this is -1 no / was found, so the URL is the base
				        	//logger.debug("last Slash: " + lastSlash + ":" + afterProcotol);
				        	if (lastSlash < 0) {
				        		baseHref = url;
				        	} else {
				        		baseHref = url.substring(0, lastSlash + afterProcotol + 1);
				        	}
				        	
				        } catch (Exception e) {
				        	logger.debug("some error with basehref");
				        	logger.debug(e.getMessage());
				        }
				        logger.debug("Base: " + baseHref);
				        // Instantiate visitor
				        visitor = new SampleVisitor(baseHref);
				        // Parse nodes
				        parser.visitAllNodesWith(visitor);
	    				
	    		        // Get writer
	    		        PrintWriter out = response.getWriter();

	    		        // Push HTML content
	    	            if (out != null) { out.flush(); out.print(((SampleVisitor) visitor).getModifiedHTML()); out.close(); }

	    			}

	    			// Garbagge collect
	    			stream = null;
	    			
				}
				
				// Garbagge collect
				
				method.releaseConnection();
				method = null;
				
			} catch(Exception e) {
				
				// Log error
				logger.error("Sample authorization failure: " + e.getMessage());
			
				
				
				// Garbagge collect
				webProcessor = null;
				
				method.releaseConnection();
				method = null;
				
			}
			
		}
		
		//
		// End of the authorization process
		//

		// Set logger level
		//logger.setLevel(Level.DEBUG);
		
		// Return status code
		return statusCode;
		
	}
	
	 public static String readFully(Reader input) throws IOException {
		         BufferedReader bufferedReader = input instanceof BufferedReader 
		 	        ? (BufferedReader) input
		 	        : new BufferedReader(input);
		         StringBuffer result = new StringBuffer();
		         char[] buffer = new char[4 * 1024];
		         int charsRead;
		         while ((charsRead = bufferedReader.read(buffer)) != -1) {
		             result.append(buffer, 0, charsRead);
		         }	        
		         return result.toString();
		     }
		 
		

}

class Request {
    
    private HttpServletRequest request = null;
    private HttpServletResponse response = null;
    private Cookie[] responseCookies = null;
    private String url = null;
    private int statusCode = 0;
    
    public Request(HttpServletRequest request, HttpServletResponse response, Cookie[] responseCookies, String url) {
        this.request = request;
        this.response = response;
        this.responseCookies = responseCookies;
        this.url = url;
    }

	public HttpServletRequest getRequest() {
		return request;
	}

	public HttpServletResponse getResponse() {
		return response;
	}

	public Cookie[] getResponseCookies() {
		return responseCookies;
	}

	public String getUrl() {
		return url;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}
    
}

class SampleVisitor extends NodeVisitor {
	
	private StringBuffer modifiedHTML = null;
	private String basehref = null;
	private Logger logger = null;
	
    public SampleVisitor(String basehref) {
    	
    	// Call parent constructor
        super(true, true);
        
        this.logger = Logger.getLogger(SampleVisitor.class);

        
        // Instantiate buffer
        modifiedHTML = new StringBuffer();
        this.basehref = basehref;
        
    }

    public void visitTag(Tag tag) {
    	
        if (tag instanceof LinkTag) {

        	String link = null;
        	
        	// Cache link
        	link = ((LinkTag) tag).getLink();

        	// Protection
        	if (link != null) {
        		if (!link.startsWith("http")) {
        			if (!link.startsWith("/")) { link = "/" + link; }
        			
        			try {
						((LinkTag) tag).setLink("http://172.28.69.54:8080/valve2/login.jsp?returnPath=http://www.google.com" + URLEncoder.encode(link,"utf-8"));
					} catch (UnsupportedEncodingException e) {
						// TODO Auto-generated catch block
						logger.error("Exception encoding Re-written URL from www.google.com");
					}        		
        		}
        	}
            
        } else if (tag instanceof ImageTag) {
        	
        	String url = null;
        	
        	// Cache url
        	url = ((ImageTag) tag).getImageURL();
        	
        	// Protection
        	if (url != null) {
        		if (!url.startsWith("http")){

        			if (url.startsWith("/")) {         				
        				((ImageTag) tag).setImageURL("http://www.google.com" + url);
        			} else { 
        				((ImageTag) tag).setImageURL(basehref + url);        				 
        			}
        
        		}
        	}
            
        } else if (tag instanceof ScriptTag) {
        	
        	String url = null;
        	
        	// Cache url
        	url = ((ScriptTag) tag).getAttribute("src");
        	
        	// Protection
        	if ((url != null) && (url.startsWith("/"))) ((ScriptTag) tag).setAttribute("src", "http://www.google.com" + url);
            
        }

        // Handle HTML parent node
        if ((tag.getParent() == null) && (!(tag instanceof CompositeTag) || (((CompositeTag) tag).getEndTag() == null))) modifiedHTML.append(tag.toHtml());

    }

    public void visitEndTag(Tag tag) {
    	
        Node parent;
        
        // Get parent tag
        parent = tag.getParent();
        
        // Process orphan end tags
        if (parent == null) modifiedHTML.append(tag.toHtml());
        
        // Process top level tag with no parents
        else if (parent.getParent() == null) modifiedHTML.append(parent.toHtml());
        
    }
    
	public String getModifiedHTML() {
		return modifiedHTML.toString();
	}
	
}
