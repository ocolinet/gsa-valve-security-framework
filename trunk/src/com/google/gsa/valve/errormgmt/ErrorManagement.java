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

package com.google.gsa.valve.errormgmt;

import com.google.gsa.valve.configuration.ValveConfigurationException;

import java.io.File;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;

/**
 * This class processes the error messages sent back to the user. Usually this 
 * can be done in the web application using the mechanisms provided by the 
 * application server, whatever it would be. In some deployment scenarios, 
 * it's recommended to configure a custom error management, specially for 
 * 401 (Unauthorized) error. This scenario is for example silent Kerberos, as 
 * a 401 error could be either part of the negotiation process, i.e. the server 
 * is sending this error to tell the browser some credentials are needed, or the 
 * final error response. This last case is the only one the error message should 
 * be sent back to the user.
 * <p>
 * It reads the specific error messages stored in html file, having as a name 
 * the HTTP error number (for instance 401.html). Each error is put in a 
 * map that is populated just once and can be read multiple times.
 * 
 */
public class ErrorManagement {

    //default error pages location
    private static String errorLocation = null;

    //logger
    private static Logger logger = Logger.getLogger(ErrorManagement.class);

    //Error Vector
    private static Map<Integer, String> errorMap = null;


    /**
     * Class Constructor
     * 
     * @param errorLocation the path where the error messages are located
     * 
     * @throws ValveConfigurationException
     */
    public ErrorManagement(String errorLocation) throws ValveConfigurationException {
        //Set error location
        setErrorLocation(errorLocation);
        //Initialize Error Map
        initializeErrorMap();
    }


    /**
     * Sets the path to the error directory
     * 
     * @param errorLocation the path where the error messages are located
     */
    public void setErrorLocation(String errorLocation) {
        this.errorLocation = errorLocation;
    }

    /**
     * Gets the location where the error directory is
     * 
     * @return the path where the error messages are located
     */
    public String getErrorLocation() {
        return errorLocation;
    }

    /**
     * Initilizes the map that contains the error messages located at 
     * "errorLocation" directory. Once this map is created, it can be used 
     * multiple times to immediately send the error message back to the user.
     * 
     * @throws ValveConfigurationException
     */
    private void initializeErrorMap() throws ValveConfigurationException {
        if (errorLocation != null) {
            if (errorMap == null) {
                //protection: check if location dir exists and it's not null           
                if (errorLocation != null) {
                    File locationDir = new File(errorLocation);
                    logger.debug("Absolute path is: " + 
                                 locationDir.getAbsolutePath());
                    if ((locationDir.exists()) && 
                        (locationDir.isDirectory())) {
                        logger.debug("Creating the error file Map");
                        //initialize map
                        errorMap = new HashMap<Integer, String>();
                        logger.debug("Populating the error Map with error numbers and their associated files");
                        //populate map
                        populateErrorMap(locationDir);
                    } else {
                        throw new ValveConfigurationException("Error Directory Location (errorLocation) has not been set up properly. Review your config file");
                    }
                }
            }
        } else {
            throw new ValveConfigurationException("Error Directory Location (errorLocation) has not been defined. Review your config file");
        }
    }

    /**
     * Populates all the existing error files in the directory
     * 
     * @param location the path where the error messages are located
     */
    private void populateErrorMap(File location) {
        //Get all files
        File[] files = location.listFiles();

        int i = 0;
        int n = (files == null) ? 0 : files.length;

        logger.debug("Number of error files found: " + n);

        try {
            while (i < n) {
                //Get file
                File errorHTMLFile = files[i];
                //Protection: check if it's a file
                if (errorHTMLFile.isFile()) {
                    //get file name
                    String fileName = errorHTMLFile.getName();
                    logger.debug("Error file found: " + fileName);
                    String fileNumber = null;
                    try {
                        fileNumber = 
                                fileName.substring(0, fileName.lastIndexOf("."));
                    } catch (java.lang.StringIndexOutOfBoundsException e) {
                        logger.error("Error: the file name should have an extension");
                    }
                    logger.debug("It's file number is: " + fileNumber);
                    if (fileNumber != null) {
                        if (checkValidHTTPError(fileNumber)) {
                            String absolutePath = 
                                errorHTMLFile.getAbsolutePath();
                            logger.debug("File's absolute path: " + 
                                         absolutePath);
                            errorMap.put((new Integer(fileNumber)), 
                                         absolutePath);
                            logger.debug("New error file inserted");
                        }
                    }
                }
                i++;
            }
        } catch (Exception e) {
            logger.error("Error when processing error files: " + e);
        }

    }

    /**
     * Checks if the file name it's a valid error number
     * 
     * @param errorNumber HTTP error number
     * 
     * @return boolean - "true" if the string contains a valid error number
     */
    private boolean checkValidHTTPError(String errorNumber) {
        boolean validError = false;

        try {
            Integer errorInteger = new Integer(errorNumber);
            int errorInt = errorInteger.intValue();
            if ((errorInt >= 100) && (errorInt < 600)) {
                validError = true;
            }
        } catch (NumberFormatException ex) {
            logger.error("Non valid error number: the file format should be <http_error_code_int>.html " + 
                         ex);
        } catch (Exception ex) {
            logger.error("Error processing error file name " + ex);
        } finally {
        }

        return validError;
    }

    /**
     * Processes the HTTP error number and returns the error page
     * 
     * @param errorNumber standard HTTP error number
     * 
     * @return the HTML error page content if it does exist (if not, null)
     */
    public String processError(int errorNumber) {
        String errorPage = null;
        try {
            if (errorMap != null) {
                String fileLoc = errorMap.get(new Integer(errorNumber));
                if (fileLoc != null) {
                    errorPage = readHTMLFile(fileLoc);
                } else {
                    logger.debug("Error file does not exist");
                }
            }
        } catch (Exception ex) {
            logger.error("Error processing error page: " + ex);
        } finally {
        }
        return errorPage;
    }

    /**
     * Reads the error HTML file
     * 
     * @param fileLoc the path where the error message HTML file is located
     * 
     * @return the HTML error page content if it does exist (if not, null)
     */
    public String readHTMLFile(String fileLoc) {
        String errorPage = null;
        try {
            FileInputStream fis = new FileInputStream(fileLoc);
            int x = fis.available();
            byte b[] = new byte[x];
            fis.read(b);
            errorPage = new String(b);
            //close buffers
            fis.close();
            b = null;
        } catch (Exception ex) {
            logger.error("Error reading error page: " + ex);
        } finally {
        }
        return errorPage;
    }

    /**
     * Inserts the HTML error message in the response
     * 
     * @param response servlet HTTP response
     * 
     * @param content the HTML error message
     */
    public static void showHTMLError(HttpServletResponse response, 
                                     String content) {

        if (content != null) {

            // Get writer
            PrintWriter out = null;

            try {
                out = response.getWriter();

                // Push HTML content
                if (out != null) {
                    out.flush();
                    out.print(content);
                    out.close();
                }
            } catch (IOException e) {
                logger.error("Erro sending HTML message: " + e);
            }
        }
    }

}
