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

package com.google.gsa.valve.saml.authn;

import com.google.gsa.valve.saml.ArtifactTimer;
import com.google.gsa.valve.configuration.ValveConfiguration;
import com.google.gsa.valve.configuration.ValveConfigurationException;
import com.google.gsa.valve.configuration.ValveConfigurationInstance;
import com.google.gsa.valve.saml.SAMLArtifactProcessor;
import com.google.gsa.valve.saml.XmlProcessingException;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.Writer;

import java.net.InetAddress;

import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.TimeZone;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.impl.OMNamespaceImpl;
import org.apache.axiom.soap.SOAPBody;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.impl.builder.StAXSOAPModelBuilder;
import org.apache.log4j.Logger;

/**
 * Processes the authentication resolve request. This is sent by the client 
 * component (appliance) to verify the authentication process was succesful 
 * and the unique identifier of the authenticated user.
 * 
 */
public class SAMLAuthNResolve extends HttpServlet {

    static final String SOAP_ENV_NS = 
        "http://schemas.xmlsoap.org/soap/envelope/";
    static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    static final String SAML_STATUS_CODE_SUCCESS = 
        "urn:oasis:names:tc:SAML:2.0:status:Success";
    static final String SAML_STATUS_CODE_REQUESTER = 
        "urn:oasis:names:tc:SAML:2.0:status:Requester";
    static final String SAML_STATUS_CODE_RESPONDER = 
        "urn:oasis:names:tc:SAML:2.0:status:Responder";

    //Encoding
    private static final String encoding = "UTF-8";

    //Date Format
    private static final SimpleDateFormat dateFormat = 
        new SimpleDateFormat("yyyy'-'MM'-'dd'T'HH:mm:ss'Z'");
    // Seconds in minutes for conversion.
    private static final long SECS_IN_MIN = 60;
    // Milliseconds in seconds for conversion.
    private static final long MSECS_IN_SEC = 1000;

    //Default username
    private static final String DEFAULT_USERNAME = "default_user";

    //SAML Timeout
    private static Long samlTimeout = null;

    //Artifact timer
    ArtifactTimer artifactTimer;

    //SAMLUserAuthentication
    private SAMLUserAuthentication userAuthentication = null;

    //Logger
    private static Logger logger = Logger.getLogger(SAMLAuthNResolve.class);

    /** 
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> 
     * methods. It gets the SAML request from the appliance and processes it 
     * accordingly.
     * 
     * @param request HTTP request
     * @param response HTTP response
     */
    protected void processRequest(HttpServletRequest request, 
                                  HttpServletResponse response) throws ServletException, 
                                                                       IOException {

        logger.debug("SAMLAuthNResolve:processRequest");

        //ArtifactTimer
        artifactTimer = ArtifactTimer.getInstance();
        artifactTimer.setTimer();

        response.setContentType("text/xml;charset=" + encoding);

        String buildStatus = SAML_STATUS_CODE_SUCCESS;

        ArtifactRequest artifactRequest = null;

        try {
            artifactRequest = extractDataFromRequest(request);
        } catch (XmlProcessingException ex) {
            logger.error("Bad input XML string - will respond " + 
                         SAML_STATUS_CODE_REQUESTER, ex);
            buildStatus = SAML_STATUS_CODE_REQUESTER;
        } catch (Exception ex) {
            logger.error("Bad input XML string - unable to respond", ex);
            throw new ServletException(ex);
        }

        PrintWriter out = response.getWriter();

        String userName = null;
        if (artifactRequest != null) {
            userAuthentication = 
                    SAMLArtifactProcessor.getInstance().consumeArtifact(artifactRequest.getArtifact());
            userName = userAuthentication.getUserName();
        } else {
            artifactRequest = new ArtifactRequest();
        }

        logger.debug("ArtifactResolve received with ID=\"" + 
                     artifactRequest.getId() + "\"" + " for artifact=\"" + 
                     artifactRequest.getArtifact() + "\"" + 
                     ", responding userName=\"" + userName + "\"");

        try {
            buildResponse(buildStatus, out, artifactRequest, userName);
        } catch (Exception ex) {
            logger.error("Problems generating SOAP response - unable to respond", 
                         ex);
            throw new ServletException(ex);
        }

        out.close();
    }

    /**
     * Servlet's doGet
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws ServletException
     * @throws IOException
     */
    protected void doGet(HttpServletRequest request, 
                         HttpServletResponse response) throws ServletException, 
                                                              IOException {
        processRequest(request, response);
    }

    /**
     * Servlet's doPost
     * 
     * @param request HTTP request
     * @param response HTTP response
     * 
     * @throws ServletException
     * @throws IOException
     */
    protected void doPost(HttpServletRequest request, 
                          HttpServletResponse response) throws ServletException, 
                                                               IOException {
        processRequest(request, response);
    }

    /**
     * Extracts SAML from the XML message sent in the request
     * 
     * @param request HTTP request
     * 
     * @return artifact request
     * 
     * @throws IOException
     * @throws XMLStreamException
     * @throws XmlProcessingException
     */
    private ArtifactRequest extractDataFromRequest(HttpServletRequest request) throws IOException, 
                                                                                      XMLStreamException, 
                                                                                      XmlProcessingException {
        InputStream is = request.getInputStream();
        XMLInputFactory xif = XMLInputFactory.newInstance();
        XMLStreamReader reader = xif.createXMLStreamReader(is);
        StAXSOAPModelBuilder builder = new StAXSOAPModelBuilder(reader);

        QName qName = null;
        try {
            qName = new QName(SAMLP_NS, "ArtifactResolve");
            OMElement artifactResolve = 
                builder.getSOAPEnvelope().getBody().getFirstChildWithName(qName);
            checkNotNull(artifactResolve);
            qName = new QName(null, "ID");
            OMAttribute id = artifactResolve.getAttribute(qName);
            checkNotNull(id);
            qName = new QName(null, "IssueInstant");
            OMAttribute issueInstant = artifactResolve.getAttribute(qName);
            checkNotNull(issueInstant);
            qName = new QName(SAMLP_NS, "Artifact");
            OMElement artifact = artifactResolve.getFirstChildWithName(qName);
            checkNotNull(artifact);

            return new ArtifactRequest(id.getAttributeValue(), 
                                       artifact.getText(), 
                                       issueInstant.getAttributeValue());
        } catch (NullPointerException ex) {
            throw new XmlProcessingException(qName + 
                                             " not found while processing SAML ArtifactResolve request");
        } catch (Exception ex) {
            throw new XmlProcessingException(qName + 
                                             " not found while processing SAML ArtifactResolve request", 
                                             ex);
        }

    }

    /**
     * Calculates the expire time based on the timeout and the creation time
     * 
     * @param creationTime creation time
     * @param samlTimeout saml timeout
     * 
     * @return the expiration date
     */
    private String getExpireTime(long creationTime, long samlTimeout) {

        //Note: creationTime is coming in secs
        long expireTime;
        Date dateExp;
        String strDateExp = null;

        //transform samlTimeout to secs
        samlTimeout = samlTimeout * SECS_IN_MIN;

        //Get Expire Date as String
        try {
            expireTime = (creationTime + samlTimeout) * MSECS_IN_SEC;
            dateExp = new Date(expireTime);
            //Set Time Zone
            dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            strDateExp = dateFormat.format(dateExp).toString();
            logger.debug("Expire date: " + strDateExp);
        } catch (Exception e) {
            logger.error("Date error: " + e);
        }

        return strDateExp;
    }

    /**
     * Gets current date as a String
     * 
     * @return the current date
     */
    private String getCurrentDate() {

        String strCurrentDate = null;

        //Get current Date as String
        try {
            long currentTimeMillis = System.currentTimeMillis();
            Date currentDate = new Date(currentTimeMillis);
            //Set Time Zone
            dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
            strCurrentDate = dateFormat.format(currentDate);
        } catch (Exception e) {
            logger.error("Date error: " + e);
        }

        return strCurrentDate;
    }

    /**
     * Builds the SAML response to be sent to the caller
     * 
     * @param buildStatus status
     * @param writer servlet writer
     * @param artifactRequest artifact request
     * @param userName user ID
     * 
     * @throws XMLStreamException
     */
    private void buildResponse(String buildStatus, Writer writer, 
                               ArtifactRequest artifactRequest, 
                               String userName) throws XMLStreamException {

        logger.debug("SAMLAuthNResolve::buildResponse");

        String requestId = null;
        if (artifactRequest != null) {
            requestId = artifactRequest.getId();
        }

        SOAPFactory factory = OMAbstractFactory.getSOAP12Factory();
        SOAPEnvelope soapEnvelope = factory.createSOAPEnvelope();
        soapEnvelope.setNamespace(new OMNamespaceImpl(SOAP_ENV_NS, "soapenv"));
        soapEnvelope.addAttribute("xmlns:xsd", 
                                  "http://www.w3.org/2001/XMLSchema", null);
        soapEnvelope.addAttribute("xmlns:xsi", 
                                  "http://www.w3.org/2001/XMLSchema-instance", 
                                  null);
        SOAPBody soapBody = factory.createSOAPBody(soapEnvelope);

        String issuerName = "unknown";

        String strCurrentDate = "unknown";
        String strExpireDate = "unknown";

        try {

            if (userName == null) {
                userName = DEFAULT_USERNAME;
                if (userName != null) {
                    userName = userName.trim();
                }
            }

            InetAddress addr = InetAddress.getLocalHost();
            issuerName = addr.getHostName();


        } catch (Exception ex) {
            buildStatus = SAML_STATUS_CODE_RESPONDER;
            logger.error("Problems building response - will respond " + 
                         buildStatus, ex);
        }

        strCurrentDate = getCurrentDate();
        strExpireDate = 
                getExpireTime(userAuthentication.getTime(), getSamlTimeout());


        // build the SAML stuff
        OMNamespace samlp = 
            factory.createOMNamespace("urn:oasis:names:tc:SAML:2.0:protocol", 
                                      "samlp");

        OMElement artifactResponse = 
            factory.createOMElement("ArtifactResponse", samlp, soapBody);
        OMNamespace saml = 
            artifactResponse.declareDefaultNamespace("urn:oasis:names:tc:SAML:2.0:assertion");
        artifactResponse.addAttribute("ID", "foo1", null);
        artifactResponse.addAttribute("Version", "2.0", null);
        artifactResponse.addAttribute("InResponseTo", "Unspecified", null);
        artifactResponse.addAttribute("IssueInstant", 
                                      artifactRequest.getIssueInstant(), null);


        //namespace
        OMElement issuer = 
            factory.createOMElement("Issuer", saml, artifactResponse);
        issuer.addAttribute("xmlns", "urn:oasis:names:tc:SAML:2.0:assertion", 
                            null);
        issuer.setText(issuerName);


        OMElement status = 
            factory.createOMElement("Status", samlp, artifactResponse);
        OMElement statusCode = 
            factory.createOMElement("StatusCode", samlp, status);
        statusCode.addAttribute("Value", buildStatus, null);

        if (buildStatus == SAML_STATUS_CODE_SUCCESS && userName != null) {
            OMElement response = 
                factory.createOMElement("Response", samlp, artifactResponse);
            response.addAttribute("ID", "foo2", null);
            response.addAttribute("Version", "2.0", null);
            response.addAttribute("IssueInstant", strCurrentDate, null);

            status = factory.createOMElement("Status", samlp, response);
            statusCode = factory.createOMElement("StatusCode", samlp, status);
            statusCode.addAttribute("Value", buildStatus, null);

            OMElement assertion = 
                factory.createOMElement("Assertion", saml, response);
            assertion.addAttribute("xmlns", 
                                   "urn:oasis:names:tc:SAML:2.0:assertion", 
                                   null);

            assertion.addAttribute("ID", "foo3", null);
            assertion.addAttribute("Version", "2.0", null);
            assertion.addAttribute("IssueInstant", strCurrentDate, null);

            issuer = factory.createOMElement("Issuer", saml, assertion);
            issuer.setText(issuerName);

            OMElement subject = 
                factory.createOMElement("Subject", saml, assertion);

            OMElement nameID = 
                factory.createOMElement("NameID", saml, subject);


            String nameIdSubject = userName;

            nameID.setText(nameIdSubject);
            OMElement conditions = 
                factory.createOMElement("Conditions", saml, assertion);
            conditions.addAttribute("NotBefore", strCurrentDate, null);
            conditions.addAttribute("NotOnOrAfter", strExpireDate, null);

            OMElement authnStatement = 
                factory.createOMElement("AuthnStatement", saml, assertion);
            authnStatement.addAttribute("AuthnInstant", 
                                        artifactRequest.getIssueInstant(), 
                                        null);

            OMElement authnContext = 
                factory.createOMElement("AuthnContext", saml, authnStatement);

            OMElement authnContextClassRef = 
                factory.createOMElement("AuthnContextClassRef", saml, 
                                        authnContext);
            authnContextClassRef.setText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        }

        soapEnvelope.serializeAndConsume(writer);
    }

    /**
     * Gets the user's Distinguished Name (DN)
     * 
     * @param userName user name
     * @param rdnAttr relative DN LDAP attribute
     * @param ldapBaseuser LDAP base user entry
     * 
     * @return the user's DN
     */
    public String getUsername(String userName, String rdnAttr, 
                              String ldapBaseuser) {
        String userDN = null;
        try {
            userDN = rdnAttr + "=" + userName + "," + ldapBaseuser;
        } catch (Exception ex) {
            logger.error("Problem getting the DN");
        } finally {
        }
        return userDN;
    }

    /**
     * Checks the Object is not null
     * 
     * @param object the object instance
     */
    public static final void checkNotNull(final Object object) {
        if (object == null) {
            throw new NullPointerException();
        }
    }

    /**
     * Reads the saml timeout defined in the config file
     * 
     * @return saml timeout
     */
    public long getSamlTimeout() {

        if (samlTimeout == null) {

            ValveConfiguration valveConfig = getValveConfig();

            if (valveConfig != null) {
                samlTimeout = 
                        new Long(valveConfig.getSAMLConfig().getSamlTimeout()).longValue();
                if (samlTimeout < 0) {
                    samlTimeout = Long.MAX_VALUE;
                }
            }
        }
        return samlTimeout.longValue();
    }

    /**
     * Gets the Valve configuration instance
     * 
     * @return valve configuration
     */
    public ValveConfiguration getValveConfig() {

        ValveConfiguration valveConfig = null;

        try {
            valveConfig = ValveConfigurationInstance.getValveConfig();
        } catch (ValveConfigurationException e) {
            logger.error("Configuration Exception when getting Valve Config: " + 
                         e);
        }

        return valveConfig;
    }

    /**
     * This inner class implements an artifact request that is stored in the 
     * artifact vector, to get all the references there and securely consume 
     * them
     * 
     */
    private static final class ArtifactRequest {
        /**
         * Holds value of property id.
         */
        private String id;

        /**
         * Holds value of property artifact.
         */
        private String artifact;

        /**
         * Holds value of property issueInstant
         */
        private String issueInstant;

        /**
         * Class constructor - default
         * 
         */
        public ArtifactRequest() {
        }

        /**
         * Class constructor
         * 
         * @param id artifact id
         * @param artifact artifact
         * @param issueInstant timestamp
         */
        public ArtifactRequest(String id, String artifact, 
                               String issueInstant) {
            this.id = id;
            this.artifact = artifact;
            this.issueInstant = issueInstant;
        }

        /**
         * Gets the artifact.
         * 
         * @return artifact.
         */
        public String getArtifact() {
            return this.artifact;
        }

        /**
         * Sets the artifact.
         * @param artifact artifact vulue
         */
        public void setArtifact(String artifact) {
            this.artifact = artifact;
        }

        /**
         * Gets the artifact id.
         * @return artifact id
         */
        public String getId() {
            return this.id;
        }

        /**
         * Sets the artifact id
         * @param id artifact id
         */
        public void setId(String id) {
            this.id = id;
        }

        /**
         * Gets the issueInstant
         * @return issueInstant
         */
        public String getIssueInstant() {
            return this.issueInstant;
        }

        /**
         * Sets the issueInstant.
         * @param issueInstant timestamp
         */
        public void setIssueInstant(String issueInstant) {
            this.issueInstant = issueInstant;
        }
    }

}
