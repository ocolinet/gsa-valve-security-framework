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

package com.google.gsa.valve.saml;

import com.google.gsa.valve.saml.authn.SAMLUserAuthentication;

import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;

/**
 * It implements the SAML artifact processor
 * 
 */
public class SAMLArtifactProcessor {

    private static SAMLArtifactProcessor instance = null;

    private static Logger logger = 
        Logger.getLogger(SAMLArtifactProcessor.class);

    private static final long DEFAULT_MAX_ARTIFACT_AGE = 60; //one minute
    private static long maxArtifactAge = DEFAULT_MAX_ARTIFACT_AGE;
    private static final long MSECS_IN_SEC = 1000;
    private static final long SECS_IN_MIN = 60;

    private static Random randomGenerator = new Random(new Date().getTime());

    private static Map<String, SAMLUserAuthentication> artifactMap;

    /**
     * Class contructor
     * 
     */
    protected SAMLArtifactProcessor() {
        logger.debug("Initializing artifactMap");
        artifactMap = new HashMap<String, SAMLUserAuthentication>();
    }

    /**
     * Gets the unique artifact processor instance
     * 
     * @return this unique instance
     */
    public static SAMLArtifactProcessor getInstance() {
        if (instance == null) {
            logger.debug("Instance does not exist yet. Creating");
            instance = new SAMLArtifactProcessor();
        } else {
            logger.debug("Instance already exists");
        }
        return instance;
    }

    /**
     * Gets the unique artifact processor instance, setting the maximum 
     * artifact age
     * 
     * @param maxArtAge maximum artifact age
     * 
     * @return this unique instance
     */
    public static SAMLArtifactProcessor getInstance(long maxArtAge) {
        maxArtifactAge = maxArtAge;
        return getInstance();
    }

    /**
     * Removes the artifact passed as a parameter
     * 
     * @param artifact artifact
     * 
     * @return the user authentication associated to the artifact (if exists)
     */
    private static SAMLUserAuthentication removeArtifactMap(String artifact) {
        SAMLUserAuthentication userAuthN = null;
        try {
            synchronized (artifactMap) {
                userAuthN = artifactMap.remove(artifact);
            }
        } catch (Exception e) {
            logger.error("Error when deleting artifact in the map");
        }
        return userAuthN;
    }

    /**
     * Creates a new artifact and put in in the map
     * 
     * @param artifact artifact
     * @param userName user name
     * @param time time
     */
    private static void createArtifactMap(String artifact, String userName, 
                                          long time) {
        try {
            synchronized (artifactMap) {
                artifactMap.put(artifact, 
                                new SAMLUserAuthentication(userName, time));
            }

        } catch (Exception e) {
            logger.error("Error when putting artifact in the map");
        }
    }

    /**
     * Creates the artifact string
     * 
     * @return the artifact
     */
    public static String createArtifact() {
        Base64 base64 = new Base64();
        String artifact = createRandomHexString(20);
        return new String(base64.encode(artifact.getBytes()));

    }

    /**
     * Consumes the artifact and returns it back (if it exists)
     * 
     * @param artifact artifact
     * 
     * @return user authentication instance
     */
    public static SAMLUserAuthentication consumeArtifact(String artifact) {
        // resolve and consume the artifact
        logger.debug("Consuming artifact (" + artifact + ")");

        SAMLUserAuthentication authentication = removeArtifactMap(artifact);

        if (authentication != null) {
            long age = 
                (new Date().getTime() / MSECS_IN_SEC) - authentication.getTime();
            // if expired set to null
            if (age > maxArtifactAge) {
                logger.debug("Artifact is out of date");
                return null;
            }
        } else {
            logger.debug("Artifact does not exist");
        }

        return authentication;
    }

    /**
     * Stores the artifact
     * 
     * @param userName user name
     *  
     * @return the artifact
     */
    public static String storeArtifact(String userName) {
        long time = new Date().getTime() / MSECS_IN_SEC;
        Base64 base64 = new Base64();
        String artifact = 
            new String(base64.encode(createRandomHexString(20).getBytes()));
        logger.debug("storeArtifact: storing artifact (" + artifact + 
                     ") for user (" + userName + ") and time (" + 
                     new Long(time).toString() + ")");
        createArtifactMap(artifact, userName, time);
        return artifact;
    }

    /**
     * Generate a random Hex for creating the artifact
     * 
     * @param size artifact size
     * 
     * @return random number
     */
    public static String createRandomHexString(int size) {
        byte[] bytes = new byte[size];
        randomGenerator.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int i = 0; i < bytes.length; i++) {
            Byte aByte = new Byte(bytes[i]);
            int intVal = Math.abs(aByte.intValue());
            sb.append(Integer.toHexString(intVal));
        }
        return sb.toString();
    }

    /**
     * Logs the artifact map
     * 
     */
    public static void logArtifactMap() {

        logger.debug("Logging Artifact Map");

        Map<String, SAMLUserAuthentication> cacheArtifactMap;

        try {
            //Set<String> userIDs = userSessions.keySet();  
            synchronized (artifactMap) {
                cacheArtifactMap = new HashMap(artifactMap);
            }

            if (!cacheArtifactMap.isEmpty()) {
                Iterator it;
                synchronized (cacheArtifactMap) {
                    it = cacheArtifactMap.keySet().iterator();
                }
                while (it.hasNext()) {

                    String userKey;
                    synchronized (it) {
                        userKey = (String)it.next();
                    }

                    SAMLUserAuthentication userAuthentication;
                    synchronized (cacheArtifactMap) {
                        userAuthentication = cacheArtifactMap.get(userKey);
                    }

                    if (userAuthentication != null) {

                        String userName = userAuthentication.getUserName();
                        long artifactTime = userAuthentication.getTime();

                        logger.debug("Artifact Entry: " + userKey + 
                                     " for user=" + userName + "; time=" + 
                                     artifactTime);
                    }

                }
            } else {
                logger.debug("Artifact Map is empty");
            }
        } catch (Exception e) {
            logger.error("Error when logging out artifacts: " + e);
        }
    }

    /**
     * Deletes no longer valid artifact in the map
     * 
     */
    public static void deleteNoLongerValidArtifact() {

        Map<String, SAMLUserAuthentication> cacheArtifactMap;

        try {
            //Set<String> userIDs = userSessions.keySet();  
            synchronized (artifactMap) {
                cacheArtifactMap = new HashMap(artifactMap);
            }

            if (!cacheArtifactMap.isEmpty()) {
                Iterator it;
                synchronized (cacheArtifactMap) {
                    it = cacheArtifactMap.keySet().iterator();
                }
                while (it.hasNext()) {

                    String userKey;
                    synchronized (it) {
                        userKey = (String)it.next();
                    }

                    SAMLUserAuthentication userAuthentication;
                    synchronized (cacheArtifactMap) {
                        userAuthentication = cacheArtifactMap.get(userKey);
                    }

                    if (userAuthentication != null) {

                        long artifactTime = userAuthentication.getTime();

                        long time = new Date().getTime() / MSECS_IN_SEC;

                        long delayTime = time - maxArtifactAge;

                        if (artifactTime < delayTime) {
                            logger.debug("Artifact [" + userKey + 
                                         "] is out of date as artifactTime[" + 
                                         artifactTime + 
                                         "] is lower than the delayTime [" + 
                                         delayTime + "]");
                            removeArtifactMap(userKey);
                        }
                    }

                }
            }
        } catch (Exception e) {
            logger.error("Error when deleting no longer valid artifacts: " + 
                         e);
        }
    }


}
