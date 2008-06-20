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

import com.google.gsa.valve.saml.SAMLArtifactProcessor;

import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;

/**
 * This class implements an TimerTask to avoid any kind of memory leak 
 * when consuming the artifact vector.
 * 
 */
public class ArtifactTimer extends TimerTask {

    //singleton
    private static ArtifactTimer instance = null;

    //Timing
    private Timer timer = new Timer();
    private static boolean isTimeSet = false;
    public static final long MILLS_IN_SEC = 1000;
    public static final long SEC_IN_MIN = 60;
    public static final long MIN_IN_DAY = (24 * 60);

    //This is the default interval: once per day just to avoid any kind of memory leak
    private static final long interval = 
        MIN_IN_DAY * SEC_IN_MIN * MILLS_IN_SEC;

    //Logger
    private static Logger logger = null;

    /**
     * Gets the unique timer instance
     * 
     * @return artifact timer instance
     */
    public static ArtifactTimer getInstance() {
        //Instantiate logger
        if (logger == null) {
            logger = Logger.getLogger(ArtifactTimer.class);
        }

        if (instance == null) {
            logger.debug("ArtifactTimer Instance does not exist yet. Creating");
            instance = new ArtifactTimer();
        } else {
            logger.debug("ArtifactSession Instance already exists");
        }
        return instance;
    }

    /**
     * Class constructor
     * 
     */
    protected ArtifactTimer() {
        //Instantiate logger
        if (logger == null) {
            logger = Logger.getLogger(ArtifactTimer.class);
        }
        setIsTimeSet(false);
        logger.debug("SessionTimer instance created");
    }

    /**
     * Sets if the time is set
     * 
     * @param isTimeSet boolean
     */
    public void setIsTimeSet(boolean isTimeSet) {
        this.isTimeSet = isTimeSet;
    }

    /**
     * Gets if the time is already set
     * 
     * @return boolean
     */
    public boolean getIsTimeSet() {
        return isTimeSet;
    }

    /**
     * Gets the time interval
     * 
     * @return time interval
     */
    public long getInterval() {
        return interval;
    }

    /**
     * run method. Executes the timing logic
     * 
     */
    public void run() {
        //Execute session cleanup
        logger.debug("ArtifactTimer cleaning up process");
        try {
            SAMLArtifactProcessor.getInstance().deleteNoLongerValidArtifact();
        } catch (Exception ex) {
            logger.error("Error during Artifact cleaning up process");
        } finally {
        }

    }

    /**
     * Sets timer
     * 
     */
    public void setTimer() {
        if (!isTimeSet) {
            logger.debug("SetTimer: Setting schedule process");
            timer.scheduleAtFixedRate(instance, 0, interval);
            setIsTimeSet(true);
        }
    }

    /**
     * Cancels
     * 
     * @return true
     */
    public boolean cancel() {
        logger.debug("SessionTimer: cancel");
        return true;
    }

}

