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

package com.google.gsa;


/**
 * WebProcess instance used as a HTTP connection in the Authentication and 
 * Authorization modules
 * 
 */
public class WebProcessor extends IWebProcess {

    /**
     * Class constructor - default
     * 
     */
    public WebProcessor() {

        // Invoke parent constructor
        super();

    }

    /**
     * Class contructor
     * <p>
     * Support for connection management
     * 
     * @param maxConnectionsPerHost maximum number of HTTP connex per host
     * @param maxTotalConnections maximum total number of HTTP connex
     */
    public WebProcessor(int maxConnectionsPerHost, int maxTotalConnections) {

        // Invoke parent constructor
        super(maxConnectionsPerHost, maxTotalConnections);

    }


}
