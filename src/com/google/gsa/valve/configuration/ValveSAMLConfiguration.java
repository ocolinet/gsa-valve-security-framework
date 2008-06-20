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

package com.google.gsa.valve.configuration;

public class ValveSAMLConfiguration {

    private String isSAML = "false";
    private String maxArtifactAge = null;
    private String samlTimeout = null;

    public ValveSAMLConfiguration() {
    }
    
    public void setIsSAML(String isSAML) {
        this.isSAML = isSAML;
    }

    public String isSAML() {
        return isSAML;
    }

    public void setMaxArtifactAge(String maxArtifactAge) {
        this.maxArtifactAge = maxArtifactAge;
    }

    public String getMaxArtifactAge() {
        return maxArtifactAge;
    }

    public void setSamlTimeout(String samlTimeout) {
        this.samlTimeout = samlTimeout;
    }

    public String getSamlTimeout() {
        return samlTimeout;
    }
}
