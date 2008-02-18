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

public class ValveKerberosConfiguration {
    
    private String isKerberos = null;
    private String isNegotiate = null;
    private String krbini = null;
    private String krbconfig = null;
    private String krbAdditionalAuthN = null;
    private String krbLoginUrl = null;
    private String krbUsrPwdCrawler = null;   
    private String krbUsrPwdCrawlerUrl = null;
    
    public ValveKerberosConfiguration() {
    }


    public void setIsKerberos(String isKerberos) {
        this.isKerberos = isKerberos;
    }

    public String isKerberos() {
        return isKerberos;
    }

    public void setIsNegotiate(String isNegotiate) {
        this.isNegotiate = isNegotiate;
    }

    public String isNegotiate() {
        return isNegotiate;
    }

    public void setKrbini(String krbini) {
        this.krbini = krbini;
    }

    public String getKrbini() {
        return krbini;
    }

    public void setKrbconfig(String krbconfig) {
        this.krbconfig = krbconfig;
    }

    public String getKrbconfig() {
        return krbconfig;
    }

    public void setKrbAdditionalAuthN(String krbAdditionalAuthN) {
        this.krbAdditionalAuthN = krbAdditionalAuthN;
    }

    public String isKrbAdditionalAuthN() {
        return krbAdditionalAuthN;
    }

    public void setKrbLoginUrl(String krbLoginUrl) {
        this.krbLoginUrl = krbLoginUrl;
    }

    public String getKrbLoginUrl() {
        return krbLoginUrl;
    }

    public void setKrbUsrPwdCrawler(String krbUsrPwdCrawler) {
        this.krbUsrPwdCrawler = krbUsrPwdCrawler;
    }

    public String isKrbUsrPwdCrawler() {
        return krbUsrPwdCrawler;
    }

    public void setKrbUsrPwdCrawlerUrl(String krbUsrPwdCrawlerUrl) {
        this.krbUsrPwdCrawlerUrl = krbUsrPwdCrawlerUrl;
    }

    public String getKrbUsrPwdCrawlerUrl() {
        return krbUsrPwdCrawlerUrl;
    }
}
