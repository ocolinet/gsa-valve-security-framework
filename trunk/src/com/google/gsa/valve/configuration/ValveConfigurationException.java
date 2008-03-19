package com.google.gsa.valve.configuration;

public class ValveConfigurationException extends Exception {
    
    private String message = null;
    
    public ValveConfigurationException() {
    }
    
    public ValveConfigurationException(String message) {
        super (message);
        setMessage (message);        
    }

    private void setMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
