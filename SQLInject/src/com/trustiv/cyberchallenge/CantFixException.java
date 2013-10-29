/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.trustiv.cyberchallenge;

/**
 *
 * @author james
 */
public class CantFixException extends Exception {
    public CantFixException() {
        super();
    }
    
    public CantFixException(String msg) {
        super(msg);
    }

    public CantFixException(Throwable cause) {
        super(cause);
    }

    public CantFixException(String message, Throwable cause) {
        super(message, cause);
    }
}
