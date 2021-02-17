package com.evolveum.polygon.connector.ldap;

/**
 * Exception used to request operation retry with connection re-connect.
 * It is a RuntimeException, although it should be checked exception.
 * But all ConnId exceptions are runtime, and we want to avoid crazy class casts and instanceofs.
 */
@SuppressWarnings("unused")
public class ReconnectException extends RuntimeException {

    public ReconnectException(String message) {
        super(message);
    }

    public ReconnectException(String message, Throwable cause) {
        super(message, cause);
    }
}
