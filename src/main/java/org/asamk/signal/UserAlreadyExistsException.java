package org.asamk.signal;

public class UserAlreadyExistsException extends SignalProtocolException {
    private final String username;
    private final String fileName;

    public UserAlreadyExistsException(String username, String fileName) {
        this.username = username;
        this.fileName = fileName;
    }

    public String getUsername() {
        return username;
    }

    public String getFileName() {
        return fileName;
    }
}
