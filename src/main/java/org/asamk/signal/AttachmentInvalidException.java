package org.asamk.signal;

public class AttachmentInvalidException extends SignalProtocolException {
    public AttachmentInvalidException(String message) {
        super(message);
    }

    public AttachmentInvalidException(String attachment, Exception e) {
        super(attachment + ": " + e.getMessage());
    }
}
