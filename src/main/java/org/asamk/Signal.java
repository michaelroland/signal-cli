package org.asamk;

import org.asamk.signal.AttachmentInvalidException;
import org.asamk.signal.GroupNotFoundException;
import org.whispersystems.signalservice.api.push.exceptions.EncapsulatedExceptions;

import java.io.IOException;
import java.util.List;
import org.asamk.signal.NotAGroupMemberException;

public interface Signal {
    void sendMessage(String message, List<String> attachments, String recipient) throws EncapsulatedExceptions, AttachmentInvalidException, IOException;

    void sendMessage(String message, List<String> attachments, List<String> recipients) throws EncapsulatedExceptions, AttachmentInvalidException, IOException;

    void sendEndSessionMessage(List<String> recipients) throws IOException, EncapsulatedExceptions;

    void sendGroupMessage(String message, List<String> attachments, byte[] groupId) throws EncapsulatedExceptions, GroupNotFoundException, NotAGroupMemberException, AttachmentInvalidException, IOException;

    String getContactName(String number);

    void setContactName(String number, String name);

    String getGroupName(byte[] groupId);

    List<String> getGroupMembers(byte[] groupId);

    byte[] updateGroup(byte[] groupId, String name, List<String> members, String avatar) throws IOException, EncapsulatedExceptions, GroupNotFoundException, NotAGroupMemberException, AttachmentInvalidException;

    class MessageReceived {
        private long timestamp;
        private String sender;
        private byte[] groupId;
        private String message;
        private List<String> attachments;

        public MessageReceived(String objectpath, long timestamp, String sender, byte[] groupId, String message, List<String> attachments) {
            this.timestamp = timestamp;
            this.sender = sender;
            this.groupId = groupId;
            this.message = message;
            this.attachments = attachments;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getSender() {
            return sender;
        }

        public byte[] getGroupId() {
            return groupId;
        }

        public String getMessage() {
            return message;
        }

        public List<String> getAttachments() {
            return attachments;
        }
    }

    class ReceiptReceived {
        private long timestamp;
        private String sender;

        public ReceiptReceived(String objectpath, long timestamp, String sender) {
            this.timestamp = timestamp;
            this.sender = sender;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getSender() {
            return sender;
        }
    }
}
