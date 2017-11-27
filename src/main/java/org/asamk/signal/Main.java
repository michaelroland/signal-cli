/**
 * Copyright (C) 2015 AsamK
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.asamk.signal;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.*;
import org.apache.http.util.TextUtils;
import org.asamk.Signal;
import org.asamk.signal.storage.contacts.ContactInfo;
import org.asamk.signal.storage.groups.GroupInfo;
import org.asamk.signal.storage.protocol.JsonIdentityKeyStore;
import org.asamk.signal.util.Hex;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.*;
import org.whispersystems.signalservice.api.messages.multidevice.*;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.exceptions.EncapsulatedExceptions;
import org.whispersystems.signalservice.api.push.exceptions.NetworkFailureException;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.api.util.PhoneNumberFormatter;
import org.whispersystems.signalservice.internal.util.Base64;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.security.Security;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Main {

    private static final TimeZone tzUTC = TimeZone.getTimeZone("UTC");
    private static final String DEFAULT_CONFIG_DIR = System.getProperty("user.home") + "/.config/signal";

    public static void main(String[] args) {
        // Workaround for BKS truststore
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);

        Namespace ns = parseArgs(args);
        if (ns == null) {
            System.exit(1);
        }

        int res = handleCommands(ns);
        System.exit(res);
    }

    private static int handleCommands(Namespace ns) {
        final String username = ns.getString("username");
        Manager m;
        Signal ts;
        try {
            String settingsPath = ns.getString("config");

            m = new Manager(username, settingsPath);
            ts = m;
            if (m.userExists()) {
                try {
                    m.init();
                } catch (Exception e) {
                    System.err.println("Error loading state file \"" + m.getFileName() + "\": " + e.getMessage());
                    return 2;
                }
            }

            switch (ns.getString("command")) {
                case "register":
                    if (!m.userHasKeys()) {
                        m.createNewIdentity();
                    }
                    try {
                        m.register(ns.getBoolean("voice"));
                    } catch (IOException e) {
                        System.err.println("Request verify error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "unregister":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.unregister();
                    } catch (IOException e) {
                        System.err.println("Unregister error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "updateAccount":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.updateAccountAttributes();
                    } catch (IOException e) {
                        System.err.println("UpdateAccount error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "verify":
                    if (!m.userHasKeys()) {
                        System.err.println("User has no keys, first call register.");
                        return 1;
                    }
                    if (m.isRegistered()) {
                        System.err.println("User registration is already verified");
                        return 1;
                    }
                    try {
                        m.verifyAccount(ns.getString("verificationCode"));
                    } catch (IOException e) {
                        System.err.println("Verify error: " + e.getMessage());
                        return 3;
                    }
                    break;
                case "link":
                    // When linking, username is null and we always have to create keys
                    m.createNewIdentity();

                    String deviceName = ns.getString("name");
                    if (deviceName == null) {
                        deviceName = "cli";
                    }
                    try {
                        System.out.println(m.getDeviceLinkUri());
                        m.finishDeviceLink(deviceName);
                        System.out.println("Associated with: " + m.getUsername());
                    } catch (TimeoutException e) {
                        System.err.println("Link request timed out, please try again.");
                        return 3;
                    } catch (IOException e) {
                        System.err.println("Link request error: " + e.getMessage());
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        return 2;
                    } catch (UserAlreadyExists e) {
                        System.err.println("The user " + e.getUsername() + " already exists\nDelete \"" + e.getFileName() + "\" before trying again.");
                        return 1;
                    }
                    break;
                case "addDevice":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        m.addDeviceLink(new URI(ns.getString("uri")));
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                        return 2;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                        return 2;
                    }
                    break;
                case "listDevices":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        List<DeviceInfo> devices = m.getLinkedDevices();
                        for (DeviceInfo d : devices) {
                            System.out.println("Device " + d.getId() + (d.getId() == m.getDeviceId() ? " (this device)" : "") + ":");
                            System.out.println(" Name: " + d.getName());
                            System.out.println(" Created: " + formatTimestamp(d.getCreated()));
                            System.out.println(" Last seen: " + formatTimestamp(d.getLastSeen()));
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    }
                    break;
                case "removeDevice":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    try {
                        int deviceId = ns.getInt("deviceId");
                        m.removeLinkedDevices(deviceId);
                    } catch (IOException e) {
                        e.printStackTrace();
                        return 3;
                    }
                    break;
                case "send":
                    if (ns.getBoolean("endsession")) {
                        if (ns.getList("recipient") == null) {
                            System.err.println("No recipients given");
                            System.err.println("Aborting sending.");
                            return 1;
                        }
                        try {
                            ts.sendEndSessionMessage(ns.<String>getList("recipient"));
                        } catch (IOException e) {
                            handleIOException(e);
                            return 3;
                        } catch (EncapsulatedExceptions e) {
                            handleEncapsulatedExceptions(e);
                            return 3;
                        } catch (AssertionError e) {
                            handleAssertionError(e);
                            return 1;
                        }
                    } else {
                        String messageText = ns.getString("message");
                        if (messageText == null) {
                            try {
                                messageText = readAll(System.in);
                            } catch (IOException e) {
                                System.err.println("Failed to read message from stdin: " + e.getMessage());
                                System.err.println("Aborting sending.");
                                return 1;
                            }
                        }

                        try {
                            List<String> attachments = ns.getList("attachment");
                            if (attachments == null) {
                                attachments = new ArrayList<>();
                            }
                            if (ns.getString("group") != null) {
                                byte[] groupId = decodeGroupId(ns.getString("group"));
                                ts.sendGroupMessage(messageText, attachments, groupId);
                            } else {
                                ts.sendMessage(messageText, attachments, ns.<String>getList("recipient"));
                            }
                        } catch (IOException e) {
                            handleIOException(e);
                            return 3;
                        } catch (EncapsulatedExceptions e) {
                            handleEncapsulatedExceptions(e);
                            return 3;
                        } catch (AssertionError e) {
                            handleAssertionError(e);
                            return 1;
                        } catch (GroupNotFoundException e) {
                            handleGroupNotFoundException(e);
                            return 1;
                        } catch (NotAGroupMemberException e) {
                            handleNotAGroupMemberException(e);
                            return 1;
                        } catch (AttachmentInvalidException e) {
                            System.err.println("Failed to add attachment: " + e.getMessage());
                            System.err.println("Aborting sending.");
                            return 1;
                        }
                    }

                    break;
                case "receive":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    double timeout = 5;
                    if (ns.getDouble("timeout") != null) {
                        timeout = ns.getDouble("timeout");
                    }
                    boolean returnOnTimeout = true;
                    if (timeout < 0) {
                        returnOnTimeout = false;
                        timeout = 3600;
                    }
                    boolean ignoreAttachments = ns.getBoolean("ignore_attachments");
                    try {
                        final Manager.ReceiveMessageHandler handler = ns.getBoolean("json") ? new JsonReceiveMessageHandler(m) : new ReceiveMessageHandler(m);
                        m.receiveMessages((long) (timeout * 1000), TimeUnit.MILLISECONDS, returnOnTimeout, ignoreAttachments, handler);
                    } catch (IOException e) {
                        System.err.println("Error while receiving messages: " + e.getMessage());
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    }
                    break;
                case "quitGroup":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }

                    try {
                        m.sendQuitGroupMessage(decodeGroupId(ns.getString("group")));
                    } catch (IOException e) {
                        handleIOException(e);
                        return 3;
                    } catch (EncapsulatedExceptions e) {
                        handleEncapsulatedExceptions(e);
                        return 3;
                    } catch (AssertionError e) {
                        handleAssertionError(e);
                        return 1;
                    } catch (GroupNotFoundException e) {
                        handleGroupNotFoundException(e);
                        return 1;
                    } catch (NotAGroupMemberException e) {
                        handleNotAGroupMemberException(e);
                        return 1;
                    }

                    break;
                case "updateGroup":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }

                    try {
                        byte[] groupId = null;
                        if (ns.getString("group") != null) {
                            groupId = decodeGroupId(ns.getString("group"));
                        }
                        if (groupId == null) {
                            groupId = new byte[0];
                        }
                        String groupName = ns.getString("name");
                        if (groupName == null) {
                            groupName = "";
                        }
                        List<String> groupMembers = ns.<String>getList("member");
                        if (groupMembers == null) {
                            groupMembers = new ArrayList<String>();
                        }
                        String groupAvatar = ns.getString("avatar");
                        if (groupAvatar == null) {
                            groupAvatar = "";
                        }
                        byte[] newGroupId = ts.updateGroup(groupId, groupName, groupMembers, groupAvatar);
                        if (groupId.length != newGroupId.length) {
                            System.out.println("Creating new group \"" + Base64.encodeBytes(newGroupId) + "\" …");
                        }
                    } catch (IOException e) {
                        handleIOException(e);
                        return 3;
                    } catch (AttachmentInvalidException e) {
                        System.err.println("Failed to add avatar attachment for group\": " + e.getMessage());
                        System.err.println("Aborting sending.");
                        return 1;
                    } catch (GroupNotFoundException e) {
                        handleGroupNotFoundException(e);
                        return 1;
                    } catch (NotAGroupMemberException e) {
                        handleNotAGroupMemberException(e);
                        return 1;
                    } catch (EncapsulatedExceptions e) {
                        handleEncapsulatedExceptions(e);
                        return 3;
                    }

                    break;
                case "listGroups":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }

                    List<GroupInfo> groups = m.getGroups();
                    boolean detailed = ns.getBoolean("detailed");

                    for (GroupInfo group : groups) {
                        printGroup(group, detailed);
                    }
                    break;
                case "listIdentities":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    if (ns.get("number") == null) {
                        for (Map.Entry<String, List<JsonIdentityKeyStore.Identity>> keys : m.getIdentities().entrySet()) {
                            for (JsonIdentityKeyStore.Identity id : keys.getValue()) {
                                printIdentityFingerprint(m, keys.getKey(), id);
                            }
                        }
                    } else {
                        String number = ns.getString("number");
                        for (JsonIdentityKeyStore.Identity id : m.getIdentities(number)) {
                            printIdentityFingerprint(m, number, id);
                        }
                    }
                    break;
                case "trust":
                    if (!m.isRegistered()) {
                        System.err.println("User is not registered.");
                        return 1;
                    }
                    String number = ns.getString("number");
                    if (ns.getBoolean("trust_all_known_keys")) {
                        boolean res = m.trustIdentityAllKeys(number);
                        if (!res) {
                            System.err.println("Failed to set the trust for this number, make sure the number is correct.");
                            return 1;
                        }
                    } else {
                        String fingerprint = ns.getString("verified_fingerprint");
                        if (fingerprint != null) {
                            fingerprint = fingerprint.replaceAll(" ", "");
                            if (fingerprint.length() == 66) {
                                byte[] fingerprintBytes;
                                try {
                                    fingerprintBytes = Hex.toByteArray(fingerprint.toLowerCase(Locale.ROOT));
                                } catch (Exception e) {
                                    System.err.println("Failed to parse the fingerprint, make sure the fingerprint is a correctly encoded hex string without additional characters.");
                                    return 1;
                                }
                                boolean res = m.trustIdentityVerified(number, fingerprintBytes);
                                if (!res) {
                                    System.err.println("Failed to set the trust for the fingerprint of this number, make sure the number and the fingerprint are correct.");
                                    return 1;
                                }
                            } else if (fingerprint.length() == 60) {
                                boolean res = m.trustIdentityVerifiedSafetyNumber(number, fingerprint);
                                if (!res) {
                                    System.err.println("Failed to set the trust for the safety number of this phone number, make sure the phone number and the safety number are correct.");
                                    return 1;
                                }
                            } else {
                                System.err.println("Fingerprint has invalid format, either specify the old hex fingerprint or the new safety number");
                                return 1;
                            }
                        } else {
                            System.err.println("You need to specify the fingerprint you have verified with -v FINGERPRINT");
                            return 1;
                        }
                    }
                    break;
            }
            return 0;
        } finally {
            // cleanup code
        }
    }

    private static void printIdentityFingerprint(Manager m, String theirUsername, JsonIdentityKeyStore.Identity theirId) {
        String digits = formatSafetyNumber(m.computeSafetyNumber(theirUsername, theirId.getIdentityKey()));
        System.out.println(String.format("%s: %s Added: %s Fingerprint: %s Safety Number: %s", theirUsername,
                theirId.getTrustLevel(), theirId.getDateAdded(), Hex.toStringCondensed(theirId.getFingerprint()), digits));
    }

    private static void printGroup(GroupInfo group, boolean detailed) {
        if (detailed) {
            System.out.println(String.format("Id: %s Name: %s  Active: %s Members: %s",
                    Base64.encodeBytes(group.groupId), group.name, group.active, group.members));
        } else {
            System.out.println(String.format("Id: %s Name: %s  Active: %s", Base64.encodeBytes(group.groupId),
                    group.name, group.active));
        }
    }

    private static String formatSafetyNumber(String digits) {
        final int partCount = 12;
        int partSize = digits.length() / partCount;
        StringBuilder f = new StringBuilder(digits.length() + partCount);
        for (int i = 0; i < partCount; i++) {
            f.append(digits.substring(i * partSize, (i * partSize) + partSize)).append(" ");
        }
        return f.toString();
    }

    private static void handleGroupNotFoundException(GroupNotFoundException e) {
        System.err.println("Failed to send to group: " + e.getMessage());
        System.err.println("Aborting sending.");
    }

    private static void handleNotAGroupMemberException(NotAGroupMemberException e) {
        System.err.println("Failed to send to group: " + e.getMessage());
        System.err.println("Update the group on another device to readd the user to this group.");
        System.err.println("Aborting sending.");
    }

    private static byte[] decodeGroupId(String groupId) {
        try {
            return Base64.decode(groupId);
        } catch (IOException e) {
            System.err.println("Failed to decode groupId (must be base64) \"" + groupId + "\": " + e.getMessage());
            System.err.println("Aborting sending.");
            System.exit(1);
            return null;
        }
    }

    private static Namespace parseArgs(String[] args) {
        ArgumentParser parser = ArgumentParsers.newArgumentParser("signal-client")
                .defaultHelp(true)
                .description("Signal Command-Line Client")
                .version(Manager.PROJECT_NAME + " " + Manager.PROJECT_VERSION);

        parser.addArgument("-v", "--version")
                .help("Show package version")
                .action(Arguments.version());
        parser.addArgument("--config")
                .setDefault(DEFAULT_CONFIG_DIR)
                .help("Set the path, where to store the config");

        MutuallyExclusiveGroup mut = parser.addMutuallyExclusiveGroup();
        mut.addArgument("-u", "--username")
                .help("Specify your phone number, that will be used for verification");

        Subparsers subparsers = parser.addSubparsers()
                .title("subcommands")
                .dest("command")
                .description("valid subcommands")
                .help("additional help");

        Subparser parserLink = subparsers.addParser("link")
                .help("Register this device as new linked device");
        parserLink.addArgument("-n", "--name")
                .help("Specify a name to describe this new device");

        Subparser parserAddDevice = subparsers.addParser("addDevice")
                .help("Add a new linked device");
        parserAddDevice.addArgument("--uri")
                .required(true)
                .help("Specify the URI contained in the QR code shown by the new device");

        Subparser parserDevices = subparsers.addParser("listDevices")
                .help("List registered device IDs");

        Subparser parserRemoveDevice = subparsers.addParser("removeDevice")
                .help("Remove a registered device");
        parserRemoveDevice.addArgument("-d", "--deviceId")
                .type(int.class)
                .required(true)
                .help("Specify the device you want to remove; use listDevices to see the device IDs");

        Subparser parserRegister = subparsers.addParser("register")
                .help("Register this device as new primary device");
        parserRegister.addArgument("-v", "--voice")
                .help("Perform verification over voice instead of SMS")
                .action(Arguments.storeTrue());

        Subparser parserUnregister = subparsers.addParser("unregister")
                .help("Unregister this device from the Signal server");

        Subparser parserUpdateAccount = subparsers.addParser("updateAccount")
                .help("Update the account attributes on the Signal server");

        Subparser parserVerify = subparsers.addParser("verify")
                .help("Perform the account verification step");
        parserVerify.addArgument("verificationCode")
                .help("The verification code you received via SMS or voice call");

        Subparser parserSend = subparsers.addParser("send")
                .help("Send a message");
        parserSend.addArgument("-g", "--group")
                .help("Specify the recipient group ID");
        parserSend.addArgument("recipient")
                .help("Specify the recipients' phone number")
                .nargs("*");
        parserSend.addArgument("-m", "--message")
                .help("Specify the message; if absent, message is read from standard input");
        parserSend.addArgument("-a", "--attachment")
                .nargs("*")
                .help("Add file as attachment");
        parserSend.addArgument("-e", "--endsession")
                .help("Clear session state and send end session message")
                .action(Arguments.storeTrue());

        Subparser parserLeaveGroup = subparsers.addParser("quitGroup")
                .help("Leave a group");
        parserLeaveGroup.addArgument("-g", "--group")
                .required(true)
                .help("Specify the recipient group ID");

        Subparser parserUpdateGroup = subparsers.addParser("updateGroup")
                .help("Update a group");
        parserUpdateGroup.addArgument("-g", "--group")
                .help("Specify the recipient group ID");
        parserUpdateGroup.addArgument("-n", "--name")
                .help("Specify the new group name");
        parserUpdateGroup.addArgument("-a", "--avatar")
                .help("Specify a new group avatar image file");
        parserUpdateGroup.addArgument("-m", "--member")
                .nargs("*")
                .help("Specify one or more members to add to the group");

        Subparser parserListGroups = subparsers.addParser("listGroups")
                .help("List all groups");
        parserListGroups.addArgument("-d", "--detailed").action(Arguments.storeTrue())
                .help("List members of each group");
        parserListGroups.help("List group name and IDs");

        Subparser parserListIdentities = subparsers.addParser("listIdentities")
                .help("List identities");
        parserListIdentities.addArgument("-n", "--number")
                .help("Only show identity keys for the given phone number");

        Subparser parserTrust = subparsers.addParser("trust")
                .help("Update user trust");
        parserTrust.addArgument("number")
                .help("Specify the phone number, for which to set the trust")
                .required(true);
        MutuallyExclusiveGroup mutTrust = parserTrust.addMutuallyExclusiveGroup();
        mutTrust.addArgument("-a", "--trust-all-known-keys")
                .help("Trust all known keys of this user, only use this for testing")
                .action(Arguments.storeTrue());
        mutTrust.addArgument("-v", "--verified-fingerprint")
                .help("Specify the fingerprint of the key, only use this option if you have verified the fingerprint");

        Subparser parserReceive = subparsers.addParser("receive")
                .help("Receive messages");
        parserReceive.addArgument("-t", "--timeout")
                .type(double.class)
                .help("Number of seconds to wait for new messages (negative values disable timeout)");
        parserReceive.addArgument("--ignore-attachments")
                .help("Don't download attachments of received messages")
                .action(Arguments.storeTrue());
        parserReceive.addArgument("--json")
                .help("Output received messages in json format, one json object per line")
                .action(Arguments.storeTrue());

        try {
            Namespace ns = parser.parseArgs(args);
            if ("link".equals(ns.getString("command"))) {
                if (ns.getString("username") != null) {
                    parser.printUsage();
                    System.err.println("You cannot specify a username (phone number) when linking");
                    System.exit(2);
                }
            } else {
                if (ns.getString("username") == null) {
                    parser.printUsage();
                    System.err.println("You need to specify a username (phone number)");
                    System.exit(2);
                }
                if (!PhoneNumberFormatter.isValidNumber(ns.getString("username"))) {
                    System.err.println("Invalid username (phone number), make sure you include the country code.");
                    System.exit(2);
                }
            }
            if (ns.getList("recipient") != null && !ns.getList("recipient").isEmpty() && ns.getString("group") != null) {
                System.err.println("You cannot specify recipients by phone number and groups at the same time");
                System.exit(2);
            }
            return ns;
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            return null;
        }
    }

    private static void handleAssertionError(AssertionError e) {
        System.err.println("Failed to send/receive message (Assertion): " + e.getMessage());
        e.printStackTrace();
        System.err.println("If you use an Oracle JRE please check if you have unlimited strength crypto enabled, see README");
    }

    private static void handleEncapsulatedExceptions(EncapsulatedExceptions e) {
        System.err.println("Failed to send (some) messages:");
        for (NetworkFailureException n : e.getNetworkExceptions()) {
            System.err.println("Network failure for \"" + n.getE164number() + "\": " + n.getMessage());
        }
        for (UnregisteredUserException n : e.getUnregisteredUserExceptions()) {
            System.err.println("Unregistered user \"" + n.getE164Number() + "\": " + n.getMessage());
        }
        for (UntrustedIdentityException n : e.getUntrustedIdentityExceptions()) {
            System.err.println("Untrusted Identity for \"" + n.getE164Number() + "\": " + n.getMessage());
        }
    }

    private static void handleIOException(IOException e) {
        System.err.println("Failed to send message: " + e.getMessage());
    }

    private static String readAll(InputStream in) throws IOException {
        StringWriter output = new StringWriter();
        byte[] buffer = new byte[4096];
        long count = 0;
        int n;
        while (-1 != (n = System.in.read(buffer))) {
            output.write(new String(buffer, 0, n, Charset.defaultCharset()));
            count += n;
        }
        return output.toString();
    }

    private static class ReceiveMessageHandler implements Manager.ReceiveMessageHandler {
        final Manager m;

        public ReceiveMessageHandler(Manager m) {
            this.m = m;
        }

        @Override
        public void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, Throwable exception) {
            SignalServiceAddress source = envelope.getSourceAddress();
            ContactInfo sourceContact = m.getContact(source.getNumber());
            System.out.println(String.format("Envelope from: %s (device: %d)", (sourceContact == null ? "" : "“" + sourceContact.name + "” ") + source.getNumber(), envelope.getSourceDevice()));
            if (source.getRelay().isPresent()) {
                System.out.println("Relayed by: " + source.getRelay().get());
            }
            System.out.println("Timestamp: " + formatTimestamp(envelope.getTimestamp()));

            if (envelope.isReceipt()) {
                System.out.println("Got receipt.");
            } else if (envelope.isSignalMessage() | envelope.isPreKeySignalMessage()) {
                if (exception != null) {
                    if (exception instanceof org.whispersystems.libsignal.UntrustedIdentityException) {
                        org.whispersystems.libsignal.UntrustedIdentityException e = (org.whispersystems.libsignal.UntrustedIdentityException) exception;
                        System.out.println("The user's key is untrusted, either the user has reinstalled Signal or a third party sent this message.");
                        System.out.println("Use 'signal-client -u " + m.getUsername() + " listIdentities -n " + e.getName() + "', verify the key and run 'signal-client -u " + m.getUsername() + " trust -v \"FINGER_PRINT\" " + e.getName() + "' to mark it as trusted");
                        System.out.println("If you don't care about security, use 'signal-client -u " + m.getUsername() + " trust -a " + e.getName() + "' to trust it without verification");
                    } else {
                        System.out.println("Exception: " + exception.getMessage() + " (" + exception.getClass().getSimpleName() + ")");
                    }
                }
                if (content == null) {
                    System.out.println("Failed to decrypt message.");
                } else {
                    if (content.getDataMessage().isPresent()) {
                        SignalServiceDataMessage message = content.getDataMessage().get();
                        handleSignalServiceDataMessage(message);
                    }
                    if (content.getSyncMessage().isPresent()) {
                        System.out.println("Received a sync message");
                        SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();

                        if (syncMessage.getContacts().isPresent()) {
                            final ContactsMessage contactsMessage = syncMessage.getContacts().get();
                            if (contactsMessage.isComplete()) {
                                System.out.println("Received complete sync contacts");
                            } else {
                                System.out.println("Received sync contacts");
                            }
                            printAttachment(contactsMessage.getContactsStream());
                        }
                        if (syncMessage.getGroups().isPresent()) {
                            System.out.println("Received sync groups");
                            printAttachment(syncMessage.getGroups().get());
                        }
                        if (syncMessage.getRead().isPresent()) {
                            System.out.println("Received sync read messages list");
                            for (ReadMessage rm : syncMessage.getRead().get()) {
                                ContactInfo fromContact = m.getContact(rm.getSender());
                                System.out.println("From: " + (fromContact == null ? "" : "“" + fromContact.name + "” ") + rm.getSender() + " Message timestamp: " + formatTimestamp(rm.getTimestamp()));
                            }
                        }
                        if (syncMessage.getRequest().isPresent()) {
                            System.out.println("Received sync request");
                            if (syncMessage.getRequest().get().isContactsRequest()) {
                                System.out.println(" - contacts request");
                            }
                            if (syncMessage.getRequest().get().isGroupsRequest()) {
                                System.out.println(" - groups request");
                            }
                        }
                        if (syncMessage.getSent().isPresent()) {
                            System.out.println("Received sync sent message");
                            final SentTranscriptMessage sentTranscriptMessage = syncMessage.getSent().get();
                            String to;
                            if (sentTranscriptMessage.getDestination().isPresent()) {
                                String dest = sentTranscriptMessage.getDestination().get();
                                ContactInfo destContact = m.getContact(dest);
                                to = (destContact == null ? "" : "“" + destContact.name + "” ") + dest;
                            } else {
                                to = "Unknown";
                            }
                            System.out.println("To: " + to + " , Message timestamp: " + formatTimestamp(sentTranscriptMessage.getTimestamp()));
                            if (sentTranscriptMessage.getExpirationStartTimestamp() > 0) {
                                System.out.println("Expiration started at: " + formatTimestamp(sentTranscriptMessage.getExpirationStartTimestamp()));
                            }
                            SignalServiceDataMessage message = sentTranscriptMessage.getMessage();
                            handleSignalServiceDataMessage(message);
                        }
                        if (syncMessage.getBlockedList().isPresent()) {
                            System.out.println("Received sync message with block list");
                            System.out.println("Blocked numbers:");
                            final BlockedListMessage blockedList = syncMessage.getBlockedList().get();
                            for (String number : blockedList.getNumbers()) {
                                System.out.println(" - " + number);
                            }
                        }
                        if (syncMessage.getVerified().isPresent()) {
                            System.out.println("Received sync message with verified identities:");
                            final VerifiedMessage verifiedMessage = syncMessage.getVerified().get();
                            System.out.println(" - " + verifiedMessage.getDestination() + ": " + verifiedMessage.getVerified());
                            String safetyNumber = formatSafetyNumber(m.computeSafetyNumber(verifiedMessage.getDestination(), verifiedMessage.getIdentityKey()));
                            System.out.println("   " + safetyNumber);
                        }
                    }
                }
            } else {
                System.out.println("Unknown message received.");
            }
            System.out.println();
        }

        private void handleSignalServiceDataMessage(SignalServiceDataMessage message) {
            System.out.println("Message timestamp: " + formatTimestamp(message.getTimestamp()));

            if (message.getBody().isPresent()) {
                System.out.println("Body: " + message.getBody().get());
            }
            if (message.getGroupInfo().isPresent()) {
                SignalServiceGroup groupInfo = message.getGroupInfo().get();
                System.out.println("Group info:");
                System.out.println("  Id: " + Base64.encodeBytes(groupInfo.getGroupId()));
                if (groupInfo.getType() == SignalServiceGroup.Type.UPDATE && groupInfo.getName().isPresent()) {
                    System.out.println("  Name: " + groupInfo.getName().get());
                } else {
                    GroupInfo group = m.getGroup(groupInfo.getGroupId());
                    if (group != null) {
                        System.out.println("  Name: " + group.name);
                    } else {
                        System.out.println("  Name: <Unknown group>");
                    }
                }
                System.out.println("  Type: " + groupInfo.getType());
                if (groupInfo.getMembers().isPresent()) {
                    for (String member : groupInfo.getMembers().get()) {
                        System.out.println("  Member: " + member);
                    }
                }
                if (groupInfo.getAvatar().isPresent()) {
                    System.out.println("  Avatar:");
                    printAttachment(groupInfo.getAvatar().get());
                }
            }
            if (message.isEndSession()) {
                System.out.println("Is end session");
            }
            if (message.isExpirationUpdate()) {
                System.out.println("Is Expiration update: " + message.isExpirationUpdate());
            }
            if (message.getExpiresInSeconds() > 0) {
                System.out.println("Expires in: " + message.getExpiresInSeconds() + " seconds");
            }

            if (message.getAttachments().isPresent()) {
                System.out.println("Attachments: ");
                for (SignalServiceAttachment attachment : message.getAttachments().get()) {
                    printAttachment(attachment);
                }
            }
        }

        private void printAttachment(SignalServiceAttachment attachment) {
            System.out.println("- " + attachment.getContentType() + " (" + (attachment.isPointer() ? "Pointer" : "") + (attachment.isStream() ? "Stream" : "") + ")");
            if (attachment.isPointer()) {
                final SignalServiceAttachmentPointer pointer = attachment.asPointer();
                System.out.println("  Id: " + pointer.getId() + " Key length: " + pointer.getKey().length + (pointer.getRelay().isPresent() ? " Relay: " + pointer.getRelay().get() : ""));
                System.out.println("  Filename: " + (pointer.getFileName().isPresent() ? pointer.getFileName().get() : "-"));
                System.out.println("  Size: " + (pointer.getSize().isPresent() ? pointer.getSize().get() + " bytes" : "<unavailable>") + (pointer.getPreview().isPresent() ? " (Preview is available: " + pointer.getPreview().get().length + " bytes)" : ""));
                System.out.println("  Voice note: " + (pointer.getVoiceNote() ? "yes" : "no"));
                File file = m.getAttachmentFile(pointer.getId());
                if (file.exists()) {
                    System.out.println("  Stored plaintext in: " + file);
                }
            }
        }
    }

    private static class JsonReceiveMessageHandler implements Manager.ReceiveMessageHandler {
        final Manager m;
        final ObjectMapper jsonProcessor;

        public JsonReceiveMessageHandler(Manager m) {
            this.m = m;
            this.jsonProcessor = new ObjectMapper();
            jsonProcessor.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY); // disable autodetect
            jsonProcessor.enable(SerializationFeature.WRITE_NULL_MAP_VALUES);
            jsonProcessor.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
            jsonProcessor.disable(JsonGenerator.Feature.AUTO_CLOSE_TARGET);
        }

        @Override
        public void handleMessage(SignalServiceEnvelope envelope, SignalServiceContent content, Throwable exception) {
            ObjectNode result = jsonProcessor.createObjectNode();
            if (exception != null) {
                result.putPOJO("error", new JsonError(exception));
            }
            if (envelope != null) {
                result.putPOJO("envelope", new JsonMessageEnvelope(envelope, content));
            }
            try {
                jsonProcessor.writeValue(System.out, result);
                System.out.println();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static String formatTimestamp(long timestamp) {
        Date date = new Date(timestamp);
        final DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"); // Quoted "Z" to indicate UTC, no timezone offset
        df.setTimeZone(tzUTC);
        return timestamp + " (" + df.format(date) + ")";
    }
}
