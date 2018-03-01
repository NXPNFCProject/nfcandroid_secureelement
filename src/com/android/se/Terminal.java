/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (c) 2015-2017, The Linux Foundation.
 */

/*
 * Contributed by: Giesecke & Devrient GmbH.
 */

package com.android.se;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.secure_element.V1_0.ISecureElement;
import android.hardware.secure_element.V1_0.ISecureElementHalCallback;
import android.hardware.secure_element.V1_0.LogicalChannelResponse;
import android.hardware.secure_element.V1_0.SecureElementStatus;
import android.os.RemoteException;
import android.os.ServiceSpecificException;
import android.se.omapi.ISecureElementListener;
import android.se.omapi.ISecureElementReader;
import android.se.omapi.ISecureElementSession;
import android.se.omapi.SEService;
import android.util.Log;

import com.android.se.SecureElementService.SecureElementSession;
import com.android.se.internal.ByteArrayConverter;
import com.android.se.security.AccessControlEnforcer;
import com.android.se.security.ChannelAccess;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * Each Terminal represents a Secure Element.
 * Communicates to the SE via SecureElement HAL.
 */
public class Terminal {

    private final String mTag;
    private final Map<Integer, Channel> mChannels = new HashMap<Integer, Channel>();
    private final Object mLock = new Object();
    private final String mName;
    public boolean mIsConnected = false;
    private Context mContext;
    private boolean mDefaultApplicationSelectedOnBasicChannel = true;

    private boolean mDebug = true;

    private ISecureElement mSEHal;

    /** For each Terminal there will be one AccessController object. */
    private AccessControlEnforcer mAccessControlEnforcer;

    private ISecureElementHalCallback.Stub mHalCallback = new ISecureElementHalCallback.Stub() {
        @Override
        public void onStateChange(boolean state) {
            synchronized (mLock) {
                Log.i(mTag, "OnStateChange:" + state);
                mIsConnected = state;
                if (!state) {
                    if (mAccessControlEnforcer != null) {
                        mAccessControlEnforcer.reset();
                    }
                } else {
                    initializeAccessControl();
                    synchronized (mLock) {
                        mDefaultApplicationSelectedOnBasicChannel = true;
                    }
                }
            }
        }
    };

    public Terminal(String name, Context context, ISecureElement seHal) {
        if (seHal == null) {
            throw new IllegalArgumentException("ISecureElement cannot be null ");
        }
        mContext = context;
        mName = name;
        mTag = "SecureElement-Terminal-" + getName();
        mSEHal = seHal;
        try {
            seHal.init(mHalCallback);
        } catch (RemoteException e) {
        }
    }

    private ArrayList<Byte> byteArrayToArrayList(byte[] array) {
        ArrayList<Byte> list = new ArrayList<Byte>();
        if (array == null) {
            return list;
        }

        for (Byte b : array) {
            list.add(b);
        }
        return list;
    }

    private byte[] arrayListToByteArray(ArrayList<Byte> list) {
        Byte[] byteArray = list.toArray(new Byte[list.size()]);
        int i = 0;
        byte[] result = new byte[list.size()];
        for (Byte b : byteArray) {
            result[i++] = b.byteValue();
        }
        return result;
    }

    /**
     * Closes the given channel
     */
    public void closeChannel(Channel channel) {
        if (channel == null) {
            return;
        }
        if (mIsConnected && !channel.isBasicChannel()) {
            try {
                byte status = mSEHal.closeChannel((byte) channel.getChannelNumber());
                if (status != SecureElementStatus.SUCCESS) {
                    Log.e(mTag, "Error closing channel " + channel.getChannelNumber());
                }
            } catch (RemoteException e) {
                Log.e(mTag, "Exception in closeChannel() " + e);
            }
        }
        synchronized (mLock) {
            mChannels.remove(channel.getChannelNumber(), channel);
            if (mChannels.get(channel.getChannelNumber()) != null) {
                Log.e(mTag, "Removing channel failed");
            }
        }
    }

    /**
     * This method is called in SecureElementService:onDestroy to clean up
     * all open channels.
     */
    public synchronized void closeChannels() {
        Collection<Channel> col = mChannels.values();
        Channel[] channelList = col.toArray(new Channel[col.size()]);
        for (Channel channel : channelList) {
            closeChannel(channel);
        }
    }

    public String getName() {
        return mName;
    }

    /**
     * Returns the ATR of the Secure Element, or null if not available.
     */
    public byte[] getAtr() {
        if (!mIsConnected) {
            return null;
        }

        try {
            ArrayList<Byte> responseList = mSEHal.getAtr();
            if (responseList.isEmpty()) {
                return null;
            }
            return arrayListToByteArray(responseList);
        } catch (RemoteException e) {
            Log.e(mTag, "Exception in getAtr()" + e);
            return null;
        }
    }

    /**
     * Selects the default application on the basic channel.
     *
     * If there is an exception selecting the default application, select
     * is performed with the default access control aid.
     */
    public void selectDefaultApplication() {
        try {
            select(null);
        } catch (NoSuchElementException e) {
            if (getAccessControlEnforcer() != null) {
                try {
                    select(mAccessControlEnforcer.getDefaultAccessControlAid());
                } catch (Exception ignore) {
                }
            }
        } catch (RemoteException ignore) {
        }
    }

    private void select(byte[] aid) throws RemoteException {
        int commandSize = (aid == null ? 0 : aid.length) + 5;
        byte[] selectCommand = new byte[commandSize];
        selectCommand[0] = 0x00;
        selectCommand[1] = (byte) 0xA4;
        selectCommand[2] = 0x04;
        selectCommand[3] = 0x00;
        if (aid != null && aid.length != 0) {
            selectCommand[4] = (byte) aid.length;
            System.arraycopy(aid, 0, selectCommand, 5, aid.length);
        } else {
            selectCommand[4] = 0x00;
        }
        byte[] selectResponse = transmit(selectCommand);
        if (selectResponse.length < 2) {
            selectResponse = null;
            throw new NoSuchElementException("Response length is too small");
        }
        int sw1 = selectResponse[selectResponse.length - 2] & 0xFF;
        int sw2 = selectResponse[selectResponse.length - 1] & 0xFF;
        if (sw1 != 0x90 || sw2 != 0x00) {
            selectResponse = null;
            throw new NoSuchElementException("Status word is incorrect");
        }
    }

    /**
     * Opens a Basic Channel with the given AID and P2 paramters
     */
    public Channel openBasicChannel(SecureElementSession session, byte[] aid, byte p2,
            ISecureElementListener listener, String packageName,
            int pid) throws RemoteException {
        if (aid != null && aid.length == 0) {
            aid = null;
        } else if (aid != null && (aid.length < 5 || aid.length > 16)) {
            throw new IllegalArgumentException("AID out of range");
        }

        Log.w(mTag, "Enable access control on basic channel for " + packageName);
        ChannelAccess channelAccess = setUpChannelAccess(aid, packageName, true, pid);

        synchronized (mLock) {
            if (mChannels.get(0) != null) {
                Log.e(mTag, "basic channel in use");
                return null;
            }
            if (aid == null && !mDefaultApplicationSelectedOnBasicChannel) {
                Log.e(mTag, "default application is not selected");
                return null;
            }

            ArrayList<byte[]> responseList = new ArrayList<byte[]>();
            byte[] status = new byte[1];
            mSEHal.openBasicChannel(byteArrayToArrayList(aid), p2,
                    new ISecureElement.openBasicChannelCallback() {
                        @Override
                        public void onValues(ArrayList<Byte> responseObject, byte halStatus) {
                            status[0] = halStatus;
                            responseList.add(arrayListToByteArray(responseObject));
                            return;
                        }
                    });
            byte[] selectResponse = responseList.get(0);
            if (status[0] == SecureElementStatus.CHANNEL_NOT_AVAILABLE) {
                return null;
            } else if (status[0] == SecureElementStatus.UNSUPPORTED_OPERATION) {
                throw new UnsupportedOperationException("OpenBasicChannel() failed");
            } else if (status[0] == SecureElementStatus.IOERROR) {
                throw new ServiceSpecificException(SEService.IO_ERROR, "OpenBasicChannel() failed");
            } else if (status[0] == SecureElementStatus.NO_SUCH_ELEMENT_ERROR) {
                throw new ServiceSpecificException(SEService.NO_SUCH_ELEMENT_ERROR,
                        "OpenBasicChannel() failed");
            }

            Channel basicChannel = new Channel(session, this, 0, selectResponse,
                    listener);
            basicChannel.setChannelAccess(channelAccess);

            byte[] selectedAid = getSelectedAid(selectResponse);
            if (selectedAid != null) {
                basicChannel.hasSelectedAid(true, selectedAid);
            } else {
                basicChannel.hasSelectedAid((aid != null) ? true : false, aid);
            }

            if (aid != null) {
                mDefaultApplicationSelectedOnBasicChannel = false;
            }
            mChannels.put(0, basicChannel);
            return basicChannel;
        }
    }

    /**
     * Opens a logical Channel without Channel Access initialization.
     */
    public Channel openLogicalChannelWithoutChannelAccess(byte[] aid) throws RemoteException {
        return openLogicalChannel(null, aid, (byte) 0x00, null, null, 0);
    }

    /**
     * Opens a logical Channel with AID.
     */
    public Channel openLogicalChannel(
            SecureElementSession session, byte[] aid, byte p2,
            ISecureElementListener listener, String packageName,
            int pid) throws RemoteException {
        if (aid != null && aid.length == 0) {
            aid = null;
        } else if (aid != null && (aid.length < 5 || aid.length > 16)) {
            throw new IllegalArgumentException("AID out of range");
        } else if (!mIsConnected) {
            throw new ServiceSpecificException(SEService.IO_ERROR,
                    "Secure Element is not connected");
        }

        ChannelAccess channelAccess = null;
        if (packageName != null) {
            Log.w(mTag, "Enable access control on logical channel for " + packageName);
            channelAccess = setUpChannelAccess(aid, packageName, true, pid);
        }

        synchronized (mLock) {
            LogicalChannelResponse[] responseArray = new LogicalChannelResponse[1];
            byte[] status = new byte[1];
            mSEHal.openLogicalChannel(byteArrayToArrayList(aid), p2,
                    new ISecureElement.openLogicalChannelCallback() {
                        @Override
                        public void onValues(LogicalChannelResponse response, byte halStatus) {
                            status[0] = halStatus;
                            responseArray[0] = response;
                            return;
                        }
                    });
            if (status[0] == SecureElementStatus.CHANNEL_NOT_AVAILABLE) {
                return null;
            } else if (status[0] == SecureElementStatus.UNSUPPORTED_OPERATION) {
                throw new UnsupportedOperationException("OpenLogicalChannel() failed");
            } else if (status[0] == SecureElementStatus.IOERROR) {
                throw new ServiceSpecificException(SEService.IO_ERROR,
                        "OpenLogicalChannel() failed");
            } else if (status[0] == SecureElementStatus.NO_SUCH_ELEMENT_ERROR) {
                throw new ServiceSpecificException(SEService.NO_SUCH_ELEMENT_ERROR,
                        "OpenLogicalChannel() failed");
            }
            if (responseArray[0].channelNumber <= 0 || status[0] != SecureElementStatus.SUCCESS) {
                return null;
            }
            int channelNumber = responseArray[0].channelNumber;
            byte[] selectResponse = arrayListToByteArray(responseArray[0].selectResponse);
            Channel logicalChannel = new Channel(session, this, channelNumber,
                    selectResponse, listener);
            logicalChannel.setChannelAccess(channelAccess);

            byte[] selectedAid = selectedAid = getSelectedAid(selectResponse);
            if (selectedAid != null) {
                logicalChannel.hasSelectedAid(true, selectedAid);
            } else {
                logicalChannel.hasSelectedAid((aid != null) ? true : false, aid);
            }

            mChannels.put(channelNumber, logicalChannel);
            return logicalChannel;
        }
    }

    /**
     * Returns true if the given AID can be selected on the Terminal
     */
    public boolean isAidSelectable(byte[] aid) {
        if (aid == null) {
            throw new NullPointerException("aid must not be null");
        } else if (!mIsConnected) {
            Log.e(mTag, "Secure Element is not connected");
            return false;
        }

        synchronized (mLock) {
            LogicalChannelResponse[] responseArray = new LogicalChannelResponse[1];
            byte[] status = new byte[1];
            try {
                mSEHal.openLogicalChannel(byteArrayToArrayList(aid), (byte) 0x00,
                        new ISecureElement.openLogicalChannelCallback() {
                            @Override
                            public void onValues(LogicalChannelResponse response, byte halStatus) {
                                status[0] = halStatus;
                                responseArray[0] = response;
                                return;
                            }
                        });
                if (status[0] == SecureElementStatus.SUCCESS) {
                    mSEHal.closeChannel(responseArray[0].channelNumber);
                    return true;
                }
                return false;
            } catch (RemoteException e) {
                Log.e(mTag, "Error in isAidSelectable() returning false" + e);
                return false;
            }
        }
    }

    /**
     * Transmits the specified command and returns the response.
     *
     * @param cmd the command APDU to be transmitted.
     * @return the response received.
     */
    public byte[] transmit(byte[] cmd) throws RemoteException {
        if (!mIsConnected) {
            Log.e(mTag, "Secure Element is not connected");
            throw new ServiceSpecificException(SEService.IO_ERROR,
                    "Secure Element is not connected");
        }

        byte[] rsp = transmitInternal(cmd);
        int sw1 = rsp[rsp.length - 2] & 0xFF;
        int sw2 = rsp[rsp.length - 1] & 0xFF;

        if (sw1 == 0x6C) {
            cmd[cmd.length - 1] = rsp[rsp.length - 1];
            rsp = transmitInternal(cmd);
        } else if (sw1 == 0x61) {
            do {
                byte[] getResponseCmd = new byte[]{
                        cmd[0], (byte) 0xC0, 0x00, 0x00, (byte) sw2
                };
                byte[] tmp = transmitInternal(getResponseCmd);
                byte[] aux = rsp;
                rsp = new byte[aux.length + tmp.length - 2];
                System.arraycopy(aux, 0, rsp, 0, aux.length - 2);
                System.arraycopy(tmp, 0, rsp, aux.length - 2, tmp.length);
                sw1 = rsp[rsp.length - 2] & 0xFF;
                sw2 = rsp[rsp.length - 1] & 0xFF;
            } while (sw1 == 0x61);
        }
        return rsp;
    }

    private byte[] transmitInternal(byte[] cmd) throws RemoteException {
        ArrayList<Byte> response = mSEHal.transmit(byteArrayToArrayList(cmd));
        if (response.isEmpty()) {
            throw new ServiceSpecificException(SEService.IO_ERROR, "Error in transmit()");
        }
        byte[] rsp = arrayListToByteArray(response);
        if (mDebug) {
            Log.i(mTag, "Sent : " + ByteArrayConverter.byteArrayToHexString(cmd));
            Log.i(mTag, "Received : " + ByteArrayConverter.byteArrayToHexString(rsp));
        }
        return rsp;
    }

    /**
     * Checks if the application is authorized to receive the transaction event.
     */
    public boolean[] isNfcEventAllowed(
            PackageManager packageManager,
            byte[] aid,
            String[] packageNames,
            boolean checkRefreshTag) {
        if (mAccessControlEnforcer == null) {
            Log.e(mTag, "Access Control Enforcer not properly set up");
            initializeAccessControl();
        }
        mAccessControlEnforcer.setPackageManager(packageManager);

        synchronized (mLock) {
            try {
                return mAccessControlEnforcer.isNfcEventAllowed(aid, packageNames,
                        checkRefreshTag);
            } catch (Exception e) {
                Log.i(mTag, "isNfcEventAllowed Exception: " + e.getMessage());
                return null;
            }
        }
    }

    /**
     * Returns true if the Secure Element is present
     */
    public boolean isSecureElementPresent() {
        try {
            return mSEHal.isCardPresent();
        } catch (RemoteException e) {
            Log.e(mTag, "Error in isSecureElementPresent() " + e);
            return false;
        }
    }

    /**
     * Initialize the Access Control and set up the channel access.
     */
    public ChannelAccess setUpChannelAccess(byte[] aid, String packageName,
            boolean checkRefreshTag, int pid) {
        if (mAccessControlEnforcer == null) {
            Log.e(mTag, "Access Control Enforcer not properly set up");
            initializeAccessControl();
        }
        mAccessControlEnforcer.setPackageManager(mContext.getPackageManager());

        synchronized (mLock) {
            try {
                ChannelAccess channelAccess =
                        mAccessControlEnforcer.setUpChannelAccess(aid, packageName,
                                checkRefreshTag);
                channelAccess.setCallingPid(pid);
                return channelAccess;
            } catch (Exception e) {
                throw new SecurityException("Exception in setUpChannelAccess()" + e);
            }
        }
    }

    /**
     * Initializes the Access Control for this Terminal
     */
    private synchronized void initializeAccessControl() {
        synchronized (mLock) {
            if (mAccessControlEnforcer == null) {
                mAccessControlEnforcer = new AccessControlEnforcer(this);
            }
            mAccessControlEnforcer.initialize(true);
        }
    }

    public AccessControlEnforcer getAccessControlEnforcer() {
        return mAccessControlEnforcer;
    }

    private byte[] getSelectedAid(byte[] selectResponse) {
        byte[] selectedAid = null;
        if ((selectResponse != null && selectResponse.length >= 2)
                && (selectResponse.length == (selectResponse[1] + 4))
                && // header(2) + SW(2)
                ((selectResponse[0] == (byte) 0x62)
                        || (selectResponse[0] == (byte) 0x6F))) { // FCP or FCI template
            int nextTlv = 2;
            while (selectResponse.length > nextTlv) {
                if (selectResponse[nextTlv] == (byte) 0x84) {
                    if (selectResponse.length >= (nextTlv + selectResponse[nextTlv + 1] + 2)) {
                        selectedAid = new byte[selectResponse[nextTlv + 1]];
                        System.arraycopy(
                                selectResponse, nextTlv + 2, selectedAid, 0,
                                selectResponse[nextTlv + 1]);
                    }
                    break;
                } else {
                    nextTlv += 2 + selectResponse[nextTlv + 1];
                }
            }
        }
        return selectedAid;
    }

    /** Dump data for debug purpose . */
    public void dump(PrintWriter writer) {
        writer.println("SECURE ELEMENT SERVICE TERMINAL: " + mName);
        writer.println();

        writer.println("mIsConnected:" + mIsConnected);
        writer.println();

        /* Dump the list of currunlty openned channels */
        writer.println("List of open channels:");

        for (Channel channel : mChannels.values()) {
            writer.println("channel " + channel.getChannelNumber() + ": ");
            writer.println("package: " + channel.getChannelAccess().getPackageName());
            writer.println("pid: " + channel.getChannelAccess().getCallingPid());
            writer.println("aid selected: " + channel.hasSelectedAid());
            writer.println("basic channel: " + channel.isBasicChannel());
            writer.println();
        }
        writer.println();

        /* Dump ACE data */
        if (mAccessControlEnforcer != null) {
            mAccessControlEnforcer.dump(writer);
        }
    }

    // Implementation of the SecureElement Reader interface according to OMAPI.
    final class SecureElementReader extends ISecureElementReader.Stub {

        private final SecureElementService mService;
        private final ArrayList<SecureElementSession> mSessions =
                new ArrayList<SecureElementSession>();

        SecureElementReader(SecureElementService service) {
            mService = service;
        }

        public byte[] getAtr() {
            return Terminal.this.getAtr();
        }

        @Override
        public boolean isSecureElementPresent() throws RemoteException {
            return Terminal.this.isSecureElementPresent();
        }

        @Override
        public void closeSessions() {
            synchronized (mLock) {
                while (mSessions.size() > 0) {
                    try {
                        mSessions.get(0).close();
                    } catch (Exception ignore) {
                    }
                }
                mSessions.clear();
            }
        }

        public void removeSession(SecureElementSession session) {
            if (session == null) {
                throw new NullPointerException("session is null");
            }
            mSessions.remove(session);
            synchronized (mLock) {
                if (mSessions.size() == 0) {
                    mDefaultApplicationSelectedOnBasicChannel = true;
                }
            }
        }

        @Override
        public ISecureElementSession openSession() throws RemoteException {
            if (!isSecureElementPresent()) {
                throw new ServiceSpecificException(SEService.IO_ERROR,
                        "Secure Element is not present.");
            }

            synchronized (mLock) {
                SecureElementSession session = mService.new SecureElementSession(this);
                mSessions.add(session);
                return session;
            }
        }

        Terminal getTerminal() {
            return Terminal.this;
        }
    }
}
