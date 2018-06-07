package com.tenone.testapplication;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;

import com.tenone.testapplication.isakmp.AlgorithmUtil;
import com.tenone.testapplication.isakmp.ESPPayload;
import com.tenone.testapplication.isakmp.KeyExchangeUtil;
import com.tenone.testapplication.isakmp.PayloadAttribute;
import com.tenone.testapplication.isakmp.PayloadBase;
import com.tenone.testapplication.isakmp.PayloadHelper;
import com.tenone.testapplication.isakmp.PayloadKeyEx;
import com.tenone.testapplication.isakmp.PayloadNonce;
import com.tenone.testapplication.isakmp.PayloadSA;
import com.tenone.testapplication.isakmp.ResponseBase;
import com.tenone.testapplication.isakmp.ResponseConfigModeFirst;
import com.tenone.testapplication.isakmp.ResponseConfigModeSecond;
import com.tenone.testapplication.isakmp.ResponseConfigModeThird;
import com.tenone.testapplication.isakmp.ResponseMainModeFirst;
import com.tenone.testapplication.isakmp.ResponseMainModeSecond;
import com.tenone.testapplication.isakmp.ResponseMainModeThird;
import com.tenone.testapplication.isakmp.ResponseQuickModeFirst;
import com.tenone.testapplication.isakmp.ResponseInformational;
import com.tenone.testapplication.isakmp.Utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;


public class VPNService extends VpnService implements Handler.Callback, Runnable{

    private static final String TAG = "VPNService";
    private static final int CONNECTION_RETRY_COUNT = 6;
    private static final int CONNECTION_RETRY_TIMEOUT = 15000;
    private static final int CONNECTION_WAIT_TIMOUT = 300;
    private static final int HANDSHAKE_BUFFER = 1024;
    private static final int DEFAULT_PACKET_SIZE = 32767;
    private static final int REQUEST_CODE = 0;
    private static final int DEFAULT_INTENT_FLAG = 0;
    private static final int DEFAULT_TIMER = 100;
    private static final int DEFAULT_TIMER_NEGATIVE = -100;
    private static final int DEFAULT_TIMER_MIN = -15000;
    private static final int DEFAULT_TIMER_MAX = 20000;
    private static final int WRITER_RETRY_COUNT = 3;
    private String mServerAddress;
    private String mServerPort;
    private String mDnsServer;
    private byte[] sharedSecret;
    private int mMtu;
    private String mRoute;
    private Handler handler;
    private Thread vpnThread;
    private ParcelFileDescriptor fileDescriptor;
    private String vpnParameters;
    private PendingIntent configureIntent;

    private PayloadHelper mPayloadHelper;
    private String mPreSharedSecret;


    private static final int ADDRESS_BUFFER_SIZE = 4;

    private static final int IKE_ATTRIBUTE_1 = 1;   // encryption-algorithm
    private static final int IKE_ATTRIBUTE_2 = 2;   // hash-algorithm
    private static final int IKE_ATTRIBUTE_3 = 3;   // authentication-method
    private static final int IKE_ATTRIBUTE_4 = 4;   // group-description
    private static final int IKE_ATTRIBUTE_11 = 11; // life-type
    private static final int IKE_ATTRIBUTE_12 = 12; // life-duration
    private static final int IKE_ATTRIBUTE_14 = 14; // key-length

    private String mUserName;
    private String mPassword;

    private byte[] mInitiatorCookie = new byte[8];
    private byte[] mResponderCookie = new byte[8];
    private KeyExchangeUtil mKeyExchangeUtil;
    private AlgorithmUtil mAlgorithmUtil;


    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // The handler is only used to show messages.
        if (handler == null) {
            handler = new Handler(this);
        }
        // Stop the previous session by interrupting the thread.
        if (vpnThread != null) {
            vpnThread.interrupt();
        }
        // Extract information from the intent.
        String prefix = BuildConfig.APPLICATION_ID;
        if (intent != null) {
//            mServerAddress = intent.getStringExtra(prefix + Constants.ADDRESS);
//
//            if (intent.hasExtra(prefix + Constants.PORT)) {
//                mServerPort = intent.getStringExtra(prefix + Constants.PORT);
//            }
//
//            if (intent.hasExtra(prefix + Constants.SECRET)) {
//                sharedSecret = intent.getStringExtra(prefix + Constants.SECRET).getBytes();
//            }
//
//            if (intent.hasExtra(prefix + Constants.DNS)) {
//                dnsServer = intent.getStringExtra(prefix + Constants.DNS);
//            }

            mMtu = 1000;
            mRoute = "0.0.0.0";
            mDnsServer = "8.8.8.8";
            mServerAddress = "52.24.97.9";
//            mServerAddress = "34.218.240.200";
            mServerPort = "500";
            mPreSharedSecret = "test4stagwell";
            mUserName = "testvpn";
            mPassword = "stagwell";
            try {
                sharedSecret = mPreSharedSecret.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                Log.e(TAG, "failed to get the bytes. " + e.getLocalizedMessage());
            }

            mKeyExchangeUtil = KeyExchangeUtil.getInstance();
            mKeyExchangeUtil.setPreSharedKey("test4stagwell");
            mAlgorithmUtil = AlgorithmUtil.getInstance();
            mPayloadHelper = PayloadHelper.getInstance();
            Intent pendingIntent = new Intent(this, MainActivity.class);
            configureIntent = PendingIntent.getActivity(this, REQUEST_CODE, pendingIntent, DEFAULT_INTENT_FLAG);

            // Start a new session by creating a new thread.
            vpnThread = new Thread(this, TAG);
            vpnThread.start();
            return START_REDELIVER_INTENT;
        }

        return super.onStartCommand(intent, flags, startId);
    }

    @Override
    public void onDestroy() {
        if (vpnThread != null) {
            vpnThread.interrupt();
        }
    }

    @Override
    public boolean handleMessage(Message message) {
        if (message != null) {
            Toast.makeText(this, message.what, Toast.LENGTH_SHORT).show();
        }
        return true;
    }

    @Override
    public synchronized void run() {
        try {
            Log.d(TAG, "Starting");

            // If anything needs to be obtained using the network, get it now.
            // This greatly reduces the complexity of seamless handover, which
            // tries to recreate the tunnel without shutting down everything.
            // In this mode, all we need to know is the server address.
            InetSocketAddress server = new InetSocketAddress(
                    mServerAddress, Integer.parseInt(mServerPort));
            // We try to create the tunnel for several times.
            for (int attempt = 0; attempt < CONNECTION_RETRY_COUNT; ++attempt) {
//                handler.sendEmptyMessage(R.string.VPN_connecting);
                // Reset the counter if we were connected.
                Log.e(TAG, "retry connection for :" + attempt);
                if (run(server)) {
                    //attempt = 0;
                }
                // Sleep for a while. This also checks if we got interrupted.
                Thread.sleep(CONNECTION_RETRY_TIMEOUT);
            }
            Log.d(TAG, "Giving up");
        } catch (Exception e) {
            Log.e(TAG, "VPN thread is failing " + e.getLocalizedMessage());
            e.printStackTrace();
        } finally {
            try {
                if (fileDescriptor != null) {
                    fileDescriptor.close();
                }
            } catch (IOException e) {
                Log.e(TAG, "FileDescriptor close failed " + e);
            }
            fileDescriptor = null;
//            vpnParameters = null;
//            handler.sendEmptyMessage(R.string.VPN_disconnected);
            Log.d(TAG, "Exiting");
        }
    }

    private boolean run(InetSocketAddress server) throws InterruptedException {
        DatagramChannel tunnel = null;
        boolean connected = false;
        try {
            // Create a DatagramChannel as the VPN tunnel.
            tunnel = DatagramChannel.open();
            // Protect the tunnel before connecting to avoid loopback.
            if (!protect(tunnel.socket())) {
                throw new IllegalStateException("Cannot protect the tunnel");
            }
            // Connect to the server.
            tunnel.connect(server);
            // Here we put the tunnel into non-blocking mode.
            tunnel.configureBlocking(false);

            // Authenticate and configure the virtual network interface.
            if (sharedSecret != null) {
                if (!doHandshake(tunnel)) {
                    return false;
                }
            } else {
                establishVPN();
            }
            // Now we are connected. Set the flag and show the message.
            connected = true;

//            handler.sendEmptyMessage(R.string.VPN_connected);
            // Packets to be sent are queued in this input stream.
            FileInputStream in = new FileInputStream(fileDescriptor.getFileDescriptor());
            // Packets received need to be written to this output stream.
            FileOutputStream out = new FileOutputStream(fileDescriptor.getFileDescriptor());
            // Allocate the buffer for a single packet.
            ByteBuffer packet = ByteBuffer.allocate(DEFAULT_PACKET_SIZE);

            boolean isDataSend = true;

            // We use a timer to determine the status of the tunnel. It
            // works on both sides. A positive value means sending, and
            // any other means receiving. We start with receiving.
            int timer = 0;
            // We keep forwarding packets till something goes wrong.
            while (true) {
                // Assume that we did not make any progress in this iteration.
                boolean idle = true;

                // Read the outgoing packet from the input stream.
                int length = in.read(packet.array());
                if (length > 0) {
                    // Write the outgoing packet to the tunnel.
                    packet.limit(length);
                    byte[] readBytes = new byte[length];
                    System.arraycopy(packet.array(), 0, readBytes, 0, length);

                    KeyExchangeUtil.getInstance().print("Outgoing packet before encryption", readBytes);

                    // adding the ESP header (SPI, sequence number), encryption, ICV, etc.
                    byte[] espPayload = mPayloadHelper.prepareESPPayload(readBytes);

                    ByteBuffer buf = ByteBuffer.allocate(espPayload.length);
                    buf.put(espPayload);
                    buf.position(0);
                    tunnel.write(buf);
                    buf.clear();

                    packet.clear();
                    // There might be more outgoing packets.
                    idle = false;
                    // If we were receiving, switch to sending.
                    if (timer < 1) {
                        timer = 1;
                    }
                }
                // Read the incoming packet from the tunnel.
                packet.clear();
                length = tunnel.read(packet);
                if (length > 0) {
                    // Ignore control messages, which start with zero.
                    packet.position(0);
                    byte firstByte = packet.get(0);
                    if (firstByte != 0 && firstByte != (byte)0xff) {
                        // Write the incoming packet to the output stream.
                        packet.position(0);
                        packet.limit(length);

                        // check ICV, decrypt
                        ESPPayload espPayload = new ESPPayload(packet);

                        KeyExchangeUtil.getInstance().print("Incoming packet after decryption", espPayload.decryptedData);

                        out.write(espPayload.payload, 0, espPayload.payload.length);
                    }
                    if (firstByte == 0) {
                        KeyExchangeUtil.getInstance().print("0 Command", packet.array());
                        ResponseInformational responseInformational = new ResponseInformational(packet);
                        if (responseInformational != null) {

                        }
                    }
                    packet.clear();
                    // There might be more incoming packets.
                    idle = false;
                    // If we were sending, switch to receiving.
                    if (timer > 0) {
                        timer = 0;
                    }
                }
                // If we are idle or waiting for the network, sleep for a
                // fraction of time to avoid busy looping.
                if (idle) {
                    Thread.sleep(CONNECTION_WAIT_TIMOUT);
                    // since everything is operated in non-blocking mode.
                    timer += (timer > 0) ? DEFAULT_TIMER : DEFAULT_TIMER_NEGATIVE;
                    // We are receiving for a long time but not sending.
                    if (timer < DEFAULT_TIMER_MIN) {
                        // Send empty control messages.
                        packet.put((byte) 0).limit(1);
                        for (int i = 0; i < WRITER_RETRY_COUNT; ++i) {
                            packet.position(0);
                            tunnel.write(packet);
                        }
                        packet.clear();
                        // Switch to sending.
                        timer = 1;
                    }
                    // We are sending for a long time but not receiving.
                    if (timer > DEFAULT_TIMER_MAX) {
                        throw new IllegalStateException("Timed out");
                    }
                }
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Thread interrupted " + e);
            throw e;
        } catch (IOException e) {
            Log.e(TAG, "Tunnel read/write failed " + e);
        } finally {
            try {
                if (tunnel != null) {
//                    byte[] deletePayload = prepareDeletePayload();
//                    ByteBuffer payload = ByteBuffer.allocate(deletePayload.length);
//                    payload.put(deletePayload).flip();
//                    tunnel.write(payload);
//
//                    KeyExchangeUtil.getInstance().print("deletePayload", deletePayload);
                    tunnel.close();
                }
            } catch (IOException e) {
                Log.e(TAG, "Tunnel close failed " + e);
            }
        }
        return connected;
    }

    private boolean doHandshake(DatagramChannel tunnel) {
        mPayloadHelper.init(mPreSharedSecret, Utils.getIPAddress1(getApplicationContext()),
                mServerAddress, mServerPort, mUserName, mPassword);

        ByteBuffer packet = ByteBuffer.allocate(HANDSHAKE_BUFFER);
        boolean success = false;
        for (int i = 1; i <= 8; i++) {
            if (i == 3) {
                try {
                    InetSocketAddress socketAddress = new InetSocketAddress(mServerAddress, 4500);
                    tunnel.disconnect();
                    tunnel.connect(socketAddress);
                    tunnel.configureBlocking(false);
                    if (!protect(tunnel.socket())) {
                        Log.e(TAG, "Failed to protect the socket");
                        break;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    break;
                }
            }
            if(!(success = messageHandler(i, packet, tunnel))){
                break;
            }
        }

        return success;
    }

    private boolean messageHandler(int index, ByteBuffer packet, DatagramChannel tunnel) {
        ResponseBase responseBase = null;
        boolean success = false;


        switch (index) {
            case 1:
                packet.clear();
                packet.put(mPayloadHelper.preparePhase1MainModeFirstMsg()).flip();
                if(sendMessage(packet, tunnel)) {
                    if (readMessage(packet, tunnel)) {
                        packet.position(0);
                        responseBase = new ResponseMainModeFirst(packet);
                        if (responseBase != null && responseBase.isValid()) {
                            mPayloadHelper.setIsakmpHeader(responseBase.isakmpHeader);
                            mKeyExchangeUtil.setResponderCookie(responseBase.isakmpHeader.responderCookie);
                            success = true;
                        }
                    }
                }
                break;
            case 2:
                packet.clear();
                packet.put(mPayloadHelper.preparePhase1MainModeSecondMsg()).flip();
                if(sendMessage(packet, tunnel)) {
                    if (readMessage(packet, tunnel)) {
                        packet.position(0);
                        responseBase = new ResponseMainModeSecond(packet);
                        if (responseBase != null && responseBase.isValid()) {
                            for (PayloadBase base : responseBase.payloadList) {
                                if (base instanceof PayloadKeyEx) {
                                    KeyExchangeUtil.getInstance().setServerPublicKeyData(((PayloadKeyEx) base).keyExData);
                                }

                                if (base instanceof PayloadNonce) {
                                    KeyExchangeUtil.getInstance().setResponderNonce(((PayloadNonce) base).nonceData);
                                }
                            }
                            success = true;
                        }
                    }
                }
                break;
            case 3:
                packet.clear();

                packet.put(mPayloadHelper.preparePhase1MainModeThirdMsg()).flip();
                if (sendMessage(packet, tunnel)) {

                    while (readMessage(packet, tunnel)) {
                        packet.position(0);
                        ResponseMainModeThird response = new ResponseMainModeThird(packet);
                        if (response != null && response.isValid()) {

                            mAlgorithmUtil.setPhase1FirstIv(response.getNextIv());
                            success = true;
                            break;
                        }
                    }
                }

                break;
            case 4:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);
                    ResponseConfigModeFirst response = new ResponseConfigModeFirst(packet);
                    if (response != null && response.isValid()) {
                        mPayloadHelper.setIsakmpHeader(response.isakmpHeader);
                        mAlgorithmUtil.setIv(response.getNextIv());
                        packet.clear();
                        byte[] msg = mPayloadHelper.preparePhase2ConfigModeFirstMsg();
                        packet.put(msg).flip();

                        if (sendMessage(packet, tunnel)) {
                            success = true;
                            break;
                        }
                    }
                }
                break;
            case 5:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);
                    ResponseConfigModeSecond response = new ResponseConfigModeSecond(packet);
                    if (response != null && response.isValid()) {
                        responseBase = response;
                        mPayloadHelper.setIsakmpHeader(response.isakmpHeader);
                        mAlgorithmUtil.setIv(response.getNextIv());
//                        isakmpHeader = response.isakmpHeader;
//                        KeyExchangeUtil.getInstance().setIV(response.getNextIv());

                        packet.clear();
                        byte[] secondMsg = mPayloadHelper.preparePhase2ConfigModeSecondMsg();
                        packet.put(secondMsg).flip();
                        if (sendMessage(packet, tunnel)) {
                            mPayloadHelper.updateIVWithEncryptedData(secondMsg);

                            packet.clear();
                            byte[] thirdMsg = mPayloadHelper.preparePhase2ConfigModeThirdMsg();
                            packet.put(thirdMsg).flip();
                            if (sendMessage(packet, tunnel)) {
                                mPayloadHelper.updateIVWithEncryptedData(thirdMsg);
                                success = true;
                                break;
                            }
                        }

                        break;
                    }
                }
                break;
            case 6:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);
                    ResponseBase response = new ResponseConfigModeThird(packet);
                    if (response != null && response.isValid()) {
                        mPayloadHelper.setIsakmpHeader(response.isakmpHeader);

                        if (response.payloadList.get(1) instanceof PayloadAttribute) {
                            byte[] serverProvidedIpAddress = ((PayloadAttribute) response.payloadList.get(1)).attributeList.get(0).value;
                            byte[] serverProvidedSubnet = ((PayloadAttribute) response.payloadList.get(1)).attributeList.get(1).value;
                            mPayloadHelper.setServerProvidedIpAndSubnet(serverProvidedIpAddress, serverProvidedSubnet);

                            packet.clear();

                            byte[] firstQuickModeMsg = mPayloadHelper.preparePhase2QuickModeFirstMsg();

                            packet.put(firstQuickModeMsg).flip();
                            if (sendMessage(packet, tunnel)) {
                                Log.d(TAG, "SENT FIRST MESSAGE IN QUICK MODE");
                                mPayloadHelper.updateIVWithEncryptedData(firstQuickModeMsg);
                                success = true;

                            }
                        }
                        break;
                    }
                }
                break;
            case 7:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);

                    ResponseQuickModeFirst response = new ResponseQuickModeFirst(packet);
                    Log.e(TAG, "read quick mode second message");
                    if (response != null && response.isValid()) {
                        responseBase = response;
                        mPayloadHelper.setIsakmpHeader(response.isakmpHeader);
                        mAlgorithmUtil.setIv(response.getNextIv());

                        packet.clear();
                        byte[] responderNonce = ((PayloadNonce)response.payloadList.get(2)).nonceData;
                        byte[] outboundSPI = ((PayloadSA)response.payloadList.get(1)).payloadProposal.spiData;
                        KeyExchangeUtil.getInstance().prepareKeyMaterial(responderNonce, outboundSPI);
                        byte[] lastMsg = mPayloadHelper.preparePhase2QuickModeSecondMsg();
                        packet.put(lastMsg).flip();
                        if (sendMessage(packet, tunnel)) {
                            Log.d(TAG, "Sent last message in quick mode");
                            success = true;
                        }
                        break;
                    }
                }
                break;
            case 8:
                setUp();
                success = true;
                break;
            default:
                break;
        }
        return success;
    }

    private boolean sendMessage(ByteBuffer packet, DatagramChannel tunnel) {
        try {
            packet.position(0);
            tunnel.write(packet);
            return true;

        }catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private boolean readMessage(ByteBuffer packet, DatagramChannel tunnel) {
        try {
            Thread.sleep(CONNECTION_WAIT_TIMOUT);
            packet.clear();
            int length = tunnel.read(packet);
            if (length > 0) {
                return true;
            }else {
                return false;
            }
        }catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    private void establishVPN() {
        Builder builder = new Builder();
        String address;
        if (mServerPort != null) {
            address = mServerAddress + ":" + mServerPort;
        } else {
            address = mServerAddress;
        }

        builder.addAddress(address, DEFAULT_INTENT_FLAG);
        if (mDnsServer != null) {
            builder.addDnsServer(mDnsServer);
        }

        fileDescriptor = builder.setSession(mServerAddress)
                .setConfigureIntent(configureIntent)
                .establish();
    }

    private void setUp() {
        if (fileDescriptor != null) {
            try {
                fileDescriptor.close();
            } catch (IOException e) {
                Log.e(TAG, "File descriptor is already closed " + e);
            }
        }
        InetAddress ia = null;
//        InetAddress ir = null;
        try {
            ia = InetAddress.getByAddress(mPayloadHelper.getServerProvidedIp());
//            ir = InetAddress.getByAddress(subnet);

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }


        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();

        builder.setMtu(mMtu);

        builder.addAddress(ia, 0);
        builder.addRoute(mRoute, 0);
        builder.addDnsServer(mDnsServer);

        // Close the old interface since the parameters have been changed.
//        try {
//            fileDescriptor.close();
//        } catch (IOException e) {
//            Log.e(TAG, "File descriptor is already closed " + e);
//        }
        // Create a new interface using the builder and save the parameters.
        fileDescriptor = builder.setSession(mServerAddress)
//                .setConfigureIntent(configureIntent)
                .establish();
//        vpnParameters = parameters;
//        Log.d(TAG, "New interface: " + parameters);
    }


}
