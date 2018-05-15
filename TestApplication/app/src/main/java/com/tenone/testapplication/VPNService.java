package com.tenone.testapplication;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;
import android.widget.Toast;


import com.tenone.testapplication.isakmp.IsakmpHeader;
import com.tenone.testapplication.isakmp.KeyExchangeUtil;
import com.tenone.testapplication.isakmp.PayloadBase;
import com.tenone.testapplication.isakmp.PayloadKeyEx;
import com.tenone.testapplication.isakmp.PayloadNonce;
import com.tenone.testapplication.isakmp.ResponseBase;
import com.tenone.testapplication.isakmp.ResponseConfigModeFirst;
import com.tenone.testapplication.isakmp.ResponseMainModeFirst;
import com.tenone.testapplication.isakmp.ResponseMainModeSecond;
import com.tenone.testapplication.isakmp.ResponseMainModeThird;
import com.tenone.testapplication.isakmp.Utils;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;


public class VPNService extends VpnService implements Handler.Callback, Runnable{

    private static final String TAG = "VPNService";
    private static final int CONNECTION_RETRY_COUNT = 1;
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
    private static final char MTU = 'm';
    private static final char ADDRESS = 'a';
    private static final char ROUTE = 'r';
    private static final char DNS = 'd';
    private static final char SEARCH_DOMAIN = 's';
    private String mServerAddress;
    private String mServerPort;
    private String dnsServer;
    private byte[] sharedSecret;
    private Handler handler;
    private Thread vpnThread;
    private ParcelFileDescriptor fileDescriptor;
    private String vpnParameters;
    private PendingIntent configureIntent;

    private byte[] mSAPayload;


    private static final int ADDRESS_BUFFER_SIZE = 4;

    private static final int IKE_ATTRIBUTE_1 = 1;   // encryption-algorithm
    private static final int IKE_ATTRIBUTE_2 = 2;   // hash-algorithm
    private static final int IKE_ATTRIBUTE_3 = 3;   // authentication-method
    private static final int IKE_ATTRIBUTE_4 = 4;   // group-description
    private static final int IKE_ATTRIBUTE_11 = 11; // life-type
    private static final int IKE_ATTRIBUTE_12 = 12; // life-duration
    private static final int IKE_ATTRIBUTE_14 = 14; // key-length

    private byte[] mInitiatorCookie = new byte[8];
    private byte[] mResponderCookie = new byte[8];
    private KeyExchangeUtil mKeyExchangeUtil;

    IsakmpHeader isakmpHeader;
    byte[] keyData;
    byte[] nonceData;


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

            mServerAddress = "52.24.97.9";
//            mServerAddress = "34.218.240.200";
            mServerPort = "500";
            try {
                sharedSecret = "test4stagwell".getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                Log.e(TAG, "failed to get the bytes. " + e.getLocalizedMessage());
            }

            mKeyExchangeUtil = KeyExchangeUtil.getInstance();
            mKeyExchangeUtil.setPreSharedKey("test4stagwell");
            mKeyExchangeUtil.setHashAlgorithm("HmacSHA256");
            mKeyExchangeUtil.setmEncryptAlgorithm("AES256");
            //Intent pendingIntent = new Intent(this, AlertActivity.class);
            //configureIntent = PendingIntent.getActivity(this, REQUEST_CODE, pendingIntent, DEFAULT_INTENT_FLAG);

            // Start a new session by creating a new thread.
            vpnThread = new Thread(this, TAG);
            vpnThread.start();
            return START_STICKY;
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
                if (run(server)) {
                    attempt = 0;
                }
                // Sleep for a while. This also checks if we got interrupted.
                Thread.sleep(CONNECTION_WAIT_TIMOUT);
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
            vpnParameters = null;
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
                doHandshake(tunnel);
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
                    tunnel.write(packet);
                    packet.clear();
                    // There might be more outgoing packets.
                    idle = false;
                    // If we were receiving, switch to sending.
                    if (timer < 1) {
                        timer = 1;
                    }
                }
                // Read the incoming packet from the tunnel.
                length = tunnel.read(packet);
                if (length > 0) {
                    // Ignore control messages, which start with zero.
                    if (packet.get(0) != 0) {
                        // Write the incoming packet to the output stream.
                        out.write(packet.array(), 0, length);
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
                    tunnel.close();
                }
            } catch (IOException e) {
                Log.e(TAG, "Tunnel close failed " + e);
            }
        }
        return connected;
    }

    private void doHandshake(DatagramChannel tunnel) {
        /*To build a secured tunnel, we should perform mutual authentication
          and exchange session keys for encryption. We send the shared secret and wait
          for the server to send the parameters.
          Allocate the buffer for handshaking.*/
//        ByteBuffer packet = ByteBuffer.allocate(HANDSHAKE_BUFFER);
//        // Control messages always start with zero.
//        packet.put((byte) 0).put(sharedSecret).flip();

//        byte[] msg = begin();
//        ByteBuffer packet = ByteBuffer.allocate(HANDSHAKE_BUFFER);
//        packet.put(msg).flip();
//        // Send the secret several times in case of packet loss.
//        for (int i = 0; i < CONNECTION_RETRY_COUNT; ++i) {
//            packet.position(0);
//            try {
//                tunnel.write(packet);
//            } catch (IOException e) {
//                Log.e(TAG, "Tunnel write failed " + e);
//            }
//        }
//        packet.clear();
//        // Wait for the parameters within a limited time.
//        for (int i = 0; i < CONNECTION_RETRY_COUNT; ++i) {
//            try {
//                Thread.sleep(CONNECTION_WAIT_TIMOUT);
//                int length = tunnel.read(packet);
////                if (length > 0 && packet.get(0) == 0) {
////                    configure(new String(packet.array(), 1, length - 1).trim());
////                    return;
//
//
////                }
//                if (length > 0) {
//                    ByteBuffer p = ByteBuffer.allocate(HANDSHAKE_BUFFER);
//                    packet.position(0);
//                    System.arraycopy(packet.array(), 8, mResponderCookie, 0, 8);
//
//                    p.put(prepareSecondMsg()).flip();
//
//                    p.position(0);
//                    tunnel.write(p);
//
//                    Thread.sleep(CONNECTION_WAIT_TIMOUT);
//
//                    packet.clear();
//                    length = tunnel.read(packet);
//
//                    if (length > 0) {
//
//                        p.put(prepareThirdMsg(packet.array()));
//                    }
//                }
//            } catch (InterruptedException e) {
//                Log.e(TAG, "Thread interrupted " + e);
//            } catch (IOException e) {
//                Log.e(TAG, "Tunnel read failed " + e);
//            }
//        }

        ByteBuffer packet = ByteBuffer.allocate(HANDSHAKE_BUFFER);
        for (int i = 1; i <= 6; i++) {
            ResponseBase base = messageHandler(i, packet, tunnel);
            if (base == null) {
                break;
            }
        }
    }

    private ResponseBase messageHandler(int index, ByteBuffer packet, DatagramChannel tunnel) {
        ResponseBase responseBase = null;

        switch (index) {
            case 1:
                packet.clear();
                packet.put(begin()).flip();
                if(sendMessage(packet, tunnel)) {
                    if (readMessage(packet, tunnel)) {
                        packet.position(0);
                        responseBase = new ResponseMainModeFirst(packet);
                        if (responseBase != null && responseBase.isValid()) {
                            isakmpHeader = responseBase.isakmpHeader;
                        }
                    }
                }
                break;
            case 2:
                packet.clear();
                packet.put(prepareSecondMsg(isakmpHeader.toData(4))).flip();
                if(sendMessage(packet, tunnel)) {
                    if (readMessage(packet, tunnel)) {
                        packet.position(0);
                        responseBase = new ResponseMainModeSecond(packet);
                        if (responseBase != null && responseBase.isValid()) {
                            for (PayloadBase base : responseBase.payloadList) {
                                if (base instanceof PayloadKeyEx) {
                                    keyData = ((PayloadKeyEx) base).keyExData;
                                }

                                if (base instanceof PayloadNonce) {
                                    nonceData = ((PayloadNonce) base).nonceData;
                                }
                            }
                        }
                    }

//                    while (readMessage(packet, tunnel) != null) {
//                        packet.position(0);
//                        ResponseBase response = new ResponseBase(packet);
//                        if (response != null && response.getResHeader().isEncrypted()) {
//                            responseBase = response;
//                            break;
//                        }
//                    }

                }
                break;
            case 3:
                packet.clear();
                byte[] flag = Utils.toBytes(1, 1);
                if (mKeyExchangeUtil.instantiateServerPublicKey(keyData)) {
                    mKeyExchangeUtil.generateExchangeInfo(nonceData, isakmpHeader.initiatorCookie, isakmpHeader.responderCookie);

                    byte[] idPayload = prepareIdentificationPayload();
                    byte[] hashPayload = prepareHashPayload(idPayload);

                    byte[] combineData = new byte[idPayload.length + hashPayload.length];
                    System.arraycopy(idPayload, 0, combineData, 0, idPayload.length);
                    System.arraycopy(hashPayload, 0, combineData, idPayload.length, hashPayload.length);

                    byte[] encryptedData = mKeyExchangeUtil.prepare1stEncryptedPayload(combineData, keyData);
                    packet.put(prepareThirdMsg(isakmpHeader.toData(5, encryptedData.length + 28, flag[0]), encryptedData)).flip();
                    if (sendMessage(packet, tunnel)) {

                        while (readMessage(packet, tunnel)) {
                            packet.position(0);
                            ResponseMainModeThird response = new ResponseMainModeThird(packet);
                            if (response != null && response.isValid()) {
                                KeyExchangeUtil.getInstance().setIV(response.getNextIv());
                                responseBase = response;
                                break;
                            }
                        }

                    }

                }
                break;
            case 4:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);
                    ResponseBase response = new ResponseConfigModeFirst(packet);
                    if (response != null && response.isValid()) {
                        responseBase = response;
                        isakmpHeader = response.isakmpHeader;
                        break;
                    }
                }
                break;
            default:
                break;
        }
        return responseBase;
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
        if (dnsServer != null) {
            builder.addDnsServer(dnsServer);
        }

        fileDescriptor = builder.setSession(mServerAddress)
                .setConfigureIntent(configureIntent)
                .establish();
    }

    private void configure(String parameters) {
        if (fileDescriptor != null && parameters.equals(vpnParameters)) {
            Log.d(TAG, "Using the previous interface");
            return;
        }
        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();

        for (String parameter : parameters.split(" ")) {
            String[] fields = parameter.split(",");
            switch (fields[0].charAt(0)) {
                case MTU:
                    builder.setMtu(Short.parseShort(fields[1]));
                    break;
                case ADDRESS:
                    builder.addAddress(fields[1], Integer.parseInt(fields[2]));
                    break;
                case ROUTE:
                    builder.addRoute(fields[1], Integer.parseInt(fields[2]));
                    break;
                case DNS:
                    builder.addDnsServer(fields[1]);
                    break;
                case SEARCH_DOMAIN:
                    builder.addSearchDomain(fields[1]);
                    break;
                default:
                    break;
            }
        }
        // Close the old interface since the parameters have been changed.
        try {
            fileDescriptor.close();
        } catch (IOException e) {
            Log.e(TAG, "File descriptor is already closed " + e);
        }
        // Create a new interface using the builder and save the parameters.
        fileDescriptor = builder.setSession(mServerAddress)
                .setConfigureIntent(configureIntent)
                .establish();
        vpnParameters = parameters;
        Log.d(TAG, "New interface: " + parameters);
    }

    private byte[] begin() {

        String sourceIp = "192.168.232.2";
        int sourcePort = 0;
        String destIp = "54.200.56.198";
        int destPort = 500;

        generateInitiatorCookie(sourceIp, sourcePort, destIp, destPort);

        byte[] header = prepareHeader(1);

        mSAPayload = prepareSAPayload();

        int size = header.length + mSAPayload.length;
        byte[] payloadLength = Utils.toBytes(size);
        System.arraycopy(payloadLength, 0, header, 24, 4);

        byte[] firstMsg = new byte[size];
        System.arraycopy(header, 0, firstMsg, 0, header.length);
        System.arraycopy(mSAPayload, 0, firstMsg, header.length, mSAPayload.length);

        return firstMsg;
    }

    private byte[] prepareHeader(int nextPayloadType) {

        byte[] header = new byte[28];

        //byte[] initiatorCookie = mInitiatorCookie;
        //byte[] responderCookie = new byte[8];
        byte[] nextPayload = Utils.toBytes(nextPayloadType, 1);    // Security Association
        byte[] version = new byte[1];
        version[0] |= 1 << 4;       // Major version: 1 (first 4 bits), Minor version: 0 (last 4 bits)
        byte[] exchangeType = Utils.toBytes(2, 1);  // 2 - Identity Protection (Main mode)
        byte[] flags = new byte[1];
        byte[] messageId = new byte[4];
        byte[] payloadLength = new byte[4];

        System.arraycopy(mInitiatorCookie, 0, header, 0, 8);
        System.arraycopy(mResponderCookie, 0, header, 8, 8);
        System.arraycopy(nextPayload, 0, header, 16, 1);
        System.arraycopy(version, 0, header, 17, 1);
        System.arraycopy(exchangeType, 0, header, 18, 1);
        System.arraycopy(flags, 0, header, 19, 1);
        System.arraycopy(messageId, 0, header, 20, 4);
        System.arraycopy(payloadLength, 0, header, 24, 4);

        return header;
    }

    private byte[] generateInitiatorCookie(String sourceIp, int sourcePort, String destIp, int destPort) {

        Long ct = System.currentTimeMillis();
        InetSocketAddress sa1 = new InetSocketAddress(sourceIp, sourcePort);
        InetSocketAddress sa2 = new InetSocketAddress(destIp, destPort);

        byte[] chars = new byte[30];
        System.arraycopy(sa1.getAddress().getAddress(), 0, chars, 0, ADDRESS_BUFFER_SIZE);

        System.arraycopy(Utils.toBytes(sa1.getPort()), 0, chars, 4, Utils.INT_BUFFER_SIZE);

        System.arraycopy(sa2.getAddress().getAddress(), 0, chars, 8, ADDRESS_BUFFER_SIZE);

        System.arraycopy(Utils.toBytes(sa2.getPort()), 0, chars, 12, Utils.INT_BUFFER_SIZE);

        System.arraycopy(Utils.toBytes(ct.longValue()), 0, chars, 16, Utils.LONG_BUFFER_SIZE);

        Random random = new Random();
        System.arraycopy(Utils.toBytes(random.nextInt()), 0, chars, 24, Utils.INT_BUFFER_SIZE);

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
            byte[] value = messageDigest.digest(chars);

            StringBuilder stringBuilder = new StringBuilder();
            for (int i = 0; i < 8; i++) {
                String c = String.format("%02x", value[i]);
                stringBuilder.append(c);
            }

            Log.d(TAG, "value: " + stringBuilder.toString());

            System.arraycopy(value, 0, mInitiatorCookie, 0, 8);
            return mInitiatorCookie;

        } catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] prepareSAPayload() {


        byte[] nextPayload = new byte[1];
        //nextPayload[0] = 0;
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] doi = Utils.toBytes(1);
        byte[] situation = Utils.toBytes(1);

        byte[] proposalPayload = prepareProposalPayload();

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + doi.length + situation.length + proposalPayload.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] saPayload = new byte[size];

        System.arraycopy(nextPayload, 0, saPayload, 0, 1);
        System.arraycopy(reserved, 0, saPayload, 1, 1);
        System.arraycopy(payloadLength, 0, saPayload, 2, 2);
        System.arraycopy(doi, 0, saPayload, 4, 4);
        System.arraycopy(situation, 0, saPayload, 8, 4);
        System.arraycopy(proposalPayload, 0, saPayload, 12, proposalPayload.length);

        return saPayload;

    }

    private byte[] prepareProposalPayload2() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(1, 1);
        byte[] spiSize = new byte[1];
        byte[] transformNumber = Utils.toBytes(1, 1);

        byte[] transformPayload1 = prepareTransformPayload(1);


        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + transformPayload1.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] proposalPayload = new byte[size];

        System.arraycopy(nextPayload, 0, proposalPayload, 0, 1);
        System.arraycopy(reserved, 0, proposalPayload, 1, 1);
        System.arraycopy(payloadLength, 0, proposalPayload, 2, 2);
        System.arraycopy(proposalNumber, 0, proposalPayload, 4, 1);
        System.arraycopy(protocolId, 0, proposalPayload, 5, 1);
        System.arraycopy(spiSize, 0, proposalPayload, 6, 1);
        System.arraycopy(transformNumber, 0, proposalPayload, 7, 1);
        System.arraycopy(transformPayload1, 0, proposalPayload, 8, transformPayload1.length);


        return proposalPayload;

    }

    private byte[] prepareProposalPayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(1, 1);
        byte[] spiSize = new byte[1];
        byte[] transformNumber = Utils.toBytes(1, 1);

        byte[] transformPayload1 = prepareTransformPayload(1);
        byte[] transformPayload2 = prepareTransformPayload(2);
        byte[] transformPayload3 = prepareTransformPayload(3);
        byte[] transformPayload4 = prepareTransformPayload(4);
        byte[] transformPayload5 = prepareTransformPayload(5);
        byte[] transformPayload6 = prepareTransformPayload(6);
        byte[] transformPayload7 = prepareTransformPayload(7);
        byte[] transformPayload8 = prepareTransformPayload(8);
        byte[] transformPayload9 = prepareTransformPayload(9);
        byte[] transformPayload10 = prepareTransformPayload(10);
        byte[] transformPayload11 = prepareTransformPayload(11);
        byte[] transformPayload12 = prepareTransformPayload(12);
        byte[] transformPayload13 = prepareTransformPayload(13);
        byte[] transformPayload14 = prepareTransformPayload(14);
        byte[] transformPayload15 = prepareTransformPayload(15);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + transformPayload1.length +
                transformPayload2.length + transformPayload3.length + transformPayload4.length +
                transformPayload5.length + transformPayload6.length + transformPayload7.length +
                transformPayload8.length + transformPayload9.length + transformPayload10.length +
                transformPayload11.length + transformPayload12.length + transformPayload13.length +
                transformPayload14.length + transformPayload15.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] proposalPayload = new byte[size];

        System.arraycopy(nextPayload, 0, proposalPayload, 0, 1);
        System.arraycopy(reserved, 0, proposalPayload, 1, 1);
        System.arraycopy(payloadLength, 0, proposalPayload, 2, 2);
        System.arraycopy(proposalNumber, 0, proposalPayload, 4, 1);
        System.arraycopy(protocolId, 0, proposalPayload, 5, 1);
        System.arraycopy(spiSize, 0, proposalPayload, 6, 1);
        System.arraycopy(transformNumber, 0, proposalPayload, 7, 1);
        System.arraycopy(transformPayload1, 0, proposalPayload, 8, transformPayload1.length);
        System.arraycopy(transformPayload2, 0, proposalPayload, 8 + transformPayload1.length, transformPayload2.length);
        System.arraycopy(transformPayload3, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length,
                transformPayload3.length);
        System.arraycopy(transformPayload4, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length, transformPayload4.length);
        System.arraycopy(transformPayload5, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length, transformPayload5.length);
        System.arraycopy(transformPayload6, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length, transformPayload6.length);
        System.arraycopy(transformPayload7, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length, transformPayload7.length);
        System.arraycopy(transformPayload8, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length, transformPayload8.length);
        System.arraycopy(transformPayload9, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length + transformPayload8.length, transformPayload9.length);
        System.arraycopy(transformPayload10, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length + transformPayload8.length + transformPayload9.length, transformPayload10.length);
        System.arraycopy(transformPayload11, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                        transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                        transformPayload7.length + transformPayload8.length + transformPayload9.length + transformPayload10.length,
                transformPayload11.length);
        System.arraycopy(transformPayload12, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length + transformPayload8.length + transformPayload9.length + transformPayload10.length +
                transformPayload11.length, transformPayload12.length);
        System.arraycopy(transformPayload13, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length + transformPayload8.length + transformPayload9.length + transformPayload10.length +
                transformPayload11.length + transformPayload12.length, transformPayload13.length);
        System.arraycopy(transformPayload14, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                transformPayload7.length + transformPayload8.length + transformPayload9.length + transformPayload10.length +
                transformPayload11.length + transformPayload12.length + transformPayload13.length, transformPayload14.length);
        System.arraycopy(transformPayload15, 0, proposalPayload, 8 + transformPayload1.length + transformPayload2.length +
                        transformPayload3.length + transformPayload4.length + transformPayload5.length + transformPayload6.length +
                        transformPayload7.length + transformPayload8.length + transformPayload9.length + transformPayload10.length +
                        transformPayload11.length + transformPayload12.length + transformPayload13.length + transformPayload14.length,
                transformPayload15.length);

        return proposalPayload;

    }

    private byte[] prepareTransformPayload(int i) {
        byte[] nextPayload = null;
//        if (i < 15) {
////            nextPayload = Utils.toBytes(3, 1);    // 3 - Transform payload
////        } else {
////            nextPayload = Utils.toBytes(0, 1);
////        }
        nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] transformNumber = Utils.toBytes(i, 1);
        byte[] transformId = Utils.toBytes(1, 1);
        byte[] reserved2 = new byte[2];

        byte[] attributes = prepareIKEAttribute1(i);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + transformNumber.length +
                transformId.length + reserved2.length + attributes.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] transformPayload = new byte[size];
        System.arraycopy(nextPayload, 0, transformPayload, 0, 1);
        System.arraycopy(reserved, 0, transformPayload, 1, 1);
        System.arraycopy(payloadLength, 0, transformPayload, 2, 2);
        System.arraycopy(transformNumber, 0, transformPayload, 4, 1);
        System.arraycopy(transformId, 0, transformPayload, 5, 1);
        System.arraycopy(reserved2, 0, transformPayload, 6, 2);
        System.arraycopy(attributes, 0, transformPayload, 8, attributes.length);

        return transformPayload;

    }

    private byte[] prepareIKEAttribute1(int transformNumber) {
        byte[] attr = null;
        switch (transformNumber) {
            case 1:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
//            System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 128), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 4), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 2:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 3:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 4:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 14), 0, attr, 24, 4);

                return attr;

            case 5:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 4), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 6:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 7:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 5), 0, attr, 24, 4);

                return attr;

            case 8:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 9:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 256), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 10:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 128), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 11:
                attr = new byte[28];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 7), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_14, 128), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 20, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 24, 4);

                return attr;

            case 12:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 5), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 13:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 5), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 14:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 1), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 2), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            case 15:
                attr = new byte[24];
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_11, 1), 0, attr, 0, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_12, 3600), 0, attr, 4, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_1, 1), 0, attr, 8, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_3, 65001), 0, attr, 12, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_2, 1), 0, attr, 16, 4);
                System.arraycopy(prepareIKEAttribute2(IKE_ATTRIBUTE_4, 2), 0, attr, 20, 4);

                return attr;

            default:
                return null;
        }
    }

    private byte[] prepareIKEAttribute2(int type, int value) {
        byte[] attributeType = new byte[2];
        byte[] attribute2ndPart = null;

        switch (type) {

            case IKE_ATTRIBUTE_1:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 1 - encryption-algorithm
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_2:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 1;     // 2 - hash-algorithm
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_3:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 3 - authentication-method
                attributeType[1] |= 1 << 1;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_4:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 2;     // 4 - group-description
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_11:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 0;     // 11 - life-type
                attributeType[1] |= 1 << 1;
                attributeType[1] |= 1 << 3;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_12:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 3;     // 12 - life-duration
                attributeType[1] |= 1 << 2;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            case IKE_ATTRIBUTE_14:
                attributeType[0] |= 1 << 7;     // Type/Value
                attributeType[1] |= 1 << 3;     // 14 - key-length
                attributeType[1] |= 1 << 2;
                attributeType[1] |= 1 << 1;
                attribute2ndPart = Utils.toBytes(value, 2);
                break;

            default:
                break;
        }

        byte[] ikeAttr = new byte[4];
        System.arraycopy(attributeType, 0, ikeAttr, 0, 2);
        System.arraycopy(attribute2ndPart, 0, ikeAttr, 2, 2);

        return ikeAttr;
    }

    private byte[] prepareSecondMsg(byte[] header) {

//        byte[] header = prepareHeader(4);
        byte[] keyExchangePayload = prepareKeyExchangePayload();
        byte[] noncePayload = prepareNoncePayload();

        int size = header.length + keyExchangePayload.length + noncePayload.length;

        byte[] msgLength = Utils.toBytes(size, 4);

        byte[] msg = new byte[size];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(msgLength, 0, msg, 24, 4);
        System.arraycopy(keyExchangePayload, 0, msg, 28, keyExchangePayload.length);
        System.arraycopy(noncePayload, 0, msg, 28 + keyExchangePayload.length, noncePayload.length);

        return msg;
    }

    private byte[] prepareKeyExchangePayload() {
        byte[] nextPayload = Utils.toBytes(10, 1);
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] keyExchangeData = prepareKeyExchangeData();

        int size = nextPayload.length + reserve.length + 2/*payloadLength.length*/ + keyExchangeData.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] payload = new byte[size];
        System.arraycopy(nextPayload, 0, payload, 0, 1);
        //System.arraycopy(reserve, 0, payload, 1, 1);
        System.arraycopy(payloadLength, 0, payload, 2, 2);
        System.arraycopy(keyExchangeData, 0, payload, 4, keyExchangeData.length);

        return payload;
    }

    private byte[] prepareNoncePayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] nonce = mKeyExchangeUtil.getNonce().toByteArray();

        int size = nextPayload.length + reserve.length + 2/*payloadLength.length*/ + nonce.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] payload = new byte[size];
        System.arraycopy(nextPayload, 0, payload, 0, 1);
        //System.arraycopy(reserve, 0, payload, 1, 1);
        System.arraycopy(payloadLength, 0, payload, 2, 2);
        System.arraycopy(nonce, 0, payload, 4, nonce.length);

        return payload;
    }



    private byte[] prepareKeyExchangeData() {
        mKeyExchangeUtil.generatePairKeys("test4stagwell");
        return mKeyExchangeUtil.getPublicKey();
    }

    private byte[] prepareThirdMsg(byte[] header, byte[] encryptedData) {
        byte[] msg = new byte[header.length + encryptedData.length];

        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(encryptedData, 0, msg, header.length, encryptedData.length);

        for (int i = 0; i < msg.length; i++) {
            Log.d(TAG, String.format("****** 0x%02x,  [%d]", msg[i], i));
        }

        return msg;
    }

    private byte[] prepareIdentificationPayload() {
        byte[] nextPayload = Utils.toBytes(8, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] idType = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(17, 1);
        byte[] port = Utils.toBytes(500, 2);

        byte[] data = new byte[4];
        data[0] = Utils.toBytes(10, 1)[0];
        data[1] = Utils.toBytes(10, 1)[0];
        data[2] = Utils.toBytes(68, 1)[0];
        data[3] = Utils.toBytes(104, 1)[0];

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + idType.length +
                protocolId.length + port.length + data.length;
        byte[] payloadLength = Utils.toBytes(size, 2);
        byte[] payload = new byte[size];

        System.arraycopy(nextPayload, 0, payload, 0, 1);
        System.arraycopy(reserved, 0, payload, 1, 1);
        System.arraycopy(payloadLength, 0, payload, 2, 2);
        System.arraycopy(idType, 0, payload, 4, 1);
        System.arraycopy(protocolId, 0, payload, 5, 1);
        System.arraycopy(port, 0, payload, 6, 2);
        System.arraycopy(data, 0, payload, 8, data.length);

        return payload;
    }

    private byte[] prepareHashPayload(byte[] idPayload) {
        byte[] nextPayload = Utils.toBytes(0, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] hashData = mKeyExchangeUtil.prepareHashPayloadData(mKeyExchangeUtil.getPublicKey(),
                keyData, isakmpHeader.initiatorCookie, isakmpHeader.responderCookie, mSAPayload, idPayload);

        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(size, 2);
        byte[] payload = new byte[size];

        System.arraycopy(nextPayload, 0, payload, 0, 1);
        System.arraycopy(reserved, 0, payload, 1, 1);
        System.arraycopy(payloadLength, 0, payload, 2, 2);
        System.arraycopy(hashData, 0, payload, 4, hashData.length);

        return payload;
    }


}
