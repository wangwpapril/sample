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
import com.tenone.testapplication.isakmp.PayloadAttribute;
import com.tenone.testapplication.isakmp.PayloadBase;
import com.tenone.testapplication.isakmp.PayloadKeyEx;
import com.tenone.testapplication.isakmp.PayloadNonce;
import com.tenone.testapplication.isakmp.ResponseBase;
import com.tenone.testapplication.isakmp.ResponseConfigModeFirst;
import com.tenone.testapplication.isakmp.ResponseConfigModeSecond;
import com.tenone.testapplication.isakmp.ResponseConfigModeThird;
import com.tenone.testapplication.isakmp.ResponseDecryptBase;
import com.tenone.testapplication.isakmp.ResponseMainModeFirst;
import com.tenone.testapplication.isakmp.ResponseMainModeSecond;
import com.tenone.testapplication.isakmp.ResponseMainModeThird;
import com.tenone.testapplication.isakmp.ResponseQuickModeFirst;
import com.tenone.testapplication.isakmp.Utils;

import org.spongycastle.util.IPAddress;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
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

    private final String mUserName = "testvpn";
    private final String mPassword = "stagwell";

    private byte[] mInitiatorCookie = new byte[8];
    private byte[] mResponderCookie = new byte[8];
    private KeyExchangeUtil mKeyExchangeUtil;

    IsakmpHeader isakmpHeader;
    byte[] keyData;
    byte[] nonceData;
    byte[] ipAddress;
    byte[] dns;
    byte[] subnet;

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
            mKeyExchangeUtil.setEncryptAlgorithm("AES256");
            Intent pendingIntent = new Intent(this, MainActivity.class);
            configureIntent = PendingIntent.getActivity(this, REQUEST_CODE, pendingIntent, DEFAULT_INTENT_FLAG);

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
//                        throw new IllegalStateException("Timed out");
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
//                    p.put(preparePhase1SecondMsg()).flip();
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
//                        p.put(preparePhase1ThirdMsg(packet.array()));
//                    }
//                }
//            } catch (InterruptedException e) {
//                Log.e(TAG, "Thread interrupted " + e);
//            } catch (IOException e) {
//                Log.e(TAG, "Tunnel read failed " + e);
//            }
//        }

        ByteBuffer packet = ByteBuffer.allocate(HANDSHAKE_BUFFER);
        for (int i = 1; i <= 10; i++) {
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
                packet.put(preparePhase1SecondMsg(isakmpHeader.toData(4))).flip();
                if(sendMessage(packet, tunnel)) {
                    if (readMessage(packet, tunnel)) {
                        packet.position(0);
                        responseBase = new ResponseMainModeSecond(packet);
                        if (responseBase != null && responseBase.isValid()) {
                            for (PayloadBase base : responseBase.payloadList) {
                                if (base instanceof PayloadKeyEx) {
                                    keyData = ((PayloadKeyEx) base).keyExData;
                                    KeyExchangeUtil.getInstance().setServerPublicKeyData(keyData);
                                }

                                if (base instanceof PayloadNonce) {
                                    nonceData = ((PayloadNonce) base).nonceData;
                                    KeyExchangeUtil.getInstance().setResponderNonce(nonceData);
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
                    byte[] hashPayload = prepareHashPayloadForIDPayload(idPayload);

                    byte[] combineData = new byte[idPayload.length + hashPayload.length];
                    System.arraycopy(idPayload, 0, combineData, 0, idPayload.length);
                    System.arraycopy(hashPayload, 0, combineData, idPayload.length, hashPayload.length);

                    byte[] encryptedData = mKeyExchangeUtil.prepare1stEncryptedPayload(combineData, keyData);
                    packet.put(preparePhase1ThirdMsg(isakmpHeader.toData(5, encryptedData.length + 28, flag[0]), encryptedData)).flip();
                    if (sendMessage(packet, tunnel)) {
                        byte[] Iv = new byte[16];
                        System.arraycopy(encryptedData, encryptedData.length - 16, Iv, 0, 16);
                        KeyExchangeUtil.getInstance().setIV(Iv);

                        while (readMessage(packet, tunnel)) {
                            packet.position(0);
                            ResponseMainModeThird response = new ResponseMainModeThird(packet);
                            if (response != null && response.isValid()) {
                                responseBase = response;
                                KeyExchangeUtil.getInstance().setFirstPhaseIv(response.getNextIv());
                                break;
                            }
                        }

                    }
                }
                break;
            case 4:
                while (readMessage(packet, tunnel)) {
                    packet.position(0);
                    ResponseConfigModeFirst response = new ResponseConfigModeFirst(packet);
                    if (response != null && response.isValid()) {
                        responseBase = response;
                        isakmpHeader = response.isakmpHeader;
                        KeyExchangeUtil.getInstance().setIV(response.getNextIv());

                        packet.clear();
                        byte[] payload = preparePhase2ConfigModeFirstMsg(isakmpHeader.toData(8), isakmpHeader.messageId);
                        packet.put(payload).flip();

                        if (sendMessage(packet, tunnel)) {
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
                        isakmpHeader = response.isakmpHeader;
                        KeyExchangeUtil.getInstance().setIV(response.getNextIv());

                        packet.clear();
                        byte[] secondMsg = preparePhase2ConfigModeSecondMsg(isakmpHeader.toData(8), isakmpHeader.messageId);
                        packet.put(secondMsg).flip();
                        if (sendMessage(packet, tunnel)) {
                            byte[] Iv = new byte[16];
                            System.arraycopy(secondMsg, secondMsg.length - 16, Iv, 0, 16);
                            KeyExchangeUtil.getInstance().setIV(Iv);

                            packet.clear();
                            Random random = new Random();
                            int messageId = random.nextInt();
                            KeyExchangeUtil.getInstance().preparePhase2IV(Utils.toBytes(messageId, 4));
                            byte[] thirdMsg = preparePhase2ConfigModeThirdMsg(isakmpHeader.toData(8, messageId), messageId);
                            packet.put(thirdMsg).flip();
                            if (sendMessage(packet, tunnel)) {
                                System.arraycopy(thirdMsg, thirdMsg.length - 16, Iv, 0, 16);
                                KeyExchangeUtil.getInstance().setIV(Iv);
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
                        responseBase = response;
                        isakmpHeader = response.isakmpHeader;
                        if (response.payloadList.get(1) instanceof PayloadAttribute) {
                            ipAddress = ((PayloadAttribute) response.payloadList.get(1)).attributeList.get(0).value;
                            subnet = ((PayloadAttribute) response.payloadList.get(1)).attributeList.get(1).value;

                            packet.clear();
                            SecureRandom random = new SecureRandom();
                            int messageId = random.nextInt();

                            byte[] firstMsgQuickMode = preparePhase2QuickModeFirstMsg(isakmpHeader.toData(8, messageId, 32),
                                    messageId, ipAddress, subnet);
                            packet.put(firstMsgQuickMode).flip();
                            if (sendMessage(packet, tunnel)) {
                                Log.d(TAG, "SENT FIRST MESSAGE IN QUICK MODE");
                                byte[] Iv = new byte[16];
                                System.arraycopy(firstMsgQuickMode, firstMsgQuickMode.length - 16, Iv, 0, 16);
                                KeyExchangeUtil.getInstance().setIV(Iv);

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
                    if (response != null && response.isValid()) {
                        responseBase = response;
                        isakmpHeader = response.isakmpHeader;

                        KeyExchangeUtil.getInstance().setIV(response.getNextIv());

                        packet.clear();
                        byte[] responderNonce = ((PayloadNonce)response.payloadList.get(2)).nonceData;
                        byte[] lastMsg = preparePhase2QuickModeSecondMsg(isakmpHeader.toData(8),
                                isakmpHeader.messageId, responderNonce);
                        packet.put(lastMsg).flip();
                        if (sendMessage(packet, tunnel)) {
                            Log.d(TAG, "Sent last message in quick mode");
                        }
                        break;
                    }
                }
                break;
            case 8:
                setUp();
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

    private void setUp() {
        if (fileDescriptor != null) {
            Log.d(TAG, "Using the previous interface");
            return;
        }
        InetAddress ia = null;
        InetAddress ir = null;
//        byte[] rr = new byte[]{(byte)0,(byte)0,(byte)0,(byte)0};
        try {
            ia = InetAddress.getByAddress(ipAddress);
            ir = InetAddress.getByAddress(subnet);
//            InetAddress in = InetAddress.getByAddress(subnet);
//            address = ia.toString();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }


        // Configure a builder while parsing the parameters.
        Builder builder = new Builder();

        builder.setMtu(15000);
        builder.addAddress(ia, 0);
//        builder.addAddress("10.10.68.200", 0);
        builder.addRoute(ir, 0);
//        builder.addRoute("0.0.0.0", 0);
        builder.addDnsServer("8.8.4.4");

        // Close the old interface since the parameters have been changed.
//        try {
//            fileDescriptor.close();
//        } catch (IOException e) {
//            Log.e(TAG, "File descriptor is already closed " + e);
//        }
//        // Create a new interface using the builder and save the parameters.
        fileDescriptor = builder.setSession(mServerAddress)
//                .setConfigureIntent(configureIntent)
                .establish();
//        vpnParameters = parameters;
//        Log.d(TAG, "New interface: " + parameters);
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

        return preparePhase1FirstMsg(header);
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
        System.arraycopy(flags, 0  , header, 19, 1);
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

    private byte[] preparePhase1FirstMsg(byte[] header) {

        mSAPayload = prepareSAPayload();

        KeyExchangeUtil.getInstance().setSAPayload(mSAPayload);

        byte[] vidPayloads = prepareVendorIDPayloads();

        int size = header.length + mSAPayload.length + vidPayloads.length;
        byte[] payloadLength = Utils.toBytes(size);
        System.arraycopy(payloadLength, 0, header, 24, 4);

        byte[] firstMsg = new byte[size];
        System.arraycopy(header, 0, firstMsg, 0, header.length);
        System.arraycopy(mSAPayload, 0, firstMsg, header.length, mSAPayload.length);
        System.arraycopy(vidPayloads, 0, firstMsg, header.length + mSAPayload.length, vidPayloads.length);

        return firstMsg;
    }

    private byte[] prepareSAPayload() {


        byte[] nextPayload = Utils.toBytes(13, 1);
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

    /**
     * Proposal payload. Currently has only one transform payload which uses AES_CBC for encryption, and SHA2-256 for hash
     * @return
     */
    private byte[] prepareProposalPayload() {
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

    /**
     * Not using at this time. Propose 15 transforms that we support
     * @return
     */
    private byte[] prepareProposalPayload2() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(1, 1);
        byte[] spiSize = new byte[1];
        byte[] transformNumber = Utils.toBytes(15, 1);

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

    private byte[] prepareVendorIDPayloads() {
        byte[] vid_payload1 = prepareVendorPayload(1);
        byte[] vid_payload2 = prepareVendorPayload(2);
        byte[] vid_payload3 = prepareVendorPayload(3);
        byte[] vid_payload4 = prepareVendorPayload(4);
        byte[] vid_payload5 = prepareVendorPayload(5);
        byte[] vid_payload6 = prepareVendorPayload(6);
        byte[] vid_payload7 = prepareVendorPayload(7);
        byte[] vid_payload8 = prepareVendorPayload(8);

        byte[] allVidPayloads = new byte[vid_payload1.length + vid_payload2.length + vid_payload3.length +
                vid_payload4.length + vid_payload5.length + vid_payload6.length + vid_payload7.length + vid_payload8.length];

        System.arraycopy(vid_payload1, 0, allVidPayloads, 0, vid_payload1.length);
        System.arraycopy(vid_payload2, 0, allVidPayloads, vid_payload1.length, vid_payload2.length);
        System.arraycopy(vid_payload3, 0, allVidPayloads, vid_payload1.length + vid_payload2.length, vid_payload3.length);
        System.arraycopy(vid_payload4, 0, allVidPayloads,
                vid_payload1.length + vid_payload2.length + vid_payload3.length, vid_payload4.length);
        System.arraycopy(vid_payload5, 0, allVidPayloads,
                vid_payload1.length + vid_payload2.length + vid_payload3.length + vid_payload4.length, vid_payload5.length);
        System.arraycopy(vid_payload6, 0, allVidPayloads,
                vid_payload1.length + vid_payload2.length + vid_payload3.length + vid_payload4.length + vid_payload5.length,
                vid_payload6.length);
        System.arraycopy(vid_payload7, 0, allVidPayloads,
                vid_payload1.length + vid_payload2.length + vid_payload3.length + vid_payload4.length + vid_payload5.length +
                vid_payload6.length, vid_payload7.length);
        System.arraycopy(vid_payload8, 0, allVidPayloads,
                vid_payload1.length + vid_payload2.length + vid_payload3.length + vid_payload4.length + vid_payload5.length +
                        vid_payload6.length + vid_payload7.length, vid_payload8.length);

        return allVidPayloads;
    }

    private byte[] prepareVendorPayload(int num) {
        byte[] nextPayload = null;
        if (num < 8) {
            nextPayload = Utils.toBytes(13, 1);
        } else {
            nextPayload = new byte[1];
        }
        byte[] reserved = new byte[1];
        //byte[] payloadLengtgh = new byte[2];
        byte[] VID_NAT_3947 = {(byte)0x4a, (byte)0x13, (byte)0x1c, (byte)0x81, (byte)0x07, (byte)0x03, (byte)0x58, (byte)0x45, (byte)0x5c, (byte)0x57, (byte)0x28, (byte)0xf2, (byte)0x0e, (byte)0x95, (byte)0x45, (byte)0x2f};
        byte[] VID_IKE2 = {(byte)0xcd, (byte)0x60, (byte)0x46, (byte)0x43, (byte)0x35, (byte)0xdf, (byte)0x21, (byte)0xf8, (byte)0x7c, (byte)0xfd, (byte)0xb2, (byte)0xfc, (byte)0x68, (byte)0xb6, (byte)0xa4, (byte)0x48};
        byte[] VID_IKE2b = {(byte)0x90, (byte)0xcb, (byte)0x80, (byte)0x91, (byte)0x3e, (byte)0xbb, (byte)0x69, (byte)0x6e, (byte)0x08, (byte)0x63, (byte)0x81, (byte)0xb5, (byte)0xec, (byte)0x42, (byte)0x7b, (byte)0x1f};
        byte[] VID_IKE = {(byte)0x44, (byte)0x85, (byte)0x15, (byte)0x2d, (byte)0x18, (byte)0xb6, (byte)0xbb, (byte)0xcd, (byte)0x0b, (byte)0xe8, (byte)0xa8, (byte)0x46, (byte)0x95, (byte)0x79, (byte)0xdd, (byte)0xcc};
        byte[] VID_XAUTH = {(byte)0x09, (byte)0x00, (byte)0x26, (byte)0x89, (byte)0xdf, (byte)0xd6, (byte)0xb7, (byte)0x12};
        byte[] VID_CISCO_UNITY = {(byte)0x12, (byte)0xf5, (byte)0xf2, (byte)0x8c, (byte)0x45, (byte)0x71, (byte)0x68, (byte)0xa9, (byte)0x70, (byte)0x2d, (byte)0x9f, (byte)0xe2, (byte)0x74, (byte)0xcc, (byte)0x01, (byte)0x00};
        byte[] VID_CISCO_FRAGMENT = {(byte)0x40, (byte)0x48, (byte)0xb7, (byte)0xd5, (byte)0x6e, (byte)0xbc, (byte)0xe8, (byte)0x85, (byte)0x25, (byte)0xe7, (byte)0xde, (byte)0x7f, (byte)0x00, (byte)0xd6, (byte)0xc2, (byte)0xd3, (byte)0x80, (byte)0x00, (byte)0x00, (byte)0x00};
        byte[] VID_NAT_3706 = {(byte)0xaf, (byte)0xca, (byte)0xd7, (byte)0x13, (byte)0x68, (byte)0xa1, (byte)0xf1, (byte)0xc9, (byte)0x6b, (byte)0x86, (byte)0x96, (byte)0xfc, (byte)0x77, (byte)0x57, (byte)0x01, (byte)0x00};
        byte[] data = null;
        
        switch (num) {
            case 1:
                data = VID_NAT_3947;
                break;

            case 2:
                data = VID_IKE2;
                break;

            case 3:
                data = VID_IKE2b;
                break;

            case 4:
                data = VID_IKE;
                break;

            case 5:
                data = VID_XAUTH;
                break;

            case 6:
                data = VID_CISCO_UNITY;
                break;

            case 7:
                data = VID_CISCO_FRAGMENT;
                break;

            case 8:
                data = VID_NAT_3706;
                break;

            default:
                break;

        }

        int len = nextPayload.length + reserved.length + 2/*payloadLengtgh*/ + data.length;
        byte[] payloadLength = Utils.toBytes(len, 2);
        byte[] payload = new byte[len];
        
        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(data, 0, payload,
                nextPayload.length + reserved.length + payloadLength.length, data.length);

        return payload;
    }

    private byte[] preparePhase1SecondMsg(byte[] header) {

//        byte[] header = prepareHeader(4);
        byte[] keyExchangePayload = prepareKeyExchangePayload();
        byte[] noncePayload = prepareNoncePayload(20, 1);
        byte[] natPayload1 = prepareNatPayload(20, isakmpHeader.responderCookie,
                mServerAddress, mServerPort);
        byte[] natPayload2 = prepareNatPayload(0, isakmpHeader.responderCookie,
                Utils.getIPAddress1(getApplicationContext()), "500");

        int size = header.length + keyExchangePayload.length + noncePayload.length + natPayload1.length + natPayload2.length;

        byte[] msgLength = Utils.toBytes(size, 4);

        byte[] msg = new byte[size];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(msgLength, 0, msg, 24, 4);
        System.arraycopy(keyExchangePayload, 0, msg, 28, keyExchangePayload.length);
        System.arraycopy(noncePayload, 0, msg, 28 + keyExchangePayload.length, noncePayload.length);
        System.arraycopy(natPayload1, 0, msg, 28 + keyExchangePayload.length + noncePayload.length,
                natPayload1.length);
        System.arraycopy(natPayload2, 0, msg, 28 + keyExchangePayload.length + noncePayload.length +
                natPayload1.length, natPayload2.length);

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

    private byte[] prepareNoncePayload(int nextPayloadNumber, int phaseNumber) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNumber, 1);
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] nonce = mKeyExchangeUtil.getNonce(phaseNumber).toByteArray();

        int size = nextPayload.length + reserve.length + 2/*payloadLength.length*/ + nonce.length;
        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] payload = new byte[size];
        System.arraycopy(nextPayload, 0, payload, 0, 1);
        //System.arraycopy(reserve, 0, payload, 1, 1);
        System.arraycopy(payloadLength, 0, payload, 2, 2);
        System.arraycopy(nonce, 0, payload, 4, nonce.length);

        return payload;
    }

    private byte[] prepareNatPayload(int nextPayloadNumber, byte[] responderCookie, String ipAddress, String port) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNumber, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] dataForHash = new byte[8 + 8 + 4 + 2];

        String[] ipNumbers = ipAddress.split("\\.");
        byte[] ipBytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            ipBytes[i] = Utils.toBytes(Integer.valueOf(ipNumbers[i]), 1)[0];
        }
        byte[] portBytes = Utils.toBytes(Integer.valueOf(port), 2);

        System.arraycopy(mInitiatorCookie, 0, dataForHash, 0, 8);
        System.arraycopy(responderCookie, 0, dataForHash, 8, 8);
        System.arraycopy(ipBytes, 0, dataForHash, 16, 4);
        System.arraycopy(portBytes, 0, dataForHash, 20, 2);

        byte[] hashData = KeyExchangeUtil.getInstance().hashDataWithoutKey(dataForHash);
        int len = nextPayload.length + reserved.length + 2/*payloadLength*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(len, 2);
        byte[] payload = new byte[len];
        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(hashData, 0, payload, nextPayload.length + reserved.length + payloadLength.length,
                hashData.length);

        return payload;
    }

    public byte[] preparePhase2ConfigModeFirstMsg(byte[] header, int messageId) {
        byte[] loginConfigPayload = prepareLoginConfigPayload(Utils.toBytes(messageId));

        byte[] msg = new byte[header.length + loginConfigPayload.length];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(Utils.toBytes(header.length + loginConfigPayload.length), 0, msg, 24, 4);
        System.arraycopy(loginConfigPayload, 0, msg, header.length, loginConfigPayload.length);

        return msg;
    }

    public byte[] preparePhase2ConfigModeSecondMsg(byte[] header, int messageId) {
        byte[] ackConfigPayload = prepareAcknowledgeConfigPayload(Utils.toBytes(messageId));

        byte[] msg = new byte[header.length + ackConfigPayload.length];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(Utils.toBytes(header.length + ackConfigPayload.length), 0, msg, 24, 4);
        System.arraycopy(ackConfigPayload, 0, msg, header.length, ackConfigPayload.length);

        return msg;
    }

    public byte[] prepareLoginConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14, 1);
        byte[] reserve = new byte[1];

        byte[] loginAttributePayload = prepareLoginAttributePayload();
        byte[][] payloads = new byte[1][];
        payloads[0] = loginAttributePayload;
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);
        byte[] payloadBeforeEncrypt = new byte[nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length + loginAttributePayload.length];

        System.arraycopy(nextPayload, 0, payloadBeforeEncrypt, 0, nextPayload.length);
        System.arraycopy(reserve, 0, payloadBeforeEncrypt, nextPayload.length, reserve.length);
        System.arraycopy(payloadLength, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length, payloadLength.length);
        System.arraycopy(hashData, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length + payloadLength.length, hashData.length);
        System.arraycopy(loginAttributePayload, 0, payloadBeforeEncrypt,
                nextPayload.length + reserve.length + payloadLength.length + hashData.length, loginAttributePayload.length);

        return mKeyExchangeUtil.encryptData(payloadBeforeEncrypt);
    }

    private byte[] prepareAcknowledgeConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14, 1);
        byte[] reserve = new byte[1];

        byte[] ackAttributePayload = prepareAckAttributePayload();
        byte[][] payloads = new byte[1][];
        payloads[0] = ackAttributePayload;
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);
        byte[] payloadBeforeEncrypt = new byte[nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length + ackAttributePayload.length];

        System.arraycopy(nextPayload, 0, payloadBeforeEncrypt, 0, nextPayload.length);
        System.arraycopy(reserve, 0, payloadBeforeEncrypt, nextPayload.length, reserve.length);
        System.arraycopy(payloadLength, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length, payloadLength.length);
        System.arraycopy(hashData, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length + payloadLength.length, hashData.length);
        System.arraycopy(ackAttributePayload, 0, payloadBeforeEncrypt,
                nextPayload.length + reserve.length + payloadLength.length + hashData.length, ackAttributePayload.length);

        return mKeyExchangeUtil.encryptData(payloadBeforeEncrypt);
    }

    private byte[] prepareAckAttributePayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(4, 1);      // ISAKMP-CFG-ACK
        byte[] identifier = new byte[2];

        // 49295 (0xc08f)
        byte[] attribute = Utils.toBytes(49295, 2);
        byte[] attribute_value = new byte[2];
        int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                type.length + identifier.length + attribute.length + attribute_value.length;
        byte[] payloadLength = Utils.toBytes(length, 2);

        byte[] payload = new byte[length];
        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserve, 0, payload, nextPayload.length, reserve.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserve.length, payloadLength.length);
        System.arraycopy(type, 0, payload, nextPayload.length + reserve.length + payloadLength.length, type.length);
        System.arraycopy(reserve, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length,
                reserve.length);
        System.arraycopy(identifier, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                reserve.length, identifier.length);
        System.arraycopy(attribute, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                reserve.length + identifier.length, attribute.length);
        System.arraycopy(attribute_value, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                reserve.length + identifier.length + attribute.length, attribute_value.length);

        return payload;
    }

    private byte[] generateHashDataForPayloads(byte[] messageId, byte[][] payloads){
        int length = messageId.length;
        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_PACKET_SIZE);
        byteBuffer.put(messageId);

        for (int i = 0; i < payloads.length; i++) {
            byteBuffer.put(payloads[i]);
            length += payloads[i].length;
        }

        byte[] inputData = new byte[length];
        System.arraycopy(byteBuffer.array(), 0, inputData, 0, length);

        return mKeyExchangeUtil.hashConfigModePayload(inputData);
    }

    public byte[] prepareLoginAttributePayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserve = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(2, 1);      // ISKAMP_CFG_REPLY
        byte[] identifier = new byte[2];

        try {
            // XAUTH-USER-NAME. https://tools.ietf.org/html/draft-beaulieu-ike-xauth-02
            byte[] attribute_username = getTypeLengthValueAttribute(16521, mUserName.getBytes("UTF-8"));
            // // XAUTH-USER-PASSWORD
            byte[] attribute_password = getTypeLengthValueAttribute(16522, mPassword.getBytes("UTF-8"));
            int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                    type.length + identifier.length + attribute_username.length + attribute_password.length;
            byte[] payloadLength = Utils.toBytes(length, 2);

            byte[] payload = new byte[length];
            System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
            System.arraycopy(reserve, 0, payload, nextPayload.length, reserve.length);
            System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserve.length, payloadLength.length);
            System.arraycopy(type, 0, payload, nextPayload.length + reserve.length + payloadLength.length, type.length);
            System.arraycopy(reserve, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length,
                    reserve.length);
            System.arraycopy(identifier, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length, identifier.length);
            System.arraycopy(attribute_username, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length, attribute_username.length);
            System.arraycopy(attribute_password, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length + attribute_username.length, attribute_password.length);

            return payload;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] getTypeLengthValueAttribute(int type, byte[] attribute_data) {
        byte[] attribute_type = Utils.toBytes(type, 2);
        byte[] output = new byte[attribute_type.length + 2 /*length*/ + attribute_data.length];
        byte[] attribute_length = Utils.toBytes(attribute_data.length, 2);
        System.arraycopy(attribute_type, 0, output, 0, attribute_type.length);
        System.arraycopy(attribute_length, 0, output, attribute_type.length, attribute_length.length);
        System.arraycopy(attribute_data, 0, output, attribute_type.length + attribute_length.length, attribute_data.length);

        return output;
    }

    private byte[] getTypeValueAttribute(int type, int value) {
        byte[] attribute_type = Utils.toBytes(type, 2);
        byte[] output = new byte[4];
        byte[] attribute_value = Utils.toBytes(value, 2);
        System.arraycopy(attribute_type, 0, output, 0, attribute_type.length);
        System.arraycopy(attribute_value, 0, output, attribute_type.length, attribute_value.length);

        return output;
    }

    private byte[] prepareKeyExchangeData() {
        mKeyExchangeUtil.generatePairKeys("test4stagwell");
        return mKeyExchangeUtil.getPublicKey();
    }

    private byte[] preparePhase1ThirdMsg(byte[] header, byte[] encryptedData) {
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

    private byte[] prepareHashPayloadForIDPayload(byte[] idPayload) {
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

    public byte[] preparePhase2ConfigModeThirdMsg(byte[] header, int messageId) {
        byte[] ipConfigPayload = prepareIpConfigPayload(Utils.toBytes(messageId));

        byte[] msg = new byte[header.length + ipConfigPayload.length];
        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(Utils.toBytes(header.length + ipConfigPayload.length), 0, msg, 24, 4);
        System.arraycopy(ipConfigPayload, 0, msg, header.length, ipConfigPayload.length);

        return msg;
    }

    private byte[] preparePhase2QuickModeFirstMsg(byte[] header, int messageId, byte[] ipAddress, byte[] subnet) {

        byte[] messageIdBytes = Utils.toBytes(messageId);
        KeyExchangeUtil.getInstance().print("Quick mode 1st message id. ", messageIdBytes);
        // use the last 16 bytes from last encrypted message in phase 1 + current message id
        KeyExchangeUtil.getInstance().preparePhase2IV(messageIdBytes);

        byte[] saPayload = preparePhase2SAPayload();
        KeyExchangeUtil.getInstance().print("saPayload 1st message in quick mode. ", saPayload);

        byte[] noncePayload = prepareNoncePayload(5, 2);
        KeyExchangeUtil.getInstance().print("noncePayload 1st message in quick mode. ", noncePayload);

        byte[] idPayload1 = preparePhase2IDPayload1(ipAddress);
        KeyExchangeUtil.getInstance().print("idPayload1 1st message in quick mode. ", idPayload1);

        byte[] idPayload2 = preparePhase2IDPayload2(subnet);
        KeyExchangeUtil.getInstance().print("idPayload2 1st message in quick mode. ", idPayload2);

        byte[][] allPayloads = new byte[4][];
        allPayloads[0] = saPayload;
        allPayloads[1] = noncePayload;
        allPayloads[2] = idPayload1;
        allPayloads[3] = idPayload2;

        byte[] hashData = generateHashDataForPayloads(messageIdBytes, allPayloads);
        KeyExchangeUtil.getInstance().print("hashData 1st message in quick mode. ", hashData);

        byte[] hashPayload = prepareHashPayload(hashData, 1);

        KeyExchangeUtil.getInstance().print("hashPayload 1st message in quick mode. ", hashPayload);

        byte[] dataForEncryption = new byte[hashPayload.length + saPayload.length + noncePayload.length +
                idPayload1.length + idPayload2.length];
        System.arraycopy(hashPayload, 0, dataForEncryption, 0, hashPayload.length);
        System.arraycopy(saPayload, 0, dataForEncryption, hashPayload.length, saPayload.length);
        System.arraycopy(noncePayload, 0, dataForEncryption, hashPayload.length + saPayload.length, noncePayload.length);
        System.arraycopy(idPayload1, 0, dataForEncryption, hashPayload.length + saPayload.length + noncePayload.length,
                idPayload1.length);
        System.arraycopy(idPayload2, 0, dataForEncryption, hashPayload.length + saPayload.length + noncePayload.length +
                idPayload1.length, idPayload2.length);

        byte[] encryptedData = KeyExchangeUtil.getInstance().encryptData(dataForEncryption);
        int len = header.length + encryptedData.length;

        byte[] msg = new byte[len];

        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(Utils.toBytes(header.length + encryptedData.length), 0, msg, 24, 4);
        System.arraycopy(encryptedData, 0, msg, header.length, encryptedData.length);

        KeyExchangeUtil.getInstance().print("1st message in quick mode. ", msg);

        return msg;
    }

    private byte[] preparePhase2QuickModeSecondMsg(byte[] header, int messageId, byte[] responderNonce) {
        byte[] zero = new byte[1];
        byte[] nonce = KeyExchangeUtil.getInstance().getNonce(2).toByteArray();
        byte[] messageIdBytes = Utils.toBytes(messageId);
        byte[] dataForHash = new byte[zero.length + messageIdBytes.length + nonce.length + responderNonce.length];
        System.arraycopy(zero, 0, dataForHash, 0, zero.length);
        System.arraycopy(messageIdBytes, 0, dataForHash, zero.length, messageIdBytes.length);
        System.arraycopy(nonce, 0, dataForHash, zero.length + messageIdBytes.length, nonce.length);
        System.arraycopy(responderNonce, 0, dataForHash,
                zero.length + messageIdBytes.length + nonce.length, responderNonce.length);
        byte[] hashData = KeyExchangeUtil.getInstance().generateHashDataForLastMsg(dataForHash);

        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        int hashPayloadLen = nextPayload.length + reserved.length + 2 + hashData.length;
        byte[] hashPayloadLength = Utils.toBytes(hashPayloadLen, 2);
        byte[] hashPayload = new byte[hashPayloadLen];

        System.arraycopy(nextPayload, 0, hashPayload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, hashPayload, nextPayload.length, reserved.length);
        System.arraycopy(hashPayloadLength, 0, hashPayload, nextPayload.length + reserved.length, hashPayloadLength.length);
        System.arraycopy(hashData, 0, hashPayload, nextPayload.length + reserved.length + hashPayloadLength.length, hashData.length);

        byte[] encryptedData = KeyExchangeUtil.getInstance().encryptData(hashPayload);
        int totalLen = header.length + encryptedData.length;
        byte[] msg = new byte[totalLen];

        System.arraycopy(header, 0, msg, 0, header.length);
        System.arraycopy(Utils.toBytes(totalLen), 0, msg, 24, 4);
        System.arraycopy(encryptedData, 0, msg, header.length, encryptedData.length);

        return msg;
    }

    public byte[] prepareIpConfigPayload(byte[] messageId) {
        byte[] nextPayload = Utils.toBytes(14, 1);
        byte[] reserve = new byte[1];

        byte[] ipRequestAttributePayload = prepareIpRequestAttributePayload();
        byte[][] payloads = new byte[1][];
        payloads[0] = ipRequestAttributePayload;
        byte[] hashData = generateHashDataForPayloads(messageId, payloads);

        byte[] payloadLength = Utils.toBytes(nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length, 2);
        byte[] payloadBeforeEncrypt = new byte[nextPayload.length + reserve.length + 2/* payloadLength */ + hashData.length + ipRequestAttributePayload.length];

        System.arraycopy(nextPayload, 0, payloadBeforeEncrypt, 0, nextPayload.length);
        System.arraycopy(reserve, 0, payloadBeforeEncrypt, nextPayload.length, reserve.length);
        System.arraycopy(payloadLength, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length, payloadLength.length);
        System.arraycopy(hashData, 0, payloadBeforeEncrypt, nextPayload.length + reserve.length + payloadLength.length, hashData.length);
        System.arraycopy(ipRequestAttributePayload, 0, payloadBeforeEncrypt,
                nextPayload.length + reserve.length + payloadLength.length + hashData.length, ipRequestAttributePayload.length);

        return mKeyExchangeUtil.encryptData(payloadBeforeEncrypt);
    }

    public byte[] prepareIpRequestAttributePayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserve = new byte[1];
        byte[] type = Utils.toBytes(1, 1);      // ISAKMP_CFG_REQUEST
        byte[] identifier = Utils.toBytes(28062, 2);

        try {
            byte[] ip4_address = getTypeValueAttribute(1, 0);
            byte[] ip4_netmask = getTypeValueAttribute(2, 0);
            byte[] ip4_dns = getTypeValueAttribute(3, 0);
            byte[] ip4_nbns = getTypeValueAttribute(4, 0);

            int length = nextPayload.length + reserve.length * 2 + 2 /*payloadLength*/ +
                    type.length + identifier.length + ip4_address.length + ip4_netmask.length
                    + ip4_dns.length + ip4_nbns.length;
            byte[] payloadLength = Utils.toBytes(length, 2);

            byte[] payload = new byte[length];
            System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
            System.arraycopy(reserve, 0, payload, nextPayload.length, reserve.length);
            System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserve.length, payloadLength.length);
            System.arraycopy(type, 0, payload, nextPayload.length + reserve.length + payloadLength.length, type.length);
            System.arraycopy(reserve, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length,
                    reserve.length);
            System.arraycopy(identifier, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length, identifier.length);
            System.arraycopy(ip4_address, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length, ip4_address.length);
            System.arraycopy(ip4_netmask, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length + ip4_address.length, ip4_netmask.length);
            System.arraycopy(ip4_dns, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length + ip4_address.length + ip4_netmask.length, ip4_dns.length);
            System.arraycopy(ip4_nbns, 0, payload, nextPayload.length + reserve.length + payloadLength.length + type.length +
                    reserve.length + identifier.length + ip4_address.length + ip4_netmask.length + ip4_dns.length, ip4_nbns.length);

            return payload;
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] preparePhase2SAPayload() {
        byte[] nextPayload = Utils.toBytes(10, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] doi = Utils.toBytes(1);
        byte[] situation = Utils.toBytes(1);        // SIT_IDENTITY_ONLY

        byte[] proposalPayload = preparePhase2ProposalPayload();
        int length = nextPayload.length + reserved.length + 2 /*payloadLength */ + doi.length + situation.length + proposalPayload.length;
        byte[] payloadLength = Utils.toBytes(length, 2);
        byte[] payload = new byte[length];

        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(doi, 0, payload, nextPayload.length + reserved.length + payloadLength.length, doi.length);
        System.arraycopy(situation, 0, payload, nextPayload.length + reserved.length + payloadLength.length + doi.length,
                situation.length);
        System.arraycopy(proposalPayload, 0, payload, nextPayload.length + reserved.length + payloadLength.length + doi.length +
                situation.length, proposalPayload.length);

        return payload;
    }

    /**
     * First ID payload for IPV4_Address
     * @param ipAddress
     * @return
     */
    private byte[] preparePhase2IDPayload1(byte[] ipAddress) {
        byte[] nextPayload = Utils.toBytes(5, 1);
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(1, 1);  // IPV4_ADDRESS
        byte[] protocolId = new byte[1];        // 0
        byte[] port = new byte[2];              // 0

        byte[] data = new byte[4];
        System.arraycopy(ipAddress, 0, data, 0, data.length);

        int length = nextPayload.length + reserved.length + 2 /*payloadLength*/ +
                type.length + protocolId.length + port.length + data.length;
        byte[] payload = new byte[length];
        byte[] payloadLength = Utils.toBytes(length, 2);

        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(type, 0, payload, nextPayload.length + reserved.length + payloadLength.length,
                type.length);
        System.arraycopy(protocolId, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length, protocolId.length);
        System.arraycopy(port, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length + protocolId.length, port.length);
        System.arraycopy(data, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length + protocolId.length + port.length, data.length);

        return payload;

    }

    /**
     * Second ID payload for IPV4_Address_Subnet
     * @param subnet
     * @return
     */
    private byte[] preparePhase2IDPayload2(byte[] subnet) {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] type = Utils.toBytes(4, 1);  // IPV4_ADDRESS_SUBNET
        byte[] protocolId = new byte[1];        // 0
        byte[] port = new byte[2];              // 0

        byte[] data = new byte[8];
        System.arraycopy(subnet, 0, data, 0, subnet.length);

        int length = nextPayload.length + reserved.length + 2 /*payloadLength*/ +
                type.length + protocolId.length + port.length + data.length;
        byte[] payload = new byte[length];
        byte[] payloadLength = Utils.toBytes(length, 2);

        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(type, 0, payload, nextPayload.length + reserved.length + payloadLength.length,
                type.length);
        System.arraycopy(protocolId, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length, protocolId.length);
        System.arraycopy(port, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length + protocolId.length, port.length);
        System.arraycopy(data, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                type.length + protocolId.length + port.length, data.length);

        return payload;

    }

    private byte[] preparePhase2ProposalPayload() {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] proposalNumber = Utils.toBytes(1, 1);
        byte[] protocolId = Utils.toBytes(3, 1);        // PROTO_IPSEC_ESP
        byte[] spiSize = Utils.toBytes(4, 1);
        byte[] transformNumber = Utils.toBytes(1, 1);
        byte[] spi = Utils.toBytes(KeyExchangeUtil.getInstance().getSPI());

        byte[] transformPayload1 = preparePhase2TransformPayload(1);


        int size = nextPayload.length + reserved.length + 2/*payloadLength.length*/ + proposalNumber.length +
                protocolId.length + spiSize.length + transformNumber.length + spi.length + transformPayload1.length;

        byte[] payloadLength = Utils.toBytes(size, 2);

        byte[] proposalPayload = new byte[size];

        System.arraycopy(nextPayload, 0, proposalPayload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, proposalPayload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, proposalPayload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(proposalNumber, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length,
                proposalNumber.length);
        System.arraycopy(protocolId, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length +
                proposalNumber.length, protocolId.length);
        System.arraycopy(spiSize, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length +
                proposalNumber.length + protocolId.length, spiSize.length);
        System.arraycopy(transformNumber, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length +
                proposalNumber.length + protocolId.length + spiSize.length, transformNumber.length);
        System.arraycopy(spi, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length +
                proposalNumber.length + protocolId.length + spiSize.length + transformNumber.length, spiSize.length);
        System.arraycopy(transformPayload1, 0, proposalPayload, nextPayload.length + reserved.length + payloadLength.length +
                proposalNumber.length + protocolId.length + spiSize.length + transformNumber.length + spi.length, transformPayload1.length);

        return proposalPayload;
    }

    private byte[] preparePhase2TransformPayload(int transformNumber) {
        byte[] nextPayload = new byte[1];
        byte[] reserved = new byte[1];
        //byte[] payloadLength = new byte[2];
        byte[] transformNum = Utils.toBytes(1, 1);
        byte[] transformID = Utils.toBytes(12, 1);
        byte[] reserved2 = new byte[2];

        byte[] attributes = prepareDOIAttribute1(1);

        int length = nextPayload.length + reserved.length + 2/*payloadLength*/ + transformNum.length
                + transformID.length + reserved2.length + attributes.length;
        byte[] payload = new byte[length];
        byte[] payloadLength = Utils.toBytes(length, 2);

        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(transformNum, 0, payload, nextPayload.length + reserved.length + payloadLength.length,
                transformNum.length);
        System.arraycopy(transformID, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                transformNum.length, transformID.length);
        System.arraycopy(reserved2, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                transformNum.length + transformID.length, reserved2.length);
        System.arraycopy(attributes, 0, payload, nextPayload.length + reserved.length + payloadLength.length +
                transformNum.length + transformID.length + reserved2.length, attributes.length);

        return payload;
    }

    private byte[] prepareDOIAttribute1(int transformNumber) {
        byte[] attributes = new byte[20];

        switch (transformNumber) {
        case 1:
            System.arraycopy(prepareDOIAttribute2(1, 1), 0, attributes, 0, 4);
            System.arraycopy(prepareDOIAttribute2(2, 28800), 0, attributes, 4, 4);
            System.arraycopy(prepareDOIAttribute2(4, 3), 0, attributes, 8, 4);
            System.arraycopy(prepareDOIAttribute2(5, 5), 0, attributes, 12, 4);
            System.arraycopy(prepareDOIAttribute2(6, 256), 0, attributes, 16, 4);
            break;

        default:
            break;
        }

        return attributes;
    }

    private byte[] prepareDOIAttribute2(int type, int value) {
        byte[] attributeType = null;
        byte[] attributeValue = null;
        byte[] output = null;

        switch (type) {
        case 1: // SA_LIFE_TYPE and Seconds
            attributeType = Utils.toBytes(0x8001, 2);
            attributeValue = Utils.toBytes(value, 2);
            break;

        case 2: // SA_LIFE_DURATION
            attributeType = Utils.toBytes(0x8002, 2);
            attributeValue = Utils.toBytes(value, 2);
            break;

        case 4: // ENCAPSULATION_MODE. ENCAPSULATION_MODE_UDP_TUNNEL_RFC
            attributeType = Utils.toBytes(0x8004, 2);
            attributeValue = Utils.toBytes(value, 2);
            break;

        case 5: // AUTH_ALGORITHM. AUTH_ALGORITHM_HMAC_SHA2_256
            attributeType = Utils.toBytes(0x8005, 2);
            attributeValue = Utils.toBytes(value, 2);
            break;

        case 6: // KEY_LENGTH.
            attributeType = Utils.toBytes(0x8006, 2);
            attributeValue = Utils.toBytes(value, 2);
            break;

        default:
            break;
        }

        if (attributeType == null || attributeValue == null) {
            return output;
        }

        output = new byte[attributeType.length + attributeValue.length];
        System.arraycopy(attributeType, 0, output, 0, attributeType.length);
        System.arraycopy(attributeValue, 0, output, attributeType.length, attributeValue.length);

        return output;
    }

    private byte[] prepareHashPayload(byte[] hashData, int nextPayloadNum) {
        byte[] nextPayload = Utils.toBytes(nextPayloadNum, 1);
        byte[] reserved = new byte[1];

        int len = nextPayload.length + reserved.length + 2 /*payloadLength*/ + hashData.length;
        byte[] payloadLength = Utils.toBytes(len, 2);
        byte[] payload = new byte[len];

        System.arraycopy(nextPayload, 0, payload, 0, nextPayload.length);
        System.arraycopy(reserved, 0, payload, nextPayload.length, reserved.length);
        System.arraycopy(payloadLength, 0, payload, nextPayload.length + reserved.length, payloadLength.length);
        System.arraycopy(hashData, 0, payload, nextPayload.length + reserved.length + payloadLength.length, hashData.length);

        return payload;
    }
}
