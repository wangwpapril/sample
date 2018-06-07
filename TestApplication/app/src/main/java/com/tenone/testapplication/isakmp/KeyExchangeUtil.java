package com.tenone.testapplication.isakmp;

import android.util.Log;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;

/**
 * This class contains the methods for Key Exchanging for VPN handshake and ESP payload
 */

public class KeyExchangeUtil {

    private static final String TAG = "KeyExchangeUtil";

    private static KeyExchangeUtil instance;

    private AlgorithmUtil mAlgorithmUtil;
    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgree;
    private BigInteger mDH_P;
    private BigInteger mDH_G;
    private BigInteger mNonce;
    private BigInteger mNoncePhase2;
    private byte[] mInboundSPI;
    private byte[] mOutboundSPI;
    private String mPreSharedSecret;
    private byte[] mInitiatorCookie;
    private byte[] mResponderCookie;
    private byte[] mSharedSecret;   // session key
    private byte[] mSKEYID;
    private byte[] mSKEYIDd;
    private byte[] mSKEYIDa;
    private byte[] mSKEYIDe;
    private byte[] mInboundEncryptKeyMaterial;
    private byte[] mInboundAuthKeyMaterial;
    private byte[] mOutboundEncryptKeyMaterial;
    private byte[] mOutboundAuthKeyMaterial;
    private byte[] mServerPublicKeyData;
    private byte[] mResponderNonce;
    private byte[] mResponderNonce2;

    private String mHashAlgorithm;

    /* RFC3526. 2048 bit MODP group*/
    private static final String modp2048 = (
            "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1" +
                    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD" +
                    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245" +
                    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED" +
                    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D" +
                    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F" +
                    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D" +
                    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B" +
                    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9" +
                    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" +
                    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF")
            .replaceAll("\\s", "");

    public static KeyExchangeUtil getInstance() {
        if(instance == null) {
            synchronized (KeyExchangeUtil.class) {
                instance = new KeyExchangeUtil();
            }
        }

        return instance;
    }

    private KeyExchangeUtil() {
        mDH_P = new BigInteger(modp2048, 16);
        mDH_G = BigInteger.valueOf(2);
        mAlgorithmUtil = AlgorithmUtil.getInstance();
    }

    /**
     * Initialize the instance
     * @param localIp
     * @param destIp
     */
    public void initialize(String localIp, String destIp) {
        Random random = new Random();
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        mNonce = new BigInteger(bytes);
        random.nextBytes(bytes);
        mNoncePhase2 = new BigInteger(bytes);
        int rn = 0;
        while (rn <= 4096 /*IPSEC_DOI_SPI_OUR_MIN*/) {
            rn = random.nextInt();
        }
        mInboundSPI = Utils.toBytes(rn);
        mInitiatorCookie = new byte[8];
        mResponderCookie = new byte[8];
        generateInitiatorCookie(localIp, destIp);
    }

    public void setPreSharedKey(String preSharedKey) {
        mPreSharedSecret = preSharedKey;
    }

    public void setResponderCookie(byte[] cookie) {
        mResponderCookie = cookie;
    }

    public boolean generatePairKeys(String preSharedSecret) {
        DHParameterSpec parameterSpec;

        try {
            parameterSpec = new DHParameterSpec(mDH_P, mDH_G);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(parameterSpec, new SecureRandom());
//            keyPairGenerator.initialize(parameterSpec);
            mKeyPair = keyPairGenerator.generateKeyPair();
            mKeyAgree = KeyAgreement.getInstance("DH");
            mKeyAgree.init(mKeyPair.getPrivate());

        } catch (NoSuchAlgorithmException | InvalidKeyException |  IllegalArgumentException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public byte[] getPublicKey() {

        byte[] key;
        BigInteger bigIntegerPublicKey = ((DHPublicKey)mKeyPair.getPublic()).getY();
//        return bigIntegerPublicKey.toByteArray();
        key = bigIntegerPublicKey.toByteArray();
        int length = bigIntegerPublicKey.bitLength();
        Log.e(TAG, "Public key length=" + key.length + "  bitlength=" + length);
        print("Public Key", key);
        if (length == 2048) {
            key = Arrays.copyOfRange(key, 1, key.length);
            Log.e(TAG, "Public key remove 0 length=" + key.length + "  bitlength=" + length);
        }

        return key;
    }

    public byte[] getPrivateKey() {
        BigInteger bigIntegerPrivateKey = ((DHPrivateKey)mKeyPair.getPrivate()).getX();
        return bigIntegerPrivateKey.toByteArray();
    }

    public BigInteger getPrime() {
        return mDH_P;
    }

    public BigInteger getNonce(int phaseNumber) {
        if (phaseNumber == 2) {
            return mNoncePhase2;
        }
        return mNonce;
    }

    public byte[] getInboundSPI() {
        return mInboundSPI;
    }

    public byte[] getOutboundSPI() {
        return mOutboundSPI;
    }

    public void setOutboundSPI(byte[] spi) {
        mOutboundSPI = spi;
    }

    public byte[] getOutboundEncryptionKey() {
        return mOutboundEncryptKeyMaterial;
    }

    public byte[] getOutboundAuthenticationKey() {
        return mOutboundAuthKeyMaterial;
    }

    public byte[] getInboundEncryptionKey() {
        return mInboundEncryptKeyMaterial;
    }

    public byte[] getInboundAuthenticationKey() {
        return mInboundAuthKeyMaterial;
    }

    public byte[] getSKEYID() {
        return mSKEYID;
    }

    public byte[] getSKEYIDd() {
        return mSKEYIDd;
    }

    public byte[] getSKEYIDa() {
        return mSKEYIDa;
    }

    public byte[] getSKEYIDe() {
        return mSKEYIDe;
    }

    public byte[] getInitiatorCookie() {
        return mInitiatorCookie;
    }

    public byte[] getResponderCookie() {
        return mResponderCookie;
    }

    /**
     * Initiate the server's DH public key into the keyAgreement, then generates the shared-secret
     * which shall be same on both parties (our client and VPN server)
     *
     * @return
     */
    public boolean instantiateServerPublicKey() {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");

            BigInteger pubKeyBI = new BigInteger(1, mServerPublicKeyData);
            PublicKey serverPublicKey = keyFactory.generatePublic(new DHPublicKeySpec(pubKeyBI, mDH_P, mDH_G));

            mKeyAgree.doPhase(serverPublicKey, true);

            mSharedSecret = mKeyAgree.generateSecret();
            //print("SharedSecret", mSharedSecret);

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Generates the derivation key, authentication key, encryption key, etc.
     * Prepare SKEYID. RFC2409. https://tools.ietf.org/html/rfc2409
     * SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
     * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
     * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
     * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
     */
    public void generateExchangeInfo() {

        byte[] initiatorNonceBytes = mNonce.toByteArray();
        byte[] inputData = new byte[initiatorNonceBytes.length + mResponderNonce.length];
        System.arraycopy(mNonce.toByteArray(), 0, inputData, 0, initiatorNonceBytes.length);
        System.arraycopy(mResponderNonce, 0, inputData, initiatorNonceBytes.length, mResponderNonce.length);

        try {
            mSKEYID = mAlgorithmUtil.hashDataWithKey(mPreSharedSecret.getBytes("UTF-8"), inputData);

            byte[][] dataArray1 = {mSharedSecret, mInitiatorCookie, mResponderCookie};
            byte[] staticData = Utils.combineData(dataArray1);
            byte[] zero = new byte[1];
            byte[] one = Utils.toBytes(1, 1);
            byte[] two = Utils.toBytes(2, 1);

            byte[][] dataArray2 = {staticData, zero};
            inputData = Utils.combineData(dataArray2);

            mSKEYIDd = mAlgorithmUtil.hashDataWithKey(mSKEYID, inputData);

            byte[][] dataArray3 = {mSKEYIDd, staticData, one};
            inputData = Utils.combineData(dataArray3);

            mSKEYIDa = mAlgorithmUtil.hashDataWithKey(mSKEYID, inputData);

            byte[][] dataArray4 = {mSKEYIDa, staticData, two};

            inputData = Utils.combineData(dataArray4);

            mSKEYIDe = mAlgorithmUtil.hashDataWithKey(mSKEYID, inputData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Get the DH shared secret
     * @return
     */
    public byte[] getSharedSecret() {
        if (mKeyAgree == null) {
            return null;
        }

        if (mSharedSecret != null) {
            mSharedSecret = mKeyAgree.generateSecret();
        }

        return mSharedSecret;
    }

    public void prepareKeyMaterial(byte[] responderNonce2, byte[] responderSPI) {
        if (mSKEYIDd == null || responderNonce2 == null) {
            Log.e(TAG, "Data not available for preparing key material");
            return;
        }

        mResponderNonce2 = responderNonce2;
        mOutboundSPI = responderSPI;
        byte[] initiatorNonce2 = mNoncePhase2.toByteArray();

        byte[][] dataArray1 = {Utils.toBytes(3, 1), mInboundSPI, initiatorNonce2, mResponderNonce2};
        byte[] data = Utils.combineData(dataArray1);

        mInboundEncryptKeyMaterial = mAlgorithmUtil.hashDataWithKey(mSKEYIDd, data);

        byte[][] dataArray2 = {mInboundEncryptKeyMaterial, data};
        byte[] data2 = Utils.combineData(dataArray2);

        mInboundAuthKeyMaterial = mAlgorithmUtil.hashDataWithKey(mSKEYIDd, data2);

        byte[][] dataArray3 = {Utils.toBytes(3, 1), responderSPI, initiatorNonce2, mResponderNonce2};
        data = Utils.combineData(dataArray3);

        mOutboundEncryptKeyMaterial = mAlgorithmUtil.hashDataWithKey(mSKEYIDd, data);

        byte[][] dataArray4 = {mOutboundEncryptKeyMaterial, data};
        data2 = Utils.combineData(dataArray4);

        mOutboundAuthKeyMaterial = mAlgorithmUtil.hashDataWithKey(mSKEYIDd, data2);

        print("Outbound Encrypt Keying Material", mOutboundEncryptKeyMaterial);

        print("Outbound auth key", mOutboundAuthKeyMaterial);

        print("Inbound Encrypt Keying Material", mInboundEncryptKeyMaterial);

        print("Inbound auth key", mInboundAuthKeyMaterial);

        print("My SPI", mInboundSPI);
        print("responder SPI", mOutboundSPI);
    }

    public void print(String label, byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : data) {
            stringBuilder.append(String.format("%02x ", b));
        }

        Log.i(TAG, "**** [" + label + "] length: " + data.length + ", " + stringBuilder.toString());
    }

    public byte[] getServerPublicKeyData() {
        return mServerPublicKeyData;
    }

    public void setServerPublicKeyData(byte[] serverPublicKeyData) {
        this.mServerPublicKeyData = serverPublicKeyData;
    }

    public byte[] getResponderNonce(int phaseNumber) {
        if (phaseNumber == 1) {
            return mResponderNonce;
        }

        return mResponderNonce2;
    }

    public void setResponderNonce(byte[] responderNonce) {
        this.mResponderNonce = responderNonce;
    }

    /**
     * Generate the initiator cookie
     * @param sourceIp
     * @param destIp
     */
    private void generateInitiatorCookie(String sourceIp, String destIp) {

        int initPort = 500;
        Long ct = System.currentTimeMillis();
        InetSocketAddress sa1 = new InetSocketAddress(sourceIp, initPort);
        InetSocketAddress sa2 = new InetSocketAddress(destIp, initPort);
        Random random = new Random();

        byte[][] dataArray = {sa1.getAddress().getAddress(),
                Utils.toBytes(sa1.getPort()),
                sa2.getAddress().getAddress(),
                Utils.toBytes(sa2.getPort()),
                Utils.toBytes(ct.longValue()),
                Utils.toBytes(random.nextInt())};

        byte[] chars = Utils.combineData(dataArray);
        byte[] hashValue = mAlgorithmUtil.hashData("SHA-1", chars);

        try{
            System.arraycopy(hashValue, 0, mInitiatorCookie, 0, 8);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

