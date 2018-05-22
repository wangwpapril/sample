package com.tenone.testapplication.isakmp;

import android.util.Log;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.paddings.ZeroBytePadding;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyExchangeUtil {

    private static final String TAG = "KeyExchangeUtil";

    private static KeyExchangeUtil instance;

    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgree;
    private BigInteger mDH_P;
    private BigInteger mDH_G;
    private BigInteger mNonce;
    private BigInteger mNoncePhase2;
    private int mSPI;
    private String mPreSharedSecret;
    private byte[] mSharedSecret;   // session key
    private byte[] mSKEYID;
    private byte[] mSKEYIDd;
    private byte[] mSKEYIDa;
    private byte[] mSKEYIDe;
    private byte[] mIv;
    private byte[] mFirstPhaseIv;
    private byte[] mServerPublicKeyData;
    private byte[] mResponderNonce;
    private byte[] mSAPayload;
    private byte[] mResponderIDPayload;

    private String mHashAlgorithm;
    private String mEncryptAlgorithm;

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

    public void setPreSharedKey(String preSharedKey) {
        mPreSharedSecret = preSharedKey;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        mHashAlgorithm = hashAlgorithm;
    }

    public void setEncryptAlgorithm(String encryptAlgorithm) {
        mEncryptAlgorithm = encryptAlgorithm;
    }

    public boolean generatePairKeys(String preSharedSecret) {
        DHParameterSpec parameterSpec;

        try {
            generateRandomNumbers();
            parameterSpec = new DHParameterSpec(mDH_P, mDH_G);


            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(parameterSpec, new SecureRandom());
            keyPairGenerator.initialize(parameterSpec);
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

        BigInteger bigIntegerPublicKey = ((DHPublicKey)mKeyPair.getPublic()).getY();
        return bigIntegerPublicKey.toByteArray();
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

    public int getSPI() {
        return mSPI;
    }

    /**
     * Initiate the server's DH public key into the keyAgreement, then generates the shared-secret
     * which shall be same on both parties (our client and VPN server)
     *
     * @param serverPublicKeyData
     * @return
     */
    public boolean instantiateServerPublicKey(byte[] serverPublicKeyData) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");

            BigInteger pubKeyBI = new BigInteger(1, serverPublicKeyData);
            PublicKey serverPublicKey = keyFactory.generatePublic(new DHPublicKeySpec(pubKeyBI, mDH_P, mDH_G));

            mKeyAgree.doPhase(serverPublicKey, true);

            mSharedSecret = mKeyAgree.generateSecret();
            print("SharedSecret", mSharedSecret);

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    /**
     * Generates the derivation key, authentication key, encryption key, etc.
     * @param responderNonce
     * @param initiatorCookie
     * @param responderCookie
     */
    public void generateExchangeInfo(byte[] responderNonce, byte[] initiatorCookie, byte[] responderCookie) {

        prepareSKEYID(responderNonce);
        prepareSKEYIDd(initiatorCookie, responderCookie);
        prepareSKEYIDa(initiatorCookie, responderCookie);
        prepareSKEYIDe(initiatorCookie, responderCookie);
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

    /**
     * Prepare SKEYID. RFC2409. https://tools.ietf.org/html/rfc2409
     * SKEYID = prf(pre-shared-key, Ni_b | Nr_b)
     *
     * @param responderNonce
     */
    public void prepareSKEYID(byte[] responderNonce) {

        byte[] initiatorNonceBytes = mNonce.toByteArray();
        byte[] inputData = new byte[initiatorNonceBytes.length + responderNonce.length];
        System.arraycopy(mNonce.toByteArray(), 0, inputData, 0, initiatorNonceBytes.length);
        System.arraycopy(responderNonce, 0, inputData, initiatorNonceBytes.length, responderNonce.length);

        try {
            mSKEYID = hashDataWithKey(mPreSharedSecret.getBytes("UTF-8"), inputData);

            print("Nonce (initiator)", initiatorNonceBytes);
            print("Nonce (responder)", responderNonce);
            print("SKEYID: ", mSKEYID);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Prepare SKEYID_d. RFC2409. https://tools.ietf.org/html/rfc2409
     * SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
     *
     * @param initiatorCookie
     * @param responderCookie
     */
    public void prepareSKEYIDd(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null) {
            return;
        }

        byte[] inputData = new byte[mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
        System.arraycopy(mSharedSecret, 0, inputData, 0, mSharedSecret.length);
        System.arraycopy(initiatorCookie, 0, inputData, mSharedSecret.length, initiatorCookie.length);
        System.arraycopy(responderCookie, 0, inputData, mSharedSecret.length + initiatorCookie.length,
                responderCookie.length);
        //System.arraycopy(Utils.toBytes(0, 1), 0, inputData, mSharedSecret.length + initiatorCookie.length + responderCookie.length, 1);
        mSKEYIDd = hashDataWithKey(mSKEYID, inputData);

        print("Initiator cookie", initiatorCookie);
        print("responder cookie", responderCookie);
        print("SKEYID_d", mSKEYIDd);

    }

    /**
     * Prepare SKEYID_a. RFC2409. https://tools.ietf.org/html/rfc2409
     * SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
     *
     * @param initiatorCookie
     * @param responderCookie
     */
    public void prepareSKEYIDa(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null || mSKEYIDd == null) {
            return;
        }

        byte[] inputData = new byte[mSKEYIDd.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
        System.arraycopy(mSKEYIDd, 0, inputData, 0, mSKEYIDd.length);
        System.arraycopy(mSharedSecret, 0, inputData, mSKEYIDd.length, mSharedSecret.length);
        System.arraycopy(initiatorCookie, 0, inputData, mSKEYIDd.length + mSharedSecret.length, initiatorCookie.length);
        System.arraycopy(responderCookie, 0, inputData,
                mSKEYIDd.length + mSharedSecret.length + initiatorCookie.length, responderCookie.length);
        System.arraycopy(Utils.toBytes(1, 1), 0, inputData,
                mSKEYIDd.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length, 1);

        mSKEYIDa = hashDataWithKey(mSKEYID, inputData);

        print("SKEYID_a", mSKEYIDa);
    }

    /**
     * Prepare SKEYID_e. RFC2409. https://tools.ietf.org/html/rfc2409
     * SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)
     *
     * @param initiatorCookie
     * @param responderCookie
     */
    public void prepareSKEYIDe(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null || mSKEYIDa == null) {
            return;
        }

        byte[] inputData = new byte[mSKEYIDa.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
        System.arraycopy(mSKEYIDa, 0, inputData, 0, mSKEYIDa.length);
        System.arraycopy(mSharedSecret, 0, inputData, mSKEYIDa.length, mSharedSecret.length);
        System.arraycopy(initiatorCookie, 0, inputData, mSKEYIDa.length + mSharedSecret.length, initiatorCookie.length);
        System.arraycopy(responderCookie, 0, inputData,
                mSKEYIDa.length + mSharedSecret.length + initiatorCookie.length, responderCookie.length);
        System.arraycopy(Utils.toBytes(2, 1), 0, inputData,
                mSKEYIDa.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length, 1);

        mSKEYIDe = hashDataWithKey(mSKEYID, inputData);

        print("SKEYID_e", mSKEYIDe);

    }

    /**
     * Prepare hash payload
     * HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
     *
     * @param initiatorPublicKey
     * @param responderPublicKey
     * @param initiatorCookie
     * @param responderCookie
     * @param saPayload
     * @param idPayload
     * @return
     */
    public byte[] prepareHashPayloadData(byte[] initiatorPublicKey, byte[] responderPublicKey, byte[] initiatorCookie, byte[] responderCookie,
                                         byte[] saPayload, byte[] idPayload) {

        byte[] data = new byte[initiatorPublicKey.length + responderPublicKey.length +
            initiatorCookie.length + responderCookie.length + saPayload.length - 4 + idPayload.length - 4];

        System.arraycopy(initiatorPublicKey, 0, data, 0, initiatorPublicKey.length);
        System.arraycopy(responderPublicKey, 0, data, initiatorPublicKey.length, responderPublicKey.length);
        System.arraycopy(initiatorCookie, 0, data,
                initiatorPublicKey.length + responderPublicKey.length, initiatorCookie.length);
        System.arraycopy(responderCookie, 0, data,
                initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length, responderCookie.length);
        System.arraycopy(saPayload, 4, data,
                initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length + responderCookie.length,
                saPayload.length - 4);
        System.arraycopy(idPayload, 4, data,
                initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length + responderCookie.length + saPayload.length - 4,
                idPayload.length - 4);

        byte[] hashData = hashDataWithKey(mSKEYID, data);

        print("HashData", hashData);

        return hashData;
    }

    public byte[] generateResponder1stHashData(byte[] initiatorCookie,
                byte[] responderCookie, byte[] responderIDPayload) {
        byte[] initiatorPublicKey = getPublicKey();

        byte[] data = new byte[initiatorPublicKey.length + mServerPublicKeyData.length +
                initiatorCookie.length + responderCookie.length + mSAPayload.length - 4 + responderIDPayload.length];


        System.arraycopy(mServerPublicKeyData, 0, data, 0, mServerPublicKeyData.length);
        System.arraycopy(initiatorPublicKey, 0, data, mServerPublicKeyData.length, initiatorPublicKey.length);

        System.arraycopy(responderCookie, 0, data,
                initiatorPublicKey.length + mServerPublicKeyData.length, responderCookie.length);
        System.arraycopy(initiatorCookie, 0, data,
                initiatorPublicKey.length + mServerPublicKeyData.length + responderCookie.length, initiatorCookie.length);
        System.arraycopy(mSAPayload, 4, data,
                initiatorPublicKey.length + mServerPublicKeyData.length + initiatorCookie.length + responderCookie.length,
                mSAPayload.length - 4);
        System.arraycopy(responderIDPayload, 0, data,
                initiatorPublicKey.length + mServerPublicKeyData.length + initiatorCookie.length + responderCookie.length + mSAPayload.length - 4,
                responderIDPayload.length);

        byte[] hashData = hashDataWithKey(mSKEYID, data);

        print("Responder's 1st responderIDPayload", responderIDPayload);
        print("Responder's 1st HashData", hashData);

        return hashData;
    }

    public byte[] prepare1stEncryptedPayload(byte[] payloadData, byte[] serverPublicKey) {
        try {
            // first encrypted message using the IV from initiator's and responder's public keys
            byte[] data = new byte[serverPublicKey.length + getPublicKey().length];
            System.arraycopy(getPublicKey(), 0, data, 0, getPublicKey().length);
            System.arraycopy(serverPublicKey, 0, data, getPublicKey().length, serverPublicKey.length);

            byte[] ivBytes = hashDataWithoutKey(data);
            mIv = new byte[16];
            if (ivBytes != null) {
                System.arraycopy(ivBytes, 0, mIv, 0, 16);
            }

            byte[] output = encryptData(payloadData);

            print("Encrypted data", output);

            return output;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] generateHashDataForAttributePayload(byte[] messageId, byte[] attributePayloads){
        int length = messageId.length + attributePayloads.length;

        byte[] inputData = new byte[length];
        System.arraycopy(messageId, 0, inputData, 0, messageId.length);
        System.arraycopy(attributePayloads, 0, inputData, messageId.length, attributePayloads.length);

        return hashConfigModePayload(inputData);
    }

    public byte[] generateHashDataForLastMsg(byte[] data) {
        return hashDataWithKey(mSKEYIDa, data);
    }

    public byte[] hashConfigModePayload(byte[] data) {
        byte[] output = hashDataWithKey(mSKEYIDa, data);

        print("Hash data for config mode payload", output);

        return output;
    }

    public byte[] encryptData(byte[] payloadData) {

        byte[] output = null;
        print("IV", mIv);

        if (mEncryptAlgorithm.equals("AES256")) {
            output = aes256Encrypt(payloadData);

            print("Encrypted data", output);
            print("payload before encrypt", payloadData);
        }

        return output;
    }

    public byte[] decryptData(byte[] encryptedData) {
        byte[] output = null;

        if (mEncryptAlgorithm.equals("AES256")) {
            output = aes256Decrypt(encryptedData);
        }

        return output;
    }

    public void print(String label, byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : data) {
            stringBuilder.append(String.format("%02x ", b));
        }

        Log.i(TAG, "**** [" + label + "] length: " + data.length + ", " + stringBuilder.toString());
    }

    private void generateRandomNumbers() {
        Random random = new Random();

        mDH_P = new BigInteger(modp2048, 16);
        mDH_G = BigInteger.valueOf(2);
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        mNonce = new BigInteger(bytes);
        random.nextBytes(bytes);
        mNoncePhase2 = new BigInteger(bytes);
        while (mSPI <= 4096 /*IPSEC_DOI_SPI_OUR_MIN*/) {
            mSPI = random.nextInt();
        }
    }

    public byte[] md5Hash(byte[] data) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            messageDigest.update(data);
            return messageDigest.digest();
        }catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] hashDataWithoutKey(byte[] data) {
        byte[] output = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(getHashProvider());
            messageDigest.update(data);
            output = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return output;
    }

    private byte[] hashDataWithKey(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(mHashAlgorithm);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, mHashAlgorithm);
            mac.init(secretKeySpec);

            byte[] output = mac.doFinal(data);

            mac.reset();

            return output;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] aes256Encrypt(byte[] inputData) {

        try {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

            cipher.init(true, new ParametersWithIV(new KeyParameter(mSKEYIDe), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(inputData.length)];

            int processed = cipher.processBytes(inputData, 0, inputData.length, outBuffer, 0);
            processed += cipher.doFinal(outBuffer, processed);

//            System.arraycopy(outBuffer, outBuffer.length - 16, mIv, 0, 16);

            return outBuffer;

        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] aes256Decrypt(byte[] encryptedData) {
        try{

            print("data before decrypt", encryptedData);
            print("mIv before decrypt", mIv);


            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());

            cipher.init(false, new ParametersWithIV(new KeyParameter(mSKEYIDe), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(encryptedData.length)];

            int processed = cipher.processBytes(encryptedData, 0, encryptedData.length, outBuffer, 0);
            processed += cipher.doFinal(outBuffer, processed);

//            System.arraycopy(encryptedData, encryptedData.length - 16, mIv, 0, 16);

            print("data after decrypt", outBuffer);
//            print("mIv after decrypt", mIv);

            return outBuffer;

        } catch(Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Generates the new IV base on the last IV and message id
     * https://tools.ietf.org/id/draft-ietf-ipsec-ike-01.txt, section 4.2
     *
     * @param messageId
     */
    public void preparePhase2IV(byte[] messageId) {
        if (mFirstPhaseIv == null || mIv == null) {
            return;
        }

        byte[] data = new byte[16 + messageId.length];
        System.arraycopy(mFirstPhaseIv, 0, data, 0, 16);
        System.arraycopy(messageId, 0, data, 16, messageId.length);

        byte[] ivBytes = hashDataWithoutKey(data);
        if (ivBytes != null) {
            System.arraycopy(ivBytes, 0, mIv, 0, 16);
        }
    }

    public void setIV(byte[] iv) {
        if (iv != null && iv.length == 16)
            this.mIv = iv;
        print("SetIv=", iv);
    }

    private String getHashProvider() {
        String provider = "SHA-256";

        if (mHashAlgorithm.equals("HmacSHA1")) {
            provider = "SHA-1";
        } else if (mHashAlgorithm.equals("HmacSHA512")) {
            provider = "SHA-512";
        }

        return provider;
    }

    public byte[] getServerPublicKeyData() {
        return mServerPublicKeyData;
    }

    public void setServerPublicKeyData(byte[] mServerPublicKeyData) {
        this.mServerPublicKeyData = mServerPublicKeyData;
    }

    public byte[] getResponderNonce() {
        return mResponderNonce;
    }

    public void setResponderNonce(byte[] mResponderNonce) {
        this.mResponderNonce = mResponderNonce;
    }

    public byte[] getSAPayload() {
        return mSAPayload;
    }

    public void setSAPayload(byte[] mSAPayload) {
        this.mSAPayload = mSAPayload;
    }

    public byte[] getResponderIDPayload() {
        return mResponderIDPayload;
    }

    public void setResponderIDPayload(byte[] mResponderIDPayload) {
        this.mResponderIDPayload = mResponderIDPayload;
    }

    public byte[] getFirstPhaseIv() {
        return mFirstPhaseIv;
    }

    public void setFirstPhaseIv(byte[] mFirstPhaseIv) {
        this.mFirstPhaseIv = mFirstPhaseIv;
    }
}

