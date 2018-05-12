package com.tenone.testapplication.isakmp;

import android.util.Log;

import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyExchangeUtil {

    private static final String TAG = "KeyExchangeUtil";

    private static KeyExchangeUtil instance;

    private KeyPair mKeyPair;
    private KeyAgreement mKeyAgree;
    private BigInteger mDH_P;
    private BigInteger mDH_G;
    private BigInteger mNonce;
    private String mPreSharedSecret;
    private byte[] mSharedSecret;   // session key
    private byte[] mSKEYID;
    private byte[] mSKEYIDd;
    private byte[] mSKEYIDa;
    private byte[] mSKEYIDe;
    private byte[] mIv;

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

    public boolean generatePairKeys(String preSharedSecret) {
        DHParameterSpec parameterSpec;

        try {
            generateRandomNumbers();
            //AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("DH");
            //parameterGenerator.init(2048);
//            AlgorithmParameters parameters = parameterGenerator.generateParameters();
//            parameterSpec = parameters.getParameterSpec(DHParameterSpec.class);

            parameterSpec = new DHParameterSpec(mDH_P, mDH_G);


            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(parameterSpec, new SecureRandom());
            //keyPairGenerator.initialize(2048);
            keyPairGenerator.initialize(parameterSpec);
            mKeyPair = keyPairGenerator.generateKeyPair();
            mKeyAgree = KeyAgreement.getInstance("DH");
            mKeyAgree.init(mKeyPair.getPrivate());
            //mDH_P = parameterSpec.getP();

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

    public BigInteger getNonce() {
        return mNonce;
    }

    public boolean instantiateServerPublicKey(byte[] serverPublicKeyData) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("DH");

            BigInteger pubKeyBI = new BigInteger(1, serverPublicKeyData);
            PublicKey serverPublicKey = keyFactory.generatePublic(new DHPublicKeySpec(pubKeyBI, mDH_P, mDH_G));

            //X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyData);
            //PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);
            mKeyAgree.doPhase(serverPublicKey, true);

            mSharedSecret = mKeyAgree.generateSecret();
            print("SharedSecret", mSharedSecret);

            return true;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
    }

    public void generateExchangeInfo(byte[] responderNonce, byte[] initiatorCookie, byte[] responderCookie) {

        prepareSKEYID(responderNonce);
        prepareSKEYIDd(initiatorCookie, responderCookie);
        prepareSKEYIDa(initiatorCookie, responderCookie);
        prepareSKEYIDe(initiatorCookie, responderCookie);
    }

    public byte[] getSharedSecret() {
        if (mKeyAgree == null) {
            return null;
        }

        if (mSharedSecret != null) {
            mSharedSecret = mKeyAgree.generateSecret();
        }

        return mSharedSecret;
    }

    public void prepareSKEYID(byte[] responderNonce) {

//        if (mSKEYID != null){
//            return;
//        }

        try {
            Mac sha256_HAMC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKeySpec = new SecretKeySpec(mPreSharedSecret.getBytes("UTF-8"), "HmacSHA256");
            sha256_HAMC.init(secretKeySpec);

            byte[] byteInitiatorNonce = mNonce.toByteArray();
            sha256_HAMC.update(byteInitiatorNonce);
            sha256_HAMC.update(responderNonce);
            mSKEYID = sha256_HAMC.doFinal();
            sha256_HAMC.reset();

            print("Nonce (initiator)", byteInitiatorNonce);
            print("Nonce (responder)", responderNonce);
            print("SKEYID: ", mSKEYID);

//            byte[] data = new byte[byteInitiatorNonce.length + responderNonce.length];
//            System.arraycopy(byteInitiatorNonce, 0, data, 0, byteInitiatorNonce.length);
//            System.arraycopy(responderNonce, 0, data, byteInitiatorNonce.length, responderNonce.length);
//            mSKEYID = sha256_HAMC.doFinal(data);
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            digest.update(mPreSharedSecret.getBytes("UTF-8"));
//            digest.update(mNonce.toByteArray());
//            digest.update(responderNonce);
//            mSKEYID = digest.digest();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void prepareSKEYIDd(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null) {
            return;
        }

        try {
            Mac sha256_HAMC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYID, "HmacSHA256");
            sha256_HAMC.init(secretKeySpec);

            sha256_HAMC.update(mSharedSecret);
            sha256_HAMC.update(initiatorCookie);
            sha256_HAMC.update(responderCookie);
            sha256_HAMC.update(new byte[1]);

            mSKEYIDd = sha256_HAMC.doFinal();
            sha256_HAMC.reset();

            print("Initiator cookie", initiatorCookie);
            print("responder cookie", responderCookie);
            print("SKEYID_d", mSKEYIDd);
//
//            byte[] data = new byte[mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
//
//            System.arraycopy(mSharedSecret, 0, data, 0, mSharedSecret.length);
//            System.arraycopy(initiatorCookie, 0, data, mSharedSecret.length, initiatorCookie.length);
//            System.arraycopy(responderCookie, 0, data, mSharedSecret.length + initiatorCookie.length, responderCookie.length);
//            System.arraycopy(Utils.toBytes(0, 1), 0, data, data.length - 1, 1);
//
//            mSKEYIDd = sha256_HAMC.doFinal(data);
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            digest.update(mSKEYID);
//            digest.update(mSharedSecret);
//            digest.update(initiatorCookie);
//            digest.update(responderCookie);
//            digest.update(Utils.toBytes(0, 1));
//            mSKEYIDd = digest.digest();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void prepareSKEYIDa(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null || mSKEYIDd == null) {
            return;
        }

        try {
            Mac sha256_HAMC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYID, "HmacSHA256");
            sha256_HAMC.init(secretKeySpec);

            sha256_HAMC.update(mSKEYIDd);
            sha256_HAMC.update(mSharedSecret);
            sha256_HAMC.update(initiatorCookie);
            sha256_HAMC.update(responderCookie);
            sha256_HAMC.update(Utils.toBytes(1, 1));

            mSKEYIDa = sha256_HAMC.doFinal();
            sha256_HAMC.reset();

            print("SKEYID_a", mSKEYIDa);
//
//            byte[] data = new byte[mSKEYIDd.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
//
//            System.arraycopy(mSKEYIDd, 0, data, 0, mSKEYIDd.length);
//            System.arraycopy(mSharedSecret, 0, data, mSKEYIDd.length, mSharedSecret.length);
//            System.arraycopy(initiatorCookie, 0, data, mSKEYIDd.length + mSharedSecret.length, initiatorCookie.length);
//            System.arraycopy(responderCookie, 0, data, mSKEYIDd.length + mSharedSecret.length + initiatorCookie.length,
//                    responderCookie.length);
//            System.arraycopy(Utils.toBytes(1, 1), 0, data, data.length - 1, 1);
//
//            mSKEYIDa = sha256_HAMC.doFinal(data);

//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//            digest.update(mSKEYIDd);
//            digest.update(mSharedSecret);
//            digest.update(initiatorCookie);
//            digest.update(responderCookie);
//            digest.update(Utils.toBytes(0, 1));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void prepareSKEYIDe(byte[] initiatorCookie, byte[] responderCookie) {
        if (mSKEYID == null || mSharedSecret == null || mSKEYIDa == null) {
            return;
        }

        try {
            Mac sha256_HAMC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYID, "HmacSHA256");
            sha256_HAMC.init(secretKeySpec);

            sha256_HAMC.update(mSKEYIDa);
            sha256_HAMC.update(mSharedSecret);
            sha256_HAMC.update(initiatorCookie);
            sha256_HAMC.update(responderCookie);
            sha256_HAMC.update(Utils.toBytes(2, 1));

            mSKEYIDe = sha256_HAMC.doFinal();
            sha256_HAMC.reset();

            print("SKEYID_e", mSKEYIDe);

//            byte[] data = new byte[mSKEYIDa.length + mSharedSecret.length + initiatorCookie.length + responderCookie.length + 1];
//
//            System.arraycopy(mSKEYIDa, 0, data, 0, mSKEYIDa.length);
//            System.arraycopy(mSharedSecret, 0, data, mSKEYIDa.length, mSharedSecret.length);
//            System.arraycopy(initiatorCookie, 0, data, mSKEYIDa.length + mSharedSecret.length, initiatorCookie.length);
//            System.arraycopy(responderCookie, 0, data, mSKEYIDa.length + mSharedSecret.length + initiatorCookie.length,
//                    responderCookie.length);
//            System.arraycopy(Utils.toBytes(1, 1), 0, data, data.length - 1, 1);
//
//            mSKEYIDe = sha256_HAMC.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }

    public byte[] prepareHashPayloadData(byte[] initiatorPublicKey, byte[] responderPublicKey, byte[] initiatorCookie, byte[] responderCookie,
                                         byte[] saPayload, byte[] idPayload) {

        try {
            Mac sha256_HAMC = Mac.getInstance("HmacSHA256");

            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYID, "HmacSHA256");
            sha256_HAMC.init(secretKeySpec);

            sha256_HAMC.update(initiatorPublicKey);
            sha256_HAMC.update(responderPublicKey);
            sha256_HAMC.update(initiatorCookie);
            sha256_HAMC.update(responderCookie);
            sha256_HAMC.update(saPayload, 4, saPayload.length - 4);
            sha256_HAMC.update(idPayload, 4, idPayload.length - 4);

            byte[] hashData = sha256_HAMC.doFinal();

            print("Initiator public key", initiatorPublicKey);
            print("Responder public key", responderPublicKey);
            print("Security authentication payload", saPayload);
            print("Identification payload", idPayload);
            print("HashData", hashData);

            return hashData;

//            byte[] data = new byte[initiatorPublicKey.length + responderPublicKey.length +
//                    initiatorCookie.length + responderCookie.length + saPayload.length - 4 + idPayload.length - 4];
//
//            System.arraycopy(initiatorPublicKey, 0, data, 0, initiatorPublicKey.length);
//            System.arraycopy(responderPublicKey, 0, data, initiatorPublicKey.length, responderPublicKey.length);
//            System.arraycopy(initiatorCookie, 0, data, initiatorPublicKey.length + responderPublicKey.length, initiatorCookie.length);
//            System.arraycopy(responderCookie, 0, data, initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length,
//                    responderCookie.length);
//            System.arraycopy(saPayload, 4, data, initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length +
//                    responderCookie.length, saPayload.length - 4);
//            System.arraycopy(idPayload, 4, data, initiatorPublicKey.length + responderPublicKey.length + initiatorCookie.length +
//                    responderCookie.length + saPayload.length - 4, idPayload.length - 4);
//
//            return sha256_HAMC.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] encryptData(byte[] payloadData, byte[] serverPublicKey) {

        try {
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
////            SecretKey secretKey = keyGenerator.generateKey();
//            byte[] salts = new byte[16];
//            SecureRandom secureRandom = new SecureRandom();
//            secureRandom.nextBytes(salts);
////            IvParameterSpec ivSpec = new IvParameterSpec(salts);
////            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYIDe, "AES");
//
//            //SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//            //PBEKeySpec pbeKeySpec = new PBEKeySpec(new String(mSKEYIDe, "UTF-8").toCharArray(), salts, 65536, 256);
//            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
//            generator.init(mSKEYIDe, salts, 65536);
//            KeyParameter key = (KeyParameter)generator.generateDerivedParameters(256);
//            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getKey(), "AES");
//
//            //SecretKey secretKey = factory.generateSecret(pbeKeySpec);
//            //SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
//
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            //cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);
//            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
//
//            mIv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
//
//            return cipher.doFinal(payloadData);

            byte[] data = new byte[serverPublicKey.length + getPublicKey().length];
            System.arraycopy(getPublicKey(), 0, data, 0, getPublicKey().length);
            System.arraycopy(serverPublicKey, 0, data, getPublicKey().length, serverPublicKey.length);
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(data);
            byte[] ivBytes = messageDigest.digest();
            mIv = new byte[16];
            System.arraycopy(ivBytes, 0, mIv, 0, 16);

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

//            SecureRandom random = new SecureRandom();
//            byte[] ivBytes = new byte[16];
//            random.nextBytes(ivBytes);

            cipher.init(true, new ParametersWithIV(new KeyParameter(mSKEYIDe), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(payloadData.length)];

            int processed = cipher.processBytes(payloadData, 0, payloadData.length, outBuffer, 0);
            processed += cipher.doFinal(outBuffer, processed);

//            byte[] outBuffer2 = new byte[processed + 16];
//            System.arraycopy(ivBytes, 0, outBuffer2, 0, 16);
//            System.arraycopy(outBuffer, 0, outBuffer2, 16, processed);

//            IvParameterSpec ivParameterSpec = new IvParameterSpec(mIv);
//            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYIDe, "AES");
//
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
//            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
//
//            cipher.update(payloadData);
//
//            byte[] outBuffer = cipher.doFinal();

            print("IV", mIv);
            print("Encrypted data", outBuffer);
            print("payload before encrypt", payloadData);

            System.arraycopy(outBuffer, outBuffer.length - 16, mIv, 0, 16);

            return outBuffer;

        } catch (Exception  e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decryptData(byte[] encryptedData) {
        try{
//            SecretKeySpec secretKeySpec = new SecretKeySpec(mSKEYIDe, "AES");
//
//            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(mIv));
//
//            return cipher.doFinal(encryptedData);

            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

            cipher.init(false, new ParametersWithIV(new KeyParameter(mSKEYIDe), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(encryptedData.length)];

            int processed = cipher.processBytes(encryptedData, 0, encryptedData.length, outBuffer, 0);
//            processed += cipher.doFinal(outBuffer, processed);

            return outBuffer;

        } catch(Exception e) {
            e.printStackTrace();
        }

        return null;
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
    }

}

