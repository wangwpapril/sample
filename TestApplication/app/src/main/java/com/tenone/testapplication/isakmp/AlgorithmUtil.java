package com.tenone.testapplication.isakmp;

import android.util.Log;

import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.paddings.ZeroBytePadding;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class AlgorithmUtil {

    private static final String TAG = "AlgorithmUtil";
    private static final int AES_BLOCK_SIZE = 16;
    private byte[] mIv;

    /**
     * Encrypt data use AESCBC
     * @param key
     * @param inputData
     * @return
     */
    public byte[] aesEncryptData(byte[] key, byte[] inputData, boolean withPadding){
        try {
            BufferedBlockCipher cipher = null;
            if (withPadding) {
                cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());
            } else {
                cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            }

            cipher.init(true, new ParametersWithIV(new KeyParameter(key), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(inputData.length)];

            int processed = cipher.processBytes(inputData, 0, inputData.length, outBuffer, 0);
            processed += cipher.doFinal(outBuffer, processed);

            return outBuffer;

        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Decrypt the data using AESCBC
     * @param key
     * @param encryptedData
     * @param withPadding
     * @return
     */
    public byte[] aesDecryptData(byte[] key, byte[] encryptedData, boolean withPadding) {

        try{

            BufferedBlockCipher cipher = null;

//            print("data before decrypt", encryptedData);
//            print("mIv before decrypt", mIv);


            if (withPadding) {
                cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());
            } else {
                cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
            }

            cipher.init(false, new ParametersWithIV(new KeyParameter(key), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(encryptedData.length)];

            int processed = cipher.processBytes(encryptedData, 0, encryptedData.length, outBuffer, 0);

            if (encryptedData.length - processed >= AES_BLOCK_SIZE) {
                processed += cipher.doFinal(outBuffer, processed);
            } else {
                byte[] removedPaddingBytes = new byte[processed];
                System.arraycopy(outBuffer, 0, removedPaddingBytes, 0, processed);

                return removedPaddingBytes;
            }

            print("data after decrypt", outBuffer);

            return outBuffer;

        } catch(Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Hash the data without key
     * @param provider
     * @param data
     * @return
     */
    public byte[] hashData(String provider, byte[] data) {
        byte[] output = null;
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(provider);
            messageDigest.update(data);
            output = messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            output = null;
        }

        return output;
    }

    /**
     * Hash data with provided key
     * @param provider
     * @param key
     * @param data
     * @return
     */
    private byte[] hashDataWithKey(String provider, byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(provider);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, provider);
            mac.init(secretKeySpec);

            byte[] output = mac.doFinal(data);

            mac.reset();

            return output;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Get the Initialization Vector (IV)
     * @return
     */
    public byte[] getIv() {
        return mIv;
    }

    /**
     * Update the Initialization Vector (IV) for encryption
     * @param newIv
     */
    public void setIv(byte[] newIv) {
        mIv = newIv;
    }

    private void print(String label, byte[] data) {
        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : data) {
            stringBuilder.append(String.format("%02x ", b));
        }

        Log.i(TAG, "**** [" + label + "] length: " + data.length + ", " + stringBuilder.toString());
    }
}
