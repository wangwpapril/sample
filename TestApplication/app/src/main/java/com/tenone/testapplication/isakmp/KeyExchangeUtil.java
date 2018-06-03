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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
    private byte[] mInboundEncryptKeyMaterial;
    private byte[] mInboundAuthKeyMaterial;
    private byte[] mOutboundEncryptKeyMaterial;
    private byte[] mOutboundAuthKeyMaterial;
    private byte[] mIv;
    private byte[] mFirstPhaseIv;
    private byte[] mServerPublicKeyData;
    private byte[] mResponderNonce;
    private byte[] mResponderNonce2;
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


//        try {
//
//            byte[] dataToDecrypt = {(byte)0xd1,(byte)0x11,(byte)0x5f,(byte)0x1a,(byte)0x03,(byte)0xeb,(byte)0x0f,(byte)0x92,(byte)0xbb,(byte)0x84,(byte)0x22,(byte)0x57,(byte)0x34,(byte)0x50,(byte)0x3e,(byte)0x70,(byte)0xfb,(byte)0x81,(byte)0x4b,(byte)0x25,(byte)0x81,(byte)0xc1,(byte)0xf1,(byte)0x54,(byte)0xe5,(byte)0xfd,(byte)0xd3,(byte)0x34,(byte)0xe5,(byte)0xe0,(byte)0x90,(byte)0x82,(byte)0xc3,(byte)0xf5,(byte)0xe4,(byte)0xb8,(byte)0x10,(byte)0x4e,(byte)0x1a,(byte)0x0d,(byte)0x3c,(byte)0xda,(byte)0x8b,(byte)0x4f,(byte)0xa5,(byte)0xd5,(byte)0x03,(byte)0xe5,(byte)0xec,(byte)0xd6,(byte)0x1c,(byte)0xd8,(byte)0x86,(byte)0x4b,(byte)0x9b,(byte)0xe9,(byte)0x03,(byte)0x8e,(byte)0x37,(byte)0xfb,(byte)0x5f,(byte)0xd1,(byte)0xe0,(byte)0x2c,(byte)0x4d,(byte)0x59,(byte)0xea,(byte)0xdf,(byte)0x82,(byte)0x95,(byte)0x17,(byte)0x95,(byte)0x5f,(byte)0x59,(byte)0xa2,(byte)0x91,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,};
//            byte[] tIV = {(byte)0xf4,(byte)0xfd,(byte)0x3c,(byte)0xa9,(byte)0xe5,(byte)0x6b,(byte)0xed,(byte)0x67,(byte)0xa1,(byte)0x40,(byte)0x02,(byte)0x3d,(byte)0x10,(byte)0x19,(byte)0x6b,(byte)0x50};
//            byte[] tSkeyId_d = {(byte)0x8d,(byte)0xd0,(byte)0x78,(byte)0xef,(byte)0x1c,(byte)0x05,(byte)0x58,(byte)0x3e,(byte)0x4b,(byte)0xc1,(byte)0x28,(byte)0xe4,(byte)0x8d,(byte)0xc7,(byte)0xe4,(byte)0x27,(byte)0xa2,(byte)0xac,(byte)0x84,(byte)0x92,(byte)0x4d,(byte)0xa4,(byte)0x5a,(byte)0xc4,(byte)0x23,(byte)0xa1,(byte)0x5f,(byte)0xf5,(byte)0x35,(byte)0xd0,(byte)0x4e,(byte)0xa4};
//            byte[] tResponderNonce = {(byte)0x31,(byte)0x11,(byte)0xeb,(byte)0x4b,(byte)0x5a,(byte)0x92,(byte)0x2f,(byte)0x61,(byte)0x7f,(byte)0xfe,(byte)0x18,(byte)0x9b,(byte)0x12,(byte)0x34,(byte)0x18,(byte)0x65,(byte)0xda,(byte)0x7b,(byte)0x92,(byte)0x91,(byte)0xba,(byte)0xdf,(byte)0xe1,(byte)0xa9,(byte)0x94,(byte)0x36,(byte)0x82,(byte)0x8e,(byte)0x47,(byte)0x4b,(byte)0x73,(byte)0x04};
//            byte[] tInitiatorNonce = {(byte)0xb6,(byte)0xc5,(byte)0x21,(byte)0xcd,(byte)0xdc,(byte)0x67,(byte)0x0b,(byte)0x4c,(byte)0xce,(byte)0x8b,(byte)0x66,(byte)0x42,(byte)0x25,(byte)0xc4,(byte)0x3e,(byte)0x93};
//            byte[] tSPI_i = {(byte)0x05,(byte)0x24,(byte)0x28,(byte)0xe5};
//            byte[] tSPI_r = {(byte)0xd4,(byte)0x97,(byte)0xe1,(byte)0xda};
//
//            byte[] tIV2 = {(byte)0x75,(byte)0x8e,(byte)0x53,(byte)0xb5,(byte)0x3c,(byte)0x52,(byte)0x55,(byte)0xa6,(byte)0x42,(byte)0xd5,(byte)0xc2,(byte)0xff,(byte)0xd6,(byte)0x0f,(byte)0x60,(byte)0x0e};
//            byte[] dataToDecrypt2 = {(byte)0x62,(byte)0xe8,(byte)0x32,(byte)0x09,(byte)0xe1,(byte)0x7c,(byte)0xf2,(byte)0x57,(byte)0x09,(byte)0x89,(byte)0xa0,(byte)0x94,(byte)0x0b,(byte)0xf8,(byte)0xdd,(byte)0xe6,(byte)0xa1,(byte)0x7a,(byte)0xd4,(byte)0x04,(byte)0x0d,(byte)0x95,(byte)0xfb,(byte)0x30,(byte)0x45,(byte)0xed,(byte)0x15,(byte)0x9e,(byte)0x7a,(byte)0x12,(byte)0xc1,(byte)0xd7,(byte)0x7d,(byte)0xd9,(byte)0x39,(byte)0x0d,(byte)0xc4,(byte)0xce,(byte)0x26,(byte)0x0f,(byte)0x66,(byte)0x55,(byte)0x6f,(byte)0xfa,(byte)0x96,(byte)0xda,(byte)0xc3,(byte)0xa3,(byte)0xcf,(byte)0xce,(byte)0x9f,(byte)0x27,(byte)0xe2,(byte)0xd4,(byte)0x30,(byte)0x6b,(byte)0xcc,(byte)0x7a,(byte)0x88,(byte)0xdd,(byte)0x74,(byte)0x84,(byte)0xf5,(byte)0xb9,(byte)0x39,(byte)0x2d,(byte)0x10,(byte)0x0a,(byte)0xb5,(byte)0x87,(byte)0xa6,(byte)0xe8,(byte)0x32,(byte)0x7d,(byte)0xb3,(byte)0x0b};
//
//            byte[] tIV3 = {(byte)0x6b,(byte)0xec,(byte)0xa3,(byte)0x0f,(byte)0x04,(byte)0xea,(byte)0xea,(byte)0x35,(byte)0x05,(byte)0xeb,(byte)0x9f,(byte)0xd7,(byte)0x7e,(byte)0x55,(byte)0xa1,(byte)0xd0};
//            byte[] dataToDecrypt3 = {(byte)0x6f,(byte)0x71,(byte)0x41,(byte)0x48,(byte)0x85,(byte)0x04,(byte)0xa8,(byte)0xbf,(byte)0x51,(byte)0x32,(byte)0xe2,(byte)0xa7,(byte)0x26,(byte)0xf5,(byte)0xf4,(byte)0x4a,(byte)0x93,(byte)0xbd,(byte)0xc2,(byte)0xe5,(byte)0x61,(byte)0x34,(byte)0x3d,(byte)0x2b,(byte)0x2c,(byte)0xf8,(byte)0xec,(byte)0xda,(byte)0x78,(byte)0x80,(byte)0xac,(byte)0x69,(byte)0x2a,(byte)0x48,(byte)0xe9,(byte)0x97,(byte)0xa2,(byte)0xcf,(byte)0xcb,(byte)0xb8,(byte)0x9c,(byte)0x90,(byte)0xd8,(byte)0xf7,(byte)0xed,(byte)0x9e,(byte)0xf9,(byte)0x82,(byte)0x9d,(byte)0x3d,(byte)0x20,(byte)0xc0,(byte)0xaf,(byte)0x6a,(byte)0x3c,(byte)0xbf,(byte)0x4b,(byte)0xba,(byte)0xb8,(byte)0x99,(byte)0x25,(byte)0x3f,(byte)0x12,(byte)0x7a,(byte)0x1f,(byte)0xd0,(byte)0x94,(byte)0x9c,(byte)0x88,(byte)0xf5,(byte)0x66,(byte)0x1d,(byte)0x6a,(byte)0x14,(byte)0x6f,(byte)0xc2,(byte)0x88,(byte)0xd7,(byte)0xd6,(byte)0xe4,(byte)0xe1,(byte)0x27,(byte)0x4e,(byte)0xa7,(byte)0xdb,(byte)0xc7,(byte)0x01,(byte)0x53,(byte)0x6b,(byte)0x01,(byte)0x1e,(byte)0x4a,(byte)0xf7,(byte)0x97,(byte)0x3e,(byte)0x4b,(byte)0xaa,(byte)0xee,(byte)0xad,(byte)0xd2,(byte)0x90,(byte)0xd5,(byte)0x53,(byte)0x81,(byte)0x44,(byte)0x6d,(byte)0x61,(byte)0x7c,(byte)0xe7,(byte)0xd8,(byte)0x64,(byte)0xbf,(byte)0xc2,(byte)0x87,(byte)0xd2,(byte)0xa7,(byte)0x79,(byte)0x48,(byte)0x5b,(byte)0x53,(byte)0xd8,(byte)0x1a,(byte)0x3f,(byte)0x83,(byte)0x8d,(byte)0xea,(byte)0x56,(byte)0x71,(byte)0x09,(byte)0x83,(byte)0x38,(byte)0x5c,(byte)0xc8,(byte)0x00,(byte)0x74,(byte)0xdd,(byte)0x7a,(byte)0x61,(byte)0x0a,(byte)0x44,(byte)0x1f,(byte)0x47,(byte)0xd2,(byte)0xca,(byte)0xcd,(byte)0xf9,(byte)0x82,(byte)0xd9,(byte)0xa2,(byte)0xe9,(byte)0x3f,(byte)0x16,(byte)0xfa,(byte)0x78,(byte)0xcf,(byte)0x62,(byte)0xe9,(byte)0x43,(byte)0xeb,(byte)0xe9,(byte)0x3b,(byte)0x36,(byte)0x87,(byte)0x26,(byte)0x60,(byte)0x4f,(byte)0x6f,(byte)0x1f,(byte)0x47,(byte)0xbe,(byte)0x0a,(byte)0x09};
//
//            byte[] tIV4 = {(byte)0xd6,(byte)0xf5,(byte)0xa0,(byte)0x2b,(byte)0xd0,(byte)0x8b,(byte)0x33,(byte)0x46,(byte)0xa9,(byte)0x15,(byte)0xc8,(byte)0x6e,(byte)0x00,(byte)0x1a,(byte)0x5b,(byte)0x2e};
//            byte[] dataToDecrypt4 = {(byte)0x6b,(byte)0x2c,(byte)0x74,(byte)0xfb,(byte)0x37,(byte)0xf7,(byte)0x8e,(byte)0x07,(byte)0x96,(byte)0x25,(byte)0x24,(byte)0x69,(byte)0xfa,(byte)0x7a,(byte)0xad,(byte)0xa0,(byte)0xb4,(byte)0xe4,(byte)0xe8,(byte)0x39,(byte)0xe6,(byte)0x58,(byte)0xe4,(byte)0x3a,(byte)0x0b,(byte)0xc4,(byte)0x1e,(byte)0x71,(byte)0x1f,(byte)0x7a,(byte)0x44,(byte)0x5f,(byte)0xdf,(byte)0x1f,(byte)0xea,(byte)0xa0,(byte)0x16,(byte)0x1f,(byte)0x93,(byte)0x1d,(byte)0x66,(byte)0xa5,(byte)0xd8,(byte)0x6a,(byte)0x3e,(byte)0x0c,(byte)0x72,(byte)0x76,(byte)0x06,(byte)0x72,(byte)0x10,(byte)0x7a,(byte)0xe3,(byte)0x77,(byte)0x0d,(byte)0x1e,(byte)0x27,(byte)0xcd,(byte)0x9f,(byte)0xa1,(byte)0xe2,(byte)0x85,(byte)0x6b,(byte)0xa4,(byte)0x12,(byte)0x45,(byte)0x96,(byte)0xd1,(byte)0xb7,(byte)0xb9,(byte)0x61,(byte)0x3c,(byte)0x2e,(byte)0xa4,(byte)0x0c,(byte)0x4d,(byte)0xb6,(byte)0x6b,(byte)0x40,(byte)0x28,(byte)0x1f,(byte)0x6f,(byte)0xdc,(byte)0xbc,(byte)0x07,(byte)0x9d,(byte)0xa7,(byte)0x7c,(byte)0x63,(byte)0x84,(byte)0xfc,(byte)0xfb,(byte)0x9f,(byte)0xad,(byte)0x61,(byte)0xc7,(byte)0x40,(byte)0x60,(byte)0x4d,(byte)0xe0,(byte)0x3b,(byte)0x53,(byte)0xfe,(byte)0xb4,(byte)0xc1,(byte)0x65,(byte)0x51,(byte)0x00,(byte)0x92,(byte)0x6c,(byte)0xa0,(byte)0xef,(byte)0x9f,(byte)0x2f,(byte)0x68,(byte)0x56,(byte)0x10,(byte)0x1b,(byte)0xb1,(byte)0xad,(byte)0x1a,(byte)0xa0,(byte)0x5b,(byte)0x67,(byte)0xbb,(byte)0x5e,(byte)0x6c,(byte)0x21,(byte)0xe4,(byte)0xca,(byte)0x1f,(byte)0x61,(byte)0xa2,(byte)0xf5,(byte)0xfe,(byte)0x7a,(byte)0xe4,(byte)0xca,(byte)0xb8,(byte)0x87,(byte)0x86,(byte)0xf0,(byte)0x0f,(byte)0x14,(byte)0x68,(byte)0x75,(byte)0x46,(byte)0xb0,(byte)0x21,(byte)0x7d,(byte)0xec,(byte)0x32,(byte)0x25,(byte)0xb3,(byte)0x03,(byte)0x94,(byte)0x78,(byte)0x31,(byte)0xc0,(byte)0x7e};
//            byte[] tSkeyId_d2 = {(byte)0x93,(byte)0xaf,(byte)0xc6,(byte)0xab,(byte)0xfd,(byte)0x5b,(byte)0xae,(byte)0x9a,(byte)0xd7,(byte)0xdd,(byte)0x52,(byte)0xfb,(byte)0xda,(byte)0x7a,(byte)0xac,(byte)0xf9,(byte)0xbc,(byte)0x08,(byte)0x60,(byte)0xa7,(byte)0x7f,(byte)0x3e,(byte)0x90,(byte)0x35,(byte)0xfd,(byte)0x41,(byte)0x38,(byte)0x23,(byte)0x48,(byte)0xd9,(byte)0x35,(byte)0x5a};
//            byte[] Ni_b2 = {(byte)0xd3,(byte)0x1f,(byte)0xcf,(byte)0x97,(byte)0x9e,(byte)0x2c,(byte)0x0b,(byte)0x47,(byte)0x36,(byte)0x5d,(byte)0x49,(byte)0x5d,(byte)0x99,(byte)0x52,(byte)0xe3,(byte)0xfa};
//            byte[] Nr_b2 = {(byte)0x21,(byte)0x1f,(byte)0xdb,(byte)0x66,(byte)0xcc,(byte)0x60,(byte)0x01,(byte)0xad,(byte)0x03,(byte)0x97,(byte)0xb9,(byte)0x38,(byte)0xed,(byte)0x6a,(byte)0xea,(byte)0xfb,(byte)0x3d,(byte)0x49,(byte)0xad,(byte)0xc1,(byte)0x9f,(byte)0x24,(byte)0x34,(byte)0xca,(byte)0x2b,(byte)0x47,(byte)0xb1,(byte)0xa5,(byte)0xb4,(byte)0x11,(byte)0x4b,(byte)0xf4};
//            byte[] spi_r2 = {(byte)0xc9,(byte)0x2f,(byte)0x40,(byte)0x31};
//
//            byte[] tIV5 = {(byte)0xc8,(byte)0xb7,(byte)0x37,(byte)0x03,(byte)0xc5,(byte)0x8e,(byte)0x2f,(byte)0xbe,(byte)0x13,(byte)0xe6,(byte)0x9e,(byte)0x12,(byte)0xf1,(byte)0x23,(byte)0x1e,(byte)0x25};
//            byte[] dataToDecrypt5 = {(byte)0x93,(byte)0x32,(byte)0x32,(byte)0xd0,(byte)0x56,(byte)0xb1,(byte)0xde,(byte)0x92,(byte)0xb3,(byte)0x7c,(byte)0x87,(byte)0x55,(byte)0x73,(byte)0xad,(byte)0xaa,(byte)0x9a,(byte)0x41,(byte)0x42,(byte)0x0b,(byte)0x12,(byte)0xc3,(byte)0xfe,(byte)0x0f,(byte)0x5c,(byte)0xa3,(byte)0xea,(byte)0x33,(byte)0xc8,(byte)0xb8,(byte)0xeb,(byte)0x1f,(byte)0x85,(byte)0xb8,(byte)0xb0,(byte)0x1f,(byte)0x30,(byte)0x1b,(byte)0x20,(byte)0x74,(byte)0x85,(byte)0xa3,(byte)0xa5,(byte)0xfa,(byte)0xa9,(byte)0xe3,(byte)0xa1,(byte)0xbd,(byte)0x08,(byte)0x4c,(byte)0x07,(byte)0xd8,(byte)0x75,(byte)0x96,(byte)0x50,(byte)0x88,(byte)0x1e,(byte)0x7c,(byte)0x07,(byte)0x81,(byte)0x06,(byte)0xeb,(byte)0x7f,(byte)0x34,(byte)0x10,(byte)0xe6,(byte)0xb0,(byte)0x6b,(byte)0x44,(byte)0x81,(byte)0x8f,(byte)0x5c,(byte)0x6b,(byte)0x4a,(byte)0x6f,(byte)0x9e,(byte)0x7e};
//
//            byte[] keymat5 = {(byte)0xbb,(byte)0x85,(byte)0x33,(byte)0xea,(byte)0x53,(byte)0xd2,(byte)0x70,(byte)0xe0,(byte)0xcf,(byte)0xa6,(byte)0x71,(byte)0xf5,(byte)0xa1,(byte)0x84,(byte)0xdb,(byte)0x64,(byte)0x4e,(byte)0xd9,(byte)0xd2,(byte)0x94,(byte)0x4b,(byte)0x24,(byte)0x26,(byte)0x0b,(byte)0xd6,(byte)0x59,(byte)0x8b,(byte)0x87,(byte)0x87,(byte)0xda,(byte)0x6d,(byte)0x76};
//
//            setIV(tIV5);
//            byte[] out = aes256Decrypt(keymat5, dataToDecrypt5);
//
//            print("out", out);
//
//            byte[]dataForHash = new byte[1 + tResponderNonce.length + tInitiatorNonce.length + tSPI_r.length];
//            //byte[]dataForHash = new byte[1 + tResponderNonce.length + tInitiatorNonce.length + tSPI_i.length];
//            System.arraycopy(Utils.toBytes(3, 1), 0,dataForHash, 0, 1);
//            System.arraycopy(tSPI_r, 0,dataForHash, 1, tSPI_r.length);
//            System.arraycopy(tInitiatorNonce, 0,dataForHash, 1 + tSPI_r.length, tInitiatorNonce.length);
//            System.arraycopy(tResponderNonce, 0,dataForHash, 1 + tSPI_r.length + tInitiatorNonce.length, tResponderNonce.length);
//
//            byte[] keymat = hashDataWithKey(tSkeyId_d,dataForHash);
//
//
//            byte[]dataForHash2 = new byte[1 + Ni_b2.length + Nr_b2.length + spi_r2.length];
//            //byte[]dataForHash = new byte[1 + tResponderNonce.length + tInitiatorNonce.length + tSPI_i.length];
//            System.arraycopy(Utils.toBytes(3, 1), 0,dataForHash2, 0, 1);
//            System.arraycopy(spi_r2, 0,dataForHash2, 1, spi_r2.length);
//            System.arraycopy(Ni_b2, 0,dataForHash2, 1 + spi_r2.length, Ni_b2.length);
//            System.arraycopy(Nr_b2, 0,dataForHash2, 1 + spi_r2.length + Ni_b2.length, Nr_b2.length);
//
//            byte[] keymat2 = hashDataWithKey(tSkeyId_d2,dataForHash2);
//
//            setIV(tIV4);
//            byte[] output = aes256Decrypt(keymat2, dataToDecrypt4);
//
//            byte[] d5 = {(byte)0x42,(byte)0x6E,(byte)0x4B,(byte)0xA1,(byte)0xC5,(byte)0x0F,(byte)0x48,(byte)0xA9,(byte)0x91,(byte)0xAA,(byte)0xBE,(byte)0x65,(byte)0xFC,(byte)0xBB,(byte)0xA8,(byte)0xAA,(byte)0xD4,(byte)0x8C,(byte)0x47,(byte)0xB5,(byte)0x33,(byte)0x31,(byte)0xEB,(byte)0x4A,(byte)0x8B,(byte)0x17,(byte)0xEA,(byte)0x4D,(byte)0x5E,(byte)0x95,(byte)0xF8,(byte)0xA9,(byte)0x5D,(byte)0x6F,(byte)0x12,(byte)0xE3,(byte)0x52,(byte)0x60,(byte)0x30,(byte)0x9E,(byte)0x28,(byte)0x06,(byte)0x78,(byte)0x7C,(byte)0x25,(byte)0xA1,(byte)0x4E,(byte)0x1C,(byte)0xE8,(byte)0x4B,(byte)0x8C,(byte)0x0,(byte)0xBE,(byte)0x10,(byte)0x91,(byte)0x39,(byte)0x36,(byte)0x0,(byte)0xDB,(byte)0x0B,(byte)0xF1,(byte)0x0E,(byte)0xD3,(byte)0xBF,(byte)0xF9,(byte)0xEE,(byte)0x1B,(byte)0x7B,(byte)0xFA,(byte)0x3D,(byte)0xAB,(byte)0xEC,(byte)0x75,(byte)0xAA,(byte)0x56,(byte)0x08,(byte)0x4B,(byte)0xFD,(byte)0x5B,(byte)0x4A,(byte)0x65,(byte)0xAF,(byte)0x95,(byte)0x93,(byte)0x05,(byte)0x37,(byte)0xFF,(byte)0x93,(byte)0xA7,(byte)0x8E,(byte)0x02,(byte)0x99,(byte)0x5A,(byte)0xE1,(byte)0xD3,(byte)0x7B};
//            byte[] hash5 = {(byte)0x39,(byte)0x92,(byte)0xB2,(byte)0xCE,(byte)0x5A,(byte)0x14,(byte)0x78,(byte)0xF4,(byte)0xC1,(byte)0x1,(byte)0xE0,(byte)0x4A};
//            byte[] iv5 = {(byte)0xD4,(byte)0xC2,(byte)0xEF,(byte)0x84,(byte)0x7B,(byte)0x28,(byte)0x7A,(byte)0x44,(byte)0x33,(byte)0xC5,(byte)0xED,(byte)0xB1,(byte)0x55,(byte)0x2A,(byte)0xDD,(byte)0x88};
//            byte[] eh5 = {(byte)0x1D,(byte)0xB7,(byte)0xEE,(byte)0xBE,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x1};
//            byte[] k5 = {(byte)0x76,(byte)0xab,(byte)0x5a,(byte)0xbd,(byte)0x3e,(byte)0xca,(byte)0xf2,(byte)0x8c,(byte)0x8a,(byte)0x74,(byte)0xbb,(byte)0xed,(byte)0xfc,(byte)0x18,(byte)0x8d,(byte)0xe3,(byte)0x32,(byte)0xf4,(byte)0x19,(byte)0x7c,(byte)0x65,(byte)0x1a,(byte)0x36,(byte)0x49,(byte)0x02,(byte)0x8d,(byte)0xdc,(byte)0xa2,(byte)0x17,(byte)0xd1,(byte)0x31,(byte)0xf1};
//
//            setIV(iv5);
//
//            output = aes256Decrypt(k5, d5);
//
//            print("output", output);
//
//            byte[] temp = new byte[d5.length + iv5.length + eh5.length];
//            System.arraycopy(eh5, 0, temp, 0, eh5.length);
//            System.arraycopy(iv5, 0, temp, eh5.length, iv5.length);
//            System.arraycopy(d5, 0, temp, eh5.length + iv5.length, d5.length);
//            byte[] hk5 = {(byte)0x71,(byte)0x52,(byte)0xf1,(byte)0xce,(byte)0xe5,(byte)0x6b,(byte)0x31,(byte)0xf6,(byte)0x44,(byte)0xf1,(byte)0xb1,(byte)0x48,(byte)0x34,(byte)0xa2,(byte)0x9f,(byte)0xc4,(byte)0x62,(byte)0xf0,(byte)0x77,(byte)0x43,(byte)0x35,(byte)0x6f,(byte)0x63,(byte)0x6f,(byte)0xde,(byte)0xd9,(byte)0xa6,(byte)0xf8,(byte)0x43,(byte)0xb8,(byte)0xf9,(byte)0x4b};
//
//            output = hashDataWithKey(hk5, temp);
//
//            for (int i = 0; i < hash5.length; i++) {
//                if (output[i] != hash5[i]) {
//                    Log.i(TAG, "hash not matches");
//                }
//            }
//
//            Log.i(TAG, "Finish hash comparison");
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }


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
            //print("SharedSecret", mSharedSecret);

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

//            print("Nonce (initiator)", initiatorNonceBytes);
//            print("Nonce (responder)", responderNonce);
//            print("SKEYID: ", mSKEYID);

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

//        print("Initiator cookie", initiatorCookie);
//        print("responder cookie", responderCookie);
//        print("SKEYID_d", mSKEYIDd);

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

//        print("SKEYID_a", mSKEYIDa);
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

//        print("SKEYID_e", mSKEYIDe);

    }

    public void prepareKeyMaterial(byte[] responderNonce2, byte[] responderSPI) {
        if (mSKEYIDd == null || responderNonce2 == null) {
            Log.e(TAG, "Data not available for preparing key material");
            return;
        }

        mResponderNonce2 = responderNonce2;
        byte[] initiatorNonce2 = mNoncePhase2.toByteArray();
        byte[] data = new byte[1/*protocol*/ + 4/*spi*/ + initiatorNonce2.length + mResponderNonce2.length];

        System.arraycopy(Utils.toBytes(3, 1), 0, data, 0, 1);
        System.arraycopy(Utils.toBytes(mSPI), 0, data, 1, 4);
        System.arraycopy(initiatorNonce2, 0, data, 1 + 4, initiatorNonce2.length);
        System.arraycopy(mResponderNonce2, 0, data, 1 + 4 + initiatorNonce2.length, mResponderNonce2.length);

        mInboundEncryptKeyMaterial = hashDataWithKey(mSKEYIDd, data);

        byte[] data2 = new byte[mInboundEncryptKeyMaterial.length + data.length];
        System.arraycopy(mInboundEncryptKeyMaterial, 0, data2, 0, mInboundEncryptKeyMaterial.length);
        System.arraycopy(data, 0, data2, mInboundEncryptKeyMaterial.length, data.length);

        mInboundAuthKeyMaterial = hashDataWithKey(mSKEYIDd, data2);

        System.arraycopy(Utils.toBytes(3, 1), 0, data, 0, 1);
        System.arraycopy(responderSPI, 0, data, 1, 4);
        System.arraycopy(initiatorNonce2, 0, data, 1 + 4, initiatorNonce2.length);
        System.arraycopy(mResponderNonce2, 0, data, 1 + 4 + initiatorNonce2.length, mResponderNonce2.length);

        mOutboundEncryptKeyMaterial = hashDataWithKey(mSKEYIDd, data);

        System.arraycopy(mOutboundEncryptKeyMaterial, 0, data2, 0, mOutboundEncryptKeyMaterial.length);
        System.arraycopy(data, 0, data2, mOutboundEncryptKeyMaterial.length, data.length);

        mOutboundAuthKeyMaterial = hashDataWithKey(mSKEYIDd, data2);

        print("Outbound Encrypt Keying Material", mOutboundEncryptKeyMaterial);

        print("Outbound auth key", mOutboundAuthKeyMaterial);

        print("Inbound Encrypt Keying Material", mInboundEncryptKeyMaterial);

        print("Inbound auth key", mInboundAuthKeyMaterial);

        print("My SPI", Utils.toBytes(mSPI));
        print("responder SPI", responderSPI);
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

//        print("HashData", hashData);

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

//        print("Responder's 1st responderIDPayload", responderIDPayload);
//        print("Responder's 1st HashData", hashData);

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

//            print("Encrypted data", output);

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

//        print("Hash data for config mode payload", output);

        return output;
    }

    public byte[] encryptESPPayload(byte[] payload) {
        return aes256Encrypt2(mOutboundEncryptKeyMaterial, payload);
    }

    public byte[] decryptESPPayload(byte[] payload) {
        return aes256Decrypt2(mInboundEncryptKeyMaterial, payload);
    }

    public byte[] encryptData(byte[] payloadData) {

        return encryptDataWithKey(mSKEYIDe, payloadData);
    }

    public byte[] encryptDataWithKey(byte[] key, byte[] payloadData) {

        byte[] output = null;
//        print("IV", mIv);

        if (mEncryptAlgorithm.equals("AES256")) {
            output = aes256Encrypt(key, payloadData);

//            print("Encrypted data", output);
//            print("payload before encrypt", payloadData);
        }

        return output;
    }

    public byte[] decryptData(byte[] encryptedData) {
        return decryptDataWithKey(mSKEYIDe, encryptedData);
    }

    public byte[] decryptDataWithKey(byte[] key, byte[] encryptedData) {
        byte[] output = null;

        if (mEncryptAlgorithm.equals("AES256")) {
            output = aes256Decrypt(key, encryptedData);
        }

        return output;
    }

    public byte[] generateESPSPI() {
        SecureRandom random = new SecureRandom();

        while (true) {
            int randomNum = random.nextInt();
            // 0 is reserved for local, 1 - 255 are reserved by IANA
            if (randomNum > 255){
                return Utils.toBytes(randomNum);
            }
        }
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

    public byte[] generateESPOutboundICV(byte[] data) {
        return hashDataWithKey(mOutboundAuthKeyMaterial, data);
    }

    public byte[] generateESPInboundICV(byte[] data) {
        return hashDataWithKey(mInboundAuthKeyMaterial, data);
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

    private byte[] aes256Encrypt(byte[] key, byte[] inputData) {

        try {
            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());

            cipher.init(true, new ParametersWithIV(new KeyParameter(key), mIv));
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

    private byte[] aes256Encrypt2(byte[] key, byte[] inputData) {

        try {
            BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

            cipher.init(true, new ParametersWithIV(new KeyParameter(key), mIv));
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

    private byte[] aes256Decrypt(byte[] key, byte[] encryptedData) {
        try{

//            print("data before decrypt", encryptedData);
//            print("mIv before decrypt", mIv);


            PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());

            cipher.init(false, new ParametersWithIV(new KeyParameter(key), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(encryptedData.length)];

            int processed = cipher.processBytes(encryptedData, 0, encryptedData.length, outBuffer, 0);

            if (encryptedData.length - processed >= 16) {
                processed += cipher.doFinal(outBuffer, processed);
            } else {
                byte[] removedPaddingBytes = new byte[processed];
                System.arraycopy(outBuffer, 0, removedPaddingBytes, 0, processed);

                return removedPaddingBytes;
            }

//            System.arraycopy(encryptedData, encryptedData.length - 16, mIv, 0, 16);

//            print("data after decrypt", outBuffer);
//            print("mIv after decrypt", mIv);

            return outBuffer;

        } catch(Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private byte[] aes256Decrypt2(byte[] key, byte[] encryptedData) {
        try{

            print("data before decrypt", encryptedData);
            print("mIv before decrypt", mIv);


            BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

            cipher.init(false, new ParametersWithIV(new KeyParameter(key), mIv));
            byte[] outBuffer = new byte[cipher.getOutputSize(encryptedData.length)];

            int processed = cipher.processBytes(encryptedData, 0, encryptedData.length, outBuffer, 0);

            if (encryptedData.length - processed >= 16) {
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
        //print("SetIv=", iv);
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

