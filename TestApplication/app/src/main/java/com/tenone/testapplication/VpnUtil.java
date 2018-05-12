package com.tenone.testapplication;

/**
 * Created by willwang on 2018-04-26.
 */

import android.content.Context;
import android.net.ConnectivityManager;
import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;


public class VpnUtil {
    private static Class vpnProfileClz;
    private static Class credentialsClz;
    private static Class keyStoreClz;
    private static Class iConManagerClz;
    private static Object iConManagerObj;

    public static void init(Context context){
        try {
            vpnProfileClz = Class.forName("com.android.internal.net.VpnProfile");
            keyStoreClz = Class.forName("android.security.KeyStore");

            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            Field fieldIConManager = null;

            fieldIConManager = cm.getClass().getDeclaredField("mService");
            fieldIConManager.setAccessible(true);
            iConManagerObj = fieldIConManager.get(cm);
            iConManagerClz = Class.forName(iConManagerObj.getClass().getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Object createVpnProfile(String name, String server, String username, String password) {
        Object vpnProfileObj = null;
        try {
            long millis = System.currentTimeMillis();
            String vpnKey = Long.toHexString(millis);
            Constructor constructor = vpnProfileClz.getConstructor(String.class);
            vpnProfileObj = constructor.newInstance(vpnKey);
            setParams(vpnProfileObj,name,server,username,password);
            insertVpn(vpnProfileObj,vpnKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return vpnProfileObj;
    }

    public static Object setParams(Object vpnProfileObj,String name, String server, String username, String password) {
        try {
            Field field_username = vpnProfileClz.getDeclaredField("username");
            Field field_password = vpnProfileClz.getDeclaredField("password");
            Field field_server = vpnProfileClz.getDeclaredField("server");
            Field field_name = vpnProfileClz.getDeclaredField("name");
            Field field_ipsecSecret = vpnProfileClz.getDeclaredField("ipsecSecret");

            field_name.set(vpnProfileObj, name);
            field_server.set(vpnProfileObj, server);
            field_username.set(vpnProfileObj, username);
            field_password.set(vpnProfileObj, password);
            field_ipsecSecret.set(vpnProfileObj, "test4stagwell");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return vpnProfileObj;
    }

    public static boolean connect(Context context, Object profile) {
        boolean isConnected = true;
        try {
            Method metStartLegacyVpn = iConManagerClz.getDeclaredMethod("startLegacyVpn", vpnProfileClz);
            metStartLegacyVpn.setAccessible(true);
            //unlock KeyStore
            unlock(context);

            metStartLegacyVpn.invoke(iConManagerObj, profile);
        } catch (Exception e) {
            isConnected = false;
            e.printStackTrace();
        }
        return isConnected;
    }

    public static boolean disconnect(Context context) {
        boolean disconnected = true;
        try {
            Method metPrepare = iConManagerClz.getDeclaredMethod("prepareVpn", String.class, String.class);
            metPrepare.invoke(iConManagerObj, "[Legacy VPN]", "[Legacy VPN]");
        } catch (Exception e) {
            disconnected = false;
            e.printStackTrace();
        }
        return disconnected;
    }

    public static Object getVpnProfile() {
        try {
            Object keyStoreObj = getKeyStoreInstance();

            Method keyStore_saw = keyStoreClz.getMethod("saw",String.class);
            keyStore_saw.setAccessible(true);
            String[] keys = (String[]) keyStore_saw.invoke(keyStoreObj,"VPN_");
            if(keys == null || keys.length == 0){
                return null;
            }

            for(String s : keys){
                Log.i("key:",s);
            }

            Method vpnProfile_decode = vpnProfileClz.getDeclaredMethod("decode", String.class, byte[].class);
            vpnProfile_decode.setAccessible(true);

            Method keyStore_get = keyStoreClz.getDeclaredMethod("get", String.class);
            keyStore_get.setAccessible(true);
            Object byteArrayValue = keyStore_get.invoke(keyStoreObj,"VPN_"+keys[0]);
            Object vpnProfileObj = vpnProfile_decode.invoke(null, keys[0], byteArrayValue);

            return vpnProfileObj;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    private static void insertVpn(Object profieObj,String key)throws Exception{
        Method keyStore_put = keyStoreClz.getDeclaredMethod("put", String.class, byte[].class, int.class, int.class);
        Object keyStoreObj = getKeyStoreInstance();
        Class vpnProfileClz = Class.forName("com.android.internal.net.VpnProfile");
        Method vpnProfile_encode = vpnProfileClz.getDeclaredMethod("encode");
        byte[] bytes = (byte[]) vpnProfile_encode.invoke(profieObj);
        keyStore_put.invoke(keyStoreObj,"VPN_"+key,bytes,-1,1);
    }

    private static Object getKeyStoreInstance() throws Exception {
        Method keyStore_getInstance = keyStoreClz.getMethod("getInstance");
        keyStore_getInstance.setAccessible(true);
        Object keyStoreObj = keyStore_getInstance.invoke(null);
        return keyStoreObj;
    }

    private static void unlock(Context mContext) throws Exception {
        credentialsClz = Class.forName("android.security.Credentials");

        Method credentials_getInstance = credentialsClz.getDeclaredMethod("getInstance");
        Object credentialsObj = credentials_getInstance.invoke(null);

        Method credentials_unlock = credentialsClz.getDeclaredMethod("unlock",Context.class);
        credentials_unlock.invoke(credentialsObj,mContext);
    }


}