package com.tenone.testapplication;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Handler;
import android.util.Log;

public class NetChangeReceiver extends BroadcastReceiver {
    public static volatile int mNetState;

    public final static int  NET_STATE_NONE = 0;
    public final static int NET_STATE_MOBILE = 1;
    public final static int NET_STATE_WIFI = 2;

    private Handler mHandler;

    public NetChangeReceiver(){}

    public NetChangeReceiver(Context context, Handler handler){

        mHandler = handler;

        ConnectivityManager connMgr = (ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr
                .getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        boolean isWifiConn = networkInfo.isConnected();

        if(isWifiConn){
            mNetState = NET_STATE_WIFI;

            return;
        }

        networkInfo = connMgr.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);
        boolean isMobileConn = networkInfo.isConnected();
        if(isMobileConn){
            mNetState = NET_STATE_MOBILE;

            return;
        }
        mNetState = NET_STATE_NONE;

    }

    @Override
    public void onReceive(Context context, Intent intent) {
        ConnectivityManager connMgr = (ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connMgr
                .getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        boolean isWifiConn = networkInfo.isConnected();

        if(isWifiConn){
            mNetState = NET_STATE_WIFI;
            return;
        }

        networkInfo = connMgr.getNetworkInfo(ConnectivityManager.TYPE_MOBILE);
        boolean isMobileConn = networkInfo.isConnected();
        if(isMobileConn){
            mNetState = NET_STATE_MOBILE;
            return;
        }
        mNetState = NET_STATE_NONE;

    }
}
