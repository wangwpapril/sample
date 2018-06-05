package com.tenone.testapplication.isakmp;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.util.Log;

//import com.harrisxocr.database.DbHelper;
//import com.harrisxocr.database.EventRecord;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Created by willwang on 2018-01-31.
 */

public class Utils {
    public static final int INT_BUFFER_SIZE = 4;
    public static final int LONG_BUFFER_SIZE = 8;

    private static final String TAG = "Utils";
    private static Context appContext;
    private static final int DEFAULT_SIZE = 65535;

    public static String getSSID(Context context) {
        String ssid = null;
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                WifiInfo info = wifiManager.getConnectionInfo();

                // This value should be wrapped in double quotes, so we need to unwrap it.
                ssid = info.getSSID();
                if (ssid.startsWith("\"") && ssid.endsWith("\"")) {
                    ssid = ssid.substring(1, ssid.length() - 1);
                }
            }

        }catch (Exception ex) {
            ex.printStackTrace();
        }
        return ssid;
    }

    public static String getIPAddress(Context context) {
        String ipAddress = null;

        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                WifiInfo info = wifiManager.getConnectionInfo();
                if (info != null) {
                    ipAddress = longToIP(info.getIpAddress());

                }
            }

        }catch (Exception ex) {
            ex.printStackTrace();
        }

        return ipAddress;
    }

    public static String getCurrentSignalStrength(Context context) {
        String strength = null;
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                WifiInfo info = wifiManager.getConnectionInfo();
                if (info != null) {
                    strength = String.valueOf(info.getRssi());
                }
            }
        }catch (Exception ex) {
            ex.printStackTrace();
        }

        return strength;
    }

    public static String getProviderName(Context context, String ssid) {
        String provider = null;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || ssid == null || ssid.isEmpty()) {
            return null;
        }
        try {
            WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                List<ScanResult> results = wifiManager.getScanResults();

                for (ScanResult result : results) {
                    if (!result.SSID.equals("") && result.SSID.equals(ssid)) {
                        provider = result.operatorFriendlyName.toString();
                        break;
                    }
                }
            }

        }catch (Exception ex) {
            ex.printStackTrace();
        }

        return provider;
    }

    public static boolean isWifiApOpen(Context context) {
        try {
            WifiManager manager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            Method method = manager.getClass().getDeclaredMethod("getWifiApState");
            int state = (int) method.invoke(manager);
            Field field = manager.getClass().getDeclaredField("WIFI_AP_STATE_ENABLED");
            int value = (int) field.get(manager);
            if (state == value) {
                return true;
            } else {
                return false;
            }
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String getWifiApSSID(Context context) {
        String ssid = null;
        try {
            WifiManager manager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            Method method = manager.getClass().getDeclaredMethod("getWifiApConfiguration");
            WifiConfiguration configuration = (WifiConfiguration) method.invoke(manager);
            ssid = configuration.SSID;
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return ssid;
    }

    static public ArrayList<String> getConnectedIP(){
        ArrayList<String> connectedIp=new ArrayList<String>();
        try {
            BufferedReader br=new BufferedReader(new FileReader(
                    "/proc/net/arp"));
            String line;
            while ((line=br.readLine())!=null){
                String[] splitted=line.split(" +");
                if (splitted !=null && splitted.length>=4){
                    String ip=splitted[0];
                    if (!ip.equalsIgnoreCase("ip")){
                        connectedIp.add(ip);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return connectedIp;
    }

    public static ArrayList<ClientScanResult> getApClientList() {
        BufferedReader br = null;
        final ArrayList<ClientScanResult> result = new ArrayList<>();

        try {
            br = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            while ((line = br.readLine()) != null) {
                String[] splitted = line.split(" +");

                if ((splitted != null) && (splitted.length >= 4)) {
                    // Basic sanity check
                    String mac = splitted[3];

                    if (mac.matches("..:..:..:..:..:..")) {
                        final String ipAddress = splitted[0];
                        final String hwAddress = splitted[3];
                        final String deviceName = splitted[5];
                        InetAddress inetAddress = InetAddress.getByName(ipAddress);
                        boolean isReachable = inetAddress.isReachable(300);

                        if (isReachable) {
                            result.add(new ClientScanResult(ipAddress, hwAddress, deviceName, isReachable));
                        } else {

                            try {
                                int exit = 1;

                                // try again with ping command
                                Process process = Runtime.getRuntime().exec("ping -c 1 " + ipAddress);
//                                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
//                                    if (process.waitFor(1500, TimeUnit.MILLISECONDS)) {
//                                        exit = process.exitValue();
//                                    }
//                                } else {
//                                    exit = process.waitFor();
//
//                                /*InputStream is = process.getInputStream();
//                                BufferedReader reader = new BufferedReader(new InputStreamReader(is));
//
//                                String pingLine = null;
//                                while ((pingLine = reader.readLine()) != null) {
//                                    Log.d(TAG, pingLine);
//                                }
//                                reader.close();
//                                */
//                                }

                                if (exit == 0) {
                                    result.add(new ClientScanResult(ipAddress, hwAddress, deviceName, true));
                                }

                                process.destroy();

                            } catch (Exception e) {
                                Log.e(TAG, "Failed to ping " + ipAddress + ". " + e.getLocalizedMessage(), e);
                            }

                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                br.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return result;
    }

    public static long getTrafficInfo1(int uid) {
        FileReader mReader = null;
        BufferedReader mBufReader = null;

        String fileName = "/proc/net/xt_qtaguid/stats";
        long ret = 0;
        try{
            mReader = new FileReader(fileName);
            mBufReader = new BufferedReader(mReader);
            String line = null;
            int count = 0;
            while ( (line = mBufReader.readLine()) != null){
                count++;
                if(count == 1 ) continue;
                String[] vecTemp = line.split("[:\\\\s]+");
                if(vecTemp[1].equals("wlan0") && Integer.valueOf(vecTemp[3]) == uid){
                    ret += Long.valueOf(vecTemp[5]) + Long.valueOf(vecTemp[7]);
                }
            }
        }catch (IOException e){
//            Log.e(LOG_TAG,e.getMessage());
        }finally {
            try {
                if (mBufReader != null) {
                    mBufReader.close();
                }
                if (mReader != null) {
                    mReader.close();
                }
            }catch (IOException e){
//                Log.e(LOG_TAG,e.getMessage());
            }
        }
        return ret;
    }

    public static long getTrafficInfo(int uid) {
        File file = new File("/proc/net/xt_qtaguid/stats");
        List<String> list = readFile2List(file, "utf-8");
        long rxBytesWlan = 0L;
        long txBytesWlan = 0L;
        for (String stat : list) {
            String[] split = stat.split(" ");
            try {
                int idx = Integer.parseInt(split[3]);
                if (uid == idx) {
                    long rx_bytes = Long.parseLong(split[5]);
                    long tx_bytes = Long.parseLong(split[7]);
//                    if (split[1].startsWith("wlan")) {
                        rxBytesWlan += rx_bytes;
                        txBytesWlan += tx_bytes;
//                    }
                }
            } catch (NumberFormatException ignored) {
            }
        }
//        long result = rxBytesWlan + txBytesWlan;
        return rxBytesWlan;

    }

    public static long getTotalTraffic(int uid) {
        long rx_bytes = 0;
        long tx_bytes = 0 ;
        try {
            FileReader stream = new FileReader("/proc/net/xt_qtaguid/stats");
            BufferedReader in = new BufferedReader(stream, 500);
            String line;
            String[] dataStrings;
            while ((line = in.readLine()) != null) {
                dataStrings = line.split(" ");
                if (String.valueOf(uid).equals(dataStrings[3])) {
//                    TrafficData dataTotal = new TrafficData();
//                    TrafficData dataDiff = new TrafficData();
//
//                    dataTotal.iface = dataDiff.iface = dataStrings[1];
//                    dataTotal.moduleTag = dataDiff.moduleTag = dataStrings[2];
//                    dataTotal.cnt_set = dataDiff.cnt_set = dataStrings[4];

                    rx_bytes += Long.parseLong(dataStrings[5]);
                    tx_bytes += Long.parseLong(dataStrings[7]);

                }
            }
            in.close();
            stream.close();
        } catch (Exception e) {
        }

        return rx_bytes + tx_bytes;
    }

    public static long getTotalTraffic(String iface) {
        long rx_bytes = 0;
        long tx_bytes = 0 ;
        try {
            FileReader stream = new FileReader("/proc/net/xt_qtaguid/stats");
            BufferedReader in = new BufferedReader(stream, 500);
            String line;
            String[] dataStrings;
            while ((line = in.readLine()) != null) {
                dataStrings = line.split(" ");
                if (iface.equals(dataStrings[1])) {
//                    TrafficData dataTotal = new TrafficData();
//                    TrafficData dataDiff = new TrafficData();
//
//                    dataTotal.iface = dataDiff.iface = dataStrings[1];
//                    dataTotal.moduleTag = dataDiff.moduleTag = dataStrings[2];
//                    dataTotal.cnt_set = dataDiff.cnt_set = dataStrings[4];

                    rx_bytes += Long.parseLong(dataStrings[5]);
                    tx_bytes += Long.parseLong(dataStrings[7]);

                }
            }
            in.close();
            stream.close();
        } catch (Exception e) {
        }

        return rx_bytes + tx_bytes;
    }

    public static List<String> readFile2List(File file, String charsetName) {
        if (file == null) {
            return null;
        }
        BufferedReader reader = null;
        try {
            String line;
            int curLine = 0;
            List<String> list = new ArrayList<>();
            if ((charsetName == null || charsetName.trim().length() == 0)) {
                reader = new BufferedReader(new FileReader(file));
            } else {
                reader = new BufferedReader(new InputStreamReader(new FileInputStream(file), charsetName));
            }
            while ((line = reader.readLine()) != null) {
                if (0 < curLine) {
                    list.add(line);
                }
                ++curLine;
            }
            return list;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } finally {
            try {
                if (reader != null) {
                    reader.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static class ClientScanResult {

        private String IpAddr;
        private String HWAddr;
        private String Device;
        private boolean isReachable;

        public ClientScanResult(String ipAddr, String hWAddr, String device, boolean isReachable) {
            super();
            this.IpAddr = ipAddr;
            this.HWAddr = hWAddr;
            this.Device = device;
            this.isReachable = isReachable;
        }

        public String getIpAddr() {
            return IpAddr;
        }

        public void setIpAddr(String ipAddr) {
            IpAddr = ipAddr;
        }

        public String getHWAddr() {
            return HWAddr;
        }

        public void setHWAddr(String hWAddr) {
            HWAddr = hWAddr;
        }

        public String getDevice() {
            return Device;
        }

        public void setDevice(String device) {
            Device = device;
        }

        public boolean isReachable() {
            return isReachable;
        }

        public void setReachable(boolean isReachable) {
            this.isReachable = isReachable;
        }
    }

    /**
     * Reads the file and output the contents
     *
     * @param path
     * @return
     */
    public static String readFile(String path) {
        BufferedReader reader = null;
        StringBuilder output = new StringBuilder();

        try {
            reader = new BufferedReader(new FileReader(path));

            String line = null;

            while((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.d(TAG, "Unable to read the file (" + path + "). " + e.getLocalizedMessage(), e);
        }
        finally {

            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }

        return output.toString();
    }

    /**
     *  convert ip address
     * @param longIp
     * @return
     */
    public static String longToIP(int longIp) {
        StringBuffer sb = new StringBuffer("");
        String[] strip = new String[4];
        strip[3] = String.valueOf((longIp >>> 24));
        strip[2] = String.valueOf((longIp & 0x00FFFFFF) >>> 16);
        strip[1] = String.valueOf((longIp & 0x0000FFFF) >>> 8);
        strip[0] = String.valueOf((longIp & 0x000000FF));
        sb.append(strip[0]);
        sb.append(".");
        sb.append(strip[1]);
        sb.append(".");
        sb.append(strip[2]);
        sb.append(".");
        sb.append(strip[3]);
        return sb.toString();
    }

    /**
     * Get the connected devices to the hotspot (this needs to be called periodically to check, the broadcast not
     * working well after 5.1), then save in the database
     */
    public static void getTetherConnectedDevices() {
//        AsyncTask.execute(new Runnable() {
//            @Override
//            public void run() {
//                long currentTime = System.currentTimeMillis();
//                DbHelper dbHelper = DbHelper.getInstance(getAppContext());
//
//                EventRecord record = dbHelper.getLastEventRecordBeforeTime(Constants.TAG_TETHER_STATE, currentTime);
//                // records the connected device only when hotspot is enabled. Ignore otherwise.
//                if (record != null && Boolean.parseBoolean(record.getValue())) {
//
//                    JSONArray jsonArray = new JSONArray();
//                    List<ClientScanResult> clientConnected = getApClientList();
//                    for (ClientScanResult client : clientConnected) {
//                        try {
//                            jsonArray.put(new JSONObject().put(Constants.IP_ADDRESS, client.getIpAddr())
//                                    .put(Constants.HW_ADDRESS, client.getHWAddr())
//                                    .put(Constants.DEVICE_NAME, client.getDevice()));
//                        } catch (JSONException e) {
//                            e.printStackTrace();
//                        }
//                    }
//
//                    if (jsonArray.length() > 0) {
//                        dbHelper.insertEventRecord(Constants.TAG_TETHER_CONNECTED_DEVICES, currentTime, jsonArray.toString());
//                    }
//                }
//            }
//        });
    }

    /**
     * Get the ApplicationContext (in a global place that can be used in anywhere)
     * @return
     */
    public static Context getAppContext(){
        return appContext;
    }

    /**
     * Set the ApplicationContext (do in the entry point of the app starts)
     * @param context
     */
    public static void setAppContext(Context context) {
        appContext = context;
    }

    public static byte[] toBytes(int value) {
        return toBytes(value, INT_BUFFER_SIZE);
    }

    public static byte[] toBytes(int value, int byteNumber) {
        if (byteNumber <= 0) {
            return null;
        }
        ByteBuffer byteBuffer = ByteBuffer.allocate(INT_BUFFER_SIZE);
        byteBuffer.putInt(value);
        byte[] ret = new byte[byteNumber];
        System.arraycopy(byteBuffer.array(), INT_BUFFER_SIZE - byteNumber, ret, 0, byteNumber);
        return ret;
    }

    public static byte[] toBytes(long value) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(LONG_BUFFER_SIZE);
        byteBuffer.putLong(value);
        return byteBuffer.array();
    }

    public static String getIPAddress1(Context context) {
        NetworkInfo info = ((ConnectivityManager) context
                .getSystemService(Context.CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
        if (info != null && info.isConnected()) {
            if (info.getType() == ConnectivityManager.TYPE_MOBILE) {
                try {
                    //Enumeration<NetworkInterface> en=NetworkInterface.getNetworkInterfaces();
                    for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements(); ) {
                        NetworkInterface intf = en.nextElement();
                        for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements(); ) {
                            InetAddress inetAddress = enumIpAddr.nextElement();
                            if (!inetAddress.isLoopbackAddress() && inetAddress instanceof Inet4Address) {
                                return inetAddress.getHostAddress();
                            }
                        }
                    }
                } catch (SocketException e) {
                    e.printStackTrace();
                }

            } else if (info.getType() == ConnectivityManager.TYPE_WIFI) {
                WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                String ipAddress = intIP2StringIP(wifiInfo.getIpAddress());
                return ipAddress;
            }
        } else {

        }
        return null;
    }

    /**
     *
     *
     * @param ip
     * @return
     */
    public static String intIP2StringIP(int ip) {
        return (ip & 0xFF) + "." +
                ((ip >> 8) & 0xFF) + "." +
                ((ip >> 16) & 0xFF) + "." +
                (ip >> 24 & 0xFF);
    }

    public static byte[] ipv4AddressToBytes(String ipAddress) {
        // in case the ip address is \10.0.2.15
        String[] parts = ipAddress.replace("\\", "").split("\\.");

        byte[] data = new byte[4];
        data[0] = Utils.toBytes(Integer.valueOf(parts[0]), 1)[0];
        data[1] = Utils.toBytes(Integer.valueOf(parts[1]), 1)[0];
        data[2] = Utils.toBytes(Integer.valueOf(parts[2]), 1)[0];
        data[3] = Utils.toBytes(Integer.valueOf(parts[3]), 1)[0];

        return data;
    }

    public static byte[] combineData(byte[][] inputArray) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(DEFAULT_SIZE);
        int length = 0;
        for (int i = 0; i < inputArray.length; i++) {
            byteBuffer.put(inputArray[i]);
            length += inputArray[i].length;
        }

        byteBuffer.limit(length);

        byte[] ret = new byte[length];
        byteBuffer.position(0);
        byteBuffer.get(ret, 0, length);

        return ret;
    }

    public int generateRandomInt() {
        SecureRandom random = new SecureRandom();

        return random.nextInt();
    }

    public byte[] generateRandomBytes(int byteNumber) {
        SecureRandom random = new SecureRandom();

        byte[] randomBytes = new byte[byteNumber];

        random.nextBytes(randomBytes);

        return randomBytes;
    }
}
