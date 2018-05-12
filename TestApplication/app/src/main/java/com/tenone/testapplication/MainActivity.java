package com.tenone.testapplication;

import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;

import com.tenone.testapplication.peer.PeerList;
import com.tenone.testapplication.racoon.CertManager;
import com.tenone.testapplication.racoon.ConfigManager;
import com.tenone.testapplication.racoon.NativeCommand;
import com.tenone.testapplication.racoon.NativeService;

import java.io.IOException;
import java.security.Security;

public class MainActivity extends AppCompatActivity {
    private NativeService mBoundService;
    private boolean mIsBound; /** True if bound. */
    private PeerList mPeers;
    private ConfigManager mCM;
    private final boolean RACOON_STARTUP = false;
    private Handler mGuiHandler;
    private CertManager mCertManager;
    private NativeCommand mNative;
    final private String binaries[] = {
            NativeService.RACOON_EXEC_NAME,
            "racoonctl.sh",
            NativeService.SETKEY_EXEC_NAME,
    };
    private static final String ZIP_FILE = "ipsec-tools.zip";

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }



    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        mGuiHandler = new Handler();

        mNative = new NativeCommand(this);
        try {
            mCertManager = new CertManager(this);
        } catch(Exception e) {
            // TODO
            throw new RuntimeException(e);
        }
        mCM = new ConfigManager(this, mNative, mCertManager);

//        for (int i=0; i < binaries.length; i++) {
//            mNative.putBinary(binaries[i]);
//        }
//        try {
//            mNative.checkZipBinaries(ZIP_FILE);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
        mPeers = new PeerList(mGuiHandler, getApplicationContext(), mCM, 0);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = VpnService.prepare(MainActivity.this);
                if (intent != null) {
                    startActivityForResult(intent, 0);
                } else {
                    onActivityResult(0, RESULT_OK, null);
                }

//                startService();

//                VpnUtil.init(MainActivity.this);
////                Object vpnProfile = VpnUtil.getVpnProfile();
//                Object vpnProfile = null;
//                if(vpnProfile == null){
//                    vpnProfile = VpnUtil.createVpnProfile("vpn1", "54.200.56.198", "testvpn", "stagwell");
//                }else{
//                    VpnUtil.setParams(vpnProfile,"vpn1", "54.200.56.198", "testvpn", "stagwell");
//                }
//                //连接
//                VpnUtil.connect(MainActivity.this,vpnProfile);

            }
        });
    }

    protected void startService() {
        if (mBoundService != null)
            return;
        if (!NativeService.isServiceRunning(this)) {
            startService(new Intent(MainActivity.this,
                    NativeService.class));

        }

        doBindService();
    }

    void doBindService() {
        // Establish a connection with the service.  We use an explicit
        // class name because we want a specific service implementation that
        // we know will be running in our own process (and thus won't be
        // supporting component replacement by other applications).
        // FIXME handle start errors
        mIsBound = bindService(new Intent(MainActivity.this,
                NativeService.class), mConnection, 0);
        Log.i("ipsec-tools", "doBindService " + mIsBound);
    }

    private ServiceConnection mConnection = new ServiceConnection() {
        public void onServiceConnected(ComponentName className, IBinder service) {
            // This is called when the connection with the service has been
            // established, giving us the service object we can use to
            // interact with the service.  Because we have bound to a explicit
            // service that we know is running in our own process, we can
            // cast its IBinder to a concrete class and directly access it.
            mBoundService = ((NativeService.NativeBinder)service).getService();
//            output("Connected");
            Log.i("ipsec-tools", "connected " + mBoundService);
            mPeers.setService(mBoundService);

            if (mBoundService.isRacoonRunning())
                mPeers.dumpIsakmpSA();
            else {
                mPeers.disableAll();
                try {
                    mCM.build(mPeers, true);
                } catch (IOException e) {
//                    throw new RuntimeException(e);
                }

//                if ( RACOON_STARTUP )
                    mBoundService.startRacoon();
            }

            // Tell the user about this for our demo.
//	        Toast.makeText(Binding.this, R.string.native_service_connected,
            //                Toast.LENGTH_SHORT).show();
        }

        public void onServiceDisconnected(ComponentName className) {
            // This is called when the connection with the service has been
            // unexpectedly disconnected -- that is, its process crashed.
            // Because it is running in our same process, we should never
            // see this happen.
            onServiceUnbound();
        }
    };

    private void onServiceUnbound() {
        mBoundService = null;
//        output("Disconnected");
        mPeers.clearService();
        //      Toast.makeText(Binding.this, R.string.native_service_disconnected,
        //            Toast.LENGTH_SHORT).show();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (resultCode == RESULT_OK) {
            Intent intent = new Intent(MainActivity.this, VPNService.class);
            startService(intent);
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
