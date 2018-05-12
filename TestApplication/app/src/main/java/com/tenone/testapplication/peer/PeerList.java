package com.tenone.testapplication.peer;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Iterator;

//import org.za.hem.ipsec_tools.NativeCommand;
//import org.za.hem.ipsec_tools.R;
//import org.za.hem.ipsec_tools.service.ConfigManager;
//import org.za.hem.ipsec_tools.service.ConfigManager.Action;
//import org.za.hem.ipsec_tools.service.NativeService;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Log;

import com.tenone.testapplication.racoon.ConfigManager;
import com.tenone.testapplication.racoon.NativeCommand;
import com.tenone.testapplication.racoon.NativeService;

/**
 * Peer List Controller
 *
 * @author mikael
 *
 */
public class PeerList extends ArrayList<Peer> {

	public static final int HANDLER_VPN_CONNECT = 1;
	public static final int HANDLER_VPN_DISCONNECT = 2;
	public static final int HANDLER_DUMP_ISAKMP_SA = 3;
    public static final int HANDLER_ENABLE_AND_CONNECT = 4;
    public static final int HANDLER_DISCONNECT_AND_DISABLE = 5;
    public static final int HANDLER_UPDATE_CONFIG = 6;

    public static final String HANDLER_KEY_ACTION = "action";

    /**
	 * Serial for Serializable 
	 */
	private static final long serialVersionUID = -3584858864706289236L;
	
	private ArrayList<Peer> mPeers;
	private OnPeerChangeListener mListener;
	private HandlerThread mHandlerThread;
	private Handler mHandler;
	private NativeService mBoundService;
	private Context mContext;
	private ConfigManager mConfigManager;
	private Handler mGuiHandler;
	
	public PeerList(Handler guiHandler, Context context, ConfigManager configManager, int capacity) {
		super(capacity);
		mGuiHandler = guiHandler;
		mContext = context;
		mConfigManager = configManager;
		mBoundService = null;
		mPeers = this;
		mHandler = null;
		mHandlerThread = null;
	}
	
	private void startHandler() {
		mHandlerThread  = new HandlerThread("PeerList");
		mHandlerThread.start();
		mHandler = new Handler(mHandlerThread.getLooper()) {
			public void handleMessage(Message msg) {
				String addr;
				switch (msg.what) {
				case HANDLER_VPN_CONNECT:
			    	addr = (String)msg.obj;
			   		mBoundService.vpnConnect(addr);
					break;
				case HANDLER_VPN_DISCONNECT:
			    	addr = (String)msg.obj;
			   		mBoundService.vpnDisconnect(addr);
					break;
				case HANDLER_DUMP_ISAKMP_SA:
				    mBoundService.dumpIsakmpSA();
				    break;
				case HANDLER_ENABLE_AND_CONNECT:
				    doEnableAndConnect((PeerID)msg.obj);
				    break;
				case HANDLER_DISCONNECT_AND_DISABLE:
				    doDisconnectAndDisable((PeerID)msg.obj);
				    break;
				case HANDLER_UPDATE_CONFIG:
				    try {
				        doUpdateConfig((PeerID)msg.obj,
				                (ConfigManager.Action)msg.getData().getSerializable(HANDLER_KEY_ACTION));
				    } catch (IOException e) {
				        e.printStackTrace();
				    }
				}	
			}
		};		
	}
	
	private void stopHandler() {
		if (mHandler == null)
			return;
		mHandler.getLooper().quit();
		try {
			mHandlerThread.join(1000);
		} catch (InterruptedException e) {
		}
		mHandlerThread = null;
		mHandler = null;
	}
	
	public void setService(NativeService service) {
		if (service == null)
			throw new NullPointerException();

		mBoundService = service;		
		if (mHandlerThread == null)
			startHandler();
	}
	
	public void clearService() {
		stopHandler();
		mBoundService = null;
	}
	
	public Peer get(PeerID id) {
		int i = id.intValue();
		return mPeers.get(i);
	}
	
	protected void set(PeerID id, Peer peer) {
		mPeers.set(id.intValue(), peer);
	}
	
	public void setOnPeerChangeListener(OnPeerChangeListener listener) {
		mListener = listener;
	}

	public Peer findForRemote(final InetSocketAddress sa,
				  boolean isUp) {
    	InetAddress addr = sa.getAddress();
    	Iterator<Peer> iter = iterator();
    	
    	while (iter.hasNext()) {
    		Peer peer = iter.next();
    		if (peer == null)
    			continue;
		Log.i("ipsec-tools", "findForRemote " + peer + " " + peer.getStatus() + " " + peer.isEnabled());
		if (isUp) {
		    if (!peer.isConnected()) continue;
		} else {
		    if (!peer.isEnabled()) continue;
		}
			InetAddress peerAddr = peer.getRemoteAddr();
    		if (peerAddr != null && peerAddr.equals(addr))
    			return peer;
    	}

    	return null;
    }
	
    public PeerID createPeer(Context context)
    {
        int empty = mPeers.indexOf(null);
        if (empty == -1) {
        	empty = mPeers.size();
        	Log.i("ipsec-tools", "Size " + mPeers.size());
        }
        mPeers.ensureCapacity(empty+1);

    	Log.i("ipsec-tools", "New id " + empty);
        PeerID newId = new PeerID(empty);
    	Peer peer = new Peer(mGuiHandler, context, newId, null);
    	if (empty >= mPeers.size())
    		mPeers.add(peer);
    	else
    		mPeers.set(empty, peer);
        
        if (mListener != null)
        	mListener.onCreatePeer(peer);
        
        return newId;
    }
    	
    public void deletePeer(final PeerID id, Context context) {
    	final Peer peer = get(id);
    	
		Log.i("ipsec-tools", "deletePeer");
		AlertDialog.Builder builder = new AlertDialog.Builder(context);
//		builder.setTitle(R.string.title_delete_peer);
//		String msgFormat = context.getResources().getString(R.string.msg_delete_peer);
//		String msg = String.format(msgFormat, peer.getName());
//		builder.setMessage(msg);
		builder.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface arg0, int arg1) {
				// do something when the OK button is clicked
				if (mListener != null)
					mListener.onDeletePeer(peer);

				peer.clear();
				set(id, null);
			}
		});
		builder.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface arg0, int arg1) {
				  // do something when the Cancel button is clicked
			}
		});
		AlertDialog alert = builder.create();
		alert.show();
		Log.i("ipsec-tools", "After show");
    }
    

	
    public void edit(Context context, final PeerID id) {
    	Peer peer = mPeers.get(id.intValue());
       	if (!peer.canEdit()) {
    		AlertDialog.Builder builder = new AlertDialog.Builder(context);
    		builder.setIcon(android.R.drawable.ic_dialog_alert);
    		builder.setTitle(peer.getName());
//    		builder.setMessage(R.string.msg_disconnect_first);
    		builder.setPositiveButton(android.R.string.ok, null);
    		AlertDialog alert = builder.create();
    		alert.show();
    		return;
    	}

        Intent settingsActivity = new Intent(context,
                PeerPreferences.class);
        settingsActivity.putExtra(PeerPreferences.EXTRA_ID, id.intValue());
        context.startActivity(settingsActivity);
    }

    public void dumpIsakmpSA() {
    	Message msg = mHandler.obtainMessage(HANDLER_DUMP_ISAKMP_SA);
    	msg.sendToTarget();
    }
    
    public void connect(final PeerID id) {
    	if (mBoundService == null)
    		return;
    	
    	Peer peer = get(id);
    	InetAddress addr = peer.getRemoteAddr();
    	if (addr == null)
    		throw new NullPointerException();
    	Log.i("ipsec-tools", "connectPeer " + addr);
    	peer.onConnect();

    	Message msg = mHandler.obtainMessage(HANDLER_VPN_CONNECT);
    	msg.obj = addr.getHostAddress();
    	msg.sendToTarget();
    }

    // TODO add return value
    public void enableAndConnect(PeerID id)
    {
        Message msg = mHandler.obtainMessage(HANDLER_ENABLE_AND_CONNECT);
        msg.obj = id;
        msg.sendToTarget();
    }
    
    
   protected void doEnableAndConnect(PeerID id)
   {
       try {	
           Peer peer = get(id);
            if (!peer.isEnabled()) {
    			Log.i("ipsec-tools", "Enable " + id);
    			peer.setEnabled(true);
    			doUpdateConfig(id, ConfigManager.Action.ADD);
    		}
    		else
    		    Log.i("ipsec-tools", "Already enabled " + id);
    		connect(id);
    	} catch (IOException e) {
    		// TODO display error
    	}
    }

    
    public void disconnect(Peer peer) {
    	if (mBoundService == null) {
    		Log.i("ipsec-tools", "No service");
    		return;
    	}
    	
    	InetAddress addr = peer.getRemoteAddr();
    	if (addr == null)
    		throw new NullPointerException();
    	Log.i("ipsec-tools", "disconnectPeer " + addr);
    	peer.onDisconnect();
    	Message msg = mHandler.obtainMessage(HANDLER_VPN_DISCONNECT);
    	msg.obj = addr.getHostAddress();
    	msg.sendToTarget();
    }
    
    public void disconnectAndDisable(final PeerID id) {
        Message msg = mHandler.obtainMessage(HANDLER_DISCONNECT_AND_DISABLE);
        msg.obj = id;
        msg.sendToTarget();
    }
    
    private void doDisconnectAndDisable(final PeerID id) {
    	Peer peer = get(id);
    	deleteSPD(peer);
    	disconnect(peer);
	Log.i("ipsec-tools", "Disable " + id);
	peer.setEnabled(false);
    	try {
    		// TODO Remove at disconnect
    		doUpdateConfig(id, ConfigManager.Action.DELETE);
    	} catch (IOException e) {
    		// TODO handle error
    	}
    }
        
    public void toggle(final PeerID id) {
    	Peer peer = get(id);
    	Boolean isRacoonRunning = mBoundService.isRacoonRunning();
    	Log.i("ipsec-tools", "togglePeer " + id + " " + peer);
    	if (isRacoonRunning && peer.canDisconnect()) {
    		disconnectAndDisable(id);
	} else if (isRacoonRunning && peer.canConnect()) {
    		enableAndConnect(id);
	}
    }

    /**
     * Racoon destroyed. Notify all peers on phase1 down.
     */
    public void onDestroy() {
    	Iterator<Peer> iter = iterator();
    	
    	while (iter.hasNext()) {
    		Peer peer = iter.next();
    		if (peer == null)
    			continue;
    		peer.onPhase1Down();
    	}
    }

    // TODO add return value
    public void updateConfig(PeerID id, ConfigManager.Action action)
    {
        Bundle data = new Bundle();
        Message msg = mHandler.obtainMessage(HANDLER_UPDATE_CONFIG);
        data.putSerializable(HANDLER_KEY_ACTION, action);
        msg.obj = id;
        msg.setData(data);
        msg.sendToTarget();
    }
    
    
	public void doUpdateConfig(PeerID id, ConfigManager.Action action) throws IOException
	{
		mConfigManager.build(this, false);
		Peer peer = get(id);
		Log.i("ipsec-tools", "updateConfig peer " + id);
	
		File binDir = mContext.getDir("bin", Context.MODE_PRIVATE);
		FileWriter setKeyOs = new FileWriter(new File(binDir, ConfigManager.SETKEY_CONFIG));
		Writer pskOs = null;
		if (peer != null) {
			mConfigManager.buildPeerConfig(action, peer, setKeyOs, pskOs);
		}
		setKeyOs.close();
		if (mBoundService != null)
			mBoundService.runSetKey();
		// if (peer.isEnabled()) {
		// 	peer.setStatus(Peer.STATUS_DISCONNECTED);
		// } else {
		// 	peer.setStatus(Peer.STATUS_DISABLED);
		// }
		if (mBoundService != null)
			mBoundService.reloadConf();
	}
	
	public void addSPD(Peer peer) {
		try {
			mConfigManager.buildAddSPD(peer);
		} catch (IOException e) {
			// TODO handle error
		}
		File binDir = mContext.getDir("bin", Context.MODE_PRIVATE);
		NativeCommand.system(new File(binDir, NativeService.SETKEY_EXEC_NAME).getAbsolutePath() +
				" -FP");
	}

	public void deleteSPD(Peer peer) {
		try {
			mConfigManager.buildDeleteSPD(peer);
		} catch (IOException e) {
			// TODO handle error
		}
		File binDir = mContext.getDir("bin", Context.MODE_PRIVATE);
		NativeCommand.system(new File(binDir, NativeService.SETKEY_EXEC_NAME).getAbsolutePath() +
				" -FP");
	}
	
	public void disableAll() {
	    Iterator <Peer> i = mPeers.iterator();
	    
	    while (i.hasNext()) {
	        Peer peer = i.next();
	        if ( peer != null )
	            peer.setEnabled(false);
	    }
	}
}
