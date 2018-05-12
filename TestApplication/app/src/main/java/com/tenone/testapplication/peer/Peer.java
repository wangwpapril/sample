package com.tenone.testapplication.peer;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;


import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.os.Handler;
import android.preference.Preference;
import android.util.Log;

import com.tenone.testapplication.racoon.Utils;

/**
 * Peer controller object
 * 
 * @author mikael
 *
 */
public class Peer implements OnSharedPreferenceChangeListener {
	/** Peer is down but enabled. */
	public static final int STATUS_DISCONNECTED = 0;
	/** Peer is up. */
	public static final int STATUS_CONNECTED = 1;
	/** Peer is up, and disconnection has been initiated.  */
	public static final int STATUS_DISCONNECTING = 2;
	/** Peer is down, and connection has been initiated. */
	public static final int STATUS_CONNECTING = 3;
	/** Peer is down, and disabled. */
	public static final int STATUS_DISABLED = 4;
	/** Peer is faulty. Unused */
	public static final int STATUS_BUSY = 5;
	public static final int STATUS_NUM = 6;
	
	public static final int[] STATUS_SUMMARY = {
//		R.string.connect_peer,
//		R.string.disconnect_peer,
//		R.string.connect_peer,
//		R.string.disconnect_peer,
//		R.string.connect_peer,
		-1,
	};
	
	/* 
	 * Icons
	 * 
	 * 0 - presence_invisible	grey dot
     * 1 - presence_online		green dot
     * 2 - presence_away		blue clock
     * 3 - presence_away		blue clock
     * 4 - presence_offline		grey cross
     * 5 - presence_busy		red dash
	 */

	public static final int[] STATUS_ICON = {
		
	};
	
	private PeerID mID;
	private StatePreference mPref;
	private SharedPreferences mShared;
	private Handler mGuiHandler;
	private int mStatus;

	public Peer(Handler guiHandler, Context context, PeerID id, StatePreference pref) {
	    mGuiHandler = guiHandler;
		mID = id;
		mPref = pref;
		mShared = context.getSharedPreferences(
					PeerPreferences.getSharedPreferencesName(context, id),
    				Activity.MODE_PRIVATE);
		mStatus = -1;
		setStatus(isEnabled() ? STATUS_DISCONNECTED : STATUS_DISABLED);
	}
	
	public void clear() {
		Editor editor = mShared.edit();
		editor.clear();
		editor.commit();
	}

	public PeerID getPeerID() {
		return mID;
	}
	
	public boolean isEnabled() {
		return mShared.getBoolean(PeerPreferences.ENABLED_PREFERENCE, true);
	}
	
	public void setEnabled(boolean enabled) {
		Editor editor = mShared.edit();
		editor.putBoolean(PeerPreferences.ENABLED_PREFERENCE, enabled);
		editor.commit();
	}

	public boolean canConnect() {
		return mStatus == STATUS_DISCONNECTED || mStatus == STATUS_DISABLED;
	}

	public boolean canDisconnect() {
		return mStatus == STATUS_CONNECTED || mStatus == STATUS_DISCONNECTING || mStatus == STATUS_CONNECTING;
	}
	
	public boolean isConnected() {
		return mStatus == STATUS_CONNECTED
			|| mStatus == STATUS_DISCONNECTING;
	}
	
	public boolean isDisconnected() {
		return mStatus == STATUS_DISCONNECTED
			|| mStatus == STATUS_CONNECTING
			|| mStatus == STATUS_DISABLED;
	}

	public boolean canEdit() {
		return mStatus == STATUS_DISCONNECTED
			|| mStatus == STATUS_DISABLED;
	}
	
	public Preference getPreference() {
		return mPref;
	}
	
	public void setPreference(StatePreference pref) {
		mPref = pref;
	}
	
	public String getName() {
		return mShared.getString(PeerPreferences.NAME_PREFERENCE, "");
	}
	
    public String getCertAlias() {
        return mShared.getString(PeerPreferences.CERT_ALIAS_PREFERENCE, "");
    }

	public String getCert() {
		return mShared.getString(PeerPreferences.CERT_PREFERENCE, "");
	}

	public String getKey() {
		return mShared.getString(PeerPreferences.KEY_PREFERENCE, "");
	}

	public InetAddress getRemoteAddr() {
		String host = mShared.getString(PeerPreferences.REMOTE_ADDR_PREFERENCE, null);
		String ip = mShared.getString(PeerPreferences.REMOTE_ADDR_IP_PREFERENCE, null);
		try {
			InetAddress ipAddr = InetAddress.getByName(ip);
			InetAddress addr = InetAddress.getByAddress(host, ipAddr.getAddress());
			Log.i("ipsec-tools", "getRemoteAddr " + addr);
			return addr;
		} catch (UnknownHostException e) {
			return null;
		}
	}
	
	public InetAddress getLocalAddr() {
		return Utils.getLocalAddress(getRemoteAddr());
	}
	
	public File getTemplateFile() {
		String addr = mShared.getString(PeerPreferences.TEMPLATE_PREFERENCE, null);
		Log.i("ipsec-tools", "getTemplateFile " + addr);
		if (addr == null)
			return null;
		return new File(addr);
	}
	
	public String getDns1() {
		return mShared.getString(PeerPreferences.DNS1_PREFERENCE, null);		
	}
	
	public String getDns2() {
		return mShared.getString(PeerPreferences.DNS2_PREFERENCE, null);		
	}

	public String getPsk() {
		return mShared.getString(PeerPreferences.PSK_PREFERENCE, null);
	}

	public int getStatus() {
		return mStatus;
	}

	public void setStatus(final int status) {
	    mGuiHandler.post(new Runnable() {
	        public void run() { 
	            if (mStatus != status && status < STATUS_NUM) {
	                mStatus = status;
	                if (mPref != null) {
	                    mPref.setIconLevel(mStatus);
	                    mPref.setSummary(STATUS_SUMMARY[mStatus]);
	                }
	                Log.i("ipsec-tools", "setStatus " + getName() + " "+ mStatus);
	            }
	        }
	    });
	}

	/** Called when Phase 1 goes up */
	public void onPhase1Up() {
		setStatus(STATUS_CONNECTED);
	}

	/** Called when Phase 1 goes down */
	public void onPhase1Down() {
		setStatus(isEnabled() ? STATUS_DISCONNECTED : STATUS_DISABLED);
	}
	
	/** Called when initiating disconnect */
	public void onConnect() {
    	setStatus(STATUS_CONNECTING);
	}
	
	/** Called when initiating disconnect */
	public void onDisconnect() {
    	setStatus(STATUS_DISCONNECTING);
	}

	public void onPreferenceActivityResume() {
		mShared.registerOnSharedPreferenceChangeListener(this);
		updatePreferenceName();
	}
	
	public void onPreferenceActivityPause() {
		mShared.unregisterOnSharedPreferenceChangeListener(this);
	}
	
	@Override
	public void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String key) {
		//Called when a shared preference is changed, added, or removed.
		Log.i("ipsec-tools", "peer pref " + key + " changed");
		if (key.equals(PeerPreferences.NAME_PREFERENCE)) {
			updatePreferenceName();
		}
	}
	
	protected void updatePreferenceName() {
	    mGuiHandler.post(new Runnable() {
	        public void run() { 
	            getPreference().setTitle(getName());
	        }
	    });
	}
	
	public String toString() {
		return "Peer[" + getName() + " " + getRemoteAddr() + "]";
	}
}
