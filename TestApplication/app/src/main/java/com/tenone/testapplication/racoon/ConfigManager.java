package com.tenone.testapplication.racoon;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.net.InetAddress;
import java.util.AbstractCollection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


import android.content.Context;
import android.os.Environment;
import android.os.Process;

import com.tenone.testapplication.peer.Peer;

/**
 * Racoon and setkey config files builder.
 * 
 * @author mikael
 *
 */
public class ConfigManager {
	
	public static final String PATTERN = "\\$\\{([a-zA-Z0-9_]+)\\}";
	public static final String CONFIG_POSTFIX = ".conf";
	public static final String PEERS_CONFIG = "peers.conf";
	public static final String SETKEY_CONFIG = "setkey.conf";
	public static final String PSK_CONFIG = "psk.txt";
	public static final String RACOON_HEAD = "racoon.head";
	public static final String SETKEY_HEAD = "setkey.head";
	public static final String PIDFILE = "racoon.pid";
	
	public static final String BINDIR = "bin";
	public static final String CERTDIR = "certs";

	public enum Action {NONE, ADD, DELETE, UPDATE};
	
	// Variables usable in config files
	private static final String VAR_BINDIR = "bindir";
	private static final String VAR_CERTDIR = "certdir";
	private static final String VAR_EXTDIR = "extdir";
	private static final String VAR_REMOTE_ADDR = "remote_addr";
	private static final String VAR_LOCAL_ADDR = "local_addr";
	private static final String VAR_UID = "uid";
	private static final String VAR_GID = "gid";
	private static final String VAR_NAME = "name";
	private static final String VAR_ACTION = "action";
	private static final String VAR_CERT = "cert";
	private static final String VAR_KEY = "key";
	

	private Pattern mPat;
	private Map<String,String> mVariables;
	private Context mContext;
	private NativeCommand mNative;
	private File mBinDir;
	private File mCertDir;
	private CertManager mCertManager;
	
	public ConfigManager(Context context, NativeCommand nativeCmd, CertManager certManager) {
		mBinDir = context.getDir(BINDIR, Context.MODE_PRIVATE);
		mCertDir = context.getDir(CERTDIR, Context.MODE_PRIVATE);
		mVariables = new HashMap<String,String>();
		mVariables.put(VAR_BINDIR, mBinDir.getAbsolutePath());
		mVariables.put(VAR_CERTDIR, mCertDir.getAbsolutePath());
		mVariables.put(VAR_EXTDIR, Environment.getExternalStorageDirectory().getAbsolutePath());
		mVariables.put(VAR_UID, "" + Process.myUid());
		mVariables.put(VAR_GID, "" + Process.myUid());
		mPat = Pattern.compile(PATTERN);
		mContext = context;
		mNative = nativeCmd;
		mCertManager = certManager;
	}
	
	protected File getPeerConfigFile(Peer peer) {
		return new File(mBinDir, peer.getPeerID().toString() + CONFIG_POSTFIX);
	}
	
	/**
	 * Build racoon config for one peer and setkey portion
	 * @param peer
	 * @param racoonOs
	 * @param setkeyUpOs
	 * @param setkeyDownOs
	 * @throws IOException
	 */
	private void writePeerConfig(Action action, Peer peer, Writer racoonOs,
				     Writer setkeyOs, Writer pskOs) throws IOException {
	    String certPrefix = CertManager.CERT_PREFIX + peer.getPeerID().intValue();
	    String certAlias = peer.getCertAlias();
		InetAddress addr = peer.getRemoteAddr();
		if (addr != null)
			mVariables.put(VAR_REMOTE_ADDR, addr.getHostAddress());
		mVariables.put(VAR_LOCAL_ADDR, peer.getLocalAddr().getHostAddress());
		mVariables.put(VAR_NAME, peer.getName());
		if (certAlias == null || certAlias == "") {
		    mVariables.put(VAR_CERT, peer.getCert());
		    mVariables.put(VAR_KEY, peer.getKey());
		} else {
		    mVariables.put(VAR_CERT, certPrefix + CertManager.CERT_POSTFIX);
		    mVariables.put(VAR_KEY, certPrefix + CertManager.KEY_POSTFIX);
		}
		mVariables.put(VAR_ACTION, actionToString(action));
		File tmpl = peer.getTemplateFile();
		if (tmpl == null)
			return;
		PolicyFile policy = new PolicyFile(tmpl);
		if (racoonOs != null)
			substitute(policy.getRacoonConfStream(), racoonOs);
		if (action != Action.NONE && setkeyOs != null)
			substitute(policy.getSetkeyConfStream(), setkeyOs);
		if (pskOs != null && addr != null) {
			pskOs.write("# Peer " + peer.getName() + "\n");
			pskOs.write(mVariables.get(VAR_REMOTE_ADDR) + " " + peer.getPsk() + "\n");
		}
		mCertManager.writeCert(mCertDir, certPrefix, certAlias);
	}
	
	private static String actionToString(Action action) {
		switch (action) {
		case NONE:
			return "none";
		case ADD:
			return "add";
		case DELETE:
			return "delete";
		case UPDATE:
			return "update";
		default:
			throw new RuntimeException("Unknown action: " + action);
		}
	}

	/**
	 * Build racoon config for one peer and setkey portion
	 * @param action
	 * @param peer
	 * @param setkeyOs
	 * @return racoon config file
	 * @throws IOException
	 */
	public File buildPeerConfig(Action action, Peer peer, Writer setkeyOs, Writer pskOs) throws IOException {
 		mVariables.put(VAR_LOCAL_ADDR, peer.getLocalAddr().getHostAddress());
		
 		File racoonFile = getPeerConfigFile(peer);
		FileWriter racoonOs = new FileWriter(racoonFile);
		
		writePeerConfig(action, peer, racoonOs, setkeyOs, pskOs);
		racoonOs.close();
		return racoonFile;
	}
	
	/**
	 * 
	 * @param peers
	 * @param updateAllPeers
	 * @throws IOException
	 */
	public void build(AbstractCollection<Peer> peers,
			boolean addAllPeers) throws IOException {
		Iterator<Peer> iter = peers.iterator();
		File pskFile = new File(mBinDir, PSK_CONFIG);
		Writer out = null;
		Writer setkeyOut = null;
		Writer pskOut = null;
		Reader inHead = null;
		Reader setkeyHead = null;

		try {
			out = new FileWriter(new File(mBinDir, PEERS_CONFIG));
			inHead = new InputStreamReader(mContext.getAssets().open(RACOON_HEAD));
			substitute(inHead, out);
			
			setkeyOut = new FileWriter(new File(mBinDir, SETKEY_CONFIG));
			setkeyHead = new InputStreamReader(mContext.getAssets().open(SETKEY_HEAD));
			substitute(setkeyHead, setkeyOut);

			pskFile.delete();
			pskOut = new FileWriter(pskFile);
			
			while (iter.hasNext()) {
				Peer peer = iter.next();
				if (peer == null)
					continue;
				if (!peer.isEnabled())
					continue;
				mVariables.remove(VAR_REMOTE_ADDR);
				mVariables.remove(VAR_LOCAL_ADDR);
				mVariables.remove(VAR_NAME);
				try {
					File output;
					if (addAllPeers)
						output = buildPeerConfig(Action.ADD, peer, setkeyOut, pskOut);
					else {
						writePeerConfig(Action.NONE, peer, null, setkeyOut, pskOut);
						output = getPeerConfigFile(peer);
					}
					out.write("include \"" + output.getAbsolutePath() + "\";\n");
				} catch (IOException e){
				}
			}

			mNative.chown(pskFile, "root", "root");
		} finally {
			if (out != null)
				out.close();
			if (setkeyOut != null)
				setkeyOut.close();
			if (pskOut != null)
				pskOut.close();
			if (inHead != null)
				inHead.close();
			if (setkeyHead != null)
				setkeyHead.close();
		}
		// build peers.conf
	}
	
	public void buildSPDAction(Peer peer, Action action) throws IOException {
		Writer setkeyOut = null;
		Reader setkeyHead = null;

		setkeyOut = new FileWriter(new File(mBinDir, SETKEY_CONFIG));
		setkeyHead = new InputStreamReader(mContext.getAssets().open(SETKEY_HEAD));
		substitute(setkeyHead, setkeyOut);

		mVariables.remove(VAR_REMOTE_ADDR);
		mVariables.remove(VAR_LOCAL_ADDR);
		mVariables.remove(VAR_NAME);

		writePeerConfig(action, peer, null, setkeyOut, null);

		if (setkeyOut != null)
			setkeyOut.close();
		if (setkeyHead != null)
			setkeyHead.close();
	}

	public void buildAddSPD(Peer peer) throws IOException {
		buildSPDAction(peer, Action.ADD);
	}

	public void buildDeleteSPD(Peer peer) throws IOException {
		buildSPDAction(peer, Action.DELETE);
	}

	public void addVariable(String key, String value) {
		mVariables.put(key, value);
	}

	private String substituteLine(String line) {
		StringBuffer buf = new StringBuffer();
		Matcher m = mPat.matcher(line);

		while (m.find()) {
			String var = m.group(1);
			String value;
			
			if (mVariables.containsKey(var)) {
				value = mVariables.get(var);
			} else {
				value = "";
			}

			m.appendReplacement(buf, value);
		}
		m.appendTail(buf);
		buf.append('\n');

		return buf.toString();
	}
	
	private void substitute(Reader input, Writer os) {
		BufferedReader is = new BufferedReader(input, 8192);
			
		try {
			String line;
			while ( (line = is.readLine()) != null) {
				os.write(substituteLine(line));
			}				
		} catch (FileNotFoundException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
		}
	}

	private void substitute(java.io.InputStream input, Writer os) {
		substitute(new InputStreamReader(input), os);
	}

	private void substitute(File input, Writer os) {
		Reader is = null;
		try {
			is = new FileReader(input);
			substitute(is, os);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				if (is != null)
					is.close();
			} catch (IOException e) {
			}
		}
	}
}
