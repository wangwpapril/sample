package com.tenone.testapplication.peer;


public interface OnPeerChangeListener {
	public abstract void onDeletePeer(Peer peer);
	public abstract void onCreatePeer(Peer peer);
}
