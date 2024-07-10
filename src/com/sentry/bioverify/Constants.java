package com.sentry.bioverify;

/**
 * General Class containing all required constants.
 */
public class Constants {
	/**
	 * Note: Get data, set data, and related tags are the same as the Wallet applet.
	 */

	/**
	 * Status of the biometric verification.
	 */
    public interface Bio
    {
	    public static final byte BIO_NOT_ATTEMPTED = (byte) 0x00;
	    public static final byte BIO_FAILED = (byte) 0x5A;
	    public static final byte BIO_SUCCESSFUL = (byte) 0xA5;
    }
    
    /**
     * All supported APDU Command Ins bytes.
     */
    public interface CommandIns
    {
        /** Select Ins */
        public static final byte SELECT = (byte) 0xA4;
        
        /** CVM Status */
        public static final byte CVM_STATUS = (byte) 0xB6;
        
        /** Get Data */
        public static final byte GET_DATA = (byte) 0xCA;
        
        /** Set Data */
        public static final byte SET_DATA = (byte) 0xDA;
        
        /** Internal Authenticate */
        public static final byte INT_AUTH = (byte) 0x88;    
    }
    
    /**
     * CVM Modes.
     */
    public interface CVMMode
    {
    	/** Activate the CVM */
    	public static final byte ACTIVATE = (byte) 0x06;
    	
    	/** Perform a biometric match */
    	public static final byte BIO_VERIFY = (byte) 0x05;
    }
    
    /** Hardcoded Values */
    public static interface Hardcoded
    {
        /** Applet version */
        public static final short APPLET_VERSION = (short) 0x0102; 	// ver 1.2
    }
    
    /**
     * Get/Set Data Constants
     */
    public interface Data_Tag
    {
        // Applet Version
        public static final short APPLET_VERSION = (short) 0x5FC1;
        
        // Super Secret Data
        public static final short STORED_DATA = (short) 0x5FC2;
    }
    
    /** Maximum Lengths */
    public static interface Lengths
    {
        // Maximum length of stored data
        public static final short STORED_DATA_MAX_LENGTH = (short) 2048;		// 2k of data
    }
    
    /**
     * Secure Boolean Constants
     */
    public interface Secure_Bool
    {
        /** Secure Boolean True defined as a byte */
        public static final byte TRUE = (byte) 0x5A;

        /** Secure Boolean False defined as a byte */
        public static final byte FALSE = (byte) 0xA5;
    }
}
