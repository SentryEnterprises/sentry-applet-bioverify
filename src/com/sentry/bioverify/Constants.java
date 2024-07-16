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
	    public static final byte BIO_CVM_UNAVAILABLE = (byte) 0x0A;
	    public static final byte BIO_CVM_BLOCKED = (byte) 0x0B;
	    public static final byte BIO_FINGERPRINT_VERIFIED = (byte) 0xA5;
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
        
        /** Get Data Secure */
        public static final byte GET_DATA_SECURE = (byte) 0xCB;
        
        /** Set Data */
        public static final byte SET_DATA = (byte) 0xDA;
        
        /** Set Data Secure */
        public static final byte SET_DATA_SECURE = (byte) 0xDB;
        
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
        public static final short APPLET_VERSION = (short) 0x0103; 	// ver 1.3
    }
    
    /**
     * Get/Set Data Constants
     */
    public interface Data_Tag
    {
        // Applet Version
        public static final short APPLET_VERSION = (short) 0x5FC1;
        
        public static final short STORED_DATA_SECURE = (short) 0x5FC2;
                
        public static final short UNSECURE_DATA_SMALL = (short) 0x5FB0;
    }
    
    public interface Data_Tag_Secure
    {
    	// Super Secret Data
        public static final byte SECURE_DATA_HUGE = (byte) 0xC2;
        
    	public static final byte SECURE_DATA_SMALL = (byte) 0xD0;
    }
    
    /** Maximum Lengths */
    public static interface Lengths
    {
        // Maximum length of stored data
        public static final short STORED_DATA_HUGE_MAX_LENGTH = (short) 2048;			// 2k of data
        
        public static final short STORED_DATA_SMALL_MAX_LENGTH = (short) 255;			// 255 bytes of data
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
