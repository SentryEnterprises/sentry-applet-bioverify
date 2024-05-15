package com.sentry.bioverify;

/**
 * General Class containing all required constants.
 */
public class Constants {

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
}
