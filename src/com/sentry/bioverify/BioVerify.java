/** 
 * Copyright (c) 1998, 2024, Oracle and/or its affiliates. All rights reserved.
 * 
 */

package com.sentry.bioverify;

import org.globalplatform.CVM;
import org.globalplatform.GPSystem;
import org.globalplatform.GlobalService;
import org.globalplatform.SecureChannel;

import com.sentry.bioverify.Constants.*;

import javacard.framework.*;

/**
 * Applet class
 * 
 * @author John Ayres
 */

public class BioVerify extends Applet {
	/**
	 * Properties
	 */
	
    // Secure Channel Object
    private SecureChannel o_MySecureChannel;
    
	CVM cvm;

    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new BioVerify(bArray, bOffset, bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected BioVerify(byte[] bArray, short bOffset, byte bLength) {
        register(bArray,((short)(bOffset + 1)), bArray[bOffset]);
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    @Override
    public void process(APDU apdu) {
		// return if we're just selecting the applet
		if (selectingApplet()) {
			return;
		}

		byte[] buf = apdu.getBuffer();
		short sLength = 0; //, outLength;
        short inLength = (short) ((short) (buf[ISO7816.OFFSET_LC] & 0xff) + (short) 5);
		
        // Not allowed to work without SCP when the application is in release mode (AppletRelease=1)
//        if (!AppletSecurityCheck(_baBuf[ISO7816.OFFSET_CLA], _baBuf[ISO7816.OFFSET_INS]))
//            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
		// handle secure channel (CLA = 0x84(
        byte CLA = buf[ISO7816.OFFSET_CLA];
        if ((CLA & 0x04) == 0x04)
        {
            o_MySecureChannel = GPSystem.getSecureChannel();
            o_MySecureChannel.unwrap(buf, (short) 0, inLength);
        }

		switch (buf[ISO7816.OFFSET_INS]) {
        //-----------------------------------------------------------------------------------------------------
        //Application CVM STATUS
        //**********************
        case CommandIns.CVM_STATUS:
        {
            sLength = verifyFingerprint(buf, (short) 0);
        	
            if ((CLA & 0x04) == 0x04)		// secure channel
            {
                buf[(short) ((short) 0 + sLength)] = (byte) 0x90;
                sLength++;
                buf[(short) ((short) 1 + sLength)] = (byte) 0x00;
                sLength++;

                sLength = o_MySecureChannel.wrap(buf, (short) 0, (short) (sLength));
                apdu.setOutgoingAndSend((short) 0, (short) (sLength));
            }
            else
            {
            	apdu.setOutgoingAndSend((short) 0, (short) (sLength));
            }
        }
        break;
		}
    }
    
    
    
    
    
    public void CVM_init() {
        if (cvm == null)
        {
            //allocate CVM ID
            GlobalService glbl;
            byte cvmID = (byte) 0xF1;
            short serviceID = Util.makeShort(GPSystem.FAMILY_CVM, cvmID);
            
            glbl = null;
            cvm = null;
            
            try {
                glbl = GPSystem.getService(null, serviceID);
            } catch (Exception e) {
            	//TODO: need a better return here
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            
            if (glbl != null) {
                cvm = (CVM) glbl;
            }
        }
    }
    
    
    
    /**********************************************************************************************/
    /**                                      APDU HANDLERS                                       **/
    /**********************************************************************************************/

    //*************************************************************************************************
    /**
     *  Wallet Applet CVM function
     *  this function processes the state of the biometrics and requests a fingerprint
     *
     * @param _ba_apdu_buffer Current APDU Buffer
     * @param _s_offset APDU Data Offset
     * @param _s_length APDU Data Length
     * @throws
     *
     */
    private short verifyFingerprint(byte[] ba_apdu_buffer , short s_offset)
    {
        byte cvmIsAvailable = 0;
        byte fingerprintVerified = 0;
        
        CVM_init(); // initialize CVM
        
        if (cvm != null)
        {
        	cvmIsAvailable = 1;
            short res = cvm.verify(null, (short) 0, (byte) 0, (byte) 0x06);
            if (res == (short) 0xA502)
            {
            	fingerprintVerified += 0x10;			// starts as unverified
                if (ba_apdu_buffer[ISO7816.OFFSET_P1] == 0x01) // P1==1
                {
                    // get the bio result
                    res = cvm.verify(null, (short) 0, (byte) 0, (byte) 0x05);
                    cvm.resetState();
                    
                    //check the first byte of the result
                    byte result = (byte) ((short) (res >> (byte) 8) & ((short) 0xff));
                    
                    //check the status not performed to replace by 00
                    if ((result == Bio.BIO_SUCCESSFUL))
                    {
                    	fingerprintVerified += 1;		// fingerprint is verified
//                        if (updateWSSMState(WSSM.PIN_AUTH) != Constants.Secure_Bool.TRUE)
//                        {
//                            Kill();
//                        }
                    }
                }
            }
        }
        
      //  //Util.setShort(ba_apdu_buffer, s_offset, (short) 0x5F3C); // Get_Data_A.TAG_CVM);
        ba_apdu_buffer[s_offset] = (byte) 0x5F;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) 0x3C;
        s_offset++;
        
        ba_apdu_buffer[s_offset] = (byte) 0x02;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) cvmIsAvailable;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) fingerprintVerified;
        s_offset++;
        
        // Set Tag for Authentication Status as a Sub Tag
//        Util.setShort(ba_apdu_buffer, s_offset, Get_Data_A.TAG_WSSM);
//        s_offset += (short) 2;
//        ba_apdu_buffer[s_offset] = Utility.LENGTH_WALLET_AUTHENTICATION_STATUS;
//        s_offset += (short) 1;
        
        // Set Authentication Status Data
//        ba_apdu_buffer[s_offset] = getWSSM();
//        s_offset += (short) 1;
        return s_offset;
    }
    //*************************************************************************************************

}
