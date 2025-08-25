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
import javacardx.apdu.ExtendedLength;

/**
 * Applet class
 * 
 * Copyright 2025 Sentry Enterprises
 */
public class BioVerify extends Applet implements ExtendedLength {
	/**
	 * Properties
	 */
	
    // Secure Channel Object
    private SecureChannel o_MySecureChannel;
    
    // Release=1 or Debug Mode=0
    public static byte AppletRelease = 1;		//1-Release 0-Debug
    
    // Stores super secret private data
    private byte[] superSecretPrivateData = null;
    
    private byte[] secureDataSmall = null;
    
    private byte[] unsecureDataSmall = null;
    
    // Size of the data stored in superSecretPrivateData
    private short superSecretPrivateDataLength = 0;
    
    private short secureDataSmallLength = 0;
    
    private short unsecureDataSmallLength = 0;
    
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
		short sLength = 0, outLength;
        short inLength = (short) ((short) (buf[ISO7816.OFFSET_LC] & 0xff) + (short) 5);
        
        short recvLen = apdu.setIncomingAndReceive();
        
		// handle secure channel (CLA = 0x84)
        byte CLA = buf[ISO7816.OFFSET_CLA];

		switch (buf[ISO7816.OFFSET_INS]) {
        //-----------------------------------------------------------------------------------------------------
        //Internal Authenticate
        case CommandIns.INT_AUTH:
        {
            o_MySecureChannel = GPSystem.getSecureChannel();
            outLength = o_MySecureChannel.processSecurity(apdu);
            apdu.setOutgoingAndSend(apdu.getOffsetCdata(), outLength);
            return;
        }
 
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
            return;
        }
        
        //-----------------------------------------------------------------------------------------------------
        // Set Data Secure Command
        case CommandIns.SET_DATA_SECURE:
        {
        	handleSetDataSecure(apdu, recvLen);
        	return;
        }
        
        //-----------------------------------------------------------------------------------------------------
        // Get Data Secure Command
        case CommandIns.GET_DATA_SECURE:
        {
        	handleGetDataSecure(apdu);
        	return;
        }
        
        //-----------------------------------------------------------------------------------------------------
        // Get Data Command
        case CommandIns.SET_DATA:
        {
            handleSetData(apdu, recvLen);	
            return;
        }
        
        //-----------------------------------------------------------------------------------------------------
        // Get Data Command
        case CommandIns.GET_DATA:
        {                
        	handleGetData(apdu);        	
            return;
        }
        
        default: ;
		}
		
		// throw an exception for unsupported APDU commands
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);		
    }
    
    
  //-----------------------------------------------------------------------------------------------------
    private boolean AppletSecurityCheck(byte cla , byte ins, short p1p2)
    {
        if ((AppletRelease == 0x00) || (ins == CommandIns.INT_AUTH) || (ins == CommandIns.SELECT) || ((ins == CommandIns.GET_DATA) && p1p2 == (short) 0x5FC1) || (cla == (byte) 0x84))
            return true;
        return false;
    }
    
    private void CVM_init() {
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

    private void handleSetDataSecure(APDU apdu, short recvLen)
    {
        byte[] buffer = apdu.getBuffer();
        
        byte verificationResult = validateFingerprint(buffer);
                
        // indicate if the CVM applet was blocked or unavailable
        if (verificationResult == Constants.Bio.BIO_CVM_BLOCKED)
        {
        	buffer[0] = Constants.Bio.BIO_CVM_BLOCKED;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        if (verificationResult == Constants.Bio.BIO_CVM_UNAVAILABLE)
        {
        	buffer[0] = Constants.Bio.BIO_CVM_UNAVAILABLE;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        // if the fingerprint was not verified, indicate such
        if (verificationResult != Constants.Bio.BIO_FINGERPRINT_VERIFIED)
        {
        	buffer[0] = verificationResult;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        // Retrieve the 1-byte Tag
        short tag = buffer[ISO7816.OFFSET_P2];
		short dataLen = 0;
		short dataOffset = 0;
        
      	switch (tag)
      	{
      		case Data_Tag_Secure.SECURE_DATA_HUGE:        
      			/*
      			 * NOTE: Both the secure and unsecure huge data storage commands write to the same data store!
      			 */
      			
      			dataLen = apdu.getIncomingLength();
      			dataOffset = apdu.getOffsetCdata();

      			if (dataLen > Constants.Lengths.STORED_DATA_HUGE_MAX_LENGTH) {
      			   	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      			}
      			
      	        if(superSecretPrivateData == null)
      	        {
      	        	superSecretPrivateData = new byte[Constants.Lengths.STORED_DATA_HUGE_MAX_LENGTH];
      	        }
      	        
      			Util.arrayCopyNonAtomic(buffer, dataOffset, superSecretPrivateData, (short)0, recvLen);

      			short totalRead = recvLen;
      			while (totalRead < dataLen) {
      				recvLen = apdu.receiveBytes((short)0);
      				Util.arrayCopyNonAtomic(buffer, (short)0, superSecretPrivateData, totalRead, recvLen);
      				totalRead += recvLen;
      			}

      			superSecretPrivateDataLength = totalRead;
      			Util.setShort(buffer, (short) 0, (short) superSecretPrivateDataLength);
      			apdu.setOutgoingAndSend((short) 0, (short) 2);
      			break;
      			
      		case Data_Tag_Secure.SECURE_DATA_SMALL:
      			dataLen = apdu.getIncomingLength();
      			dataOffset = apdu.getOffsetCdata();

      			if (dataLen > Constants.Lengths.STORED_DATA_SMALL_MAX_LENGTH) {
      			   	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      			}
      			
      	        if(secureDataSmall == null)
      	        {
      	        	secureDataSmall = new byte[Constants.Lengths.STORED_DATA_SMALL_MAX_LENGTH];
      	        }
      	        
      			Util.arrayCopyNonAtomic(buffer, dataOffset, secureDataSmall, (short)0, dataLen);
      			
      			secureDataSmallLength = dataLen;
      			Util.setShort(buffer, (short) 0, (short) secureDataSmallLength);
      			apdu.setOutgoingAndSend((short) 0, (short) 2);
      			break;
      			
      		default:
      			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      	}
    }
    
    /**
     *  Set Data Handler
     *  This function is in charge of handling the information asked from the ICC if
     *  the Security Level and the LifeCycle of the Applet allow it.
     *
     * @param _ba_apdu_buffer Current APDU Buffer
     * @param _s_offset APDU Data Offset
     * @param _s_length APDU Data Length
     * @return Output length to be sent through APDU response
     * @throws
     *
     */
    private void handleSetData(APDU apdu, short recvLen)
    {
        byte[] buffer = apdu.getBuffer();

        // Retrieve the 2-byte Tag
        short tag = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
		short dataLen = 0;
		short dataOffset = 0;
        
      	switch (tag)
      	{
      		case Data_Tag.APPLET_VERSION:
      			ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      			break;
      			
      		case Data_Tag.STORED_DATA_SECURE:        
      			dataLen = apdu.getIncomingLength();
      			dataOffset = apdu.getOffsetCdata();

      			if (dataLen > Constants.Lengths.STORED_DATA_HUGE_MAX_LENGTH) {
      			   	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      			}
      			
      	        if(superSecretPrivateData == null)
      	        {
      	        	superSecretPrivateData = new byte[Constants.Lengths.STORED_DATA_HUGE_MAX_LENGTH];
      	        }
      	        
      			Util.arrayCopyNonAtomic(buffer, dataOffset, superSecretPrivateData, (short)0, recvLen);

      			short totalRead = recvLen;
      			while (totalRead < dataLen) {
      				recvLen = apdu.receiveBytes((short)0);
      				Util.arrayCopyNonAtomic(buffer, (short)0, superSecretPrivateData, totalRead, recvLen);
      				totalRead += recvLen;
      			}

      			superSecretPrivateDataLength = totalRead;
      			Util.setShort(buffer, (short) 0, (short) superSecretPrivateDataLength);
      			apdu.setOutgoingAndSend((short) 0, (short) 2);
      			break;
      			
      		case Data_Tag.UNSECURE_DATA_SMALL:
      			dataLen = apdu.getIncomingLength();
      			dataOffset = apdu.getOffsetCdata();

      			if (dataLen > Constants.Lengths.STORED_DATA_SMALL_MAX_LENGTH) {
      			   	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
      			}
      			
      	        if(unsecureDataSmall == null)
      	        {
      	        	unsecureDataSmall = new byte[Constants.Lengths.STORED_DATA_SMALL_MAX_LENGTH];
      	        }
      	        
      			Util.arrayCopyNonAtomic(buffer, dataOffset, unsecureDataSmall, (short)0, dataLen);
      			
      			unsecureDataSmallLength = dataLen;
      			Util.setShort(buffer, (short) 0, (short) unsecureDataSmallLength);
      			apdu.setOutgoingAndSend((short) 0, (short) 2);
      			break;
      			
      		default:
      			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      	}
    }

    //*************************************************************************************************
    
    private void handleGetDataSecure(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
        
        byte verificationResult = validateFingerprint(buffer);
                
        // indicate if the CVM applet was blocked or unavailable
        if (verificationResult == Constants.Bio.BIO_CVM_BLOCKED)
        {
        	buffer[0] = Constants.Bio.BIO_CVM_BLOCKED;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        if (verificationResult == Constants.Bio.BIO_CVM_UNAVAILABLE)
        {
        	buffer[0] = Constants.Bio.BIO_CVM_UNAVAILABLE;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        // if the fingerprint was not verified, indicate such
        if (verificationResult != Constants.Bio.BIO_FINGERPRINT_VERIFIED)
        {
        	buffer[0] = verificationResult;
        	apdu.setOutgoingAndSend((short) 0, (short) 1);
        	return;
        }
        
        // Retrieve the 1-byte Tag
        short tag = buffer[ISO7816.OFFSET_P2];
		short toSend = 0;
		short maxLen = 0;
        
      	switch (tag)
      	{
		case Data_Tag_Secure.SECURE_DATA_HUGE:
			
			toSend = superSecretPrivateDataLength;
			
			if (toSend == 0) {
				apdu.setOutgoingAndSend((short)0, (short)0);
				return;
			}
			
			maxLen = apdu.setOutgoing();
			
			if (superSecretPrivateDataLength < maxLen) {
				maxLen = superSecretPrivateDataLength;
			}

			apdu.setOutgoingLength(maxLen);
			
			short outgoingOffset = 0;
			short amountSent = maxLen;
			
			while (toSend > 0) {
				if (toSend < maxLen) {
					amountSent = toSend;
				}
				
				apdu.sendBytesLong(superSecretPrivateData, outgoingOffset, (short) maxLen);

				toSend -= amountSent;
				outgoingOffset += amountSent;    						
			}

			break;
      			
      		case Data_Tag_Secure.SECURE_DATA_SMALL:
    			toSend = secureDataSmallLength;
    			
    			if (toSend == 0) {
    				apdu.setOutgoingAndSend((short)0, (short)0);
    				return;
    			}

    			maxLen = apdu.setOutgoing();
    			
    			if (secureDataSmallLength < maxLen) {
    				maxLen = secureDataSmallLength;
    			}

    			apdu.setOutgoingLength(maxLen);
    			apdu.sendBytesLong(secureDataSmall, (short) 0, (short) maxLen);

      			break;
      			
      		default:
      			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      	}
    }
    
    //*************************************************************************************************
    
    private void handleGetData(APDU apdu) 				
    {
    	byte[] buffer = apdu.getBuffer();
    	
    	// Retrieve the 2-byte Tag
    	short tag = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
		short toSend = 0;
		short maxLen = 0;

    	switch (tag)
    	{
    		case Data_Tag.APPLET_VERSION:
    			Util.setShort(buffer, (short) 0, Hardcoded.APPLET_VERSION);
    			apdu.setOutgoingAndSend((short) 0, (short) 2);
    		break;
    		    		
    		case Data_Tag.UNSECURE_DATA_SMALL:
    			
    			toSend = unsecureDataSmallLength;
    			
    			if (toSend == 0) {
    				apdu.setOutgoingAndSend((short)0, (short)0);
    				return;
    			}

    			maxLen = apdu.setOutgoing();
    			
    			if (unsecureDataSmallLength < maxLen) {
    				maxLen = unsecureDataSmallLength;
    			}

    			apdu.setOutgoingLength(maxLen);
    			apdu.sendBytesLong(unsecureDataSmall, (short) 0, (short) maxLen);
    		break;    			
    		
    		default:
    			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    		break;
    	}
    }
    
    private byte validateFingerprint(byte[] ba_apdu_buffer)
    {
        byte cvmIsAvailable = 0;
        byte cvmIsBlocked = 1;
        byte verificationResult = 0;
        
        CVM_init(); // initialize CVM
        
        if (cvm != null)
        {
        	cvmIsAvailable = 1;
        	// see if we're blocked first
        	if (!cvm.isBlocked())
        	{
        		cvmIsBlocked = 0;
        		
        		// activate the CVM
        		short res = cvm.verify(null, (short) 0, (byte) 0, CVMMode.ACTIVATE);
        		if (res == (short) 0xA502)
        		{
        			if (ba_apdu_buffer[ISO7816.OFFSET_P1] == 0x01)
        			{
        				// get the bio result
        				res = cvm.verify(null, (short) 0, (byte) 0, CVMMode.BIO_VERIFY);
        				cvm.resetState();
        				
        				//check the first byte of the result
        				byte result = (byte) ((short) (res >> (byte) 8) & ((short) 0xff));
        				verificationResult = result;
                    
        				// note: the second byte returned is the try counter value
        			}
        		}
        	}
        }
        
        if (cvmIsBlocked == 1) 
        {
        	return Constants.Bio.BIO_CVM_BLOCKED;
        }
        
        if (cvmIsAvailable == 0) 
        {
        	return Constants.Bio.BIO_CVM_UNAVAILABLE;
        }
        
        return verificationResult;
    }
    
    private short verifyFingerprint(byte[] apduBuffer, short s_offset)
    {
        byte verificationResult = validateFingerprint(apduBuffer);
        
        apduBuffer[s_offset] = (byte) 0x5F;
        s_offset++;
        apduBuffer[s_offset] = (byte) 0x3C; 
        s_offset++;
        apduBuffer[s_offset] = (byte) 0x02;
        s_offset++;
        
        byte cvmIsAvailable = 1;
        byte cvmIsBlocked = 0;
        
        if (verificationResult == Constants.Bio.BIO_CVM_BLOCKED)
        {
        	cvmIsBlocked = 1;
        }
        
        if (verificationResult == Constants.Bio.BIO_CVM_UNAVAILABLE)
        {
        	cvmIsAvailable = 0;
        	verificationResult = 0;
        }
        
        apduBuffer[s_offset] = (byte) cvmIsAvailable;
        s_offset++;
        apduBuffer[s_offset] = (byte) verificationResult;
        s_offset++;
        apduBuffer[s_offset] = (byte) cvmIsBlocked;
        s_offset++;
        
        return s_offset;
    }
    
  //*************************************************************************************************
}
