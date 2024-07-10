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
 * @author John Ayres
 */

//public class BioVerify extends Applet implements ExtendedLength {
//    private byte[] superSecretPrivateData = null;
//    
//    private short superSecretPrivateDataLength = 0;
//    
//    public static void install(byte[] bArray, short bOffset, byte bLength) {
//        new BioVerify(bArray, bOffset, bLength);
//    }
//
//    protected BioVerify(byte[] bArray, short bOffset, byte bLength) {
//        register(bArray,((short)(bOffset + 1)), bArray[bOffset]);
//    }
//
//    @Override
//    public void process(APDU apdu) {
//		if (selectingApplet()) {
//			return;
//		} 
//        
//		byte[] buf = apdu.getBuffer();
//
//		switch (buf[ISO7816.OFFSET_INS]) {
//
//        //-----------------------------------------------------------------------------------------------------
//        // Get Data Command
//        case (byte)0xCA:
//        {
//            handleSetData(apdu);
//            return;
//        }
//        
//        default: ;
//		}
//		
//		// throw an exception for unsupported APDU commands
//		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
//    }
//    
//   
//    private void handleSetData(APDU apdu)
//    {
//        if(superSecretPrivateData == null)
//        {
//        	superSecretPrivateData = new byte[1024];
//        }
//        
//        byte[] buffer = apdu.getBuffer();
//        short len = apdu.setIncomingAndReceive();
//        short offset = apdu.getOffsetCdata();
//
//        Util.setShort(buffer, (short)0, len);
//        Util.setShort(buffer, (short)2, offset);
//        apdu.setOutgoingAndSend((short) 0, (short) 4);
//        
////        byte zero = buffer[0];
////        byte one = buffer[1];
////        byte two = buffer[2];
////        byte three = buffer[3];
////        byte four = buffer[4];
////        byte five = buffer[5];
////        byte six = buffer[6];
////        
//////        Util.setShort(buffer, (short)0, len);
//////        apdu.setOutgoingAndSend((short) 0, (short) 2);
////        
////        
////        buffer[0] = zero;
////        buffer[1] = one;
////        buffer[2] = two;
////        buffer[3] = three;
////        buffer[4] = four;
////        buffer[5] = five;
////        buffer[6] = six;
////		apdu.setOutgoingAndSend((short) 0, (short) 7);
//    }
//}

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
    
    // Size of the data stored in superSecretPrivateData
    private short superSecretPrivateDataLength = 0;
    
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
    //	if (apdu.isISOInterindustryCLA()) {
			if (selectingApplet()) {
				return;
			} 
//			else {
//				ISOException.throwIt (ISO7816.SW_CLA_NOT_SUPPORTED);
//		    }
    //	}

		byte[] buf = apdu.getBuffer();
		short sLength = 0, outLength;
        short inLength = (short) ((short) (buf[ISO7816.OFFSET_LC] & 0xff) + (short) 5);
		//short inLength = apdu.getIncomingLength();
		
        // Not allowed to work without SCP when the application is in release mode (AppletRelease=1)
 //       if (!AppletSecurityCheck(buf[ISO7816.OFFSET_CLA], buf[ISO7816.OFFSET_INS], Util.getShort(buf, ISO7816.OFFSET_P1)))
 //           ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        
        short recvLen = apdu.setIncomingAndReceive();
        
		// handle secure channel (CLA = 0x84)
        byte CLA = buf[ISO7816.OFFSET_CLA];
//        if ((CLA & 0x04) == 0x04)
//        {
//            o_MySecureChannel = GPSystem.getSecureChannel();
//            o_MySecureChannel.unwrap(buf, (short) 0, inLength);
//        }

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
        // Get Data Command
        case CommandIns.SET_DATA:
        {
            handleSetData(apdu, recvLen);	//    buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]);
//            sLength = apdu.getOffsetCdata();
//        	
//            if ((CLA & 0x04) == 0x04)		// secure channel
//            {
//                buf[(short) ((short) 0 + sLength)] = (byte) 0x90;
//                sLength++;
//                buf[(short) ((short) 1 + sLength)] = (byte) 0x00;
//                sLength++;
//
//                sLength = o_MySecureChannel.wrap(buf, (short) 0, (short) (sLength));
//                apdu.setOutgoingAndSend((short) 0, (short) (sLength));
//            }
//            else
//            {
//            	apdu.setOutgoingAndSend((short) 0, (short) (sLength));
//            }
            
            return;
        }
        /**
            accountMustBeSelected(Secure_Bool.TRUE);
            // Check if Application is Blocked
            if (o_currentlySelAcc
                    .isAppletBlocked() == Constants.Secure_Bool.TRUE)
            {
                ISOException.throwIt(Status_Word.APPLICATION_BLOCKED);
            }
            _sLength = handleAccountSetData(_baBuf, ISO7816.OFFSET_CDATA,
                    _baBuf[ISO7816.OFFSET_LC]);
            _baBuf[ISO7816.OFFSET_LC] = (byte) _sLength;
            */
        
        //-----------------------------------------------------------------------------------------------------
        // Get Data Command
        case CommandIns.GET_DATA:
        {
        	/**
            //Check if account is selected
            if (s_isAccountSelected == Secure_Bool.TRUE)
            {
                // Check if Application is Blocked
                if (o_currentlySelAcc
                        .isAppletBlocked() == Constants.Secure_Bool.TRUE)
                {
                    ISOException.throwIt(Status_Word.APPLICATION_BLOCKED);
                }
                _sLength = handleAccountGetData(_baBuf,
                        ISO7816.OFFSET_CDATA, _baBuf[ISO7816.OFFSET_LC]);
                _baBuf[ISO7816.OFFSET_LC] = (byte) _sLength;
                if ((CLA & 0x04) == 0x04)
                {
                    _baBuf[(short) (ISO7816.OFFSET_P1 + _sLength
                            + 3)] = (byte) 0x90;
                    _sLength++;
                    _baBuf[(short) (ISO7816.OFFSET_P1 + _sLength
                            + 3)] = (byte) 0x00;
                    _sLength++;

                    _sLength = o_MySecureChannel.wrap(_baBuf,
                            ISO7816.OFFSET_P1, (short) (_sLength + 3));
                    _oApdu.setOutgoingAndSend(ISO7816.OFFSET_P1,
                            (short) (_sLength));
                }
                else
                {
                    _oApdu.setOutgoingAndSend(ISO7816.OFFSET_P1,
                            (short) (_sLength + 3));
                }
            }
            else
            {
            */
                
        	handleGetData(apdu);        	
        	
        	//byte _bNbrBytesLe = 0x00;
            //    sLength = handleGetData(buf, ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]);
            //    buf[ISO7816.OFFSET_LC] = (byte) sLength;
              
        	
        	
        	
                /**
                if (_sLength > 0x7F)
                {
                    _bNbrBytesLe = (byte) 0x01;

                    if (_sLength > (short) 0x00FF)
                    {
                        _bNbrBytesLe = (byte) 0x02;
                    }
                    //Put specefic length byte on apdu buffer
                    _baBuf[ISO7816.OFFSET_LC] = (byte) ((byte) 0x80
                            + _bNbrBytesLe);
                    //Shift buffer to enter the number of additionnal bytes for length
                    Util.arrayCopyNonAtomic(_baBuf, ISO7816.OFFSET_CDATA,
                            _baBuf,
                            (short) (ISO7816.OFFSET_CDATA + _bNbrBytesLe),
                            _sLength);
                    //put the additional sub bytes for length in the buffer
                    if (_bNbrBytesLe == 0x01)
                    {
                        _baBuf[ISO7816.OFFSET_CDATA] = (byte) (_sLength
                                & 0x00FF);
                    }
                    else
                    {
                        Util.setShort(_baBuf, ISO7816.OFFSET_CDATA,
                                _sLength);
                    }
                }
                else
                {
                    _baBuf[ISO7816.OFFSET_LC] = (byte) _sLength;
                }
                */
        	
                        	
//                if ((CLA & 0x04) == 0x04)
//                {
//                    buf[(short) (ISO7816.OFFSET_P1 + sLength + 3 + _bNbrBytesLe)] = (byte) 0x90;
//                    sLength++;
//                    buf[(short) (ISO7816.OFFSET_P1 + sLength + 3 + _bNbrBytesLe)] = (byte) 0x00;
//                    sLength++;
//                    sLength = o_MySecureChannel.wrap(buf, ISO7816.OFFSET_P1, (short) (sLength + 3 + _bNbrBytesLe));	//add 9000
//                    apdu.setOutgoingAndSend(ISO7816.OFFSET_P1, (short) (sLength));
//                }
//                else
//                {
//                    apdu.setOutgoingAndSend(ISO7816.OFFSET_P1, (short) (sLength + 3 + _bNbrBytesLe));
//                }
            //}
                return;
        }
        
        default: ;
		}
		
		// throw an exception for unsupported APDU commands
//		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		
		byte INS = buf[ISO7816.OFFSET_INS];
		byte isEqual = (byte) 0;
		if (INS == CommandIns.INT_AUTH)
			isEqual = 1;
		buf[ISO7816.OFFSET_P1] = (byte) INS;
		buf[ISO7816.OFFSET_P2] = CommandIns.INT_AUTH;
		buf[ISO7816.OFFSET_LC] = isEqual;
		apdu.setOutgoingAndSend((short) 0, (short) 5);
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
        if(superSecretPrivateData == null)
        {
        	superSecretPrivateData = new byte[Constants.Lengths.STORED_DATA_MAX_LENGTH];
        }
        
        byte[] buffer = apdu.getBuffer();

        
        short dataLen = apdu.getIncomingLength();
        short dataOffset = apdu.getOffsetCdata();
        
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
        
        
        
//        superSecretPrivateDataLength = apdu.getIncomingLength();
//                        
//        short total = recvLen;
//         
//   //     if (superSecretPrivateDataLength >= Constants.Lengths.STORED_DATA_MAX_LENGTH) {
//   //     	ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
//   //     }
//     
//       // short recvLen = apdu.setIncomingAndReceive();
//        //short dataOffset = apdu.getOffsetCdata();
//        short initialBufferLength = (short)buffer.length;
//        short sizeInCurrentBuffer = (short) (buffer.length - apdu.getOffsetCdata());
//        
//        if (apdu.getIncomingLength() <= sizeInCurrentBuffer) {
//        	Util.arrayCopy(buffer, apdu.getOffsetCdata(), superSecretPrivateData, (short) 0, apdu.getIncomingLength());
//        } else {
//        	Util.arrayCopy(buffer, apdu.getOffsetCdata(), superSecretPrivateData, (short) 0, sizeInCurrentBuffer);
//        }
//     
//        short privateDataOffset = sizeInCurrentBuffer;
//        
//        while (apdu.getCurrentState() != APDU.STATE_FULL_INCOMING) {
//        	recvLen = apdu.receiveBytes((short) 0);
//        	privateDataOffset = Util.arrayCopy(buffer, (short) 0, superSecretPrivateData, privateDataOffset, (short) recvLen);
//        	total += recvLen;
//        }
//        
//        superSecretPrivateDataLength = total;
//        
//        Util.setShort(buffer, (short) 0, (short) superSecretPrivateDataLength);
//        apdu.setOutgoingAndSend((short) 0, (short) 2);
        
        

        

        
        
        
        /**
        while (recvLen > 0) {
        	Util.arrayCopyNonAtomic(buffer[dataOffset], , buffer, recvLen, dataOffset)
            ...
            [process data in buffer[dataOffset]...]
                    ...
                    recvLen = apdu.receiveBytes(dataOffset);
        }
        */
        
    //    if (_ba_apdu_buffer[ISO7816.OFFSET_LC] > Lengths.STORED_DATA_MAX_LENGTH)
    //    {
    //        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    //    }
        
        /**
        Util.arrayCopyNonAtomic(_ba_apdu_buffer, _s_offset, superSecretPrivateData, (short) 0, (short) _ba_apdu_buffer[ISO7816.OFFSET_LC]);
        superSecretPrivateDataLength = (byte)_ba_apdu_buffer[ISO7816.OFFSET_LC];
        
        return Constants.Secure_Bool.TRUE;

    default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        return Constants.Secure_Bool.FALSE;
        */


    	
    	
    	/**
        // Temporary Tag Storage
        short _sTag = 0;
        
        // Length is not null as we are setting a data
        if (_s_length == 0)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        // Check if Tag is a 1-byte Tag or a 2-bytes Tag
        if ((_ba_apdu_buffer[ISO7816.OFFSET_P1] & 0x1F) == 0x1F)
        {
            // Retrieve the 2-byte Tag
            _sTag = Util.makeShort(_ba_apdu_buffer[ISO7816.OFFSET_P1], _ba_apdu_buffer[ISO7816.OFFSET_P2]);
        }
        else
        {
            // Retrieve the 1-byte Tag
            _sTag = _ba_apdu_buffer[ISO7816.OFFSET_P1];
        }
        
        switch (_sTag)
        {
            // store super secret data
            case Data_Tag.STORED_DATA:
            	
                // make sure data length is not greater than the maximum length
                
                if(superSecretPrivateData == null)
                {
                	superSecretPrivateData = new byte[255];//Constants.Lengths.STORED_DATA_MAX_LENGTH];
                	//superSecretPrivateData = new byte[5];
                }
                
            //    if (_ba_apdu_buffer[ISO7816.OFFSET_LC] > Lengths.STORED_DATA_MAX_LENGTH)
            //    {
            //        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            //    }
                
                Util.arrayCopyNonAtomic(_ba_apdu_buffer, _s_offset, superSecretPrivateData, (short) 0, (short) _ba_apdu_buffer[ISO7816.OFFSET_LC]);
                superSecretPrivateDataLength = (byte)_ba_apdu_buffer[ISO7816.OFFSET_LC];
                
                return Constants.Secure_Bool.TRUE;

            default:
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                return Constants.Secure_Bool.FALSE;
        }
        */
    }

    //*************************************************************************************************
    
    private void handleGetData(APDU apdu) 				//byte[] _ba_apdu_buffer , short _s_offset , short _s_length) ISO7816.OFFSET_CDATA, buf[ISO7816.OFFSET_LC]
    {
    	byte[] buffer = apdu.getBuffer();
    	
    //	short LE = apdu.setOutgoing();
    	
//		buffer[ISO7816.OFFSET_P1] = (byte) 0x11;
//		buffer[ISO7816.OFFSET_P2] = (byte) 0x22;
//		buffer[ISO7816.OFFSET_LC] = (byte) 0x33;
//		apdu.setOutgoingAndSend((short) 0, (short) 5);
//		return;

    
      // Temporary Tag Storage
      short tag = 0;
   // Retrieve the 2-byte Tag
      tag = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
      
    	switch (tag)
    	{
    		case Data_Tag.APPLET_VERSION:

//    			Util.setShort(buffer, apdu.getOffsetCdata(), Hardcoded.APPLET_VERSION);
//    			buffer[ISO7816.OFFSET_LC] = (byte) 2;
//    			apdu.setOutgoingAndSend((short) 0, (short) 7);

    			Util.setShort(buffer, (short) 0, (short) 2);
    			Util.setShort(buffer, (short) 2, Hardcoded.APPLET_VERSION);
    			apdu.setOutgoingAndSend((short) 0, (short) 4);
    			
//                if ((buffer[ISO7816.OFFSET_CLA]) == 0x04)
//                {
//                    buffer[(short) (apdu.getOffsetCdata() + 2)] = (byte) 0x90;
//                    buffer[(short) (apdu.getOffsetCdata() + 3)] = (byte) 0x00;
//                    short sLength = o_MySecureChannel.wrap(buffer, apdu.getOffsetCdata(), (short) 4);	//add 9000
//                    apdu.setOutgoingAndSend(apdu.getOffsetCdata(), (short) (sLength));
//                }
//                else
//                {
//                    apdu.setOutgoingAndSend((short) 0, (short) 4);
//                }

    		break;
    		
    		case Data_Tag.STORED_DATA:
    			
    			short toSend = superSecretPrivateDataLength;
    			short maxLen = apdu.setOutgoing();
    			
    			//maxLen = (short) 256;
    			
    			if (superSecretPrivateDataLength < maxLen) {
    				maxLen = superSecretPrivateDataLength;
    				apdu.setOutgoingLength(maxLen);
    			}

    			apdu.setOutgoingLength( (short)superSecretPrivateDataLength );
    			
    			short outgoingOffset = 0;
    			short amountSent = maxLen;
    			
    			while (toSend > 0) {
    				if (toSend < maxLen) {
    					amountSent = toSend;
    				}
    				
    				//apdu.sendBytesLong(superSecretPrivateData, outgoingOffset, amountSent);
    				
      			  //Util.setShort(buffer, (short) 0, amountSent);
      			  //Util.setShort(buffer, (short) 2, (short) toSend);
      			  //apdu.sendBytes ( (short)0 , (short)4 );
      			  
    				apdu.sendBytesLong(superSecretPrivateData, outgoingOffset, (short) maxLen);

    				toSend -= amountSent;
    				outgoingOffset += amountSent;    						
    			}
    			
    			
    			
    			
//    			short le = apdu.setOutgoing();
//    			  //if (le < (short)2) ISOException.throwIt( ISO7816.SW_WRONG_LENGTH );
//    			  apdu.setOutgoingLength( (short)4 );
//    			 
//    			  // build response data in apdu.buffer[ 0.. outCount-1 ];
//    			  //buffer[0] = (byte)1; buffer[1] = (byte)2; buffer[2] = (byte)3; buffer[3] = (byte)4;
//    			  Util.setShort(buffer, (short) 0, le);
//    			  Util.setShort(buffer, (short) 2, (short) superSecretPrivateDataLength);
//    			  apdu.sendBytes ( (short)0 , (short)4 );
    			  
    			  
//    			short LE = apdu.setOutgoing();
//    			
//    			Util.setShort(buffer, (short) 0, LE);
//    			Util.setShort(buffer, (short) 2, (short) superSecretPrivateDataLength);
//    			//apdu.setOutgoingAndSend((short) 0, (short) 4);
//    			apdu.sendBytes((short)0, (short) 4);
    			
////    			buffer[ISO7816.OFFSET_P1] = (byte) 0x11;
////    			buffer[ISO7816.OFFSET_P2] = (byte) 0x22;
////    			buffer[ISO7816.OFFSET_LC] = (byte) 0x33;
////    			apdu.setOutgoingAndSend((short) 0, (short) 5);
//  
//    			//Util.setShort(buffer, (short) 0, toSend);
//    			//apdu.setOutgoingAndSend((short) 0, (short) 2);
//    			
////    			toSend += 2;
//    			apdu.setOutgoing();
//    			apdu.setOutgoingLength(superSecretPrivateDataLength);
////    			
////    			Util.setShort(buffer, (short) 0, (short) superSecretPrivateDataLength);
////    			apdu.sendBytes((short) 0, (short) 2);
//    			apdu.sendBytesLong(superSecretPrivateData, (short) 0, superSecretPrivateDataLength);

    		break;
    		
    		default:
    			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    		break;
    	}
    	
    	
//        // Temporary Tag Storage
//        short _sTag = 0;
//        
//        // Current Offset for matching case
//   //     short _sCurrentOffset = 0;
//        
//        // Local Return Length
//        short _sReturnLength = 0;
//        
//        // Check if Tag is a 1-byte Tag or a 2-bytes Tag
//        if ((_ba_apdu_buffer[ISO7816.OFFSET_P1] & 0x1F) == 0x1F)
//        {
//            // Retrieve the 2-byte Tag
//            _sTag = Util.makeShort(_ba_apdu_buffer[ISO7816.OFFSET_P1], _ba_apdu_buffer[ISO7816.OFFSET_P2]);
//        }
//        else
//        {
//            // Retrieve the 1-byte Tag
//            _sTag = _ba_apdu_buffer[ISO7816.OFFSET_P1];
//        }
//        
//        switch (_sTag)
//        {
//            case Data_Tag.APPLET_VERSION:
//                Util.setShort(_ba_apdu_buffer, _s_offset, Hardcoded.APPLET_VERSION);
//                _sReturnLength = (byte) 2;
//            break;
//            
//            case Data_Tag.STORED_DATA:
////            	_ba_apdu_buffer[_s_offset] = (byte)0x11;
////            	_ba_apdu_buffer[(short) (_s_offset + 1)] = (byte)0x22;
////            	_ba_apdu_buffer[(short) (_s_offset + 2)] = (byte)0x33;
////            	_sReturnLength = (byte) 3;
//
//            	//_ba_apdu_buffer[_s_offset] = superSecretPrivateDataLength;
//            	
//            	if (superSecretPrivateDataLength > 0)
//            	{
//            		Util.arrayCopyNonAtomic(superSecretPrivateData, (short)0, _ba_apdu_buffer, _s_offset, superSecretPrivateDataLength);
//            	}
//            	_sReturnLength = superSecretPrivateDataLength;
//            	
//
//            break;
//            
//            default:
//                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//            break;
//        }
//        
//        return _sReturnLength;
    }
    
  //*************************************************************************************************
    
    /**
     *  Applet CVM function
     *  this function processes the state of the biometrics and requests a fingerprint
     *
     * @param _ba_apdu_buffer Current APDU Buffer
     * @param _s_offset APDU Data Offset
     * @param _s_length APDU Data Length
     * @throws
     *
     */
    private short verifyFingerprint(byte[] ba_apdu_buffer, short s_offset)
    {
        byte cvmIsAvailable = 0;
        byte cvmIsBlocked = 1;
        byte verificationResult = 0;		// 0x7D indicates a match was never performed (i.e. an error occurred); 0 indicates CVM is blocked
        
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
        			// TODO: Why do we need the P1 parameter = 1?
        			if (ba_apdu_buffer[ISO7816.OFFSET_P1] == 0x01) // P1==1
        			{
        				// get the bio result
        				res = cvm.verify(null, (short) 0, (byte) 0, CVMMode.BIO_VERIFY);
        				cvm.resetState();
        				
        				//check the first byte of the result
        				byte result = (byte) ((short) (res >> (byte) 8) & ((short) 0xff));
        				verificationResult = result;
                    
        				// note: the second byte returned is the try counter value
                    
                    //check the result
               //     if (result == Bio.BIO_FAILED)
              //      {
               //     	fingerprintVerified = 0x10;			// fingerprint did not match
             //       } 
              //      else if (result == Bio.BIO_SUCCESSFUL)
              //      {
             //       	fingerprintVerified = 0x11;			// fingerprint is verified
                    	
                    	// TODO: Not sure if we need this
//                        if (updateWSSMState(WSSM.PIN_AUTH) != Constants.Secure_Bool.TRUE)
//                        {
//                            Kill();
//                        }
                  //  }
        			}
        		}
        	}
        }
        
        // TODO: This return data may change, unsure if all of this is necessary
      //  //Util.setShort(ba_apdu_buffer, s_offset, (short) 0x5F3C); // Get_Data_A.TAG_CVM);
        ba_apdu_buffer[s_offset] = (byte) 0x5F;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) 0x3C; 
        s_offset++;
        
        ba_apdu_buffer[s_offset] = (byte) 0x02;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) cvmIsAvailable;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) verificationResult;
        s_offset++;
        ba_apdu_buffer[s_offset] = (byte) cvmIsBlocked;
        s_offset++;


        // TODO: Unsure if this is needed
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
