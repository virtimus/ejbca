/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package com.primekey.ejbca.egov.il.publisher;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * 
 * $Id$
 *
 */

public class BlobWriter {
	
	private ByteArrayOutputStream baos = new ByteArrayOutputStream ();
	
	BlobWriter putString (String string) throws IOException {
		return putArray (string.getBytes("UTF-8"));
	}
	
	BlobWriter putArray (byte[] array) throws IOException {
		if (array == null) {
			return putShort (0);
		}
		putShort (array.length);
		baos.write(array);
		return this;
	}
	
	BlobWriter putShort (int value) {
		baos.write ((byte)(value >>> 8));
		baos.write ((byte)value);
		return this;
	}
	
	BlobWriter putInt (int value) {
		putShort (value >>> 16);
		putShort (value);
		return this;
	}

	BlobWriter putLong (long value) {
		putInt ((int)(value >>> 32));
		putInt ((int)value);
		return this;
	}
	
	byte[] getTotal () {
		return baos.toByteArray();
	}

}
