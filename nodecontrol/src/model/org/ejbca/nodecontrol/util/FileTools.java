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
 
package org.ejbca.nodecontrol.util;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.jboss.seam.util.Base64;


/**
 * Tools to handle some common file operations.
 *
 * @version $Id: FileTools.java,v 1.1 2006/01/17 20:32:19 anatom Exp $
 */
public class FileTools {

    /**
     * Creates new FileTools
     */
    public FileTools() {
    }

    /**
     * Reads binary bytes from a PEM-file. The PEM-file may contain other stuff, the first item
     * between beginKey and endKey is read. Example: <code>-----BEGIN CERTIFICATE REQUEST-----
     * base64 encoded PKCS10 certification request -----END CERTIFICATE REQUEST----- </code>
     *
     * @param inbuf input buffer containing PEM-formatted stuff.
     * @param beginKey begin line of PEM message
     * @param endKey end line of PEM message
     *
     * @return byte[] containing binary Base64 decoded bytes.
     *
     * @throws IOException if the PEM file does not contain the right keys.
     */
    public static byte[] getBytesFromPEM(byte[] inbuf, String beginKey, String endKey)
        throws IOException {
        ByteArrayInputStream instream = new ByteArrayInputStream(inbuf);
        BufferedReader bufRdr = new BufferedReader(new InputStreamReader(instream));
        CharArrayWriter caw = new CharArrayWriter();
        String temp;

        try {
            while (((temp = bufRdr.readLine()) != null) && !temp.equals(beginKey)) {
                continue;
            }

            if (temp == null) {
                throw new IOException("Error in input buffer, missing " + beginKey + " boundary");
            }

            while (((temp = bufRdr.readLine()) != null) && !temp.equals(endKey)) {
            	caw.append(temp);
            }

            if (temp == null) {
                throw new IOException("Error in input buffer, missing " + endKey + " boundary");
            }

            byte[] bytes = Base64.decode(caw.toString());        	
            return bytes;
        } finally {
        	bufRdr.close();
        	caw.close();
        }
    } // getBytesfromPEM

    /**
     * Helpfunction to read a file to a byte array.
     *
     * @param file filename of file.
     *
     * @return byte[] containing the contents of the file.
     *
     * @throws IOException if the file does not exist or cannot be read.
     */
    public static byte[] readFiletoBuffer(String file)
        throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        InputStream in = new FileInputStream(file);
        int len = 0;
        byte[] buf = new byte[1024];

        while ((len = in.read(buf)) > 0) {
            os.write(buf, 0, len);
        }

        in.close();
        os.close();

        return os.toByteArray();
    } // readFiletoBuffer
} // FileTools
