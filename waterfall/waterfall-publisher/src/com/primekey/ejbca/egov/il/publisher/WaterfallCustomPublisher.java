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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

/**
 * This class is used for publishing to user defined script or command.
 * 
 * @version $Id$
 */
public class WaterfallCustomPublisher implements ICustomPublisher {
    private static Logger log = Logger.getLogger(WaterfallCustomPublisher.class);
    private static final InternalResources intres = InternalResources.getInstance();

    public static final String SIGNING_CA_PROPERTY_NAME = "signingCA";
    public static final String ANONYMIZE_CERTIFICATES_PROPERTY_NAME = "anonymizeCertificates";

    public static final String WORKING_DIRECTORY_PROPERTY_NAME = "workingDirectory";
    public static final String FAIL_ON_ERROR_CODE_PROPERTY_NAME = "failOnErrorCode";
    public static final String FAIL_ON_STANDARD_ERROR_PROPERTY_NAME = "failOnStandardError";
    public static final String CRL_EXTERNAL_COMMAND_PROPERTY_NAME = "crl.application";
    public static final String CERT_EXTERNAL_COMMAND_PROPERTY_NAME = "cert.application";

    public static final String CRL_SCP_DESTINATION_PROPERTY_NAME = "crl.scp.destination";
    public static final String CERT_SCP_DESTINATION_PROPERTY_NAME = "cert.scp.destination";
    public static final String SCP_PRIVATE_KEY_PROPERTY_NAME = "scp.privatekey";
    public static final String SCP_KNOWN_HOSTS_PROPERTY_NAME = "scp.knownhosts";

    private static final String OCSP_SIGNER_EKU = "1.3.6.1.5.5.7.3.9";
    
    private String signingCA = null;
    private boolean anonymizeCertificates;

    private String workingDirectory = null;
    private boolean failOnErrorCode = true;
    private boolean failOnStandardError = true;
    private String crlExternalCommandFileName = null;
    private String certExternalCommandFileName = null;

    private String crlSCPDestination = null;
    private String certSCPDestination = null;
    private String SCPPrivateKey = null;
    private String SCPKnownHosts = null;


    private transient SignSessionRemote signSession;

    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public WaterfallCustomPublisher() {
    }
    
    /**
     * Load used properties.
     * 
     * @param properties
     *            The properties to load.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    @Override
    public void init(Properties properties) {
        if (log.isTraceEnabled()) {
            log.trace(">init");
        }
        signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        signingCA = getProperty(properties, SIGNING_CA_PROPERTY_NAME);
        anonymizeCertificates = getBooleanProperty(properties, ANONYMIZE_CERTIFICATES_PROPERTY_NAME);

        // Find out if we are using EXTERNAL or INTERNAL mode
        if (properties.containsKey(WORKING_DIRECTORY_PROPERTY_NAME)) {
            workingDirectory = getProperty(properties, WORKING_DIRECTORY_PROPERTY_NAME);
            failOnErrorCode = getBooleanProperty(properties, FAIL_ON_ERROR_CODE_PROPERTY_NAME);
            failOnStandardError = getBooleanProperty(properties, FAIL_ON_STANDARD_ERROR_PROPERTY_NAME);
            crlExternalCommandFileName = getProperty(properties, CRL_EXTERNAL_COMMAND_PROPERTY_NAME);
            certExternalCommandFileName = getProperty(properties, CERT_EXTERNAL_COMMAND_PROPERTY_NAME);
        } else {
            crlSCPDestination = getProperty(properties, CRL_SCP_DESTINATION_PROPERTY_NAME);
            certSCPDestination = getProperty(properties, CERT_SCP_DESTINATION_PROPERTY_NAME);
            SCPPrivateKey = getProperty(properties, SCP_PRIVATE_KEY_PROPERTY_NAME);
            SCPKnownHosts = getProperty(properties, SCP_KNOWN_HOSTS_PROPERTY_NAME);
        }
    }

    private String getProperty(Properties properties, String propertyName) {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            return "";
        } else {
            return property;
        }
    }

    private boolean getBooleanProperty(Properties properties, String propertyName) {
        String property = getProperty(properties, propertyName);
        if (property.equalsIgnoreCase("true")) {
            return true;
        }
        else {
           return false;
        }
    }

    /**
     * Writes certificate to temporary file and executes an external command
     * with the full pathname of the temporary file as argument. The temporary
     * file is the encoded form of the certificate e.g. X.509 certificates would
     * be encoded as ASN.1 DER. All parameters but incert are ignored.
     * 
     * @param incert
     *            The certificate
     * @param username
     *            The username
     * @param type
     *            The certificate type
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.ejbca.core.model.log.Admin,
     *      java.security.cert.Certificate, java.lang.String, java.lang.String,
     *      int, int)
     */
    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificate, Storing Certificate for user: " + username);
        }
        if ((status == CertificateConstants.CERT_REVOKED) || (status == CertificateConstants.CERT_ACTIVE)) {
            // Don't publish non-active certificates
            try {
                log.debug("WF BEGIN");
                byte[] certBlob = incert.getEncoded();
                X509Certificate x509cert = (X509Certificate) incert;
                String fingerprint = CertTools.getFingerprintAsString(certBlob);
                String issuerDN = CertTools.getIssuerDN(incert);
                String serialNumber = x509cert.getSerialNumber().toString();
                String subjectDN = CertTools.getSubjectDN(incert);
                boolean anon = anonymizeCertificates && type == CertificateConstants.CERTTYPE_ENDENTITY;
                if (anon) {
                    List<String> ekus = x509cert.getExtendedKeyUsage();
                    if (ekus != null)
                        for (String eku : ekus) {
                            if (eku.equals(OCSP_SIGNER_EKU)) {
                                anon = false;
                            }
                        }
                }
                BlobWriter bw = new BlobWriter();
                // Now write the object..
                // MUST be in the same order as read by the reader!
                bw.putString(fingerprint).putString(issuerDN).putString(serialNumber).putString(anon ? "anonymized" : subjectDN)
                        .putArray(anon ? null : certBlob).putInt(type).putInt(status).putLong(revocationDate).putInt(revocationReason)
                        .putLong(lastUpdate).putInt(certificateProfileId).putLong(x509cert.getNotAfter().getTime());
                publishSignedFile(admin, certExternalCommandFileName, certSCPDestination, fingerprint + ".cer", bw.getTotal());
            } catch (GeneralSecurityException e) {
                String msg = e.getMessage();
                log.error(msg);
                throw new PublisherException(msg);
            } catch (IOException e) {
                String msg = e.getMessage();
                log.error(msg);
                throw new PublisherException(msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificate");
        }
        return true;
    }

    /**
     * Writes the CRL to a temporary file and executes an external command with
     * the temporary file as argument. By default, a PublisherException is
     * thrown if the external command returns with an errorlevel or outputs to
     * stderr.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.ejbca.core.model.log.Admin,
     *      byte[], java.lang.String, int)
     */
    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL, Storing CRL");
        }
        String fileName = CertTools.getFingerprintAsString(incrl) + ".crl";
        publishSignedFile(admin, crlExternalCommandFileName, crlSCPDestination, fileName, incrl);
        if (log.isTraceEnabled()) {
            log.trace("<storeCRL");
        }
        return true;
    }

    /**
     * Check if the specified external excutable file(s) exist.
     * 
     * @param admin
     *            Ignored
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
     */
    @Override
    public void testConnection() throws PublisherConnectionException {
        if (log.isTraceEnabled()) {
            log.trace("testConnection, Testing connection");
        }
        // Test if specified commands exist
        if (workingDirectory != null) {
            if (!(new File(crlExternalCommandFileName)).exists()) {
                String msg = intres.getLocalizedMessage("publisher.commandnotfound", crlExternalCommandFileName);
                log.error(msg);
                throw new PublisherConnectionException(msg);
            }
        }
        if (workingDirectory != null) {
            if (!(new File(certExternalCommandFileName)).exists()) {
                String msg = intres.getLocalizedMessage("publisher.commandnotfound", certExternalCommandFileName);
                log.error(msg);
                throw new PublisherConnectionException(msg);
            }
        }
    }

    /**
     * Writes a byte-array to a temporary file and executes the given command
     * with the file as argument. The function will, depending on its
     * parameters, fail if output to standard error from the command was
     * detected or the command returns with an non-zero exit code.
     * 
     * @param externalCommand
     *            The command to run.
     * @param fileExtension
     *            The file extension to use
     * @param bytes
     *            The buffer with content to write to the file.
     * @param failOnCode
     *            Determines if the method should fail on a non-zero exit code.
     * @param failOnOutput
     *            Determines if the method should fail on output to standard
     *            error.
     * @param additionalArguments
     *            Added to the command after the tempfiles name
     * @throws PublisherException
     */
    private void publishSignedFile(AuthenticationToken admin, String externalCommand, String scpDestinationPath, String fileName, byte[] bytes)
            throws PublisherException {
        // Create temporary file
        String tempFileName = workingDirectory == null ? null : workingDirectory + File.separatorChar + fileName;
        String msg = null;
        Exception ex = null;
        try {
            bytes = signSession.signPayload(admin, bytes, signingCA);
            if (workingDirectory != null) {
                writeFile(tempFileName, bytes);
            }
        } catch (CryptoTokenOfflineException e) {
            msg = "CA token is offline";
            ex = e;
        } catch (AuthorizationDeniedException e) {
            msg = "Not authorized to this CA operation";
            ex = e;
        } catch (IOException | SignRequestSignatureException | CADoesntExistsException e) {
            ex = e;
        }
        if (ex != null) {
            if (msg == null) {
                msg = ex.getMessage();
            }
            log.error(msg == null ? "Unknown error" : msg, ex);
            throw new PublisherException(msg);
        }

        // Are we using Internal mode?
        if (workingDirectory == null) {
            try {
                log.debug("WF WRITING:" + fileName);
                performScp(fileName, bytes, scpDestinationPath, SCPPrivateKey, SCPKnownHosts);
                log.debug("WF DONE:" + fileName);
            } catch (Exception e) {
                msg = e.getMessage();
                log.error(msg == null ? "Unknown error" : msg, e);
                throw new PublisherException(msg);
            }
            return;
        }
        // Not Internal => Exec file from properties with the file as an
        // argument
        try {
            String[] cmdarray = new String[2];
            cmdarray[0] = externalCommand;
            cmdarray[1] = tempFileName;
            Process externalProcess = Runtime.getRuntime().exec(cmdarray, null, null);
            BufferedReader stdError = new BufferedReader(new InputStreamReader(externalProcess.getErrorStream()));
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(externalProcess.getInputStream()));
            while (stdInput.readLine() != null) {
            } // Required under win32 to avoid lock
            String stdErrorOutput = null;
            // Check errorcode and the external applications output to stderr
            if (((externalProcess.waitFor() != 0) && failOnErrorCode) || (stdError.ready() && failOnStandardError)) {
                String errTemp = null;
                while (stdError.ready() && (errTemp = stdError.readLine()) != null) {
                    if (stdErrorOutput == null) {
                        stdErrorOutput = errTemp;
                    } else {
                        stdErrorOutput += "\n" + errTemp;
                    }
                }
                msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
                if (stdErrorOutput != null) {
                    msg += " - " + stdErrorOutput + " - " + tempFileName;
                }
                log.error(msg);
                throw new PublisherException(msg);
            }
        } catch (IOException e) {
            msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
            throw new PublisherException(msg);
        } catch (InterruptedException e) {
            msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
            throw new PublisherException(msg);
        }
    }

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    private void writeFile(String filename, byte[] b) throws IOException {
        FileOutputStream fos = new FileOutputStream(new File(filename));
        fos.write(b);
        fos.close();
    }

    

    private void performScp(String sourcefile, byte[] optionalData, String destination, String privateKeyPath, String knownHostsFile)
            throws JSchException, IOException {
        String user = destination.substring(0, destination.indexOf('@'));
        destination = destination.substring(destination.indexOf('@') + 1);
        String host = destination.substring(0, destination.indexOf(':'));
        String rfile = destination.substring(destination.indexOf(':') + 1);
        JSch jsch = new JSch();
        jsch.addIdentity(privateKeyPath);
        jsch.setKnownHosts(knownHostsFile);
        Session session = jsch.getSession(user, host, 22);
        session.connect();
        // exec 'scp -t rfile' remotely
        String command = "scp -p -t " + rfile;
        Channel channel = session.openChannel("exec");
        ((ChannelExec) channel).setCommand(command);
        // get I/O streams for remote scp
        OutputStream out = channel.getOutputStream();
        InputStream in = channel.getInputStream();
        channel.connect();
        checkAck(in);
        // send "C0644 filesize filename", where filename should not include '/'
        long filesize = optionalData == null ? (new File(sourcefile)).length() : optionalData.length;
        command = "C0644 " + filesize + " ";
        if (sourcefile.lastIndexOf('/') > 0) {
            command += sourcefile.substring(sourcefile.lastIndexOf('/') + 1);
        } else {
            command += sourcefile;
        }
        command += "\n";
        out.write(command.getBytes());
        out.flush();
        checkAck(in);

        // send a content of sourcefile
        byte[] buf = new byte[1024];
        if (optionalData == null) {
            FileInputStream fis = new FileInputStream(sourcefile);
            while (true) {
                int len = fis.read(buf, 0, buf.length);
                if (len <= 0)
                    break;
                out.write(buf, 0, len); // out.flush();
            }
            fis.close();
            fis = null;
        } else {
            out.write(optionalData);
        }
        // send '\0'
        buf[0] = 0;
        out.write(buf, 0, 1);
        out.flush();
        checkAck(in);
        out.close();
        channel.disconnect();
        session.disconnect();
    }

    private void checkAck(InputStream in) throws IOException {
        int b = in.read();
        // b may be 0 for success,
        // 1 for error,
        // 2 for fatal error,
        // -1
        if (b <= 0)
            return;
        StringBuffer sb = new StringBuffer();
        int c;
        do {
            c = in.read();
            sb.append((char) c);
        } while (c != '\n');
        throw new IOException("SCP error: " + sb.toString());
    }
}
