
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.ws.WebFault;


/**
 * This class was generated by the JAX-WS RI.
 * JAX-WS RI 2.2.4-b01
 * Generated source version: 2.2
 * 
 */
@WebFault(name = "CAExistsException", targetNamespace = "http://ws.protocol.core.ejbca.org/")
public class CAExistsException_Exception
    extends Exception
{

    private static final long serialVersionUID = 1L;
    
    /**
     * Java type that goes as soapenv:Fault detail element.
     * 
     */
    private CAExistsException faultInfo;

    /**
     * 
     * @param message
     * @param faultInfo
     */
    public CAExistsException_Exception(String message, CAExistsException faultInfo) {
        super(message);
        this.faultInfo = faultInfo;
    }

    /**
     * 
     * @param message
     * @param faultInfo
     * @param cause
     */
    public CAExistsException_Exception(String message, CAExistsException faultInfo, Throwable cause) {
        super(message, cause);
        this.faultInfo = faultInfo;
    }

    /**
     * 
     * @return
     *     returns fault bean: org.ejbca.core.protocol.ws.client.gen.CAExistsException
     */
    public CAExistsException getFaultInfo() {
        return faultInfo;
    }

}
