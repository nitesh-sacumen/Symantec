package com.symantec.tree.request.util;

import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br> 
 * @Description Add credentials using "AddCredentialRequest".
 *
 */
public class AddCredential {
private Logger logger = LoggerFactory.getLogger(AddCredential.class);

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @return true if success, else false.
	 * @throws NodeProcessException
	 */
	public String addCredential(String userName, String credValue, String credIdType,String key_store,String key_store_pass) throws NodeProcessException {

		String payload = getViewUserPayload(userName, credValue, credIdType);
		logger.info("Request payload is "+payload);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payload);
	    return doc.getElementsByTagName("status").item(0).getTextContent();
	}
	

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @return AddCredentialRequest payload
	 */
	private String getViewUserPayload(String userName, String credValue, String credIdType) {
		logger.info("getting payload for AddCredentialRequest");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:AddCredentialRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>" + "<vip:credentialDetail>"
				+ "<vip:credentialId>" + credValue + "</vip:credentialId>" + "<vip:credentialType>" + credIdType
				+ "</vip:credentialType>" + "</vip:credentialDetail>" + "</vip:AddCredentialRequest>"
				+ "</soapenv:Body>" + "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @param otpreceived
	 * @return true if success, else false
	 * @throws NodeProcessException
	 */
	public String addCredential(String userName, String credValue, String credIdType, String otpreceived,String key_store,String key_store_pass)
			throws NodeProcessException {
		String payLoad = getViewUserPayload(userName, credValue, credIdType, otpreceived);
		logger.info("Request payload is "+payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);
	    return doc.getElementsByTagName("status").item(0).getTextContent();
	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @param otpReceived
	 * @return AddCredentialRequest payload
	 */
	private String getViewUserPayload(String userName, String credValue, String credIdType, String otpReceived) {

		logger.info("getting payload for AddCredentialRequest with otp");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:AddCredentialRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>" + "<vip:credentialDetail>"
				+ "<vip:credentialId>" + credValue + "</vip:credentialId>" + "<vip:credentialType>" + credIdType
				+ "</vip:credentialType>" + "</vip:credentialDetail>" + "<vip:otpAuthData>" + "<vip:otp>" + otpReceived
				+ "</vip:otp>" + "</vip:otpAuthData>" + "</vip:AddCredentialRequest>" + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return ManagementServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}
