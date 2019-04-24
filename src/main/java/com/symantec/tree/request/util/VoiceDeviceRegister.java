package com.symantec.tree.request.util;

import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br>
 *         <br>
 * 
 */
public class VoiceDeviceRegister {

private Logger logger = LoggerFactory.getLogger(VoiceDeviceRegister.class);

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param key_store
	 * @param key_store_pass
	 * @return true if SendOtpRequest success, else false.
	 * @throws NodeProcessException
	 */
	public Boolean voiceDeviceRegister(String userName, String credValue, String key_store, String key_store_pass)
			throws NodeProcessException {
		logger.info("Executing voiceDeviceRegister request");
		
		String payLoad = getViewUserPayload(userName, credValue);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		logger.debug("Request Payload: " + payLoad);

		String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
		if ("success".equalsIgnoreCase(statusMessage)) {
			return true;

		}

		return false;
	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @return SendOtpRequest payload
	 */
	private String getViewUserPayload(String userName, String credValue) {
		logger.info("getting SendOtpRequest ");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:SendOtpRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>" + "<vip:voiceDeliveryInfo>"
				+ "<vip:phoneNumber>" + credValue + "</vip:phoneNumber>" + "" + "</vip:voiceDeliveryInfo>"
				+ "</vip:SendOtpRequest>" + "</soapenv:Body>" + "</soapenv:Envelope>";
	}

	/**
	 * 
	 * @return ManagementServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}