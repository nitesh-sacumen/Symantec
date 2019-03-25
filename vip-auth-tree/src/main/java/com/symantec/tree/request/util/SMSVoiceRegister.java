package com.symantec.tree.request.util;

import java.util.Random;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br>
 *         <br>
 *         Executing RegisterRequest for SMS and Voice
 */
public class SMSVoiceRegister {
private Logger logger = LoggerFactory.getLogger(SMSVoiceRegister.class);

	/**
	 * 
	 * @param credValue register SMS
	 * @throws NodeProcessException
	 */
	public String smsRegister(String credValue, String key_store, String key_store_pass) throws NodeProcessException {
		String payLoad = getSmsPayload(credValue);
		String status;
		logger.debug("Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		status = doc.getElementsByTagName("status").item(0).getTextContent();

		return status;

	}

	/**
	 * 
	 * @param credValue register voice
	 * @throws NodeProcessException
	 */
	public String voiceRegister(String credValue, String key_store, String key_store_pass) throws NodeProcessException {
		String payLoad = getVoicePayload(credValue);
		String status;
		logger.debug("Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		status = doc.getElementsByTagName("status").item(0).getTextContent();

		return status;

	}

	/**
	 * 
	 * @param credValue
	 * @return RegisterRequest payload
	 */
	private String getSmsPayload(String credValue) {
		logger.debug("getting RegisterRequest payload for SMS");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:RegisterRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "" + "<vip:smsDeliveryInfo>" + "<vip:phoneNumber>" + credValue
				+ "</vip:phoneNumber> " + "</vip:smsDeliveryInfo> " + "</vip:RegisterRequest>" + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @param credValue
	 * @return RegisterRequest payload for voice
	 */
	private String getVoicePayload(String credValue) {
		logger.info("getting RegisterRequest payload for voice");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:RegisterRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "" + "<vip:voiceDeliveryInfo>" + "<vip:phoneNumber>" + credValue
				+ "</vip:phoneNumber> " + "</vip:voiceDeliveryInfo> " + "</vip:RegisterRequest>" + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return ManagementServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}