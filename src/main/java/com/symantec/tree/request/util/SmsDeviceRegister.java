package com.symantec.tree.request.util;

import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br>
 *         <br>
 * @Description Executing SendOtpRequest
 *
 */
public class SmsDeviceRegister {

private Logger logger = LoggerFactory.getLogger(SmsDeviceRegister.class);

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @return true if success, else false
	 * @throws NodeProcessException
	 */
	public Boolean smsDeviceRegister(String userName, String credValue, String key_store, String key_store_pass)
			throws NodeProcessException {
		String payLoad = getViewUserPayload(userName, credValue);
		logger.debug("Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String statusMessage;

		statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();

		if ("success".equalsIgnoreCase(statusMessage)) {
			return true;

		}
		return false;
	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @return SendOtpRequest payoad
	 */
	private String getViewUserPayload(String userName, String credValue) {
		logger.info("getting SendOtpRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:SendOtpRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "" + "<vip:userId>" + userName + "</vip:userId>" + "" + "<vip:smsDeliveryInfo>"
				+ "<vip:phoneNumber>" + credValue + "</vip:phoneNumber>" + "" + "</vip:smsDeliveryInfo>" + ""
				+ "</vip:SendOtpRequest>" + "</soapenv:Body>" + "</soapenv:Envelope>";

	}

	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}