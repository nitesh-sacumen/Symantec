package com.symantec.tree.request.util;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br>
 *         <br>
 * @Desription Getting activation code using GetActivationCode request
 *
 */
public class GenerateActivationCode {
private Logger logger = LoggerFactory.getLogger(GenerateActivationCode.class);

	/**
	 * 
	 * @return activation code with status
	 * @throws NodeProcessException
	 */
	public String generateCode(String key_store, String key_store_pass) throws NodeProcessException {
        logger.info("Executing Generate Activation Code request");

		String activationCode;
		String status;

		String payLoad = createPayload();
		logger.debug("Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		status = doc.getElementsByTagName("ReasonCode").item(0).getTextContent();
		if (doc.getElementsByTagName("ActivationCode").item(0) != null) {
			activationCode = doc.getElementsByTagName("ActivationCode").item(0).getTextContent();
		} else
			activationCode = " ";

		String code = status + "," + activationCode;
		logger.debug("Status and TransactionId \t" + code);
		return code;
	}

	/**
	 * 
	 * @return GetActivationCode payload
	 */
	private String createPayload() {
		logger.info("gtting GetActivationCode payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:vip=\"http://www"
				+ ".verisign.com/2006/08/vipservice\">" + "   <soapenv:Header/>" + "   <soapenv:Body>"
				+ "      <vip:GetActivationCode Version=\"1.0\" Id=" + "\"" + Math.round(Math.random() * 100000) + "\">"
				+ "        <vip:ACProfile>" + "MOBILEPHONE" + "</vip:ACProfile>" + "      </vip:GetActivationCode>"
				+ "   </soapenv:Body>" + "</soapenv:Envelope>";

	}

	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("SDKServiceURL");
	}

}