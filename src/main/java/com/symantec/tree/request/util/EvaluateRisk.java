package com.symantec.tree.request.util;

import java.util.HashMap;
import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * 
 *         Executing Evaluate Risk request
 *
 */
public class EvaluateRisk {
private Logger logger = LoggerFactory.getLogger(EvaluateRisk.class);

	/**
	 * @param userName       UserID
	 * @param IP             IP For Evaluate Risk request
	 * @param auth_data      Auth Data, Evaluate Risk For
	 * @param userAgent      User Agent
	 * @param key_store      keystore.ks file location
	 * @param key_store_pass keystore.ks file password
	 * @return Hash Map which contains status of Evaluate Risk request, Event ID,
	 *         Device Tag and finally Score to make decision.
	 * @throws NodeProcessException
	 */

	public HashMap<String, String> evaluateRisk(String userName, String IP, String auth_data, String userAgent,
			String key_store, String key_store_pass) throws NodeProcessException {
        logger.info("Executing Evaluate Risk request");

		String payLoad = getPayload(userName, IP, auth_data, userAgent);
		logger.debug("Evaluate Request Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String status;
		HashMap<String,String> evaluateRiskResponseAttribute;

		evaluateRiskResponseAttribute = new HashMap<>();
		String eventId = doc.getElementsByTagName("EventId").item(0).getTextContent();
		String deviceTag = doc.getElementsByTagName("KeyValuePairs").item(2).getChildNodes().item(1).getTextContent();
		status = doc.getElementsByTagName("status").item(0).getTextContent();
		String riskScore = doc.getElementsByTagName("RiskScore").item(0).getTextContent();

		logger.debug("event id is " + eventId);
		logger.debug("deviceTag tag is " + deviceTag);

		evaluateRiskResponseAttribute.put("EventId", eventId);
		evaluateRiskResponseAttribute.put("status", status);
		evaluateRiskResponseAttribute.put("DeviceTag", deviceTag);
		evaluateRiskResponseAttribute.put("score", riskScore);

		return evaluateRiskResponseAttribute;
	}

	/**
	 * 
	 * @param userName  UserID
	 * @param IP        IP Address
	 * @param auth_data Auth Data
	 * @param userAgent User Agent
	 * @return Payload of Evaluate Risk request
	 */
	private String getPayload(String userName, String IP, String auth_data, String userAgent) {
		logger.info("getting payload for Evaluate Risk");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:EvaluateRiskRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:UserId>" + userName + "</vip:UserId>" + "<vip:Ip>" + IP + "</vip:Ip>"
				+ "<vip:UserAgent>" + userAgent + "</vip:UserAgent>" + "<vip:IAAuthData>" + auth_data
				+ "</vip:IAAuthData>" + "</vip:EvaluateRiskRequest>" + "</soapenv:Body>" + "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return AuthenticationServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("AuthenticationServiceURL");
	}
}
