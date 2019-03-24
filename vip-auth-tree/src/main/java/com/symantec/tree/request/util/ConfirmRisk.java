package com.symantec.tree.request.util;

import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * Executing Confirm Risk request
 *
 */
public class ConfirmRisk {
private Logger logger = LoggerFactory.getLogger(ConfirmRisk.class);
		
	/**
	 * 
	 * @param userName UserId
	 * @param eventID  Event Id evaluated from Evaluate Risk API.
	 * @param key_store keystore.ks file location
	 * @param key_store_pass keystore.ks file password
	 * @return status of Confirm Risk request response
	 * @throws NodeProcessException
	 */
	public String confirmRisk(String userName,String eventID,String key_store,String key_store_pass) throws NodeProcessException {
		String payLoad = getPayload(userName,eventID);
		logger.debug("Confirm Risk Request Payload: " + payLoad);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String status;
		
		status = doc.getElementsByTagName("status").item(0).getTextContent();
					
	    logger.debug("Confirm Risk request response code is "+status);
		return status;
	}
	
	/**
	 * 
	 * @param userName UserId
	 * @param eventID Event Id evaluated from Evaluate Risk API.
	 * @return Confirm Risk request payload
	 */
	private String getPayload(String userName,String eventID) {
		logger.info("getting payload for Confirm Risk");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		       + "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
		       + "<soapenv:Body>" + "<vip:ConfirmRiskRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
		       + "</vip:requestId>" + "<vip:UserId>" + userName + "</vip:UserId>"
		       + "<vip:EventId>" + eventID + "</vip:EventId>"
		       + "</vip:ConfirmRiskRequest>" + "</soapenv:Body>"
		       + "</soapenv:Envelope>";

	}
	
	/**
	 * 
	 * @return AuthenticationServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("AuthenticationServiceURL");
	}
}
