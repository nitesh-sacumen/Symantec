package com.symantec.tree.request.util;
import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * 
 * Executing Deny Risk request
 *
 */
public class DenyRisk {
private Logger logger = LoggerFactory.getLogger(DenyRisk.class);
	
	/**
	 * 
	 * @param userName UserId
	 * @param eventID Event Id evaluated from Evaluate Risk API.
	 * @param auth_data Auth data Deny Risk For
	 * @param deviceFriendlyName Device Friendly Name
	 * @param key_store keystore.ks file location 
	 * @param key_store_pass keystore.ks file password
	 * @return status of Deny Risk request response
	 * @throws NodeProcessException
	 */
	public String denyRisk(String userName,String eventID, String auth_data, String deviceFriendlyName,String key_store,String key_store_pass) throws NodeProcessException {
        logger.info("Executing Deny Risk request");

		String payLoad = getPayload(userName,eventID,auth_data,deviceFriendlyName);
		
		logger.debug("Deny Risk Request Payload: " + payLoad);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);

		String status;
		
		status = doc.getElementsByTagName("status").item(0).getTextContent();
			
	    logger.debug("Deny Risk request response code is "+status);
			
		return status;
	}
	
	/**
	 * 
	 * @param userName UserID
	 * @param eventID Event ID
	 * @param auth_data Auth Data
	 * @param deviceFriendlyName Device Friendly Name
	 * @return Payload of Deny Risk request
	 */
	private String getPayload(String userName,String eventID, String auth_data, String deviceFriendlyName) {
		logger.info("getting payload for DenyRisk Risk");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		       + "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
		       + "<soapenv:Body>" + "<vip:DenyRiskRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
		       + "</vip:requestId>" + "<vip:UserId>" + userName + "</vip:UserId>"
		       + "<vip:EventId>" + eventID + "</vip:EventId>" + "<vip:IAAuthData>" + auth_data
		       + "</vip:IAAuthData>"
		       + "<vip:RememberDevice>" + true + "</vip:RememberDevice>"
		       + "<vip:FriendlyName>" + deviceFriendlyName + "</vip:FriendlyName>"
		       + "</vip:DenyRiskRequest>" + "</soapenv:Body>"
		       + "</soapenv:Envelope>";

	}
	
	/**
	 * 
	 * @return AuthenticationServiceURL 
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("AuthenticationServiceURL");
	}
}
