package com.symantec.tree.request.util;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;


/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * Create user if not exist.
 *
 */
public class VIPCreateUser {

private Logger logger = LoggerFactory.getLogger(VIPCreateUser.class);

	/**
	 * 
	 * @param userId
	 * @return CreateUserRequest payload
	 */
	private String createUserPayload(String userId) {
		logger.info("getting CreateUserRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
				"xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" +
				"   <soapenv:Header/>" +
				"   <soapenv:Body>" +
				"      <vip:CreateUserRequest>" +
				"               <vip:requestId>" + Math.round(Math.random() * 100000) + "</vip:requestId>" +
				"             <vip:userId>" + userId + "</vip:userId>" +
				"      </vip:CreateUserRequest>" +
				"   </soapenv:Body>" +
				"</soapenv:Envelope>";
	}

	/**
	 * 
	 * @param userId
	 * @return true id user is create, else false
	 * @throws NodeProcessException 
	 * 
	 */
	public boolean createVIPUser(String userId,String key_store,String key_store_pass) throws NodeProcessException {
		    boolean isUserExisted = false;

			String userPayload = createUserPayload(userId);
			Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), userPayload);

			String statusMessage;
			
			statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
			
			if ("Success".equals(statusMessage)) {
				isUserExisted = true;
			}

		return isUserExisted;
	}

	/**
	 * 
	 * @return ManagementServiceURL
	 */
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}
}
