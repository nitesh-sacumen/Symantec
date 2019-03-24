package com.symantec.tree.request.util;

import java.util.Random;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;


/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * getting status of poll push request using PollPushStatusRequest
 *
 */
public class AuthPollPush {

private Logger logger = LoggerFactory.getLogger(AuthPollPush.class);

	/**
	 * 
	 * @param authId
	 * @return response status code
	 * @throws NodeProcessException 
	 */
	public String authPollPush(String authId,String key_store,String key_store_pass) throws NodeProcessException {

		String payLoad = getViewUserPayload(authId);
		logger.debug("Request Payload in authPollPush: " + payLoad);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);
		String status = doc.getElementsByTagName("status").item(1).getTextContent();
		return status;

	}

	/**
	 * 
	 * @param authId
	 * @return PollPushStatusRequest payload
	 */
	private String getViewUserPayload(String authId) {
		logger.info("getting payload for PollPushStatusRequest");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
				"xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" +
				"<soapenv:Header/>" +
				"<soapenv:Body>" +
				"<vip:PollPushStatusRequest>" +
				"<vip:requestId>" + new Random().nextInt(10) + 11111 + "</vip:requestId>" +
				"<vip:transactionId>" + authId + "</vip:transactionId>" +
				"</vip:PollPushStatusRequest>" +
				"</soapenv:Body>" +
				"</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return QueryServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("QueryServiceURL");
	}

}
