package com.symantec.tree.request.util;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import com.sun.identity.shared.debug.Debug;
import java.util.HashMap;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @Description Get user info from vip data base if user exists, else return
 *              false.
 *
 */

public class VIPGetUser {

	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * 
	 * @param userId
	 * @param KEY_STORE_PATH
	 * @param KEY_STORE_PASS
	 * @return status code of response.
	 * @throws NodeProcessException
	 */
	public String viewUserInfo(String userId, String KEY_STORE_PATH, String KEY_STORE_PASS)
			throws NodeProcessException {

		String userPayload = getViewUserPayload(userId);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), userPayload);

		String status;
	
		status = doc.getElementsByTagName("status").item(0).getTextContent();
		
		return status;
	}

	/**
	 * 
	 * @param userId
	 * @return GetUserInfoRequest Payload
	 */
	private String getViewUserPayload(String userId) {
		debug.message("getting GetUserInfoRequest payload");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:GetUserInfoRequest>" + "<vip:requestId>" + Math.round(Math.random() * 100000)
				+ "</vip:requestId>" + "" + "<vip:userId>" + userId + "</vip:userId>" + ""
				+ "<vip:iaInfo>true</vip:iaInfo>" + "<vip:includePushAttributes>true</vip:includePushAttributes>"
				+ "<vip:includeTokenInfo>true</vip:includeTokenInfo>" + "</vip:GetUserInfoRequest>" + "</soapenv:Body>"
				+ "</soapenv:Envelope>";
	}

	/**
	 * 
	 * @param userId
	 * @param KEY_STORE_PATH
	 * @param KEY_STORE_PASS
	 * @return User's Mobile information, If user exists in vip database.
	 * @throws NullPointerException
	 * @throws NodeProcessException
	 */
	public String getMobInfo(String userId, String KEY_STORE_PATH, String KEY_STORE_PASS)
			throws NullPointerException, NodeProcessException {
		String phoneNumber = null;
	
		String userPayload = getViewUserPayload(userId);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), userPayload);

			if (doc.getElementsByTagName("credentialBindingDetail") != null) {
				if (doc.getElementsByTagName("credentialBindingDetail").item(0) != null) {
					String credBindingDetail = doc.getElementsByTagName("credentialBindingDetail").item(0)
							.getTextContent();

					String credType = doc.getElementsByTagName("credentialType").item(0).getTextContent();
					if (credBindingDetail == null || credType.equalsIgnoreCase("SMS_OTP")
							|| credType.equalsIgnoreCase("VOICE_OTP")) {
						phoneNumber = doc.getElementsByTagName("credentialId").item(0).getTextContent();
					} else {
						String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
						if (statusMessage != null && statusMessage.equalsIgnoreCase("Success")) {
							return "VIP_CRED_REGISTERED";

						}
					}
				}

				else {
					String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
					if (statusMessage != null && statusMessage.equalsIgnoreCase("Success")) {
						return "NO_CRED_REGISTERED";
					}
				}
			} else {
				String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
				debug.message("Status is:\t" + statusMessage);
				if (statusMessage != null && statusMessage.equalsIgnoreCase("Success")) {
					return "NO_CRED_REGISTERED";
				}
			}

		
		return phoneNumber;
	}

	/**
	 * 
	 * @return QueryServiceURL
	 * @throws NodeProcessException
	 */

	public HashMap<String, String> getCredentialBindingDetail(String userId, String KEY_STORE_PATH, String KEY_STORE_PASS, TreeContext context) throws NodeProcessException {
		HashMap<String, String> credentialBindingDetail = new HashMap<>();

		String userPayload = getViewUserPayload(userId);
		
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), userPayload);

		org.w3c.dom.NodeList nList = doc.getElementsByTagName("credentialBindingDetail");
		for (int temp = 0; temp < nList.getLength(); temp++) {
			Node node = nList.item(temp);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				Element eElement = (Element) node;
				String credentialId = eElement.getElementsByTagName("TokenId").item(0).getTextContent();
				String credentialType = eElement.getElementsByTagName("Adapter").item(0).getTextContent();
				credentialBindingDetail.put(credentialType, credentialId);
			}
		}
		return credentialBindingDetail;
	}
	
	private String getURL() {
		return GetVIPServiceURL.serviceUrls.get("QueryServiceURL");
	}
}
