package com.symantec.tree.request.util;

import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;


/**
 * 
 * @author Sacumen(www.sacumen.com) <br>
 *         <br>
 *         Authenticate credentials using AuthenticateCredentialsRequest
 *
 */
public class AuthenticateCredential {
private Logger logger = LoggerFactory.getLogger(AuthenticateCredential.class);

	/**
	 * 
	 * @param credID
	 * @param displayMsgText
	 * @param displayMsgTitle
	 * @param displayMsgProfile
	 * @param key_store
	 * @param key_store_pass
	 * @return status of AuthenticateCredentialsRequest
	 * @throws NodeProcessException
	 */
	public String authCredential(String credID, String displayMsgText, String displayMsgTitle, String displayMsgProfile,
			String key_store, String key_store_pass) throws NodeProcessException {
		String transactionID = "";
		String payLoad = getViewUserPayload(credID, displayMsgText, displayMsgTitle, displayMsgProfile);

        logger.debug("AuthenticateCredentialsRequest Payload: " + payLoad);

		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);
		String status = null;

		status = doc.getElementsByTagName("status").item(0).getTextContent();
		if (doc.getElementsByTagName("transactionId").item(0) != null) {
			transactionID = doc.getElementsByTagName("transactionId").item(0).getTextContent();
		}
		String transtat = status + "," + transactionID;
		logger.debug("Status and TransactionId \t" + transtat);
		return transtat;
	}

	/**
	 * 
	 * @param credId
	 * @param displayMsgText
	 * @param displayMsgTitle
	 * @param displayMsgProfile
	 * @return AuthenticateCredentialsRequest payload
	 */
	private String getViewUserPayload(String credId, String displayMsgText, String displayMsgTitle,
			String displayMsgProfile) {
		logger.info("getting payload for AuthenticateCredentialsRequest");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "   <soapenv:Header/>"
				+ "   <soapenv:Body>" + "      <vip:AuthenticateCredentialsRequest>" + "<vip:requestId>"
				+ Math.round(Math.random() * 100000) + "</vip:requestId>" + "           <vip:credentials>"
				+ "            <vip:credentialId>" + credId + "</vip:credentialId>" + "            <vip:credentialType>"
				+ com.symantec.tree.config.Constants.STANDARD_OTP + "</vip" + ":credentialType>"
				+ "           </vip:credentials>     " + "<vip:pushAuthData>" + "<!--0 to 20 repetitions:-->"
				+ "<vip:displayParameters>" + "<vip:Key>" + "display.message.text" + "</vip:Key>" + "<vip:Value>"
				+ displayMsgText + "</vip:Value>" + "" + "</vip:displayParameters>" + "<vip:displayParameters>"
				+ "<vip:Key>" + "display.message.title" + "</vip:Key>" + "<vip:Value>" + displayMsgTitle
				+ "</vip:Value>" + "" + "</vip:displayParameters>" + "<vip:displayParameters>" + "<vip:Key>"
				+ "display.message.profile" + "</vip:Key>" + "<vip:Value>" + displayMsgProfile + "</vip:Value>" + ""
				+ "</vip:displayParameters>" + "" + "</vip:pushAuthData>"
				+ "       </vip:AuthenticateCredentialsRequest>" + "   </soapenv:Body>" + "</soapenv:Envelope>";
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
