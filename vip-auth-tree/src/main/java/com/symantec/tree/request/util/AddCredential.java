package com.symantec.tree.request.util;

import java.io.IOException;
import java.io.StringReader;
import java.util.Random;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.identity.shared.debug.Debug;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br> 
 * @Description Add credentials using "AddCredentialRequest".
 *
 */
public class AddCredential {
	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @return true if success, else false.
	 * @throws NodeProcessException
	 */
	public String addCredential(String userName, String credValue, String credIdType,String key_store,String key_store_pass) throws NodeProcessException {

		String payload = getViewUserPayload(userName, credValue, credIdType);
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payload);
	    return doc.getElementsByTagName("status").item(0).getTextContent();
	}
	

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @return AddCredentialRequest payload
	 */
	private String getViewUserPayload(String userName, String credValue, String credIdType) {
		debug.message("getting payload for AddCredentialRequest");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:AddCredentialRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>" + "<vip:credentialDetail>"
				+ "<vip:credentialId>" + credValue + "</vip:credentialId>" + "<vip:credentialType>" + credIdType
				+ "</vip:credentialType>" + "</vip:credentialDetail>" + "</vip:AddCredentialRequest>"
				+ "</soapenv:Body>" + "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @param otpreceived
	 * @return true if success, else false
	 * @throws NodeProcessException
	 */
	public String addCredential(String userName, String credValue, String credIdType, String otpreceived,String key_store,String key_store_pass)
			throws NodeProcessException {
		String payLoad = getViewUserPayload(userName, credValue, credIdType, otpreceived);
		Document doc = HttpClientUtil.getInstance().executeRequst(getURL(), payLoad);
	    return doc.getElementsByTagName("status").item(0).getTextContent();
	}

	/**
	 * 
	 * @param userName
	 * @param credValue
	 * @param credIdType
	 * @param otpReceived
	 * @return AddCredentialRequest payload
	 */
	private String getViewUserPayload(String userName, String credValue, String credIdType, String otpReceived) {

		debug.message("getting payload for AddCredentialRequest with otp");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
				+ "<soapenv:Body>" + "<vip:AddCredentialRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
				+ "</vip:requestId>" + "<vip:userId>" + userName + "</vip:userId>" + "<vip:credentialDetail>"
				+ "<vip:credentialId>" + credValue + "</vip:credentialId>" + "<vip:credentialType>" + credIdType
				+ "</vip:credentialType>" + "</vip:credentialDetail>" + "<vip:otpAuthData>" + "<vip:otp>" + otpReceived
				+ "</vip:otp>" + "</vip:otpAuthData>" + "</vip:AddCredentialRequest>" + "</soapenv:Body>"
				+ "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return ManagementServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.serviceUrls.get("ManagementServiceURL");
	}

}
