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
 * @author Sacumen (www.sacumen.com)
 * 
 * Executing Deny Risk request
 *
 */
public class DenyRisk {
	private final Debug debug = Debug.getInstance("VIP");
	
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
		HttpClientUtil clientUtil = HttpClientUtil.getInstance();
		HttpPost post = new HttpPost(getURL());
		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		String payLoad = getPayload(userName,eventID,auth_data,deviceFriendlyName);
		debug.message("Deny Risk Request Payload: " + payLoad);
		String status;
		try {
			HttpClient httpClient = clientUtil.getHttpClientForgerock(key_store,key_store_pass);
			post.setEntity(new StringEntity(payLoad));
			HttpResponse response = httpClient.execute(post);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());
			debug.message("Deny Risk Response is "+body);
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			Document doc = builder.parse(src);
			status = doc.getElementsByTagName("status").item(0).getTextContent();
			
			debug.message("Deny Risk request response code is "+status);
			
		} catch (IOException | ParserConfigurationException | SAXException e) {
			debug.error("Not able to process Request");
			throw new NodeProcessException(e);
		}

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
		debug.message("getting payload for DenyRisk Risk");
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
		return GetVIPServiceURL.getInstance().serviceUrls.get("AuthenticationServiceURL");
	}
}
