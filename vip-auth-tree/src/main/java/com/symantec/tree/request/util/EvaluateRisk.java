package com.symantec.tree.request.util;

import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
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
 * Executing Evaluate Risk request
 *
 */
public class EvaluateRisk {
	private final Debug debug = Debug.getInstance("VIP");

	//TODO This variable does not need to be global
	private HashMap<String,String> evaluateRiskResponseAttribute;
	
<<<<<<< HEAD
	HashMap<String,String> evaluateRiskResponseAttribute;
	
	/**
	 * @param userName UserID
	 * @param IP IP For Evaluate Risk request
	 * @param auth_data Auth Data, Evaluate Risk For
	 * @param userAgent User Agent
	 * @param key_store keystore.ks file location
	 * @param key_store_pass keystore.ks file password
	 * @return Hash Map which contains status of Evaluate Risk request, Event ID, Device Tag and finally Score to make decision.
	 * @throws NodeProcessException
	 */
	public HashMap<String,String> evaluateRisk(String userName,String IP, String auth_data,String userAgent, String key_store,String key_store_pass) throws NodeProcessException {
=======
	public HashMap<String,String> evaluateRisk(String userName,String IP, String auth_data,String userAgent,
												String key_store,String key_store_pass) throws NodeProcessException {
		//TODO Duplicate code
>>>>>>> remotes/origin/no_sdk_frank_changes
		HttpClientUtil clientUtil = HttpClientUtil.getInstance();
		HttpPost post = new HttpPost(getURL());
		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		String payLoad = getPayload(userName,IP,auth_data,userAgent);
		debug.message("Evaluate Request Payload: " + payLoad);
		String status;
		try {
			HttpClient httpClient = clientUtil.getHttpClientForgerock(key_store,key_store_pass);
			post.setEntity(new StringEntity(payLoad));
			HttpResponse response = httpClient.execute(post);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());
			debug.message("Evaluate Risk Response is "+body);
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			Document doc = builder.parse(src);
			evaluateRiskResponseAttribute = new HashMap<>();
			String eventId = doc.getElementsByTagName("EventId").item(0).getTextContent();
			String deviceTag = doc.getElementsByTagName("KeyValuePairs").item(2).getChildNodes().item(1).getTextContent();
			//TODO Status message never used
			String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
			status = doc.getElementsByTagName("status").item(0).getTextContent();
			String riskScore = doc.getElementsByTagName("RiskScore").item(0).getTextContent();

			debug.message("event id is "+eventId);
			debug.message("deviceTag tag is "+deviceTag);

			evaluateRiskResponseAttribute.put("EventId",eventId);
			evaluateRiskResponseAttribute.put("status",status);
			evaluateRiskResponseAttribute.put("DeviceTag",deviceTag);
			evaluateRiskResponseAttribute.put("score",riskScore);
			
		} catch (IOException | ParserConfigurationException | SAXException e) {
			debug.error("Not able to process Request");
			throw new NodeProcessException(e);
		}

		return evaluateRiskResponseAttribute;
	}
	
	/**
	 * 
	 * @param userName UserID
	 * @param IP IP Address
	 * @param auth_data Auth Data
	 * @param userAgent User Agent
	 * @return Payload of Evaluate Risk request
	 */
	private String getPayload(String userName,String IP, String auth_data, String userAgent) {
		debug.message("getting payload for Evaluate Risk");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
		       + "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "<soapenv:Header/>"
		       + "<soapenv:Body>" + "<vip:EvaluateRiskRequest>" + "<vip:requestId>" + new Random().nextInt(10) + 11111
		       + "</vip:requestId>" + "<vip:UserId>" + userName + "</vip:UserId>"
		       + "<vip:Ip>" + IP + "</vip:Ip>" + "<vip:UserAgent>" + userAgent
		       + "</vip:UserAgent>"+ "<vip:IAAuthData>" + auth_data
		       + "</vip:IAAuthData>"+ "</vip:EvaluateRiskRequest>" + "</soapenv:Body>"
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
