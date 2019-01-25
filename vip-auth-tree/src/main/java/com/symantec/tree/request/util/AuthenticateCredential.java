package com.symantec.tree.request.util;

import java.io.IOException;
import java.io.StringReader;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * Authenticate credentials using AuthenticateCredentialsRequest
 *
 */
public class AuthenticateCredential {
	static Logger logger = LoggerFactory.getLogger(AuthenticateCredential.class);
	
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
	public String authCredential(String credID, String displayMsgText, String displayMsgTitle,String displayMsgProfile,
			String key_store,String key_store_pass) throws NodeProcessException {
		String transactionID = "";
		HttpClientUtil clientUtil = HttpClientUtil.getInstance();
		HttpPost post = new HttpPost(getURL());
		String status = null;
		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		String payLoad = getViewUserPayload(credID, displayMsgText, displayMsgTitle, displayMsgProfile);
		logger.debug("Request Payload: " + payLoad);
		try {
			HttpClient httpClient = clientUtil.getHttpClientForgerock(key_store,key_store_pass);
			post.setEntity(new StringEntity(payLoad));
			HttpResponse response = httpClient.execute(post);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			Document doc = builder.parse(src);
			status = doc.getElementsByTagName("status").item(0).getTextContent();
			String statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
			if(doc.getElementsByTagName("transactionId").item(0) !=null) {
				transactionID = doc.getElementsByTagName("transactionId").item(0).getTextContent();
			}
			else
				transactionID = " ";
			logger.debug("Status is:\t" + statusMessage);
		
		} catch (IOException | ParserConfigurationException | SAXException e) {
			throw new NodeProcessException(e);
		}
		String transtat=status+","+transactionID;
		logger.debug( "Status and TransactionId \t"+transtat);
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
	private static String getViewUserPayload(String credId, String displayMsgText, String displayMsgTitle,
											  String displayMsgProfile) {
		logger.info("getting payload for AuthenticateCredentialsRequest");
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
				"xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" +
				"   <soapenv:Header/>" +
				"   <soapenv:Body>" +
				"      <vip:AuthenticateCredentialsRequest>" +
				"<vip:requestId>" + Math.round(Math.random() * 100000) + "</vip:requestId>" +
				"           <vip:credentials>" +
				"            <vip:credentialId>" + credId + "</vip:credentialId>" +
				"            <vip:credentialType>" + com.symantec.tree.config.Constants.STANDARD_OTP + "</vip" +
				":credentialType>" +
				"           </vip:credentials>     " +
				"<vip:pushAuthData>" +
				"<!--0 to 20 repetitions:-->" +
				"<vip:displayParameters>" +
				"<vip:Key>" + "display.message.text" + "</vip:Key>" +
				"<vip:Value>" + displayMsgText + "</vip:Value>" +
				"" +
				"</vip:displayParameters>" +
				"<vip:displayParameters>" +
				"<vip:Key>" + "display.message.title" + "</vip:Key>" +
				"<vip:Value>" + displayMsgTitle + "</vip:Value>" +
				"" +
				"</vip:displayParameters>" +
				"<vip:displayParameters>" +
				"<vip:Key>" + "display.message.profile" + "</vip:Key>" +
				"<vip:Value>" + displayMsgProfile + "</vip:Value>" +
				"" +
				"</vip:displayParameters>" +
				"" +
				"</vip:pushAuthData>" +
				"       </vip:AuthenticateCredentialsRequest>" +
				"   </soapenv:Body>" +
				"</soapenv:Envelope>";
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
