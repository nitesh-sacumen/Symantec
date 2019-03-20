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
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.sun.identity.shared.debug.Debug;

import static com.symantec.tree.config.Constants.*;


/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br> 
 * @Description Deleting credential id , which is associated with user using
 *         RemoveCredentialRequest
 *
 */
public class DeleteCredential {
	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * 
	 * @param userName
	 * @param credId
	 * @param credType
	 * @throws NodeProcessException
	 */
	public void deleteCredential(String userName, String credId, String credType,String key_store,String key_store_pass) throws NodeProcessException {
		HttpPost post = new HttpPost(getURL());
		post.setHeader("CONTENT-TYPE", "text/xml; charset=ISO-8859-1");
		String payLoad = getRemoveCredPayload(userName, credId, credType);
		debug.message("Request Payload: " + payLoad);
		String status;
		try {
			HttpClient httpClient = HttpClientUtil.getInstance().getHttpClientForgerock(key_store,key_store_pass);
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

		} catch (IOException | ParserConfigurationException | SAXException e) {
			debug.error("Not able to process Request");
			throw new NodeProcessException(e);
		}
		if (SUCCESS_CODE.equals(status)) {
			debug.message("Credential " + credType + " removed successfully for " + userName);
		}
	}

	/**
	 * 
	 * @param userId
	 * @param credId
	 * @param credType
	 * @return RemoveCredentialRequest payload
	 */
	private String getRemoveCredPayload(String userId, String credId, String credType) {
		return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				+ "xmlns:vip=\"https://schemas.symantec.com/vip/2011/04/vipuserservices\">" + "   <soapenv:Header/>"
				+ "   <soapenv:Body>" + "      <vip:RemoveCredentialRequest>" + "<vip:requestId>"
				+ Math.round(Math.random() * 100000) + "</vip:requestId>" + "         <vip:userId>" + userId
				+ "</vip:userId>" + "         <vip:credentialId>" + credId + "</vip:credentialId>"
				+ "          <vip:credentialType>" + credType + "</vip:credentialType>      "
				+ "      </vip:RemoveCredentialRequest>" + "   </soapenv:Body>" + "</soapenv:Envelope>";

	}

	/**
	 * 
	 * @return ManagementServiceURL
	 * @throws NodeProcessException 
	 */
	private String getURL() throws NodeProcessException {
		return GetVIPServiceURL.getInstance().serviceUrls.get("ManagementServiceURL");
	}

}
