package com.symantec.tree.request.util;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.InputStreamEntity;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;


import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * Create user if not exist.
 *
 */
public class VIPCreateUser {

	static Logger logger = LoggerFactory.getLogger(VIPCreateUser.class);

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
			HttpPost httpPost = new HttpPost(getURL());
			httpPost.addHeader("Accept-Encoding", "gzip,deflate");
			httpPost.addHeader("Content-Type", "text/xml;charset=utf-8");
			httpPost.addHeader("SOAPAction", ""); /* \"\" */
			httpPost.addHeader("User-Agent", "Apache-HttpClient/4.1.1");

			String userPayload = createUserPayload(userId);
			InputStream is = new ByteArrayInputStream(userPayload.getBytes());

			InputStreamEntity reqEntity = new InputStreamEntity(is, -1);
			reqEntity.setContentType("text/xml");
			reqEntity.setContentEncoding("charset=utf-8");
			reqEntity.setChunked(true);

			logger.debug("req content length:\t" + reqEntity.getContentLength());
			httpPost.setEntity(reqEntity);
			String statusMessage;
			try {
			HttpClient httpClient = HttpClientUtil.getInstance().getHttpClientForgerock(key_store,key_store_pass);
			HttpResponse response = httpClient.execute(httpPost);
			HttpEntity entity = response.getEntity();
			String body = IOUtils.toString(entity.getContent());
			DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
			InputSource src = new InputSource();
			src.setCharacterStream(new StringReader(body));
			Document doc = builder.parse(src);
			String status = doc.getElementsByTagName("status").item(0).getTextContent();
			statusMessage = doc.getElementsByTagName("statusMessage").item(0).getTextContent();
			}
			catch (IOException | ParserConfigurationException | SAXException e) {
				throw new NodeProcessException(e);
			}
			if ("Success".equals(statusMessage)) {
				isUserExisted = true;
			}

		return isUserExisted;
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
