package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.symantec.tree.config.Constants;
import com.symantec.tree.config.Constants.VIPAuthStatusCode;
import com.symantec.tree.request.util.AuthenticateCredential;
import com.symantec.tree.request.util.DeleteCredential;
import com.symantec.tree.request.util.GetVIPServiceURL;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.util.HashMap;
import java.util.Map;

import static com.symantec.tree.config.Constants.*;
/**s
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Authenticate Push Credential" node with true and false outcome, If true, go
 *             to "VIP Poll Push Reg" else false, go to "VIP Enter SecurityCode/OTP".
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPAuthCredential.Config.class)
public class VIPAuthCredential extends AbstractDecisionNode {
	private final Logger logger =LoggerFactory.getLogger(VIPAuthCredential.class);

    private AuthenticateCredential authPushCred;
	private final Map<String, String> vipPushCodeMap = new HashMap<>();

	/**
	 * Configuration for the node.
	 */
	public interface Config {

		@Attribute(order = 100, requiredValue = true)
		default String displayMsgText() {
			return "";
		}

		@Attribute(order = 200, requiredValue = true)
		default String displayMsgTitle() {
			return "";
		}

		@Attribute(order = 300, requiredValue = true)
		default String displayMsgProfile() {
			return "";
		}

	}

	/**
	 * Create the node.
	 * 
	 * @param config The service config.
     */
	@Inject
	public VIPAuthCredential(@Assisted Config config,AuthenticateCredential authPushCred) {

        logger.debug("Display Message Text:", config.displayMsgText());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TEXT, config.displayMsgText());

		logger.debug("Display Message Title", config.displayMsgTitle());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TITLE, config.displayMsgTitle());

		logger.debug("Display Message Profile", config.displayMsgProfile());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_PROFILE, config.displayMsgProfile());

		this.authPushCred = authPushCred;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("Calling VIP Auth credential");

		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		String credId = context.sharedState.get(CRED_ID).asString();
				
		// Executing AuthenticateCredentialsRequest 
		String Stat = authPushCred.authCredential(credId, vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TEXT),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TITLE),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_PROFILE),
				vip.getKeyStorePath(),vip.getKeyStorePasswod());
		
		// Getting AuthenticateCredentialsRequest response
		String[] trastat = Stat.split(",");
		
		String status = trastat[0];
		String transactionId = trastat[1];
		
		logger.debug("Status of AuthenticateCredentialsRequest  .. " + status);
		logger.debug("TransactionID of AuthenticateCredentialsRequest  .. " + transactionId);

		context.sharedState.put(TXN_ID, transactionId);
		
		//Making decision based on AuthenticateCredentialsRequest response
		if (status.equalsIgnoreCase(VIPAuthStatusCode.SUCCESS_CODE)) {
			logger.info("Mobile Push is sent successfully");
			return goTo(true).build();
		} 
		else {
			logger.info("Mobile Push has not sent successfully");
			context.sharedState.put(OTP_ERROR,"Not able to send push, Please enter Security Code");
			deleteCredential(vip.getUserName(), credId,context);
			return goTo(false).build();
		}

	}

	/** 
	 * @param userName UserID
	 * @param credId Credential ID
	 * @throws NodeProcessException 
     */
	private void deleteCredential(String userName, String credId, TreeContext context) throws NodeProcessException {
		logger.info("Deleting credentials");
		
		DeleteCredential delCred = new DeleteCredential();
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();
		
		//Executing RemoveCredentialRequest
		delCred.deleteCredential(userName, credId, Constants.STANDARD_OTP,vip.getKeyStorePath(),vip.getKeyStorePasswod());
	}
}