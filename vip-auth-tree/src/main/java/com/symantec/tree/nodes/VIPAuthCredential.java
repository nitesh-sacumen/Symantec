package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants;
import com.symantec.tree.config.Constants.VIPAuthStatusCode;
import com.symantec.tree.request.util.AuthenticateCredential;
import com.symantec.tree.request.util.DeleteCredential;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
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
	private final Debug debug = Debug.getInstance("VIP");

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

        debug.message("Display Message Text:", config.displayMsgText());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TEXT, config.displayMsgText());

		debug.message("Display Message Title", config.displayMsgTitle());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TITLE, config.displayMsgTitle());

		debug.message("Display Message Profile", config.displayMsgProfile());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_PROFILE, config.displayMsgProfile());

		this.authPushCred = authPushCred;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		String credId = context.sharedState.get(CRED_ID).asString();
        String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
        String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		
		debug.message("Calling VIP Auth credential");
		
		// Executing AuthenticateCredentialsRequest 
		String Stat = authPushCred.authCredential(credId, vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TEXT),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TITLE),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_PROFILE),
				key_store,key_store_pass);
		
		// Getting AuthenticateCredentialsRequest response
		String[] trastat = Stat.split(",");
		for (String s : trastat)
			debug.message("Values:" + s);
		String status = trastat[0];
		String transactionId = trastat[1];
		
		debug.message("Status of AuthenticateCredentialsRequest  .. " + status);
		debug.message("TransactionID of AuthenticateCredentialsRequest  .. " + transactionId);

		context.sharedState.put(TXN_ID, transactionId);
		
		//Making decision based on AuthenticateCredentialsRequest response
		if (status.equalsIgnoreCase(VIPAuthStatusCode.SUCCESS_CODE)) {
			debug.message("Mobile Push is sent successfully:" + status);
			return goTo(true).build();
		} else {
			context.sharedState.put(OTP_ERROR,"Not able to send push, Please enter Security Code");
			deleteCredential(userName, credId,context);
			return goTo(false).build();
		}

	}

	/** 
	 * @param userName UserID
	 * @param credId Credential ID
	 * @throws NodeProcessException 
     */
	private void deleteCredential(String userName, String credId, TreeContext context) throws NodeProcessException {
		debug.message("Deleting credentials");
		
		DeleteCredential delCred = new DeleteCredential();
		String key_store = context.sharedState.get("key_store_path").asString();
		String key_store_pass = context.sharedState.get("key_store_pass").asString();
		
		//Executing RemoveCredentialRequest
		delCred.deleteCredential(userName, credId, Constants.STANDARD_OTP,key_store,key_store_pass);
	}
}