	package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import com.google.inject.assistedinject.Assisted;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.config.Constants;
import com.symantec.tree.request.util.AuthenticateUser;
import com.symantec.tree.request.util.GetVIPServiceURL;

import java.util.HashMap;
import java.util.Map;
import javax.inject.Inject;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Push Auth User" node with TRUE,FALSE outcome. If TRUE, it will go to "VIP Poll Push Auth". If False, go to
 *             "VIP OTPAuth Creds".
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPPushAuth.Config.class)
public class VIPPushAuth extends AbstractDecisionNode {

    private Logger logger = LoggerFactory.getLogger(VIPPushAuth.class);

	private AuthenticateUser pushAuthUser;
	private final Map<String, String> vipPushCodeMap = new HashMap<>();
	private final Config config;

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
	public VIPPushAuth(@Assisted Config config,AuthenticateUser pushAuthUser) {

		this.config = config;
		logger.debug("Display Message Text:", config.displayMsgText());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TEXT, config.displayMsgText());

		logger.debug("Display Message Title", config.displayMsgTitle());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_TITLE, config.displayMsgTitle());

		logger.debug("Display Message Profile", config.displayMsgProfile());
		vipPushCodeMap.put(Constants.PUSH_DISPLAY_MESSAGE_PROFILE, config.displayMsgProfile());

		this.pushAuthUser = pushAuthUser;
	}

	/**
	 * Main logic of the node
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("VIP Push Auth");
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		String transactionId = pushAuthUser.authUser(vip.getUserName(), vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TEXT),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_TITLE),
				vipPushCodeMap.get(Constants.PUSH_DISPLAY_MESSAGE_PROFILE),
				vip.getKeyStorePath(),vip.getKeyStorePasswod());
		
		logger.debug("TransactionId is " + transactionId);
		
		if (transactionId != null && !transactionId.isEmpty()) {
			context.sharedState.put(TXN_ID, transactionId);
			return goTo(true).build();
		} else {
			context.sharedState.put(PUSH_ERROR,"Not able to send push, Please select other credential option");
			return goTo(false).build();
		}

	}
}