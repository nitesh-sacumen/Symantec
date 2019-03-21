package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.KEY_STORE_PASS;
import static com.symantec.tree.config.Constants.KEY_STORE_PATH;
import static com.symantec.tree.config.Constants.NO_CREDENTIALS_REGISTERED;

<<<<<<< HEAD
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.request.util.VIPCreateUser;
import javax.inject.Inject;
import org.forgerock.openam.auth.node.api.*;
=======
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
>>>>>>> remotes/origin/no_sdk_frank_changes

import com.symantec.tree.request.util.VIPCreateUser;

import javax.inject.Inject;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Register User" node with TRUE,FALSE outcome. If TRUE, it will go to "VIP Display Creds". If False, go to
 *             "Failure".
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPRegisterUser.Config.class)
public class VIPRegisterUser extends AbstractDecisionNode {

	private final Debug debug = Debug.getInstance("VIP");

	private VIPCreateUser vIPCreateUser;


	/**
	 * Configuration for the node.
	 */
	public interface Config {

	}

	/**
	 * Create the node.
	 *
	 */
	@Inject
	public VIPRegisterUser(VIPCreateUser vIPCreateUser) {
		this.vIPCreateUser = vIPCreateUser;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String credRegistrationStatus = context.transientState.get(NO_CREDENTIALS_REGISTERED).toString();
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		boolean isVIPProfileRegistered;

		debug.message("credRegistrationStatus:" + credRegistrationStatus);

		if (credRegistrationStatus != null && credRegistrationStatus.equalsIgnoreCase("true")) {
			debug.message("User already registered and hence not making user registration call");
			return goTo(true).build();
		} else {
			debug.message("User not registered and hence making user registration call");
			isVIPProfileRegistered = vIPCreateUser.createVIPUser(userName,key_store,key_store_pass);
			return goTo(isVIPProfileRegistered).build();
		}
	}
}