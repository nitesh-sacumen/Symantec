package com.symantec.tree.nodes;

import static com.symantec.tree.config.Constants.*;

import com.google.inject.assistedinject.Assisted;
import com.symantec.tree.nodes.VIPGenerateActivationCode.Config;
import com.symantec.tree.request.util.SdkAddCredential;
import javax.inject.Inject;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIPSDKAddCredential" node with true and false outcome.
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPSDKAddCredential.Config.class)
public class VIPSDKAddCredential extends AbstractDecisionNode {

	private SdkAddCredential addCred;
	private final Config config;
	private final Logger logger = LoggerFactory.getLogger(VIPSDKAddCredential.class);


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
	public VIPSDKAddCredential(@Assisted Config config,SdkAddCredential addCred) {
		this.config = config;
		this.addCred = addCred;
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String credValue = context.sharedState.get(CRED_ID).asString();
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();
		if (credValue != null) {
			boolean isCredAdded = addCred.addCredential(userName, credValue,STANDARD_OTP,key_store,key_store_pass);
			System.out.println("isCredAdded is "+isCredAdded);
			return goTo(isCredAdded).build();
		}
		return goTo(false).build();
	}

}
