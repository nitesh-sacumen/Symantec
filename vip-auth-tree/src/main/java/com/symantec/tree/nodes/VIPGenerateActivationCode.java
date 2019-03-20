package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPSDKStatusCode;
import com.symantec.tree.request.util.GenerateActivationCode;
import org.forgerock.openam.auth.node.api.*;
import static com.symantec.tree.config.Constants.*;
import javax.inject.Inject;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP Activation Code" node with true and false outcome.
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPGenerateActivationCode.Config.class)
public class VIPGenerateActivationCode extends AbstractDecisionNode {

	private GenerateActivationCode generateActivationCode;
	private final Config config;
	private final Debug debug = Debug.getInstance("VIP");

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * 
	 */
	@Inject
	public VIPGenerateActivationCode(@Assisted Config config,GenerateActivationCode generateActivationCode) {
		this.config = config;
		this.generateActivationCode = generateActivationCode;
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	 public Action process(TreeContext context) throws NodeProcessException {
    	debug.message("Collecting activtion code...");
    	String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();

		// Executing GetActivationCode request
    	String Stat = generateActivationCode.generateCode(key_store,key_store_pass);
		
    	// Getting GetActivationCode request response
    	String[] array = Stat.split(",");
		for (String s : array)
			debug.message("Values:" + s);
		String status = array[0];
		String activationCode = array[1];
		
		debug.message("Status of get Activation_code API call: " + status);
		debug.message("Activation code is: " + activationCode);
		
		//Making decision based on GetActivationCode request response
		if (status.equalsIgnoreCase(VIPSDKStatusCode.SUCCESS_CODE)) {
			debug.message("Activation code generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,activationCode);
			return goTo(true).build();

		} else {
			debug.message("Activation code not generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,"ERROR");
			return goTo(false).build();
		}
    	              	
    }
	
}