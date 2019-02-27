package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPSDKStatusCode;
import com.symantec.tree.request.util.GenerateActivationCode;
import org.forgerock.openam.annotations.sm.Attribute;
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
		@Attribute(order = 100, requiredValue = true)
		String Key_Store_Path();


		@Attribute(order = 200, requiredValue = true)
		String Key_Store_Password();
		
		@Attribute(order = 300, requiredValue = true)
		String SDK_Service_URL();
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
    	String Stat = generateActivationCode.generateCode(config.Key_Store_Path(),config.Key_Store_Password(),config.SDK_Service_URL());
		String[] array = Stat.split(",");
		for (String s : array)
			debug.message("Values:" + s);
		String status = array[0];
		String activationCode = array[1];
		debug.message("Status of get Activation_code API call: " + status);
		debug.message("Activation code is: " + activationCode);
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