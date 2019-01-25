package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.symantec.tree.config.Constants.VIPSDKStatusCode;
import com.symantec.tree.nodes.VIPSearchUser.Config;
import com.symantec.tree.request.util.GenerateActivationCode;

import org.forgerock.guava.common.base.Strings;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.symantec.tree.config.Constants.*;
import static org.forgerock.openam.auth.node.api.Action.send;

import javax.inject.Inject;
import javax.security.auth.callback.TextOutputCallback;

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
	private final Logger logger = LoggerFactory.getLogger(VIPGenerateActivationCode.class);

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
	 * 
	 * @param context
	 * @return Action
	 * 
	 * Displaying activation code using TextOutputCallback
	 */
	private Action displayActivationCode(TreeContext context) {
		String activationCode=context.sharedState.get(ACTIVATION_CODE).asString();
		TextOutputCallback pcb = new TextOutputCallback(0, activationCode);
		return send(pcb).build();
	}

	/**
	 * Main logic of the node.
	 * @throws NodeProcessException 
	 */
	@Override
	 public Action process(TreeContext context) throws NodeProcessException {
    	logger.info("Inside VIP DISPLAY ERROR Page");
    	String Stat = generateActivationCode.generateCode(config.Key_Store_Path(),config.Key_Store_Password(),config.SDK_Service_URL());
		String[] array = Stat.split(",");
		for (String s : array)
			System.out.println("Values:" + s);
		String status = array[0];
		String activationCode = array[1];
		System.out.println("Status of get Activation_code API call: " + status);
		System.out.println("Activation code is: " + activationCode);
		if (status.equalsIgnoreCase(VIPSDKStatusCode.SUCCESS_CODE)) {
			System.out.println("Activation code generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,activationCode);
			return goTo(true).build();

		} else {
			System.out.println("Activation code not generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,"ERROR");
			return goTo(false).build();
		}
    	
//		return context.getCallback(TextOutputCallback.class).map(TextOutputCallback::getMessage)
//                .map(String::new)
//                .filter(name -> !Strings.isNullOrEmpty(name))
//                .map(name -> {
//                	return goTo(true).build();
//                }).orElseGet(() -> {
//					System.out.println("Displaying Activation Code");
//					return displayActivationCode(context);
//				});
//                	
    }
	
}