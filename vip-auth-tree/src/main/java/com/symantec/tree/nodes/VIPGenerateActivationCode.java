package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.config.Constants.VIPSDKStatusCode;
import com.symantec.tree.request.util.GenerateActivationCode;
import com.symantec.tree.request.util.GetVIPServiceURL;

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
    private Logger logger = LoggerFactory.getLogger(VIPGenerateActivationCode.class);

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
    	logger.debug("Collecting activtion code...");

		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();

		// Executing GetActivationCode request
    	String Stat = generateActivationCode.generateCode(vip.getKeyStorePath(),vip.getKeyStorePasswod());
		
    	// Getting GetActivationCode request response
    	String[] array = Stat.split(",");
		for (String s : array)
			logger.debug("Values:" + s);
		String status = array[0];
		String activationCode = array[1];
		
		logger.debug("Status of get Activation_code API call: " + status);
		logger.debug("Activation code is: " + activationCode);
		
		//Making decision based on GetActivationCode request response
		if (status.equalsIgnoreCase(VIPSDKStatusCode.SUCCESS_CODE)) {
			logger.debug("Activation code generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,activationCode);
			return goTo(true).build();

		} else {
			logger.debug("Activation code not generated successfully:" + status);
			context.sharedState.put(ACTIVATION_CODE,"ERROR");
			return goTo(false).build();
		}
    	              	
    }
	
}