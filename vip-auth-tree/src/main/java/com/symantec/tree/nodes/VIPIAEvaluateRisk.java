package com.symantec.tree.nodes;

import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.request.util.EvaluateRisk;
import com.symantec.tree.request.util.GetVIPServiceURL;
import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;

import javax.inject.Inject;
import static com.symantec.tree.config.Constants.*;

/**
 * 
 * @author Sacumen (www.sacumen.com) <br> <br>
 * @category Node
 * 
 * Execute Evaluate Risk API to Evaluate Risk for new device through Auth Data.
 * 
 * Node with TRUE/FALSE/ERROR outcome. True outcome means user has authenticated successfully with "0000" status code.
 * False outcome means user has not authenticated with "6009" status code.
 * Error outcome means user has not authenticated but the status code is other than "6009".
 *
 * True outcome is connected to "VIP Risk Score Decision Node" and false outcome is connected to "VIP IA Registration" and Error
 * outcome is connected to "DISPLAY ERROR" nodes.
 */
@Node.Metadata(outcomeProvider = VIPIAEvaluateRisk.SymantecOutcomeProvider.class, configClass = VIPIAEvaluateRisk.Config.class)
public class VIPIAEvaluateRisk implements Node {

	private EvaluateRisk evaluateRisk;
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPIAEvaluateRisk";
    private Logger logger = LoggerFactory.getLogger(VIPIAEvaluateRisk.class);

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * 
	 */
	@Inject
	public VIPIAEvaluateRisk(EvaluateRisk evaluateRisk) {
		this.evaluateRisk = evaluateRisk;
	}

	/**
	 * The possible outcomes for the DisplayCredentail.
	 */
	private enum Symantec {
		/**
		 * Successful.
		 */
		TRUE,
		/**
		 * failed.
		 */
		FALSE,

		/**
		 * Error.
		 */
		ERROR

	}

	private ActionBuilder goTo(Symantec outcome) {
		return Action.goTo(outcome.name());
	}

	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class SymantecOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIAEvaluateRisk.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}

	/**
	 * Main logic of the node.
	 * 
	 * @throws NodeProcessException
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		logger.info("Evaluating IA Request....");
		
		JsonValue sharedState = context.sharedState;
		JsonValue transientState = context.sharedState;
		
		GetVIPServiceURL vip = GetVIPServiceURL.getInstance();
		

		//Getting IP Address.
//		String ip = context.request.clientIp;
//		logger.debug("IP is "+ip);
		
		//Getting Test Agent
		String userAgent = VIPIA.TEST_AGENT;
		
		//Getting Auth data
		String authData = sharedState.get(VIPIA.AUTH_DATA).asString();
		logger.debug("auth data in ia check is "+authData);
        
		// Executing Evaluate Risk API
		HashMap<String, String> evaluateRiskResponseAttribute = evaluateRisk.evaluateRisk(
				vip.getUserName(),"192.168.56.1", authData, userAgent,
				vip.getKeyStorePath(),vip.getKeyStorePasswod());

		//Getting status, event id, device tag and score from Evaluate Risk response.
		String status = evaluateRiskResponseAttribute.get("status");
		
		logger.debug("status is in ia check: " + status);
		logger.debug("EVENT_ID is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.EVENT_ID));
        logger.debug("DEVICE_TAG is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.DEVICE_TAG));
        logger.debug("SCORE is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.SCORE));
		
		sharedState.put(VIPIA.EVENT_ID, evaluateRiskResponseAttribute.get(VIPIA.EVENT_ID));
		sharedState.put(VIPIA.DEVICE_TAG, evaluateRiskResponseAttribute.get(VIPIA.DEVICE_TAG));

		//Making decision according to Evaluate Risk request response.
		if (status.equals(VIPIA.NOT_REGISTERED)) {
            return goTo(Symantec.FALSE).replaceTransientState(transientState).replaceSharedState(sharedState).build();
        }
		else if (status.equals(VIPIA.REGISTERED)) {
			transientState.put(VIPIA.SCORE, evaluateRiskResponseAttribute.get(VIPIA.SCORE));
			return goTo(Symantec.TRUE).replaceSharedState(sharedState).replaceTransientState(transientState).build();
		} 
		else {
            sharedState.put(DISPLAY_ERROR,
					"Could not able to proceed because status of evaluate risk response is " + status);
		    return goTo(Symantec.ERROR).replaceSharedState(sharedState).build();
		 }

	}

}