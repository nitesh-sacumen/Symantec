package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.request.util.EvaluateRisk;

import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.i18n.PreferredLocales;
import java.net.InetAddress;
import java.net.UnknownHostException;
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
@Node.Metadata(outcomeProvider = VIPIACheck.SymantecOutcomeProvider.class, configClass = VIPIACheck.Config.class)
public class VIPIACheck implements Node {

	private EvaluateRisk evaluateRisk;
	private final Config config;
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPIACheck";
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
	public VIPIACheck(@Assisted Config config, EvaluateRisk evaluateRisk) {
		this.config = config;
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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIACheck.BUNDLE,
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
		debug.message("Evaluating IA Request....");
		JsonValue sharedState = context.sharedState;
		JsonValue transientState = context.sharedState;
		
		// Getting ketstore.ks file path and password to execute Symantec APIs.
		String key_store = sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = sharedState.get(KEY_STORE_PASS).asString();

		//Getting IP Address.
		InetAddress localhost=null;
		try {
			localhost = InetAddress.getLocalHost();
		} catch (UnknownHostException e) {
			new NodeProcessException(e.getLocalizedMessage());
		}
		String ip = localhost.getHostAddress().trim();
		
		//Getting Test Agent
		String userAgent = VIPIA.TEST_AGENT;
		
		//Getting Auth data
		String authData = sharedState.get(VIPIA.AUTH_DATA).asString();
		debug.message("auth data in ia check is "+authData);
        
		// Executing Evaluate Risk API
		HashMap<String, String> evaluateRiskResponseAttribute = evaluateRisk.evaluateRisk(
				sharedState.get(SharedStateConstants.USERNAME).asString(), ip, authData, userAgent,
				key_store,key_store_pass);

		//Getting status, event id, device tag and score from Evaluate Risk response.
		String status = evaluateRiskResponseAttribute.get("status");
		
		debug.message("status is in ia check: " + status);
		debug.message("EVENT_ID is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.EVENT_ID));
        debug.message("DEVICE_TAG is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.DEVICE_TAG));
        debug.message("SCORE is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.SCORE));
		
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