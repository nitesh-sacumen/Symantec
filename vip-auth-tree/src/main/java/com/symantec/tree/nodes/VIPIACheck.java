package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.request.util.EvaluateRisk;

import com.google.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
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
 * @author Sacumen (www.sacumen.com) <br>
 *         <br>
 * @category Node
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
		@Attribute(order = 100, requiredValue = true)
		String Key_Store_Path();

		@Attribute(order = 200, requiredValue = true)
		String Key_Store_Password();

		@Attribute(order = 300, requiredValue = true)
		String Service_URL();
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

		sharedState.put(KEY_STORE_PATH, config.Key_Store_Path());
		sharedState.put(KEY_STORE_PASS, config.Key_Store_Password());
		sharedState.put(IA_SERVICE_URL, config.Service_URL());

		InetAddress localhost=null;
		try {
			localhost = InetAddress.getLocalHost();
		} catch (UnknownHostException e) {
			new NodeProcessException(e.getLocalizedMessage());
		}
		String ip = localhost.getHostAddress().trim();
		String userAgent = VIPIA.TEST_AGENT;
		String authData = sharedState.get(VIPIA.AUTH_DATA).asString();
		
		debug.message("auth data in ia check is "+authData);

		HashMap<String, String> evaluateRiskResponseAttribute = evaluateRisk.evaluateRisk(config.Service_URL(),
				sharedState.get(SharedStateConstants.USERNAME).asString(), ip, authData, userAgent,
				config.Key_Store_Path(), config.Key_Store_Password());

		String status = evaluateRiskResponseAttribute.get("status");
		debug.message("status is in ia check: " + status);
		
		debug.message("EVENT_ID is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.EVENT_ID));

		debug.message("DEVICE_TAG is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.DEVICE_TAG));

		debug.message("SCORE is in ia check: " + evaluateRiskResponseAttribute.get(VIPIA.SCORE));


		if (status.equals(VIPIA.NOT_REGISTERED)) {
			sharedState.put(VIPIA.EVENT_ID, evaluateRiskResponseAttribute.get(VIPIA.EVENT_ID));
			sharedState.put(VIPIA.DEVICE_TAG, evaluateRiskResponseAttribute.get(VIPIA.DEVICE_TAG));

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