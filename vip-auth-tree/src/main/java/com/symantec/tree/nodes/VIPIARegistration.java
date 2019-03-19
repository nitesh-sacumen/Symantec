package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.TextOutputCallback;
import com.google.common.collect.ImmutableList;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.shared.debug.Debug;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;
import org.forgerock.util.Strings;
import org.forgerock.util.i18n.PreferredLocales;
import com.symantec.tree.config.Constants.VIPIA;
import com.symantec.tree.request.util.DenyRisk;
import static com.symantec.tree.config.Constants.*;

/**
 * 
 * @author Sacumen (www.sacumen.com)
 * 
 * Executes Deny Risk request.
 * 
 * This node having TRUE/FALSE outcome.True outcome means user has denied risk successfully with "0000" status code.
 * False outcome means request has failed with other then "0000" status code.
 * 
 * True outcome is connected to "VIP IA Collect Auth Data" and false outcome is connected to "Failure". 
 *
 */
@Node.Metadata(outcomeProvider = VIPIARegistration.SymantecOutcomeProvider.class, configClass = VIPIARegistration.Config.class)
public class VIPIARegistration implements Node {
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPIARegistration";
	private final Debug debug = Debug.getInstance("VIP");
	private DenyRisk denyRisk;

	/**
	 * Configuration for the node.
	 */
	public interface Config {
	}

	/**
	 * Create the node.
	 */
	@Inject
	public VIPIARegistration(DenyRisk denyRisk) {
		this.denyRisk = denyRisk;
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
		FALSE

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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIARegistration.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")));
		}
	}

	/**
	 * 
	 * @param context
	 * @return sending call backs.
	 * 
	 * Returning Event Id and Device Tag to user to set and get mobile data In case of mobile device.
	 */
	private Action collectAuthData(TreeContext context) {

		//Getting event id and device tag
		String eventId = context.sharedState.get(VIPIA.EVENT_ID).asString();
		String deviceTag = context.sharedState.get(VIPIA.DEVICE_TAG).asString();

		//Sending eventId and deviceTag to the user.
		List<Callback> cbList = new ArrayList<>();
		HiddenValueCallback enterEventId = new HiddenValueCallback(VIPIA.EVENT_ID);
		HiddenValueCallback enterAuthData = new HiddenValueCallback(VIPIA.AUTH_DATA);

		TextOutputCallback displayEventId = new TextOutputCallback(0, "EventId : " + eventId);
		TextOutputCallback displayDeviceTag = new TextOutputCallback(0, "DeviceTag : " + deviceTag);

		cbList.add(displayEventId);
		cbList.add(displayDeviceTag);
		cbList.add(enterEventId);
		cbList.add(enterAuthData);
		return send(ImmutableList.copyOf(cbList)).build();
	}

	/**
	 * Main logic of the node
	 * 
	 * @throws NodeProcessException
	 * 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		
		//Getting auth data through mobile.
		String mobileAuthData = context.sharedState.get(VIPIA.MOBILE_AUTH_DATA).asString();

		if (mobileAuthData != null) {
			
			//Execute Deny Risk for mobile
			return processForMobile(context);
		} else {
			
			//Execute Deny Risk for Web
			return processForWeb(context);
		}

	}

	private Action processForWeb(TreeContext context) throws NodeProcessException {
		debug.message("VIP registration for web flow.......");

		JsonValue sharedState = context.sharedState;

		//Getting Auth Data in case of Web
		Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue)
				.filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));

		if (result.isPresent()) {
			
			// Adding auth data to shared state
			debug.message("auth data in IA Registration is " + result.get());
			sharedState.put(VIPIA.DEVICE_FINGERPRINT, result.get());

			//Getting device friendly name
			String deviceFriendlyName = VIPIA.DEVICE_FRIENDLY_NAME;
			
			//Executing Deny Risk request
			String status = denyRisk.denyRisk(sharedState.get(SharedStateConstants.USERNAME).asString(),
					sharedState.get(VIPIA.EVENT_ID).asString(), sharedState.get(VIPIA.DEVICE_FINGERPRINT).asString(),
					deviceFriendlyName, sharedState.get(KEY_STORE_PATH).asString(),
					sharedState.get(KEY_STORE_PASS).asString());

			debug.message("status in vip ia registration is " + status);

			// Making decision based on Deny Risk request response
			if (status.equals(VIPIA.REGISTERED)) {
				return goTo(Symantec.TRUE).replaceSharedState(sharedState).build();
			} else {
				return goTo(Symantec.FALSE).build();
			}

		} else {
            
			// Getting script to set Auth data
			String setAuthData = String.format(setAuthDataScriptString(sharedState.get(VIPIA.DEVICE_TAG).asString(),
					sharedState.get(VIPIA.SCRIPT_URL).asString()));

			debug.message("setAuthData script is " + setAuthData);

			//Script output call back to execute script on forgerock platform
			ScriptTextOutputCallback setAuthDataScriptOutputCallback = new ScriptTextOutputCallback(setAuthData);

			//Hidden value call back to get Auth Data
			HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);

			//Sending callbacks
			ImmutableList<Callback> callbacks = ImmutableList.of(hiddenValueCallback, setAuthDataScriptOutputCallback);
            return send(callbacks).build();
		}
	}

	private Action processForMobile(TreeContext context) throws NodeProcessException {

		debug.message("vip registration for Mobile..........");
		JsonValue sharedState = context.sharedState;

		if (!context.getCallbacks(HiddenValueCallback.class).isEmpty()) {
			
			//Getting Auth Data and event Id in case of Mobile
			String eventID = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
			String authData = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();

			debug.message("event id is " + eventID);
			debug.message("auth data is " + authData);

			//Getting device friendly name
			String deviceFriendlyName = VIPIA.DEVICE_FRIENDLY_NAME;

			//Executing deny Risk request
			String status = denyRisk.denyRisk(sharedState.get(SharedStateConstants.USERNAME).asString(), eventID,
					authData, deviceFriendlyName, sharedState.get(KEY_STORE_PATH).asString(),
					sharedState.get(KEY_STORE_PASS).asString());

			debug.message("status in vip ia registration is " + status);

			//Making decision based on Deny Risk request response.
			if (status.equals(VIPIA.REGISTERED)) {
				return goTo(Symantec.TRUE).build();
			} 
			else {
				return goTo(Symantec.FALSE).build();
			} 
		} else {
			
			//Sending callback to the user to get event Id and Auth data.
			return collectAuthData(context);
		}

	}

	private String setAuthDataScriptString(String deviceTag, String ScriptURL) {
		return "var loadJS = function(url, implementationCode, location){\r\n"
				+ "    var scriptTag = document.createElement('script');\r\n" + "    scriptTag.src = url;\r\n"
				+ "    scriptTag.onload = implementationCode;\r\n"
				+ "    scriptTag.onreadystatechange = implementationCode;\r\n"
				+ "    location.appendChild(scriptTag);\r\n" + "};\r\n" + "var yourCodeToBeCalled = function(){\r\n"
				+ "IaDfp.writeTag(" + "\"" + deviceTag + "\"" + ",true);\r\n"
				+ "document.getElementById('deviceFingerprint').setAttribute('value',IaDfp.readFingerprint());\r\n"
				+ "}\r\n" + "loadJS(" + "\"" + ScriptURL + "\"" + ", yourCodeToBeCalled, document.body);";
	}
}
