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


@Node.Metadata(outcomeProvider = VIPIARegistration.SymantecOutcomeProvider.class, configClass = VIPIARegistration.Config.class)
public class VIPIARegistration implements Node{
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
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPIARegistration.BUNDLE,
					SymantecOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(Symantec.TRUE.name(), bundle.getString("trueOutcome")),
					new Outcome(Symantec.FALSE.name(), bundle.getString("falseOutcome")),
					new Outcome(Symantec.ERROR.name(), bundle.getString("errorOutcome")));
		}
	}
	
	/**
	 * 
	 * @param context
	 * @return sending call backs.
	 */
	private Action collectAuthData(TreeContext context) {
		
		String eventId = context.sharedState.get(VIPIA.EVENT_ID).asString();
		String deviceTag = context.sharedState.get(VIPIA.DEVICE_TAG).asString();
		
		List<Callback> cbList = new ArrayList<>();
		HiddenValueCallback enterEventId = new HiddenValueCallback(VIPIA.EVENT_ID);
		HiddenValueCallback enterAuthData = new HiddenValueCallback(VIPIA.AUTH_DATA);
		
		TextOutputCallback displayEventId = new TextOutputCallback(0,"EventId : "+eventId);
		TextOutputCallback displayDeviceTag = new TextOutputCallback(0,"DeviceTag : "+deviceTag);
		
		cbList.add(displayEventId);
		cbList.add(displayDeviceTag);
        cbList.add(enterEventId);
		cbList.add(enterAuthData);
		return send(ImmutableList.copyOf(cbList)).build();
	}
	
	/**
	 * Main logic of the node
	 * @throws NodeProcessException 
	 */
	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		String mobileAuthData = context.sharedState.get(VIPIA.MOBILE_AUTH_DATA).asString();
		
		if(mobileAuthData!=null) {
			return processForMobile(context);
		}else {
			return processForWeb(context);
		}
		
	}
	
  private Action processForWeb(TreeContext context) throws NodeProcessException {
	  debug.message("VIP registration for web flow.......");
	  
      JsonValue sharedState = context.sharedState;  

	  Optional<String> result = context.getCallback(HiddenValueCallback.class).map(HiddenValueCallback::getValue).filter(scriptOutput -> !Strings.isNullOrEmpty(scriptOutput));
      
	  if (result.isPresent()) {
		  debug.message("auth data in IA Registration is "+result.get());
		  sharedState.put(VIPIA.DEVICE_FINGERPRINT, result.get());
		  
          String deviceFriendlyName=VIPIA.DEVICE_FRIENDLY_NAME;
			String status = denyRisk.denyRisk(sharedState.get(IA_SERVICE_URL).asString(),
					sharedState.get(SharedStateConstants.USERNAME).asString(),
					sharedState.get(VIPIA.EVENT_ID).asString(), 
					sharedState.get(VIPIA.DEVICE_FINGERPRINT).asString(),
					deviceFriendlyName,sharedState.get(KEY_STORE_PATH).asString(),sharedState.get(KEY_STORE_PASS).asString());

			debug.message("status in vip ia registration is "+status);
			
			if(status.equals(VIPIA.REGISTERED)) {
				return goTo(Symantec.TRUE).replaceSharedState(sharedState).build();
			}
			else {
				return goTo(Symantec.FALSE).build();
			}
		}     
      else{
    
      String setAuthData = 	String.format(setAuthDataScriptString(sharedState.get(VIPIA.DEVICE_TAG).asString(),sharedState.get(VIPIA.SCRIPT_URL).asString())); 
      
      debug.message("setAuthData script is "+setAuthData);
	  
      ScriptTextOutputCallback setAuthDataScriptOutputCallback =
              new ScriptTextOutputCallback(setAuthData);
      
	  HiddenValueCallback hiddenValueCallback = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);

      ImmutableList<Callback> callbacks = ImmutableList.of(hiddenValueCallback,setAuthDataScriptOutputCallback);

      return send(callbacks).build();
     }
}

private Action processForMobile(TreeContext context) throws NodeProcessException {
	
	debug.message("vip registration for Mobile..........");
	JsonValue sharedState = context.sharedState;
	
	if(!context.getCallbacks(HiddenValueCallback.class).isEmpty()) {
		String eventID = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
		String authData = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();
		
		debug.message("event id is "+eventID);
		debug.message("auth data is "+authData);
		
		String deviceFriendlyName=VIPIA.DEVICE_FRIENDLY_NAME;
		
		String status = denyRisk.denyRisk(sharedState.get(IA_SERVICE_URL).asString(),sharedState.get(SharedStateConstants.USERNAME).asString(), eventID, authData,
				deviceFriendlyName,sharedState.get(KEY_STORE_PATH).asString(),sharedState.get(KEY_STORE_PASS).asString());
		
		debug.message("status in vip ia registration is "+status);

		if(status.equals(VIPIA.REGISTERED)) {
			return goTo(Symantec.TRUE).build();
		}
		else {
			return goTo(Symantec.FALSE).build();
		}
	}else {
		return collectAuthData(context);
	}
	
}
private String setAuthDataScriptString(String deviceTag,String ScriptURL) {
	return "var loadJS = function(url, implementationCode, location){\r\n" + 
			"    var scriptTag = document.createElement('script');\r\n" + 
			"    scriptTag.src = url;\r\n" + 
			"    scriptTag.onload = implementationCode;\r\n" + 
			"    scriptTag.onreadystatechange = implementationCode;\r\n" + 
			"    location.appendChild(scriptTag);\r\n" + 
			"};\r\n" + 
			"var yourCodeToBeCalled = function(){\r\n" + 
			"IaDfp.writeTag("+"\""+deviceTag+"\""+",true);\r\n" +
			"document.getElementById('deviceFingerprint').setAttribute('value',IaDfp.readFingerprint());\r\n" + 
			"}\r\n" + 
			"loadJS("+"\""+ScriptURL+"\""+", yourCodeToBeCalled, document.body);";
}
}
