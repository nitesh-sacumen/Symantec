package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.authentication.callbacks.ScriptTextOutputCallback;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPIA;


@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = VIPAIDataCollector.Config.class)
public class VIPAIDataCollector extends SingleOutcomeNode {
	private final Debug debug = Debug.getInstance("VIP");
	private final Config config;

	public interface Config {
		
		@Attribute(order = 100, requiredValue = true)
		default String Script() {
			return "";
		};
		
		 @Attribute(order = 200)
	        default boolean PageNode() {
	            return false;
	        }
	}

	@Inject
	public VIPAIDataCollector(@Assisted Config config) {
		this.config = config;
	}

	private Action collectData(TreeContext context) {
		debug.message("Collecting IA Data.......");
		
		debug.message("get ai data script is " + getAuthDataScript(context.sharedState.get(VIPIA.SCRIPT_URL).asString()));
		
		List<Callback> cbList = new ArrayList<>();
		HiddenValueCallback ncb = new HiddenValueCallback(VIPIA.MOBILE_AUTH_DATA);
		HiddenValueCallback hcb = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);
		ScriptTextOutputCallback scb = new ScriptTextOutputCallback(String.format(getAuthDataScript(context.sharedState.get(VIPIA.SCRIPT_URL).asString())));
		cbList.add(ncb);
		cbList.add(hcb);
		cbList.add(scb);
		if(!config.PageNode()) {
			debug.message("Page node is enabled...");
			ScriptTextOutputCallback lscb = new ScriptTextOutputCallback(String.format(VIPIA.DISABLE_LOGIN_BUTTON_SCRIPT));
			cbList.add(lscb);

		}
		return send(ImmutableList.copyOf(cbList)).build();
	}

	@Override
	public Action process(TreeContext context) {
		debug.message("collecting AI DATA..........");
		JsonValue sharedState = context.sharedState;
		sharedState.put(VIPIA.SCRIPT_URL,config.Script());
		if(!context.getCallbacks(HiddenValueCallback.class).isEmpty()&& 
				(!context.getCallbacks(HiddenValueCallback.class).get(0).getValue().equals(VIPIA.MOBILE_AUTH_DATA)||
				!context.getCallbacks(HiddenValueCallback.class).get(1).getValue().equals(VIPIA.DEVICE_FINGERPRINT))) {
			
			String mobileAuthData = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
			String webAuthData = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();
			

		if (!(mobileAuthData.equals(VIPIA.MOBILE_AUTH_DATA))) {
			
			debug.message("Mobile Auth Data is "+mobileAuthData);

			sharedState.put(VIPIA.MOBILE_AUTH_DATA,mobileAuthData);
			sharedState.put(VIPIA.AUTH_DATA, mobileAuthData);
		}
		else{
			debug.message("Web Auth Data "+webAuthData);

			sharedState.put(VIPIA.DEVICE_FINGERPRINT, webAuthData);
			sharedState.put(VIPIA.AUTH_DATA,webAuthData);
		}
	
		return goToNext().build();

	}
		else {
			return collectData(context);
		}

	}
	
	private String getAuthDataScript(String scriptURL) {
		return "var loadJS = function(url, implementationCode, location){\r\n" + 
    			"    var scriptTag = document.createElement('script');\r\n" + 
    			"    scriptTag.src = url;\r\n" + 
    			"    scriptTag.onload = implementationCode;\r\n" + 
    			"    scriptTag.onreadystatechange = implementationCode;\r\n" + 
    			"    location.appendChild(scriptTag);\r\n" + 
    			"};\r\n" + 
    			"var yourCodeToBeCalled = function(){\r\n" + 
    			"document.getElementById('deviceFingerprint').setAttribute('value',IaDfp.readFingerprint());\r\n" + 
    			"}\r\n" + 
    			"loadJS("+"\""+scriptURL+"\""+", yourCodeToBeCalled, document.body);";
	}
}