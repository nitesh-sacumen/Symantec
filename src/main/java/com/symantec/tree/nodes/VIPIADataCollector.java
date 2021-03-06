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
import org.slf4j.Logger;import org.slf4j.LoggerFactory;
import com.symantec.tree.config.Constants.VIPIA;

/**
 * 
 * @author Sacumen(www.sacumen.com)
 * 
 * It collects Auth Data using HiddenValueCallBack and ScriptTextOutputCallback.
 * 
 * In case of mobile Auth data taken using HiddenValueCallback and In case of web Auth data taken using ScriptTextOutputCallback.
 * 
 * Single outcome node, collects data and fetch data to "VIP Evaluate Risk" node.
 *
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = VIPIADataCollector.Config.class)
public class VIPIADataCollector extends SingleOutcomeNode {
    private Logger logger = LoggerFactory.getLogger(VIPIADataCollector.class);
	private final Config config;

	public interface Config {
		
		@Attribute(order = 100, requiredValue = true)
		default String Script() {
			return "";
		}
		
		@Attribute(order = 200)
		default boolean PageNode() {
	            return false;
	        }
	}

	@Inject
	public VIPIADataCollector(@Assisted Config config) {
		this.config = config;
	}

	/**
	 * 
	 * @param context
	 * @return Action
	 * 
	 * Collecting Auth Data.
	 */
	private Action collectData(TreeContext context) {
		logger.info("Collecting IA Data for mobile from callbacks.......");
		
		logger.debug("get ai data script is " + getAuthDataScript(context.sharedState.get(VIPIA.SCRIPT_URL).asString()));
		
		List<Callback> cbList = new ArrayList<>();
		HiddenValueCallback ncb = new HiddenValueCallback(VIPIA.MOBILE_AUTH_DATA);
		HiddenValueCallback hcb = new HiddenValueCallback(VIPIA.DEVICE_FINGERPRINT);
		ScriptTextOutputCallback scb = new ScriptTextOutputCallback(
				getAuthDataScript(context.sharedState.get(VIPIA.SCRIPT_URL).asString()));
		cbList.add(ncb);
		cbList.add(hcb);
		cbList.add(scb);
		if(!config.PageNode()) {
			logger.info("Page node is enabled...");
			ScriptTextOutputCallback lscb = new ScriptTextOutputCallback(VIPIA.DISABLE_LOGIN_BUTTON_SCRIPT);
			cbList.add(lscb);

		}
		return send(ImmutableList.copyOf(cbList)).build();
	}

	/**
	 * Getting data from the callbacks and fetch this to next node.
	 */
	@Override
	public Action process(TreeContext context) {
		logger.info("collecting AI DATA..........");
		
		JsonValue sharedState = context.sharedState;
		sharedState.put(VIPIA.SCRIPT_URL,config.Script());
		
		if(!context.getCallbacks(HiddenValueCallback.class).isEmpty()&& 
				(!context.getCallbacks(HiddenValueCallback.class).get(0).getValue().equals(VIPIA.MOBILE_AUTH_DATA)||
				!context.getCallbacks(HiddenValueCallback.class).get(1).getValue().equals(VIPIA.DEVICE_FINGERPRINT))) {
			
			String mobileAuthData = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
			String webAuthData = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();
			
			logger.debug("mobileAuthData: "+mobileAuthData);
			logger.debug("webAuthData: "+webAuthData);

			if (!(mobileAuthData.equals(VIPIA.MOBILE_AUTH_DATA))) {
			
				logger.debug("Mobile Auth Data is "+mobileAuthData);
				sharedState.put(VIPIA.MOBILE_AUTH_DATA,mobileAuthData);
				sharedState.put(VIPIA.AUTH_DATA, mobileAuthData);
			}
			else {
				logger.debug("Web Auth Data "+webAuthData);
				sharedState.put(VIPIA.DEVICE_FINGERPRINT, webAuthData);
				sharedState.put(VIPIA.AUTH_DATA,webAuthData);
			}
		return goToNext().build();
		}
		else {
			return collectData(context);
		}

	}
	
	/**
	 * 
	 * @param scriptURL JS Script reference.
	 * @return Getting Script to collect auth data.
	 */
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