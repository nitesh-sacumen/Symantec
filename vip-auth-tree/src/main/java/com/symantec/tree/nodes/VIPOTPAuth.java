package com.symantec.tree.nodes;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.sm.RequiredValueValidator;
import com.symantec.tree.request.util.SmsDeviceRegister;
import com.symantec.tree.request.util.VoiceDeviceRegister;

import static org.forgerock.openam.auth.node.api.Action.send;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.forgerock.util.i18n.PreferredLocales;
import com.google.common.collect.ImmutableList;
import org.forgerock.openam.auth.node.api.Action.ActionBuilder;

import javax.inject.Inject;
import javax.security.auth.callback.ChoiceCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.Callback;
import java.util.*;

import static com.symantec.tree.config.Constants.*;

/**
 * 
 * @author Sacumen(www.sacumen.com) <br> <br>
 * @category Node
 * @Descrition "VIP OTPAuth Creds" node with SMS, VOICE, ERROR and TOKEN outcome. If
 *             SMS,TOKEN and VOICE, it will go to "VIP Enter SecurityCode/OTP". If
 *             ERROR, go to "VIP Display Error".
 *
 */
@Node.Metadata(outcomeProvider = VIPOTPAuth.OTPAuthOutcomeProvider.class, configClass = VIPOTPAuth.Config.class)
public class VIPOTPAuth implements Node {
	static Logger logger = LoggerFactory.getLogger(VIPOTPAuth.class);

	private final Config config;
	private VoiceDeviceRegister voiceDeviceRegister;
	private SmsDeviceRegister smsDeviceRegister;
	private static final String BUNDLE = "com/symantec/tree/nodes/VIPOTPAuth";

	/**
	 * Configuration for the node.
	 */
	public interface Config {
		@Attribute(order = 100, validators = { RequiredValueValidator.class })
		default Map<Integer, String> referrerCredList() {
			return Collections.emptyMap();
		}

	}

	/**
	 * Create the node.
	 * 
	 * @param config The service config.
	 */
	@Inject
	public VIPOTPAuth(@Assisted Config config, VoiceDeviceRegister voiceDeviceRegister,
			SmsDeviceRegister smsDeviceRegister) {
		this.config = config;
		this.voiceDeviceRegister = voiceDeviceRegister;
		this.smsDeviceRegister = smsDeviceRegister;
	}

	/**
	 * Main logic of the node.
	 */
	@Override
	public Action process(TreeContext context) {
		logger.info("Selecting option from SMS/VOICE/TOKEN");
		JsonValue sharedState = context.sharedState;
		String userName = context.sharedState.get(SharedStateConstants.USERNAME).asString();
		String credValue = context.sharedState.get(MOB_NUM).asString();
		String key_store = context.sharedState.get(KEY_STORE_PATH).asString();
		String key_store_pass = context.sharedState.get(KEY_STORE_PASS).asString();

		return context.getCallback(ChoiceCallback.class).map(c -> c.getSelectedIndexes()[0]).map(Integer::new)
				.filter(choice -> -1 < choice && choice < 3).map(choice -> {
					sharedState.put(CRED_CHOICE, config.referrerCredList().get(choice));
					switch (choice) {

					case 1:
						boolean isOTPVoiceAuthenticated = false;
						try {
						   isOTPVoiceAuthenticated = voiceDeviceRegister.voiceDeviceRegister(userName, credValue,
									key_store, key_store_pass);
						} catch (NodeProcessException e) {
							e.printStackTrace();
						}
						if(isOTPVoiceAuthenticated) {
							return goTo(SymantecOTPAuthOutcome.VOICE).replaceSharedState(sharedState).build();
						}else {
							context.sharedState.put(DISPLAY_ERROR,"There is error to Send OTP through Voice, either Authenticate with other credentials or contact to admin. ");
							return goTo(SymantecOTPAuthOutcome.ERROR).replaceSharedState(sharedState).build();
						}
					case 0:
						boolean isOTPSmsAuthenticated = false;
						try {
							isOTPSmsAuthenticated = smsDeviceRegister.smsDeviceRegister(userName, credValue, key_store,
									key_store_pass);
						} catch (NodeProcessException e) {
							e.printStackTrace();
						}
						if(isOTPSmsAuthenticated) {
							return goTo(SymantecOTPAuthOutcome.SMS).replaceSharedState(sharedState).build();
						}else {
							context.sharedState.put(DISPLAY_ERROR,"There is error to Send OTP through SMS, either Authenticate with other credentials or contact to admin. ");
							return goTo(SymantecOTPAuthOutcome.ERROR).replaceSharedState(sharedState).build();
						}
					default:
						return goTo(SymantecOTPAuthOutcome.TOKEN).replaceSharedState(sharedState).build();
						

					}
				}).orElseGet(() -> {
					logger.debug("collecting choice");
					return displayCredentials(context);
				});
	}

	/**
	 * 
	 * @param context
	 * @return list of callbacks.
	 */
	private Action displayCredentials(TreeContext context) {
		List<Callback> cbList = new ArrayList<>(2);
		Collection<String> values = config.referrerCredList().values();
		String[] targetArray = values.toArray(new String[0]);
		String outputError = context.sharedState.get(PUSH_ERROR).asString();
		logger.debug("text block error" + outputError);
		if (outputError == null) {

			ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE,
					getClass().getClassLoader());
			ChoiceCallback ccb = new ChoiceCallback(bundle.getString("callback.creds"), targetArray, 0, false);
			cbList.add(ccb);
		} else {
			TextOutputCallback tcb = new TextOutputCallback(0, outputError);
			ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE,
					getClass().getClassLoader());
			ChoiceCallback ccb = new ChoiceCallback(bundle.getString("callback.creds"), targetArray, 0, false);
			cbList.add(tcb);
			cbList.add(ccb);
		}

		return send(ImmutableList.copyOf(cbList)).build();

	}

	private ActionBuilder goTo(SymantecOTPAuthOutcome outcome) {
		return Action.goTo(outcome.name());
	}

	/**
	 * The possible outcomes for the SymantecVerifyAuth.
	 */
	private enum SymantecOTPAuthOutcome {
		/**
		 * selection for SMS.
		 */
		SMS,
		/**
		 * selection for VOICE.
		 */
		VOICE,
		/**
		 * selection for TOKEN.
		 */
		TOKEN,
		
		/**
		 * selection for TOKEN.
		 */
		ERROR,

	}

	/**
	 * Defines the possible outcomes from this SymantecOutcomeProvider node.
	 */
	public static class OTPAuthOutcomeProvider implements OutcomeProvider {
		@Override
		public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
			ResourceBundle bundle = locales.getBundleInPreferredLocale(VIPOTPAuth.BUNDLE,
					OTPAuthOutcomeProvider.class.getClassLoader());
			return ImmutableList.of(new Outcome(SymantecOTPAuthOutcome.SMS.name(), bundle.getString("smsOutcome")),
					new Outcome(SymantecOTPAuthOutcome.VOICE.name(), bundle.getString("voiceOutcome")),
					new Outcome(SymantecOTPAuthOutcome.TOKEN.name(), bundle.getString("tokenOutcome")),
			        new Outcome(SymantecOTPAuthOutcome.ERROR.name(),bundle.getString("errorOutcome")));
		}
	}
}