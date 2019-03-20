package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;

import org.apache.commons.codec.binary.Base64;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPDR;
import com.symantec.tree.request.util.DeviceHygieneVerification;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;

@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VIPDRDataCollector.Config.class)
public class VIPDRDataCollector extends AbstractDecisionNode {
	private final Debug debug = Debug.getInstance("VIP");
	private DeviceHygieneVerification deviceHygieneVerification;


	public interface Config {
	}

	@Inject
	public VIPDRDataCollector(@Assisted Config config, DeviceHygieneVerification deviceHygieneVerification) {
		this.deviceHygieneVerification = deviceHygieneVerification;
	}

	private Action collectOTP(TreeContext context) {
		List<Callback> cbList = new ArrayList<>();
		
		HiddenValueCallback ncbp = new HiddenValueCallback(VIPDR.VIP_DR_DATA_PAYLOAD);
		HiddenValueCallback ncbh = new HiddenValueCallback(VIPDR.VIP_DR_DATA_HEADER);
		HiddenValueCallback ncbs = new HiddenValueCallback(VIPDR.VIP_DR_DATA_SIGNATURE);

		cbList.add(ncbp);
		cbList.add(ncbh);
		cbList.add(ncbs);
		return send(ImmutableList.copyOf(cbList)).build();
	}

	@Override
	public Action process(TreeContext context) throws NodeProcessException {
		debug.message("Collecting DR Data..........");
		JsonValue sharedState = context.sharedState;
		if(!context.getCallbacks(HiddenValueCallback.class).isEmpty()) {
			String payload = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
			String header = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();
			String signature = context.getCallbacks(HiddenValueCallback.class).get(2).getValue();
			
			debug.message("encoded dr data payload is "+payload);
			debug.message("encoded dr data header is "+header);
			debug.message("encoded dr data signature is "+signature);
			
			String[] result = deviceHygieneVerification.validateDHSignatureAndChain(header, payload, signature);
			
			if(!result[0].equals(VIPDR.DEVICE_HYGIENE_VERIFICATION_SUCCESS_MSG) && !result[1].equals(VIPDR.DEVICE_HYGIENE_VERIFICATION_WITH_VIP_SUCCESS_MSG)) {
				return goTo(false).build();

			}

            byte[] DecodedDRData = Base64.decodeBase64(payload);
			
			debug.message("Decoded DR Data is "+DecodedDRData);
			
			String str1 = new String(DecodedDRData);
			ObjectMapper mapper = new ObjectMapper();
			try {
				JsonNode JsonDRData = mapper.readTree(str1);
				JsonDRData.fieldNames().forEachRemaining(key -> {
					debug.message("key and value in DR Json is, key: "+key+" value: "+JsonDRData.get(key).toString());
					sharedState.put(key,JsonDRData.get(key).toString());
				});
			} catch (IOException e) {
				e.printStackTrace();
			}

			return goTo(true).replaceSharedState(sharedState).build();

		}else {
			return collectOTP(context);
		}
	}
}
