package com.symantec.tree.nodes;

import static org.forgerock.openam.auth.node.api.Action.send;
import org.apache.commons.codec.binary.Base64;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import javax.security.auth.callback.Callback;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.shared.debug.Debug;
import com.symantec.tree.config.Constants.VIPDR;

@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = VIPDRDataCollector.Config.class)
public class VIPDRDataCollector extends SingleOutcomeNode {
	private final Debug debug = Debug.getInstance("VIP");

	public interface Config {
	}

	@Inject
	public VIPDRDataCollector() {
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
	public Action process(TreeContext context) {
		debug.message("Collecting DR Data..........");
		JsonValue sharedState = context.sharedState;
		if(!context.getCallbacks(HiddenValueCallback.class).isEmpty()) {
			String payload = context.getCallbacks(HiddenValueCallback.class).get(0).getValue();
			String header = context.getCallbacks(HiddenValueCallback.class).get(1).getValue();
			String signature = context.getCallbacks(HiddenValueCallback.class).get(2).getValue();
			
			debug.message("encoded dr data payload is "+payload);
			debug.message("encoded dr data header is "+header);
			debug.message("encoded dr data signature is "+signature);


			
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

			return goToNext().replaceSharedState(sharedState).build();

		}else {
			return collectOTP(context);
		}
	}
}
