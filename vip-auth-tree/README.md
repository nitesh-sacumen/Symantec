<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright ${data.get('yyyy')} ForgeRock AS.
-->
# VipAuthTreeNode
A simple authentication node for ForgeRock's Access Manager 6.0 and above.

## Information

VIP Forgerock offers secondary authentication along with the authentication offered by the openam. Following are the authentication mechanisms available: 1) Push 2) OTP

## Installation

The VIP OpenAM tree nodes will be packaged as a jar file using the maven build tool and will be deployed in to the ForgeRock Access Management (AM)6 application WEB-INF/lib folder which is running on tomcat server.

## Steps

1) Configure Maven to be able to access the OpenAM repositories

2) Setup a Maven Project for building the Custom Authentication Node I.e. vip-auth-tree

3) Write the custom logic inside tree nodes to communicate with vip services

4) Change to the root directory of the Maven project of the vip Tree Node Run the mvn package command.

5) The project will generate a .jar file containing our custom nodes I.e . VIP OpenAM Tree Nodes, In the form of vip-auth-tree-1.0.jar.

6) Copy the vip-auth-tree-1.0.jar file to the WEB-INF/lib/ folder where AM is deployed

7) Restart the AM for the new plug-in to become available.

The vip tree nodes are now available in the tree designer to add to authentication trees

Following are the nodes that will be available after deploying the jar file:

![nodes-1](https://user-images.githubusercontent.com/20396535/48183641-6883e600-e355-11e8-8e07-421f399cc55b.PNG)

![nodes-2](https://user-images.githubusercontent.com/20396535/48184091-f01e2480-e356-11e8-8707-962a3fc1110a.PNG)

![display_error](https://user-images.githubusercontent.com/20396535/48692472-2fbcfa00-ebfc-11e8-9570-141944be1d25.PNG)


* VIP DISPLAY ERROR
```js
This node will display error assiciated with exceed attempts of invalid otp. There are no configurable attributes to it.
```

* VIP Add Credential
```js
This node will add credentials as credential id associtaed with user in VIP Database. There are no configurable attributes to it.
```

* VIP Add More Credentials
```js
This node gives you a screen where you can choose yes/no for add more credentilas in VIP. There are no configurable attributes to it.
```

* VIP AddCred with VerifyCode
```js
This node will add credentials as credential id and OTP  or phone number and OTP associtaed with user in VIP Database. There are no configurable attributes to it.
```

* VIP Authenticate Push Credentals
```js
This node will authenticate push credentials during registration.
Attributes to be configured are:
 * Push Display Message Text: The message which should be display on push event. Ex. VIP Push Cred
 * Push Display Message Title: The message title which should be display on push event. Ex. VIP Push
 * Push Display Message Profile. The message profile. Ex www.vip.com
```
![auth-push](https://user-images.githubusercontent.com/20396535/48187242-7c811500-e360-11e8-8bee-a7d7668aed8c.PNG)

* VIP Check Symantec OTP
```js
This node will verify OTP with username. There are no configurable attributes to it.
```

* VIP Display Creds
```js
This node gives you a screen where you need choose your credential type. Where you can choose VIP/SMS/VOICE.
Attributes to be configured are:
 * List of Creds : You need to configure key-value pair as
    0 - VIP
    1 - SMS
    2 - VOICE
```
![display](https://user-images.githubusercontent.com/20396535/48187643-b0106f00-e361-11e8-9d25-e6a6b0b38f49.PNG)


* VIP Enter CredentialID
```js
This node gives you a screen where you need to enter credential id generated on vip app. There are no configurable attributes to it.
```

* VIP Enter Phone Number
```js
This node gives you a screen where you need to enter phone number. There are no configurable attributes to it.
```

* VIP Enter SecurityCode/OTP
```js
This node gives you a screen where you need to enter OTP, which appears on given phone number . There are no configurable attributes to it.
```

* VIP OTPAuth Creds
```js
This node gives you a screen where you need choose your authentication credential type. Where you can choose SMS/VOICE.
Attributes to be configured are:
 * List of Creds : You need to configure key-value pair as
    0 - SMS
    1 - VOICE
```
![otp-auth](https://user-images.githubusercontent.com/20396535/48188130-f914f300-e362-11e8-8a38-61f611ad8450.PNG)


* VIP Poll Push Auth
```js
This node get poll push request status during authentication. There are no configurable attributes to it.
```

* VIP Poll Push Reg
```js
This node get poll push request status during registraton. There are no configurable attributes to it.
```

* VIP Push Auth User
```js
This node will authenticate push credentials during authentication.
Attributes to be configured are:
 * Push Display Message Text: The message which should be display on push event. Ex. VIP Push Cred
 * Push Display Message Title: The message title which should be display on push event. Ex. VIP Push
 * Push Display Message Profile. The message profile. Ex www.vip.com
```
![auth-push-1](https://user-images.githubusercontent.com/20396535/48188528-f8c92780-e363-11e8-95c9-480ee7f63aca.PNG)


* VIP Register User
```js
This node register user in VIP, If user dont exist. There are no configurable attributes to it.
```

* VIP Search User
```js
This node search user in VIP and get user info, if user exits.
Attributes to be configured are:
 * Keystore Path: Path for keystore file.
 * Keystore Password: Password of keystore file.
 * Authentication Service URL: VIP Authentication Service URL
 * Query Service URL: VIP Query Service URL
 * Management Service URL: VIP Management Service URL
```

* VIP Set Configuration
```js
This node search user in VIP and get user info, if user exits.
Attributes to be configured are:
 * Keystore Path: Path for keystore file.
 * Keystore Password: Password of keystore file.
 * Authentication Service URL: VIP Authentication Service URL
 * Query Service URL: VIP Query Service URL
 * Management Service URL: VIP Management Service URL
 * SDK Service URL : Service url to get Activation Code
```

![url_conf](https://user-images.githubusercontent.com/20396535/48860971-68212b80-ede8-11e8-9953-646b9625bb70.PNG)

* VIP DR Data Collector
```js
This node collects DR data(payload, signature, header) in encoded form. There are no configurable attributes to it.
```

* VIP DR Data Eval
```js
This node takes decesion according to json which are coming from from DR Data Collector node. If attribute value in json true then it goes to another node for further verification and if it is false then it goes to success node. 

Attributes to be configured are:
* DR Data Fields : You need to choose field from DR Data JSON, Which you want to evaluate.
```
![p_4](https://user-images.githubusercontent.com/20396535/54487945-edfa4280-48c1-11e9-941b-6faf14cd6bc5.PNG)

* VIP DR OS Decesion Node
```js
This node just verify forDR Data coming from android device or ios device. There are no configurable attributes to it.
```

* VIP IA Authentication
```js
This node execute Evalate Risk request after Deny Risk. There are no configurable attributes to it.
```

* VIP IA Confirm Risk
```js
This node execute Confirm Risk request. There are no configurable attributes to it.
```

* VIP IA Data Collector Node
```js
This node collects Auth Data using HiddenValueCallBack and ScriptTextOutputCallback.

Attributes to be configured are:
* Script : Script URL which will collect Auth Data.
* Is Page Node : If it false then user will not able to see login button on web page, it will be clicked by script and if it is true then login button will appear on web page and user need to click it to navigate next page.
```

![p_5](https://user-images.githubusercontent.com/20396535/54488211-37985c80-48c5-11e9-9e29-40071c1387b1.PNG)

* VIP IA Deny Risk
```js
This node execute Deny Risk request. There are no configurable attributes to it.
```

* VIP IA Evaluate Risk
```js
This node execute Evaluate Risk request. There are no configurable attributes to it.
```

* VIP IA Registration
```js
This node execute Deny Risk request to register new device. There are no configurable attributes to it.
```

* VIP IA Risk Score Decision Node
```js
This node makes decision based on score fetch by evaluate risk api. There are no configurable attributes to it.

Attributes to be configured are:
* low_threshold : Low range of score. By default it is 20.
* high_threshold : High range of score. By default it is 80.
```

![p_6](https://user-images.githubusercontent.com/20396535/54488293-2734b180-48c6-11e9-84b2-34e5b8c78732.PNG)



## Set Logging Level

* User can set log level in forgerock instance, To set user need to follow this path:
```js
DEPLOYMENT-->SERVERS-->LocalInstance-->Debugging
```

![set_logging](https://user-images.githubusercontent.com/20396535/48692807-621b2700-ebfd-11e8-993b-d9f0da2f9191.PNG)

## Configure the trees as follows

 * Navigate to **Realm** > **Authentication** > **Trees** > **Create Tree**
 
 ![tree](https://user-images.githubusercontent.com/20396535/48189113-66c21e80-e365-11e8-8045-326786a41aca.PNG)


## Configuring VIP Auth Tre
```js
this section depicts configuration of VIP Auth Tree
```
* Configure VIP Auth Tree as shown below

![sdk_7](https://user-images.githubusercontent.com/20396535/49303025-a5737080-f4ee-11e8-9f8f-e439b4472729.PNG)


```js
 Nodes To be Configured:
    * VIP Display Creds
    * VIP OTPAuth Creds
    * VIP Authenticate Push Credentials
    * VIP Push Auth User
    * VIP Search User
```

* Now access the protected site by OpenAM

![login](https://user-images.githubusercontent.com/20396535/48189557-7c841380-e366-11e8-8050-f1b54e3d8e1c.PNG)


# VIP SDK Flow

## Nodes For SDK Flow

* VIP SDK Add Credential
```js
This node will add credentials as credential id associtaed with user in VIP Database. There are no configurable attributes to it.
```

* VIP SDK Check Symantec OTP
```js
This node will verify OTP with username.
Attributes to be configured are:
 * Keystore Path: Path for keystore file.
 * Keystore Password: Password of keystore file.
 * Authentication Service URL: VIP Authentication Service URL
```

* VIP Activation Code
```js
This node will get activation code from VIP Service.
Attributes to be configured are:
 * Keystore Path: Path for keystore file.
 * Keystore Password: Password of keystore file.
 * SDK Service URL: VIP SDK Service URL
```

* VIP SDK Enter CredentialID
```js
This node gives you a screen where you need to enter credential id generated on vip app. There are no configurable attributes to it.
```

* VIP SDK Enter SecurityCode/OTP
```js
This node gives you a screen where you need to enter OTP. There are no configurable attributes to it.
```
![sdk_1](https://user-images.githubusercontent.com/20396535/49300307-df8d4400-f4e7-11e8-8a6f-b93881ab74cc.PNG)


## Follow the below steps for VIP SDK Flow using VIP-Auth-tree.

### VIP Get Activation Code

![activation_code](https://user-images.githubusercontent.com/20396535/49300990-94743080-f4e9-11e8-8d48-c3863ff4762a.PNG)

```js
* User uses postman to post to the link of OpenAM and submits username and password in the header
* URL : http://localhost:8080/AM-eval-6.0.0.4/json/realms/root/authenticate?authIndexType=service&authIndexValue=VIP_SDK_GEN_CODE
* Method: POST
* Headers: 
    Accept-API-Version:  resource=2.0, protocol=1.0
    X-OpenAM-Username:  user1
    X-OpenAM-Password:  password123$ 
```

* IF authentication is successful, It gives response like this:

![gen_code](https://user-images.githubusercontent.com/20396535/49301177-051b4d00-f4ea-11e8-9f1d-e37f0ed00a67.PNG)


### VIP SDK Add Credential

![sdk_add_cred](https://user-images.githubusercontent.com/20396535/49301339-63e0c680-f4ea-11e8-8629-e879f2e21972.PNG)

```js
* User uses postman to post to the link of OpenAM and submits username and password in the header
* URL : http://localhost:8080/AM-eval-6.0.0.4/json/realms/root/authenticate?authIndexType=service&authIndexValue=VIP_SDK_Add_Cred
* Method: POST
* Headers: 
    Accept-API-Version:  resource=2.0, protocol=1.0
    X-OpenAM-Username:  user1
    X-OpenAM-Password:  password123$ 
```

* IF authentication is successful,  It gives response prompting for CredentialID

![sdk_2](https://user-images.githubusercontent.com/20396535/49301512-ca65e480-f4ea-11e8-9529-bf3d9f113a80.PNG)

* add the obtained CredentialID to the response body and send it to the same url using this as the request.

![sdk_3](https://user-images.githubusercontent.com/20396535/49301629-13b63400-f4eb-11e8-8477-dcdc168f252d.PNG)

* IF authentication is successful, It gives response like this:

![gen_code](https://user-images.githubusercontent.com/20396535/49301177-051b4d00-f4ea-11e8-9f1d-e37f0ed00a67.PNG)

### VIP SDK Verify OTP

![sdk_4](https://user-images.githubusercontent.com/20396535/49301823-80313300-f4eb-11e8-8c47-28e6e572bce2.PNG)

```js
* User uses postman to post to the link of OpenAM and submits username and password in the header
* URL : http://localhost:8080/AM-eval-6.0.0.4/json/realms/root/authenticate?authIndexType=service&authIndexValue=VIP_SDK_Verify_OTP
* Method: POST
* Headers: 
    Accept-API-Version:  resource=2.0, protocol=1.0
    X-OpenAM-Username:  user1
    X-OpenAM-Password:  password123$ 
```

* IF authentication is successful,  It gives response prompting for Enter SecurityCode/OTP

![sdk_5](https://user-images.githubusercontent.com/20396535/49301999-e6b65100-f4eb-11e8-88ea-69f6941623bd.PNG)

* add the obtained OTP to the response body and send it to the same url using this as the request.

![sdk_6](https://user-images.githubusercontent.com/20396535/49302109-27ae6580-f4ec-11e8-879a-8a632a66495f.PNG)

* IF authentication is successful, It gives response like this:

![gen_code](https://user-images.githubusercontent.com/20396535/49301177-051b4d00-f4ea-11e8-9f1d-e37f0ed00a67.PNG)




        






 




