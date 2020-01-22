/*
 *     Copyright 2016 IBM Corp.
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 */

package com.ibm.mobilefirstplatform.serversdk.java.push;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.mobilefirstplatform.serversdk.java.push.exception.PushServerSDKException;
import java.security.KeyStoreException;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.ssl.SSLContextBuilder;

/**
 * This class is used to send notifications from a Java server to mobile devices
 * using the Push Notification service.
 */
public class PushNotifications {
	public static final String US_SOUTH_REGION = ".ng.bluemix.net";
	public static final String UK_REGION = ".eu-gb.bluemix.net";
	public static final String SYDNEY_REGION = ".au-syd.bluemix.net";
	//public static final String FRANKFURT_REGION = ".eu-de.bluemix.net";
	public static final String FRANKFURT_REGION = ".cloud.ibm.com";
	public static final String US_EAST_REGION = ".us-east.bluemix.net";
	public static final String JP_TOK = ".jp-tok.bluemix.net";


	public static final Logger logger = Logger.getLogger(PushNotifications.class.getName());

	protected static String secret;
	
	protected static String apiKeyIdIs;
	
	protected static long apiKeyExpireyTime;
	
	protected static String accessToken;
	
	protected static String iamRegion = ".eu-de.bluemix.net";

	protected static String pushMessageEndpointURL;

	private static  PushNotificationsResponseListener pushListner;
	
	/**
	 * Overrides default server host with the provided host. It
	 * {@code overrideServerHost} can be used for dedicated service and
	 * overrides default host with dedicated service host.
	 * 
	 */
	public static String overrideServerHost = null;

	/**
	 * Specify the credentials and Bluemix region for your push notification
	 * service. Also if you are using dedicated service, use overrideServerHost.
	 * 
	 * @param tenantId
	 *            The tenant ID for the Bluemix application that the Push
	 *            Notifications service is bound to.
	 * @param pushSecret
	 *            The credential required for Push Notifications service
	 *            authorization.
	 * @param bluemixRegion
	 *            The Bluemix region where the Push Notifications service is
	 *            hosted. For example, US_SOUTH_REGION.
	 */
	public static void init(String tenantId, String pushSecret, String bluemixRegion) {
		secret = pushSecret;

		createPushEndPointUrl(tenantId, bluemixRegion);

	}

	private static void createPushEndPointUrl(String tenantId, String bluemixRegion) {
		if (overrideServerHost != null) {
			pushMessageEndpointURL = overrideServerHost + PushConstants.URL + tenantId + PushConstants.API;
                        pushMessageEndpointURL = pushMessageEndpointURL.replace("﻿imfpush.eu-de.bluemix.net", "﻿eu-de.imfpush.cloud.ibm.com");
		} else {
			if (bluemixRegion.equals(JP_TOK)) {
				pushMessageEndpointURL = PushConstants.JPHOST + PushConstants.URL + tenantId + PushConstants.API;
			} else {
				pushMessageEndpointURL = PushConstants.HOST + bluemixRegion + PushConstants.URL + tenantId 
				+ PushConstants.API;
                                pushMessageEndpointURL = pushMessageEndpointURL.replace("﻿imfpush.eu-de.bluemix.net", "﻿eu-de.imfpush.cloud.ibm.com");
			}
		}
	}

	/**
	 * If your application server is running on Bluemix, and your push
	 * notification service is bound to your application, you can use this
	 * method for initialization which will get the credentials from Bluemix's
	 * environment variables.
	 * 
	 * @param bluemixRegion
	 *            The Bluemix region where the Push Notifications service is
	 *            hosted. For example, US_SOUTH_REGION.
	 * 
	 * @throws IllegalArgumentException
	 *             If either the push application ID or the secret is not found
	 *             in the environment variables.
	 */
	public static void init(String bluemixRegion) {
		String tenantId = null;
		String pushSecret = null;

		tenantId = getApplicationIdFromVCAP();
		pushSecret = getPushSecretFromVCAP();

		if (tenantId != null && pushSecret != null) {
			init(tenantId, pushSecret, bluemixRegion);
		} else {
			PushServerSDKException exception = new PushServerSDKException(PushConstants.PushServerSDKExceptions.PUSH_INIT_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);
			throw exception;
		}
	}
	
	public static void initWithApiKey(String tenantId, String apiKeyId, String bluemixRegionn) {
		String tenantIdIs = tenantId;
		apiKeyIdIs = apiKeyId;

		if(tenantIdIs == null) {
			tenantIdIs = getApplicationIdFromVCAP();	
		}
		
		if (apiKeyIdIs == null) {
			apiKeyIdIs = getPushApiKeyFromVCAP();	
		}
		if (tenantId != null && apiKeyId != null) {
			createPushEndPointUrl(tenantId, bluemixRegionn);
		} else {
			PushServerSDKException exception = new PushServerSDKException(PushConstants.PushServerSDKExceptions.PUSH_INIT_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);
			throw exception;
		}
		System.out.println(bluemixRegionn);
		iamRegion = bluemixRegionn;
	}
	
	public static CloseableHttpResponse getAuthToken() {
		//HttpClientBuilder httpClientBuilder = HttpClientBuilder.create().useSystemProperties();
                //2020-01-20
                String proxyHost = null;
                String proxyPort = null;
                String proxyType = null;

                proxyHost = System.getProperty("https.proxyHost");
                proxyPort = System.getProperty("https.proxyPort");
                proxyType = "http";
                
                // 2017-12-14: Proxy terminiert https selbst und leite http weiter? TLS termination proxy
                // System.getProperty("https.isTlsTerminationProxy");
                String isTlsTerminationProxy = System.getProperty("https.isTlsTerminationProxy");

                if( isTlsTerminationProxy != null && "true".equals( isTlsTerminationProxy ) ){
                   // System.out.println("using proxy: is TLS termination proxy");
                    proxyType = "http";
                }
//                
//                HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
//                httpClientBuilder.setProxy(new HttpHost(proxyHost, Integer.valueOf(proxyPort), proxyType));
//                
//                    if(PushConstants.IAM_URI.startsWith("https://")){
//                    try {
//                        SSLContextBuilder builder = new SSLContextBuilder();
////				builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
//                        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
//                                NoopHostnameVerifier.INSTANCE);
//                        httpClientBuilder.setSSLSocketFactory(sslsf);
//                    } catch (NoSuchAlgorithmException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    } catch (KeyManagementException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    }
//                    }
System.out.println("use proxy "+ proxyHost + " port " + proxyPort + " type " + proxyType);
                
                CloseableHttpClient httpClient = HttpsSSLClient.createSSLInsecureClient();
                //CloseableHttpClient httpClient = httpClientBuilder.build();
                String iamUri = PushConstants.IAM_URI + iamRegion + PushConstants.IAM_TOKEN_PATH;
                System.out.println("iam uri");
                System.out.println(iamUri);
                HttpPost pushPost = new HttpPost(iamUri);
                            HttpHost proxy = new HttpHost(proxyHost, NumberParser.parseInt(proxyPort,80), proxyType);
            
            RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
            pushPost.setConfig(config);
                pushPost.addHeader(HTTP.CONTENT_TYPE, PushConstants.IAM_CONTENT_TYPE);
                List <NameValuePair> nvps = new ArrayList <NameValuePair>();
                nvps.add(new BasicNameValuePair(PushConstants.GRANT_TYPE, PushConstants.GRANT_TYPE_VALUE_APIKEY));
                nvps.add(new BasicNameValuePair("apikey", apiKeyIdIs));
                try {
                    pushPost.setEntity(new UrlEncodedFormEntity(nvps,  PushConstants.UTFEIGHT));
                    return httpClient.execute(pushPost);
                } catch (IOException e) {
                    logger.log(Level.SEVERE, e.toString(), e);
                    throw  new PushServerSDKException(PushConstants.PushServerSDKExceptions.IAM_FAILURE_EXCEPTION, e);
                }
		
	}

	protected static String getApplicationIdFromVCAP() {
		String vcapServicesAsString = getEnvironmentVariable(PushConstants.VCAP_SERVICES);

		if (vcapServicesAsString != null) {
			JSONObject vcapServices = new JSONObject(vcapServicesAsString);

			if (vcapServices.has(PushConstants.IMFPUSH)) {
				JSONObject imfPushCredentials = vcapServices.getJSONArray(PushConstants.IMFPUSH).optJSONObject(0)
						.optJSONObject(PushConstants.CREDENTIALS);

				if (imfPushCredentials != null) {
					return imfPushCredentials.optString(PushConstants.APPGUID);
				}
			}
		}
		return null;
	}

	protected static String getEnvironmentVariable(String name) {
		return System.getenv(name);
	}

	protected static String getPushSecretFromVCAP() {
		String vcapServicesAsString = getEnvironmentVariable(PushConstants.VCAP_SERVICES);

		if (vcapServicesAsString != null) {
			JSONObject vcapServices = new JSONObject(vcapServicesAsString);

			if (vcapServices.has(PushConstants.IMFPUSH)) {
				JSONObject imfPushCredentials = vcapServices.getJSONArray(PushConstants.IMFPUSH).optJSONObject(0)
						.optJSONObject(PushConstants.CREDENTIALS);

				if (imfPushCredentials != null) {
					return imfPushCredentials.optString(PushConstants.APPSECRET);
				}
			}
		}

		return null;
	}
	
	protected static String getPushApiKeyFromVCAP() {
		String vcapServicesAsString = getEnvironmentVariable(PushConstants.VCAP_SERVICES);

		if (vcapServicesAsString != null) {
			JSONObject vcapServices = new JSONObject(vcapServicesAsString);

			if (vcapServices.has(PushConstants.IMFPUSH)) {
				JSONObject imfPushCredentials = vcapServices.getJSONArray(PushConstants.IMFPUSH).optJSONObject(0)
						.optJSONObject(PushConstants.CREDENTIALS);

				if (imfPushCredentials != null) {
					return imfPushCredentials.optString(PushConstants.APIKEY);
				}
			}
		}

		return null;
	}

	/**
	 * Send the given push notification, as configured, to devices using the
	 * Push Notification service.
	 * 
	 * @param notification
	 *            The push notification to be sent.
	 * @param listener
	 *            Optional PushNotificationsResponseListener to listen to the
	 *            result of this operation.
	 */
	public static void send(Notification notification, PushNotificationsResponseListener listener) throws Exception{
		pushListner = listener;
		if (pushMessageEndpointURL == null || pushMessageEndpointURL.length() == 0) {
			Throwable exception = new RuntimeException(PushConstants.PushServerSDKExceptions.NULL_NOTIFICATION_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);
			
			if (listener != null) {
				listener.onFailure(null, null, exception);
			}
			return;
		}

		if (notification == null) {
			Throwable exception = new IllegalArgumentException(PushConstants.PushServerSDKExceptions.NULL_NOTIFICATION_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);
			if (listener != null) {
				listener.onFailure(null, null, exception);
			}
			return;
		}
                
		CloseableHttpClient httpClient = enableTLS();
                

		
		PushMessageModel model = new PushMessageModel.Builder().message(notification.getMessage())
				.target(notification.getTarget()).settings(notification.getSettings()).build();

		JSONObject notificationJson = generateJSON(model);
//		notificationJson.put("warningId", 1);
//                notificationJson.put("type", "FOOD");
		HttpPost pushPost = null;

		pushPost = createPushPostRequest(notificationJson);
                
               pushPost.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 Firefox/26.0");
                logger.log(Level.INFO, notificationJson.toString());
		executePushPostRequest(pushPost, httpClient, listener);
		

        
        
        }
	
	public static void sendBulk(Notification[] notifications, PushNotificationsResponseListener listener)  throws Exception{
		
		pushListner = listener;
		if (pushMessageEndpointURL == null || pushMessageEndpointURL.length() == 0) {
			Throwable exception = new RuntimeException(PushConstants.PushServerSDKExceptions.NOT_PROPERLY_INITIALIZED_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);

			if (listener != null) {
				listener.onFailure(null, null, exception);
			}
			return;
		}

		if (notifications.length == 0) {
			Throwable exception = new IllegalArgumentException(PushConstants.PushServerSDKExceptions.NULL_NOTIFICATION_EXCEPTION);
			logger.log(Level.SEVERE, exception.toString(), exception);
			if (listener != null) {
				listener.onFailure(null, null, exception);
			}
			return;
		}

		CloseableHttpClient httpClient = enableTLS();

		
		List<JSONObject> MessageJson = new ArrayList<JSONObject>();
		for (Notification notification: notifications){
			
			PushMessageModel model = new PushMessageModel.Builder().message(notification.getMessage())
					.target(notification.getTarget()).settings(notification.getSettings()).build();

			JSONObject notificationJson = generateJSON(model);
			MessageJson.add(notificationJson);
		}
		
		
		HttpPost pushPost = createBulkPushPostRequest(MessageJson);

                pushPost.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 Firefox/26.0");     
                String proxyHost = null;
                String proxyPort = null;
                String proxyType = null;

                proxyHost = System.getProperty("https.proxyHost");
                proxyPort = System.getProperty("https.proxyPort");
                proxyType = "http";
                
                // 2017-12-14: Proxy terminiert https selbst und leite http weiter? TLS termination proxy
                // System.getProperty("https.isTlsTerminationProxy");
                String isTlsTerminationProxy = System.getProperty("https.isTlsTerminationProxy");

                if( isTlsTerminationProxy != null && "true".equals( isTlsTerminationProxy ) ){
                   // System.out.println("using proxy: is TLS termination proxy");
                    proxyType = "http";
                }
                HttpHost proxy = new HttpHost(proxyHost, NumberParser.parseInt(proxyPort,80), proxyType);
            
                RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
                pushPost.setConfig(config);
                
		executePushPostRequest(pushPost, httpClient, listener);
	}

	private static CloseableHttpClient enableTLS() throws Exception {
		CloseableHttpClient httpClient = null;
		SSLContext sslContext = null;
		try {
			sslContext = SSLContext.getInstance(PushConstants.TLS_VERSION);
			sslContext.init(null, null, null);
			httpClient = HttpClients.custom().setUserAgent("my UserAgent 5.0").setSSLContext(sslContext).build();
		} catch (NoSuchAlgorithmException e) {
			logger.log(Level.SEVERE, e.toString(), e);
		} catch (KeyManagementException e) {
			logger.log(Level.SEVERE, e.toString(), e);
		}
		return httpClient;
//		HttpClientBuilder httpClientBuilder = HttpClientBuilder.create().useSystemProperties();
//                
//                try {
//				SSLContextBuilder builder = new SSLContextBuilder();
//				builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
//				SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
//						NoopHostnameVerifier.INSTANCE);
//				httpClientBuilder.setSSLSocketFactory(sslsf);
//			
//
//                    CloseableHttpClient httpClient = httpClientBuilder.build();
//                     return httpClient;
//                }
//                catch(Exception ex){
//                   
//                      throw ex;
//                        }

               //return HttpsSSLClient.createSSLInsecureClient();
               
               
	}

	/**
	 * API converts object to json format.
	 * 
	 * @param obj
	 *            The object which needs to be serialized as json string.
	 * 
	 * @return Return a JSONOject for the passed object.
	 */
	private static JSONObject generateJSON(Object obj) {

		ObjectMapper mapper = new ObjectMapper();

		String jsonString = null;
		try {
			mapper.setSerializationInclusion(Include.NON_EMPTY);
			jsonString = mapper.writeValueAsString(obj);

		} catch (JsonProcessingException exception) {

			logger.log(Level.SEVERE, exception.toString(), exception);
		}

		JSONObject json = jsonString != null ? new JSONObject(jsonString) : new JSONObject();
		
		if (json.has("settings")) {
			
			JSONObject settingsJson = json.getJSONObject("settings");
			if(settingsJson.has("fcm")) {
				settingsJson.put("gcm", settingsJson.getJSONObject("fcm"));
				settingsJson.remove("fcm");
			}
		}

		return json;
	}

	protected static HttpPost createPushPostRequest(JSONObject notification)  {
String proxyHost = null;
                String proxyPort = null;
                String proxyType = null;

                proxyHost = System.getProperty("https.proxyHost");
                proxyPort = System.getProperty("https.proxyPort");
                proxyType = "http";
                
                // 2017-12-14: Proxy terminiert https selbst und leite http weiter? TLS termination proxy
                // System.getProperty("https.isTlsTerminationProxy");
                String isTlsTerminationProxy = System.getProperty("https.isTlsTerminationProxy");

                if( isTlsTerminationProxy != null && "true".equals( isTlsTerminationProxy ) ){
                   // System.out.println("using proxy: is TLS termination proxy");
                    proxyType = "http";
                }
//                
//                HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
//                httpClientBuilder.setProxy(new HttpHost(proxyHost, Integer.valueOf(proxyPort), proxyType));
//                
//                    if(PushConstants.IAM_URI.startsWith("https://")){
//                    try {
//                        SSLContextBuilder builder = new SSLContextBuilder();
////				builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
//                        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
//                                NoopHostnameVerifier.INSTANCE);
//                        httpClientBuilder.setSSLSocketFactory(sslsf);
//                    } catch (NoSuchAlgorithmException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    } catch (KeyManagementException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    }
//                    }
            System.out.println("use proxy "+ proxyHost + " port " + proxyPort + " type " + proxyType);

                            CloseableHttpClient httpClient = HttpsSSLClient.createSSLInsecureClient();
                            //CloseableHttpClient httpClient = httpClientBuilder.build();
                            String iamUri = PushConstants.IAM_URI + iamRegion + PushConstants.IAM_TOKEN_PATH;
                            System.out.println("iam uri in create push");
                            System.out.println(iamUri);
                            System.out.println(pushMessageEndpointURL);
                            HttpPost pushPost = new HttpPost(pushMessageEndpointURL);
                            if(proxyHost !=null){
                                        HttpHost proxy = new HttpHost(proxyHost, NumberParser.parseInt(proxyPort,80), proxyType);

                RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
                pushPost.setConfig(config);

                            }
            

		pushPost.addHeader(HTTP.CONTENT_TYPE, PushConstants.CONTENT_TYPE);
		pushPost.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 Firefox/26.0");     
		setHeader(pushPost);
                System.out.println("headers set");
                System.out.println(notification.toString());
		StringEntity body = new StringEntity(notification.toString(), PushConstants.UTFEIGHT);
		pushPost.setEntity(body);

		return pushPost;
	}
	
	protected static HttpPost createBulkPushPostRequest(List<JSONObject> messageJson) {
            String proxyHost = null;
                String proxyPort = null;
                String proxyType = null;

                proxyHost = System.getProperty("https.proxyHost");
                proxyPort = System.getProperty("https.proxyPort");
                proxyType = "http";
                
                // 2017-12-14: Proxy terminiert https selbst und leite http weiter? TLS termination proxy
                // System.getProperty("https.isTlsTerminationProxy");
                String isTlsTerminationProxy = System.getProperty("https.isTlsTerminationProxy");

                if( isTlsTerminationProxy != null && "true".equals( isTlsTerminationProxy ) ){
                   // System.out.println("using proxy: is TLS termination proxy");
                    proxyType = "http";
                }
//                
//                HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
//                httpClientBuilder.setProxy(new HttpHost(proxyHost, Integer.valueOf(proxyPort), proxyType));
//                
//                    if(PushConstants.IAM_URI.startsWith("https://")){
//                    try {
//                        SSLContextBuilder builder = new SSLContextBuilder();
////				builder.loadTrustMaterial(null, new TrustSelfSignedStrategy());
//                        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(builder.build(),
//                                NoopHostnameVerifier.INSTANCE);
//                        httpClientBuilder.setSSLSocketFactory(sslsf);
//                    } catch (NoSuchAlgorithmException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    } catch (KeyManagementException ex) {
//                        Logger.getLogger(PushNotifications.class.getName()).log(Level.SEVERE, null, ex);
//                    }
//                    }
            System.out.println("use proxy "+ proxyHost + " port " + proxyPort + " type " + proxyType);

                            CloseableHttpClient httpClient = HttpsSSLClient.createSSLInsecureClient();
                            //CloseableHttpClient httpClient = httpClientBuilder.build();
                            String iamUri = PushConstants.IAM_URI + iamRegion + PushConstants.IAM_TOKEN_PATH;
                            System.out.println("iam uri");
                            System.out.println(iamUri);
                           HttpPost pushPost = new HttpPost(pushMessageEndpointURL + "/bulk");
if(proxyHost !=null){
                                        HttpHost proxy = new HttpHost(proxyHost, NumberParser.parseInt(proxyPort,80), proxyType);

                RequestConfig config = RequestConfig.custom().setProxy(proxy).build();
                pushPost.setConfig(config);
}
		pushPost.setHeader(HttpHeaders.USER_AGENT, "Mozilla/5.0 Firefox/26.0");     
		pushPost.addHeader(HTTP.CONTENT_TYPE, PushConstants.CONTENT_TYPE);
		setHeader(pushPost);
		
		StringEntity body = new StringEntity(messageJson.toString(), PushConstants.UTFEIGHT);
		pushPost.setEntity(body);

		return pushPost;
	}

	private static void setHeader(HttpPost pushPost) {
		if (secret != null) {
                    System.out.println("add secret "+secret);
			pushPost.addHeader(PushConstants.APPSECRET, secret);
		} else {
			CloseableHttpResponse auth = null;
			try {
				if (accessToken == null || (apiKeyExpireyTime - (System.currentTimeMillis() / 1000)) < 0) {
                                    System.out.println("has no access token or expired");
					auth = getAuthToken();
//                                        try {
//
//                                            HttpEntity entity = auth.getEntity();
//
//                                            // Read the contents of an entity and return it as a String.
//                                            String content = EntityUtils.toString(entity);
//                                            System.out.println(content);
//
//                                        } catch (IOException e) {
//                                            e.printStackTrace();
//                                        }
System.out.println(auth);
					JSONObject json = null;
					json = new JSONObject(EntityUtils.toString(auth.getEntity()));
                                        System.out.println(json.toString());
					int statusCode = auth.getStatusLine().getStatusCode();
					String resonPhrase = auth.getStatusLine().getReasonPhrase();

					if (statusCode == 200) {
						accessToken = json.getString(PushConstants.ACCESS_TOKEN);
						apiKeyExpireyTime = json.getInt(PushConstants.EXPIRATION);
						pushPost.addHeader(PushConstants.AUTHORIZATION_HEADER,
								PushConstants.BEARER + PushConstants.EMPTY_SPACE + accessToken);
                                                System.out.println("add header access");
                                                System.out.println(PushConstants.AUTHORIZATION_HEADER + " " +PushConstants.BEARER + PushConstants.EMPTY_SPACE + accessToken);
                                                 
					} else {
                                            System.out.println("push failed for "+ auth.getStatusLine().getReasonPhrase());
						PushServerSDKException pushServerSDKException = new PushServerSDKException(resonPhrase);
						if (pushListner != null) {
							pushListner.onFailure(statusCode, pushServerSDKException.getLocalizedMessage(),
									pushServerSDKException);
						}
						throw pushServerSDKException;

					}
				} else {
                                    System.out.println("has auth already use access "+accessToken);
					pushPost.addHeader(PushConstants.AUTHORIZATION_HEADER, "Bearer " + accessToken);
				}
			}  catch (ParseException e) {
				throw new PushServerSDKException(PushConstants.PushServerSDKExceptions.JSON_PARSER_EXCEPTION, e);
			} catch (IOException e) {
				throw  new PushServerSDKException(PushConstants.PushServerSDKExceptions.JSON_IO_EXCEPTION, e);
			} finally {
				if (auth != null) {
					try {
						auth.close();
					} catch (IOException e) {
						logger.log(Level.SEVERE, e.toString(), e);
					}
				}
			}
			

		}
	}


	protected static void executePushPostRequest(HttpPost pushPost, CloseableHttpClient httpClient,
			PushNotificationsResponseListener listener) {
		CloseableHttpResponse response = null;

		try {
			if (httpClient != null && listener != null) {
                                System.out.println("execute");
				response = httpClient.execute(pushPost);
				sendResponseToListener(response, listener);
			} else {
				throw new PushServerSDKException(PushConstants.PushServerSDKExceptions.NOT_PROPERLY_INITIALIZED_EXCEPTION);
			}
		} catch (ClientProtocolException e) {
			logger.log(Level.SEVERE, e.toString(), e);
			if (listener != null) {
				listener.onFailure(null, null, e);
			}
		} catch (IOException e) {
			logger.log(Level.SEVERE, e.toString(), e);
			if (listener != null) {
				listener.onFailure(null, null, e);
			}
		} finally {
			if (response != null) {
				try {
					response.close();
				} catch (IOException e) {
					// Closing response is merely a best effort.
				}
			}

		}
	}

	protected static void sendResponseToListener(CloseableHttpResponse response,
			PushNotificationsResponseListener listener) throws IOException {
		String responseBody = null;

		if (response.getEntity() != null) {
			ByteArrayOutputStream outputAsByteArray = new ByteArrayOutputStream();
			response.getEntity().writeTo(outputAsByteArray);

			responseBody = new String(outputAsByteArray.toByteArray());
                        System.out.println("response has entity");
                        System.out.println(responseBody);
		}

		Integer statusCode = null;

		if (response.getStatusLine() != null) {
			statusCode = response.getStatusLine().getStatusCode();
		}

		if (statusCode != null && statusCode == HttpStatus.SC_ACCEPTED) {
			listener.onSuccess(statusCode, responseBody);
		} else {
			if(statusCode != null && statusCode == 401) {
				accessToken = null;
				logger.log(Level.SEVERE, response.getStatusLine().getReasonPhrase());
			}
			listener.onFailure(statusCode, responseBody, null);
		}
	}
}
