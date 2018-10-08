/*
 * Copyright 2010-2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

/**
 * @file subscribe_publish_sample.c
 * @brief simple MQTT publish and subscribe on the same topic
 *
 * This example takes the parameters from the aws_iot_config.h file and establishes a connection to the AWS IoT MQTT Platform.
 * It subscribes and publishes to the same topic - "sdkTest/sub"
 *
 * If all the certs are correct, you should see the messages received by the application in a loop.
 *
 * The application takes in the certificate path, host name , port and the number of times the publish should happen.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

#define HOST_ADDRESS_SIZE 255
/**
 * @brief Default cert location
 */
char certDirectory[PATH_MAX + 1] = "/system/etc/certs";

/**
 * @brief Default MQTT HOST URL is pulled from the aws_iot_config.h
 */
char HostAddress[HOST_ADDRESS_SIZE] = AWS_IOT_MQTT_HOST;

/**
 * @brief Default MQTT port is pulled from the aws_iot_config.h
 */
uint32_t port = AWS_IOT_MQTT_PORT;

/**
 * @brief This parameter will avoid infinite loop of publish and exit the program after certain number of publishes
 */
uint32_t publishCount = 0;

void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData) {
	IOT_UNUSED(pData);
    //	IOT_UNUSED(pClient);
	printf("Subscribe callback\n");
	printf("%.*s\t%.*s\n", topicNameLen, topicName, (int) params->payloadLen, (char *) params->payload);

    char filename[24];
    char cPayload[1024];
	IoT_Publish_Message_Params paramsQOS0;
    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    snprintf(filename, sizeof(filename), "%s.log", (char *) params->payload);
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        return;
    }
    while ((read = getline(&line, &len, fp)) != -1) {

        snprintf(cPayload, sizeof(cPayload), "%s", line); 
        paramsQOS0.qos = QOS0;
        paramsQOS0.payload = (void *) cPayload;
        paramsQOS0.isRetained = 0;
		paramsQOS0.payloadLen = strlen(cPayload);

		aws_iot_mqtt_publish(pClient, "sdkTest/log", 11, &paramsQOS0);

        sleep(1);
    }
    fclose(fp);
    if (line) free(line);
}

void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) {
	printf("MQTT Disconnect\n");
	IoT_Error_t rc = FAILURE;

	if(NULL == pClient) {
		return;
	}

	IOT_UNUSED(data);

	if(aws_iot_is_autoreconnect_enabled(pClient)) {
		printf("Auto Reconnect is enabled, Reconnecting attempt will start now\n");
	} else {
		printf("Auto Reconnect not enabled. Starting manual reconnect...\n");
		rc = aws_iot_mqtt_attempt_reconnect(pClient);
		if(NETWORK_RECONNECTED == rc) {
			printf("Manual Reconnect Successful\n");
		} else {
			printf("Manual Reconnect Failed - %d\n", rc);
		}
	}
}

void parseInputArgsForConnectParams(int argc, char **argv) {
	int opt;

	while(-1 != (opt = getopt(argc, argv, "h:p:c:x:"))) {
		switch(opt) {
			case 'h':
				strncpy(HostAddress, optarg, HOST_ADDRESS_SIZE);
				printf("Host %s\n", optarg);
				break;
			case 'p':
				port = atoi(optarg);
				printf("arg %s\n", optarg);
				break;
			case 'c':
				strncpy(certDirectory, optarg, PATH_MAX + 1);
				printf("cert root directory %s\n", optarg);
				break;
			case 'x':
				publishCount = atoi(optarg);
				printf("publish %s times\n\n", optarg);
				break;
			case '?':
				if(optopt == 'c') {
					printf("Option -%c requires an argument.\n", optopt);
				} else if(isprint(optopt)) {
					printf("Unknown option `-%c'.\n", optopt);
				} else {
					printf("Unknown option character `\\x%x'.\n", optopt);
				}
				break;
			default:
				printf("Error in command line argument parsing\n");
				break;
		}
	}

}

int main(int argc, char **argv) {
	bool infinitePublishFlag = true;

	char rootCA[PATH_MAX + 1];
	char clientCRT[PATH_MAX + 1];
	char clientKey[PATH_MAX + 1];
	char CurrentWD[PATH_MAX + 1];
	char cPayload[100];

	int32_t i = 0;

	IoT_Error_t rc = FAILURE;

	AWS_IoT_Client client;
	IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
	IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

	IoT_Publish_Message_Params paramsQOS0;
	IoT_Publish_Message_Params paramsQOS1;

    printf("Hello World!!!!!\n");

	parseInputArgsForConnectParams(argc, argv);

	printf("\nAWS IoT SDK Version %d.%d.%d-%s\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

	getcwd(CurrentWD, sizeof(CurrentWD));
	snprintf(rootCA, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_ROOT_CA_FILENAME);
	snprintf(clientCRT, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_CERTIFICATE_FILENAME);
	snprintf(clientKey, PATH_MAX + 1, "%s/%s/%s", CurrentWD, certDirectory, AWS_IOT_PRIVATE_KEY_FILENAME);

	printf("rootCA %s\n", rootCA);
	printf("clientCRT %s\n", clientCRT);
	printf("clientKey %s\n", clientKey);
	mqttInitParams.enableAutoReconnect = false; // We enable this later below
	mqttInitParams.pHostURL = HostAddress;
	mqttInitParams.port = port;
	mqttInitParams.pRootCALocation = rootCA;
	mqttInitParams.pDeviceCertLocation = clientCRT;
	mqttInitParams.pDevicePrivateKeyLocation = clientKey;
	mqttInitParams.mqttCommandTimeout_ms = 20000;
	mqttInitParams.tlsHandshakeTimeout_ms = 5000;
	mqttInitParams.isSSLHostnameVerify = true;
	mqttInitParams.disconnectHandler = disconnectCallbackHandler;
	mqttInitParams.disconnectHandlerData = NULL;

	rc = aws_iot_mqtt_init(&client, &mqttInitParams);
	if(SUCCESS != rc) {
		printf("aws_iot_mqtt_init returned error : %d \n", rc);
		return rc;
	}

	connectParams.keepAliveIntervalInSec = 600;
	connectParams.isCleanSession = true;
	connectParams.MQTTVersion = MQTT_3_1_1;
	connectParams.pClientID = AWS_IOT_MQTT_CLIENT_ID;
	connectParams.clientIDLen = (uint16_t) strlen(AWS_IOT_MQTT_CLIENT_ID);
	connectParams.isWillMsgPresent = false;

	printf("Connecting...\n");
	rc = aws_iot_mqtt_connect(&client, &connectParams);
	if(SUCCESS != rc) {
		printf("Error(%d) connecting to %s:%d\n", rc, mqttInitParams.pHostURL, mqttInitParams.port);
		return rc;
	}
	/*
	 * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
	 *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
	 *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
	 */
	rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
	if(SUCCESS != rc) {
		printf("Unable to set Auto Reconnect to true - %d\n", rc);
		return rc;
	}

	printf("Subscribing...\n");
	rc = aws_iot_mqtt_subscribe(&client, "sdkTest/upload", 14, QOS0, iot_subscribe_callback_handler, NULL);
	if(SUCCESS != rc) {
		printf("Error subscribing : %d \n", rc);
		return rc;
	}

    while (true) {
		//Max time the yield function will wait for read messages
		rc = aws_iot_mqtt_yield(&client, 100);
		if(NETWORK_ATTEMPTING_RECONNECT == rc) {
			// If the client is attempting to reconnect we will skip the rest of the loop.
			continue;
		}

        //		printf("-->sleep");
		sleep(1);        
    }

    /*
	sprintf(cPayload, "%s : %d ", "hello from SDK", i);
 
	paramsQOS0.qos = QOS0;
	paramsQOS0.payload = (void *) cPayload;
	paramsQOS0.isRetained = 0;

	paramsQOS1.qos = QOS1;
	paramsQOS1.payload = (void *) cPayload;
	paramsQOS1.isRetained = 0;

	if(publishCount != 0) {
		infinitePublishFlag = false;
	}

	while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc)
		  && (publishCount > 0 || infinitePublishFlag)) {

		//Max time the yield function will wait for read messages
		rc = aws_iot_mqtt_yield(&client, 100);
		if(NETWORK_ATTEMPTING_RECONNECT == rc) {
			// If the client is attempting to reconnect we will skip the rest of the loop.
			continue;
		}

		printf("-->sleep");
		sleep(1);
		sprintf(cPayload, "%s : %d ", "hello from SDK QOS0", i++);
		paramsQOS0.payloadLen = strlen(cPayload);
		rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS0);
		if(publishCount > 0) {
			publishCount--;
		}

		if(publishCount == 0 && !infinitePublishFlag) {
			break;
		}

		sprintf(cPayload, "%s : %d ", "hello from SDK QOS1", i++);
		paramsQOS1.payloadLen = strlen(cPayload);
		rc = aws_iot_mqtt_publish(&client, "sdkTest/sub", 11, &paramsQOS1);
		if (rc == MQTT_REQUEST_TIMEOUT_ERROR) {
			IOT_WARN("QOS1 publish ack not received.\n");
			rc = SUCCESS;
		}
		if(publishCount > 0) {
			publishCount--;
		}
	}
    */

	// Wait for all the messages to be received
	aws_iot_mqtt_yield(&client, 100);

	if(SUCCESS != rc) {
		printf("An error occurred in the loop.\n");
	} else {
		printf("Publish done\n");
	}

	return rc;
}
