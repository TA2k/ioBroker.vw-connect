.class public interface abstract Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract getActionCallback()Lorg/eclipse/paho/mqttv5/client/MqttActionListener;
.end method

.method public abstract getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;
.end method

.method public abstract getException()Lorg/eclipse/paho/mqttv5/common/MqttException;
.end method

.method public abstract getGrantedQos()[I
.end method

.method public abstract getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
.end method

.method public abstract getMessageId()I
.end method

.method public abstract getReasonCodes()[I
.end method

.method public abstract getRequestMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.end method

.method public abstract getRequestProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
.end method

.method public abstract getResponse()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.end method

.method public abstract getResponseProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
.end method

.method public abstract getSessionPresent()Z
.end method

.method public abstract getTopics()[Ljava/lang/String;
.end method

.method public abstract getUserContext()Ljava/lang/Object;
.end method

.method public abstract isComplete()Z
.end method

.method public abstract setActionCallback(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)V
.end method

.method public abstract setUserContext(Ljava/lang/Object;)V
.end method

.method public abstract waitForCompletion()V
.end method

.method public abstract waitForCompletion(J)V
.end method
