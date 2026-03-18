.class public interface abstract Lorg/eclipse/paho/mqttv5/client/IMqttClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract close()V
.end method

.method public abstract connect()V
.end method

.method public abstract connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)V
.end method

.method public abstract connectWithResult(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract disconnect()V
.end method

.method public abstract disconnect(J)V
.end method

.method public abstract disconnectForcibly()V
.end method

.method public abstract disconnectForcibly(J)V
.end method

.method public abstract disconnectForcibly(JJ)V
.end method

.method public abstract getClientId()Ljava/lang/String;
.end method

.method public abstract getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract getServerURI()Ljava/lang/String;
.end method

.method public abstract getTopic(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/MqttTopic;
.end method

.method public abstract isConnected()Z
.end method

.method public abstract messageArrivedComplete(II)V
.end method

.method public abstract publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
.end method

.method public abstract publish(Ljava/lang/String;[BIZ)V
.end method

.method public abstract reconnect()V
.end method

.method public abstract setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
.end method

.method public abstract setManualAcks(Z)V
.end method

.method public abstract subscribe(Ljava/lang/String;I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe(Ljava/lang/String;ILorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Ljava/lang/String;[I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Ljava/lang/String;[I[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract unsubscribe(Ljava/lang/String;)V
.end method

.method public abstract unsubscribe([Ljava/lang/String;)V
.end method
