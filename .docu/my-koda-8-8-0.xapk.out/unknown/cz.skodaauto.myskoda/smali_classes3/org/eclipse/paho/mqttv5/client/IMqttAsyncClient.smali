.class public interface abstract Lorg/eclipse/paho/mqttv5/client/IMqttAsyncClient;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract authenticate(ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract checkPing(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract close()V
.end method

.method public abstract close(Z)V
.end method

.method public abstract connect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract connect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract connect(Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract deleteBufferedMessage(I)V
.end method

.method public abstract disconnect()Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract disconnect(J)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract disconnect(JLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract disconnect(Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract disconnectForcibly()V
.end method

.method public abstract disconnectForcibly(J)V
.end method

.method public abstract disconnectForcibly(JJILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
.end method

.method public abstract disconnectForcibly(JJZ)V
.end method

.method public abstract getBufferedMessage(I)Lorg/eclipse/paho/mqttv5/common/MqttMessage;
.end method

.method public abstract getBufferedMessageCount()I
.end method

.method public abstract getClientId()Ljava/lang/String;
.end method

.method public abstract getCurrentServerURI()Ljava/lang/String;
.end method

.method public abstract getDebug()Lorg/eclipse/paho/mqttv5/client/util/Debug;
.end method

.method public abstract getInFlightMessageCount()I
.end method

.method public abstract getPendingTokens()[Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract getServerURI()Ljava/lang/String;
.end method

.method public abstract isConnected()Z
.end method

.method public abstract messageArrivedComplete(II)V
.end method

.method public abstract publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract publish(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract publish(Ljava/lang/String;[BIZ)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract publish(Ljava/lang/String;[BIZLjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract reconnect()V
.end method

.method public abstract setBufferOpts(Lorg/eclipse/paho/mqttv5/client/DisconnectedBufferOptions;)V
.end method

.method public abstract setCallback(Lorg/eclipse/paho/mqttv5/client/MqttCallback;)V
.end method

.method public abstract setClientId(Ljava/lang/String;)V
.end method

.method public abstract setManualAcks(Z)V
.end method

.method public abstract subscribe(Ljava/lang/String;I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe(Ljava/lang/String;ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe(Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Ljava/lang/String;[I)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Ljava/lang/String;[ILjava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;[Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract subscribe([Lorg/eclipse/paho/mqttv5/common/MqttSubscription;Lorg/eclipse/paho/mqttv5/client/IMqttMessageListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract unsubscribe(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract unsubscribe(Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract unsubscribe([Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method

.method public abstract unsubscribe([Ljava/lang/String;Ljava/lang/Object;Lorg/eclipse/paho/mqttv5/client/MqttActionListener;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/client/IMqttToken;
.end method
