.class public interface abstract Lorg/eclipse/paho/mqttv5/client/MqttCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract authPacketArrived(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
.end method

.method public abstract connectComplete(ZLjava/lang/String;)V
.end method

.method public abstract deliveryComplete(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
.end method

.method public abstract disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V
.end method

.method public abstract messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
.end method

.method public abstract mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
.end method
