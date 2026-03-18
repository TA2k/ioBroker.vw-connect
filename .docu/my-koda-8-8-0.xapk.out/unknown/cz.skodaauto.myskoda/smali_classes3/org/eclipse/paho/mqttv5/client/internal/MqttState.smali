.class public interface abstract Lorg/eclipse/paho/mqttv5/client/internal/MqttState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public abstract checkForActivity(Lorg/eclipse/paho/mqttv5/client/MqttActionListener;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
.end method

.method public abstract connected()V
.end method

.method public abstract disconnected(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
.end method

.method public abstract getActualInFlight()I
.end method

.method public abstract getDebug()Ljava/util/Properties;
.end method

.method public abstract getIncomingMaximumPacketSize()Ljava/lang/Long;
.end method

.method public abstract getOutgoingMaximumPacketSize()Ljava/lang/Long;
.end method

.method public abstract notifyQueueLock()V
.end method

.method public abstract notifyReceivedBytes(I)V
.end method

.method public abstract notifySentBytes(I)V
.end method

.method public abstract persistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
.end method

.method public abstract quiesce(J)V
.end method

.method public abstract resolveOldTokens(Lorg/eclipse/paho/mqttv5/common/MqttException;)Ljava/util/Vector;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lorg/eclipse/paho/mqttv5/common/MqttException;",
            ")",
            "Ljava/util/Vector<",
            "Lorg/eclipse/paho/mqttv5/client/MqttToken;",
            ">;"
        }
    .end annotation
.end method

.method public abstract send(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
.end method

.method public abstract unPersistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
.end method
