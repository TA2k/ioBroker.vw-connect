.class Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttCallback;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "MqttReconnectCallback"
.end annotation


# instance fields
.field final automaticReconnect:Z

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-boolean p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->automaticReconnect:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public authPacketArrived(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 0

    .line 1
    return-void
.end method

.method public connectComplete(ZLjava/lang/String;)V
    .locals 0

    .line 1
    return-void
.end method

.method public deliveryComplete(Lorg/eclipse/paho/mqttv5/client/IMqttToken;)V
    .locals 0

    .line 1
    return-void
.end method

.method public disconnected(Lorg/eclipse/paho/mqttv5/client/MqttDisconnectResponse;)V
    .locals 1

    .line 1
    iget-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->automaticReconnect:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 6
    .line 7
    iget-object p1, p1, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    invoke-virtual {p1, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->setRestingState(Z)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 14
    .line 15
    invoke-static {p1, v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$3(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Z)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$MqttReconnectCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 19
    .line 20
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$4(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public messageArrived(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 0

    .line 1
    return-void
.end method

.method public mqttErrorOccurred(Lorg/eclipse/paho/mqttv5/common/MqttException;)V
    .locals 0

    .line 1
    return-void
.end method
