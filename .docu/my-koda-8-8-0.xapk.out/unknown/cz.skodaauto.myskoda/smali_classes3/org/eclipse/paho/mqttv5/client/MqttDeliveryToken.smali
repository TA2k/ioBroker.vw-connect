.class public Lorg/eclipse/paho/mqttv5/client/MqttDeliveryToken;
.super Lorg/eclipse/paho/mqttv5/client/MqttToken;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/IMqttDeliveryToken;


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->getMessage()Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method
