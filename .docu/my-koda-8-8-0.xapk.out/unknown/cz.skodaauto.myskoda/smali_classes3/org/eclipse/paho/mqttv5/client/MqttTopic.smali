.class public Lorg/eclipse/paho/mqttv5/client/MqttTopic;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private name:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 5
    .line 6
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->name:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method

.method private createPublish(Lorg/eclipse/paho/mqttv5/common/MqttMessage;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    .line 2
    .line 3
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-direct {v0, p0, p1, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;-><init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttMessage;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public getName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public publish(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 3

    .line 5
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;

    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    invoke-virtual {v1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    move-result-object v1

    invoke-interface {v1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;-><init>(Ljava/lang/String;)V

    .line 6
    iget-object v1, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->setDeliveryToken(Z)V

    .line 7
    invoke-virtual {v0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttToken;->setMessage(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)V

    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    new-instance v2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {v2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    invoke-direct {p0, p1, v2}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->createPublish(Lorg/eclipse/paho/mqttv5/common/MqttMessage;Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)Lorg/eclipse/paho/mqttv5/common/packet/MqttPublish;

    move-result-object p0

    invoke-virtual {v1, p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->sendNoWait(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 9
    iget-object p0, v0, Lorg/eclipse/paho/mqttv5/client/MqttToken;->internalTok:Lorg/eclipse/paho/mqttv5/client/internal/Token;

    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/Token;->waitUntilSent()V

    return-object v0
.end method

.method public publish([BIZ)Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 1

    .line 1
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttMessage;

    invoke-direct {v0, p1}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;-><init>([B)V

    .line 2
    invoke-virtual {v0, p2}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setQos(I)V

    .line 3
    invoke-virtual {v0, p3}, Lorg/eclipse/paho/mqttv5/common/MqttMessage;->setRetained(Z)V

    .line 4
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->publish(Lorg/eclipse/paho/mqttv5/common/MqttMessage;)Lorg/eclipse/paho/mqttv5/client/MqttToken;

    move-result-object p0

    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/MqttTopic;->getName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
