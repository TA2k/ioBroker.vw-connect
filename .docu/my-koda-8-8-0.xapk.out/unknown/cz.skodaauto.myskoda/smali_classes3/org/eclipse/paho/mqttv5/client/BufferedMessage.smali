.class public Lorg/eclipse/paho/mqttv5/client/BufferedMessage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private message:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

.field private token:Lorg/eclipse/paho/mqttv5/client/MqttToken;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->message:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public getMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->message:Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 2
    .line 3
    return-object p0
.end method

.method public getToken()Lorg/eclipse/paho/mqttv5/client/MqttToken;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->token:Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 2
    .line 3
    return-object p0
.end method
