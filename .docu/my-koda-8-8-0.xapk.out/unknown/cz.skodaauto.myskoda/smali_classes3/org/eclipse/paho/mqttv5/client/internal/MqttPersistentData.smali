.class public Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/common/MqttPersistable;


# instance fields
.field private hLength:I

.field private hOffset:I

.field private header:[B

.field private key:Ljava/lang/String;

.field private pLength:I

.field private pOffset:I

.field private payload:[B


# direct methods
.method public constructor <init>(Ljava/lang/String;[BII[BII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->key:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->header:[B

    .line 7
    .line 8
    iput p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->hOffset:I

    .line 9
    .line 10
    iput p4, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->hLength:I

    .line 11
    .line 12
    iput-object p5, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->payload:[B

    .line 13
    .line 14
    iput p6, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->pOffset:I

    .line 15
    .line 16
    iput p7, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->pLength:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public getHeaderBytes()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->header:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getHeaderLength()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->hLength:I

    .line 2
    .line 3
    return p0
.end method

.method public getHeaderOffset()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->hOffset:I

    .line 2
    .line 3
    return p0
.end method

.method public getKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->key:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPayloadBytes()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->payload:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public getPayloadLength()I
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->payload:[B

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->pLength:I

    .line 8
    .line 9
    return p0
.end method

.method public getPayloadOffset()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;->pOffset:I

    .line 2
    .line 3
    return p0
.end method
