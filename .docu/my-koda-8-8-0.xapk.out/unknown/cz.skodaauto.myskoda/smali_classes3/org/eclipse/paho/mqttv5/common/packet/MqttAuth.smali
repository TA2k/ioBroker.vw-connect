.class public Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;
.super Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final validProperties:[Ljava/lang/Byte;

.field private static final validReturnCodes:[I


# instance fields
.field private properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    const/4 v1, 0x1

    .line 5
    const/16 v2, 0x18

    .line 6
    .line 7
    aput v2, v0, v1

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    const/16 v2, 0x19

    .line 11
    .line 12
    aput v2, v0, v1

    .line 13
    .line 14
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validReturnCodes:[I

    .line 15
    .line 16
    const/16 v0, 0x15

    .line 17
    .line 18
    invoke-static {v0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const/16 v1, 0x16

    .line 23
    .line 24
    invoke-static {v1}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    const/16 v2, 0x1f

    .line 29
    .line 30
    invoke-static {v2}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    const/16 v3, 0x26

    .line 35
    .line 36
    invoke-static {v3}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    filled-new-array {v0, v1, v2, v3}, [Ljava/lang/Byte;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sput-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validProperties:[Ljava/lang/Byte;

    .line 45
    .line 46
    return-void
.end method

.method public constructor <init>(ILorg/eclipse/paho/mqttv5/common/packet/MqttProperties;)V
    .locals 1

    const/16 v0, 0xf

    .line 9
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    if-eqz p2, :cond_0

    .line 10
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    goto :goto_0

    .line 11
    :cond_0
    new-instance p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-direct {p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>()V

    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 12
    :goto_0
    iget-object p2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validProperties:[Ljava/lang/Byte;

    invoke-virtual {p2, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->setValidProperties([Ljava/lang/Byte;)V

    .line 13
    sget-object p2, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validReturnCodes:[I

    invoke-virtual {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 14
    iput p1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    return-void
.end method

.method public constructor <init>([B)V
    .locals 2

    const/16 v0, 0xf

    .line 1
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;-><init>(B)V

    .line 2
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validProperties:[Ljava/lang/Byte;

    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;-><init>([Ljava/lang/Byte;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 3
    new-instance v0, Ljava/io/ByteArrayInputStream;

    invoke-direct {v0, p1}, Ljava/io/ByteArrayInputStream;-><init>([B)V

    .line 4
    new-instance p1, Ljava/io/DataInputStream;

    invoke-direct {p1, v0}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 5
    invoke-virtual {p1}, Ljava/io/DataInputStream;->readUnsignedByte()I

    move-result v0

    iput v0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->validReturnCodes:[I

    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->validateReturnCode(I[I)V

    .line 7
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->decodeProperties(Ljava/io/DataInputStream;)V

    .line 8
    invoke-virtual {p1}, Ljava/io/InputStream;->close()V

    return-void
.end method


# virtual methods
.method public getMessageInfo()B
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public getProperties()Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 2
    .line 3
    return-object p0
.end method

.method public getReturnCode()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 2
    .line 3
    return p0
.end method

.method public getVariableHeader()[B
    .locals 3

    .line 1
    :try_start_0
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/io/DataOutputStream;

    .line 7
    .line 8
    invoke-direct {v1, v0}, Ljava/io/DataOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 9
    .line 10
    .line 11
    iget v2, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 12
    .line 13
    invoke-virtual {v1, v2}, Ljava/io/DataOutputStream;->writeByte(I)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 17
    .line 18
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;->encodeProperties()[B

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    invoke-virtual {v1, p0}, Ljava/io/OutputStream;->write([B)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/io/DataOutputStream;->flush()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 29
    .line 30
    .line 31
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    return-object p0

    .line 33
    :catch_0
    move-exception p0

    .line 34
    new-instance v0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 35
    .line 36
    invoke-direct {v0, p0}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    throw v0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MqttAuth [returnCode="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->reasonCode:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", properties="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/common/packet/MqttAuth;->properties:Lorg/eclipse/paho/mqttv5/common/packet/MqttProperties;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "]"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
