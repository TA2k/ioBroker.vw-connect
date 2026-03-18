.class public Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;
.super Ljava/io/OutputStream;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.wire.MqttOutputStream"


# instance fields
.field private clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private out:Ljava/io/BufferedOutputStream;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/MqttState;Ljava/io/OutputStream;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/io/OutputStream;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 15
    .line 16
    new-instance p1, Ljava/io/BufferedOutputStream;

    .line 17
    .line 18
    invoke-direct {p1, p2}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    .line 22
    .line 23
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 24
    .line 25
    invoke-interface {p0, p3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public close()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/OutputStream;->close()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public flush()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/io/BufferedOutputStream;->flush()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public write(I)V
    .locals 0

    .line 5
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    invoke-virtual {p0, p1}, Ljava/io/BufferedOutputStream;->write(I)V

    return-void
.end method

.method public write(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V
    .locals 6

    .line 6
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getHeader()[B

    move-result-object v0

    .line 7
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getPayload()[B

    move-result-object v1

    .line 8
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    invoke-interface {v2}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->getOutgoingMaximumPacketSize()Ljava/lang/Long;

    move-result-object v2

    if-eqz v2, :cond_1

    .line 9
    array-length v2, v0

    array-length v3, v1

    add-int/2addr v2, v3

    int-to-long v2, v2

    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    invoke-interface {v4}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->getOutgoingMaximumPacketSize()Ljava/lang/Long;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    move-result-wide v4

    cmp-long v2, v2, v4

    if-gtz v2, :cond_0

    goto :goto_0

    :cond_0
    const p0, 0xc73a

    .line 10
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/common/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    move-result-object p0

    throw p0

    .line 11
    :cond_1
    :goto_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    array-length v3, v0

    const/4 v4, 0x0

    invoke-virtual {v2, v0, v4, v3}, Ljava/io/BufferedOutputStream;->write([BII)V

    .line 12
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    array-length v0, v0

    invoke-interface {v2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifySentBytes(I)V

    .line 13
    :goto_1
    array-length v0, v1

    if-lt v4, v0, :cond_2

    .line 14
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    sget-object v0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->CLASS_NAME:Ljava/lang/String;

    const-string v1, "529"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "write"

    invoke-interface {p0, v0, v2, v1, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 15
    :cond_2
    array-length v0, v1

    sub-int/2addr v0, v4

    const/16 v2, 0x400

    invoke-static {v2, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    .line 16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    invoke-virtual {v2, v1, v4, v0}, Ljava/io/BufferedOutputStream;->write([BII)V

    add-int/lit16 v4, v4, 0x400

    .line 17
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    invoke-interface {v2, v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifySentBytes(I)V

    goto :goto_1
.end method

.method public write([B)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    invoke-virtual {v0, p1}, Ljava/io/OutputStream;->write([B)V

    .line 2
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    array-length p1, p1

    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifySentBytes(I)V

    return-void
.end method

.method public write([BII)V
    .locals 1

    .line 3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->out:Ljava/io/BufferedOutputStream;

    invoke-virtual {v0, p1, p2, p3}, Ljava/io/BufferedOutputStream;->write([BII)V

    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/wire/MqttOutputStream;->clientState:Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    invoke-interface {p0, p3}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->notifySentBytes(I)V

    return-void
.end method
