.class Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/internal/IDisconnectedBufferCallback;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ReconnectDisconnectedBufferCallback"
.end annotation


# instance fields
.field final methodName:Ljava/lang/String;

.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;


# direct methods
.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->methodName:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public publishBufferedMessage(Lorg/eclipse/paho/mqttv5/client/BufferedMessage;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->isConnected()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 10
    .line 11
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$2()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->methodName:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->getMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v3}, Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;->getKey()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v3

    .line 29
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    const-string v4, "510"

    .line 34
    .line 35
    invoke-interface {v0, v1, v2, v4, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 39
    .line 40
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->getMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->getToken()Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-virtual {v0, v1, v2}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->internalSend(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;Lorg/eclipse/paho/mqttv5/client/MqttToken;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 52
    .line 53
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$6(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/internal/ClientState;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/BufferedMessage;->getMessage()Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientState;->unPersistBufferedMessage(Lorg/eclipse/paho/mqttv5/common/packet/MqttWireMessage;)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :cond_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->this$0:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 66
    .line 67
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$1(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->access$2()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms$ReconnectDisconnectedBufferCallback;->methodName:Ljava/lang/String;

    .line 76
    .line 77
    const-string v1, "208"

    .line 78
    .line 79
    invoke-interface {p1, v0, p0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    const/16 p0, 0x7d68

    .line 83
    .line 84
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->createMqttException(I)Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    throw p0
.end method
