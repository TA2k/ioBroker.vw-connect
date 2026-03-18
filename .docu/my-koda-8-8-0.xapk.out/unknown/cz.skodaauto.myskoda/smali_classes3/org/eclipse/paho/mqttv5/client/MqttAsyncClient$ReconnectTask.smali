.class Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;
.super Ljava/util/TimerTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "ReconnectTask"
.end annotation


# static fields
.field private static final methodName:Ljava/lang/String; = "ReconnectTask.run"


# instance fields
.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;


# direct methods
.method private constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    invoke-direct {p0}, Ljava/util/TimerTask;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;-><init>(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$0(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$1()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const-string v2, "ReconnectTask.run"

    .line 12
    .line 13
    const-string v3, "506"

    .line 14
    .line 15
    invoke-interface {v0, v1, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient$ReconnectTask;->this$0:Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;

    .line 19
    .line 20
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;->access$2(Lorg/eclipse/paho/mqttv5/client/MqttAsyncClient;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
