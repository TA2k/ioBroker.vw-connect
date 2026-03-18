.class Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;
.super Ljava/util/TimerTask;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/TimerPingSender;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "PingTask"
.end annotation


# static fields
.field private static final methodName:Ljava/lang/String; = "PingTask.run"


# instance fields
.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;


# direct methods
.method private constructor <init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    invoke-direct {p0}, Ljava/util/TimerTask;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;-><init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 5

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "MQTT Ping: "

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 13
    .line 14
    invoke-static {v2}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$0(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 29
    .line 30
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$1(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$2()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 39
    .line 40
    .line 41
    move-result-wide v2

    .line 42
    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    const-string v3, "PingTask.run"

    .line 51
    .line 52
    const-string v4, "660"

    .line 53
    .line 54
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 58
    .line 59
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$3(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->checkForActivity()Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 64
    .line 65
    .line 66
    return-void
.end method
