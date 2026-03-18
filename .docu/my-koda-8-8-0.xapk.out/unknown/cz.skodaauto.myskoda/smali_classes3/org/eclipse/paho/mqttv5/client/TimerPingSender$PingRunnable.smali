.class Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/eclipse/paho/mqttv5/client/TimerPingSender;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "PingRunnable"
.end annotation


# static fields
.field private static final methodName:Ljava/lang/String; = "PingTask.run"


# instance fields
.field final synthetic this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;


# direct methods
.method private constructor <init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;-><init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)V

    return-void
.end method


# virtual methods
.method public run()V
    .locals 6

    .line 1
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    new-instance v2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v3, "MQTT Ping: "

    .line 16
    .line 17
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 21
    .line 22
    invoke-static {v3}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$0(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 37
    .line 38
    invoke-static {v1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$1(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$2()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 47
    .line 48
    .line 49
    move-result-wide v3

    .line 50
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    const-string v4, "PingTask.run"

    .line 59
    .line 60
    const-string v5, "660"

    .line 61
    .line 62
    invoke-interface {v1, v2, v4, v5, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;->this$0:Lorg/eclipse/paho/mqttv5/client/TimerPingSender;

    .line 66
    .line 67
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->access$3(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->checkForActivity()Lorg/eclipse/paho/mqttv5/client/MqttToken;

    .line 72
    .line 73
    .line 74
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {p0, v0}, Ljava/lang/Thread;->setName(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return-void
.end method
