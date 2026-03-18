.class public Lorg/eclipse/paho/mqttv5/client/TimerPingSender;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttPingSender;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;,
        Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;
    }
.end annotation


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.TimerPingSender"


# instance fields
.field private clientid:Ljava/lang/String;

.field private comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private executorService:Ljava/util/concurrent/ScheduledExecutorService;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private scheduledFuture:Ljava/util/concurrent/ScheduledFuture;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ScheduledFuture<",
            "*>;"
        }
    .end annotation
.end field

.field private timer:Ljava/util/Timer;


# direct methods
.method public constructor <init>(Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    .line 15
    .line 16
    return-void
.end method

.method public static synthetic access$0(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->clientid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$1(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$2()Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->CLASS_NAME:Ljava/lang/String;

    .line 2
    .line 3
    return-object v0
.end method

.method public static synthetic access$3(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;)Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public init(Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 4
    .line 5
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClient()Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-interface {p1}, Lorg/eclipse/paho/mqttv5/client/MqttClientInterface;->getClientId()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->clientid:Ljava/lang/String;

    .line 14
    .line 15
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 16
    .line 17
    invoke-interface {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    const-string p1, "ClientComms cannot be null."

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public schedule(J)V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->timer:Ljava/util/Timer;

    .line 7
    .line 8
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;

    .line 9
    .line 10
    invoke-direct {v2, p0, v1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;-><init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v2, p1, p2}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;

    .line 18
    .line 19
    invoke-direct {v2, p0, v1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;-><init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingRunnable;)V

    .line 20
    .line 21
    .line 22
    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 23
    .line 24
    invoke-interface {v0, v2, p1, p2, v1}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->scheduledFuture:Ljava/util/concurrent/ScheduledFuture;

    .line 29
    .line 30
    return-void
.end method

.method public start()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->clientid:Ljava/lang/String;

    .line 6
    .line 7
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    const-string v3, "start"

    .line 12
    .line 13
    const-string v4, "659"

    .line 14
    .line 15
    invoke-interface {v0, v1, v3, v4, v2}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    .line 19
    .line 20
    if-nez v0, :cond_0

    .line 21
    .line 22
    new-instance v0, Ljava/util/Timer;

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v2, "MQTT Ping: "

    .line 27
    .line 28
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->clientid:Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-direct {v0, v1}, Ljava/util/Timer;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->timer:Ljava/util/Timer;

    .line 44
    .line 45
    new-instance v1, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;

    .line 46
    .line 47
    const/4 v2, 0x0

    .line 48
    invoke-direct {v1, p0, v2}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;-><init>(Lorg/eclipse/paho/mqttv5/client/TimerPingSender;Lorg/eclipse/paho/mqttv5/client/TimerPingSender$PingTask;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 52
    .line 53
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getKeepAlive()J

    .line 54
    .line 55
    .line 56
    move-result-wide v2

    .line 57
    invoke-virtual {v0, v1, v2, v3}, Ljava/util/Timer;->schedule(Ljava/util/TimerTask;J)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :cond_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 62
    .line 63
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getKeepAlive()J

    .line 64
    .line 65
    .line 66
    move-result-wide v0

    .line 67
    invoke-virtual {p0, v0, v1}, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->schedule(J)V

    .line 68
    .line 69
    .line 70
    return-void
.end method

.method public stop()V
    .locals 5

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "661"

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const-string v4, "stop"

    .line 9
    .line 10
    invoke-interface {v0, v1, v4, v2, v3}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->executorService:Ljava/util/concurrent/ScheduledExecutorService;

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->timer:Ljava/util/Timer;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/util/Timer;->cancel()V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/TimerPingSender;->scheduledFuture:Ljava/util/concurrent/ScheduledFuture;

    .line 26
    .line 27
    if-eqz p0, :cond_1

    .line 28
    .line 29
    const/4 v0, 0x1

    .line 30
    invoke-interface {p0, v0}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 31
    .line 32
    .line 33
    :cond_1
    return-void
.end method
