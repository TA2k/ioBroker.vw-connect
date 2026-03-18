.class public Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/logging/Logger;


# instance fields
.field private catalogID:Ljava/lang/String;

.field private julLogger:Ljava/util/logging/Logger;

.field private logMessageCatalog:Ljava/util/ResourceBundle;

.field private loggerName:Ljava/lang/String;

.field private resourceName:Ljava/lang/String;

.field private traceMessageCatalog:Ljava/util/ResourceBundle;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 6
    .line 7
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logMessageCatalog:Ljava/util/ResourceBundle;

    .line 8
    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->traceMessageCatalog:Ljava/util/ResourceBundle;

    .line 10
    .line 11
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->catalogID:Ljava/lang/String;

    .line 12
    .line 13
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->resourceName:Ljava/lang/String;

    .line 14
    .line 15
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->loggerName:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method public static dumpMemoryTrace47(Ljava/util/logging/Logger;)V
    .locals 5

    .line 1
    if-eqz p0, :cond_2

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/logging/Logger;->getHandlers()[Ljava/util/logging/Handler;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    array-length v1, v0

    .line 8
    const/4 v2, 0x0

    .line 9
    :goto_0
    if-lt v2, v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/util/logging/Logger;->getParent()Ljava/util/logging/Logger;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->dumpMemoryTrace47(Ljava/util/logging/Logger;)V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    aget-object v3, v0, v2

    .line 20
    .line 21
    instance-of v4, v3, Ljava/util/logging/MemoryHandler;

    .line 22
    .line 23
    if-eqz v4, :cond_1

    .line 24
    .line 25
    monitor-enter v3

    .line 26
    :try_start_0
    move-object p0, v3

    .line 27
    check-cast p0, Ljava/util/logging/MemoryHandler;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/util/logging/MemoryHandler;->push()V

    .line 30
    .line 31
    .line 32
    monitor-exit v3

    .line 33
    return-void

    .line 34
    :catchall_0
    move-exception p0

    .line 35
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    throw p0

    .line 37
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_2
    return-void
.end method

.method private getResourceMessage(Ljava/util/ResourceBundle;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    :try_start_0
    invoke-virtual {p1, p2}, Ljava/util/ResourceBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/util/MissingResourceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    return-object p2
.end method

.method private logToJsr47(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 0

    .line 1
    const-string p4, "====="

    .line 2
    .line 3
    invoke-virtual {p6, p4}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result p4

    .line 7
    if-nez p4, :cond_0

    .line 8
    .line 9
    invoke-direct {p0, p5, p6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->getResourceMessage(Ljava/util/ResourceBundle;Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p4

    .line 13
    invoke-static {p4, p7}, Ljava/text/MessageFormat;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p6

    .line 17
    :cond_0
    new-instance p4, Ljava/util/logging/LogRecord;

    .line 18
    .line 19
    new-instance p5, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    iget-object p7, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->resourceName:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {p7}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p7

    .line 27
    invoke-direct {p5, p7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string p7, ": "

    .line 31
    .line 32
    invoke-static {p5, p7, p6}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p5

    .line 36
    invoke-direct {p4, p1, p5}, Ljava/util/logging/LogRecord;-><init>(Ljava/util/logging/Level;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p4, p2}, Ljava/util/logging/LogRecord;->setSourceClassName(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p4, p3}, Ljava/util/logging/LogRecord;->setSourceMethodName(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->loggerName:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p4, p1}, Ljava/util/logging/LogRecord;->setLoggerName(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    if-eqz p8, :cond_1

    .line 51
    .line 52
    invoke-virtual {p4, p8}, Ljava/util/logging/LogRecord;->setThrown(Ljava/lang/Throwable;)V

    .line 53
    .line 54
    .line 55
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 56
    .line 57
    invoke-virtual {p0, p4}, Ljava/util/logging/Logger;->log(Ljava/util/logging/LogRecord;)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method private mapJULLevel(I)Ljava/util/logging/Level;
    .locals 0

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return-object p0

    .line 6
    :pswitch_0
    sget-object p0, Ljava/util/logging/Level;->FINEST:Ljava/util/logging/Level;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_1
    sget-object p0, Ljava/util/logging/Level;->FINER:Ljava/util/logging/Level;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_2
    sget-object p0, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_3
    sget-object p0, Ljava/util/logging/Level;->CONFIG:Ljava/util/logging/Level;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_4
    sget-object p0, Ljava/util/logging/Level;->INFO:Ljava/util/logging/Level;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_5
    sget-object p0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_6
    sget-object p0, Ljava/util/logging/Level;->SEVERE:Ljava/util/logging/Level;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public config(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x4

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public config(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x4

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public config(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x4

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public dumpTrace()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->dumpMemoryTrace47(Ljava/util/logging/Logger;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x5

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x5

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x5

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finer(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x6

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finer(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x6

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finer(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x6

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finest(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x7

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finest(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x7

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public finest(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x7

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public formatMessage(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 0

    .line 1
    :try_start_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logMessageCatalog:Ljava/util/ResourceBundle;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ljava/util/ResourceBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0
    :try_end_0
    .catch Ljava/util/MissingResourceException; {:try_start_0 .. :try_end_0} :catch_0

    .line 7
    return-object p0

    .line 8
    :catch_0
    return-object p1
.end method

.method public info(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x3

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public info(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x3

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public info(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x3

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public initialise(Ljava/util/ResourceBundle;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logMessageCatalog:Ljava/util/ResourceBundle;

    .line 2
    .line 3
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->traceMessageCatalog:Ljava/util/ResourceBundle;

    .line 4
    .line 5
    iput-object p3, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->resourceName:Ljava/lang/String;

    .line 6
    .line 7
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->loggerName:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {p2}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 10
    .line 11
    .line 12
    move-result-object p2

    .line 13
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 14
    .line 15
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logMessageCatalog:Ljava/util/ResourceBundle;

    .line 16
    .line 17
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->traceMessageCatalog:Ljava/util/ResourceBundle;

    .line 18
    .line 19
    const-string p2, "0"

    .line 20
    .line 21
    invoke-virtual {p1, p2}, Ljava/util/ResourceBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->catalogID:Ljava/lang/String;

    .line 26
    .line 27
    return-void
.end method

.method public isLoggable(I)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->mapJULLevel(I)Ljava/util/logging/Level;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {v0, p0}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 9

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->mapJULLevel(I)Ljava/util/logging/Level;

    .line 2
    .line 3
    .line 4
    move-result-object v1

    .line 5
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 6
    .line 7
    invoke-virtual {p1, v1}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->catalogID:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logMessageCatalog:Ljava/util/ResourceBundle;

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    move-object v2, p2

    .line 19
    move-object v3, p3

    .line 20
    move-object v6, p4

    .line 21
    move-object v7, p5

    .line 22
    move-object v8, p6

    .line 23
    invoke-direct/range {v0 .. v8}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logToJsr47(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public setResourceName(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->resourceName:Ljava/lang/String;

    .line 2
    .line 3
    return-void
.end method

.method public severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x1

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x1

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public severe(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x1

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public trace(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 9

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->mapJULLevel(I)Ljava/util/logging/Level;

    .line 2
    .line 3
    .line 4
    move-result-object v1

    .line 5
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->julLogger:Ljava/util/logging/Logger;

    .line 6
    .line 7
    invoke-virtual {p1, v1}, Ljava/util/logging/Logger;->isLoggable(Ljava/util/logging/Level;)Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->catalogID:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v5, p0, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->traceMessageCatalog:Ljava/util/ResourceBundle;

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    move-object v2, p2

    .line 19
    move-object v3, p3

    .line 20
    move-object v6, p4

    .line 21
    move-object v7, p5

    .line 22
    move-object v8, p6

    .line 23
    invoke-direct/range {v0 .. v8}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->logToJsr47(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/ResourceBundle;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    return-void
.end method

.method public warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v1, 0x2

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    .line 1
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 7

    const/4 v1, 0x2

    const/4 v6, 0x0

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    .line 2
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method

.method public warning(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V
    .locals 7

    const/4 v1, 0x2

    move-object v0, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    move-object v6, p5

    .line 3
    invoke-virtual/range {v0 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/JSR47Logger;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    return-void
.end method
