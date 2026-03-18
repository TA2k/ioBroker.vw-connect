.class public Lorg/eclipse/paho/mqttv5/client/util/Debug;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String;

.field private static final lineSep:Ljava/lang/String;

.field private static final separator:Ljava/lang/String; = "=============="


# instance fields
.field private clientID:Ljava/lang/String;

.field private comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 8
    .line 9
    const-string v0, "line.separator"

    .line 10
    .line 11
    const-string v1, "\n"

    .line 12
    .line 13
    invoke-static {v0, v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->lineSep:Ljava/lang/String;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->clientID:Ljava/lang/String;

    .line 15
    .line 16
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 17
    .line 18
    invoke-interface {v0, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;
    .locals 6

    .line 1
    new-instance v0, Ljava/lang/StringBuffer;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/util/Properties;->propertyNames()Ljava/util/Enumeration;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    new-instance v2, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/util/Debug;->lineSep:Ljava/lang/String;

    .line 13
    .line 14
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v4

    .line 18
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v4, "============== "

    .line 22
    .line 23
    const-string v5, " =============="

    .line 24
    .line 25
    invoke-static {v2, v4, p1, v5, v3}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    invoke-virtual {v0, p1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 30
    .line 31
    .line 32
    :goto_0
    invoke-interface {v1}, Ljava/util/Enumeration;->hasMoreElements()Z

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    if-nez p1, :cond_0

    .line 37
    .line 38
    new-instance p0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string p1, "=========================================="

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/util/Debug;->lineSep:Ljava/lang/String;

    .line 46
    .line 47
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {v0, p0}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :cond_0
    invoke-interface {v1}, Ljava/util/Enumeration;->nextElement()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Ljava/lang/String;

    .line 67
    .line 68
    new-instance v2, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    const/16 v3, 0x1c

    .line 71
    .line 72
    const/16 v4, 0x20

    .line 73
    .line 74
    invoke-static {p1, v3, v4}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->left(Ljava/lang/String;IC)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    const-string v3, ":  "

    .line 86
    .line 87
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0, p1}, Ljava/util/Properties;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    sget-object p1, Lorg/eclipse/paho/mqttv5/client/util/Debug;->lineSep:Ljava/lang/String;

    .line 98
    .line 99
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-virtual {v0, p1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 107
    .line 108
    .line 109
    goto :goto_0
.end method

.method public static left(Ljava/lang/String;IC)Ljava/lang/String;
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-lt v0, p1, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance v0, Ljava/lang/StringBuffer;

    .line 9
    .line 10
    invoke-direct {v0, p1}, Ljava/lang/StringBuffer;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    sub-int/2addr p1, p0

    .line 21
    :goto_0
    add-int/lit8 p1, p1, -0x1

    .line 22
    .line 23
    if-gez p1, :cond_1

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_1
    invoke-virtual {v0, p2}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 31
    .line 32
    .line 33
    goto :goto_0
.end method


# virtual methods
.method public dumpBaseDebug()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpVersion()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpSystemProperties()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpMemoryTrace()V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public dumpClientComms()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getDebug()Ljava/util/Properties;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 10
    .line 11
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 12
    .line 13
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->clientID:Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const-string v3, " : ClientComms"

    .line 20
    .line 21
    invoke-virtual {p0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {v0, p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-virtual {p0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    const-string v0, "dumpClientComms"

    .line 34
    .line 35
    invoke-interface {v1, v2, v0, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    return-void
.end method

.method public dumpClientDebug()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpClientComms()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpConOptions()V

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpClientState()V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpBaseDebug()V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public dumpClientState()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClientState()Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 12
    .line 13
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getClientState()Lorg/eclipse/paho/mqttv5/client/internal/MqttState;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-interface {v0}, Lorg/eclipse/paho/mqttv5/client/internal/MqttState;->getDebug()Ljava/util/Properties;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 22
    .line 23
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 24
    .line 25
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->clientID:Ljava/lang/String;

    .line 26
    .line 27
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    const-string v3, " : ClientState"

    .line 32
    .line 33
    invoke-virtual {p0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-static {v0, p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    const-string v0, "dumpClientState"

    .line 46
    .line 47
    invoke-interface {v1, v2, v0, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :cond_0
    return-void
.end method

.method public dumpConOptions()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->comms:Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->getConOptions()Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/MqttConnectionOptions;->getDebug()Ljava/util/Properties;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 14
    .line 15
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 16
    .line 17
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->clientID:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    const-string v3, " : Connect Options"

    .line 24
    .line 25
    invoke-virtual {p0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    invoke-static {v0, p0}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const-string v0, "dumpConOptions"

    .line 38
    .line 39
    invoke-interface {v1, v2, v0, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-void
.end method

.method public dumpMemoryTrace()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    invoke-interface {p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->dumpTrace()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public dumpSystemProperties()V
    .locals 3

    .line 1
    invoke-static {}, Ljava/lang/System;->getProperties()Ljava/util/Properties;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 6
    .line 7
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 8
    .line 9
    const-string v2, "SystemProperties"

    .line 10
    .line 11
    invoke-static {v0, v2}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->dumpProperties(Ljava/util/Properties;Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/String;->toString()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v2, "dumpSystemProperties"

    .line 20
    .line 21
    invoke-interface {p0, v1, v2, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public dumpVersion()V
    .locals 7

    .line 1
    new-instance v0, Ljava/lang/StringBuffer;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/util/Debug;->lineSep:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v3, "============== Version Info =============="

    .line 18
    .line 19
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 30
    .line 31
    .line 32
    new-instance v1, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v3, "Version"

    .line 35
    .line 36
    const/16 v4, 0x14

    .line 37
    .line 38
    const/16 v5, 0x20

    .line 39
    .line 40
    invoke-static {v3, v4, v5}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->left(Ljava/lang/String;IC)Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    const-string v3, ":  "

    .line 52
    .line 53
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    sget-object v6, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->VERSION:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 69
    .line 70
    .line 71
    new-instance v1, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v6, "Build Level"

    .line 74
    .line 75
    invoke-static {v6, v4, v5}, Lorg/eclipse/paho/mqttv5/client/util/Debug;->left(Ljava/lang/String;IC)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    invoke-static {v4}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    sget-object v3, Lorg/eclipse/paho/mqttv5/client/internal/ClientComms;->BUILD_LEVEL:Ljava/lang/String;

    .line 90
    .line 91
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 102
    .line 103
    .line 104
    new-instance v1, Ljava/lang/StringBuilder;

    .line 105
    .line 106
    const-string v3, "=========================================="

    .line 107
    .line 108
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 119
    .line 120
    .line 121
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/util/Debug;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 122
    .line 123
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/util/Debug;->CLASS_NAME:Ljava/lang/String;

    .line 124
    .line 125
    const-string v2, "dumpVersion"

    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    invoke-interface {p0, v1, v2, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    return-void
.end method
