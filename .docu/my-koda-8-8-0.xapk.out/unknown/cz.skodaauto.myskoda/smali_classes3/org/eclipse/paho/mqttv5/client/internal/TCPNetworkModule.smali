.class public Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/internal/NetworkModule;


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.TCPNetworkModule"


# instance fields
.field private conTimeout:I

.field private factory:Ljavax/net/SocketFactory;

.field private host:Ljava/lang/String;

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private port:I

.field protected socket:Ljava/net/Socket;


# direct methods
.method public constructor <init>(Ljavax/net/SocketFactory;Ljava/lang/String;ILjava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    invoke-interface {v0, p4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->factory:Ljavax/net/SocketFactory;

    .line 18
    .line 19
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->host:Ljava/lang/String;

    .line 20
    .line 21
    iput p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->port:I

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public getInputStream()Ljava/io/InputStream;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/net/Socket;->getInputStream()Ljava/io/InputStream;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getOutputStream()Ljava/io/OutputStream;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/net/Socket;->getOutputStream()Ljava/io/OutputStream;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getServerURI()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "tcp://"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->host:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ":"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->port:I

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method

.method public setConnectTimeout(I)V
    .locals 0

    .line 1
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->conTimeout:I

    .line 2
    .line 3
    return-void
.end method

.method public start()V
    .locals 10

    .line 1
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 2
    .line 3
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 4
    .line 5
    const-string v2, "start"

    .line 6
    .line 7
    const-string v3, "252"

    .line 8
    .line 9
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->host:Ljava/lang/String;

    .line 10
    .line 11
    iget v5, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->port:I

    .line 12
    .line 13
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    iget v6, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->conTimeout:I

    .line 18
    .line 19
    const/16 v7, 0x3e8

    .line 20
    .line 21
    mul-int/2addr v6, v7

    .line 22
    int-to-long v8, v6

    .line 23
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    filled-new-array {v4, v5, v6}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    invoke-interface {v0, v1, v2, v3, v4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    new-instance v0, Ljava/net/InetSocketAddress;

    .line 35
    .line 36
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->host:Ljava/lang/String;

    .line 37
    .line 38
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->port:I

    .line 39
    .line 40
    invoke-direct {v0, v1, v2}, Ljava/net/InetSocketAddress;-><init>(Ljava/lang/String;I)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->factory:Ljavax/net/SocketFactory;

    .line 44
    .line 45
    invoke-virtual {v1}, Ljavax/net/SocketFactory;->createSocket()Ljava/net/Socket;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    iput-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 50
    .line 51
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->conTimeout:I

    .line 52
    .line 53
    mul-int/2addr v2, v7

    .line 54
    invoke-virtual {v1, v0, v2}, Ljava/net/Socket;->connect(Ljava/net/SocketAddress;I)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 58
    .line 59
    invoke-virtual {v0, v7}, Ljava/net/Socket;->setSoTimeout(I)V
    :try_end_0
    .catch Ljava/net/ConnectException; {:try_start_0 .. :try_end_0} :catch_0

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :catch_0
    move-exception v0

    .line 64
    move-object v6, v0

    .line 65
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 66
    .line 67
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 68
    .line 69
    const-string v4, "250"

    .line 70
    .line 71
    const/4 v5, 0x0

    .line 72
    const-string v3, "start"

    .line 73
    .line 74
    invoke-interface/range {v1 .. v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 75
    .line 76
    .line 77
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttException;

    .line 78
    .line 79
    const/16 v0, 0x7d67

    .line 80
    .line 81
    invoke-direct {p0, v0, v6}, Lorg/eclipse/paho/mqttv5/common/MqttException;-><init>(ILjava/lang/Throwable;)V

    .line 82
    .line 83
    .line 84
    throw p0
.end method

.method public stop()V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/net/Socket;->shutdownInput()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/net/Socket;->close()V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method
