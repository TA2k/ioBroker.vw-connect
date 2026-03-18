.class public Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;
.super Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.SSLNetworkModule"


# instance fields
.field private enabledCiphers:[Ljava/lang/String;

.field private handshakeTimeoutSecs:I

.field private host:Ljava/lang/String;

.field private hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

.field private httpsHostnameVerificationEnabled:Z

.field private log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

.field private port:I


# direct methods
.method public constructor <init>(Ljavax/net/ssl/SSLSocketFactory;Ljava/lang/String;ILjava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;-><init>(Ljavax/net/SocketFactory;Ljava/lang/String;ILjava/lang/String;)V

    .line 2
    .line 3
    .line 4
    const-string p1, "org.eclipse.paho.mqttv5.client.internal.nls.logcat"

    .line 5
    .line 6
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 7
    .line 8
    invoke-static {p1, v0}, Lorg/eclipse/paho/mqttv5/client/logging/LoggerFactory;->getLogger(Ljava/lang/String;Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 13
    .line 14
    const/4 v0, 0x1

    .line 15
    iput-boolean v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->httpsHostnameVerificationEnabled:Z

    .line 16
    .line 17
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->host:Ljava/lang/String;

    .line 18
    .line 19
    iput p3, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->port:I

    .line 20
    .line 21
    invoke-interface {p1, p4}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->setResourceName(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public getEnabledCiphers()[Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->enabledCiphers:[Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSSLHostnameVerifier()Ljavax/net/ssl/HostnameVerifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getServerURI()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ssl://"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->host:Ljava/lang/String;

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
    iget p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->port:I

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

.method public isHttpsHostnameVerificationEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->httpsHostnameVerificationEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public setEnabledCiphers([Ljava/lang/String;)V
    .locals 5

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->enabledCiphers:[Ljava/lang/String;

    .line 2
    .line 3
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 4
    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    if-eqz p1, :cond_3

    .line 8
    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 10
    .line 11
    const/4 v1, 0x5

    .line 12
    invoke-interface {v0, v1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->isLoggable(I)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_2

    .line 17
    .line 18
    const-string v0, ""

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    :goto_0
    array-length v2, p1

    .line 22
    if-lt v1, v2, :cond_0

    .line 23
    .line 24
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->log:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 25
    .line 26
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->CLASS_NAME:Ljava/lang/String;

    .line 27
    .line 28
    const-string v3, "260"

    .line 29
    .line 30
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const-string v4, "setEnabledCiphers"

    .line 35
    .line 36
    invoke-interface {v1, v2, v4, v3, v0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_0
    if-lez v1, :cond_1

    .line 41
    .line 42
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const-string v2, ","

    .line 47
    .line 48
    invoke-virtual {v0, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 53
    .line 54
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    aget-object v0, p1, v1

    .line 62
    .line 63
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    add-int/lit8 v1, v1, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    :goto_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 74
    .line 75
    check-cast p0, Ljavax/net/ssl/SSLSocket;

    .line 76
    .line 77
    invoke-virtual {p0, p1}, Ljavax/net/ssl/SSLSocket;->setEnabledCipherSuites([Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    :cond_3
    return-void
.end method

.method public setHttpsHostnameVerificationEnabled(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->httpsHostnameVerificationEnabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public setSSLHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 2
    .line 3
    return-void
.end method

.method public setSSLhandshakeTimeout(I)V
    .locals 0

    .line 1
    invoke-super {p0, p1}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->setConnectTimeout(I)V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->handshakeTimeoutSecs:I

    .line 5
    .line 6
    return-void
.end method

.method public start()V
    .locals 5

    .line 1
    invoke-super {p0}, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->start()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->enabledCiphers:[Ljava/lang/String;

    .line 5
    .line 6
    invoke-virtual {p0, v0}, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->setEnabledCiphers([Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/net/Socket;->getSoTimeout()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 16
    .line 17
    iget v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->handshakeTimeoutSecs:I

    .line 18
    .line 19
    mul-int/lit16 v2, v2, 0x3e8

    .line 20
    .line 21
    invoke-virtual {v1, v2}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 22
    .line 23
    .line 24
    new-instance v1, Ljavax/net/ssl/SSLParameters;

    .line 25
    .line 26
    invoke-direct {v1}, Ljavax/net/ssl/SSLParameters;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v2, Ljava/util/ArrayList;

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 33
    .line 34
    .line 35
    new-instance v3, Ljavax/net/ssl/SNIHostName;

    .line 36
    .line 37
    iget-object v4, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->host:Ljava/lang/String;

    .line 38
    .line 39
    invoke-direct {v3, v4}, Ljavax/net/ssl/SNIHostName;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, v2}, Ljavax/net/ssl/SSLParameters;->setServerNames(Ljava/util/List;)V

    .line 46
    .line 47
    .line 48
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 49
    .line 50
    check-cast v2, Ljavax/net/ssl/SSLSocket;

    .line 51
    .line 52
    invoke-virtual {v2, v1}, Ljavax/net/ssl/SSLSocket;->setSSLParameters(Ljavax/net/ssl/SSLParameters;)V

    .line 53
    .line 54
    .line 55
    iget-boolean v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->httpsHostnameVerificationEnabled:Z

    .line 56
    .line 57
    if-eqz v1, :cond_0

    .line 58
    .line 59
    new-instance v1, Ljavax/net/ssl/SSLParameters;

    .line 60
    .line 61
    invoke-direct {v1}, Ljavax/net/ssl/SSLParameters;-><init>()V

    .line 62
    .line 63
    .line 64
    const-string v2, "HTTPS"

    .line 65
    .line 66
    invoke-virtual {v1, v2}, Ljavax/net/ssl/SSLParameters;->setEndpointIdentificationAlgorithm(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 70
    .line 71
    check-cast v2, Ljavax/net/ssl/SSLSocket;

    .line 72
    .line 73
    invoke-virtual {v2, v1}, Ljavax/net/ssl/SSLSocket;->setSSLParameters(Ljavax/net/ssl/SSLParameters;)V

    .line 74
    .line 75
    .line 76
    :cond_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 77
    .line 78
    check-cast v1, Ljavax/net/ssl/SSLSocket;

    .line 79
    .line 80
    invoke-virtual {v1}, Ljavax/net/ssl/SSLSocket;->startHandshake()V

    .line 81
    .line 82
    .line 83
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 84
    .line 85
    if-eqz v1, :cond_2

    .line 86
    .line 87
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 88
    .line 89
    check-cast v1, Ljavax/net/ssl/SSLSocket;

    .line 90
    .line 91
    invoke-virtual {v1}, Ljavax/net/ssl/SSLSocket;->getSession()Ljavax/net/ssl/SSLSession;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->hostnameVerifier:Ljavax/net/ssl/HostnameVerifier;

    .line 96
    .line 97
    iget-object v3, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->host:Ljava/lang/String;

    .line 98
    .line 99
    invoke-interface {v2, v3, v1}, Ljavax/net/ssl/HostnameVerifier;->verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    if-eqz v2, :cond_1

    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_1
    invoke-interface {v1}, Ljavax/net/ssl/SSLSession;->invalidate()V

    .line 107
    .line 108
    .line 109
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 110
    .line 111
    invoke-virtual {v0}, Ljava/net/Socket;->close()V

    .line 112
    .line 113
    .line 114
    new-instance v0, Ljavax/net/ssl/SSLPeerUnverifiedException;

    .line 115
    .line 116
    new-instance v2, Ljava/lang/StringBuilder;

    .line 117
    .line 118
    const-string v3, "Host: "

    .line 119
    .line 120
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/SSLNetworkModule;->host:Ljava/lang/String;

    .line 124
    .line 125
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const-string p0, ", Peer Host: "

    .line 129
    .line 130
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-interface {v1}, Ljavax/net/ssl/SSLSession;->getPeerHost()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-direct {v0, p0}, Ljavax/net/ssl/SSLPeerUnverifiedException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw v0

    .line 148
    :cond_2
    :goto_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/internal/TCPNetworkModule;->socket:Ljava/net/Socket;

    .line 149
    .line 150
    invoke-virtual {p0, v0}, Ljava/net/Socket;->setSoTimeout(I)V

    .line 151
    .line 152
    .line 153
    return-void
.end method
