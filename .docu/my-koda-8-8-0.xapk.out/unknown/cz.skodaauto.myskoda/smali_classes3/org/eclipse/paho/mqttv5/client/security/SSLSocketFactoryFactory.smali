.class public Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CIPHERSUITES:Ljava/lang/String; = "com.ibm.ssl.enabledCipherSuites"

.field private static final CLASS_NAME:Ljava/lang/String; = "org.eclipse.paho.mqttv5.client.internal.security.SSLSocketFactoryFactory"

.field public static final CLIENTAUTH:Ljava/lang/String; = "com.ibm.ssl.clientAuthentication"

.field public static final DEFAULT_PROTOCOL:Ljava/lang/String; = "TLS"

.field public static final JSSEPROVIDER:Ljava/lang/String; = "com.ibm.ssl.contextProvider"

.field public static final KEYSTORE:Ljava/lang/String; = "com.ibm.ssl.keyStore"

.field public static final KEYSTOREMGR:Ljava/lang/String; = "com.ibm.ssl.keyManager"

.field public static final KEYSTOREPROVIDER:Ljava/lang/String; = "com.ibm.ssl.keyStoreProvider"

.field public static final KEYSTOREPWD:Ljava/lang/String; = "com.ibm.ssl.keyStorePassword"

.field public static final KEYSTORETYPE:Ljava/lang/String; = "com.ibm.ssl.keyStoreType"

.field public static final SSLPROTOCOL:Ljava/lang/String; = "com.ibm.ssl.protocol"

.field public static final SYSKEYMGRALGO:Ljava/lang/String; = "ssl.KeyManagerFactory.algorithm"

.field public static final SYSKEYSTORE:Ljava/lang/String; = "javax.net.ssl.keyStore"

.field public static final SYSKEYSTOREPWD:Ljava/lang/String; = "javax.net.ssl.keyStorePassword"

.field public static final SYSKEYSTORETYPE:Ljava/lang/String; = "javax.net.ssl.keyStoreType"

.field public static final SYSTRUSTMGRALGO:Ljava/lang/String; = "ssl.TrustManagerFactory.algorithm"

.field public static final SYSTRUSTSTORE:Ljava/lang/String; = "javax.net.ssl.trustStore"

.field public static final SYSTRUSTSTOREPWD:Ljava/lang/String; = "javax.net.ssl.trustStorePassword"

.field public static final SYSTRUSTSTORETYPE:Ljava/lang/String; = "javax.net.ssl.trustStoreType"

.field public static final TRUSTSTORE:Ljava/lang/String; = "com.ibm.ssl.trustStore"

.field public static final TRUSTSTOREMGR:Ljava/lang/String; = "com.ibm.ssl.trustManager"

.field public static final TRUSTSTOREPROVIDER:Ljava/lang/String; = "com.ibm.ssl.trustStoreProvider"

.field public static final TRUSTSTOREPWD:Ljava/lang/String; = "com.ibm.ssl.trustStorePassword"

.field public static final TRUSTSTORETYPE:Ljava/lang/String; = "com.ibm.ssl.trustStoreType"

.field private static final key:[B

.field private static final propertyKeys:[Ljava/lang/String;

.field private static final xorTag:Ljava/lang/String; = "{xor}"


# instance fields
.field private configs:Ljava/util/Hashtable;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Hashtable<",
            "Ljava/lang/String;",
            "Ljava/util/Properties;",
            ">;"
        }
    .end annotation
.end field

.field private defaultProperties:Ljava/util/Properties;

.field private logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    .line 1
    const-string v12, "com.ibm.ssl.enabledCipherSuites"

    .line 2
    .line 3
    const-string v13, "com.ibm.ssl.clientAuthentication"

    .line 4
    .line 5
    const-string v0, "com.ibm.ssl.protocol"

    .line 6
    .line 7
    const-string v1, "com.ibm.ssl.contextProvider"

    .line 8
    .line 9
    const-string v2, "com.ibm.ssl.keyStore"

    .line 10
    .line 11
    const-string v3, "com.ibm.ssl.keyStorePassword"

    .line 12
    .line 13
    const-string v4, "com.ibm.ssl.keyStoreType"

    .line 14
    .line 15
    const-string v5, "com.ibm.ssl.keyStoreProvider"

    .line 16
    .line 17
    const-string v6, "com.ibm.ssl.keyManager"

    .line 18
    .line 19
    const-string v7, "com.ibm.ssl.trustStore"

    .line 20
    .line 21
    const-string v8, "com.ibm.ssl.trustStorePassword"

    .line 22
    .line 23
    const-string v9, "com.ibm.ssl.trustStoreType"

    .line 24
    .line 25
    const-string v10, "com.ibm.ssl.trustStoreProvider"

    .line 26
    .line 27
    const-string v11, "com.ibm.ssl.trustManager"

    .line 28
    .line 29
    filled-new-array/range {v0 .. v13}, [Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->propertyKeys:[Ljava/lang/String;

    .line 34
    .line 35
    const/16 v0, 0x8

    .line 36
    .line 37
    new-array v0, v0, [B

    .line 38
    .line 39
    fill-array-data v0, :array_0

    .line 40
    .line 41
    .line 42
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->key:[B

    .line 43
    .line 44
    return-void

    .line 45
    :array_0
    .array-data 1
        -0x63t
        -0x59t
        -0x27t
        -0x80t
        0x5t
        -0x48t
        -0x77t
        -0x64t
    .end array-data
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 3
    new-instance v0, Ljava/util/Hashtable;

    invoke-direct {v0}, Ljava/util/Hashtable;-><init>()V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    return-void
.end method

.method public constructor <init>(Lorg/eclipse/paho/mqttv5/client/logging/Logger;)V
    .locals 0

    .line 4
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;-><init>()V

    .line 5
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    return-void
.end method

.method private checkPropertyKeys(Ljava/util/Properties;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/util/Properties;->keySet()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/lang/String;

    .line 21
    .line 22
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->keyValid(Ljava/lang/String;)Z

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    if-eqz v1, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 30
    .line 31
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    const-string v0, " is not a valid IBM SSL property key."

    .line 36
    .line 37
    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method private convertPassword(Ljava/util/Properties;)V
    .locals 3

    .line 1
    const-string p0, "com.ibm.ssl.keyStorePassword"

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "{xor}"

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-nez v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->obfuscate([C)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p1, p0, v0}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    :cond_0
    const-string p0, "com.ibm.ssl.trustStorePassword"

    .line 29
    .line 30
    invoke-virtual {p1, p0}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-nez v1, :cond_1

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->obfuscate([C)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {p1, p0, v0}, Ljava/util/Properties;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    :cond_1
    return-void
.end method

.method public static deObfuscate(Ljava/lang/String;)[C
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p0, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    const/4 v1, 0x5

    .line 6
    :try_start_0
    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SimpleBase64Encoder;->decode(Ljava/lang/String;)[B

    .line 11
    .line 12
    .line 13
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    const/4 v0, 0x0

    .line 15
    :goto_0
    array-length v1, p0

    .line 16
    if-lt v0, v1, :cond_1

    .line 17
    .line 18
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->toChar([B)[C

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    aget-byte v1, p0, v0

    .line 24
    .line 25
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->key:[B

    .line 26
    .line 27
    array-length v3, v2

    .line 28
    rem-int v3, v0, v3

    .line 29
    .line 30
    aget-byte v2, v2, v3

    .line 31
    .line 32
    xor-int/2addr v1, v2

    .line 33
    and-int/lit16 v1, v1, 0xff

    .line 34
    .line 35
    int-to-byte v1, v1

    .line 36
    aput-byte v1, p0, v0

    .line 37
    .line 38
    add-int/lit8 v0, v0, 0x1

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :catch_0
    return-object v0
.end method

.method private getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getPropertyFromConfig(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    if-eqz p3, :cond_1

    .line 9
    .line 10
    invoke-static {p3}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :cond_1
    return-object p0
.end method

.method private getPropertyFromConfig(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 5
    .line 6
    invoke-virtual {v1, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    check-cast p1, Ljava/util/Properties;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object p1, v0

    .line 14
    :goto_0
    if-eqz p1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1, p2}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_1

    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 24
    .line 25
    if-eqz p0, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0, p2}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_2
    return-object v0
.end method

.method private getSSLContext(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
    .locals 13

    .line 1
    const-string v0, "com.ibm.ssl.keyStore"

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getSSLProtocol(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    const-string v1, "TLS"

    .line 10
    .line 11
    :cond_0
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 12
    .line 13
    const-string v3, "null (broker defaults)"

    .line 14
    .line 15
    const-string v4, "getSSLContext"

    .line 16
    .line 17
    const-string v5, "org.eclipse.paho.mqttv5.client.internal.security.SSLSocketFactoryFactory"

    .line 18
    .line 19
    if-eqz v2, :cond_2

    .line 20
    .line 21
    if-eqz p1, :cond_1

    .line 22
    .line 23
    move-object v6, p1

    .line 24
    goto :goto_0

    .line 25
    :cond_1
    move-object v6, v3

    .line 26
    :goto_0
    filled-new-array {v6, v1}, [Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v6

    .line 30
    const-string v7, "12000"

    .line 31
    .line 32
    invoke-interface {v2, v5, v4, v7, v6}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_2
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getJSSEProvider(Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    if-nez v2, :cond_3

    .line 40
    .line 41
    :try_start_0
    invoke-static {v1}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    goto :goto_1

    .line 46
    :cond_3
    invoke-static {v1, v2}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    :goto_1
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 51
    .line 52
    if-eqz v2, :cond_5

    .line 53
    .line 54
    const-string v6, "12001"

    .line 55
    .line 56
    if-eqz p1, :cond_4

    .line 57
    .line 58
    move-object v7, p1

    .line 59
    goto :goto_2

    .line 60
    :cond_4
    move-object v7, v3

    .line 61
    :goto_2
    invoke-virtual {v1}, Ljavax/net/ssl/SSLContext;->getProvider()Ljava/security/Provider;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    invoke-virtual {v8}, Ljava/security/Provider;->getName()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v8

    .line 69
    filled-new-array {v7, v8}, [Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    invoke-interface {v2, v5, v4, v6, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    :cond_5
    const/4 v2, 0x0

    .line 77
    invoke-direct {p0, p1, v0, v2}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    if-nez v6, :cond_6

    .line 82
    .line 83
    const-string v6, "javax.net.ssl.keyStore"

    .line 84
    .line 85
    invoke-direct {p0, p1, v0, v6}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    :cond_6
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_0 .. :try_end_0} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_0 .. :try_end_0} :catch_9

    .line 90
    .line 91
    const-string v7, "null"

    .line 92
    .line 93
    if-eqz v0, :cond_9

    .line 94
    .line 95
    :try_start_1
    const-string v8, "12004"

    .line 96
    .line 97
    if-eqz p1, :cond_7

    .line 98
    .line 99
    move-object v9, p1

    .line 100
    goto :goto_3

    .line 101
    :cond_7
    move-object v9, v3

    .line 102
    :goto_3
    if-eqz v6, :cond_8

    .line 103
    .line 104
    move-object v10, v6

    .line 105
    goto :goto_4

    .line 106
    :cond_8
    move-object v10, v7

    .line 107
    :goto_4
    filled-new-array {v9, v10}, [Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v9

    .line 111
    invoke-interface {v0, v5, v4, v8, v9}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :cond_9
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getKeyStorePassword(Ljava/lang/String;)[C

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 119
    .line 120
    if-eqz v8, :cond_c

    .line 121
    .line 122
    const-string v9, "12005"

    .line 123
    .line 124
    if-eqz p1, :cond_a

    .line 125
    .line 126
    move-object v10, p1

    .line 127
    goto :goto_5

    .line 128
    :cond_a
    move-object v10, v3

    .line 129
    :goto_5
    if-eqz v0, :cond_b

    .line 130
    .line 131
    invoke-static {v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->obfuscate([C)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v11

    .line 135
    goto :goto_6

    .line 136
    :cond_b
    move-object v11, v7

    .line 137
    :goto_6
    filled-new-array {v10, v11}, [Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v10

    .line 141
    invoke-interface {v8, v5, v4, v9, v10}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_c
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getKeyStoreType(Ljava/lang/String;)Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    if-nez v8, :cond_d

    .line 149
    .line 150
    invoke-static {}, Ljava/security/KeyStore;->getDefaultType()Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    :cond_d
    iget-object v9, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 155
    .line 156
    if-eqz v9, :cond_10

    .line 157
    .line 158
    const-string v10, "12006"

    .line 159
    .line 160
    if-eqz p1, :cond_e

    .line 161
    .line 162
    move-object v11, p1

    .line 163
    goto :goto_7

    .line 164
    :cond_e
    move-object v11, v3

    .line 165
    :goto_7
    if-eqz v8, :cond_f

    .line 166
    .line 167
    move-object v12, v8

    .line 168
    goto :goto_8

    .line 169
    :cond_f
    move-object v12, v7

    .line 170
    :goto_8
    filled-new-array {v11, v12}, [Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v11

    .line 174
    invoke-interface {v9, v5, v4, v10, v11}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 175
    .line 176
    .line 177
    :cond_10
    invoke-static {}, Ljavax/net/ssl/KeyManagerFactory;->getDefaultAlgorithm()Ljava/lang/String;

    .line 178
    .line 179
    .line 180
    move-result-object v9

    .line 181
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getKeyStoreProvider(Ljava/lang/String;)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v10

    .line 185
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getKeyManager(Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v11
    :try_end_1
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_1 .. :try_end_1} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_1 .. :try_end_1} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_1 .. :try_end_1} :catch_9

    .line 189
    if-eqz v11, :cond_11

    .line 190
    .line 191
    move-object v9, v11

    .line 192
    :cond_11
    if-eqz v6, :cond_16

    .line 193
    .line 194
    if-eqz v8, :cond_16

    .line 195
    .line 196
    if-eqz v9, :cond_16

    .line 197
    .line 198
    :try_start_2
    invoke-static {v8}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 199
    .line 200
    .line 201
    move-result-object v8

    .line 202
    new-instance v11, Ljava/io/FileInputStream;

    .line 203
    .line 204
    invoke-direct {v11, v6}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v8, v11, v0}, Ljava/security/KeyStore;->load(Ljava/io/InputStream;[C)V

    .line 208
    .line 209
    .line 210
    if-eqz v10, :cond_12

    .line 211
    .line 212
    invoke-static {v9, v10}, Ljavax/net/ssl/KeyManagerFactory;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/net/ssl/KeyManagerFactory;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    goto :goto_9

    .line 217
    :cond_12
    invoke-static {v9}, Ljavax/net/ssl/KeyManagerFactory;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/KeyManagerFactory;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    :goto_9
    iget-object v10, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 222
    .line 223
    if-eqz v10, :cond_15

    .line 224
    .line 225
    const-string v11, "12010"

    .line 226
    .line 227
    if-eqz p1, :cond_13

    .line 228
    .line 229
    move-object v12, p1

    .line 230
    goto :goto_a

    .line 231
    :cond_13
    move-object v12, v3

    .line 232
    :goto_a
    filled-new-array {v12, v9}, [Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v9

    .line 236
    invoke-interface {v10, v5, v4, v11, v9}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    iget-object v9, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 240
    .line 241
    const-string v10, "12009"

    .line 242
    .line 243
    if-eqz p1, :cond_14

    .line 244
    .line 245
    move-object v11, p1

    .line 246
    goto :goto_b

    .line 247
    :cond_14
    move-object v11, v3

    .line 248
    :goto_b
    invoke-virtual {v6}, Ljavax/net/ssl/KeyManagerFactory;->getProvider()Ljava/security/Provider;

    .line 249
    .line 250
    .line 251
    move-result-object v12

    .line 252
    invoke-virtual {v12}, Ljava/security/Provider;->getName()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v12

    .line 256
    filled-new-array {v11, v12}, [Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v11

    .line 260
    invoke-interface {v9, v5, v4, v10, v11}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 261
    .line 262
    .line 263
    :cond_15
    invoke-virtual {v6, v8, v0}, Ljavax/net/ssl/KeyManagerFactory;->init(Ljava/security/KeyStore;[C)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v6}, Ljavax/net/ssl/KeyManagerFactory;->getKeyManagers()[Ljavax/net/ssl/KeyManager;

    .line 267
    .line 268
    .line 269
    move-result-object v0
    :try_end_2
    .catch Ljava/security/KeyStoreException; {:try_start_2 .. :try_end_2} :catch_4
    .catch Ljava/security/cert/CertificateException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/security/UnrecoverableKeyException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_2 .. :try_end_2} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_2 .. :try_end_2} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_2 .. :try_end_2} :catch_9

    .line 270
    goto :goto_c

    .line 271
    :catch_0
    move-exception p0

    .line 272
    :try_start_3
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 273
    .line 274
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 275
    .line 276
    .line 277
    throw p1

    .line 278
    :catch_1
    move-exception p0

    .line 279
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 280
    .line 281
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 282
    .line 283
    .line 284
    throw p1

    .line 285
    :catch_2
    move-exception p0

    .line 286
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 287
    .line 288
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 289
    .line 290
    .line 291
    throw p1

    .line 292
    :catch_3
    move-exception p0

    .line 293
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 294
    .line 295
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 296
    .line 297
    .line 298
    throw p1

    .line 299
    :catch_4
    move-exception p0

    .line 300
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 301
    .line 302
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 303
    .line 304
    .line 305
    throw p1

    .line 306
    :cond_16
    move-object v0, v2

    .line 307
    :goto_c
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getTrustStore(Ljava/lang/String;)Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v6

    .line 311
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 312
    .line 313
    if-eqz v8, :cond_19

    .line 314
    .line 315
    const-string v9, "12011"

    .line 316
    .line 317
    if-eqz p1, :cond_17

    .line 318
    .line 319
    move-object v10, p1

    .line 320
    goto :goto_d

    .line 321
    :cond_17
    move-object v10, v3

    .line 322
    :goto_d
    if-eqz v6, :cond_18

    .line 323
    .line 324
    move-object v11, v6

    .line 325
    goto :goto_e

    .line 326
    :cond_18
    move-object v11, v7

    .line 327
    :goto_e
    filled-new-array {v10, v11}, [Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v10

    .line 331
    invoke-interface {v8, v5, v4, v9, v10}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 332
    .line 333
    .line 334
    :cond_19
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getTrustStorePassword(Ljava/lang/String;)[C

    .line 335
    .line 336
    .line 337
    move-result-object v8

    .line 338
    iget-object v9, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 339
    .line 340
    if-eqz v9, :cond_1c

    .line 341
    .line 342
    const-string v10, "12012"

    .line 343
    .line 344
    if-eqz p1, :cond_1a

    .line 345
    .line 346
    move-object v11, p1

    .line 347
    goto :goto_f

    .line 348
    :cond_1a
    move-object v11, v3

    .line 349
    :goto_f
    if-eqz v8, :cond_1b

    .line 350
    .line 351
    invoke-static {v8}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->obfuscate([C)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v12

    .line 355
    goto :goto_10

    .line 356
    :cond_1b
    move-object v12, v7

    .line 357
    :goto_10
    filled-new-array {v11, v12}, [Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v11

    .line 361
    invoke-interface {v9, v5, v4, v10, v11}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 362
    .line 363
    .line 364
    :cond_1c
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getTrustStoreType(Ljava/lang/String;)Ljava/lang/String;

    .line 365
    .line 366
    .line 367
    move-result-object v9

    .line 368
    if-nez v9, :cond_1d

    .line 369
    .line 370
    invoke-static {}, Ljava/security/KeyStore;->getDefaultType()Ljava/lang/String;

    .line 371
    .line 372
    .line 373
    move-result-object v9

    .line 374
    :cond_1d
    iget-object v10, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 375
    .line 376
    if-eqz v10, :cond_20

    .line 377
    .line 378
    const-string v11, "12013"

    .line 379
    .line 380
    if-eqz p1, :cond_1e

    .line 381
    .line 382
    move-object v12, p1

    .line 383
    goto :goto_11

    .line 384
    :cond_1e
    move-object v12, v3

    .line 385
    :goto_11
    if-eqz v9, :cond_1f

    .line 386
    .line 387
    move-object v7, v9

    .line 388
    :cond_1f
    filled-new-array {v12, v7}, [Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v7

    .line 392
    invoke-interface {v10, v5, v4, v11, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 393
    .line 394
    .line 395
    :cond_20
    invoke-static {}, Ljavax/net/ssl/TrustManagerFactory;->getDefaultAlgorithm()Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v7

    .line 399
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getTrustStoreProvider(Ljava/lang/String;)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    move-result-object v10

    .line 403
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getTrustManager(Ljava/lang/String;)Ljava/lang/String;

    .line 404
    .line 405
    .line 406
    move-result-object v11
    :try_end_3
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_3 .. :try_end_3} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_3 .. :try_end_3} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_3 .. :try_end_3} :catch_9

    .line 407
    if-eqz v11, :cond_21

    .line 408
    .line 409
    move-object v7, v11

    .line 410
    :cond_21
    if-eqz v6, :cond_26

    .line 411
    .line 412
    if-eqz v9, :cond_26

    .line 413
    .line 414
    if-eqz v7, :cond_26

    .line 415
    .line 416
    :try_start_4
    invoke-static {v9}, Ljava/security/KeyStore;->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;

    .line 417
    .line 418
    .line 419
    move-result-object v9

    .line 420
    new-instance v11, Ljava/io/FileInputStream;

    .line 421
    .line 422
    invoke-direct {v11, v6}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V

    .line 423
    .line 424
    .line 425
    invoke-virtual {v9, v11, v8}, Ljava/security/KeyStore;->load(Ljava/io/InputStream;[C)V

    .line 426
    .line 427
    .line 428
    if-eqz v10, :cond_22

    .line 429
    .line 430
    invoke-static {v7, v10}, Ljavax/net/ssl/TrustManagerFactory;->getInstance(Ljava/lang/String;Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;

    .line 431
    .line 432
    .line 433
    move-result-object v6

    .line 434
    goto :goto_12

    .line 435
    :cond_22
    invoke-static {v7}, Ljavax/net/ssl/TrustManagerFactory;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;

    .line 436
    .line 437
    .line 438
    move-result-object v6

    .line 439
    :goto_12
    iget-object v8, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 440
    .line 441
    if-eqz v8, :cond_25

    .line 442
    .line 443
    const-string v10, "12017"

    .line 444
    .line 445
    if-eqz p1, :cond_23

    .line 446
    .line 447
    move-object v11, p1

    .line 448
    goto :goto_13

    .line 449
    :cond_23
    move-object v11, v3

    .line 450
    :goto_13
    filled-new-array {v11, v7}, [Ljava/lang/Object;

    .line 451
    .line 452
    .line 453
    move-result-object v7

    .line 454
    invoke-interface {v8, v5, v4, v10, v7}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 455
    .line 456
    .line 457
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 458
    .line 459
    const-string v7, "12016"

    .line 460
    .line 461
    if-eqz p1, :cond_24

    .line 462
    .line 463
    goto :goto_14

    .line 464
    :cond_24
    move-object p1, v3

    .line 465
    :goto_14
    invoke-virtual {v6}, Ljavax/net/ssl/TrustManagerFactory;->getProvider()Ljava/security/Provider;

    .line 466
    .line 467
    .line 468
    move-result-object v3

    .line 469
    invoke-virtual {v3}, Ljava/security/Provider;->getName()Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v3

    .line 473
    filled-new-array {p1, v3}, [Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object p1

    .line 477
    invoke-interface {p0, v5, v4, v7, p1}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    :cond_25
    invoke-virtual {v6, v9}, Ljavax/net/ssl/TrustManagerFactory;->init(Ljava/security/KeyStore;)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v6}, Ljavax/net/ssl/TrustManagerFactory;->getTrustManagers()[Ljavax/net/ssl/TrustManager;

    .line 484
    .line 485
    .line 486
    move-result-object p0
    :try_end_4
    .catch Ljava/security/KeyStoreException; {:try_start_4 .. :try_end_4} :catch_8
    .catch Ljava/security/cert/CertificateException; {:try_start_4 .. :try_end_4} :catch_7
    .catch Ljava/io/FileNotFoundException; {:try_start_4 .. :try_end_4} :catch_6
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_5
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_4 .. :try_end_4} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_4 .. :try_end_4} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_4 .. :try_end_4} :catch_9

    .line 487
    goto :goto_15

    .line 488
    :catch_5
    move-exception p0

    .line 489
    :try_start_5
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 490
    .line 491
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 492
    .line 493
    .line 494
    throw p1

    .line 495
    :catch_6
    move-exception p0

    .line 496
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 497
    .line 498
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 499
    .line 500
    .line 501
    throw p1

    .line 502
    :catch_7
    move-exception p0

    .line 503
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 504
    .line 505
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 506
    .line 507
    .line 508
    throw p1

    .line 509
    :catch_8
    move-exception p0

    .line 510
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 511
    .line 512
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 513
    .line 514
    .line 515
    throw p1

    .line 516
    :cond_26
    move-object p0, v2

    .line 517
    :goto_15
    invoke-virtual {v1, v0, p0, v2}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
    :try_end_5
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_5 .. :try_end_5} :catch_b
    .catch Ljava/security/NoSuchProviderException; {:try_start_5 .. :try_end_5} :catch_a
    .catch Ljava/security/KeyManagementException; {:try_start_5 .. :try_end_5} :catch_9

    .line 518
    .line 519
    .line 520
    return-object v1

    .line 521
    :catch_9
    move-exception p0

    .line 522
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 523
    .line 524
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 525
    .line 526
    .line 527
    throw p1

    .line 528
    :catch_a
    move-exception p0

    .line 529
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 530
    .line 531
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 532
    .line 533
    .line 534
    throw p1

    .line 535
    :catch_b
    move-exception p0

    .line 536
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;

    .line 537
    .line 538
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttSecurityException;-><init>(Ljava/lang/Throwable;)V

    .line 539
    .line 540
    .line 541
    throw p1
.end method

.method public static isSupportedOnJVM()Z
    .locals 1

    .line 1
    const-string v0, "javax.net.ssl.SSLServerSocketFactory"

    .line 2
    .line 3
    :try_start_0
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    return v0

    .line 8
    :catch_0
    const/4 v0, 0x0

    .line 9
    return v0
.end method

.method private keyValid(Ljava/lang/String;)Z
    .locals 3

    .line 1
    const/4 p0, 0x0

    .line 2
    move v0, p0

    .line 3
    :goto_0
    sget-object v1, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->propertyKeys:[Ljava/lang/String;

    .line 4
    .line 5
    array-length v2, v1

    .line 6
    if-lt v0, v2, :cond_0

    .line 7
    .line 8
    goto :goto_1

    .line 9
    :cond_0
    aget-object v2, v1, v0

    .line 10
    .line 11
    invoke-virtual {v2, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    :goto_1
    array-length p1, v1

    .line 18
    if-ge v0, p1, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    :cond_1
    return p0

    .line 22
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    goto :goto_0
.end method

.method public static obfuscate([C)Ljava/lang/String;
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->toByte([C)[B

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 v0, 0x0

    .line 10
    :goto_0
    array-length v1, p0

    .line 11
    if-lt v0, v1, :cond_1

    .line 12
    .line 13
    new-instance v0, Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SimpleBase64Encoder;->encode([B)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-direct {v0, p0}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string p0, "{xor}"

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    aget-byte v1, p0, v0

    .line 30
    .line 31
    sget-object v2, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->key:[B

    .line 32
    .line 33
    array-length v3, v2

    .line 34
    rem-int v3, v0, v3

    .line 35
    .line 36
    aget-byte v2, v2, v3

    .line 37
    .line 38
    xor-int/2addr v1, v2

    .line 39
    and-int/lit16 v1, v1, 0xff

    .line 40
    .line 41
    int-to-byte v1, v1

    .line 42
    aput-byte v1, p0, v0

    .line 43
    .line 44
    add-int/lit8 v0, v0, 0x1

    .line 45
    .line 46
    goto :goto_0
.end method

.method public static packCipherSuites([Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 1
    if-eqz p0, :cond_2

    .line 2
    .line 3
    new-instance v0, Ljava/lang/StringBuffer;

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    :goto_0
    array-length v2, p0

    .line 10
    if-lt v1, v2, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    aget-object v2, p0, v1

    .line 18
    .line 19
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(Ljava/lang/String;)Ljava/lang/StringBuffer;

    .line 20
    .line 21
    .line 22
    array-length v2, p0

    .line 23
    add-int/lit8 v2, v2, -0x1

    .line 24
    .line 25
    if-ge v1, v2, :cond_1

    .line 26
    .line 27
    const/16 v2, 0x2c

    .line 28
    .line 29
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 30
    .line 31
    .line 32
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_2
    const/4 p0, 0x0

    .line 36
    return-object p0
.end method

.method public static toByte([C)[B
    .locals 6

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    array-length v0, p0

    .line 6
    mul-int/lit8 v0, v0, 0x2

    .line 7
    .line 8
    new-array v0, v0, [B

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    array-length v3, p0

    .line 13
    if-lt v1, v3, :cond_1

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_1
    add-int/lit8 v3, v2, 0x1

    .line 17
    .line 18
    aget-char v4, p0, v1

    .line 19
    .line 20
    and-int/lit16 v5, v4, 0xff

    .line 21
    .line 22
    int-to-byte v5, v5

    .line 23
    aput-byte v5, v0, v2

    .line 24
    .line 25
    add-int/lit8 v2, v2, 0x2

    .line 26
    .line 27
    add-int/lit8 v1, v1, 0x1

    .line 28
    .line 29
    shr-int/lit8 v4, v4, 0x8

    .line 30
    .line 31
    and-int/lit16 v4, v4, 0xff

    .line 32
    .line 33
    int-to-byte v4, v4

    .line 34
    aput-byte v4, v0, v3

    .line 35
    .line 36
    goto :goto_0
.end method

.method public static toChar([B)[C
    .locals 6

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    array-length v0, p0

    .line 6
    div-int/lit8 v0, v0, 0x2

    .line 7
    .line 8
    new-array v0, v0, [C

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    move v2, v1

    .line 12
    :goto_0
    array-length v3, p0

    .line 13
    if-lt v1, v3, :cond_1

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_1
    add-int/lit8 v3, v2, 0x1

    .line 17
    .line 18
    add-int/lit8 v4, v1, 0x1

    .line 19
    .line 20
    aget-byte v5, p0, v1

    .line 21
    .line 22
    and-int/lit16 v5, v5, 0xff

    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x2

    .line 25
    .line 26
    aget-byte v4, p0, v4

    .line 27
    .line 28
    and-int/lit16 v4, v4, 0xff

    .line 29
    .line 30
    shl-int/lit8 v4, v4, 0x8

    .line 31
    .line 32
    add-int/2addr v5, v4

    .line 33
    int-to-char v4, v5

    .line 34
    aput-char v4, v0, v2

    .line 35
    .line 36
    move v2, v3

    .line 37
    goto :goto_0
.end method

.method public static unpackCipherSuites(Ljava/lang/String;)[Ljava/lang/String;
    .locals 5

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return-object p0

    .line 5
    :cond_0
    new-instance v0, Ljava/util/Vector;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/Vector;-><init>()V

    .line 8
    .line 9
    .line 10
    const/16 v1, 0x2c

    .line 11
    .line 12
    invoke-virtual {p0, v1}, Ljava/lang/String;->indexOf(I)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const/4 v3, 0x0

    .line 17
    :goto_0
    const/4 v4, -0x1

    .line 18
    if-gt v2, v4, :cond_1

    .line 19
    .line 20
    invoke-virtual {p0, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {v0, p0}, Ljava/util/Vector;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/util/Vector;->size()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    new-array p0, p0, [Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Ljava/util/Vector;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    return-object p0

    .line 37
    :cond_1
    invoke-virtual {p0, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    invoke-virtual {v0, v3}, Ljava/util/Vector;->add(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    add-int/lit8 v3, v2, 0x1

    .line 45
    .line 46
    invoke-virtual {p0, v1, v3}, Ljava/lang/String;->indexOf(II)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    goto :goto_0
.end method


# virtual methods
.method public createSocketFactory(Ljava/lang/String;)Ljavax/net/ssl/SSLSocketFactory;
    .locals 5

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getSSLContext(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->logger:Lorg/eclipse/paho/mqttv5/client/logging/Logger;

    .line 6
    .line 7
    if-eqz v1, :cond_2

    .line 8
    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    move-object v2, p1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const-string v2, "null (broker defaults)"

    .line 14
    .line 15
    :goto_0
    invoke-virtual {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getEnabledCipherSuites(Ljava/lang/String;)[Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    if-eqz v3, :cond_1

    .line 20
    .line 21
    const-string v3, "com.ibm.ssl.enabledCipherSuites"

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct {p0, p1, v3, v4}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    const-string p0, "null (using platform-enabled cipher suites)"

    .line 30
    .line 31
    :goto_1
    filled-new-array {v2, p0}, [Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const-string p1, "org.eclipse.paho.mqttv5.client.internal.security.SSLSocketFactoryFactory"

    .line 36
    .line 37
    const-string v2, "createSocketFactory"

    .line 38
    .line 39
    const-string v3, "12020"

    .line 40
    .line 41
    invoke-interface {v1, p1, v2, v3, p0}, Lorg/eclipse/paho/mqttv5/client/logging/Logger;->fine(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    :cond_2
    invoke-virtual {v0}, Ljavax/net/ssl/SSLContext;->getSocketFactory()Ljavax/net/ssl/SSLSocketFactory;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

.method public getClientAuthentication(Ljava/lang/String;)Z
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.clientAuthentication"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public getConfiguration(Ljava/lang/String;)Ljava/util/Properties;
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Ljava/util/Properties;

    .line 13
    .line 14
    return-object p0
.end method

.method public getEnabledCipherSuites(Ljava/lang/String;)[Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.enabledCipherSuites"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->unpackCipherSuites(Ljava/lang/String;)[Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public getJSSEProvider(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.contextProvider"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public getKeyManager(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.keyManager"

    .line 2
    .line 3
    const-string v1, "ssl.KeyManagerFactory.algorithm"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getKeyStore(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "com.ibm.ssl.keyStore"

    .line 2
    .line 3
    invoke-direct {p0, p1, v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getPropertyFromConfig(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const-string p0, "javax.net.ssl.keyStore"

    .line 11
    .line 12
    invoke-static {p0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public getKeyStorePassword(Ljava/lang/String;)[C
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.keyStorePassword"

    .line 2
    .line 3
    const-string v1, "javax.net.ssl.keyStorePassword"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    const-string p1, "{xor}"

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->deObfuscate(Ljava/lang/String;)[C

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    return-object p0
.end method

.method public getKeyStoreProvider(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.keyStoreProvider"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public getKeyStoreType(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.keyStoreType"

    .line 2
    .line 3
    const-string v1, "javax.net.ssl.keyStoreType"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getSSLProtocol(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.protocol"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public getTrustManager(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.trustManager"

    .line 2
    .line 3
    const-string v1, "ssl.TrustManagerFactory.algorithm"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getTrustStore(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.trustStore"

    .line 2
    .line 3
    const-string v1, "javax.net.ssl.trustStore"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public getTrustStorePassword(Ljava/lang/String;)[C
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.trustStorePassword"

    .line 2
    .line 3
    const-string v1, "javax.net.ssl.trustStorePassword"

    .line 4
    .line 5
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    const-string p1, "{xor}"

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    invoke-static {p0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->deObfuscate(Ljava/lang/String;)[C

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_1
    const/4 p0, 0x0

    .line 30
    return-object p0
.end method

.method public getTrustStoreProvider(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.trustStoreProvider"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public getTrustStoreType(Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "com.ibm.ssl.trustStoreType"

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {p0, p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->getProperty(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    return-object p0
.end method

.method public initialize(Ljava/util/Properties;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->checkPropertyKeys(Ljava/util/Properties;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/Properties;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/Properties;-><init>()V

    .line 7
    .line 8
    .line 9
    invoke-virtual {v0, p1}, Ljava/util/Properties;->putAll(Ljava/util/Map;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->convertPassword(Ljava/util/Properties;)V

    .line 13
    .line 14
    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 18
    .line 19
    invoke-virtual {p0, p2, v0}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 24
    .line 25
    return-void
.end method

.method public merge(Ljava/util/Properties;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->checkPropertyKeys(Ljava/util/Properties;)V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 5
    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 9
    .line 10
    invoke-virtual {v0, p2}, Ljava/util/Hashtable;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Ljava/util/Properties;

    .line 15
    .line 16
    :cond_0
    if-nez v0, :cond_1

    .line 17
    .line 18
    new-instance v0, Ljava/util/Properties;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/Properties;-><init>()V

    .line 21
    .line 22
    .line 23
    :cond_1
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->convertPassword(Ljava/util/Properties;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/util/Properties;->putAll(Ljava/util/Map;)V

    .line 27
    .line 28
    .line 29
    if-eqz p2, :cond_2

    .line 30
    .line 31
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 32
    .line 33
    invoke-virtual {p0, p2, v0}, Ljava/util/Hashtable;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_2
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 38
    .line 39
    return-void
.end method

.method public remove(Ljava/lang/String;)Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-eqz p1, :cond_1

    .line 4
    .line 5
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->configs:Ljava/util/Hashtable;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/Hashtable;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    return v0

    .line 14
    :cond_0
    return v1

    .line 15
    :cond_1
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/security/SSLSocketFactoryFactory;->defaultProperties:Ljava/util/Properties;

    .line 21
    .line 22
    return v0

    .line 23
    :cond_2
    return v1
.end method
