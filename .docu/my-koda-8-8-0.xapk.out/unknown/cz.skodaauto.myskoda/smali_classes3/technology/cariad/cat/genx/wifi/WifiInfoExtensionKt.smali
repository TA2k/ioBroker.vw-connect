.class public final Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\u001a\u0018\u0010\u0000\u001a\u0004\u0018\u00010\u0001*\u00020\u00022\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u0004H\u0000\u001a\u0016\u0010\u0005\u001a\u0004\u0018\u00010\u0006*\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0008H\u0002\u00a8\u0006\t"
    }
    d2 = {
        "wifi",
        "Ltechnology/cariad/cat/genx/wifi/Wifi;",
        "Landroid/net/wifi/WifiInfo;",
        "linkProperties",
        "Landroid/net/LinkProperties;",
        "resolveInetAddressByInt",
        "Ljava/net/InetAddress;",
        "ipAddress",
        "",
        "genx_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static synthetic a()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->resolveInetAddressByInt$lambda$0()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b(I)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->resolveInetAddressByInt$lambda$1(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic c(Ljava/net/InetAddress;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->wifi$lambda$0(Ljava/net/InetAddress;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static final resolveInetAddressByInt(Landroid/net/wifi/WifiInfo;I)Ljava/net/InetAddress;
    .locals 9

    .line 1
    const/4 v1, 0x0

    .line 2
    if-eqz p1, :cond_3

    .line 3
    .line 4
    int-to-long v2, p1

    .line 5
    invoke-static {v2, v3}, Ljava/math/BigInteger;->valueOf(J)Ljava/math/BigInteger;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v2, "valueOf(...)"

    .line 10
    .line 11
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/math/BigInteger;->toByteArray()[B

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    const-string v2, "toByteArray(...)"

    .line 19
    .line 20
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    array-length v2, v0

    .line 24
    if-nez v2, :cond_0

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    array-length v2, v0

    .line 28
    new-array v2, v2, [B

    .line 29
    .line 30
    array-length v3, v0

    .line 31
    add-int/lit8 v3, v3, -0x1

    .line 32
    .line 33
    if-ltz v3, :cond_1

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    :goto_0
    sub-int v5, v3, v4

    .line 37
    .line 38
    aget-byte v6, v0, v4

    .line 39
    .line 40
    aput-byte v6, v2, v5

    .line 41
    .line 42
    if-eq v4, v3, :cond_1

    .line 43
    .line 44
    add-int/lit8 v4, v4, 0x1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_1
    move-object v0, v2

    .line 48
    :goto_1
    array-length v2, v0

    .line 49
    const/4 v3, 0x4

    .line 50
    if-ne v2, v3, :cond_2

    .line 51
    .line 52
    :try_start_0
    invoke-static {v0}, Ljava/net/InetAddress;->getByAddress([B)Ljava/net/InetAddress;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    instance-of v0, p1, Ljava/net/Inet4Address;

    .line 57
    .line 58
    if-eqz v0, :cond_3

    .line 59
    .line 60
    check-cast p1, Ljava/net/Inet4Address;
    :try_end_0
    .catch Ljava/net/UnknownHostException; {:try_start_0 .. :try_end_0} :catch_0

    .line 61
    .line 62
    return-object p1

    .line 63
    :catch_0
    move-exception v0

    .line 64
    move-object p1, v0

    .line 65
    move-object v6, p1

    .line 66
    new-instance v5, Ltechnology/cariad/cat/genx/wifi/g;

    .line 67
    .line 68
    const/4 p1, 0x1

    .line 69
    invoke-direct {v5, p1}, Ltechnology/cariad/cat/genx/wifi/g;-><init>(I)V

    .line 70
    .line 71
    .line 72
    new-instance v2, Lt51/j;

    .line 73
    .line 74
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    const-string p0, "getName(...)"

    .line 79
    .line 80
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v8

    .line 84
    const-string v3, "GenX"

    .line 85
    .line 86
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 87
    .line 88
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 92
    .line 93
    .line 94
    return-object v1

    .line 95
    :cond_2
    new-instance v0, Le1/h1;

    .line 96
    .line 97
    const/16 v2, 0xb

    .line 98
    .line 99
    invoke-direct {v0, p1, v2}, Le1/h1;-><init>(II)V

    .line 100
    .line 101
    .line 102
    const-string p1, "GenX"

    .line 103
    .line 104
    invoke-static {p0, p1, v1, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 105
    .line 106
    .line 107
    :cond_3
    return-object v1
.end method

.method private static final resolveInetAddressByInt$lambda$0()Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "resolveInetAddressByInt(): Exception while getting network address. -> Return null"

    .line 2
    .line 3
    return-object v0
.end method

.method private static final resolveInetAddressByInt$lambda$1(I)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "resolveInetAddressByInt(): \'"

    .line 2
    .line 3
    const-string v1, "\' has invalid format. -> Return null"

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public static final wifi(Landroid/net/wifi/WifiInfo;Landroid/net/LinkProperties;)Ltechnology/cariad/cat/genx/wifi/Wifi;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    if-eqz p1, :cond_2

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/net/LinkProperties;->getLinkAddresses()Ljava/util/List;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    check-cast v0, Ljava/lang/Iterable;

    .line 15
    .line 16
    new-instance v1, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    instance-of v3, v2, Ljava/net/Inet4Address;

    .line 36
    .line 37
    if-eqz v3, :cond_0

    .line 38
    .line 39
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    invoke-static {v1}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Ljava/net/Inet4Address;

    .line 48
    .line 49
    if-eqz v0, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    invoke-virtual {p0}, Landroid/net/wifi/WifiInfo;->getIpAddress()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    invoke-static {p0, v0}, Ltechnology/cariad/cat/genx/wifi/WifiInfoExtensionKt;->resolveInetAddressByInt(Landroid/net/wifi/WifiInfo;I)Ljava/net/InetAddress;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :goto_1
    const/4 v1, 0x0

    .line 61
    if-eqz v0, :cond_5

    .line 62
    .line 63
    instance-of v2, v0, Ljava/net/Inet4Address;

    .line 64
    .line 65
    if-eqz v2, :cond_5

    .line 66
    .line 67
    move-object v2, v0

    .line 68
    check-cast v2, Ljava/net/Inet4Address;

    .line 69
    .line 70
    invoke-virtual {v2}, Ljava/net/Inet4Address;->isLoopbackAddress()Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-nez v3, :cond_5

    .line 75
    .line 76
    invoke-virtual {v2}, Ljava/net/Inet4Address;->isAnyLocalAddress()Z

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    if-eqz v3, :cond_3

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    invoke-virtual {p0}, Landroid/net/wifi/WifiInfo;->getSSID()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    const-string v3, "getSSID(...)"

    .line 88
    .line 89
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const-string v3, ""

    .line 93
    .line 94
    const/4 v4, 0x0

    .line 95
    const-string v5, "\""

    .line 96
    .line 97
    invoke-static {v4, v0, v5, v3}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    if-eqz p1, :cond_4

    .line 102
    .line 103
    invoke-virtual {p1}, Landroid/net/LinkProperties;->getDomains()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    :cond_4
    invoke-virtual {p0}, Landroid/net/wifi/WifiInfo;->getBSSID()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    const-string p1, "getBSSID(...)"

    .line 112
    .line 113
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/Wifi;

    .line 117
    .line 118
    invoke-direct {p1, v0, p0, v2, v1}, Ltechnology/cariad/cat/genx/wifi/Wifi;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/net/Inet4Address;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    return-object p1

    .line 122
    :cond_5
    :goto_2
    new-instance p1, Ltechnology/cariad/cat/genx/wifi/m;

    .line 123
    .line 124
    const/4 v2, 0x3

    .line 125
    invoke-direct {p1, v0, v2}, Ltechnology/cariad/cat/genx/wifi/m;-><init>(Ljava/lang/Object;I)V

    .line 126
    .line 127
    .line 128
    const-string v0, "GenX"

    .line 129
    .line 130
    invoke-static {p0, v0, v1, p1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 131
    .line 132
    .line 133
    return-object v1
.end method

.method private static final wifi$lambda$0(Ljava/net/InetAddress;)Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "wifi(): ipAddress of wifi info is not available or valid: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p0, " -> Return null"

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method
