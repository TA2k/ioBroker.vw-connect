.class public final Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0012\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u001a\u000e\u0010\u0000\u001a\u0004\u0018\u00010\u0001*\u00020\u0002H\u0000\u001a\u000e\u0010\u0003\u001a\u0004\u0018\u00010\u0004*\u00020\u0002H\u0000\u001a\u000c\u0010\u0005\u001a\u00020\u0002*\u00020\u0004H\u0000\u001a\u000c\u0010\u0005\u001a\u00020\u0002*\u00020\u0001H\u0000\u00a8\u0006\u0006"
    }
    d2 = {
        "toLinkParametersResponseValues",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;",
        "",
        "toLinkParametersRequestValues",
        "Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;",
        "toByteArray",
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
.method public static synthetic a([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;->toLinkParametersRequestValues$lambda$0([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParametersKt;->toLinkParametersResponseValues$lambda$0([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final toByteArray(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;)[B
    .locals 9

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;->getIntervalMinFactor()I

    move-result v0

    and-int/lit16 v1, v0, 0xff

    int-to-byte v1, v1

    const/16 v2, 0x8

    ushr-int/2addr v0, v2

    int-to-byte v0, v0

    .line 2
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;->getIntervalMaxFactor()I

    move-result v3

    and-int/lit16 v4, v3, 0xff

    int-to-byte v4, v4

    ushr-int/2addr v3, v2

    int-to-byte v3, v3

    .line 3
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;->getConnectionLatency()I

    move-result v5

    and-int/lit16 v6, v5, 0xff

    int-to-byte v6, v6

    ushr-int/2addr v5, v2

    int-to-byte v5, v5

    .line 4
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;->getConnectionTimeoutFactor()I

    move-result p0

    and-int/lit16 v7, p0, 0xff

    int-to-byte v7, v7

    ushr-int/2addr p0, v2

    int-to-byte p0, p0

    .line 5
    new-array v2, v2, [B

    const/4 v8, 0x0

    aput-byte v1, v2, v8

    const/4 v1, 0x1

    aput-byte v0, v2, v1

    const/4 v0, 0x2

    aput-byte v4, v2, v0

    const/4 v0, 0x3

    aput-byte v3, v2, v0

    const/4 v0, 0x4

    aput-byte v6, v2, v0

    const/4 v0, 0x5

    aput-byte v5, v2, v0

    const/4 v0, 0x6

    aput-byte v7, v2, v0

    const/4 v0, 0x7

    aput-byte p0, v2, v0

    return-object v2
.end method

.method public static final toByteArray(Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;)[B
    .locals 8

    const-string v0, "<this>"

    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getInterval()I

    move-result v0

    and-int/lit16 v1, v0, 0xff

    int-to-byte v1, v1

    ushr-int/lit8 v0, v0, 0x8

    int-to-byte v0, v0

    .line 7
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getLatency()I

    move-result v2

    and-int/lit16 v3, v2, 0xff

    int-to-byte v3, v3

    ushr-int/lit8 v2, v2, 0x8

    int-to-byte v2, v2

    .line 8
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getTimeout()I

    move-result v4

    and-int/lit16 v5, v4, 0xff

    int-to-byte v5, v5

    ushr-int/lit8 v4, v4, 0x8

    int-to-byte v4, v4

    .line 9
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;->getLinkParameterStatus()B

    move-result p0

    const/4 v6, 0x7

    new-array v6, v6, [B

    const/4 v7, 0x0

    aput-byte v1, v6, v7

    const/4 v1, 0x1

    aput-byte v0, v6, v1

    const/4 v0, 0x2

    aput-byte v3, v6, v0

    const/4 v0, 0x3

    aput-byte v2, v6, v0

    const/4 v0, 0x4

    aput-byte v5, v6, v0

    const/4 v0, 0x5

    aput-byte v4, v6, v0

    const/4 v0, 0x6

    aput-byte p0, v6, v0

    return-object v6
.end method

.method public static final toLinkParametersRequestValues([B)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    const/16 v1, 0x8

    .line 8
    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    new-instance v5, Ln51/a;

    .line 12
    .line 13
    const/4 v0, 0x2

    .line 14
    invoke-direct {v5, v0, p0}, Ln51/a;-><init>(I[B)V

    .line 15
    .line 16
    .line 17
    new-instance v2, Lt51/j;

    .line 18
    .line 19
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    const-string p0, "getName(...)"

    .line 24
    .line 25
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v8

    .line 29
    const-string v3, "GenX"

    .line 30
    .line 31
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 32
    .line 33
    const/4 v6, 0x0

    .line 34
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x0

    .line 41
    return-object p0

    .line 42
    :cond_0
    const/4 v0, 0x0

    .line 43
    aget-byte v0, p0, v0

    .line 44
    .line 45
    and-int/lit16 v0, v0, 0xff

    .line 46
    .line 47
    const/4 v2, 0x1

    .line 48
    aget-byte v2, p0, v2

    .line 49
    .line 50
    and-int/lit16 v2, v2, 0xff

    .line 51
    .line 52
    shl-int/2addr v2, v1

    .line 53
    add-int/2addr v0, v2

    .line 54
    const/4 v2, 0x2

    .line 55
    aget-byte v2, p0, v2

    .line 56
    .line 57
    and-int/lit16 v2, v2, 0xff

    .line 58
    .line 59
    const/4 v3, 0x3

    .line 60
    aget-byte v3, p0, v3

    .line 61
    .line 62
    and-int/lit16 v3, v3, 0xff

    .line 63
    .line 64
    shl-int/2addr v3, v1

    .line 65
    add-int/2addr v2, v3

    .line 66
    const/4 v3, 0x4

    .line 67
    aget-byte v3, p0, v3

    .line 68
    .line 69
    and-int/lit16 v3, v3, 0xff

    .line 70
    .line 71
    const/4 v4, 0x5

    .line 72
    aget-byte v4, p0, v4

    .line 73
    .line 74
    and-int/lit16 v4, v4, 0xff

    .line 75
    .line 76
    shl-int/2addr v4, v1

    .line 77
    add-int/2addr v3, v4

    .line 78
    const/4 v4, 0x6

    .line 79
    aget-byte v4, p0, v4

    .line 80
    .line 81
    and-int/lit16 v4, v4, 0xff

    .line 82
    .line 83
    const/4 v5, 0x7

    .line 84
    aget-byte p0, p0, v5

    .line 85
    .line 86
    and-int/lit16 p0, p0, 0xff

    .line 87
    .line 88
    shl-int/2addr p0, v1

    .line 89
    add-int/2addr v4, p0

    .line 90
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;

    .line 91
    .line 92
    invoke-direct {p0, v0, v2, v3, v4}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$RequestValues;-><init>(IIII)V

    .line 93
    .line 94
    .line 95
    return-object p0
.end method

.method private static final toLinkParametersRequestValues$lambda$0([B)Ljava/lang/String;
    .locals 2

    .line 1
    array-length p0, p0

    .line 2
    const-string v0, "toLinkParametersResponseValues(): Bytearray requires size 8 but is \'"

    .line 3
    .line 4
    const-string v1, "\' -> Cannot extract LinkParametersRequest"

    .line 5
    .line 6
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public static final toLinkParametersResponseValues([B)Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p0

    .line 7
    const/4 v1, 0x7

    .line 8
    if-eq v0, v1, :cond_0

    .line 9
    .line 10
    new-instance v5, Ln51/a;

    .line 11
    .line 12
    const/4 v0, 0x3

    .line 13
    invoke-direct {v5, v0, p0}, Ln51/a;-><init>(I[B)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Lt51/j;

    .line 17
    .line 18
    invoke-static {p0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->correctedClassFromThisDoNotUse(Ljava/lang/Object;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v7

    .line 22
    const-string p0, "getName(...)"

    .line 23
    .line 24
    invoke-static {p0}, Lp3/m;->h(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v8

    .line 28
    const-string v3, "GenX"

    .line 29
    .line 30
    sget-object v4, Lt51/e;->a:Lt51/e;

    .line 31
    .line 32
    const/4 v6, 0x0

    .line 33
    invoke-direct/range {v2 .. v8}, Lt51/j;-><init>(Ljava/lang/String;Lt51/i;Lay0/a;Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {v2}, Lt51/a;->a(Lt51/j;)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x0

    .line 40
    return-object p0

    .line 41
    :cond_0
    const/4 v0, 0x0

    .line 42
    aget-byte v0, p0, v0

    .line 43
    .line 44
    invoke-static {v0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    const/4 v1, 0x1

    .line 49
    aget-byte v1, p0, v1

    .line 50
    .line 51
    invoke-static {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    shl-int/lit8 v1, v1, 0x8

    .line 56
    .line 57
    or-int/2addr v0, v1

    .line 58
    const/4 v1, 0x2

    .line 59
    aget-byte v1, p0, v1

    .line 60
    .line 61
    invoke-static {v1}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    const/4 v2, 0x3

    .line 66
    aget-byte v2, p0, v2

    .line 67
    .line 68
    invoke-static {v2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    shl-int/lit8 v2, v2, 0x8

    .line 73
    .line 74
    or-int/2addr v1, v2

    .line 75
    const/4 v2, 0x4

    .line 76
    aget-byte v2, p0, v2

    .line 77
    .line 78
    invoke-static {v2}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    const/4 v3, 0x5

    .line 83
    aget-byte v3, p0, v3

    .line 84
    .line 85
    invoke-static {v3}, Ltechnology/cariad/cat/genx/VehicleAntennaTransportKt;->toUnsignedInt(B)I

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    shl-int/lit8 v3, v3, 0x8

    .line 90
    .line 91
    or-int/2addr v2, v3

    .line 92
    const/4 v3, 0x6

    .line 93
    aget-byte p0, p0, v3

    .line 94
    .line 95
    new-instance v3, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 96
    .line 97
    invoke-direct {v3, v0, v1, v2, p0}, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;-><init>(IIIB)V

    .line 98
    .line 99
    .line 100
    return-object v3
.end method

.method private static final toLinkParametersResponseValues$lambda$0([B)Ljava/lang/String;
    .locals 2

    .line 1
    array-length p0, p0

    .line 2
    const-string v0, "toLinkParametersResponseValues(): Bytearray requires size 7 but is \'"

    .line 3
    .line 4
    const-string v1, "\' -> Cannot extract LinkParametersResponse"

    .line 5
    .line 6
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
