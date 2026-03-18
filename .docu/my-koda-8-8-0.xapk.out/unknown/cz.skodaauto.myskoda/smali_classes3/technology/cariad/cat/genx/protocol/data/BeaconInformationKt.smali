.class public final Ltechnology/cariad/cat/genx/protocol/data/BeaconInformationKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u001a\u0013\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u0000\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u001a\u0015\u0010\u0004\u001a\u0004\u0018\u00010\u0000*\u00020\u0001H\u0000\u00a2\u0006\u0004\u0008\u0004\u0010\u0005\"\u0014\u0010\u0007\u001a\u00020\u00068\u0002X\u0082T\u00a2\u0006\u0006\n\u0004\u0008\u0007\u0010\u0008\"\u0014\u0010\t\u001a\u00020\u00068\u0002X\u0082T\u00a2\u0006\u0006\n\u0004\u0008\t\u0010\u0008\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "",
        "toByteArray",
        "(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)[B",
        "toBeaconInformation",
        "([B)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;",
        "Llx0/u;",
        "USHORT_MSB_MASK",
        "I",
        "USHORT_LSB_MASK",
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


# static fields
.field private static final USHORT_LSB_MASK:I = 0xff

.field private static final USHORT_MSB_MASK:I = 0xff00


# direct methods
.method public static synthetic a([B)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformationKt;->toBeaconInformation$lambda$0([B)Ljava/lang/String;

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
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformationKt;->toBeaconInformation$lambda$1([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final toBeaconInformation([B)Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;
    .locals 7

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
    const/4 v1, 0x5

    .line 8
    const-string v2, "GenX"

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-eq v0, v1, :cond_0

    .line 12
    .line 13
    new-instance v0, Ln51/a;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1, p0}, Ln51/a;-><init>(I[B)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v2, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    return-object v3

    .line 23
    :cond_0
    const/4 v0, 0x0

    .line 24
    aget-byte v0, p0, v0

    .line 25
    .line 26
    and-int/lit16 v0, v0, 0xff

    .line 27
    .line 28
    const/4 v1, 0x1

    .line 29
    aget-byte v1, p0, v1

    .line 30
    .line 31
    shl-int/lit8 v1, v1, 0x8

    .line 32
    .line 33
    const v4, 0xff00

    .line 34
    .line 35
    .line 36
    and-int/2addr v1, v4

    .line 37
    or-int/2addr v0, v1

    .line 38
    int-to-short v0, v0

    .line 39
    const/4 v1, 0x2

    .line 40
    aget-byte v1, p0, v1

    .line 41
    .line 42
    and-int/lit16 v1, v1, 0xff

    .line 43
    .line 44
    const/4 v5, 0x3

    .line 45
    aget-byte v5, p0, v5

    .line 46
    .line 47
    shl-int/lit8 v5, v5, 0x8

    .line 48
    .line 49
    and-int/2addr v4, v5

    .line 50
    or-int/2addr v1, v4

    .line 51
    int-to-short v1, v1

    .line 52
    const/4 v4, 0x4

    .line 53
    aget-byte v4, p0, v4

    .line 54
    .line 55
    sget-object v5, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->ONLINE:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 56
    .line 57
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->getRawValue()B

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    if-ne v4, v6, :cond_1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    sget-object v5, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->OFFLINE:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 65
    .line 66
    invoke-virtual {v5}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->getRawValue()B

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    if-ne v4, v6, :cond_2

    .line 71
    .line 72
    :goto_0
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;

    .line 73
    .line 74
    invoke-direct {p0, v0, v1, v5, v3}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;-><init>(SSLtechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;Lkotlin/jvm/internal/g;)V

    .line 75
    .line 76
    .line 77
    return-object p0

    .line 78
    :cond_2
    new-instance v0, Ln51/a;

    .line 79
    .line 80
    const/4 v1, 0x1

    .line 81
    invoke-direct {v0, v1, p0}, Ln51/a;-><init>(I[B)V

    .line 82
    .line 83
    .line 84
    invoke-static {p0, v2, v3, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 85
    .line 86
    .line 87
    return-object v3
.end method

.method private static final toBeaconInformation$lambda$0([B)Ljava/lang/String;
    .locals 2

    .line 1
    array-length p0, p0

    .line 2
    const-string v0, "toBeaconInformation(): Bytearray requires size 5 but is \'"

    .line 3
    .line 4
    const-string v1, "\' -> Cannot extract BeaconConfiguration"

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

.method private static final toBeaconInformation$lambda$1([B)Ljava/lang/String;
    .locals 5

    .line 1
    const/4 v0, 0x4

    .line 2
    aget-byte p0, p0, v0

    .line 3
    .line 4
    sget-object v0, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->ONLINE:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 5
    .line 6
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->getRawValue()B

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    sget-object v1, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->OFFLINE:Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 11
    .line 12
    invoke-virtual {v1}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->getRawValue()B

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const-string v2, ", but expected "

    .line 17
    .line 18
    const-string v3, " or "

    .line 19
    .line 20
    const-string v4, "toBeaconInformation(): Byte for \'Source\' is not defined, received "

    .line 21
    .line 22
    invoke-static {p0, v0, v4, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public static final toByteArray(Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;)[B
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->getMajor-Mh2AYeg()S

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    int-to-byte v0, v0

    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->getMajor-Mh2AYeg()S

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const v2, 0xffff

    .line 16
    .line 17
    .line 18
    and-int/2addr v1, v2

    .line 19
    shr-int/lit8 v1, v1, 0x8

    .line 20
    .line 21
    int-to-byte v1, v1

    .line 22
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->getMinor-Mh2AYeg()S

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    int-to-byte v3, v3

    .line 27
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->getMinor-Mh2AYeg()S

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    and-int/2addr v2, v4

    .line 32
    shr-int/lit8 v2, v2, 0x8

    .line 33
    .line 34
    int-to-byte v2, v2

    .line 35
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation;->getSource()Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/BeaconInformation$Source;->getRawValue()B

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    const/4 v4, 0x5

    .line 44
    new-array v4, v4, [B

    .line 45
    .line 46
    const/4 v5, 0x0

    .line 47
    aput-byte v0, v4, v5

    .line 48
    .line 49
    const/4 v0, 0x1

    .line 50
    aput-byte v1, v4, v0

    .line 51
    .line 52
    const/4 v0, 0x2

    .line 53
    aput-byte v3, v4, v0

    .line 54
    .line 55
    const/4 v0, 0x3

    .line 56
    aput-byte v2, v4, v0

    .line 57
    .line 58
    const/4 v0, 0x4

    .line 59
    aput-byte p0, v4, v0

    .line 60
    .line 61
    return-object v4
.end method
