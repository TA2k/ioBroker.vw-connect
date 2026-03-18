.class public final Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersionKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0000\n\u0002\u0010\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u0012\n\u0002\u0008\u0002\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0002H\u0080\u0002\u001a\u000c\u0010\u0004\u001a\u00020\u0005*\u00020\u0002H\u0000\u001a\u000e\u0010\u0006\u001a\u0004\u0018\u00010\u0002*\u00020\u0005H\u0000\u00a8\u0006\u0007"
    }
    d2 = {
        "compareTo",
        "",
        "Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;",
        "other",
        "toByteArray",
        "",
        "toProtocolVersion",
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
    invoke-static {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersionKt;->toProtocolVersion$lambda$0([B)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final compareTo(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;)I
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "other"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMajor-w2LRezQ()B

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    and-int/lit16 v0, v0, 0xff

    .line 16
    .line 17
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMajor-w2LRezQ()B

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    and-int/lit16 v1, v1, 0xff

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/4 v1, 0x1

    .line 28
    if-lez v0, :cond_0

    .line 29
    .line 30
    return v1

    .line 31
    :cond_0
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMajor-w2LRezQ()B

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    and-int/lit16 v0, v0, 0xff

    .line 36
    .line 37
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMajor-w2LRezQ()B

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    and-int/lit16 v2, v2, 0xff

    .line 42
    .line 43
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->g(II)I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    const/4 v2, -0x1

    .line 48
    if-lez v0, :cond_1

    .line 49
    .line 50
    return v2

    .line 51
    :cond_1
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMinor-w2LRezQ()B

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    and-int/lit16 v0, v0, 0xff

    .line 56
    .line 57
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMinor-w2LRezQ()B

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    and-int/lit16 v3, v3, 0xff

    .line 62
    .line 63
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-lez v0, :cond_2

    .line 68
    .line 69
    return v1

    .line 70
    :cond_2
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMinor-w2LRezQ()B

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    and-int/lit16 v0, v0, 0xff

    .line 75
    .line 76
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMinor-w2LRezQ()B

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    and-int/lit16 v3, v3, 0xff

    .line 81
    .line 82
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    if-lez v0, :cond_3

    .line 87
    .line 88
    return v2

    .line 89
    :cond_3
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getPatch-w2LRezQ()B

    .line 90
    .line 91
    .line 92
    move-result v0

    .line 93
    and-int/lit16 v0, v0, 0xff

    .line 94
    .line 95
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getPatch-w2LRezQ()B

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    and-int/lit16 v3, v3, 0xff

    .line 100
    .line 101
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->g(II)I

    .line 102
    .line 103
    .line 104
    move-result v0

    .line 105
    if-lez v0, :cond_4

    .line 106
    .line 107
    return v1

    .line 108
    :cond_4
    invoke-virtual {p1}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getPatch-w2LRezQ()B

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    and-int/lit16 p1, p1, 0xff

    .line 113
    .line 114
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getPatch-w2LRezQ()B

    .line 115
    .line 116
    .line 117
    move-result p0

    .line 118
    and-int/lit16 p0, p0, 0xff

    .line 119
    .line 120
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->g(II)I

    .line 121
    .line 122
    .line 123
    move-result p0

    .line 124
    if-lez p0, :cond_5

    .line 125
    .line 126
    return v2

    .line 127
    :cond_5
    const/4 p0, 0x0

    .line 128
    return p0
.end method

.method public static final toByteArray(Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;)[B
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMajor-w2LRezQ()B

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getMinor-w2LRezQ()B

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-virtual {p0}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;->getPatch-w2LRezQ()B

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    const/4 v2, 0x3

    .line 19
    new-array v2, v2, [B

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    aput-byte v0, v2, v3

    .line 23
    .line 24
    const/4 v0, 0x1

    .line 25
    aput-byte v1, v2, v0

    .line 26
    .line 27
    const/4 v0, 0x2

    .line 28
    aput-byte p0, v2, v0

    .line 29
    .line 30
    return-object v2
.end method

.method public static final toProtocolVersion([B)Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;
    .locals 5

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
    const/4 v1, 0x3

    .line 8
    const/4 v2, 0x0

    .line 9
    if-eq v0, v1, :cond_0

    .line 10
    .line 11
    new-instance v0, Ln51/a;

    .line 12
    .line 13
    const/4 v1, 0x4

    .line 14
    invoke-direct {v0, v1, p0}, Ln51/a;-><init>(I[B)V

    .line 15
    .line 16
    .line 17
    const-string v1, "GenX"

    .line 18
    .line 19
    invoke-static {p0, v1, v2, v0}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    return-object v2

    .line 23
    :cond_0
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    aget-byte v1, p0, v1

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    aget-byte v3, p0, v3

    .line 30
    .line 31
    const/4 v4, 0x2

    .line 32
    aget-byte p0, p0, v4

    .line 33
    .line 34
    invoke-direct {v0, v1, v3, p0, v2}, Ltechnology/cariad/cat/genx/protocol/data/ProtocolVersion;-><init>(BBBLkotlin/jvm/internal/g;)V

    .line 35
    .line 36
    .line 37
    return-object v0
.end method

.method private static final toProtocolVersion$lambda$0([B)Ljava/lang/String;
    .locals 2

    .line 1
    array-length p0, p0

    .line 2
    const-string v0, "toProtocolVersion(): Bytearray requires size 3 but is \'"

    .line 3
    .line 4
    const-string v1, "\' -> Cannot extract ProtocolVersion"

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
