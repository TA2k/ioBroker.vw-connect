.class public final Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;,
        Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;,
        Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
    }
.end annotation


# static fields
.field private static final ATTRIBUTES_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

.field private static final GROUPER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

.field private static final MAX_INNER_LOOP_SIZE:I = 0x7f8

.field private static final MOST_SIGNIFICANT_BIT_MASK:J = -0x7f7f7f7f7f7f7f80L


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->GROUPER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->key()Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->ATTRIBUTES_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 12
    .line 13
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->lambda$sizeRepeatedMessageWithContext$1()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic b()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->lambda$sizeRepeatedMessageWithContext$2()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static synthetic c()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->lambda$sizeRepeatedMessageWithContext$3()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static countNegative([B)I
    .locals 14

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    move v3, v0

    .line 4
    move v4, v3

    .line 5
    move v2, v1

    .line 6
    :goto_0
    array-length v5, p0

    .line 7
    div-int/lit16 v5, v5, 0x7f8

    .line 8
    .line 9
    add-int/2addr v5, v1

    .line 10
    if-gt v2, v5, :cond_2

    .line 11
    .line 12
    mul-int/lit16 v5, v2, 0x7f8

    .line 13
    .line 14
    array-length v6, p0

    .line 15
    and-int/lit8 v6, v6, -0x8

    .line 16
    .line 17
    invoke-static {v5, v6}, Ljava/lang/Math;->min(II)I

    .line 18
    .line 19
    .line 20
    move-result v5

    .line 21
    const-wide/16 v6, 0x0

    .line 22
    .line 23
    move-wide v8, v6

    .line 24
    :goto_1
    if-ge v3, v5, :cond_0

    .line 25
    .line 26
    invoke-static {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->getLong([BI)J

    .line 27
    .line 28
    .line 29
    move-result-wide v10

    .line 30
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr v10, v12

    .line 36
    const/4 v12, 0x7

    .line 37
    ushr-long/2addr v10, v12

    .line 38
    add-long/2addr v8, v10

    .line 39
    add-int/lit8 v3, v3, 0x8

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_0
    cmp-long v5, v8, v6

    .line 43
    .line 44
    if-eqz v5, :cond_1

    .line 45
    .line 46
    move v5, v0

    .line 47
    :goto_2
    const/16 v6, 0x8

    .line 48
    .line 49
    if-ge v5, v6, :cond_1

    .line 50
    .line 51
    const-wide/16 v10, 0xff

    .line 52
    .line 53
    and-long/2addr v10, v8

    .line 54
    long-to-int v7, v10

    .line 55
    add-int/2addr v4, v7

    .line 56
    ushr-long/2addr v8, v6

    .line 57
    add-int/lit8 v5, v5, 0x1

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_2
    :goto_3
    array-length v0, p0

    .line 64
    if-ge v3, v0, :cond_3

    .line 65
    .line 66
    aget-byte v0, p0, v3

    .line 67
    .line 68
    ushr-int/lit8 v0, v0, 0x1f

    .line 69
    .line 70
    add-int/2addr v4, v0

    .line 71
    add-int/lit8 v3, v3, 0x1

    .line 72
    .line 73
    goto :goto_3

    .line 74
    :cond_3
    return v4
.end method

.method public static synthetic d()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->lambda$groupByResourceAndScope$0()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method private static encodeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    const/16 v2, 0x80

    .line 7
    .line 8
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-ge v3, v2, :cond_0

    .line 15
    .line 16
    int-to-byte v2, v3

    .line 17
    invoke-virtual {p0, v2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v1, v1, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    if-ne v1, v0, :cond_1

    .line 24
    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_1
    :goto_1
    if-ge v1, v0, :cond_6

    .line 28
    .line 29
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-ge v3, v2, :cond_2

    .line 34
    .line 35
    int-to-byte v3, v3

    .line 36
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 37
    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_2
    const/16 v4, 0x800

    .line 41
    .line 42
    if-ge v3, v4, :cond_3

    .line 43
    .line 44
    ushr-int/lit8 v4, v3, 0x6

    .line 45
    .line 46
    or-int/lit16 v4, v4, 0x3c0

    .line 47
    .line 48
    int-to-byte v4, v4

    .line 49
    invoke-virtual {p0, v4}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 50
    .line 51
    .line 52
    and-int/lit8 v3, v3, 0x3f

    .line 53
    .line 54
    or-int/2addr v3, v2

    .line 55
    int-to-byte v3, v3

    .line 56
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {v3}, Ljava/lang/Character;->isSurrogate(C)Z

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    const/16 v5, 0x3f

    .line 65
    .line 66
    if-nez v4, :cond_4

    .line 67
    .line 68
    ushr-int/lit8 v4, v3, 0xc

    .line 69
    .line 70
    or-int/lit16 v4, v4, 0x1e0

    .line 71
    .line 72
    int-to-byte v4, v4

    .line 73
    invoke-virtual {p0, v4}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 74
    .line 75
    .line 76
    ushr-int/lit8 v4, v3, 0x6

    .line 77
    .line 78
    and-int/2addr v4, v5

    .line 79
    or-int/2addr v4, v2

    .line 80
    int-to-byte v4, v4

    .line 81
    invoke-virtual {p0, v4}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 82
    .line 83
    .line 84
    and-int/lit8 v3, v3, 0x3f

    .line 85
    .line 86
    or-int/2addr v3, v2

    .line 87
    int-to-byte v3, v3

    .line 88
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    invoke-static {p1, v1}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 93
    .line 94
    .line 95
    move-result v4

    .line 96
    if-eq v4, v3, :cond_5

    .line 97
    .line 98
    ushr-int/lit8 v3, v4, 0x12

    .line 99
    .line 100
    or-int/lit16 v3, v3, 0xf0

    .line 101
    .line 102
    int-to-byte v3, v3

    .line 103
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 104
    .line 105
    .line 106
    ushr-int/lit8 v3, v4, 0xc

    .line 107
    .line 108
    and-int/2addr v3, v5

    .line 109
    or-int/2addr v3, v2

    .line 110
    int-to-byte v3, v3

    .line 111
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 112
    .line 113
    .line 114
    ushr-int/lit8 v3, v4, 0x6

    .line 115
    .line 116
    and-int/2addr v3, v5

    .line 117
    or-int/2addr v3, v2

    .line 118
    int-to-byte v3, v3

    .line 119
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 120
    .line 121
    .line 122
    and-int/lit8 v3, v4, 0x3f

    .line 123
    .line 124
    or-int/2addr v3, v2

    .line 125
    int-to-byte v3, v3

    .line 126
    invoke-virtual {p0, v3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 127
    .line 128
    .line 129
    add-int/lit8 v1, v1, 0x1

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_5
    invoke-virtual {p0, v5}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write(B)V

    .line 133
    .line 134
    .line 135
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 136
    .line 137
    goto :goto_1

    .line 138
    :cond_6
    :goto_3
    return-void
.end method

.method private static encodedUtf8Length(Ljava/lang/String;)I
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/16 v3, 0x80

    .line 13
    .line 14
    if-ge v2, v3, :cond_0

    .line 15
    .line 16
    add-int/lit8 v1, v1, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v2, v0

    .line 20
    :goto_1
    if-ge v1, v0, :cond_2

    .line 21
    .line 22
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    const/16 v4, 0x800

    .line 27
    .line 28
    if-ge v3, v4, :cond_1

    .line 29
    .line 30
    rsub-int/lit8 v3, v3, 0x7f

    .line 31
    .line 32
    ushr-int/lit8 v3, v3, 0x1f

    .line 33
    .line 34
    add-int/2addr v2, v3

    .line 35
    add-int/lit8 v1, v1, 0x1

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    invoke-static {p0, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->encodedUtf8LengthGeneral(Ljava/lang/String;I)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    add-int/2addr v2, p0

    .line 43
    :cond_2
    if-lt v2, v0, :cond_3

    .line 44
    .line 45
    return v2

    .line 46
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 47
    .line 48
    new-instance v0, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v1, "UTF-8 length does not fit in int: "

    .line 51
    .line 52
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    int-to-long v1, v2

    .line 56
    const-wide v3, 0x100000000L

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    add-long/2addr v1, v3

    .line 62
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0
.end method

.method private static encodedUtf8LengthGeneral(Ljava/lang/String;I)I
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge p1, v0, :cond_3

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/16 v3, 0x800

    .line 13
    .line 14
    if-ge v2, v3, :cond_0

    .line 15
    .line 16
    rsub-int/lit8 v2, v2, 0x7f

    .line 17
    .line 18
    ushr-int/lit8 v2, v2, 0x1f

    .line 19
    .line 20
    add-int/2addr v1, v2

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    add-int/lit8 v3, v1, 0x2

    .line 23
    .line 24
    invoke-static {v2}, Ljava/lang/Character;->isSurrogate(C)Z

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    if-eqz v4, :cond_1

    .line 29
    .line 30
    invoke-static {p0, p1}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-eq v4, v2, :cond_2

    .line 35
    .line 36
    add-int/lit8 p1, p1, 0x1

    .line 37
    .line 38
    :cond_1
    move v1, v3

    .line 39
    :cond_2
    :goto_1
    add-int/lit8 p1, p1, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_3
    return v1
.end method

.method private static getUtf8Size(Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 0

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringUnsafe()Z

    move-result p1

    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->getUtf8Size(Ljava/lang/String;Z)I

    move-result p0

    return p0
.end method

.method public static getUtf8Size(Ljava/lang/String;Z)I
    .locals 0

    if-eqz p1, :cond_0

    .line 2
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->isAvailable()Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->isLatin1(Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 3
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->getBytes(Ljava/lang/String;)[B

    move-result-object p1

    .line 4
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p0

    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->countNegative([B)I

    move-result p1

    add-int/2addr p0, p1

    return p0

    .line 5
    :cond_0
    invoke-static {p0}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->encodedUtf8Length(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public static groupByResourceAndScope(Ljava/util/Collection;Ljava/util/function/Function;Ljava/util/function/Function;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)Ljava/util/Map;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Collection<",
            "TT;>;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/resources/Resource;",
            ">;",
            "Ljava/util/function/Function<",
            "TT;",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/resources/Resource;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "Ljava/util/List<",
            "TT;>;>;>;"
        }
    .end annotation

    .line 1
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getIdentityMap()Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->GROUPER_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    .line 6
    .line 7
    new-instance v2, Lio/opentelemetry/exporter/internal/marshal/a;

    .line 8
    .line 9
    const/4 v3, 0x7

    .line 10
    invoke-direct {v2, v3}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p3, v1, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getInstance(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;Ljava/util/function/Supplier;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;

    .line 18
    .line 19
    invoke-virtual {v1, v0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;->initialize(Ljava/util/Map;Ljava/util/function/Function;Ljava/util/function/Function;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {p0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

.method private static synthetic lambda$groupByResourceAndScope$0()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$Grouper;-><init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method private static synthetic lambda$sizeRepeatedMessageWithContext$1()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;-><init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method private static synthetic lambda$sizeRepeatedMessageWithContext$2()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;-><init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method private static synthetic lambda$sizeRepeatedMessageWithContext$3()Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;-><init>(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$1;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method private static sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeLengthDelimitedFieldSize(I)I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    add-int/2addr p1, p0

    .line 14
    return p1
.end method

.method public static sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "TT;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 1
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addSize()I

    move-result v0

    .line 2
    invoke-interface {p2, p1, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p1

    .line 3
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p2

    add-int/2addr p2, p0

    add-int/2addr p2, p1

    .line 4
    invoke-virtual {p3, v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->setSize(II)V

    return p2
.end method

.method public static sizeMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "TK;TV;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
            "TK;TV;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 5
    invoke-virtual {p4}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addSize()I

    move-result v0

    .line 6
    invoke-interface {p3, p1, p2, p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;->getBinarySerializedSize(Ljava/lang/Object;Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p1

    .line 7
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result p2

    add-int/2addr p2, p0

    add-int/2addr p2, p1

    .line 8
    invoke-virtual {p4, v0, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->setSize(II)V

    return p2
.end method

.method public static sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "*>;",
            "Ljava/lang/Object;",
            ">;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 23
    invoke-interface {p1}, Lio/opentelemetry/api/common/Attributes;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    return p0

    .line 24
    :cond_0
    sget-object v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->ATTRIBUTES_SIZE_CALCULATOR_KEY:Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;

    new-instance v1, Lio/opentelemetry/exporter/internal/marshal/a;

    const/4 v2, 0x6

    invoke-direct {v1, v2}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    .line 25
    invoke-virtual {p3, v0, v1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getInstance(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;Ljava/util/function/Supplier;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 26
    invoke-virtual {v0, p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->initialize(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 27
    invoke-interface {p1, v0}, Lio/opentelemetry/api/common/Attributes;->forEach(Ljava/util/function/BiConsumer;)V

    .line 28
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->access$100(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;)I

    move-result p0

    return p0
.end method

.method public static sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Collection;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/Collection<",
            "+TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;",
            ")I"
        }
    .end annotation

    .line 9
    instance-of v0, p1, Ljava/util/List;

    if-eqz v0, :cond_0

    .line 10
    check-cast p1, Ljava/util/List;

    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result p0

    return p0

    .line 11
    :cond_0
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 p0, 0x0

    return p0

    .line 12
    :cond_1
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/a;

    const/4 v1, 0x5

    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    .line 13
    invoke-virtual {p3, p4, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getInstance(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;Ljava/util/function/Supplier;)Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;

    .line 14
    invoke-virtual {p4, p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;->initialize(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 15
    invoke-interface {p1, p4}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 16
    invoke-static {p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;->access$000(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementSizeCalculator;)I

    move-result p0

    return p0
.end method

.method public static sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/List;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/List<",
            "+TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler<",
            "TT;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            ")I"
        }
    .end annotation

    .line 1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    .line 2
    :cond_0
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    move-result p0

    move v0, v1

    .line 3
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v2

    if-ge v1, v2, :cond_1

    .line 4
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    .line 5
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addSize()I

    move-result v3

    .line 6
    invoke-interface {p2, v2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler;->getBinarySerializedSize(Ljava/lang/Object;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    move-result v2

    .line 7
    invoke-virtual {p3, v3, v2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->setSize(II)V

    .line 8
    invoke-static {v2}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->computeUInt32SizeNoTag(I)I

    move-result v3

    add-int/2addr v3, p0

    add-int/2addr v3, v2

    add-int/2addr v0, v3

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    return v0
.end method

.method public static sizeRepeatedMessageWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/util/Map;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;",
            "Ljava/util/Map<",
            "TK;TV;>;",
            "Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2<",
            "TK;TV;>;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;",
            "Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;",
            ")I"
        }
    .end annotation

    .line 17
    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    return p0

    .line 18
    :cond_0
    new-instance v0, Lio/opentelemetry/exporter/internal/marshal/a;

    const/16 v1, 0x8

    invoke-direct {v0, v1}, Lio/opentelemetry/exporter/internal/marshal/a;-><init>(I)V

    .line 19
    invoke-virtual {p3, p4, v0}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->getInstance(Lio/opentelemetry/exporter/internal/marshal/MarshalerContext$Key;Ljava/util/function/Supplier;)Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;

    .line 20
    invoke-virtual {p4, p0, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->initialize(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Lio/opentelemetry/exporter/internal/marshal/StatelessMarshaler2;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V

    .line 21
    invoke-interface {p1, p4}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 22
    invoke-static {p4}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;->access$100(Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil$RepeatedElementPairSizeCalculator;)I

    move-result p0

    return p0
.end method

.method public static sizeStringWithContext(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p2}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringNoAllocation()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-static {p1, p2}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->getUtf8Size(Ljava/lang/String;Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-virtual {p2, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addSize(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    :cond_1
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerUtil;->toBytes(Ljava/lang/String;)[B

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-virtual {p2, p1}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->addData(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    array-length p1, p1

    .line 36
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0

    .line 41
    :cond_2
    :goto_0
    const/4 p1, 0x0

    .line 42
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->sizeBytes(Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;I)I

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    return p0
.end method

.method public static writeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;ILio/opentelemetry/exporter/internal/marshal/MarshalerContext;)V
    .locals 0

    .line 1
    invoke-virtual {p3}, Lio/opentelemetry/exporter/internal/marshal/MarshalerContext;->marshalStringUnsafe()Z

    move-result p3

    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->writeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;IZ)V

    return-void
.end method

.method public static writeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;IZ)V
    .locals 0

    if-eqz p3, :cond_0

    .line 2
    invoke-static {}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->isAvailable()Z

    move-result p3

    if-eqz p3, :cond_0

    .line 3
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p3

    if-ne p3, p2, :cond_0

    .line 4
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->isLatin1(Ljava/lang/String;)Z

    move-result p2

    if-eqz p2, :cond_0

    .line 5
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/marshal/UnsafeString;->getBytes(Ljava/lang/String;)[B

    move-result-object p1

    const/4 p2, 0x0

    .line 6
    array-length p3, p1

    invoke-virtual {p0, p1, p2, p3}, Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;->write([BII)V

    return-void

    .line 7
    :cond_0
    invoke-static {p0, p1}, Lio/opentelemetry/exporter/internal/marshal/StatelessMarshalerUtil;->encodeUtf8(Lio/opentelemetry/exporter/internal/marshal/CodedOutputStream;Ljava/lang/String;)V

    return-void
.end method
