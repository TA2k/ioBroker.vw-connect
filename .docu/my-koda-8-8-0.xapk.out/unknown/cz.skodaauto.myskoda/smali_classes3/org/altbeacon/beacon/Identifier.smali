.class public Lorg/altbeacon/beacon/Identifier;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;
.implements Ljava/io/Serializable;


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Ljava/lang/Comparable<",
        "Lorg/altbeacon/beacon/Identifier;",
        ">;",
        "Ljava/io/Serializable;"
    }
.end annotation


# static fields
.field private static final DECIMAL_PATTERN:Ljava/util/regex/Pattern;

.field private static final HEX_DIGITS:[C

.field private static final HEX_PATTERN:Ljava/util/regex/Pattern;

.field private static final HEX_PATTERN_NO_PREFIX:Ljava/util/regex/Pattern;

.field private static final MAX_INTEGER:I = 0xffff

.field private static final UUID_PATTERN:Ljava/util/regex/Pattern;


# instance fields
.field private final mValue:[B


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "^0x[0-9A-Fa-f]*$"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lorg/altbeacon/beacon/Identifier;->HEX_PATTERN:Ljava/util/regex/Pattern;

    .line 8
    .line 9
    const-string v0, "^[0-9A-Fa-f]*$"

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lorg/altbeacon/beacon/Identifier;->HEX_PATTERN_NO_PREFIX:Ljava/util/regex/Pattern;

    .line 16
    .line 17
    const-string v0, "^0|[1-9][0-9]*$"

    .line 18
    .line 19
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lorg/altbeacon/beacon/Identifier;->DECIMAL_PATTERN:Ljava/util/regex/Pattern;

    .line 24
    .line 25
    const-string v0, "^[0-9A-Fa-f]{8}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{4}-?[0-9A-Fa-f]{12}$"

    .line 26
    .line 27
    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lorg/altbeacon/beacon/Identifier;->UUID_PATTERN:Ljava/util/regex/Pattern;

    .line 32
    .line 33
    const/16 v0, 0x10

    .line 34
    .line 35
    new-array v0, v0, [C

    .line 36
    .line 37
    fill-array-data v0, :array_0

    .line 38
    .line 39
    .line 40
    sput-object v0, Lorg/altbeacon/beacon/Identifier;->HEX_DIGITS:[C

    .line 41
    .line 42
    return-void

    .line 43
    :array_0
    .array-data 2
        0x30s
        0x31s
        0x32s
        0x33s
        0x34s
        0x35s
        0x36s
        0x37s
        0x38s
        0x39s
        0x61s
        0x62s
        0x63s
        0x64s
        0x65s
        0x66s
    .end array-data
.end method

.method public constructor <init>(Lorg/altbeacon/beacon/Identifier;)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    .line 2
    iget-object p1, p1, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    iput-object p1, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    return-void

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "Identifiers cannot be constructed from null pointers but \"identifier\" is null."

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>([B)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    .line 5
    iput-object p1, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string p1, "Identifiers cannot be constructed from null pointers but \"value\" is null."

    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static fromBytes([BIIZ)Lorg/altbeacon/beacon/Identifier;
    .locals 1
    .annotation build Landroid/annotation/TargetApi;
        value = 0x9
    .end annotation

    .line 1
    if-eqz p0, :cond_4

    .line 2
    .line 3
    if-ltz p1, :cond_3

    .line 4
    .line 5
    array-length v0, p0

    .line 6
    if-gt p1, v0, :cond_3

    .line 7
    .line 8
    array-length v0, p0

    .line 9
    if-gt p2, v0, :cond_2

    .line 10
    .line 11
    if-gt p1, p2, :cond_1

    .line 12
    .line 13
    invoke-static {p0, p1, p2}, Ljava/util/Arrays;->copyOfRange([BII)[B

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p3, :cond_0

    .line 18
    .line 19
    invoke-static {p0}, Lorg/altbeacon/beacon/Identifier;->reverseArray([B)V

    .line 20
    .line 21
    .line 22
    :cond_0
    new-instance p1, Lorg/altbeacon/beacon/Identifier;

    .line 23
    .line 24
    invoke-direct {p1, p0}, Lorg/altbeacon/beacon/Identifier;-><init>([B)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    const-string p1, "start > end"

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    :cond_2
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 37
    .line 38
    const-string p1, "end > bytes.length"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_3
    new-instance p0, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 45
    .line 46
    const-string p1, "start < 0 || start > bytes.length"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 53
    .line 54
    const-string p1, "Identifiers cannot be constructed from null pointers but \"bytes\" is null."

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0
.end method

.method public static fromInt(I)Lorg/altbeacon/beacon/Identifier;
    .locals 3

    .line 1
    if-ltz p0, :cond_0

    .line 2
    .line 3
    const v0, 0xffff

    .line 4
    .line 5
    .line 6
    if-gt p0, v0, :cond_0

    .line 7
    .line 8
    shr-int/lit8 v0, p0, 0x8

    .line 9
    .line 10
    int-to-byte v0, v0

    .line 11
    int-to-byte p0, p0

    .line 12
    const/4 v1, 0x2

    .line 13
    new-array v1, v1, [B

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    aput-byte v0, v1, v2

    .line 17
    .line 18
    const/4 v0, 0x1

    .line 19
    aput-byte p0, v1, v0

    .line 20
    .line 21
    new-instance p0, Lorg/altbeacon/beacon/Identifier;

    .line 22
    .line 23
    invoke-direct {p0, v1}, Lorg/altbeacon/beacon/Identifier;-><init>([B)V

    .line 24
    .line 25
    .line 26
    return-object p0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string v0, "Identifiers can only be constructed from integers between 0 and 65535 (inclusive)."

    .line 30
    .line 31
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method

.method public static fromLong(JI)Lorg/altbeacon/beacon/Identifier;
    .locals 3

    .line 1
    if-ltz p2, :cond_1

    .line 2
    .line 3
    new-array v0, p2, [B

    .line 4
    .line 5
    add-int/lit8 p2, p2, -0x1

    .line 6
    .line 7
    :goto_0
    if-ltz p2, :cond_0

    .line 8
    .line 9
    const-wide/16 v1, 0xff

    .line 10
    .line 11
    and-long/2addr v1, p0

    .line 12
    long-to-int v1, v1

    .line 13
    int-to-byte v1, v1

    .line 14
    aput-byte v1, v0, p2

    .line 15
    .line 16
    const/16 v1, 0x8

    .line 17
    .line 18
    shr-long/2addr p0, v1

    .line 19
    add-int/lit8 p2, p2, -0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Lorg/altbeacon/beacon/Identifier;

    .line 23
    .line 24
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/Identifier;-><init>([B)V

    .line 25
    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 29
    .line 30
    const-string p1, "Identifier length must be > 0."

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static fromUuid(Ljava/util/UUID;)Lorg/altbeacon/beacon/Identifier;
    .locals 3

    .line 1
    const/16 v0, 0x10

    .line 2
    .line 3
    invoke-static {v0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Ljava/util/UUID;->getMostSignificantBits()J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-virtual {v0, v1, v2}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/util/UUID;->getLeastSignificantBits()J

    .line 15
    .line 16
    .line 17
    move-result-wide v1

    .line 18
    invoke-virtual {v0, v1, v2}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 19
    .line 20
    .line 21
    new-instance p0, Lorg/altbeacon/beacon/Identifier;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/nio/ByteBuffer;->array()[B

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/Identifier;-><init>([B)V

    .line 28
    .line 29
    .line 30
    return-object p0
.end method

.method public static parse(Ljava/lang/String;)Lorg/altbeacon/beacon/Identifier;
    .locals 1

    const/4 v0, -0x1

    .line 1
    invoke-static {p0, v0}, Lorg/altbeacon/beacon/Identifier;->parse(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0
.end method

.method public static parse(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;
    .locals 2

    if-nez p0, :cond_0

    const/4 p0, 0x0

    return-object p0

    .line 2
    :cond_0
    sget-object v0, Lorg/altbeacon/beacon/Identifier;->HEX_PATTERN:Ljava/util/regex/Pattern;

    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_1

    .line 3
    invoke-virtual {p0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p1}, Lorg/altbeacon/beacon/Identifier;->parseHex(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0

    .line 4
    :cond_1
    sget-object v0, Lorg/altbeacon/beacon/Identifier;->UUID_PATTERN:Ljava/util/regex/Pattern;

    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v0

    if-eqz v0, :cond_2

    .line 5
    const-string v0, "-"

    const-string v1, ""

    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p1}, Lorg/altbeacon/beacon/Identifier;->parseHex(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0

    .line 6
    :cond_2
    sget-object v0, Lorg/altbeacon/beacon/Identifier;->DECIMAL_PATTERN:Ljava/util/regex/Pattern;

    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v0

    if-eqz v0, :cond_5

    .line 7
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(Ljava/lang/String;)Ljava/lang/Integer;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-lez p1, :cond_4

    if-ne p1, v1, :cond_3

    goto :goto_0

    :cond_3
    int-to-long v0, p0

    .line 8
    invoke-static {v0, v1, p1}, Lorg/altbeacon/beacon/Identifier;->fromLong(JI)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0

    .line 9
    :cond_4
    :goto_0
    invoke-static {p0}, Lorg/altbeacon/beacon/Identifier;->fromInt(I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0

    :catchall_0
    move-exception p0

    .line 10
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Unable to parse Identifier in decimal format."

    invoke-direct {p1, v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw p1

    .line 11
    :cond_5
    sget-object v0, Lorg/altbeacon/beacon/Identifier;->HEX_PATTERN_NO_PREFIX:Ljava/util/regex/Pattern;

    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object v0

    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v0

    if-eqz v0, :cond_6

    .line 12
    invoke-static {p0, p1}, Lorg/altbeacon/beacon/Identifier;->parseHex(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;

    move-result-object p0

    return-object p0

    .line 13
    :cond_6
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unable to parse Identifier."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private static parseHex(Ljava/lang/String;I)Lorg/altbeacon/beacon/Identifier;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    rem-int/lit8 v0, v0, 0x2

    .line 6
    .line 7
    const-string v1, "0"

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const-string v0, ""

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move-object v0, v1

    .line 15
    :goto_0
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p0}, Ljava/lang/String;->toUpperCase()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    if-lez p1, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    div-int/lit8 v0, v0, 0x2

    .line 37
    .line 38
    if-ge p1, v0, :cond_1

    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    mul-int/lit8 v2, p1, 0x2

    .line 45
    .line 46
    sub-int/2addr v0, v2

    .line 47
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    :cond_1
    if-lez p1, :cond_3

    .line 52
    .line 53
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    div-int/lit8 v0, v0, 0x2

    .line 58
    .line 59
    if-le p1, v0, :cond_3

    .line 60
    .line 61
    mul-int/lit8 p1, p1, 0x2

    .line 62
    .line 63
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    sub-int/2addr p1, v0

    .line 68
    new-instance v0, Ljava/lang/StringBuilder;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 71
    .line 72
    .line 73
    :goto_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    if-ge v2, p1, :cond_2

    .line 78
    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 84
    .line 85
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    :cond_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    div-int/lit8 p1, p1, 0x2

    .line 107
    .line 108
    new-array v0, p1, [B

    .line 109
    .line 110
    const/4 v1, 0x0

    .line 111
    :goto_2
    if-ge v1, p1, :cond_4

    .line 112
    .line 113
    mul-int/lit8 v2, v1, 0x2

    .line 114
    .line 115
    add-int/lit8 v3, v2, 0x2

    .line 116
    .line 117
    invoke-virtual {p0, v2, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    const/16 v3, 0x10

    .line 122
    .line 123
    invoke-static {v2, v3}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;I)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    and-int/lit16 v2, v2, 0xff

    .line 128
    .line 129
    int-to-byte v2, v2

    .line 130
    aput-byte v2, v0, v1

    .line 131
    .line 132
    add-int/lit8 v1, v1, 0x1

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_4
    new-instance p0, Lorg/altbeacon/beacon/Identifier;

    .line 136
    .line 137
    invoke-direct {p0, v0}, Lorg/altbeacon/beacon/Identifier;-><init>([B)V

    .line 138
    .line 139
    .line 140
    return-object p0
.end method

.method private static reverseArray([B)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    array-length v1, p0

    .line 3
    div-int/lit8 v1, v1, 0x2

    .line 4
    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    array-length v1, p0

    .line 8
    sub-int/2addr v1, v0

    .line 9
    add-int/lit8 v1, v1, -0x1

    .line 10
    .line 11
    aget-byte v2, p0, v0

    .line 12
    .line 13
    aget-byte v3, p0, v1

    .line 14
    .line 15
    aput-byte v3, p0, v0

    .line 16
    .line 17
    aput-byte v2, p0, v1

    .line 18
    .line 19
    add-int/lit8 v0, v0, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-void
.end method


# virtual methods
.method public bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lorg/altbeacon/beacon/Identifier;

    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Identifier;->compareTo(Lorg/altbeacon/beacon/Identifier;)I

    move-result p0

    return p0
.end method

.method public compareTo(Lorg/altbeacon/beacon/Identifier;)I
    .locals 6

    .line 2
    iget-object v0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    array-length v1, v0

    iget-object v2, p1, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    array-length v3, v2

    const/4 v4, -0x1

    const/4 v5, 0x1

    if-eq v1, v3, :cond_1

    .line 3
    array-length p0, v0

    array-length p1, v2

    if-ge p0, p1, :cond_0

    return v4

    :cond_0
    return v5

    :cond_1
    const/4 v0, 0x0

    move v1, v0

    .line 4
    :goto_0
    iget-object v2, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    array-length v3, v2

    if-ge v1, v3, :cond_4

    .line 5
    aget-byte v2, v2, v1

    iget-object v3, p1, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    aget-byte v3, v3, v1

    if-eq v2, v3, :cond_3

    if-ge v2, v3, :cond_2

    return v4

    :cond_2
    return v5

    :cond_3
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_4
    return v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lorg/altbeacon/beacon/Identifier;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Lorg/altbeacon/beacon/Identifier;

    .line 8
    .line 9
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 10
    .line 11
    iget-object p1, p1, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 12
    .line 13
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public getByteCount()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toByteArray()[B
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    invoke-virtual {p0}, [B->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, [B

    .line 8
    .line 9
    return-object p0
.end method

.method public toByteArrayOfSpecifiedEndianness(Z)[B
    .locals 1
    .annotation build Landroid/annotation/TargetApi;
        value = 0x9
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {p0, v0}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    invoke-static {p0}, Lorg/altbeacon/beacon/Identifier;->reverseArray([B)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-object p0
.end method

.method public toHexString()Ljava/lang/String;
    .locals 9

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    mul-int/lit8 v1, v0, 0x2

    .line 5
    .line 6
    const/4 v2, 0x2

    .line 7
    add-int/2addr v1, v2

    .line 8
    new-array v1, v1, [C

    .line 9
    .line 10
    const/16 v3, 0x30

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    aput-char v3, v1, v4

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    const/16 v5, 0x78

    .line 17
    .line 18
    aput-char v5, v1, v3

    .line 19
    .line 20
    move v3, v2

    .line 21
    :goto_0
    if-ge v4, v0, :cond_0

    .line 22
    .line 23
    add-int/lit8 v5, v3, 0x1

    .line 24
    .line 25
    sget-object v6, Lorg/altbeacon/beacon/Identifier;->HEX_DIGITS:[C

    .line 26
    .line 27
    iget-object v7, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 28
    .line 29
    aget-byte v7, v7, v4

    .line 30
    .line 31
    and-int/lit16 v8, v7, 0xf0

    .line 32
    .line 33
    ushr-int/lit8 v8, v8, 0x4

    .line 34
    .line 35
    aget-char v8, v6, v8

    .line 36
    .line 37
    aput-char v8, v1, v3

    .line 38
    .line 39
    add-int/2addr v3, v2

    .line 40
    and-int/lit8 v7, v7, 0xf

    .line 41
    .line 42
    aget-char v6, v6, v7

    .line 43
    .line 44
    aput-char v6, v1, v5

    .line 45
    .line 46
    add-int/lit8 v4, v4, 0x1

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    new-instance p0, Ljava/lang/String;

    .line 50
    .line 51
    invoke-direct {p0, v1}, Ljava/lang/String;-><init>([C)V

    .line 52
    .line 53
    .line 54
    return-object p0
.end method

.method public toInt()I
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x2

    .line 5
    if-gt v0, v1, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    move v1, v0

    .line 9
    :goto_0
    iget-object v2, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 10
    .line 11
    array-length v3, v2

    .line 12
    if-ge v0, v3, :cond_0

    .line 13
    .line 14
    aget-byte v3, v2, v0

    .line 15
    .line 16
    and-int/lit16 v3, v3, 0xff

    .line 17
    .line 18
    array-length v2, v2

    .line 19
    sub-int/2addr v2, v0

    .line 20
    add-int/lit8 v2, v2, -0x1

    .line 21
    .line 22
    mul-int/lit8 v2, v2, 0x8

    .line 23
    .line 24
    shl-int v2, v3, v2

    .line 25
    .line 26
    or-int/2addr v1, v2

    .line 27
    add-int/lit8 v0, v0, 0x1

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    return v1

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 32
    .line 33
    const-string v0, "Only supported for Identifiers with max byte length of 2"

    .line 34
    .line 35
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length v1, v0

    .line 4
    const/4 v2, 0x2

    .line 5
    if-ne v1, v2, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Identifier;->toInt()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {p0}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :cond_0
    array-length v0, v0

    .line 17
    const/16 v1, 0x10

    .line 18
    .line 19
    if-ne v0, v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Identifier;->toUuid()Ljava/util/UUID;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-virtual {p0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0

    .line 30
    :cond_1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Identifier;->toHexString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public toUuid()Ljava/util/UUID;
    .locals 5

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/Identifier;->mValue:[B

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/16 v1, 0x10

    .line 5
    .line 6
    if-ne v0, v1, :cond_0

    .line 7
    .line 8
    invoke-static {p0}, Ljava/nio/ByteBuffer;->wrap([B)Ljava/nio/ByteBuffer;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {p0}, Ljava/nio/ByteBuffer;->asLongBuffer()Ljava/nio/LongBuffer;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    new-instance v0, Ljava/util/UUID;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/nio/LongBuffer;->get()J

    .line 19
    .line 20
    .line 21
    move-result-wide v1

    .line 22
    invoke-virtual {p0}, Ljava/nio/LongBuffer;->get()J

    .line 23
    .line 24
    .line 25
    move-result-wide v3

    .line 26
    invoke-direct {v0, v1, v2, v3, v4}, Ljava/util/UUID;-><init>(JJ)V

    .line 27
    .line 28
    .line 29
    return-object v0

    .line 30
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 31
    .line 32
    const-string v0, "Only Identifiers backed by a byte array with length of exactly 16 can be UUIDs."

    .line 33
    .line 34
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0
.end method

.method public toUuidString()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/Identifier;->toUuid()Ljava/util/UUID;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
