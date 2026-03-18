.class public final Lio/opentelemetry/api/internal/PercentEscaper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEST_PAD:I = 0x20

.field private static final SAFE_CHARS:Ljava/lang/String; = "-._~!$\'()*&@:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

.field private static final UPPER_HEX_DIGITS:[C

.field private static final safeOctets:[Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "0123456789ABCDEF"

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->toCharArray()[C

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/api/internal/PercentEscaper;->UPPER_HEX_DIGITS:[C

    .line 8
    .line 9
    const-string v0, "-._~!$\'()*&@:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/internal/PercentEscaper;->createSafeOctets(Ljava/lang/String;)[Z

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/api/internal/PercentEscaper;->safeOctets:[Z

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static codePointAt(Ljava/lang/CharSequence;II)I
    .locals 7

    .line 1
    if-ge p1, p2, :cond_5

    .line 2
    .line 3
    add-int/lit8 v0, p1, 0x1

    .line 4
    .line 5
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const v2, 0xd800

    .line 10
    .line 11
    .line 12
    if-lt v1, v2, :cond_4

    .line 13
    .line 14
    const v2, 0xdfff

    .line 15
    .line 16
    .line 17
    if-le v1, v2, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const v2, 0xdbff

    .line 21
    .line 22
    .line 23
    const-string v3, "\'"

    .line 24
    .line 25
    const-string v4, " in \'"

    .line 26
    .line 27
    const-string v5, " at index "

    .line 28
    .line 29
    const-string v6, "\' with value "

    .line 30
    .line 31
    if-gt v1, v2, :cond_3

    .line 32
    .line 33
    if-ne v0, p2, :cond_1

    .line 34
    .line 35
    neg-int p0, v1

    .line 36
    return p0

    .line 37
    :cond_1
    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    invoke-static {p1}, Ljava/lang/Character;->isLowSurrogate(C)Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    if-eqz p2, :cond_2

    .line 46
    .line 47
    invoke-static {v1, p1}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0

    .line 52
    :cond_2
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 53
    .line 54
    new-instance v1, Ljava/lang/StringBuilder;

    .line 55
    .line 56
    const-string v2, "Expected low surrogate but got char \'"

    .line 57
    .line 58
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p2

    .line 93
    :cond_3
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    new-instance v0, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    const-string v2, "Unexpected low surrogate character \'"

    .line 98
    .line 99
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object p0

    .line 130
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw p2

    .line 134
    :cond_4
    :goto_0
    return v1

    .line 135
    :cond_5
    new-instance p0, Ljava/lang/IndexOutOfBoundsException;

    .line 136
    .line 137
    const-string p1, "Index exceeds specified range"

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0
.end method

.method public static create()Lio/opentelemetry/api/internal/PercentEscaper;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/internal/PercentEscaper;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/internal/PercentEscaper;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method private static createSafeOctets(Ljava/lang/String;)[Z
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->toCharArray()[C

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    array-length v0, p0

    .line 6
    const/4 v1, -0x1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v0, :cond_0

    .line 10
    .line 11
    aget-char v4, p0, v3

    .line 12
    .line 13
    invoke-static {v4, v1}, Ljava/lang/Math;->max(II)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    add-int/lit8 v3, v3, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v0, 0x1

    .line 21
    add-int/2addr v1, v0

    .line 22
    new-array v1, v1, [Z

    .line 23
    .line 24
    array-length v3, p0

    .line 25
    :goto_1
    if-ge v2, v3, :cond_1

    .line 26
    .line 27
    aget-char v4, p0, v2

    .line 28
    .line 29
    aput-boolean v0, v1, v4

    .line 30
    .line 31
    add-int/lit8 v2, v2, 0x1

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    return-object v1
.end method

.method private static escape(I)[C
    .locals 14
    .annotation runtime Ljavax/annotation/CheckForNull;
    .end annotation

    .line 5
    sget-object v0, Lio/opentelemetry/api/internal/PercentEscaper;->safeOctets:[Z

    array-length v1, v0

    if-ge p0, v1, :cond_0

    aget-boolean v0, v0, p0

    if-eqz v0, :cond_0

    const/4 p0, 0x0

    return-object p0

    :cond_0
    const/16 v0, 0x7f

    const/4 v1, 0x1

    const/4 v2, 0x2

    const/4 v3, 0x0

    const/4 v4, 0x4

    const/16 v5, 0x25

    const/4 v6, 0x3

    if-gt p0, v0, :cond_1

    .line 6
    new-array v0, v6, [C

    .line 7
    aput-char v5, v0, v3

    .line 8
    sget-object v3, Lio/opentelemetry/api/internal/PercentEscaper;->UPPER_HEX_DIGITS:[C

    and-int/lit8 v5, p0, 0xf

    aget-char v5, v3, v5

    aput-char v5, v0, v2

    ushr-int/2addr p0, v4

    .line 9
    aget-char p0, v3, p0

    aput-char p0, v0, v1

    return-object v0

    :cond_1
    const/16 v0, 0x7ff

    const/4 v7, 0x5

    const/16 v8, 0xc

    const/16 v9, 0xa

    const/4 v10, 0x6

    const/16 v11, 0x8

    if-gt p0, v0, :cond_2

    .line 10
    new-array v0, v10, [C

    .line 11
    aput-char v5, v0, v3

    .line 12
    aput-char v5, v0, v6

    .line 13
    sget-object v3, Lio/opentelemetry/api/internal/PercentEscaper;->UPPER_HEX_DIGITS:[C

    and-int/lit8 v5, p0, 0xf

    aget-char v5, v3, v5

    aput-char v5, v0, v7

    ushr-int/lit8 v5, p0, 0x4

    and-int/2addr v5, v6

    or-int/2addr v5, v11

    .line 14
    aget-char v5, v3, v5

    aput-char v5, v0, v4

    ushr-int/lit8 v4, p0, 0x6

    and-int/lit8 v4, v4, 0xf

    .line 15
    aget-char v4, v3, v4

    aput-char v4, v0, v2

    ushr-int/2addr p0, v9

    or-int/2addr p0, v8

    .line 16
    aget-char p0, v3, p0

    aput-char p0, v0, v1

    return-object v0

    :cond_2
    const v0, 0xffff

    const/16 v12, 0x9

    const/4 v13, 0x7

    if-gt p0, v0, :cond_3

    .line 17
    new-array v0, v12, [C

    .line 18
    aput-char v5, v0, v3

    const/16 v3, 0x45

    .line 19
    aput-char v3, v0, v1

    .line 20
    aput-char v5, v0, v6

    .line 21
    aput-char v5, v0, v10

    .line 22
    sget-object v1, Lio/opentelemetry/api/internal/PercentEscaper;->UPPER_HEX_DIGITS:[C

    and-int/lit8 v3, p0, 0xf

    aget-char v3, v1, v3

    aput-char v3, v0, v11

    ushr-int/lit8 v3, p0, 0x4

    and-int/2addr v3, v6

    or-int/2addr v3, v11

    .line 23
    aget-char v3, v1, v3

    aput-char v3, v0, v13

    ushr-int/lit8 v3, p0, 0x6

    and-int/lit8 v3, v3, 0xf

    .line 24
    aget-char v3, v1, v3

    aput-char v3, v0, v7

    ushr-int/lit8 v3, p0, 0xa

    and-int/2addr v3, v6

    or-int/2addr v3, v11

    .line 25
    aget-char v3, v1, v3

    aput-char v3, v0, v4

    ushr-int/2addr p0, v8

    .line 26
    aget-char p0, v1, p0

    aput-char p0, v0, v2

    return-object v0

    :cond_3
    const v0, 0x10ffff

    if-gt p0, v0, :cond_4

    .line 27
    new-array v0, v8, [C

    .line 28
    aput-char v5, v0, v3

    const/16 v3, 0x46

    .line 29
    aput-char v3, v0, v1

    .line 30
    aput-char v5, v0, v6

    .line 31
    aput-char v5, v0, v10

    .line 32
    aput-char v5, v0, v12

    .line 33
    sget-object v1, Lio/opentelemetry/api/internal/PercentEscaper;->UPPER_HEX_DIGITS:[C

    and-int/lit8 v3, p0, 0xf

    aget-char v3, v1, v3

    const/16 v5, 0xb

    aput-char v3, v0, v5

    ushr-int/lit8 v3, p0, 0x4

    and-int/2addr v3, v6

    or-int/2addr v3, v11

    .line 34
    aget-char v3, v1, v3

    aput-char v3, v0, v9

    ushr-int/lit8 v3, p0, 0x6

    and-int/lit8 v3, v3, 0xf

    .line 35
    aget-char v3, v1, v3

    aput-char v3, v0, v11

    ushr-int/lit8 v3, p0, 0xa

    and-int/2addr v3, v6

    or-int/2addr v3, v11

    .line 36
    aget-char v3, v1, v3

    aput-char v3, v0, v13

    ushr-int/lit8 v3, p0, 0xc

    and-int/lit8 v3, v3, 0xf

    .line 37
    aget-char v3, v1, v3

    aput-char v3, v0, v7

    ushr-int/lit8 v3, p0, 0x10

    and-int/2addr v3, v6

    or-int/2addr v3, v11

    .line 38
    aget-char v3, v1, v3

    aput-char v3, v0, v4

    ushr-int/lit8 p0, p0, 0x12

    and-int/2addr p0, v13

    .line 39
    aget-char p0, v1, p0

    aput-char p0, v0, v2

    return-object v0

    .line 40
    :cond_4
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Invalid unicode character value "

    .line 41
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 42
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method private static escapeSlow(Ljava/lang/String;I)Ljava/lang/String;
    .locals 11

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x400

    .line 6
    .line 7
    invoke-static {v1}, Lio/opentelemetry/api/internal/TemporaryBuffers;->chars(I)[C

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    const/4 v2, 0x0

    .line 12
    move v3, v2

    .line 13
    move v4, v3

    .line 14
    :goto_0
    if-ge p1, v0, :cond_6

    .line 15
    .line 16
    invoke-static {p0, p1, v0}, Lio/opentelemetry/api/internal/PercentEscaper;->codePointAt(Ljava/lang/CharSequence;II)I

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    if-ltz v5, :cond_5

    .line 21
    .line 22
    invoke-static {v5}, Lio/opentelemetry/api/internal/PercentEscaper;->escape(I)[C

    .line 23
    .line 24
    .line 25
    move-result-object v6

    .line 26
    invoke-static {v5}, Ljava/lang/Character;->isSupplementaryCodePoint(I)Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_0

    .line 31
    .line 32
    const/4 v5, 0x2

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    const/4 v5, 0x1

    .line 35
    :goto_1
    add-int/2addr v5, p1

    .line 36
    if-eqz v6, :cond_4

    .line 37
    .line 38
    sub-int v7, p1, v3

    .line 39
    .line 40
    add-int v8, v4, v7

    .line 41
    .line 42
    array-length v9, v6

    .line 43
    add-int/2addr v9, v8

    .line 44
    array-length v10, v1

    .line 45
    if-ge v10, v9, :cond_1

    .line 46
    .line 47
    sub-int v10, v0, p1

    .line 48
    .line 49
    add-int/2addr v10, v9

    .line 50
    add-int/lit8 v10, v10, 0x20

    .line 51
    .line 52
    invoke-static {v1, v4, v10}, Lio/opentelemetry/api/internal/PercentEscaper;->growBuffer([CII)[C

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    :cond_1
    if-lez v7, :cond_2

    .line 57
    .line 58
    invoke-virtual {p0, v3, p1, v1, v4}, Ljava/lang/String;->getChars(II[CI)V

    .line 59
    .line 60
    .line 61
    move v4, v8

    .line 62
    :cond_2
    array-length p1, v6

    .line 63
    if-lez p1, :cond_3

    .line 64
    .line 65
    array-length p1, v6

    .line 66
    invoke-static {v6, v2, v1, v4, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 67
    .line 68
    .line 69
    array-length p1, v6

    .line 70
    add-int/2addr v4, p1

    .line 71
    :cond_3
    move v3, v5

    .line 72
    :cond_4
    invoke-static {p0, v5, v0}, Lio/opentelemetry/api/internal/PercentEscaper;->nextEscapeIndex(Ljava/lang/CharSequence;II)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    goto :goto_0

    .line 77
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 78
    .line 79
    const-string p1, "Trailing high surrogate at end of input"

    .line 80
    .line 81
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_6
    sub-int p1, v0, v3

    .line 86
    .line 87
    if-lez p1, :cond_8

    .line 88
    .line 89
    add-int/2addr p1, v4

    .line 90
    array-length v5, v1

    .line 91
    if-ge v5, p1, :cond_7

    .line 92
    .line 93
    invoke-static {v1, v4, p1}, Lio/opentelemetry/api/internal/PercentEscaper;->growBuffer([CII)[C

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    :cond_7
    invoke-virtual {p0, v3, v0, v1, v4}, Ljava/lang/String;->getChars(II[CI)V

    .line 98
    .line 99
    .line 100
    move v4, p1

    .line 101
    :cond_8
    new-instance p0, Ljava/lang/String;

    .line 102
    .line 103
    invoke-direct {p0, v1, v2, v4}, Ljava/lang/String;-><init>([CII)V

    .line 104
    .line 105
    .line 106
    return-object p0
.end method

.method private static growBuffer([CII)[C
    .locals 1

    .line 1
    if-ltz p2, :cond_1

    .line 2
    .line 3
    new-array p2, p2, [C

    .line 4
    .line 5
    if-lez p1, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-static {p0, v0, p2, v0, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-object p2

    .line 12
    :cond_1
    new-instance p0, Ljava/lang/AssertionError;

    .line 13
    .line 14
    const-string p1, "Cannot increase internal buffer any further"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method private static nextEscapeIndex(Ljava/lang/CharSequence;II)I
    .locals 3

    .line 1
    :goto_0
    if-ge p1, p2, :cond_1

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sget-object v1, Lio/opentelemetry/api/internal/PercentEscaper;->safeOctets:[Z

    .line 8
    .line 9
    array-length v2, v1

    .line 10
    if-ge v0, v2, :cond_1

    .line 11
    .line 12
    aget-boolean v0, v1, v0

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    :goto_1
    return p1
.end method


# virtual methods
.method public escape(Ljava/lang/String;)Ljava/lang/String;
    .locals 4

    .line 1
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p0

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p0, :cond_2

    .line 2
    invoke-virtual {p1, v0}, Ljava/lang/String;->charAt(I)C

    move-result v1

    .line 3
    sget-object v2, Lio/opentelemetry/api/internal/PercentEscaper;->safeOctets:[Z

    array-length v3, v2

    if-ge v1, v3, :cond_1

    aget-boolean v1, v2, v1

    if-nez v1, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    .line 4
    :cond_1
    :goto_1
    invoke-static {p1, v0}, Lio/opentelemetry/api/internal/PercentEscaper;->escapeSlow(Ljava/lang/String;I)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_2
    return-object p1
.end method
