.class public final Lio/opentelemetry/api/internal/OtelEncodingUtils;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final ALPHABET:Ljava/lang/String; = "0123456789abcdef"

.field static final BYTE_BASE16:I = 0x2

.field private static final DECODING:[B

.field private static final ENCODING:[C

.field static final LONG_BASE16:I = 0x10

.field static final LONG_BYTES:I = 0x8

.field private static final NUM_ASCII_CHARACTERS:I = 0x80

.field private static final VALID_HEX:[Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->buildEncodingArray()[C

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lio/opentelemetry/api/internal/OtelEncodingUtils;->ENCODING:[C

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->buildDecodingArray()[B

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lio/opentelemetry/api/internal/OtelEncodingUtils;->DECODING:[B

    .line 12
    .line 13
    invoke-static {}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->buildValidHexArray()[Z

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sput-object v0, Lio/opentelemetry/api/internal/OtelEncodingUtils;->VALID_HEX:[Z

    .line 18
    .line 19
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

.method private static buildDecodingArray()[B
    .locals 4

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    new-array v0, v0, [B

    .line 4
    .line 5
    const/4 v1, -0x1

    .line 6
    invoke-static {v0, v1}, Ljava/util/Arrays;->fill([BB)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    :goto_0
    const/16 v2, 0x10

    .line 11
    .line 12
    if-ge v1, v2, :cond_0

    .line 13
    .line 14
    const-string v2, "0123456789abcdef"

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Ljava/lang/String;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    int-to-byte v3, v1

    .line 21
    aput-byte v3, v0, v2

    .line 22
    .line 23
    add-int/lit8 v1, v1, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    return-object v0
.end method

.method private static buildEncodingArray()[C
    .locals 5

    .line 1
    const/16 v0, 0x200

    .line 2
    .line 3
    new-array v0, v0, [C

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    const/16 v2, 0x100

    .line 7
    .line 8
    if-ge v1, v2, :cond_0

    .line 9
    .line 10
    ushr-int/lit8 v2, v1, 0x4

    .line 11
    .line 12
    const-string v3, "0123456789abcdef"

    .line 13
    .line 14
    invoke-virtual {v3, v2}, Ljava/lang/String;->charAt(I)C

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    aput-char v2, v0, v1

    .line 19
    .line 20
    or-int/lit16 v2, v1, 0x100

    .line 21
    .line 22
    and-int/lit8 v4, v1, 0xf

    .line 23
    .line 24
    invoke-virtual {v3, v4}, Ljava/lang/String;->charAt(I)C

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    aput-char v3, v0, v2

    .line 29
    .line 30
    add-int/lit8 v1, v1, 0x1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    return-object v0
.end method

.method private static buildValidHexArray()[Z
    .locals 5

    .line 1
    const v0, 0xffff

    .line 2
    .line 3
    .line 4
    new-array v1, v0, [Z

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    move v3, v2

    .line 8
    :goto_0
    if-ge v3, v0, :cond_3

    .line 9
    .line 10
    const/16 v4, 0x30

    .line 11
    .line 12
    if-gt v4, v3, :cond_0

    .line 13
    .line 14
    const/16 v4, 0x39

    .line 15
    .line 16
    if-le v3, v4, :cond_1

    .line 17
    .line 18
    :cond_0
    const/16 v4, 0x61

    .line 19
    .line 20
    if-gt v4, v3, :cond_2

    .line 21
    .line 22
    const/16 v4, 0x66

    .line 23
    .line 24
    if-gt v3, v4, :cond_2

    .line 25
    .line 26
    :cond_1
    const/4 v4, 0x1

    .line 27
    goto :goto_1

    .line 28
    :cond_2
    move v4, v2

    .line 29
    :goto_1
    aput-boolean v4, v1, v3

    .line 30
    .line 31
    add-int/lit8 v3, v3, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_3
    return-object v1
.end method

.method public static byteFromBase16(CC)B
    .locals 5

    .line 1
    const-string v0, "invalid character "

    .line 2
    .line 3
    const/16 v1, 0x80

    .line 4
    .line 5
    if-ge p0, v1, :cond_1

    .line 6
    .line 7
    sget-object v2, Lio/opentelemetry/api/internal/OtelEncodingUtils;->DECODING:[B

    .line 8
    .line 9
    aget-byte v3, v2, p0

    .line 10
    .line 11
    const/4 v4, -0x1

    .line 12
    if-eq v3, v4, :cond_1

    .line 13
    .line 14
    if-ge p1, v1, :cond_0

    .line 15
    .line 16
    aget-byte p0, v2, p1

    .line 17
    .line 18
    if-eq p0, v4, :cond_0

    .line 19
    .line 20
    shl-int/lit8 p1, v3, 0x4

    .line 21
    .line 22
    or-int/2addr p0, p1

    .line 23
    int-to-byte p0, p0

    .line 24
    return p0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    new-instance v1, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    new-instance v1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p1
.end method

.method public static byteToBase16(B[CI)V
    .locals 2

    .line 1
    and-int/lit16 p0, p0, 0xff

    .line 2
    .line 3
    sget-object v0, Lio/opentelemetry/api/internal/OtelEncodingUtils;->ENCODING:[C

    .line 4
    .line 5
    aget-char v1, v0, p0

    .line 6
    .line 7
    aput-char v1, p1, p2

    .line 8
    .line 9
    add-int/lit8 p2, p2, 0x1

    .line 10
    .line 11
    or-int/lit16 p0, p0, 0x100

    .line 12
    .line 13
    aget-char p0, v0, p0

    .line 14
    .line 15
    aput-char p0, p1, p2

    .line 16
    .line 17
    return-void
.end method

.method public static bytesFromBase16(Ljava/lang/CharSequence;I[B)V
    .locals 4

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p1, :cond_0

    .line 3
    div-int/lit8 v1, v0, 0x2

    invoke-interface {p0, v0}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v2

    add-int/lit8 v3, v0, 0x1

    invoke-interface {p0, v3}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v3

    invoke-static {v2, v3}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    move-result v2

    aput-byte v2, p2, v1

    add-int/lit8 v0, v0, 0x2

    goto :goto_0

    :cond_0
    return-void
.end method

.method public static bytesFromBase16(Ljava/lang/CharSequence;I)[B
    .locals 1

    .line 1
    div-int/lit8 v0, p1, 0x2

    new-array v0, v0, [B

    .line 2
    invoke-static {p0, p1, v0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->bytesFromBase16(Ljava/lang/CharSequence;I[B)V

    return-object v0
.end method

.method public static bytesToBase16([B[CI)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :goto_0
    if-ge v0, p2, :cond_0

    .line 3
    .line 4
    aget-byte v1, p0, v0

    .line 5
    .line 6
    mul-int/lit8 v2, v0, 0x2

    .line 7
    .line 8
    invoke-static {v1, p1, v2}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 9
    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    return-void
.end method

.method public static isValidBase16Character(C)Z
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/internal/OtelEncodingUtils;->VALID_HEX:[Z

    .line 2
    .line 3
    aget-boolean p0, v0, p0

    .line 4
    .line 5
    return p0
.end method

.method public static isValidBase16String(Ljava/lang/CharSequence;)Z
    .locals 4

    .line 1
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    move v2, v1

    .line 7
    :goto_0
    if-ge v2, v0, :cond_1

    .line 8
    .line 9
    invoke-interface {p0, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    invoke-static {v3}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->isValidBase16Character(C)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-nez v3, :cond_0

    .line 18
    .line 19
    return v1

    .line 20
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    const/4 p0, 0x1

    .line 24
    return p0
.end method

.method public static longFromBase16String(Ljava/lang/CharSequence;I)J
    .locals 7

    .line 1
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    add-int/lit8 v1, p1, 0x1

    .line 6
    .line 7
    invoke-interface {p0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    int-to-long v0, v0

    .line 16
    const-wide/16 v2, 0xff

    .line 17
    .line 18
    and-long/2addr v0, v2

    .line 19
    const/16 v4, 0x38

    .line 20
    .line 21
    shl-long/2addr v0, v4

    .line 22
    add-int/lit8 v4, p1, 0x2

    .line 23
    .line 24
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 25
    .line 26
    .line 27
    move-result v4

    .line 28
    add-int/lit8 v5, p1, 0x3

    .line 29
    .line 30
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 35
    .line 36
    .line 37
    move-result v4

    .line 38
    int-to-long v4, v4

    .line 39
    and-long/2addr v4, v2

    .line 40
    const/16 v6, 0x30

    .line 41
    .line 42
    shl-long/2addr v4, v6

    .line 43
    or-long/2addr v0, v4

    .line 44
    add-int/lit8 v4, p1, 0x4

    .line 45
    .line 46
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 47
    .line 48
    .line 49
    move-result v4

    .line 50
    add-int/lit8 v5, p1, 0x5

    .line 51
    .line 52
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 53
    .line 54
    .line 55
    move-result v5

    .line 56
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 57
    .line 58
    .line 59
    move-result v4

    .line 60
    int-to-long v4, v4

    .line 61
    and-long/2addr v4, v2

    .line 62
    const/16 v6, 0x28

    .line 63
    .line 64
    shl-long/2addr v4, v6

    .line 65
    or-long/2addr v0, v4

    .line 66
    add-int/lit8 v4, p1, 0x6

    .line 67
    .line 68
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 69
    .line 70
    .line 71
    move-result v4

    .line 72
    add-int/lit8 v5, p1, 0x7

    .line 73
    .line 74
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 75
    .line 76
    .line 77
    move-result v5

    .line 78
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    int-to-long v4, v4

    .line 83
    and-long/2addr v4, v2

    .line 84
    const/16 v6, 0x20

    .line 85
    .line 86
    shl-long/2addr v4, v6

    .line 87
    or-long/2addr v0, v4

    .line 88
    add-int/lit8 v4, p1, 0x8

    .line 89
    .line 90
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    add-int/lit8 v5, p1, 0x9

    .line 95
    .line 96
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    int-to-long v4, v4

    .line 105
    and-long/2addr v4, v2

    .line 106
    const/16 v6, 0x18

    .line 107
    .line 108
    shl-long/2addr v4, v6

    .line 109
    or-long/2addr v0, v4

    .line 110
    add-int/lit8 v4, p1, 0xa

    .line 111
    .line 112
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    add-int/lit8 v5, p1, 0xb

    .line 117
    .line 118
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    int-to-long v4, v4

    .line 127
    and-long/2addr v4, v2

    .line 128
    const/16 v6, 0x10

    .line 129
    .line 130
    shl-long/2addr v4, v6

    .line 131
    or-long/2addr v0, v4

    .line 132
    add-int/lit8 v4, p1, 0xc

    .line 133
    .line 134
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    add-int/lit8 v5, p1, 0xd

    .line 139
    .line 140
    invoke-interface {p0, v5}, Ljava/lang/CharSequence;->charAt(I)C

    .line 141
    .line 142
    .line 143
    move-result v5

    .line 144
    invoke-static {v4, v5}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 145
    .line 146
    .line 147
    move-result v4

    .line 148
    int-to-long v4, v4

    .line 149
    and-long/2addr v4, v2

    .line 150
    const/16 v6, 0x8

    .line 151
    .line 152
    shl-long/2addr v4, v6

    .line 153
    or-long/2addr v0, v4

    .line 154
    add-int/lit8 v4, p1, 0xe

    .line 155
    .line 156
    invoke-interface {p0, v4}, Ljava/lang/CharSequence;->charAt(I)C

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    add-int/lit8 p1, p1, 0xf

    .line 161
    .line 162
    invoke-interface {p0, p1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    invoke-static {v4, p0}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteFromBase16(CC)B

    .line 167
    .line 168
    .line 169
    move-result p0

    .line 170
    int-to-long p0, p0

    .line 171
    and-long/2addr p0, v2

    .line 172
    or-long/2addr p0, v0

    .line 173
    return-wide p0
.end method

.method public static longToBase16String(J[CI)V
    .locals 4

    .line 1
    const/16 v0, 0x38

    .line 2
    .line 3
    shr-long v0, p0, v0

    .line 4
    .line 5
    const-wide/16 v2, 0xff

    .line 6
    .line 7
    and-long/2addr v0, v2

    .line 8
    long-to-int v0, v0

    .line 9
    int-to-byte v0, v0

    .line 10
    invoke-static {v0, p2, p3}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 11
    .line 12
    .line 13
    const/16 v0, 0x30

    .line 14
    .line 15
    shr-long v0, p0, v0

    .line 16
    .line 17
    and-long/2addr v0, v2

    .line 18
    long-to-int v0, v0

    .line 19
    int-to-byte v0, v0

    .line 20
    add-int/lit8 v1, p3, 0x2

    .line 21
    .line 22
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 23
    .line 24
    .line 25
    const/16 v0, 0x28

    .line 26
    .line 27
    shr-long v0, p0, v0

    .line 28
    .line 29
    and-long/2addr v0, v2

    .line 30
    long-to-int v0, v0

    .line 31
    int-to-byte v0, v0

    .line 32
    add-int/lit8 v1, p3, 0x4

    .line 33
    .line 34
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 35
    .line 36
    .line 37
    const/16 v0, 0x20

    .line 38
    .line 39
    shr-long v0, p0, v0

    .line 40
    .line 41
    and-long/2addr v0, v2

    .line 42
    long-to-int v0, v0

    .line 43
    int-to-byte v0, v0

    .line 44
    add-int/lit8 v1, p3, 0x6

    .line 45
    .line 46
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 47
    .line 48
    .line 49
    const/16 v0, 0x18

    .line 50
    .line 51
    shr-long v0, p0, v0

    .line 52
    .line 53
    and-long/2addr v0, v2

    .line 54
    long-to-int v0, v0

    .line 55
    int-to-byte v0, v0

    .line 56
    add-int/lit8 v1, p3, 0x8

    .line 57
    .line 58
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 59
    .line 60
    .line 61
    const/16 v0, 0x10

    .line 62
    .line 63
    shr-long v0, p0, v0

    .line 64
    .line 65
    and-long/2addr v0, v2

    .line 66
    long-to-int v0, v0

    .line 67
    int-to-byte v0, v0

    .line 68
    add-int/lit8 v1, p3, 0xa

    .line 69
    .line 70
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 71
    .line 72
    .line 73
    const/16 v0, 0x8

    .line 74
    .line 75
    shr-long v0, p0, v0

    .line 76
    .line 77
    and-long/2addr v0, v2

    .line 78
    long-to-int v0, v0

    .line 79
    int-to-byte v0, v0

    .line 80
    add-int/lit8 v1, p3, 0xc

    .line 81
    .line 82
    invoke-static {v0, p2, v1}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 83
    .line 84
    .line 85
    and-long/2addr p0, v2

    .line 86
    long-to-int p0, p0

    .line 87
    int-to-byte p0, p0

    .line 88
    add-int/lit8 p3, p3, 0xe

    .line 89
    .line 90
    invoke-static {p0, p2, p3}, Lio/opentelemetry/api/internal/OtelEncodingUtils;->byteToBase16(B[CI)V

    .line 91
    .line 92
    .line 93
    return-void
.end method
