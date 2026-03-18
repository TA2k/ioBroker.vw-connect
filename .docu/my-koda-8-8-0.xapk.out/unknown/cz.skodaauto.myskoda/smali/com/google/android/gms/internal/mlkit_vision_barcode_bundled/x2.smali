.class public abstract Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-boolean v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-boolean v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/v2;->d:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/l0;->a:I

    .line 10
    .line 11
    :cond_0
    new-instance v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 12
    .line 13
    const/4 v1, 0x7

    .line 14
    invoke-direct {v0, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->a:Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b1;

    .line 18
    .line 19
    return-void
.end method

.method public static a([BII)I
    .locals 5

    .line 1
    sub-int/2addr p2, p1

    .line 2
    add-int/lit8 v0, p1, -0x1

    .line 3
    .line 4
    aget-byte v0, p0, v0

    .line 5
    .line 6
    const/16 v1, -0xc

    .line 7
    .line 8
    const/4 v2, -0x1

    .line 9
    if-eqz p2, :cond_4

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    if-eq p2, v3, :cond_3

    .line 13
    .line 14
    const/4 v4, 0x2

    .line 15
    if-ne p2, v4, :cond_2

    .line 16
    .line 17
    aget-byte p2, p0, p1

    .line 18
    .line 19
    add-int/2addr p1, v3

    .line 20
    aget-byte p0, p0, p1

    .line 21
    .line 22
    if-gt v0, v1, :cond_1

    .line 23
    .line 24
    const/16 p1, -0x41

    .line 25
    .line 26
    if-gt p2, p1, :cond_1

    .line 27
    .line 28
    if-le p0, p1, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    shl-int/lit8 p1, p2, 0x8

    .line 32
    .line 33
    shl-int/lit8 p0, p0, 0x10

    .line 34
    .line 35
    xor-int/2addr p1, v0

    .line 36
    xor-int/2addr p0, p1

    .line 37
    return p0

    .line 38
    :cond_1
    :goto_0
    return v2

    .line 39
    :cond_2
    new-instance p0, Ljava/lang/AssertionError;

    .line 40
    .line 41
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_3
    aget-byte p0, p0, p1

    .line 46
    .line 47
    invoke-static {v0, p0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x2;->d(II)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0

    .line 52
    :cond_4
    if-le v0, v1, :cond_5

    .line 53
    .line 54
    return v2

    .line 55
    :cond_5
    return v0
.end method

.method public static b(IILjava/lang/String;[B)I
    .locals 8

    .line 1
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    add-int v2, p0, p1

    .line 7
    .line 8
    const/16 v3, 0x80

    .line 9
    .line 10
    if-ge v1, v0, :cond_0

    .line 11
    .line 12
    add-int v4, v1, p0

    .line 13
    .line 14
    if-ge v4, v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {p2, v1}, Ljava/lang/String;->charAt(I)C

    .line 17
    .line 18
    .line 19
    move-result v5

    .line 20
    if-ge v5, v3, :cond_0

    .line 21
    .line 22
    int-to-byte v2, v5

    .line 23
    aput-byte v2, p3, v4

    .line 24
    .line 25
    add-int/lit8 v1, v1, 0x1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    if-ne v1, v0, :cond_1

    .line 29
    .line 30
    add-int/2addr p0, v0

    .line 31
    return p0

    .line 32
    :cond_1
    add-int/2addr p0, v1

    .line 33
    :goto_1
    if-ge v1, v0, :cond_b

    .line 34
    .line 35
    invoke-virtual {p2, v1}, Ljava/lang/String;->charAt(I)C

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-ge p1, v3, :cond_2

    .line 40
    .line 41
    if-ge p0, v2, :cond_2

    .line 42
    .line 43
    add-int/lit8 v4, p0, 0x1

    .line 44
    .line 45
    int-to-byte p1, p1

    .line 46
    aput-byte p1, p3, p0

    .line 47
    .line 48
    move p0, v4

    .line 49
    goto/16 :goto_2

    .line 50
    .line 51
    :cond_2
    const/16 v4, 0x800

    .line 52
    .line 53
    if-ge p1, v4, :cond_3

    .line 54
    .line 55
    add-int/lit8 v4, v2, -0x2

    .line 56
    .line 57
    if-gt p0, v4, :cond_3

    .line 58
    .line 59
    add-int/lit8 v4, p0, 0x1

    .line 60
    .line 61
    add-int/lit8 v5, p0, 0x2

    .line 62
    .line 63
    ushr-int/lit8 v6, p1, 0x6

    .line 64
    .line 65
    or-int/lit16 v6, v6, 0x3c0

    .line 66
    .line 67
    int-to-byte v6, v6

    .line 68
    aput-byte v6, p3, p0

    .line 69
    .line 70
    and-int/lit8 p0, p1, 0x3f

    .line 71
    .line 72
    or-int/2addr p0, v3

    .line 73
    int-to-byte p0, p0

    .line 74
    aput-byte p0, p3, v4

    .line 75
    .line 76
    move p0, v5

    .line 77
    goto :goto_2

    .line 78
    :cond_3
    const v4, 0xdfff

    .line 79
    .line 80
    .line 81
    const v5, 0xd800

    .line 82
    .line 83
    .line 84
    if-lt p1, v5, :cond_4

    .line 85
    .line 86
    if-le p1, v4, :cond_5

    .line 87
    .line 88
    :cond_4
    add-int/lit8 v6, v2, -0x3

    .line 89
    .line 90
    if-gt p0, v6, :cond_5

    .line 91
    .line 92
    add-int/lit8 v4, p0, 0x1

    .line 93
    .line 94
    add-int/lit8 v5, p0, 0x2

    .line 95
    .line 96
    add-int/lit8 v6, p0, 0x3

    .line 97
    .line 98
    ushr-int/lit8 v7, p1, 0xc

    .line 99
    .line 100
    or-int/lit16 v7, v7, 0x1e0

    .line 101
    .line 102
    int-to-byte v7, v7

    .line 103
    aput-byte v7, p3, p0

    .line 104
    .line 105
    ushr-int/lit8 p0, p1, 0x6

    .line 106
    .line 107
    and-int/lit8 p0, p0, 0x3f

    .line 108
    .line 109
    or-int/2addr p0, v3

    .line 110
    int-to-byte p0, p0

    .line 111
    aput-byte p0, p3, v4

    .line 112
    .line 113
    and-int/lit8 p0, p1, 0x3f

    .line 114
    .line 115
    or-int/2addr p0, v3

    .line 116
    int-to-byte p0, p0

    .line 117
    aput-byte p0, p3, v5

    .line 118
    .line 119
    move p0, v6

    .line 120
    goto :goto_2

    .line 121
    :cond_5
    add-int/lit8 v6, v2, -0x4

    .line 122
    .line 123
    if-gt p0, v6, :cond_8

    .line 124
    .line 125
    add-int/lit8 v4, v1, 0x1

    .line 126
    .line 127
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 128
    .line 129
    .line 130
    move-result v5

    .line 131
    if-eq v4, v5, :cond_7

    .line 132
    .line 133
    invoke-virtual {p2, v4}, Ljava/lang/String;->charAt(I)C

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    invoke-static {p1, v1}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 138
    .line 139
    .line 140
    move-result v5

    .line 141
    if-eqz v5, :cond_6

    .line 142
    .line 143
    add-int/lit8 v5, p0, 0x1

    .line 144
    .line 145
    add-int/lit8 v6, p0, 0x2

    .line 146
    .line 147
    add-int/lit8 v7, p0, 0x3

    .line 148
    .line 149
    invoke-static {p1, v1}, Ljava/lang/Character;->toCodePoint(CC)I

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    ushr-int/lit8 v1, p1, 0x12

    .line 154
    .line 155
    or-int/lit16 v1, v1, 0xf0

    .line 156
    .line 157
    int-to-byte v1, v1

    .line 158
    aput-byte v1, p3, p0

    .line 159
    .line 160
    ushr-int/lit8 v1, p1, 0xc

    .line 161
    .line 162
    and-int/lit8 v1, v1, 0x3f

    .line 163
    .line 164
    or-int/2addr v1, v3

    .line 165
    int-to-byte v1, v1

    .line 166
    aput-byte v1, p3, v5

    .line 167
    .line 168
    ushr-int/lit8 v1, p1, 0x6

    .line 169
    .line 170
    and-int/lit8 v1, v1, 0x3f

    .line 171
    .line 172
    or-int/2addr v1, v3

    .line 173
    int-to-byte v1, v1

    .line 174
    aput-byte v1, p3, v6

    .line 175
    .line 176
    add-int/lit8 p0, p0, 0x4

    .line 177
    .line 178
    and-int/lit8 p1, p1, 0x3f

    .line 179
    .line 180
    or-int/2addr p1, v3

    .line 181
    int-to-byte p1, p1

    .line 182
    aput-byte p1, p3, v7

    .line 183
    .line 184
    move v1, v4

    .line 185
    :goto_2
    add-int/lit8 v1, v1, 0x1

    .line 186
    .line 187
    goto/16 :goto_1

    .line 188
    .line 189
    :cond_6
    move v1, v4

    .line 190
    :cond_7
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;

    .line 191
    .line 192
    add-int/lit8 v1, v1, -0x1

    .line 193
    .line 194
    invoke-direct {p0, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;-><init>(II)V

    .line 195
    .line 196
    .line 197
    throw p0

    .line 198
    :cond_8
    if-lt p1, v5, :cond_a

    .line 199
    .line 200
    if-gt p1, v4, :cond_a

    .line 201
    .line 202
    add-int/lit8 p3, v1, 0x1

    .line 203
    .line 204
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 205
    .line 206
    .line 207
    move-result v2

    .line 208
    if-eq p3, v2, :cond_9

    .line 209
    .line 210
    invoke-virtual {p2, p3}, Ljava/lang/String;->charAt(I)C

    .line 211
    .line 212
    .line 213
    move-result p2

    .line 214
    invoke-static {p1, p2}, Ljava/lang/Character;->isSurrogatePair(CC)Z

    .line 215
    .line 216
    .line 217
    move-result p2

    .line 218
    if-nez p2, :cond_a

    .line 219
    .line 220
    :cond_9
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;

    .line 221
    .line 222
    invoke-direct {p0, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;-><init>(II)V

    .line 223
    .line 224
    .line 225
    throw p0

    .line 226
    :cond_a
    new-instance p2, Ljava/lang/ArrayIndexOutOfBoundsException;

    .line 227
    .line 228
    new-instance p3, Ljava/lang/StringBuilder;

    .line 229
    .line 230
    const-string v0, "Failed writing "

    .line 231
    .line 232
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    const-string p1, " at index "

    .line 239
    .line 240
    invoke-virtual {p3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 244
    .line 245
    .line 246
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    invoke-direct {p2, p0}, Ljava/lang/ArrayIndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 251
    .line 252
    .line 253
    throw p2

    .line 254
    :cond_b
    return p0
.end method

.method public static c(Ljava/lang/String;)I
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

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
    if-ge v2, v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/16 v4, 0x80

    .line 14
    .line 15
    if-ge v3, v4, :cond_0

    .line 16
    .line 17
    add-int/lit8 v2, v2, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v3, v0

    .line 21
    :goto_1
    if-ge v2, v0, :cond_6

    .line 22
    .line 23
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    const/16 v5, 0x800

    .line 28
    .line 29
    if-ge v4, v5, :cond_1

    .line 30
    .line 31
    rsub-int/lit8 v4, v4, 0x7f

    .line 32
    .line 33
    ushr-int/lit8 v4, v4, 0x1f

    .line 34
    .line 35
    add-int/2addr v3, v4

    .line 36
    add-int/lit8 v2, v2, 0x1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    :goto_2
    if-ge v2, v4, :cond_5

    .line 44
    .line 45
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    if-ge v6, v5, :cond_2

    .line 50
    .line 51
    rsub-int/lit8 v6, v6, 0x7f

    .line 52
    .line 53
    ushr-int/lit8 v6, v6, 0x1f

    .line 54
    .line 55
    add-int/2addr v1, v6

    .line 56
    goto :goto_3

    .line 57
    :cond_2
    add-int/lit8 v1, v1, 0x2

    .line 58
    .line 59
    const v7, 0xd800

    .line 60
    .line 61
    .line 62
    if-lt v6, v7, :cond_4

    .line 63
    .line 64
    const v7, 0xdfff

    .line 65
    .line 66
    .line 67
    if-gt v6, v7, :cond_4

    .line 68
    .line 69
    invoke-static {p0, v2}, Ljava/lang/Character;->codePointAt(Ljava/lang/CharSequence;I)I

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    const/high16 v7, 0x10000

    .line 74
    .line 75
    if-lt v6, v7, :cond_3

    .line 76
    .line 77
    add-int/lit8 v2, v2, 0x1

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    new-instance p0, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;

    .line 81
    .line 82
    invoke-direct {p0, v2, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/w2;-><init>(II)V

    .line 83
    .line 84
    .line 85
    throw p0

    .line 86
    :cond_4
    :goto_3
    add-int/lit8 v2, v2, 0x1

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_5
    add-int/2addr v3, v1

    .line 90
    :cond_6
    if-lt v3, v0, :cond_7

    .line 91
    .line 92
    return v3

    .line 93
    :cond_7
    int-to-long v0, v3

    .line 94
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 95
    .line 96
    new-instance v2, Ljava/lang/StringBuilder;

    .line 97
    .line 98
    const-string v3, "UTF-8 length does not fit in int: "

    .line 99
    .line 100
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    const-wide v3, 0x100000000L

    .line 104
    .line 105
    .line 106
    .line 107
    .line 108
    add-long/2addr v0, v3

    .line 109
    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0
.end method

.method public static d(II)I
    .locals 1

    .line 1
    const/16 v0, -0xc

    .line 2
    .line 3
    if-gt p0, v0, :cond_1

    .line 4
    .line 5
    const/16 v0, -0x41

    .line 6
    .line 7
    if-le p1, v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    shl-int/lit8 p1, p1, 0x8

    .line 11
    .line 12
    xor-int/2addr p0, p1

    .line 13
    return p0

    .line 14
    :cond_1
    :goto_0
    const/4 p0, -0x1

    .line 15
    return p0
.end method
