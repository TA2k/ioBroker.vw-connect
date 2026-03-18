.class public final Lmy0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;
.implements Ljava/io/Serializable;


# static fields
.field public static final f:Lmy0/f;

.field public static final g:Lmy0/f;


# instance fields
.field public final d:J

.field public final e:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lmy0/f;

    .line 2
    .line 3
    const-wide v1, -0x701cefeb9bec00L

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    const/4 v3, 0x0

    .line 9
    invoke-direct {v0, v1, v2, v3}, Lmy0/f;-><init>(JI)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lmy0/f;->f:Lmy0/f;

    .line 13
    .line 14
    new-instance v0, Lmy0/f;

    .line 15
    .line 16
    const-wide v1, 0x701cd2fa9578ffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    const v3, 0x3b9ac9ff

    .line 22
    .line 23
    .line 24
    invoke-direct {v0, v1, v2, v3}, Lmy0/f;-><init>(JI)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Lmy0/f;->g:Lmy0/f;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>(JI)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lmy0/f;->d:J

    .line 5
    .line 6
    iput p3, p0, Lmy0/f;->e:I

    .line 7
    .line 8
    const-wide v0, -0x701cefeb9bec00L

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    cmp-long p0, v0, p1

    .line 14
    .line 15
    if-gtz p0, :cond_0

    .line 16
    .line 17
    const-wide v0, 0x701cd2fa957900L

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    cmp-long p0, p1, v0

    .line 23
    .line 24
    if-gez p0, :cond_0

    .line 25
    .line 26
    return-void

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 28
    .line 29
    const-string p1, "Instant exceeds minimum or maximum instant"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0
.end method


# virtual methods
.method public final a()J
    .locals 12

    .line 1
    iget-wide v0, p0, Lmy0/f;->d:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long v4, v0, v2

    .line 6
    .line 7
    const v5, 0xf4240

    .line 8
    .line 9
    .line 10
    iget p0, p0, Lmy0/f;->e:I

    .line 11
    .line 12
    const-wide/16 v6, 0x3e8

    .line 13
    .line 14
    const-wide/16 v8, 0x1

    .line 15
    .line 16
    if-ltz v4, :cond_4

    .line 17
    .line 18
    cmp-long v4, v0, v8

    .line 19
    .line 20
    const-wide v8, 0x7fffffffffffffffL

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    if-nez v4, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    cmp-long v4, v0, v2

    .line 29
    .line 30
    if-eqz v4, :cond_2

    .line 31
    .line 32
    mul-long v10, v0, v6

    .line 33
    .line 34
    div-long v6, v10, v6

    .line 35
    .line 36
    cmp-long v0, v6, v0

    .line 37
    .line 38
    if-nez v0, :cond_1

    .line 39
    .line 40
    move-wide v6, v10

    .line 41
    goto :goto_0

    .line 42
    :cond_1
    return-wide v8

    .line 43
    :cond_2
    move-wide v6, v2

    .line 44
    :goto_0
    div-int/2addr p0, v5

    .line 45
    int-to-long v0, p0

    .line 46
    add-long v4, v6, v0

    .line 47
    .line 48
    xor-long v10, v6, v4

    .line 49
    .line 50
    cmp-long p0, v10, v2

    .line 51
    .line 52
    if-gez p0, :cond_3

    .line 53
    .line 54
    xor-long/2addr v0, v6

    .line 55
    cmp-long p0, v0, v2

    .line 56
    .line 57
    if-ltz p0, :cond_3

    .line 58
    .line 59
    return-wide v8

    .line 60
    :cond_3
    return-wide v4

    .line 61
    :cond_4
    add-long/2addr v0, v8

    .line 62
    cmp-long v4, v0, v8

    .line 63
    .line 64
    const-wide/high16 v8, -0x8000000000000000L

    .line 65
    .line 66
    if-nez v4, :cond_5

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_5
    cmp-long v4, v0, v2

    .line 70
    .line 71
    if-eqz v4, :cond_7

    .line 72
    .line 73
    mul-long v10, v0, v6

    .line 74
    .line 75
    div-long v6, v10, v6

    .line 76
    .line 77
    cmp-long v0, v6, v0

    .line 78
    .line 79
    if-nez v0, :cond_6

    .line 80
    .line 81
    move-wide v6, v10

    .line 82
    goto :goto_1

    .line 83
    :cond_6
    return-wide v8

    .line 84
    :cond_7
    move-wide v6, v2

    .line 85
    :goto_1
    div-int/2addr p0, v5

    .line 86
    add-int/lit16 p0, p0, -0x3e8

    .line 87
    .line 88
    int-to-long v0, p0

    .line 89
    add-long v4, v6, v0

    .line 90
    .line 91
    xor-long v10, v6, v4

    .line 92
    .line 93
    cmp-long p0, v10, v2

    .line 94
    .line 95
    if-gez p0, :cond_8

    .line 96
    .line 97
    xor-long/2addr v0, v6

    .line 98
    cmp-long p0, v0, v2

    .line 99
    .line 100
    if-ltz p0, :cond_8

    .line 101
    .line 102
    return-wide v8

    .line 103
    :cond_8
    return-wide v4
.end method

.method public final compareTo(Ljava/lang/Object;)I
    .locals 4

    .line 1
    check-cast p1, Lmy0/f;

    .line 2
    .line 3
    const-string v0, "other"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v0, p0, Lmy0/f;->d:J

    .line 9
    .line 10
    iget-wide v2, p1, Lmy0/f;->d:J

    .line 11
    .line 12
    invoke-static {v0, v1, v2, v3}, Lkotlin/jvm/internal/m;->h(JJ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    return v0

    .line 19
    :cond_0
    iget p0, p0, Lmy0/f;->e:I

    .line 20
    .line 21
    iget p1, p1, Lmy0/f;->e:I

    .line 22
    .line 23
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lmy0/f;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lmy0/f;

    .line 8
    .line 9
    iget-wide v0, p1, Lmy0/f;->d:J

    .line 10
    .line 11
    iget-wide v2, p0, Lmy0/f;->d:J

    .line 12
    .line 13
    cmp-long v0, v2, v0

    .line 14
    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    iget p0, p0, Lmy0/f;->e:I

    .line 18
    .line 19
    iget p1, p1, Lmy0/f;->e:I

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0

    .line 26
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 27
    return p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-wide v0, p0, Lmy0/f;->d:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget p0, p0, Lmy0/f;->e:I

    .line 8
    .line 9
    mul-int/lit8 p0, p0, 0x33

    .line 10
    .line 11
    add-int/2addr p0, v0

    .line 12
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 6
    .line 7
    .line 8
    iget-wide v2, v0, Lmy0/f;->d:J

    .line 9
    .line 10
    const-wide/32 v4, 0x15180

    .line 11
    .line 12
    .line 13
    div-long v6, v2, v4

    .line 14
    .line 15
    xor-long v8, v2, v4

    .line 16
    .line 17
    const-wide/16 v10, 0x0

    .line 18
    .line 19
    cmp-long v8, v8, v10

    .line 20
    .line 21
    const-wide/16 v12, -0x1

    .line 22
    .line 23
    if-gez v8, :cond_0

    .line 24
    .line 25
    mul-long v8, v6, v4

    .line 26
    .line 27
    cmp-long v8, v8, v2

    .line 28
    .line 29
    if-eqz v8, :cond_0

    .line 30
    .line 31
    add-long/2addr v6, v12

    .line 32
    :cond_0
    rem-long/2addr v2, v4

    .line 33
    xor-long v8, v2, v4

    .line 34
    .line 35
    neg-long v14, v2

    .line 36
    or-long/2addr v14, v2

    .line 37
    and-long/2addr v8, v14

    .line 38
    const/16 v14, 0x3f

    .line 39
    .line 40
    shr-long/2addr v8, v14

    .line 41
    and-long/2addr v4, v8

    .line 42
    add-long/2addr v2, v4

    .line 43
    long-to-int v2, v2

    .line 44
    const v3, 0xafaa8

    .line 45
    .line 46
    .line 47
    int-to-long v3, v3

    .line 48
    add-long/2addr v6, v3

    .line 49
    const/16 v3, 0x3c

    .line 50
    .line 51
    int-to-long v3, v3

    .line 52
    sub-long/2addr v6, v3

    .line 53
    cmp-long v3, v6, v10

    .line 54
    .line 55
    const/16 v4, 0x190

    .line 56
    .line 57
    const v5, 0x23ab1

    .line 58
    .line 59
    .line 60
    if-gez v3, :cond_1

    .line 61
    .line 62
    const-wide/16 v8, 0x1

    .line 63
    .line 64
    add-long v14, v6, v8

    .line 65
    .line 66
    move-wide/from16 v16, v8

    .line 67
    .line 68
    int-to-long v8, v5

    .line 69
    div-long/2addr v14, v8

    .line 70
    sub-long v14, v14, v16

    .line 71
    .line 72
    move-wide/from16 v16, v10

    .line 73
    .line 74
    int-to-long v10, v4

    .line 75
    mul-long/2addr v10, v14

    .line 76
    neg-long v14, v14

    .line 77
    mul-long/2addr v14, v8

    .line 78
    add-long/2addr v6, v14

    .line 79
    goto :goto_0

    .line 80
    :cond_1
    move-wide/from16 v16, v10

    .line 81
    .line 82
    :goto_0
    int-to-long v3, v4

    .line 83
    mul-long v8, v3, v6

    .line 84
    .line 85
    const/16 v14, 0x24f

    .line 86
    .line 87
    int-to-long v14, v14

    .line 88
    add-long/2addr v8, v14

    .line 89
    int-to-long v14, v5

    .line 90
    div-long/2addr v8, v14

    .line 91
    const/16 v5, 0x16d

    .line 92
    .line 93
    int-to-long v14, v5

    .line 94
    mul-long v18, v14, v8

    .line 95
    .line 96
    const/4 v5, 0x4

    .line 97
    move-wide/from16 v20, v12

    .line 98
    .line 99
    int-to-long v12, v5

    .line 100
    div-long v22, v8, v12

    .line 101
    .line 102
    add-long v22, v22, v18

    .line 103
    .line 104
    const/16 v5, 0x64

    .line 105
    .line 106
    move-wide/from16 v18, v3

    .line 107
    .line 108
    int-to-long v3, v5

    .line 109
    div-long v24, v8, v3

    .line 110
    .line 111
    sub-long v22, v22, v24

    .line 112
    .line 113
    div-long v24, v8, v18

    .line 114
    .line 115
    add-long v24, v24, v22

    .line 116
    .line 117
    sub-long v22, v6, v24

    .line 118
    .line 119
    cmp-long v5, v22, v16

    .line 120
    .line 121
    if-gez v5, :cond_2

    .line 122
    .line 123
    add-long v8, v8, v20

    .line 124
    .line 125
    mul-long/2addr v14, v8

    .line 126
    div-long v12, v8, v12

    .line 127
    .line 128
    add-long/2addr v12, v14

    .line 129
    div-long v3, v8, v3

    .line 130
    .line 131
    sub-long/2addr v12, v3

    .line 132
    div-long v3, v8, v18

    .line 133
    .line 134
    add-long/2addr v3, v12

    .line 135
    sub-long v22, v6, v3

    .line 136
    .line 137
    :cond_2
    move-wide/from16 v3, v22

    .line 138
    .line 139
    add-long/2addr v8, v10

    .line 140
    long-to-int v3, v3

    .line 141
    mul-int/lit8 v4, v3, 0x5

    .line 142
    .line 143
    add-int/lit8 v4, v4, 0x2

    .line 144
    .line 145
    div-int/lit16 v4, v4, 0x99

    .line 146
    .line 147
    add-int/lit8 v5, v4, 0x2

    .line 148
    .line 149
    rem-int/lit8 v5, v5, 0xc

    .line 150
    .line 151
    const/4 v6, 0x1

    .line 152
    add-int/2addr v5, v6

    .line 153
    mul-int/lit16 v7, v4, 0x132

    .line 154
    .line 155
    add-int/lit8 v7, v7, 0x5

    .line 156
    .line 157
    div-int/lit8 v7, v7, 0xa

    .line 158
    .line 159
    sub-int/2addr v3, v7

    .line 160
    add-int/2addr v3, v6

    .line 161
    div-int/lit8 v4, v4, 0xa

    .line 162
    .line 163
    int-to-long v10, v4

    .line 164
    add-long/2addr v8, v10

    .line 165
    long-to-int v4, v8

    .line 166
    div-int/lit16 v7, v2, 0xe10

    .line 167
    .line 168
    mul-int/lit16 v8, v7, 0xe10

    .line 169
    .line 170
    sub-int/2addr v2, v8

    .line 171
    div-int/lit8 v8, v2, 0x3c

    .line 172
    .line 173
    mul-int/lit8 v9, v8, 0x3c

    .line 174
    .line 175
    sub-int/2addr v2, v9

    .line 176
    invoke-static {v4}, Ljava/lang/Math;->abs(I)I

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    const/16 v10, 0x3e8

    .line 181
    .line 182
    const/4 v11, 0x0

    .line 183
    const/16 v12, 0x2710

    .line 184
    .line 185
    if-ge v9, v10, :cond_4

    .line 186
    .line 187
    new-instance v9, Ljava/lang/StringBuilder;

    .line 188
    .line 189
    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    .line 190
    .line 191
    .line 192
    const-string v10, "deleteCharAt(...)"

    .line 193
    .line 194
    if-ltz v4, :cond_3

    .line 195
    .line 196
    add-int/2addr v4, v12

    .line 197
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->deleteCharAt(I)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    move-result-object v4

    .line 204
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    goto :goto_1

    .line 208
    :cond_3
    sub-int/2addr v4, v12

    .line 209
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 210
    .line 211
    .line 212
    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->deleteCharAt(I)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    move-result-object v4

    .line 216
    invoke-static {v4, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    :goto_1
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_4
    if-lt v4, v12, :cond_5

    .line 224
    .line 225
    const/16 v9, 0x2b

    .line 226
    .line 227
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 228
    .line 229
    .line 230
    :cond_5
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 231
    .line 232
    .line 233
    :goto_2
    const/16 v4, 0x2d

    .line 234
    .line 235
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 236
    .line 237
    .line 238
    invoke-static {v1, v1, v5}, Lmy0/h;->h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-static {v1, v1, v3}, Lmy0/h;->h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V

    .line 245
    .line 246
    .line 247
    const/16 v3, 0x54

    .line 248
    .line 249
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    invoke-static {v1, v1, v7}, Lmy0/h;->h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V

    .line 253
    .line 254
    .line 255
    const/16 v3, 0x3a

    .line 256
    .line 257
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 258
    .line 259
    .line 260
    invoke-static {v1, v1, v8}, Lmy0/h;->h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 264
    .line 265
    .line 266
    invoke-static {v1, v1, v2}, Lmy0/h;->h(Ljava/lang/StringBuilder;Ljava/lang/StringBuilder;I)V

    .line 267
    .line 268
    .line 269
    iget v0, v0, Lmy0/f;->e:I

    .line 270
    .line 271
    if-eqz v0, :cond_7

    .line 272
    .line 273
    const/16 v2, 0x2e

    .line 274
    .line 275
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    :goto_3
    add-int/lit8 v2, v11, 0x1

    .line 279
    .line 280
    sget-object v3, Lmy0/h;->a:[I

    .line 281
    .line 282
    aget v4, v3, v2

    .line 283
    .line 284
    rem-int v4, v0, v4

    .line 285
    .line 286
    if-nez v4, :cond_6

    .line 287
    .line 288
    move v11, v2

    .line 289
    goto :goto_3

    .line 290
    :cond_6
    rem-int/lit8 v2, v11, 0x3

    .line 291
    .line 292
    sub-int/2addr v11, v2

    .line 293
    aget v2, v3, v11

    .line 294
    .line 295
    div-int/2addr v0, v2

    .line 296
    rsub-int/lit8 v2, v11, 0x9

    .line 297
    .line 298
    aget v2, v3, v2

    .line 299
    .line 300
    add-int/2addr v0, v2

    .line 301
    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    const-string v2, "null cannot be cast to non-null type java.lang.String"

    .line 306
    .line 307
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v0, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    const-string v2, "substring(...)"

    .line 315
    .line 316
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 320
    .line 321
    .line 322
    :cond_7
    const/16 v0, 0x5a

    .line 323
    .line 324
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 325
    .line 326
    .line 327
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    return-object v0
.end method
