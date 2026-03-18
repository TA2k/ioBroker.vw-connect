.class public abstract Lv01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[B

.field public static final b:[J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-string v0, "0123456789abcdef"

    .line 2
    .line 3
    sget-object v1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "getBytes(...)"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lv01/a;->a:[B

    .line 15
    .line 16
    const/16 v0, 0x14

    .line 17
    .line 18
    new-array v0, v0, [J

    .line 19
    .line 20
    fill-array-data v0, :array_0

    .line 21
    .line 22
    .line 23
    sput-object v0, Lv01/a;->b:[J

    .line 24
    .line 25
    return-void

    .line 26
    nop

    .line 27
    :array_0
    .array-data 8
        -0x1
        0x9
        0x63
        0x3e7
        0x270f
        0x1869f
        0xf423f
        0x98967f
        0x5f5e0ff
        0x3b9ac9ff
        0x2540be3ffL
        0x174876e7ffL
        0xe8d4a50fffL
        0x9184e729fffL
        0x5af3107a3fffL
        0x38d7ea4c67fffL
        0x2386f26fc0ffffL
        0x16345785d89ffffL
        0xde0b6b3a763ffffL
        0x7fffffffffffffffL
    .end array-data
.end method

.method public static final a(Lu01/f;Lu01/i;JJI)J
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p2

    .line 4
    .line 5
    move-wide/from16 v3, p4

    .line 6
    .line 7
    move/from16 v5, p6

    .line 8
    .line 9
    const-string v6, "bytes"

    .line 10
    .line 11
    move-object/from16 v7, p1

    .line 12
    .line 13
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v7}, Lu01/i;->d()I

    .line 17
    .line 18
    .line 19
    move-result v6

    .line 20
    int-to-long v8, v6

    .line 21
    const/4 v6, 0x0

    .line 22
    int-to-long v10, v6

    .line 23
    int-to-long v12, v5

    .line 24
    invoke-static/range {v8 .. v13}, Lu01/b;->e(JJJ)V

    .line 25
    .line 26
    .line 27
    if-lez v5, :cond_f

    .line 28
    .line 29
    const-wide/16 v8, 0x0

    .line 30
    .line 31
    cmp-long v10, v1, v8

    .line 32
    .line 33
    if-ltz v10, :cond_e

    .line 34
    .line 35
    cmp-long v10, v1, v3

    .line 36
    .line 37
    if-gtz v10, :cond_d

    .line 38
    .line 39
    iget-wide v10, v0, Lu01/f;->e:J

    .line 40
    .line 41
    cmp-long v14, v3, v10

    .line 42
    .line 43
    if-lez v14, :cond_0

    .line 44
    .line 45
    move-wide v3, v10

    .line 46
    :cond_0
    cmp-long v14, v1, v3

    .line 47
    .line 48
    if-nez v14, :cond_1

    .line 49
    .line 50
    goto/16 :goto_6

    .line 51
    .line 52
    :cond_1
    iget-object v14, v0, Lu01/f;->d:Lu01/c0;

    .line 53
    .line 54
    if-nez v14, :cond_2

    .line 55
    .line 56
    goto/16 :goto_6

    .line 57
    .line 58
    :cond_2
    sub-long v15, v10, v1

    .line 59
    .line 60
    cmp-long v15, v15, v1

    .line 61
    .line 62
    const-wide/16 v16, 0x1

    .line 63
    .line 64
    move/from16 v18, v6

    .line 65
    .line 66
    if-gez v15, :cond_7

    .line 67
    .line 68
    :goto_0
    cmp-long v8, v10, v1

    .line 69
    .line 70
    if-lez v8, :cond_3

    .line 71
    .line 72
    iget-object v14, v14, Lu01/c0;->g:Lu01/c0;

    .line 73
    .line 74
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget v8, v14, Lu01/c0;->c:I

    .line 78
    .line 79
    iget v9, v14, Lu01/c0;->b:I

    .line 80
    .line 81
    sub-int/2addr v8, v9

    .line 82
    int-to-long v8, v8

    .line 83
    sub-long/2addr v10, v8

    .line 84
    goto :goto_0

    .line 85
    :cond_3
    invoke-virtual {v7}, Lu01/i;->h()[B

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    aget-byte v8, v7, v18

    .line 90
    .line 91
    move-object/from16 p1, v7

    .line 92
    .line 93
    iget-wide v6, v0, Lu01/f;->e:J

    .line 94
    .line 95
    sub-long/2addr v6, v12

    .line 96
    add-long v6, v6, v16

    .line 97
    .line 98
    invoke-static {v3, v4, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 99
    .line 100
    .line 101
    move-result-wide v3

    .line 102
    :goto_1
    cmp-long v0, v10, v3

    .line 103
    .line 104
    if-gez v0, :cond_c

    .line 105
    .line 106
    iget-object v0, v14, Lu01/c0;->a:[B

    .line 107
    .line 108
    iget v6, v14, Lu01/c0;->c:I

    .line 109
    .line 110
    iget v7, v14, Lu01/c0;->b:I

    .line 111
    .line 112
    int-to-long v12, v7

    .line 113
    add-long/2addr v12, v3

    .line 114
    sub-long/2addr v12, v10

    .line 115
    int-to-long v6, v6

    .line 116
    invoke-static {v6, v7, v12, v13}, Ljava/lang/Math;->min(JJ)J

    .line 117
    .line 118
    .line 119
    move-result-wide v6

    .line 120
    long-to-int v6, v6

    .line 121
    iget v7, v14, Lu01/c0;->b:I

    .line 122
    .line 123
    int-to-long v12, v7

    .line 124
    add-long/2addr v12, v1

    .line 125
    sub-long/2addr v12, v10

    .line 126
    long-to-int v1, v12

    .line 127
    :goto_2
    if-ge v1, v6, :cond_6

    .line 128
    .line 129
    aget-byte v2, v0, v1

    .line 130
    .line 131
    if-ne v2, v8, :cond_4

    .line 132
    .line 133
    add-int/lit8 v2, v1, 0x1

    .line 134
    .line 135
    move-object/from16 v7, p1

    .line 136
    .line 137
    const/4 v9, 0x1

    .line 138
    invoke-static {v14, v2, v7, v9, v5}, Lv01/a;->b(Lu01/c0;I[BII)Z

    .line 139
    .line 140
    .line 141
    move-result v2

    .line 142
    if-eqz v2, :cond_5

    .line 143
    .line 144
    iget v0, v14, Lu01/c0;->b:I

    .line 145
    .line 146
    sub-int/2addr v1, v0

    .line 147
    int-to-long v0, v1

    .line 148
    add-long/2addr v0, v10

    .line 149
    return-wide v0

    .line 150
    :cond_4
    move-object/from16 v7, p1

    .line 151
    .line 152
    :cond_5
    add-int/lit8 v1, v1, 0x1

    .line 153
    .line 154
    move-object/from16 p1, v7

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_6
    move-object/from16 v7, p1

    .line 158
    .line 159
    iget v0, v14, Lu01/c0;->c:I

    .line 160
    .line 161
    iget v1, v14, Lu01/c0;->b:I

    .line 162
    .line 163
    sub-int/2addr v0, v1

    .line 164
    int-to-long v0, v0

    .line 165
    add-long/2addr v10, v0

    .line 166
    iget-object v14, v14, Lu01/c0;->f:Lu01/c0;

    .line 167
    .line 168
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-wide v1, v10

    .line 172
    goto :goto_1

    .line 173
    :cond_7
    :goto_3
    iget v6, v14, Lu01/c0;->c:I

    .line 174
    .line 175
    iget v10, v14, Lu01/c0;->b:I

    .line 176
    .line 177
    sub-int/2addr v6, v10

    .line 178
    int-to-long v10, v6

    .line 179
    add-long/2addr v10, v8

    .line 180
    cmp-long v6, v10, v1

    .line 181
    .line 182
    if-gtz v6, :cond_8

    .line 183
    .line 184
    iget-object v14, v14, Lu01/c0;->f:Lu01/c0;

    .line 185
    .line 186
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    move-wide v8, v10

    .line 190
    goto :goto_3

    .line 191
    :cond_8
    invoke-virtual {v7}, Lu01/i;->h()[B

    .line 192
    .line 193
    .line 194
    move-result-object v6

    .line 195
    aget-byte v7, v6, v18

    .line 196
    .line 197
    iget-wide v10, v0, Lu01/f;->e:J

    .line 198
    .line 199
    sub-long/2addr v10, v12

    .line 200
    add-long v10, v10, v16

    .line 201
    .line 202
    invoke-static {v3, v4, v10, v11}, Ljava/lang/Math;->min(JJ)J

    .line 203
    .line 204
    .line 205
    move-result-wide v3

    .line 206
    :goto_4
    cmp-long v0, v8, v3

    .line 207
    .line 208
    if-gez v0, :cond_c

    .line 209
    .line 210
    iget-object v0, v14, Lu01/c0;->a:[B

    .line 211
    .line 212
    iget v10, v14, Lu01/c0;->c:I

    .line 213
    .line 214
    iget v11, v14, Lu01/c0;->b:I

    .line 215
    .line 216
    int-to-long v11, v11

    .line 217
    add-long/2addr v11, v3

    .line 218
    sub-long/2addr v11, v8

    .line 219
    move-wide/from16 p0, v1

    .line 220
    .line 221
    move-object v2, v0

    .line 222
    int-to-long v0, v10

    .line 223
    invoke-static {v0, v1, v11, v12}, Ljava/lang/Math;->min(JJ)J

    .line 224
    .line 225
    .line 226
    move-result-wide v0

    .line 227
    long-to-int v0, v0

    .line 228
    iget v1, v14, Lu01/c0;->b:I

    .line 229
    .line 230
    int-to-long v10, v1

    .line 231
    add-long v10, v10, p0

    .line 232
    .line 233
    sub-long/2addr v10, v8

    .line 234
    long-to-int v1, v10

    .line 235
    :goto_5
    if-ge v1, v0, :cond_b

    .line 236
    .line 237
    aget-byte v10, v2, v1

    .line 238
    .line 239
    if-ne v10, v7, :cond_9

    .line 240
    .line 241
    add-int/lit8 v10, v1, 0x1

    .line 242
    .line 243
    const/4 v11, 0x1

    .line 244
    invoke-static {v14, v10, v6, v11, v5}, Lv01/a;->b(Lu01/c0;I[BII)Z

    .line 245
    .line 246
    .line 247
    move-result v10

    .line 248
    if-eqz v10, :cond_a

    .line 249
    .line 250
    iget v0, v14, Lu01/c0;->b:I

    .line 251
    .line 252
    sub-int/2addr v1, v0

    .line 253
    int-to-long v0, v1

    .line 254
    add-long/2addr v0, v8

    .line 255
    return-wide v0

    .line 256
    :cond_9
    const/4 v11, 0x1

    .line 257
    :cond_a
    add-int/lit8 v1, v1, 0x1

    .line 258
    .line 259
    goto :goto_5

    .line 260
    :cond_b
    const/4 v11, 0x1

    .line 261
    iget v0, v14, Lu01/c0;->c:I

    .line 262
    .line 263
    iget v1, v14, Lu01/c0;->b:I

    .line 264
    .line 265
    sub-int/2addr v0, v1

    .line 266
    int-to-long v0, v0

    .line 267
    add-long/2addr v8, v0

    .line 268
    iget-object v14, v14, Lu01/c0;->f:Lu01/c0;

    .line 269
    .line 270
    invoke-static {v14}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    move-wide v1, v8

    .line 274
    goto :goto_4

    .line 275
    :cond_c
    :goto_6
    const-wide/16 v0, -0x1

    .line 276
    .line 277
    return-wide v0

    .line 278
    :cond_d
    const-string v0, "fromIndex > toIndex: "

    .line 279
    .line 280
    const-string v5, " > "

    .line 281
    .line 282
    invoke-static {v1, v2, v0, v5}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 283
    .line 284
    .line 285
    move-result-object v0

    .line 286
    invoke-virtual {v0, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 287
    .line 288
    .line 289
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v0

    .line 293
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 294
    .line 295
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    throw v1

    .line 303
    :cond_e
    const-string v0, "fromIndex < 0: "

    .line 304
    .line 305
    invoke-static {v1, v2, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v0

    .line 309
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 310
    .line 311
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 316
    .line 317
    .line 318
    throw v1

    .line 319
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 320
    .line 321
    const-string v1, "byteCount == 0"

    .line 322
    .line 323
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    throw v0
.end method

.method public static final b(Lu01/c0;I[BII)Z
    .locals 5

    .line 1
    iget v0, p0, Lu01/c0;->c:I

    .line 2
    .line 3
    iget-object v1, p0, Lu01/c0;->a:[B

    .line 4
    .line 5
    :goto_0
    if-ge p3, p4, :cond_2

    .line 6
    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lu01/c0;->f:Lu01/c0;

    .line 10
    .line 11
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p1, p0, Lu01/c0;->a:[B

    .line 15
    .line 16
    iget v0, p0, Lu01/c0;->b:I

    .line 17
    .line 18
    iget v1, p0, Lu01/c0;->c:I

    .line 19
    .line 20
    move v4, v1

    .line 21
    move-object v1, p1

    .line 22
    move p1, v0

    .line 23
    move v0, v4

    .line 24
    :cond_0
    aget-byte v2, v1, p1

    .line 25
    .line 26
    aget-byte v3, p2, p3

    .line 27
    .line 28
    if-eq v2, v3, :cond_1

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_1
    add-int/lit8 p1, p1, 0x1

    .line 33
    .line 34
    add-int/lit8 p3, p3, 0x1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_2
    const/4 p0, 0x1

    .line 38
    return p0
.end method

.method public static final c(Lu01/f;J)Ljava/lang/String;
    .locals 6

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    const-wide/16 v1, 0x1

    .line 6
    .line 7
    if-lez v0, :cond_0

    .line 8
    .line 9
    sub-long v3, p1, v1

    .line 10
    .line 11
    invoke-virtual {p0, v3, v4}, Lu01/f;->h(J)B

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    const/16 v5, 0xd

    .line 16
    .line 17
    if-ne v0, v5, :cond_0

    .line 18
    .line 19
    sget-object p1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 20
    .line 21
    invoke-virtual {p0, v3, v4, p1}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    const-wide/16 v0, 0x2

    .line 26
    .line 27
    invoke-virtual {p0, v0, v1}, Lu01/f;->skip(J)V

    .line 28
    .line 29
    .line 30
    return-object p1

    .line 31
    :cond_0
    sget-object v0, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 32
    .line 33
    invoke-virtual {p0, p1, p2, v0}, Lu01/f;->M(JLjava/nio/charset/Charset;)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-virtual {p0, v1, v2}, Lu01/f;->skip(J)V

    .line 38
    .line 39
    .line 40
    return-object p1
.end method

.method public static final d(Lu01/f;Lu01/w;Z)I
    .locals 16

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    const-string v1, "options"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p0

    .line 9
    .line 10
    iget-object v1, v1, Lu01/f;->d:Lu01/c0;

    .line 11
    .line 12
    const/4 v2, -0x1

    .line 13
    if-nez v1, :cond_1

    .line 14
    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    goto :goto_4

    .line 18
    :cond_0
    return v2

    .line 19
    :cond_1
    iget-object v3, v1, Lu01/c0;->a:[B

    .line 20
    .line 21
    iget v4, v1, Lu01/c0;->b:I

    .line 22
    .line 23
    iget v5, v1, Lu01/c0;->c:I

    .line 24
    .line 25
    iget-object v0, v0, Lu01/w;->e:[I

    .line 26
    .line 27
    const/4 v6, 0x0

    .line 28
    move-object v8, v1

    .line 29
    move v9, v2

    .line 30
    move v7, v6

    .line 31
    :goto_0
    add-int/lit8 v10, v7, 0x1

    .line 32
    .line 33
    aget v11, v0, v7

    .line 34
    .line 35
    add-int/lit8 v7, v7, 0x2

    .line 36
    .line 37
    aget v10, v0, v10

    .line 38
    .line 39
    if-eq v10, v2, :cond_2

    .line 40
    .line 41
    move v9, v10

    .line 42
    :cond_2
    if-nez v8, :cond_3

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_3
    const/4 v10, 0x0

    .line 46
    if-gez v11, :cond_a

    .line 47
    .line 48
    mul-int/lit8 v11, v11, -0x1

    .line 49
    .line 50
    add-int v12, v11, v7

    .line 51
    .line 52
    :goto_1
    add-int/lit8 v11, v4, 0x1

    .line 53
    .line 54
    aget-byte v4, v3, v4

    .line 55
    .line 56
    and-int/lit16 v4, v4, 0xff

    .line 57
    .line 58
    add-int/lit8 v13, v7, 0x1

    .line 59
    .line 60
    aget v7, v0, v7

    .line 61
    .line 62
    if-eq v4, v7, :cond_4

    .line 63
    .line 64
    goto :goto_7

    .line 65
    :cond_4
    if-ne v13, v12, :cond_5

    .line 66
    .line 67
    const/4 v4, 0x1

    .line 68
    goto :goto_2

    .line 69
    :cond_5
    move v4, v6

    .line 70
    :goto_2
    if-ne v11, v5, :cond_8

    .line 71
    .line 72
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v3, v8, Lu01/c0;->f:Lu01/c0;

    .line 76
    .line 77
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    iget v5, v3, Lu01/c0;->b:I

    .line 81
    .line 82
    iget-object v7, v3, Lu01/c0;->a:[B

    .line 83
    .line 84
    iget v8, v3, Lu01/c0;->c:I

    .line 85
    .line 86
    if-ne v3, v1, :cond_7

    .line 87
    .line 88
    if-eqz v4, :cond_6

    .line 89
    .line 90
    move-object v3, v7

    .line 91
    move-object v7, v10

    .line 92
    goto :goto_5

    .line 93
    :cond_6
    :goto_3
    if-eqz p2, :cond_b

    .line 94
    .line 95
    :goto_4
    const/4 v0, -0x2

    .line 96
    return v0

    .line 97
    :cond_7
    move-object v15, v7

    .line 98
    move-object v7, v3

    .line 99
    move-object v3, v15

    .line 100
    goto :goto_5

    .line 101
    :cond_8
    move-object v7, v8

    .line 102
    move v8, v5

    .line 103
    move v5, v11

    .line 104
    :goto_5
    if-eqz v4, :cond_9

    .line 105
    .line 106
    aget v4, v0, v13

    .line 107
    .line 108
    move v15, v8

    .line 109
    move-object v8, v7

    .line 110
    move v7, v15

    .line 111
    goto :goto_8

    .line 112
    :cond_9
    move v4, v5

    .line 113
    move v5, v8

    .line 114
    move-object v8, v7

    .line 115
    move v7, v13

    .line 116
    goto :goto_1

    .line 117
    :cond_a
    add-int/lit8 v12, v4, 0x1

    .line 118
    .line 119
    aget-byte v4, v3, v4

    .line 120
    .line 121
    and-int/lit16 v4, v4, 0xff

    .line 122
    .line 123
    add-int v13, v7, v11

    .line 124
    .line 125
    :goto_6
    if-ne v7, v13, :cond_c

    .line 126
    .line 127
    :cond_b
    :goto_7
    return v9

    .line 128
    :cond_c
    aget v14, v0, v7

    .line 129
    .line 130
    if-ne v4, v14, :cond_10

    .line 131
    .line 132
    add-int/2addr v7, v11

    .line 133
    aget v4, v0, v7

    .line 134
    .line 135
    if-ne v12, v5, :cond_e

    .line 136
    .line 137
    iget-object v8, v8, Lu01/c0;->f:Lu01/c0;

    .line 138
    .line 139
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iget v3, v8, Lu01/c0;->b:I

    .line 143
    .line 144
    iget-object v5, v8, Lu01/c0;->a:[B

    .line 145
    .line 146
    iget v7, v8, Lu01/c0;->c:I

    .line 147
    .line 148
    if-ne v8, v1, :cond_d

    .line 149
    .line 150
    move-object v8, v5

    .line 151
    move v5, v3

    .line 152
    move-object v3, v8

    .line 153
    move-object v8, v10

    .line 154
    goto :goto_8

    .line 155
    :cond_d
    move-object v15, v5

    .line 156
    move v5, v3

    .line 157
    move-object v3, v15

    .line 158
    goto :goto_8

    .line 159
    :cond_e
    move v7, v5

    .line 160
    move v5, v12

    .line 161
    :goto_8
    if-ltz v4, :cond_f

    .line 162
    .line 163
    return v4

    .line 164
    :cond_f
    neg-int v4, v4

    .line 165
    move v15, v7

    .line 166
    move v7, v4

    .line 167
    move v4, v5

    .line 168
    move v5, v15

    .line 169
    goto/16 :goto_0

    .line 170
    .line 171
    :cond_10
    add-int/lit8 v7, v7, 0x1

    .line 172
    .line 173
    goto :goto_6
.end method
