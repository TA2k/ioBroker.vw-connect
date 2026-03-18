.class public final Landroidx/collection/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:[J

.field public b:[Ljava/lang/Object;

.field public c:[I

.field public d:I

.field public e:I

.field public f:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x6

    .line 9
    invoke-direct {p0, v0}, Landroidx/collection/h0;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Landroidx/collection/y0;->a:[J

    iput-object v0, p0, Landroidx/collection/h0;->a:[J

    .line 3
    sget-object v0, La1/a;->c:[Ljava/lang/Object;

    iput-object v0, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 4
    sget-object v0, Landroidx/collection/r;->a:[I

    .line 5
    iput-object v0, p0, Landroidx/collection/h0;->c:[I

    if-ltz p1, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    .line 6
    invoke-static {p1}, Landroidx/collection/y0;->d(I)I

    move-result p1

    invoke-virtual {p0, p1}, Landroidx/collection/h0;->f(I)V

    return-void

    .line 7
    :cond_1
    const-string p0, "Capacity must be a positive value."

    .line 8
    invoke-static {p0}, La1/a;->c(Ljava/lang/String;)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Landroidx/collection/h0;->e:I

    .line 3
    .line 4
    iget-object v1, p0, Landroidx/collection/h0;->a:[J

    .line 5
    .line 6
    sget-object v2, Landroidx/collection/y0;->a:[J

    .line 7
    .line 8
    if-eq v1, v2, :cond_0

    .line 9
    .line 10
    const-wide v2, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    invoke-static {v2, v3, v1}, Lmx0/n;->r(J[J)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Landroidx/collection/h0;->a:[J

    .line 19
    .line 20
    iget v2, p0, Landroidx/collection/h0;->d:I

    .line 21
    .line 22
    shr-int/lit8 v3, v2, 0x3

    .line 23
    .line 24
    and-int/lit8 v2, v2, 0x7

    .line 25
    .line 26
    shl-int/lit8 v2, v2, 0x3

    .line 27
    .line 28
    aget-wide v4, v1, v3

    .line 29
    .line 30
    const-wide/16 v6, 0xff

    .line 31
    .line 32
    shl-long/2addr v6, v2

    .line 33
    not-long v8, v6

    .line 34
    and-long/2addr v4, v8

    .line 35
    or-long/2addr v4, v6

    .line 36
    aput-wide v4, v1, v3

    .line 37
    .line 38
    :cond_0
    iget-object v1, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    iget v3, p0, Landroidx/collection/h0;->d:I

    .line 42
    .line 43
    invoke-static {v0, v3, v2, v1}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget v0, p0, Landroidx/collection/h0;->d:I

    .line 47
    .line 48
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v1, p0, Landroidx/collection/h0;->e:I

    .line 53
    .line 54
    sub-int/2addr v0, v1

    .line 55
    iput v0, p0, Landroidx/collection/h0;->f:I

    .line 56
    .line 57
    return-void
.end method

.method public final b(I)I
    .locals 9

    .line 1
    iget v0, p0, Landroidx/collection/h0;->d:I

    .line 2
    .line 3
    and-int/2addr p1, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    iget-object v2, p0, Landroidx/collection/h0;->a:[J

    .line 6
    .line 7
    shr-int/lit8 v3, p1, 0x3

    .line 8
    .line 9
    and-int/lit8 v4, p1, 0x7

    .line 10
    .line 11
    shl-int/lit8 v4, v4, 0x3

    .line 12
    .line 13
    aget-wide v5, v2, v3

    .line 14
    .line 15
    ushr-long/2addr v5, v4

    .line 16
    add-int/lit8 v3, v3, 0x1

    .line 17
    .line 18
    aget-wide v2, v2, v3

    .line 19
    .line 20
    rsub-int/lit8 v7, v4, 0x40

    .line 21
    .line 22
    shl-long/2addr v2, v7

    .line 23
    int-to-long v7, v4

    .line 24
    neg-long v7, v7

    .line 25
    const/16 v4, 0x3f

    .line 26
    .line 27
    shr-long/2addr v7, v4

    .line 28
    and-long/2addr v2, v7

    .line 29
    or-long/2addr v2, v5

    .line 30
    not-long v4, v2

    .line 31
    const/4 v6, 0x7

    .line 32
    shl-long/2addr v4, v6

    .line 33
    and-long/2addr v2, v4

    .line 34
    const-wide v4, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long/2addr v2, v4

    .line 40
    const-wide/16 v4, 0x0

    .line 41
    .line 42
    cmp-long v4, v2, v4

    .line 43
    .line 44
    if-eqz v4, :cond_0

    .line 45
    .line 46
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    shr-int/lit8 p0, p0, 0x3

    .line 51
    .line 52
    add-int/2addr p1, p0

    .line 53
    and-int p0, p1, v0

    .line 54
    .line 55
    return p0

    .line 56
    :cond_0
    add-int/lit8 v1, v1, 0x8

    .line 57
    .line 58
    add-int/2addr p1, v1

    .line 59
    and-int/2addr p1, v0

    .line 60
    goto :goto_0
.end method

.method public final c(Ljava/lang/Object;)I
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v3, 0x0

    .line 13
    :goto_0
    const v4, -0x3361d2af    # -8.2930312E7f

    .line 14
    .line 15
    .line 16
    mul-int/2addr v3, v4

    .line 17
    shl-int/lit8 v5, v3, 0x10

    .line 18
    .line 19
    xor-int/2addr v3, v5

    .line 20
    ushr-int/lit8 v5, v3, 0x7

    .line 21
    .line 22
    and-int/lit8 v3, v3, 0x7f

    .line 23
    .line 24
    iget v6, v0, Landroidx/collection/h0;->d:I

    .line 25
    .line 26
    and-int v7, v5, v6

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    :goto_1
    iget-object v9, v0, Landroidx/collection/h0;->a:[J

    .line 30
    .line 31
    shr-int/lit8 v10, v7, 0x3

    .line 32
    .line 33
    and-int/lit8 v11, v7, 0x7

    .line 34
    .line 35
    shl-int/lit8 v11, v11, 0x3

    .line 36
    .line 37
    aget-wide v12, v9, v10

    .line 38
    .line 39
    ushr-long/2addr v12, v11

    .line 40
    const/4 v14, 0x1

    .line 41
    add-int/2addr v10, v14

    .line 42
    aget-wide v9, v9, v10

    .line 43
    .line 44
    rsub-int/lit8 v15, v11, 0x40

    .line 45
    .line 46
    shl-long/2addr v9, v15

    .line 47
    move/from16 v16, v14

    .line 48
    .line 49
    int-to-long v14, v11

    .line 50
    neg-long v14, v14

    .line 51
    const/16 v11, 0x3f

    .line 52
    .line 53
    shr-long/2addr v14, v11

    .line 54
    and-long/2addr v9, v14

    .line 55
    or-long/2addr v9, v12

    .line 56
    int-to-long v11, v3

    .line 57
    const-wide v13, 0x101010101010101L

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    mul-long v17, v11, v13

    .line 63
    .line 64
    move/from16 v19, v3

    .line 65
    .line 66
    const/4 v15, 0x0

    .line 67
    xor-long v2, v9, v17

    .line 68
    .line 69
    sub-long v13, v2, v13

    .line 70
    .line 71
    not-long v2, v2

    .line 72
    and-long/2addr v2, v13

    .line 73
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    and-long/2addr v2, v13

    .line 79
    :goto_2
    const-wide/16 v17, 0x0

    .line 80
    .line 81
    cmp-long v20, v2, v17

    .line 82
    .line 83
    if-eqz v20, :cond_2

    .line 84
    .line 85
    invoke-static {v2, v3}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 86
    .line 87
    .line 88
    move-result v17

    .line 89
    shr-int/lit8 v17, v17, 0x3

    .line 90
    .line 91
    add-int v17, v7, v17

    .line 92
    .line 93
    and-int v17, v17, v6

    .line 94
    .line 95
    move/from16 v20, v4

    .line 96
    .line 97
    iget-object v4, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 98
    .line 99
    aget-object v4, v4, v17

    .line 100
    .line 101
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v4

    .line 105
    if-eqz v4, :cond_1

    .line 106
    .line 107
    return v17

    .line 108
    :cond_1
    const-wide/16 v17, 0x1

    .line 109
    .line 110
    sub-long v17, v2, v17

    .line 111
    .line 112
    and-long v2, v2, v17

    .line 113
    .line 114
    move/from16 v4, v20

    .line 115
    .line 116
    goto :goto_2

    .line 117
    :cond_2
    move/from16 v20, v4

    .line 118
    .line 119
    not-long v2, v9

    .line 120
    const/4 v4, 0x6

    .line 121
    shl-long/2addr v2, v4

    .line 122
    and-long/2addr v2, v9

    .line 123
    and-long/2addr v2, v13

    .line 124
    cmp-long v2, v2, v17

    .line 125
    .line 126
    const/16 v3, 0x8

    .line 127
    .line 128
    if-eqz v2, :cond_12

    .line 129
    .line 130
    invoke-virtual {v0, v5}, Landroidx/collection/h0;->b(I)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    iget v2, v0, Landroidx/collection/h0;->f:I

    .line 135
    .line 136
    const-wide/16 v8, 0xff

    .line 137
    .line 138
    if-nez v2, :cond_3

    .line 139
    .line 140
    iget-object v2, v0, Landroidx/collection/h0;->a:[J

    .line 141
    .line 142
    shr-int/lit8 v10, v1, 0x3

    .line 143
    .line 144
    aget-wide v17, v2, v10

    .line 145
    .line 146
    and-int/lit8 v2, v1, 0x7

    .line 147
    .line 148
    shl-int/lit8 v2, v2, 0x3

    .line 149
    .line 150
    shr-long v17, v17, v2

    .line 151
    .line 152
    and-long v17, v17, v8

    .line 153
    .line 154
    const-wide/16 v21, 0xfe

    .line 155
    .line 156
    cmp-long v2, v17, v21

    .line 157
    .line 158
    if-nez v2, :cond_4

    .line 159
    .line 160
    :cond_3
    move-wide/from16 v25, v8

    .line 161
    .line 162
    move-wide/from16 v23, v11

    .line 163
    .line 164
    const/16 p1, 0x7

    .line 165
    .line 166
    const-wide/16 v18, 0x80

    .line 167
    .line 168
    goto/16 :goto_e

    .line 169
    .line 170
    :cond_4
    iget v1, v0, Landroidx/collection/h0;->d:I

    .line 171
    .line 172
    if-le v1, v3, :cond_d

    .line 173
    .line 174
    iget v2, v0, Landroidx/collection/h0;->e:I

    .line 175
    .line 176
    move v10, v3

    .line 177
    const/16 p1, 0x7

    .line 178
    .line 179
    int-to-long v3, v2

    .line 180
    const-wide/16 v17, 0x20

    .line 181
    .line 182
    mul-long v3, v3, v17

    .line 183
    .line 184
    int-to-long v1, v1

    .line 185
    const-wide/16 v17, 0x19

    .line 186
    .line 187
    mul-long v1, v1, v17

    .line 188
    .line 189
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 190
    .line 191
    .line 192
    move-result v1

    .line 193
    if-gtz v1, :cond_c

    .line 194
    .line 195
    iget-object v1, v0, Landroidx/collection/h0;->a:[J

    .line 196
    .line 197
    iget v2, v0, Landroidx/collection/h0;->d:I

    .line 198
    .line 199
    iget-object v3, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 200
    .line 201
    iget-object v4, v0, Landroidx/collection/h0;->c:[I

    .line 202
    .line 203
    add-int/lit8 v17, v2, 0x7

    .line 204
    .line 205
    const-wide/16 v18, 0x80

    .line 206
    .line 207
    shr-int/lit8 v6, v17, 0x3

    .line 208
    .line 209
    move v7, v15

    .line 210
    :goto_3
    if-ge v7, v6, :cond_5

    .line 211
    .line 212
    aget-wide v23, v1, v7

    .line 213
    .line 214
    move-wide/from16 v25, v8

    .line 215
    .line 216
    and-long v8, v23, v13

    .line 217
    .line 218
    move-wide/from16 v23, v11

    .line 219
    .line 220
    move v12, v10

    .line 221
    not-long v10, v8

    .line 222
    ushr-long v8, v8, p1

    .line 223
    .line 224
    add-long/2addr v10, v8

    .line 225
    const-wide v8, -0x101010101010102L

    .line 226
    .line 227
    .line 228
    .line 229
    .line 230
    and-long/2addr v8, v10

    .line 231
    aput-wide v8, v1, v7

    .line 232
    .line 233
    add-int/lit8 v7, v7, 0x1

    .line 234
    .line 235
    move v10, v12

    .line 236
    move-wide/from16 v11, v23

    .line 237
    .line 238
    move-wide/from16 v8, v25

    .line 239
    .line 240
    goto :goto_3

    .line 241
    :cond_5
    move-wide/from16 v25, v8

    .line 242
    .line 243
    move-wide/from16 v23, v11

    .line 244
    .line 245
    move v12, v10

    .line 246
    invoke-static {v1}, Lmx0/n;->A([J)I

    .line 247
    .line 248
    .line 249
    move-result v6

    .line 250
    add-int/lit8 v7, v6, -0x1

    .line 251
    .line 252
    aget-wide v8, v1, v7

    .line 253
    .line 254
    const-wide v10, 0xffffffffffffffL

    .line 255
    .line 256
    .line 257
    .line 258
    .line 259
    and-long/2addr v8, v10

    .line 260
    const-wide/high16 v13, -0x100000000000000L

    .line 261
    .line 262
    or-long/2addr v8, v13

    .line 263
    aput-wide v8, v1, v7

    .line 264
    .line 265
    aget-wide v7, v1, v15

    .line 266
    .line 267
    aput-wide v7, v1, v6

    .line 268
    .line 269
    move v6, v15

    .line 270
    :goto_4
    if-eq v6, v2, :cond_b

    .line 271
    .line 272
    shr-int/lit8 v7, v6, 0x3

    .line 273
    .line 274
    aget-wide v8, v1, v7

    .line 275
    .line 276
    and-int/lit8 v13, v6, 0x7

    .line 277
    .line 278
    shl-int/lit8 v13, v13, 0x3

    .line 279
    .line 280
    shr-long/2addr v8, v13

    .line 281
    and-long v8, v8, v25

    .line 282
    .line 283
    cmp-long v14, v8, v18

    .line 284
    .line 285
    if-nez v14, :cond_6

    .line 286
    .line 287
    :goto_5
    add-int/lit8 v6, v6, 0x1

    .line 288
    .line 289
    goto :goto_4

    .line 290
    :cond_6
    cmp-long v8, v8, v21

    .line 291
    .line 292
    if-eqz v8, :cond_7

    .line 293
    .line 294
    goto :goto_5

    .line 295
    :cond_7
    aget-object v8, v3, v6

    .line 296
    .line 297
    if-eqz v8, :cond_8

    .line 298
    .line 299
    invoke-virtual {v8}, Ljava/lang/Object;->hashCode()I

    .line 300
    .line 301
    .line 302
    move-result v8

    .line 303
    goto :goto_6

    .line 304
    :cond_8
    move v8, v15

    .line 305
    :goto_6
    mul-int v8, v8, v20

    .line 306
    .line 307
    shl-int/lit8 v9, v8, 0x10

    .line 308
    .line 309
    xor-int/2addr v8, v9

    .line 310
    ushr-int/lit8 v9, v8, 0x7

    .line 311
    .line 312
    invoke-virtual {v0, v9}, Landroidx/collection/h0;->b(I)I

    .line 313
    .line 314
    .line 315
    move-result v14

    .line 316
    and-int/2addr v9, v2

    .line 317
    sub-int v17, v14, v9

    .line 318
    .line 319
    and-int v17, v17, v2

    .line 320
    .line 321
    move-wide/from16 v27, v10

    .line 322
    .line 323
    div-int/lit8 v10, v17, 0x8

    .line 324
    .line 325
    sub-int v9, v6, v9

    .line 326
    .line 327
    and-int/2addr v9, v2

    .line 328
    div-int/2addr v9, v12

    .line 329
    const-wide/high16 v29, -0x8000000000000000L

    .line 330
    .line 331
    if-ne v10, v9, :cond_9

    .line 332
    .line 333
    and-int/lit8 v8, v8, 0x7f

    .line 334
    .line 335
    int-to-long v8, v8

    .line 336
    aget-wide v10, v1, v7

    .line 337
    .line 338
    move/from16 v17, v12

    .line 339
    .line 340
    move/from16 v31, v13

    .line 341
    .line 342
    shl-long v12, v25, v31

    .line 343
    .line 344
    not-long v12, v12

    .line 345
    and-long/2addr v10, v12

    .line 346
    shl-long v8, v8, v31

    .line 347
    .line 348
    or-long/2addr v8, v10

    .line 349
    aput-wide v8, v1, v7

    .line 350
    .line 351
    array-length v7, v1

    .line 352
    add-int/lit8 v7, v7, -0x1

    .line 353
    .line 354
    aget-wide v8, v1, v15

    .line 355
    .line 356
    and-long v8, v8, v27

    .line 357
    .line 358
    or-long v8, v8, v29

    .line 359
    .line 360
    aput-wide v8, v1, v7

    .line 361
    .line 362
    add-int/lit8 v6, v6, 0x1

    .line 363
    .line 364
    move/from16 v12, v17

    .line 365
    .line 366
    move-wide/from16 v10, v27

    .line 367
    .line 368
    goto :goto_4

    .line 369
    :cond_9
    move/from16 v17, v12

    .line 370
    .line 371
    move/from16 v31, v13

    .line 372
    .line 373
    shr-int/lit8 v9, v14, 0x3

    .line 374
    .line 375
    aget-wide v10, v1, v9

    .line 376
    .line 377
    and-int/lit8 v12, v14, 0x7

    .line 378
    .line 379
    shl-int/lit8 v12, v12, 0x3

    .line 380
    .line 381
    shr-long v32, v10, v12

    .line 382
    .line 383
    and-long v32, v32, v25

    .line 384
    .line 385
    cmp-long v13, v32, v18

    .line 386
    .line 387
    if-nez v13, :cond_a

    .line 388
    .line 389
    and-int/lit8 v8, v8, 0x7f

    .line 390
    .line 391
    move v13, v2

    .line 392
    move-object/from16 v32, v3

    .line 393
    .line 394
    int-to-long v2, v8

    .line 395
    move-wide/from16 v33, v2

    .line 396
    .line 397
    shl-long v2, v25, v12

    .line 398
    .line 399
    not-long v2, v2

    .line 400
    and-long/2addr v2, v10

    .line 401
    shl-long v10, v33, v12

    .line 402
    .line 403
    or-long/2addr v2, v10

    .line 404
    aput-wide v2, v1, v9

    .line 405
    .line 406
    aget-wide v2, v1, v7

    .line 407
    .line 408
    shl-long v8, v25, v31

    .line 409
    .line 410
    not-long v8, v8

    .line 411
    and-long/2addr v2, v8

    .line 412
    shl-long v8, v18, v31

    .line 413
    .line 414
    or-long/2addr v2, v8

    .line 415
    aput-wide v2, v1, v7

    .line 416
    .line 417
    aget-object v2, v32, v6

    .line 418
    .line 419
    aput-object v2, v32, v14

    .line 420
    .line 421
    const/4 v2, 0x0

    .line 422
    aput-object v2, v32, v6

    .line 423
    .line 424
    aget v2, v4, v6

    .line 425
    .line 426
    aput v2, v4, v14

    .line 427
    .line 428
    aput v15, v4, v6

    .line 429
    .line 430
    goto :goto_7

    .line 431
    :cond_a
    move v13, v2

    .line 432
    move-object/from16 v32, v3

    .line 433
    .line 434
    and-int/lit8 v2, v8, 0x7f

    .line 435
    .line 436
    int-to-long v2, v2

    .line 437
    shl-long v7, v25, v12

    .line 438
    .line 439
    not-long v7, v7

    .line 440
    and-long/2addr v7, v10

    .line 441
    shl-long/2addr v2, v12

    .line 442
    or-long/2addr v2, v7

    .line 443
    aput-wide v2, v1, v9

    .line 444
    .line 445
    aget-object v2, v32, v14

    .line 446
    .line 447
    aget-object v3, v32, v6

    .line 448
    .line 449
    aput-object v3, v32, v14

    .line 450
    .line 451
    aput-object v2, v32, v6

    .line 452
    .line 453
    aget v2, v4, v14

    .line 454
    .line 455
    aget v3, v4, v6

    .line 456
    .line 457
    aput v3, v4, v14

    .line 458
    .line 459
    aput v2, v4, v6

    .line 460
    .line 461
    add-int/lit8 v6, v6, -0x1

    .line 462
    .line 463
    :goto_7
    array-length v2, v1

    .line 464
    add-int/lit8 v2, v2, -0x1

    .line 465
    .line 466
    aget-wide v7, v1, v15

    .line 467
    .line 468
    and-long v7, v7, v27

    .line 469
    .line 470
    or-long v7, v7, v29

    .line 471
    .line 472
    aput-wide v7, v1, v2

    .line 473
    .line 474
    add-int/lit8 v6, v6, 0x1

    .line 475
    .line 476
    move v2, v13

    .line 477
    move/from16 v12, v17

    .line 478
    .line 479
    move-wide/from16 v10, v27

    .line 480
    .line 481
    move-object/from16 v3, v32

    .line 482
    .line 483
    goto/16 :goto_4

    .line 484
    .line 485
    :cond_b
    iget v1, v0, Landroidx/collection/h0;->d:I

    .line 486
    .line 487
    invoke-static {v1}, Landroidx/collection/y0;->a(I)I

    .line 488
    .line 489
    .line 490
    move-result v1

    .line 491
    iget v2, v0, Landroidx/collection/h0;->e:I

    .line 492
    .line 493
    sub-int/2addr v1, v2

    .line 494
    iput v1, v0, Landroidx/collection/h0;->f:I

    .line 495
    .line 496
    goto/16 :goto_d

    .line 497
    .line 498
    :cond_c
    :goto_8
    move-wide/from16 v25, v8

    .line 499
    .line 500
    move-wide/from16 v23, v11

    .line 501
    .line 502
    const-wide/16 v18, 0x80

    .line 503
    .line 504
    goto :goto_9

    .line 505
    :cond_d
    const/16 p1, 0x7

    .line 506
    .line 507
    goto :goto_8

    .line 508
    :goto_9
    iget v1, v0, Landroidx/collection/h0;->d:I

    .line 509
    .line 510
    invoke-static {v1}, Landroidx/collection/y0;->b(I)I

    .line 511
    .line 512
    .line 513
    move-result v1

    .line 514
    iget-object v2, v0, Landroidx/collection/h0;->a:[J

    .line 515
    .line 516
    iget-object v3, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 517
    .line 518
    iget-object v4, v0, Landroidx/collection/h0;->c:[I

    .line 519
    .line 520
    iget v6, v0, Landroidx/collection/h0;->d:I

    .line 521
    .line 522
    invoke-virtual {v0, v1}, Landroidx/collection/h0;->f(I)V

    .line 523
    .line 524
    .line 525
    iget-object v1, v0, Landroidx/collection/h0;->a:[J

    .line 526
    .line 527
    iget-object v7, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 528
    .line 529
    iget-object v8, v0, Landroidx/collection/h0;->c:[I

    .line 530
    .line 531
    iget v9, v0, Landroidx/collection/h0;->d:I

    .line 532
    .line 533
    move v10, v15

    .line 534
    :goto_a
    if-ge v10, v6, :cond_10

    .line 535
    .line 536
    shr-int/lit8 v11, v10, 0x3

    .line 537
    .line 538
    aget-wide v11, v2, v11

    .line 539
    .line 540
    and-int/lit8 v13, v10, 0x7

    .line 541
    .line 542
    shl-int/lit8 v13, v13, 0x3

    .line 543
    .line 544
    shr-long/2addr v11, v13

    .line 545
    and-long v11, v11, v25

    .line 546
    .line 547
    cmp-long v11, v11, v18

    .line 548
    .line 549
    if-gez v11, :cond_f

    .line 550
    .line 551
    aget-object v11, v3, v10

    .line 552
    .line 553
    if-eqz v11, :cond_e

    .line 554
    .line 555
    invoke-virtual {v11}, Ljava/lang/Object;->hashCode()I

    .line 556
    .line 557
    .line 558
    move-result v12

    .line 559
    goto :goto_b

    .line 560
    :cond_e
    move v12, v15

    .line 561
    :goto_b
    mul-int v12, v12, v20

    .line 562
    .line 563
    shl-int/lit8 v13, v12, 0x10

    .line 564
    .line 565
    xor-int/2addr v12, v13

    .line 566
    ushr-int/lit8 v13, v12, 0x7

    .line 567
    .line 568
    invoke-virtual {v0, v13}, Landroidx/collection/h0;->b(I)I

    .line 569
    .line 570
    .line 571
    move-result v13

    .line 572
    and-int/lit8 v12, v12, 0x7f

    .line 573
    .line 574
    move-object/from16 v17, v1

    .line 575
    .line 576
    move-object v14, v2

    .line 577
    int-to-long v1, v12

    .line 578
    shr-int/lit8 v12, v13, 0x3

    .line 579
    .line 580
    and-int/lit8 v21, v13, 0x7

    .line 581
    .line 582
    shl-int/lit8 v21, v21, 0x3

    .line 583
    .line 584
    aget-wide v27, v17, v12

    .line 585
    .line 586
    move-wide/from16 v29, v1

    .line 587
    .line 588
    shl-long v1, v25, v21

    .line 589
    .line 590
    not-long v1, v1

    .line 591
    and-long v1, v27, v1

    .line 592
    .line 593
    shl-long v21, v29, v21

    .line 594
    .line 595
    or-long v1, v1, v21

    .line 596
    .line 597
    aput-wide v1, v17, v12

    .line 598
    .line 599
    add-int/lit8 v12, v13, -0x7

    .line 600
    .line 601
    and-int/2addr v12, v9

    .line 602
    and-int/lit8 v21, v9, 0x7

    .line 603
    .line 604
    add-int v12, v12, v21

    .line 605
    .line 606
    shr-int/lit8 v12, v12, 0x3

    .line 607
    .line 608
    aput-wide v1, v17, v12

    .line 609
    .line 610
    aput-object v11, v7, v13

    .line 611
    .line 612
    aget v1, v4, v10

    .line 613
    .line 614
    aput v1, v8, v13

    .line 615
    .line 616
    goto :goto_c

    .line 617
    :cond_f
    move-object/from16 v17, v1

    .line 618
    .line 619
    move-object v14, v2

    .line 620
    :goto_c
    add-int/lit8 v10, v10, 0x1

    .line 621
    .line 622
    move-object v2, v14

    .line 623
    move-object/from16 v1, v17

    .line 624
    .line 625
    goto :goto_a

    .line 626
    :cond_10
    :goto_d
    invoke-virtual {v0, v5}, Landroidx/collection/h0;->b(I)I

    .line 627
    .line 628
    .line 629
    move-result v1

    .line 630
    :goto_e
    iget v2, v0, Landroidx/collection/h0;->e:I

    .line 631
    .line 632
    add-int/lit8 v2, v2, 0x1

    .line 633
    .line 634
    iput v2, v0, Landroidx/collection/h0;->e:I

    .line 635
    .line 636
    iget v2, v0, Landroidx/collection/h0;->f:I

    .line 637
    .line 638
    iget-object v3, v0, Landroidx/collection/h0;->a:[J

    .line 639
    .line 640
    shr-int/lit8 v4, v1, 0x3

    .line 641
    .line 642
    aget-wide v5, v3, v4

    .line 643
    .line 644
    and-int/lit8 v7, v1, 0x7

    .line 645
    .line 646
    shl-int/lit8 v7, v7, 0x3

    .line 647
    .line 648
    shr-long v8, v5, v7

    .line 649
    .line 650
    and-long v8, v8, v25

    .line 651
    .line 652
    cmp-long v8, v8, v18

    .line 653
    .line 654
    if-nez v8, :cond_11

    .line 655
    .line 656
    move/from16 v15, v16

    .line 657
    .line 658
    :cond_11
    sub-int/2addr v2, v15

    .line 659
    iput v2, v0, Landroidx/collection/h0;->f:I

    .line 660
    .line 661
    iget v0, v0, Landroidx/collection/h0;->d:I

    .line 662
    .line 663
    shl-long v8, v25, v7

    .line 664
    .line 665
    not-long v8, v8

    .line 666
    and-long/2addr v5, v8

    .line 667
    shl-long v7, v23, v7

    .line 668
    .line 669
    or-long/2addr v5, v7

    .line 670
    aput-wide v5, v3, v4

    .line 671
    .line 672
    add-int/lit8 v2, v1, -0x7

    .line 673
    .line 674
    and-int/2addr v2, v0

    .line 675
    and-int/lit8 v0, v0, 0x7

    .line 676
    .line 677
    add-int/2addr v2, v0

    .line 678
    shr-int/lit8 v0, v2, 0x3

    .line 679
    .line 680
    aput-wide v5, v3, v0

    .line 681
    .line 682
    not-int v0, v1

    .line 683
    return v0

    .line 684
    :cond_12
    move/from16 v17, v3

    .line 685
    .line 686
    add-int/lit8 v8, v8, 0x8

    .line 687
    .line 688
    add-int/2addr v7, v8

    .line 689
    and-int/2addr v7, v6

    .line 690
    move/from16 v3, v19

    .line 691
    .line 692
    move/from16 v4, v20

    .line 693
    .line 694
    goto/16 :goto_1
.end method

.method public final d(Ljava/lang/Object;)I
    .locals 13

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    const v2, -0x3361d2af    # -8.2930312E7f

    .line 11
    .line 12
    .line 13
    mul-int/2addr v1, v2

    .line 14
    shl-int/lit8 v2, v1, 0x10

    .line 15
    .line 16
    xor-int/2addr v1, v2

    .line 17
    and-int/lit8 v2, v1, 0x7f

    .line 18
    .line 19
    iget v3, p0, Landroidx/collection/h0;->d:I

    .line 20
    .line 21
    ushr-int/lit8 v1, v1, 0x7

    .line 22
    .line 23
    :goto_1
    and-int/2addr v1, v3

    .line 24
    iget-object v4, p0, Landroidx/collection/h0;->a:[J

    .line 25
    .line 26
    shr-int/lit8 v5, v1, 0x3

    .line 27
    .line 28
    and-int/lit8 v6, v1, 0x7

    .line 29
    .line 30
    shl-int/lit8 v6, v6, 0x3

    .line 31
    .line 32
    aget-wide v7, v4, v5

    .line 33
    .line 34
    ushr-long/2addr v7, v6

    .line 35
    add-int/lit8 v5, v5, 0x1

    .line 36
    .line 37
    aget-wide v4, v4, v5

    .line 38
    .line 39
    rsub-int/lit8 v9, v6, 0x40

    .line 40
    .line 41
    shl-long/2addr v4, v9

    .line 42
    int-to-long v9, v6

    .line 43
    neg-long v9, v9

    .line 44
    const/16 v6, 0x3f

    .line 45
    .line 46
    shr-long/2addr v9, v6

    .line 47
    and-long/2addr v4, v9

    .line 48
    or-long/2addr v4, v7

    .line 49
    int-to-long v6, v2

    .line 50
    const-wide v8, 0x101010101010101L

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    mul-long/2addr v6, v8

    .line 56
    xor-long/2addr v6, v4

    .line 57
    sub-long v8, v6, v8

    .line 58
    .line 59
    not-long v6, v6

    .line 60
    and-long/2addr v6, v8

    .line 61
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 62
    .line 63
    .line 64
    .line 65
    .line 66
    and-long/2addr v6, v8

    .line 67
    :goto_2
    const-wide/16 v10, 0x0

    .line 68
    .line 69
    cmp-long v12, v6, v10

    .line 70
    .line 71
    if-eqz v12, :cond_2

    .line 72
    .line 73
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    shr-int/lit8 v10, v10, 0x3

    .line 78
    .line 79
    add-int/2addr v10, v1

    .line 80
    and-int/2addr v10, v3

    .line 81
    iget-object v11, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 82
    .line 83
    aget-object v11, v11, v10

    .line 84
    .line 85
    invoke-static {v11, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v11

    .line 89
    if-eqz v11, :cond_1

    .line 90
    .line 91
    return v10

    .line 92
    :cond_1
    const-wide/16 v10, 0x1

    .line 93
    .line 94
    sub-long v10, v6, v10

    .line 95
    .line 96
    and-long/2addr v6, v10

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    not-long v6, v4

    .line 99
    const/4 v12, 0x6

    .line 100
    shl-long/2addr v6, v12

    .line 101
    and-long/2addr v4, v6

    .line 102
    and-long/2addr v4, v8

    .line 103
    cmp-long v4, v4, v10

    .line 104
    .line 105
    if-eqz v4, :cond_3

    .line 106
    .line 107
    const/4 p0, -0x1

    .line 108
    return p0

    .line 109
    :cond_3
    add-int/lit8 v0, v0, 0x8

    .line 110
    .line 111
    add-int/2addr v1, v0

    .line 112
    goto :goto_1
.end method

.method public final e(Ljava/lang/Object;)I
    .locals 1

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ltz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Landroidx/collection/h0;->c:[I

    .line 8
    .line 9
    aget p0, p0, v0

    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 13
    .line 14
    const-string v0, "There is no key "

    .line 15
    .line 16
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string p1, " in the map"

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-static {p0}, La1/a;->e(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    throw p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    if-ne v1, v0, :cond_0

    .line 7
    .line 8
    return v2

    .line 9
    :cond_0
    instance-of v3, v1, Landroidx/collection/h0;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    if-nez v3, :cond_1

    .line 13
    .line 14
    return v4

    .line 15
    :cond_1
    check-cast v1, Landroidx/collection/h0;

    .line 16
    .line 17
    iget v3, v1, Landroidx/collection/h0;->e:I

    .line 18
    .line 19
    iget v5, v0, Landroidx/collection/h0;->e:I

    .line 20
    .line 21
    if-eq v3, v5, :cond_2

    .line 22
    .line 23
    return v4

    .line 24
    :cond_2
    iget-object v3, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 25
    .line 26
    iget-object v5, v0, Landroidx/collection/h0;->c:[I

    .line 27
    .line 28
    iget-object v0, v0, Landroidx/collection/h0;->a:[J

    .line 29
    .line 30
    array-length v6, v0

    .line 31
    add-int/lit8 v6, v6, -0x2

    .line 32
    .line 33
    if-ltz v6, :cond_7

    .line 34
    .line 35
    move v7, v4

    .line 36
    :goto_0
    aget-wide v8, v0, v7

    .line 37
    .line 38
    not-long v10, v8

    .line 39
    const/4 v12, 0x7

    .line 40
    shl-long/2addr v10, v12

    .line 41
    and-long/2addr v10, v8

    .line 42
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v10, v12

    .line 48
    cmp-long v10, v10, v12

    .line 49
    .line 50
    if-eqz v10, :cond_6

    .line 51
    .line 52
    sub-int v10, v7, v6

    .line 53
    .line 54
    not-int v10, v10

    .line 55
    ushr-int/lit8 v10, v10, 0x1f

    .line 56
    .line 57
    const/16 v11, 0x8

    .line 58
    .line 59
    rsub-int/lit8 v10, v10, 0x8

    .line 60
    .line 61
    move v12, v4

    .line 62
    :goto_1
    if-ge v12, v10, :cond_5

    .line 63
    .line 64
    const-wide/16 v13, 0xff

    .line 65
    .line 66
    and-long/2addr v13, v8

    .line 67
    const-wide/16 v15, 0x80

    .line 68
    .line 69
    cmp-long v13, v13, v15

    .line 70
    .line 71
    if-gez v13, :cond_4

    .line 72
    .line 73
    shl-int/lit8 v13, v7, 0x3

    .line 74
    .line 75
    add-int/2addr v13, v12

    .line 76
    aget-object v14, v3, v13

    .line 77
    .line 78
    aget v13, v5, v13

    .line 79
    .line 80
    invoke-virtual {v1, v14}, Landroidx/collection/h0;->d(Ljava/lang/Object;)I

    .line 81
    .line 82
    .line 83
    move-result v14

    .line 84
    if-ltz v14, :cond_3

    .line 85
    .line 86
    iget-object v15, v1, Landroidx/collection/h0;->c:[I

    .line 87
    .line 88
    aget v14, v15, v14

    .line 89
    .line 90
    if-eq v13, v14, :cond_4

    .line 91
    .line 92
    :cond_3
    return v4

    .line 93
    :cond_4
    shr-long/2addr v8, v11

    .line 94
    add-int/lit8 v12, v12, 0x1

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_5
    if-ne v10, v11, :cond_7

    .line 98
    .line 99
    :cond_6
    if-eq v7, v6, :cond_7

    .line 100
    .line 101
    add-int/lit8 v7, v7, 0x1

    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_7
    return v2
.end method

.method public final f(I)V
    .locals 9

    .line 1
    if-lez p1, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Landroidx/collection/y0;->c(I)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    const/4 v0, 0x7

    .line 8
    invoke-static {v0, p1}, Ljava/lang/Math;->max(II)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    iput p1, p0, Landroidx/collection/h0;->d:I

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    sget-object v0, Landroidx/collection/y0;->a:[J

    .line 19
    .line 20
    goto :goto_1

    .line 21
    :cond_1
    add-int/lit8 v0, p1, 0xf

    .line 22
    .line 23
    and-int/lit8 v0, v0, -0x8

    .line 24
    .line 25
    shr-int/lit8 v0, v0, 0x3

    .line 26
    .line 27
    new-array v0, v0, [J

    .line 28
    .line 29
    const-wide v1, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    invoke-static {v1, v2, v0}, Lmx0/n;->r(J[J)V

    .line 35
    .line 36
    .line 37
    :goto_1
    iput-object v0, p0, Landroidx/collection/h0;->a:[J

    .line 38
    .line 39
    shr-int/lit8 v1, p1, 0x3

    .line 40
    .line 41
    and-int/lit8 v2, p1, 0x7

    .line 42
    .line 43
    shl-int/lit8 v2, v2, 0x3

    .line 44
    .line 45
    aget-wide v3, v0, v1

    .line 46
    .line 47
    const-wide/16 v5, 0xff

    .line 48
    .line 49
    shl-long/2addr v5, v2

    .line 50
    not-long v7, v5

    .line 51
    and-long v2, v3, v7

    .line 52
    .line 53
    or-long/2addr v2, v5

    .line 54
    aput-wide v2, v0, v1

    .line 55
    .line 56
    iget v0, p0, Landroidx/collection/h0;->d:I

    .line 57
    .line 58
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v1, p0, Landroidx/collection/h0;->e:I

    .line 63
    .line 64
    sub-int/2addr v0, v1

    .line 65
    iput v0, p0, Landroidx/collection/h0;->f:I

    .line 66
    .line 67
    new-array v0, p1, [Ljava/lang/Object;

    .line 68
    .line 69
    iput-object v0, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 70
    .line 71
    new-array p1, p1, [I

    .line 72
    .line 73
    iput-object p1, p0, Landroidx/collection/h0;->c:[I

    .line 74
    .line 75
    return-void
.end method

.method public final g(I)V
    .locals 8

    .line 1
    iget v0, p0, Landroidx/collection/h0;->e:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    iput v0, p0, Landroidx/collection/h0;->e:I

    .line 6
    .line 7
    iget-object v0, p0, Landroidx/collection/h0;->a:[J

    .line 8
    .line 9
    iget v1, p0, Landroidx/collection/h0;->d:I

    .line 10
    .line 11
    shr-int/lit8 v2, p1, 0x3

    .line 12
    .line 13
    and-int/lit8 v3, p1, 0x7

    .line 14
    .line 15
    shl-int/lit8 v3, v3, 0x3

    .line 16
    .line 17
    aget-wide v4, v0, v2

    .line 18
    .line 19
    const-wide/16 v6, 0xff

    .line 20
    .line 21
    shl-long/2addr v6, v3

    .line 22
    not-long v6, v6

    .line 23
    and-long/2addr v4, v6

    .line 24
    const-wide/16 v6, 0xfe

    .line 25
    .line 26
    shl-long/2addr v6, v3

    .line 27
    or-long v3, v4, v6

    .line 28
    .line 29
    aput-wide v3, v0, v2

    .line 30
    .line 31
    add-int/lit8 v2, p1, -0x7

    .line 32
    .line 33
    and-int/2addr v2, v1

    .line 34
    and-int/lit8 v1, v1, 0x7

    .line 35
    .line 36
    add-int/2addr v2, v1

    .line 37
    shr-int/lit8 v1, v2, 0x3

    .line 38
    .line 39
    aput-wide v3, v0, v1

    .line 40
    .line 41
    iget-object p0, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    aput-object v0, p0, p1

    .line 45
    .line 46
    return-void
.end method

.method public final h(ILjava/lang/Object;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p2}, Landroidx/collection/h0;->c(Ljava/lang/Object;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-gez v0, :cond_0

    .line 6
    .line 7
    not-int v0, v0

    .line 8
    :cond_0
    iget-object v1, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 9
    .line 10
    aput-object p2, v1, v0

    .line 11
    .line 12
    iget-object p0, p0, Landroidx/collection/h0;->c:[I

    .line 13
    .line 14
    aput p1, p0, v0

    .line 15
    .line 16
    return-void
.end method

.method public final hashCode()I
    .locals 15

    .line 1
    iget-object v0, p0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/collection/h0;->c:[I

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/collection/h0;->a:[J

    .line 6
    .line 7
    array-length v2, p0

    .line 8
    add-int/lit8 v2, v2, -0x2

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    if-ltz v2, :cond_6

    .line 12
    .line 13
    move v4, v3

    .line 14
    move v5, v4

    .line 15
    :goto_0
    aget-wide v6, p0, v4

    .line 16
    .line 17
    not-long v8, v6

    .line 18
    const/4 v10, 0x7

    .line 19
    shl-long/2addr v8, v10

    .line 20
    and-long/2addr v8, v6

    .line 21
    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr v8, v10

    .line 27
    cmp-long v8, v8, v10

    .line 28
    .line 29
    if-eqz v8, :cond_4

    .line 30
    .line 31
    sub-int v8, v4, v2

    .line 32
    .line 33
    not-int v8, v8

    .line 34
    ushr-int/lit8 v8, v8, 0x1f

    .line 35
    .line 36
    const/16 v9, 0x8

    .line 37
    .line 38
    rsub-int/lit8 v8, v8, 0x8

    .line 39
    .line 40
    move v10, v3

    .line 41
    :goto_1
    if-ge v10, v8, :cond_2

    .line 42
    .line 43
    const-wide/16 v11, 0xff

    .line 44
    .line 45
    and-long/2addr v11, v6

    .line 46
    const-wide/16 v13, 0x80

    .line 47
    .line 48
    cmp-long v11, v11, v13

    .line 49
    .line 50
    if-gez v11, :cond_1

    .line 51
    .line 52
    shl-int/lit8 v11, v4, 0x3

    .line 53
    .line 54
    add-int/2addr v11, v10

    .line 55
    aget-object v12, v0, v11

    .line 56
    .line 57
    aget v11, v1, v11

    .line 58
    .line 59
    if-eqz v12, :cond_0

    .line 60
    .line 61
    invoke-virtual {v12}, Ljava/lang/Object;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v12

    .line 65
    goto :goto_2

    .line 66
    :cond_0
    move v12, v3

    .line 67
    :goto_2
    invoke-static {v11}, Ljava/lang/Integer;->hashCode(I)I

    .line 68
    .line 69
    .line 70
    move-result v11

    .line 71
    xor-int/2addr v11, v12

    .line 72
    add-int/2addr v5, v11

    .line 73
    :cond_1
    shr-long/2addr v6, v9

    .line 74
    add-int/lit8 v10, v10, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_2
    if-ne v8, v9, :cond_3

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    return v5

    .line 81
    :cond_4
    :goto_3
    if-eq v4, v2, :cond_5

    .line 82
    .line 83
    add-int/lit8 v4, v4, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_5
    return v5

    .line 87
    :cond_6
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Landroidx/collection/h0;->e:I

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    const-string v0, "{}"

    .line 8
    .line 9
    return-object v0

    .line 10
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, "{"

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, v0, Landroidx/collection/h0;->b:[Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v3, v0, Landroidx/collection/h0;->c:[I

    .line 20
    .line 21
    iget-object v4, v0, Landroidx/collection/h0;->a:[J

    .line 22
    .line 23
    array-length v5, v4

    .line 24
    add-int/lit8 v5, v5, -0x2

    .line 25
    .line 26
    if-ltz v5, :cond_5

    .line 27
    .line 28
    const/4 v6, 0x0

    .line 29
    move v7, v6

    .line 30
    move v8, v7

    .line 31
    :goto_0
    aget-wide v9, v4, v7

    .line 32
    .line 33
    not-long v11, v9

    .line 34
    const/4 v13, 0x7

    .line 35
    shl-long/2addr v11, v13

    .line 36
    and-long/2addr v11, v9

    .line 37
    const-wide v13, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 38
    .line 39
    .line 40
    .line 41
    .line 42
    and-long/2addr v11, v13

    .line 43
    cmp-long v11, v11, v13

    .line 44
    .line 45
    if-eqz v11, :cond_4

    .line 46
    .line 47
    sub-int v11, v7, v5

    .line 48
    .line 49
    not-int v11, v11

    .line 50
    ushr-int/lit8 v11, v11, 0x1f

    .line 51
    .line 52
    const/16 v12, 0x8

    .line 53
    .line 54
    rsub-int/lit8 v11, v11, 0x8

    .line 55
    .line 56
    move v13, v6

    .line 57
    :goto_1
    if-ge v13, v11, :cond_3

    .line 58
    .line 59
    const-wide/16 v14, 0xff

    .line 60
    .line 61
    and-long/2addr v14, v9

    .line 62
    const-wide/16 v16, 0x80

    .line 63
    .line 64
    cmp-long v14, v14, v16

    .line 65
    .line 66
    if-gez v14, :cond_2

    .line 67
    .line 68
    shl-int/lit8 v14, v7, 0x3

    .line 69
    .line 70
    add-int/2addr v14, v13

    .line 71
    aget-object v15, v2, v14

    .line 72
    .line 73
    aget v14, v3, v14

    .line 74
    .line 75
    if-ne v15, v0, :cond_1

    .line 76
    .line 77
    const-string v15, "(this)"

    .line 78
    .line 79
    :cond_1
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const-string v15, "="

    .line 83
    .line 84
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 85
    .line 86
    .line 87
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    add-int/lit8 v8, v8, 0x1

    .line 91
    .line 92
    iget v14, v0, Landroidx/collection/h0;->e:I

    .line 93
    .line 94
    if-ge v8, v14, :cond_2

    .line 95
    .line 96
    const-string v14, ", "

    .line 97
    .line 98
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    :cond_2
    shr-long/2addr v9, v12

    .line 102
    add-int/lit8 v13, v13, 0x1

    .line 103
    .line 104
    goto :goto_1

    .line 105
    :cond_3
    if-ne v11, v12, :cond_5

    .line 106
    .line 107
    :cond_4
    if-eq v7, v5, :cond_5

    .line 108
    .line 109
    add-int/lit8 v7, v7, 0x1

    .line 110
    .line 111
    goto :goto_0

    .line 112
    :cond_5
    const/16 v0, 0x7d

    .line 113
    .line 114
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    const-string v1, "toString(...)"

    .line 122
    .line 123
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    return-object v0
.end method
