.class public final Landroidx/collection/b0;
.super Landroidx/collection/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public f:I


# direct methods
.method public synthetic constructor <init>()V
    .locals 1

    const/4 v0, 0x6

    .line 9
    invoke-direct {p0, v0}, Landroidx/collection/b0;-><init>(I)V

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Landroidx/collection/y0;->a:[J

    iput-object v0, p0, Landroidx/collection/p;->a:[J

    .line 3
    sget-object v0, Landroidx/collection/r;->a:[I

    .line 4
    iput-object v0, p0, Landroidx/collection/p;->b:[I

    .line 5
    sget-object v0, La1/a;->c:[Ljava/lang/Object;

    iput-object v0, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

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

    invoke-virtual {p0, p1}, Landroidx/collection/b0;->f(I)V

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
.method public final c()V
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Landroidx/collection/p;->e:I

    .line 3
    .line 4
    iget-object v1, p0, Landroidx/collection/p;->a:[J

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
    iget-object v1, p0, Landroidx/collection/p;->a:[J

    .line 19
    .line 20
    iget v2, p0, Landroidx/collection/p;->d:I

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
    iget-object v1, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 39
    .line 40
    const/4 v2, 0x0

    .line 41
    iget v3, p0, Landroidx/collection/p;->d:I

    .line 42
    .line 43
    invoke-static {v0, v3, v2, v1}, Lmx0/n;->q(IILjava/lang/Object;[Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    iget v0, p0, Landroidx/collection/p;->d:I

    .line 47
    .line 48
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget v1, p0, Landroidx/collection/p;->e:I

    .line 53
    .line 54
    sub-int/2addr v0, v1

    .line 55
    iput v0, p0, Landroidx/collection/b0;->f:I

    .line 56
    .line 57
    return-void
.end method

.method public final d(I)I
    .locals 35

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static/range {p1 .. p1}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const v2, -0x3361d2af    # -8.2930312E7f

    .line 8
    .line 9
    .line 10
    mul-int/2addr v1, v2

    .line 11
    shl-int/lit8 v3, v1, 0x10

    .line 12
    .line 13
    xor-int/2addr v1, v3

    .line 14
    ushr-int/lit8 v3, v1, 0x7

    .line 15
    .line 16
    and-int/lit8 v1, v1, 0x7f

    .line 17
    .line 18
    iget v4, v0, Landroidx/collection/p;->d:I

    .line 19
    .line 20
    and-int v5, v3, v4

    .line 21
    .line 22
    const/4 v7, 0x0

    .line 23
    :goto_0
    iget-object v8, v0, Landroidx/collection/p;->a:[J

    .line 24
    .line 25
    shr-int/lit8 v9, v5, 0x3

    .line 26
    .line 27
    and-int/lit8 v10, v5, 0x7

    .line 28
    .line 29
    shl-int/lit8 v10, v10, 0x3

    .line 30
    .line 31
    aget-wide v11, v8, v9

    .line 32
    .line 33
    ushr-long/2addr v11, v10

    .line 34
    const/4 v13, 0x1

    .line 35
    add-int/2addr v9, v13

    .line 36
    aget-wide v8, v8, v9

    .line 37
    .line 38
    rsub-int/lit8 v14, v10, 0x40

    .line 39
    .line 40
    shl-long/2addr v8, v14

    .line 41
    int-to-long v14, v10

    .line 42
    neg-long v14, v14

    .line 43
    const/16 v10, 0x3f

    .line 44
    .line 45
    shr-long/2addr v14, v10

    .line 46
    and-long/2addr v8, v14

    .line 47
    or-long/2addr v8, v11

    .line 48
    int-to-long v10, v1

    .line 49
    const-wide v14, 0x101010101010101L

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    mul-long v16, v10, v14

    .line 55
    .line 56
    move/from16 v18, v7

    .line 57
    .line 58
    const/4 v12, 0x0

    .line 59
    xor-long v6, v8, v16

    .line 60
    .line 61
    sub-long v14, v6, v14

    .line 62
    .line 63
    not-long v6, v6

    .line 64
    and-long/2addr v6, v14

    .line 65
    const-wide v14, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 66
    .line 67
    .line 68
    .line 69
    .line 70
    and-long/2addr v6, v14

    .line 71
    :goto_1
    const-wide/16 v16, 0x0

    .line 72
    .line 73
    cmp-long v19, v6, v16

    .line 74
    .line 75
    if-eqz v19, :cond_1

    .line 76
    .line 77
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 78
    .line 79
    .line 80
    move-result v16

    .line 81
    shr-int/lit8 v16, v16, 0x3

    .line 82
    .line 83
    add-int v16, v5, v16

    .line 84
    .line 85
    and-int v16, v16, v4

    .line 86
    .line 87
    move/from16 v19, v2

    .line 88
    .line 89
    iget-object v2, v0, Landroidx/collection/p;->b:[I

    .line 90
    .line 91
    aget v2, v2, v16

    .line 92
    .line 93
    move/from16 v20, v12

    .line 94
    .line 95
    move/from16 v12, p1

    .line 96
    .line 97
    if-ne v2, v12, :cond_0

    .line 98
    .line 99
    return v16

    .line 100
    :cond_0
    const-wide/16 v16, 0x1

    .line 101
    .line 102
    sub-long v16, v6, v16

    .line 103
    .line 104
    and-long v6, v6, v16

    .line 105
    .line 106
    move/from16 v2, v19

    .line 107
    .line 108
    move/from16 v12, v20

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_1
    move/from16 v19, v2

    .line 112
    .line 113
    move/from16 v20, v12

    .line 114
    .line 115
    move/from16 v12, p1

    .line 116
    .line 117
    not-long v6, v8

    .line 118
    const/4 v2, 0x6

    .line 119
    shl-long/2addr v6, v2

    .line 120
    and-long/2addr v6, v8

    .line 121
    and-long/2addr v6, v14

    .line 122
    cmp-long v2, v6, v16

    .line 123
    .line 124
    const/16 v6, 0x8

    .line 125
    .line 126
    if-eqz v2, :cond_f

    .line 127
    .line 128
    invoke-virtual {v0, v3}, Landroidx/collection/b0;->e(I)I

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    iget v2, v0, Landroidx/collection/b0;->f:I

    .line 133
    .line 134
    const-wide/16 v7, 0xff

    .line 135
    .line 136
    if-nez v2, :cond_2

    .line 137
    .line 138
    iget-object v2, v0, Landroidx/collection/p;->a:[J

    .line 139
    .line 140
    shr-int/lit8 v12, v1, 0x3

    .line 141
    .line 142
    aget-wide v16, v2, v12

    .line 143
    .line 144
    and-int/lit8 v2, v1, 0x7

    .line 145
    .line 146
    shl-int/lit8 v2, v2, 0x3

    .line 147
    .line 148
    shr-long v16, v16, v2

    .line 149
    .line 150
    and-long v16, v16, v7

    .line 151
    .line 152
    const-wide/16 v21, 0xfe

    .line 153
    .line 154
    cmp-long v2, v16, v21

    .line 155
    .line 156
    if-nez v2, :cond_3

    .line 157
    .line 158
    :cond_2
    move-wide/from16 v26, v7

    .line 159
    .line 160
    move-wide/from16 v24, v10

    .line 161
    .line 162
    move/from16 v32, v13

    .line 163
    .line 164
    const/16 p1, 0x7

    .line 165
    .line 166
    const-wide/16 v16, 0x80

    .line 167
    .line 168
    goto/16 :goto_b

    .line 169
    .line 170
    :cond_3
    iget v1, v0, Landroidx/collection/p;->d:I

    .line 171
    .line 172
    if-le v1, v6, :cond_b

    .line 173
    .line 174
    iget v2, v0, Landroidx/collection/p;->e:I

    .line 175
    .line 176
    const-wide/16 v16, 0x80

    .line 177
    .line 178
    int-to-long v4, v2

    .line 179
    const-wide/16 v23, 0x20

    .line 180
    .line 181
    mul-long v4, v4, v23

    .line 182
    .line 183
    int-to-long v1, v1

    .line 184
    const-wide/16 v23, 0x19

    .line 185
    .line 186
    mul-long v1, v1, v23

    .line 187
    .line 188
    invoke-static {v4, v5, v1, v2}, Ljava/lang/Long;->compareUnsigned(JJ)I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    if-gtz v1, :cond_a

    .line 193
    .line 194
    iget-object v1, v0, Landroidx/collection/p;->a:[J

    .line 195
    .line 196
    iget v2, v0, Landroidx/collection/p;->d:I

    .line 197
    .line 198
    iget-object v4, v0, Landroidx/collection/p;->b:[I

    .line 199
    .line 200
    iget-object v5, v0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 201
    .line 202
    add-int/lit8 v12, v2, 0x7

    .line 203
    .line 204
    shr-int/lit8 v12, v12, 0x3

    .line 205
    .line 206
    move/from16 v23, v6

    .line 207
    .line 208
    move/from16 v6, v20

    .line 209
    .line 210
    :goto_2
    if-ge v6, v12, :cond_4

    .line 211
    .line 212
    aget-wide v24, v1, v6

    .line 213
    .line 214
    move-wide/from16 v26, v7

    .line 215
    .line 216
    and-long v7, v24, v14

    .line 217
    .line 218
    move-wide/from16 v24, v10

    .line 219
    .line 220
    const/16 p1, 0x7

    .line 221
    .line 222
    not-long v9, v7

    .line 223
    ushr-long v7, v7, p1

    .line 224
    .line 225
    add-long/2addr v9, v7

    .line 226
    const-wide v7, -0x101010101010102L

    .line 227
    .line 228
    .line 229
    .line 230
    .line 231
    and-long/2addr v7, v9

    .line 232
    aput-wide v7, v1, v6

    .line 233
    .line 234
    add-int/lit8 v6, v6, 0x1

    .line 235
    .line 236
    move-wide/from16 v10, v24

    .line 237
    .line 238
    move-wide/from16 v7, v26

    .line 239
    .line 240
    goto :goto_2

    .line 241
    :cond_4
    move-wide/from16 v26, v7

    .line 242
    .line 243
    move-wide/from16 v24, v10

    .line 244
    .line 245
    const/16 p1, 0x7

    .line 246
    .line 247
    invoke-static {v1}, Lmx0/n;->A([J)I

    .line 248
    .line 249
    .line 250
    move-result v6

    .line 251
    add-int/lit8 v7, v6, -0x1

    .line 252
    .line 253
    aget-wide v8, v1, v7

    .line 254
    .line 255
    const-wide v10, 0xffffffffffffffL

    .line 256
    .line 257
    .line 258
    .line 259
    .line 260
    and-long/2addr v8, v10

    .line 261
    const-wide/high16 v14, -0x100000000000000L

    .line 262
    .line 263
    or-long/2addr v8, v14

    .line 264
    aput-wide v8, v1, v7

    .line 265
    .line 266
    aget-wide v7, v1, v20

    .line 267
    .line 268
    aput-wide v7, v1, v6

    .line 269
    .line 270
    move/from16 v6, v20

    .line 271
    .line 272
    :goto_3
    if-eq v6, v2, :cond_9

    .line 273
    .line 274
    shr-int/lit8 v7, v6, 0x3

    .line 275
    .line 276
    aget-wide v8, v1, v7

    .line 277
    .line 278
    and-int/lit8 v12, v6, 0x7

    .line 279
    .line 280
    shl-int/lit8 v12, v12, 0x3

    .line 281
    .line 282
    shr-long/2addr v8, v12

    .line 283
    and-long v8, v8, v26

    .line 284
    .line 285
    cmp-long v14, v8, v16

    .line 286
    .line 287
    if-nez v14, :cond_5

    .line 288
    .line 289
    :goto_4
    add-int/lit8 v6, v6, 0x1

    .line 290
    .line 291
    goto :goto_3

    .line 292
    :cond_5
    cmp-long v8, v8, v21

    .line 293
    .line 294
    if-eqz v8, :cond_6

    .line 295
    .line 296
    goto :goto_4

    .line 297
    :cond_6
    aget v8, v4, v6

    .line 298
    .line 299
    invoke-static {v8}, Ljava/lang/Integer;->hashCode(I)I

    .line 300
    .line 301
    .line 302
    move-result v8

    .line 303
    mul-int v8, v8, v19

    .line 304
    .line 305
    shl-int/lit8 v9, v8, 0x10

    .line 306
    .line 307
    xor-int/2addr v8, v9

    .line 308
    ushr-int/lit8 v9, v8, 0x7

    .line 309
    .line 310
    invoke-virtual {v0, v9}, Landroidx/collection/b0;->e(I)I

    .line 311
    .line 312
    .line 313
    move-result v14

    .line 314
    and-int/2addr v9, v2

    .line 315
    sub-int v15, v14, v9

    .line 316
    .line 317
    and-int/2addr v15, v2

    .line 318
    div-int/lit8 v15, v15, 0x8

    .line 319
    .line 320
    sub-int v9, v6, v9

    .line 321
    .line 322
    and-int/2addr v9, v2

    .line 323
    div-int/lit8 v9, v9, 0x8

    .line 324
    .line 325
    const-wide/high16 v28, -0x8000000000000000L

    .line 326
    .line 327
    if-ne v15, v9, :cond_7

    .line 328
    .line 329
    and-int/lit8 v8, v8, 0x7f

    .line 330
    .line 331
    int-to-long v8, v8

    .line 332
    aget-wide v14, v1, v7

    .line 333
    .line 334
    move-wide/from16 v30, v10

    .line 335
    .line 336
    shl-long v10, v26, v12

    .line 337
    .line 338
    not-long v10, v10

    .line 339
    and-long/2addr v10, v14

    .line 340
    shl-long/2addr v8, v12

    .line 341
    or-long/2addr v8, v10

    .line 342
    aput-wide v8, v1, v7

    .line 343
    .line 344
    array-length v7, v1

    .line 345
    sub-int/2addr v7, v13

    .line 346
    aget-wide v8, v1, v20

    .line 347
    .line 348
    and-long v8, v8, v30

    .line 349
    .line 350
    or-long v8, v8, v28

    .line 351
    .line 352
    aput-wide v8, v1, v7

    .line 353
    .line 354
    add-int/lit8 v6, v6, 0x1

    .line 355
    .line 356
    move-wide/from16 v10, v30

    .line 357
    .line 358
    goto :goto_3

    .line 359
    :cond_7
    move-wide/from16 v30, v10

    .line 360
    .line 361
    shr-int/lit8 v9, v14, 0x3

    .line 362
    .line 363
    aget-wide v10, v1, v9

    .line 364
    .line 365
    and-int/lit8 v15, v14, 0x7

    .line 366
    .line 367
    shl-int/lit8 v15, v15, 0x3

    .line 368
    .line 369
    shr-long v32, v10, v15

    .line 370
    .line 371
    and-long v32, v32, v26

    .line 372
    .line 373
    cmp-long v18, v32, v16

    .line 374
    .line 375
    if-nez v18, :cond_8

    .line 376
    .line 377
    and-int/lit8 v8, v8, 0x7f

    .line 378
    .line 379
    move/from16 v32, v13

    .line 380
    .line 381
    move/from16 v18, v14

    .line 382
    .line 383
    int-to-long v13, v8

    .line 384
    move-object/from16 v33, v4

    .line 385
    .line 386
    move-object/from16 v34, v5

    .line 387
    .line 388
    shl-long v4, v26, v15

    .line 389
    .line 390
    not-long v4, v4

    .line 391
    and-long/2addr v4, v10

    .line 392
    shl-long v10, v13, v15

    .line 393
    .line 394
    or-long/2addr v4, v10

    .line 395
    aput-wide v4, v1, v9

    .line 396
    .line 397
    aget-wide v4, v1, v7

    .line 398
    .line 399
    shl-long v8, v26, v12

    .line 400
    .line 401
    not-long v8, v8

    .line 402
    and-long/2addr v4, v8

    .line 403
    shl-long v8, v16, v12

    .line 404
    .line 405
    or-long/2addr v4, v8

    .line 406
    aput-wide v4, v1, v7

    .line 407
    .line 408
    aget v4, v33, v6

    .line 409
    .line 410
    aput v4, v33, v18

    .line 411
    .line 412
    aput v20, v33, v6

    .line 413
    .line 414
    aget-object v4, v34, v6

    .line 415
    .line 416
    aput-object v4, v34, v18

    .line 417
    .line 418
    const/4 v4, 0x0

    .line 419
    aput-object v4, v34, v6

    .line 420
    .line 421
    goto :goto_5

    .line 422
    :cond_8
    move-object/from16 v33, v4

    .line 423
    .line 424
    move-object/from16 v34, v5

    .line 425
    .line 426
    move/from16 v32, v13

    .line 427
    .line 428
    move/from16 v18, v14

    .line 429
    .line 430
    and-int/lit8 v4, v8, 0x7f

    .line 431
    .line 432
    int-to-long v4, v4

    .line 433
    shl-long v7, v26, v15

    .line 434
    .line 435
    not-long v7, v7

    .line 436
    and-long/2addr v7, v10

    .line 437
    shl-long/2addr v4, v15

    .line 438
    or-long/2addr v4, v7

    .line 439
    aput-wide v4, v1, v9

    .line 440
    .line 441
    aget v4, v33, v18

    .line 442
    .line 443
    aget v5, v33, v6

    .line 444
    .line 445
    aput v5, v33, v18

    .line 446
    .line 447
    aput v4, v33, v6

    .line 448
    .line 449
    aget-object v4, v34, v18

    .line 450
    .line 451
    aget-object v5, v34, v6

    .line 452
    .line 453
    aput-object v5, v34, v18

    .line 454
    .line 455
    aput-object v4, v34, v6

    .line 456
    .line 457
    add-int/lit8 v6, v6, -0x1

    .line 458
    .line 459
    :goto_5
    array-length v4, v1

    .line 460
    add-int/lit8 v4, v4, -0x1

    .line 461
    .line 462
    aget-wide v7, v1, v20

    .line 463
    .line 464
    and-long v7, v7, v30

    .line 465
    .line 466
    or-long v7, v7, v28

    .line 467
    .line 468
    aput-wide v7, v1, v4

    .line 469
    .line 470
    add-int/lit8 v6, v6, 0x1

    .line 471
    .line 472
    move-wide/from16 v10, v30

    .line 473
    .line 474
    move/from16 v13, v32

    .line 475
    .line 476
    move-object/from16 v4, v33

    .line 477
    .line 478
    move-object/from16 v5, v34

    .line 479
    .line 480
    goto/16 :goto_3

    .line 481
    .line 482
    :cond_9
    move/from16 v32, v13

    .line 483
    .line 484
    iget v1, v0, Landroidx/collection/p;->d:I

    .line 485
    .line 486
    invoke-static {v1}, Landroidx/collection/y0;->a(I)I

    .line 487
    .line 488
    .line 489
    move-result v1

    .line 490
    iget v2, v0, Landroidx/collection/p;->e:I

    .line 491
    .line 492
    sub-int/2addr v1, v2

    .line 493
    iput v1, v0, Landroidx/collection/b0;->f:I

    .line 494
    .line 495
    goto/16 :goto_a

    .line 496
    .line 497
    :cond_a
    :goto_6
    move-wide/from16 v26, v7

    .line 498
    .line 499
    move-wide/from16 v24, v10

    .line 500
    .line 501
    move/from16 v32, v13

    .line 502
    .line 503
    const/16 p1, 0x7

    .line 504
    .line 505
    goto :goto_7

    .line 506
    :cond_b
    const-wide/16 v16, 0x80

    .line 507
    .line 508
    goto :goto_6

    .line 509
    :goto_7
    iget v1, v0, Landroidx/collection/p;->d:I

    .line 510
    .line 511
    invoke-static {v1}, Landroidx/collection/y0;->b(I)I

    .line 512
    .line 513
    .line 514
    move-result v1

    .line 515
    iget-object v2, v0, Landroidx/collection/p;->a:[J

    .line 516
    .line 517
    iget-object v4, v0, Landroidx/collection/p;->b:[I

    .line 518
    .line 519
    iget-object v5, v0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 520
    .line 521
    iget v6, v0, Landroidx/collection/p;->d:I

    .line 522
    .line 523
    invoke-virtual {v0, v1}, Landroidx/collection/b0;->f(I)V

    .line 524
    .line 525
    .line 526
    iget-object v1, v0, Landroidx/collection/p;->a:[J

    .line 527
    .line 528
    iget-object v7, v0, Landroidx/collection/p;->b:[I

    .line 529
    .line 530
    iget-object v8, v0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 531
    .line 532
    iget v9, v0, Landroidx/collection/p;->d:I

    .line 533
    .line 534
    move/from16 v10, v20

    .line 535
    .line 536
    :goto_8
    if-ge v10, v6, :cond_d

    .line 537
    .line 538
    shr-int/lit8 v11, v10, 0x3

    .line 539
    .line 540
    aget-wide v11, v2, v11

    .line 541
    .line 542
    and-int/lit8 v13, v10, 0x7

    .line 543
    .line 544
    shl-int/lit8 v13, v13, 0x3

    .line 545
    .line 546
    shr-long/2addr v11, v13

    .line 547
    and-long v11, v11, v26

    .line 548
    .line 549
    cmp-long v11, v11, v16

    .line 550
    .line 551
    if-gez v11, :cond_c

    .line 552
    .line 553
    aget v11, v4, v10

    .line 554
    .line 555
    invoke-static {v11}, Ljava/lang/Integer;->hashCode(I)I

    .line 556
    .line 557
    .line 558
    move-result v12

    .line 559
    mul-int v12, v12, v19

    .line 560
    .line 561
    shl-int/lit8 v13, v12, 0x10

    .line 562
    .line 563
    xor-int/2addr v12, v13

    .line 564
    ushr-int/lit8 v13, v12, 0x7

    .line 565
    .line 566
    invoke-virtual {v0, v13}, Landroidx/collection/b0;->e(I)I

    .line 567
    .line 568
    .line 569
    move-result v13

    .line 570
    and-int/lit8 v12, v12, 0x7f

    .line 571
    .line 572
    int-to-long v14, v12

    .line 573
    shr-int/lit8 v12, v13, 0x3

    .line 574
    .line 575
    and-int/lit8 v18, v13, 0x7

    .line 576
    .line 577
    shl-int/lit8 v18, v18, 0x3

    .line 578
    .line 579
    aget-wide v21, v1, v12

    .line 580
    .line 581
    move-object/from16 v28, v1

    .line 582
    .line 583
    move-object/from16 v23, v2

    .line 584
    .line 585
    shl-long v1, v26, v18

    .line 586
    .line 587
    not-long v1, v1

    .line 588
    and-long v1, v21, v1

    .line 589
    .line 590
    shl-long v14, v14, v18

    .line 591
    .line 592
    or-long/2addr v1, v14

    .line 593
    aput-wide v1, v28, v12

    .line 594
    .line 595
    add-int/lit8 v12, v13, -0x7

    .line 596
    .line 597
    and-int/2addr v12, v9

    .line 598
    and-int/lit8 v14, v9, 0x7

    .line 599
    .line 600
    add-int/2addr v12, v14

    .line 601
    shr-int/lit8 v12, v12, 0x3

    .line 602
    .line 603
    aput-wide v1, v28, v12

    .line 604
    .line 605
    aput v11, v7, v13

    .line 606
    .line 607
    aget-object v1, v5, v10

    .line 608
    .line 609
    aput-object v1, v8, v13

    .line 610
    .line 611
    goto :goto_9

    .line 612
    :cond_c
    move-object/from16 v28, v1

    .line 613
    .line 614
    move-object/from16 v23, v2

    .line 615
    .line 616
    :goto_9
    add-int/lit8 v10, v10, 0x1

    .line 617
    .line 618
    move-object/from16 v2, v23

    .line 619
    .line 620
    move-object/from16 v1, v28

    .line 621
    .line 622
    goto :goto_8

    .line 623
    :cond_d
    :goto_a
    invoke-virtual {v0, v3}, Landroidx/collection/b0;->e(I)I

    .line 624
    .line 625
    .line 626
    move-result v1

    .line 627
    :goto_b
    iget v2, v0, Landroidx/collection/p;->e:I

    .line 628
    .line 629
    add-int/lit8 v2, v2, 0x1

    .line 630
    .line 631
    iput v2, v0, Landroidx/collection/p;->e:I

    .line 632
    .line 633
    iget v2, v0, Landroidx/collection/b0;->f:I

    .line 634
    .line 635
    iget-object v3, v0, Landroidx/collection/p;->a:[J

    .line 636
    .line 637
    shr-int/lit8 v4, v1, 0x3

    .line 638
    .line 639
    aget-wide v5, v3, v4

    .line 640
    .line 641
    and-int/lit8 v7, v1, 0x7

    .line 642
    .line 643
    shl-int/lit8 v7, v7, 0x3

    .line 644
    .line 645
    shr-long v8, v5, v7

    .line 646
    .line 647
    and-long v8, v8, v26

    .line 648
    .line 649
    cmp-long v8, v8, v16

    .line 650
    .line 651
    if-nez v8, :cond_e

    .line 652
    .line 653
    goto :goto_c

    .line 654
    :cond_e
    move/from16 v32, v20

    .line 655
    .line 656
    :goto_c
    sub-int v2, v2, v32

    .line 657
    .line 658
    iput v2, v0, Landroidx/collection/b0;->f:I

    .line 659
    .line 660
    iget v0, v0, Landroidx/collection/p;->d:I

    .line 661
    .line 662
    shl-long v8, v26, v7

    .line 663
    .line 664
    not-long v8, v8

    .line 665
    and-long/2addr v5, v8

    .line 666
    shl-long v7, v24, v7

    .line 667
    .line 668
    or-long/2addr v5, v7

    .line 669
    aput-wide v5, v3, v4

    .line 670
    .line 671
    add-int/lit8 v2, v1, -0x7

    .line 672
    .line 673
    and-int/2addr v2, v0

    .line 674
    and-int/lit8 v0, v0, 0x7

    .line 675
    .line 676
    add-int/2addr v2, v0

    .line 677
    shr-int/lit8 v0, v2, 0x3

    .line 678
    .line 679
    aput-wide v5, v3, v0

    .line 680
    .line 681
    return v1

    .line 682
    :cond_f
    move/from16 v23, v6

    .line 683
    .line 684
    add-int/lit8 v7, v18, 0x8

    .line 685
    .line 686
    add-int/2addr v5, v7

    .line 687
    and-int/2addr v5, v4

    .line 688
    move/from16 v2, v19

    .line 689
    .line 690
    goto/16 :goto_0
.end method

.method public final e(I)I
    .locals 9

    .line 1
    iget v0, p0, Landroidx/collection/p;->d:I

    .line 2
    .line 3
    and-int/2addr p1, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    iget-object v2, p0, Landroidx/collection/p;->a:[J

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
    iput p1, p0, Landroidx/collection/p;->d:I

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
    iput-object v0, p0, Landroidx/collection/p;->a:[J

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
    iget v0, p0, Landroidx/collection/p;->d:I

    .line 57
    .line 58
    invoke-static {v0}, Landroidx/collection/y0;->a(I)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget v1, p0, Landroidx/collection/p;->e:I

    .line 63
    .line 64
    sub-int/2addr v0, v1

    .line 65
    iput v0, p0, Landroidx/collection/b0;->f:I

    .line 66
    .line 67
    new-array v0, p1, [I

    .line 68
    .line 69
    iput-object v0, p0, Landroidx/collection/p;->b:[I

    .line 70
    .line 71
    new-array p1, p1, [Ljava/lang/Object;

    .line 72
    .line 73
    iput-object p1, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 74
    .line 75
    return-void
.end method

.method public final g(I)Ljava/lang/Object;
    .locals 13

    .line 1
    invoke-static {p1}, Ljava/lang/Integer;->hashCode(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const v1, -0x3361d2af    # -8.2930312E7f

    .line 6
    .line 7
    .line 8
    mul-int/2addr v0, v1

    .line 9
    shl-int/lit8 v1, v0, 0x10

    .line 10
    .line 11
    xor-int/2addr v0, v1

    .line 12
    and-int/lit8 v1, v0, 0x7f

    .line 13
    .line 14
    iget v2, p0, Landroidx/collection/p;->d:I

    .line 15
    .line 16
    ushr-int/lit8 v0, v0, 0x7

    .line 17
    .line 18
    and-int/2addr v0, v2

    .line 19
    const/4 v3, 0x0

    .line 20
    :goto_0
    iget-object v4, p0, Landroidx/collection/p;->a:[J

    .line 21
    .line 22
    shr-int/lit8 v5, v0, 0x3

    .line 23
    .line 24
    and-int/lit8 v6, v0, 0x7

    .line 25
    .line 26
    shl-int/lit8 v6, v6, 0x3

    .line 27
    .line 28
    aget-wide v7, v4, v5

    .line 29
    .line 30
    ushr-long/2addr v7, v6

    .line 31
    add-int/lit8 v5, v5, 0x1

    .line 32
    .line 33
    aget-wide v4, v4, v5

    .line 34
    .line 35
    rsub-int/lit8 v9, v6, 0x40

    .line 36
    .line 37
    shl-long/2addr v4, v9

    .line 38
    int-to-long v9, v6

    .line 39
    neg-long v9, v9

    .line 40
    const/16 v6, 0x3f

    .line 41
    .line 42
    shr-long/2addr v9, v6

    .line 43
    and-long/2addr v4, v9

    .line 44
    or-long/2addr v4, v7

    .line 45
    int-to-long v6, v1

    .line 46
    const-wide v8, 0x101010101010101L

    .line 47
    .line 48
    .line 49
    .line 50
    .line 51
    mul-long/2addr v6, v8

    .line 52
    xor-long/2addr v6, v4

    .line 53
    sub-long v8, v6, v8

    .line 54
    .line 55
    not-long v6, v6

    .line 56
    and-long/2addr v6, v8

    .line 57
    const-wide v8, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    and-long/2addr v6, v8

    .line 63
    :goto_1
    const-wide/16 v10, 0x0

    .line 64
    .line 65
    cmp-long v12, v6, v10

    .line 66
    .line 67
    if-eqz v12, :cond_1

    .line 68
    .line 69
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    shr-int/lit8 v10, v10, 0x3

    .line 74
    .line 75
    add-int/2addr v10, v0

    .line 76
    and-int/2addr v10, v2

    .line 77
    iget-object v11, p0, Landroidx/collection/p;->b:[I

    .line 78
    .line 79
    aget v11, v11, v10

    .line 80
    .line 81
    if-ne v11, p1, :cond_0

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_0
    const-wide/16 v10, 0x1

    .line 85
    .line 86
    sub-long v10, v6, v10

    .line 87
    .line 88
    and-long/2addr v6, v10

    .line 89
    goto :goto_1

    .line 90
    :cond_1
    not-long v6, v4

    .line 91
    const/4 v12, 0x6

    .line 92
    shl-long/2addr v6, v12

    .line 93
    and-long/2addr v4, v6

    .line 94
    and-long/2addr v4, v8

    .line 95
    cmp-long v4, v4, v10

    .line 96
    .line 97
    if-eqz v4, :cond_3

    .line 98
    .line 99
    const/4 v10, -0x1

    .line 100
    :goto_2
    const/4 p1, 0x0

    .line 101
    if-ltz v10, :cond_2

    .line 102
    .line 103
    iget v0, p0, Landroidx/collection/p;->e:I

    .line 104
    .line 105
    add-int/lit8 v0, v0, -0x1

    .line 106
    .line 107
    iput v0, p0, Landroidx/collection/p;->e:I

    .line 108
    .line 109
    iget-object v0, p0, Landroidx/collection/p;->a:[J

    .line 110
    .line 111
    iget v1, p0, Landroidx/collection/p;->d:I

    .line 112
    .line 113
    shr-int/lit8 v2, v10, 0x3

    .line 114
    .line 115
    and-int/lit8 v3, v10, 0x7

    .line 116
    .line 117
    shl-int/lit8 v3, v3, 0x3

    .line 118
    .line 119
    aget-wide v4, v0, v2

    .line 120
    .line 121
    const-wide/16 v6, 0xff

    .line 122
    .line 123
    shl-long/2addr v6, v3

    .line 124
    not-long v6, v6

    .line 125
    and-long/2addr v4, v6

    .line 126
    const-wide/16 v6, 0xfe

    .line 127
    .line 128
    shl-long/2addr v6, v3

    .line 129
    or-long v3, v4, v6

    .line 130
    .line 131
    aput-wide v3, v0, v2

    .line 132
    .line 133
    add-int/lit8 v2, v10, -0x7

    .line 134
    .line 135
    and-int/2addr v2, v1

    .line 136
    and-int/lit8 v1, v1, 0x7

    .line 137
    .line 138
    add-int/2addr v2, v1

    .line 139
    shr-int/lit8 v1, v2, 0x3

    .line 140
    .line 141
    aput-wide v3, v0, v1

    .line 142
    .line 143
    iget-object p0, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 144
    .line 145
    aget-object v0, p0, v10

    .line 146
    .line 147
    aput-object p1, p0, v10

    .line 148
    .line 149
    return-object v0

    .line 150
    :cond_2
    return-object p1

    .line 151
    :cond_3
    add-int/lit8 v3, v3, 0x8

    .line 152
    .line 153
    add-int/2addr v0, v3

    .line 154
    and-int/2addr v0, v2

    .line 155
    goto/16 :goto_0
.end method

.method public final h(ILjava/lang/Object;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Landroidx/collection/b0;->d(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object v1, p0, Landroidx/collection/p;->b:[I

    .line 6
    .line 7
    aput p1, v1, v0

    .line 8
    .line 9
    iget-object p0, p0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 10
    .line 11
    aput-object p2, p0, v0

    .line 12
    .line 13
    return-void
.end method
