.class public final Lip/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Map;
.implements Ljava/io/Serializable;


# static fields
.field public static final j:Lip/l;


# instance fields
.field public transient d:Lip/i;

.field public transient e:Lip/j;

.field public transient f:Lip/k;

.field public final transient g:Ljava/lang/Object;

.field public final transient h:[Ljava/lang/Object;

.field public final transient i:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lip/l;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2}, Lip/l;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lip/l;->j:Lip/l;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(ILjava/lang/Object;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lip/l;->g:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p3, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p1, p0, Lip/l;->i:I

    .line 9
    .line 10
    return-void
.end method

.method public static a(I[Ljava/lang/Object;Lbb/g0;)Lip/l;
    .locals 19

    .line 1
    move/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lip/l;->j:Lip/l;

    .line 10
    .line 11
    return-object v0

    .line 12
    :cond_0
    const/4 v3, 0x0

    .line 13
    const/4 v4, 0x0

    .line 14
    const/4 v5, 0x1

    .line 15
    if-ne v0, v5, :cond_1

    .line 16
    .line 17
    aget-object v0, v1, v4

    .line 18
    .line 19
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    aget-object v0, v1, v5

    .line 23
    .line 24
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    new-instance v0, Lip/l;

    .line 28
    .line 29
    invoke-direct {v0, v5, v3, v1}, Lip/l;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :cond_1
    array-length v6, v1

    .line 34
    shr-int/2addr v6, v5

    .line 35
    invoke-static {v0, v6}, Llp/ua;->c(II)V

    .line 36
    .line 37
    .line 38
    const/4 v6, 0x2

    .line 39
    invoke-static {v0, v6}, Ljava/lang/Math;->max(II)I

    .line 40
    .line 41
    .line 42
    move-result v7

    .line 43
    const v8, 0x2ccccccc

    .line 44
    .line 45
    .line 46
    if-ge v7, v8, :cond_2

    .line 47
    .line 48
    add-int/lit8 v8, v7, -0x1

    .line 49
    .line 50
    invoke-static {v8}, Ljava/lang/Integer;->highestOneBit(I)I

    .line 51
    .line 52
    .line 53
    move-result v8

    .line 54
    :goto_0
    add-int/2addr v8, v8

    .line 55
    int-to-double v9, v8

    .line 56
    const-wide v11, 0x3fe6666666666666L    # 0.7

    .line 57
    .line 58
    .line 59
    .line 60
    .line 61
    mul-double/2addr v9, v11

    .line 62
    int-to-double v11, v7

    .line 63
    cmpg-double v9, v9, v11

    .line 64
    .line 65
    if-gez v9, :cond_3

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    const/high16 v8, 0x40000000    # 2.0f

    .line 69
    .line 70
    if-ge v7, v8, :cond_18

    .line 71
    .line 72
    :cond_3
    if-ne v0, v5, :cond_4

    .line 73
    .line 74
    aget-object v0, v1, v4

    .line 75
    .line 76
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    aget-object v0, v1, v5

    .line 80
    .line 81
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move/from16 v16, v4

    .line 85
    .line 86
    move v0, v5

    .line 87
    move/from16 v17, v0

    .line 88
    .line 89
    :goto_1
    move/from16 v18, v6

    .line 90
    .line 91
    goto/16 :goto_c

    .line 92
    .line 93
    :cond_4
    add-int/lit8 v7, v8, -0x1

    .line 94
    .line 95
    const/16 v9, 0x80

    .line 96
    .line 97
    const/4 v10, 0x3

    .line 98
    const/4 v11, -0x1

    .line 99
    if-gt v8, v9, :cond_a

    .line 100
    .line 101
    new-array v8, v8, [B

    .line 102
    .line 103
    invoke-static {v8, v11}, Ljava/util/Arrays;->fill([BB)V

    .line 104
    .line 105
    .line 106
    move v9, v4

    .line 107
    move v11, v9

    .line 108
    :goto_2
    if-ge v9, v0, :cond_8

    .line 109
    .line 110
    add-int v12, v11, v11

    .line 111
    .line 112
    add-int v13, v9, v9

    .line 113
    .line 114
    aget-object v14, v1, v13

    .line 115
    .line 116
    invoke-static {v14}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    xor-int/2addr v13, v5

    .line 120
    aget-object v13, v1, v13

    .line 121
    .line 122
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v14}, Ljava/lang/Object;->hashCode()I

    .line 126
    .line 127
    .line 128
    move-result v15

    .line 129
    invoke-static {v15}, Llp/wa;->d(I)I

    .line 130
    .line 131
    .line 132
    move-result v15

    .line 133
    :goto_3
    and-int/2addr v15, v7

    .line 134
    move/from16 v16, v4

    .line 135
    .line 136
    aget-byte v4, v8, v15

    .line 137
    .line 138
    move/from16 v17, v5

    .line 139
    .line 140
    const/16 v5, 0xff

    .line 141
    .line 142
    and-int/2addr v4, v5

    .line 143
    if-ne v4, v5, :cond_6

    .line 144
    .line 145
    int-to-byte v4, v12

    .line 146
    aput-byte v4, v8, v15

    .line 147
    .line 148
    if-ge v11, v9, :cond_5

    .line 149
    .line 150
    aput-object v14, v1, v12

    .line 151
    .line 152
    xor-int/lit8 v4, v12, 0x1

    .line 153
    .line 154
    aput-object v13, v1, v4

    .line 155
    .line 156
    :cond_5
    add-int/lit8 v11, v11, 0x1

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_6
    aget-object v5, v1, v4

    .line 160
    .line 161
    invoke-virtual {v14, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v5

    .line 165
    if-eqz v5, :cond_7

    .line 166
    .line 167
    xor-int/lit8 v3, v4, 0x1

    .line 168
    .line 169
    new-instance v4, Lip/e;

    .line 170
    .line 171
    aget-object v5, v1, v3

    .line 172
    .line 173
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    invoke-direct {v4, v14, v13, v5}, Lip/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 177
    .line 178
    .line 179
    aput-object v13, v1, v3

    .line 180
    .line 181
    move-object v3, v4

    .line 182
    :goto_4
    add-int/lit8 v9, v9, 0x1

    .line 183
    .line 184
    move/from16 v4, v16

    .line 185
    .line 186
    move/from16 v5, v17

    .line 187
    .line 188
    goto :goto_2

    .line 189
    :cond_7
    add-int/lit8 v15, v15, 0x1

    .line 190
    .line 191
    move/from16 v4, v16

    .line 192
    .line 193
    move/from16 v5, v17

    .line 194
    .line 195
    goto :goto_3

    .line 196
    :cond_8
    move/from16 v16, v4

    .line 197
    .line 198
    move/from16 v17, v5

    .line 199
    .line 200
    if-ne v11, v0, :cond_9

    .line 201
    .line 202
    move/from16 v18, v6

    .line 203
    .line 204
    move-object v3, v8

    .line 205
    goto/16 :goto_c

    .line 206
    .line 207
    :cond_9
    new-array v4, v10, [Ljava/lang/Object;

    .line 208
    .line 209
    aput-object v8, v4, v16

    .line 210
    .line 211
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 212
    .line 213
    .line 214
    move-result-object v5

    .line 215
    aput-object v5, v4, v17

    .line 216
    .line 217
    aput-object v3, v4, v6

    .line 218
    .line 219
    :goto_5
    move-object v3, v4

    .line 220
    goto/16 :goto_1

    .line 221
    .line 222
    :cond_a
    move/from16 v16, v4

    .line 223
    .line 224
    move/from16 v17, v5

    .line 225
    .line 226
    const v4, 0x8000

    .line 227
    .line 228
    .line 229
    if-gt v8, v4, :cond_10

    .line 230
    .line 231
    new-array v4, v8, [S

    .line 232
    .line 233
    invoke-static {v4, v11}, Ljava/util/Arrays;->fill([SS)V

    .line 234
    .line 235
    .line 236
    move/from16 v5, v16

    .line 237
    .line 238
    move v8, v5

    .line 239
    :goto_6
    if-ge v5, v0, :cond_e

    .line 240
    .line 241
    add-int v9, v8, v8

    .line 242
    .line 243
    add-int v11, v5, v5

    .line 244
    .line 245
    aget-object v12, v1, v11

    .line 246
    .line 247
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    xor-int/lit8 v11, v11, 0x1

    .line 251
    .line 252
    aget-object v11, v1, v11

    .line 253
    .line 254
    invoke-static {v11}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    invoke-virtual {v12}, Ljava/lang/Object;->hashCode()I

    .line 258
    .line 259
    .line 260
    move-result v13

    .line 261
    invoke-static {v13}, Llp/wa;->d(I)I

    .line 262
    .line 263
    .line 264
    move-result v13

    .line 265
    :goto_7
    and-int/2addr v13, v7

    .line 266
    aget-short v14, v4, v13

    .line 267
    .line 268
    int-to-char v14, v14

    .line 269
    const v15, 0xffff

    .line 270
    .line 271
    .line 272
    if-ne v14, v15, :cond_c

    .line 273
    .line 274
    int-to-short v14, v9

    .line 275
    aput-short v14, v4, v13

    .line 276
    .line 277
    if-ge v8, v5, :cond_b

    .line 278
    .line 279
    aput-object v12, v1, v9

    .line 280
    .line 281
    xor-int/lit8 v9, v9, 0x1

    .line 282
    .line 283
    aput-object v11, v1, v9

    .line 284
    .line 285
    :cond_b
    add-int/lit8 v8, v8, 0x1

    .line 286
    .line 287
    goto :goto_8

    .line 288
    :cond_c
    aget-object v15, v1, v14

    .line 289
    .line 290
    invoke-virtual {v12, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    move-result v15

    .line 294
    if-eqz v15, :cond_d

    .line 295
    .line 296
    xor-int/lit8 v3, v14, 0x1

    .line 297
    .line 298
    new-instance v9, Lip/e;

    .line 299
    .line 300
    aget-object v13, v1, v3

    .line 301
    .line 302
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    invoke-direct {v9, v12, v11, v13}, Lip/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 306
    .line 307
    .line 308
    aput-object v11, v1, v3

    .line 309
    .line 310
    move-object v3, v9

    .line 311
    :goto_8
    add-int/lit8 v5, v5, 0x1

    .line 312
    .line 313
    goto :goto_6

    .line 314
    :cond_d
    add-int/lit8 v13, v13, 0x1

    .line 315
    .line 316
    goto :goto_7

    .line 317
    :cond_e
    if-ne v8, v0, :cond_f

    .line 318
    .line 319
    goto :goto_5

    .line 320
    :cond_f
    new-array v5, v10, [Ljava/lang/Object;

    .line 321
    .line 322
    aput-object v4, v5, v16

    .line 323
    .line 324
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 325
    .line 326
    .line 327
    move-result-object v4

    .line 328
    aput-object v4, v5, v17

    .line 329
    .line 330
    aput-object v3, v5, v6

    .line 331
    .line 332
    move-object v3, v5

    .line 333
    goto/16 :goto_1

    .line 334
    .line 335
    :cond_10
    new-array v4, v8, [I

    .line 336
    .line 337
    invoke-static {v4, v11}, Ljava/util/Arrays;->fill([II)V

    .line 338
    .line 339
    .line 340
    move/from16 v5, v16

    .line 341
    .line 342
    move v8, v5

    .line 343
    :goto_9
    if-ge v5, v0, :cond_14

    .line 344
    .line 345
    add-int v9, v8, v8

    .line 346
    .line 347
    add-int v12, v5, v5

    .line 348
    .line 349
    aget-object v13, v1, v12

    .line 350
    .line 351
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 352
    .line 353
    .line 354
    xor-int/lit8 v12, v12, 0x1

    .line 355
    .line 356
    aget-object v12, v1, v12

    .line 357
    .line 358
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    invoke-virtual {v13}, Ljava/lang/Object;->hashCode()I

    .line 362
    .line 363
    .line 364
    move-result v14

    .line 365
    invoke-static {v14}, Llp/wa;->d(I)I

    .line 366
    .line 367
    .line 368
    move-result v14

    .line 369
    :goto_a
    and-int/2addr v14, v7

    .line 370
    aget v15, v4, v14

    .line 371
    .line 372
    if-ne v15, v11, :cond_12

    .line 373
    .line 374
    aput v9, v4, v14

    .line 375
    .line 376
    if-ge v8, v5, :cond_11

    .line 377
    .line 378
    aput-object v13, v1, v9

    .line 379
    .line 380
    xor-int/lit8 v9, v9, 0x1

    .line 381
    .line 382
    aput-object v12, v1, v9

    .line 383
    .line 384
    :cond_11
    add-int/lit8 v8, v8, 0x1

    .line 385
    .line 386
    move/from16 v18, v6

    .line 387
    .line 388
    goto :goto_b

    .line 389
    :cond_12
    move/from16 v18, v6

    .line 390
    .line 391
    aget-object v6, v1, v15

    .line 392
    .line 393
    invoke-virtual {v13, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 394
    .line 395
    .line 396
    move-result v6

    .line 397
    if-eqz v6, :cond_13

    .line 398
    .line 399
    xor-int/lit8 v3, v15, 0x1

    .line 400
    .line 401
    new-instance v6, Lip/e;

    .line 402
    .line 403
    aget-object v9, v1, v3

    .line 404
    .line 405
    invoke-static {v9}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 406
    .line 407
    .line 408
    invoke-direct {v6, v13, v12, v9}, Lip/e;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 409
    .line 410
    .line 411
    aput-object v12, v1, v3

    .line 412
    .line 413
    move-object v3, v6

    .line 414
    :goto_b
    add-int/lit8 v5, v5, 0x1

    .line 415
    .line 416
    move/from16 v6, v18

    .line 417
    .line 418
    goto :goto_9

    .line 419
    :cond_13
    add-int/lit8 v14, v14, 0x1

    .line 420
    .line 421
    move/from16 v6, v18

    .line 422
    .line 423
    goto :goto_a

    .line 424
    :cond_14
    move/from16 v18, v6

    .line 425
    .line 426
    if-ne v8, v0, :cond_15

    .line 427
    .line 428
    move-object v3, v4

    .line 429
    goto :goto_c

    .line 430
    :cond_15
    new-array v5, v10, [Ljava/lang/Object;

    .line 431
    .line 432
    aput-object v4, v5, v16

    .line 433
    .line 434
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 435
    .line 436
    .line 437
    move-result-object v4

    .line 438
    aput-object v4, v5, v17

    .line 439
    .line 440
    aput-object v3, v5, v18

    .line 441
    .line 442
    move-object v3, v5

    .line 443
    :goto_c
    instance-of v4, v3, [Ljava/lang/Object;

    .line 444
    .line 445
    if-eqz v4, :cond_17

    .line 446
    .line 447
    check-cast v3, [Ljava/lang/Object;

    .line 448
    .line 449
    aget-object v0, v3, v18

    .line 450
    .line 451
    check-cast v0, Lip/e;

    .line 452
    .line 453
    if-eqz v2, :cond_16

    .line 454
    .line 455
    iput-object v0, v2, Lbb/g0;->g:Ljava/lang/Object;

    .line 456
    .line 457
    aget-object v0, v3, v16

    .line 458
    .line 459
    aget-object v2, v3, v17

    .line 460
    .line 461
    check-cast v2, Ljava/lang/Integer;

    .line 462
    .line 463
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 464
    .line 465
    .line 466
    move-result v2

    .line 467
    add-int v3, v2, v2

    .line 468
    .line 469
    invoke-static {v1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v1

    .line 473
    move-object v3, v0

    .line 474
    move v0, v2

    .line 475
    goto :goto_d

    .line 476
    :cond_16
    invoke-virtual {v0}, Lip/e;->a()Ljava/lang/IllegalArgumentException;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    throw v0

    .line 481
    :cond_17
    :goto_d
    new-instance v2, Lip/l;

    .line 482
    .line 483
    invoke-direct {v2, v0, v3, v1}, Lip/l;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

    .line 484
    .line 485
    .line 486
    return-object v2

    .line 487
    :cond_18
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 488
    .line 489
    const-string v1, "collection too large"

    .line 490
    .line 491
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 492
    .line 493
    .line 494
    throw v0
.end method


# virtual methods
.method public final clear()V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lip/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final containsValue(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    iget-object v0, p0, Lip/l;->f:Lip/k;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lip/k;

    .line 6
    .line 7
    iget-object v1, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    iget v3, p0, Lip/l;->i:I

    .line 11
    .line 12
    invoke-direct {v0, v1, v2, v3}, Lip/k;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lip/l;->f:Lip/k;

    .line 16
    .line 17
    :cond_0
    invoke-virtual {v0, p1}, Lip/d;->contains(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final entrySet()Ljava/util/Set;
    .locals 3

    .line 1
    iget-object v0, p0, Lip/l;->d:Lip/i;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lip/i;

    .line 6
    .line 7
    iget-object v1, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    iget v2, p0, Lip/l;->i:I

    .line 10
    .line 11
    invoke-direct {v0, p0, v1, v2}, Lip/i;-><init>(Lip/l;[Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lip/l;->d:Lip/i;

    .line 15
    .line 16
    :cond_0
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    instance-of v0, p1, Ljava/util/Map;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_1
    check-cast p1, Ljava/util/Map;

    .line 12
    .line 13
    invoke-virtual {p0}, Lip/l;->entrySet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_1

    .line 3
    .line 4
    :cond_0
    :goto_0
    move-object p0, v0

    .line 5
    goto/16 :goto_4

    .line 6
    .line 7
    :cond_1
    const/4 v1, 0x1

    .line 8
    iget v2, p0, Lip/l;->i:I

    .line 9
    .line 10
    iget-object v3, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 11
    .line 12
    if-ne v2, v1, :cond_2

    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    aget-object p0, v3, p0

    .line 16
    .line 17
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    aget-object p0, v3, v1

    .line 27
    .line 28
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    goto/16 :goto_4

    .line 32
    .line 33
    :cond_2
    iget-object p0, p0, Lip/l;->g:Ljava/lang/Object;

    .line 34
    .line 35
    if-nez p0, :cond_3

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_3
    instance-of v2, p0, [B

    .line 39
    .line 40
    const/4 v4, -0x1

    .line 41
    if-eqz v2, :cond_6

    .line 42
    .line 43
    move-object v2, p0

    .line 44
    check-cast v2, [B

    .line 45
    .line 46
    array-length p0, v2

    .line 47
    add-int/lit8 v5, p0, -0x1

    .line 48
    .line 49
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Llp/wa;->d(I)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    :goto_1
    and-int/2addr p0, v5

    .line 58
    aget-byte v4, v2, p0

    .line 59
    .line 60
    const/16 v6, 0xff

    .line 61
    .line 62
    and-int/2addr v4, v6

    .line 63
    if-ne v4, v6, :cond_4

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_4
    aget-object v6, v3, v4

    .line 67
    .line 68
    invoke-virtual {p1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v6

    .line 72
    if-eqz v6, :cond_5

    .line 73
    .line 74
    xor-int/lit8 p0, v4, 0x1

    .line 75
    .line 76
    aget-object p0, v3, p0

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_5
    add-int/lit8 p0, p0, 0x1

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_6
    instance-of v2, p0, [S

    .line 83
    .line 84
    if-eqz v2, :cond_9

    .line 85
    .line 86
    move-object v2, p0

    .line 87
    check-cast v2, [S

    .line 88
    .line 89
    array-length p0, v2

    .line 90
    add-int/lit8 v5, p0, -0x1

    .line 91
    .line 92
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    invoke-static {p0}, Llp/wa;->d(I)I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    :goto_2
    and-int/2addr p0, v5

    .line 101
    aget-short v4, v2, p0

    .line 102
    .line 103
    int-to-char v4, v4

    .line 104
    const v6, 0xffff

    .line 105
    .line 106
    .line 107
    if-ne v4, v6, :cond_7

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_7
    aget-object v6, v3, v4

    .line 111
    .line 112
    invoke-virtual {p1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v6

    .line 116
    if-eqz v6, :cond_8

    .line 117
    .line 118
    xor-int/lit8 p0, v4, 0x1

    .line 119
    .line 120
    aget-object p0, v3, p0

    .line 121
    .line 122
    goto :goto_4

    .line 123
    :cond_8
    add-int/lit8 p0, p0, 0x1

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_9
    check-cast p0, [I

    .line 127
    .line 128
    array-length v2, p0

    .line 129
    add-int/2addr v2, v4

    .line 130
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    invoke-static {v5}, Llp/wa;->d(I)I

    .line 135
    .line 136
    .line 137
    move-result v5

    .line 138
    :goto_3
    and-int/2addr v5, v2

    .line 139
    aget v6, p0, v5

    .line 140
    .line 141
    if-ne v6, v4, :cond_a

    .line 142
    .line 143
    goto/16 :goto_0

    .line 144
    .line 145
    :cond_a
    aget-object v7, v3, v6

    .line 146
    .line 147
    invoke-virtual {p1, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v7

    .line 151
    if-eqz v7, :cond_c

    .line 152
    .line 153
    xor-int/lit8 p0, v6, 0x1

    .line 154
    .line 155
    aget-object p0, v3, p0

    .line 156
    .line 157
    :goto_4
    if-nez p0, :cond_b

    .line 158
    .line 159
    return-object v0

    .line 160
    :cond_b
    return-object p0

    .line 161
    :cond_c
    add-int/lit8 v5, v5, 0x1

    .line 162
    .line 163
    goto :goto_3
.end method

.method public final getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lip/l;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    return-object p2
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lip/l;->d:Lip/i;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lip/i;

    .line 6
    .line 7
    iget-object v1, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    iget v2, p0, Lip/l;->i:I

    .line 10
    .line 11
    invoke-direct {v0, p0, v1, v2}, Lip/i;-><init>(Lip/l;[Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lip/l;->d:Lip/i;

    .line 15
    .line 16
    :cond_0
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const/4 v0, 0x0

    .line 21
    move v1, v0

    .line 22
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_2

    .line 27
    .line 28
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v2, v0

    .line 40
    :goto_1
    add-int/2addr v1, v2

    .line 41
    goto :goto_0

    .line 42
    :cond_2
    return v1
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lip/l;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final keySet()Ljava/util/Set;
    .locals 4

    .line 1
    iget-object v0, p0, Lip/l;->e:Lip/j;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lip/k;

    .line 6
    .line 7
    iget-object v1, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    iget v3, p0, Lip/l;->i:I

    .line 11
    .line 12
    invoke-direct {v0, v1, v2, v3}, Lip/k;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lip/j;

    .line 16
    .line 17
    invoke-direct {v1, p0, v0}, Lip/j;-><init>(Lip/l;Lip/k;)V

    .line 18
    .line 19
    .line 20
    iput-object v1, p0, Lip/l;->e:Lip/j;

    .line 21
    .line 22
    return-object v1

    .line 23
    :cond_0
    return-object v0
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final putAll(Ljava/util/Map;)V
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 4
    .line 5
    .line 6
    throw p0
.end method

.method public final size()I
    .locals 0

    .line 1
    iget p0, p0, Lip/l;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget v0, p0, Lip/l;->i:I

    .line 2
    .line 3
    if-ltz v0, :cond_2

    .line 4
    .line 5
    int-to-long v0, v0

    .line 6
    const-wide/16 v2, 0x8

    .line 7
    .line 8
    mul-long/2addr v0, v2

    .line 9
    new-instance v2, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-wide/32 v3, 0x40000000

    .line 12
    .line 13
    .line 14
    invoke-static {v0, v1, v3, v4}, Ljava/lang/Math;->min(JJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    long-to-int v0, v0

    .line 19
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 20
    .line 21
    .line 22
    const/16 v0, 0x7b

    .line 23
    .line 24
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lip/l;->entrySet()Ljava/util/Set;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lip/i;

    .line 32
    .line 33
    invoke-virtual {p0}, Lip/i;->iterator()Ljava/util/Iterator;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const/4 v0, 0x1

    .line 38
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_1

    .line 43
    .line 44
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Ljava/util/Map$Entry;

    .line 49
    .line 50
    if-nez v0, :cond_0

    .line 51
    .line 52
    const-string v0, ", "

    .line 53
    .line 54
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    :cond_0
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const/16 v0, 0x3d

    .line 65
    .line 66
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const/4 v0, 0x0

    .line 77
    goto :goto_0

    .line 78
    :cond_1
    const/16 p0, 0x7d

    .line 79
    .line 80
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 89
    .line 90
    const-string v1, "size cannot be negative but was: "

    .line 91
    .line 92
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0
.end method

.method public final values()Ljava/util/Collection;
    .locals 4

    .line 1
    iget-object v0, p0, Lip/l;->f:Lip/k;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lip/k;

    .line 6
    .line 7
    iget-object v1, p0, Lip/l;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    const/4 v2, 0x1

    .line 10
    iget v3, p0, Lip/l;->i:I

    .line 11
    .line 12
    invoke-direct {v0, v1, v2, v3}, Lip/k;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lip/l;->f:Lip/k;

    .line 16
    .line 17
    :cond_0
    return-object v0
.end method
