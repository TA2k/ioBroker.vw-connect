.class public final Lhr/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Map;
.implements Ljava/io/Serializable;


# static fields
.field public static final j:Lhr/c1;


# instance fields
.field public transient d:Lhr/z0;

.field public transient e:Lhr/a1;

.field public transient f:Lhr/b1;

.field public final transient g:Ljava/lang/Object;

.field public final transient h:[Ljava/lang/Object;

.field public final transient i:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lhr/c1;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2}, Lhr/c1;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lhr/c1;->j:Lhr/c1;

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
    iput-object p2, p0, Lhr/c1;->g:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p3, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 7
    .line 8
    iput p1, p0, Lhr/c1;->i:I

    .line 9
    .line 10
    return-void
.end method

.method public static a(I[Ljava/lang/Object;Lbb/g0;)Lhr/c1;
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
    sget-object v0, Lhr/c1;->j:Lhr/c1;

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
    new-instance v0, Lhr/c1;

    .line 28
    .line 29
    invoke-direct {v0, v5, v3, v1}, Lhr/c1;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

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
    invoke-static {v0, v6}, Lkp/i9;->f(II)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0}, Lhr/k0;->n(I)I

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    const/4 v7, 0x2

    .line 43
    if-ne v0, v5, :cond_2

    .line 44
    .line 45
    aget-object v6, v1, v4

    .line 46
    .line 47
    invoke-static {v6}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    aget-object v6, v1, v5

    .line 51
    .line 52
    invoke-static {v6}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move/from16 v16, v4

    .line 56
    .line 57
    move/from16 v17, v5

    .line 58
    .line 59
    :goto_0
    move/from16 v18, v7

    .line 60
    .line 61
    goto/16 :goto_b

    .line 62
    .line 63
    :cond_2
    add-int/lit8 v8, v6, -0x1

    .line 64
    .line 65
    const/16 v9, 0x80

    .line 66
    .line 67
    const/4 v10, 0x3

    .line 68
    const/4 v11, -0x1

    .line 69
    if-gt v6, v9, :cond_8

    .line 70
    .line 71
    new-array v6, v6, [B

    .line 72
    .line 73
    invoke-static {v6, v11}, Ljava/util/Arrays;->fill([BB)V

    .line 74
    .line 75
    .line 76
    move v9, v4

    .line 77
    move v11, v9

    .line 78
    :goto_1
    if-ge v9, v0, :cond_6

    .line 79
    .line 80
    mul-int/lit8 v12, v9, 0x2

    .line 81
    .line 82
    mul-int/lit8 v13, v11, 0x2

    .line 83
    .line 84
    aget-object v14, v1, v12

    .line 85
    .line 86
    invoke-static {v14}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    xor-int/2addr v12, v5

    .line 90
    aget-object v12, v1, v12

    .line 91
    .line 92
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v14}, Ljava/lang/Object;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v15

    .line 99
    invoke-static {v15}, Lhr/q;->o(I)I

    .line 100
    .line 101
    .line 102
    move-result v15

    .line 103
    :goto_2
    and-int/2addr v15, v8

    .line 104
    move/from16 v16, v4

    .line 105
    .line 106
    aget-byte v4, v6, v15

    .line 107
    .line 108
    move/from16 v17, v5

    .line 109
    .line 110
    const/16 v5, 0xff

    .line 111
    .line 112
    and-int/2addr v4, v5

    .line 113
    if-ne v4, v5, :cond_4

    .line 114
    .line 115
    int-to-byte v4, v13

    .line 116
    aput-byte v4, v6, v15

    .line 117
    .line 118
    if-ge v11, v9, :cond_3

    .line 119
    .line 120
    aput-object v14, v1, v13

    .line 121
    .line 122
    xor-int/lit8 v4, v13, 0x1

    .line 123
    .line 124
    aput-object v12, v1, v4

    .line 125
    .line 126
    :cond_3
    add-int/lit8 v11, v11, 0x1

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_4
    aget-object v5, v1, v4

    .line 130
    .line 131
    invoke-virtual {v14, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v5

    .line 135
    if-eqz v5, :cond_5

    .line 136
    .line 137
    new-instance v3, Lhr/i0;

    .line 138
    .line 139
    xor-int/lit8 v4, v4, 0x1

    .line 140
    .line 141
    aget-object v5, v1, v4

    .line 142
    .line 143
    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    invoke-direct {v3, v14, v12, v5}, Lhr/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    aput-object v12, v1, v4

    .line 150
    .line 151
    :goto_3
    add-int/lit8 v9, v9, 0x1

    .line 152
    .line 153
    move/from16 v4, v16

    .line 154
    .line 155
    move/from16 v5, v17

    .line 156
    .line 157
    goto :goto_1

    .line 158
    :cond_5
    add-int/lit8 v15, v15, 0x1

    .line 159
    .line 160
    move/from16 v4, v16

    .line 161
    .line 162
    move/from16 v5, v17

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_6
    move/from16 v16, v4

    .line 166
    .line 167
    move/from16 v17, v5

    .line 168
    .line 169
    if-ne v11, v0, :cond_7

    .line 170
    .line 171
    move-object v3, v6

    .line 172
    goto :goto_0

    .line 173
    :cond_7
    new-array v4, v10, [Ljava/lang/Object;

    .line 174
    .line 175
    aput-object v6, v4, v16

    .line 176
    .line 177
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 178
    .line 179
    .line 180
    move-result-object v5

    .line 181
    aput-object v5, v4, v17

    .line 182
    .line 183
    aput-object v3, v4, v7

    .line 184
    .line 185
    :goto_4
    move-object v3, v4

    .line 186
    goto :goto_0

    .line 187
    :cond_8
    move/from16 v16, v4

    .line 188
    .line 189
    move/from16 v17, v5

    .line 190
    .line 191
    const v4, 0x8000

    .line 192
    .line 193
    .line 194
    if-gt v6, v4, :cond_e

    .line 195
    .line 196
    new-array v4, v6, [S

    .line 197
    .line 198
    invoke-static {v4, v11}, Ljava/util/Arrays;->fill([SS)V

    .line 199
    .line 200
    .line 201
    move/from16 v5, v16

    .line 202
    .line 203
    move v6, v5

    .line 204
    :goto_5
    if-ge v5, v0, :cond_c

    .line 205
    .line 206
    mul-int/lit8 v9, v5, 0x2

    .line 207
    .line 208
    mul-int/lit8 v11, v6, 0x2

    .line 209
    .line 210
    aget-object v12, v1, v9

    .line 211
    .line 212
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    xor-int/lit8 v9, v9, 0x1

    .line 216
    .line 217
    aget-object v9, v1, v9

    .line 218
    .line 219
    invoke-static {v9}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v12}, Ljava/lang/Object;->hashCode()I

    .line 223
    .line 224
    .line 225
    move-result v13

    .line 226
    invoke-static {v13}, Lhr/q;->o(I)I

    .line 227
    .line 228
    .line 229
    move-result v13

    .line 230
    :goto_6
    and-int/2addr v13, v8

    .line 231
    aget-short v14, v4, v13

    .line 232
    .line 233
    const v15, 0xffff

    .line 234
    .line 235
    .line 236
    and-int/2addr v14, v15

    .line 237
    if-ne v14, v15, :cond_a

    .line 238
    .line 239
    int-to-short v14, v11

    .line 240
    aput-short v14, v4, v13

    .line 241
    .line 242
    if-ge v6, v5, :cond_9

    .line 243
    .line 244
    aput-object v12, v1, v11

    .line 245
    .line 246
    xor-int/lit8 v11, v11, 0x1

    .line 247
    .line 248
    aput-object v9, v1, v11

    .line 249
    .line 250
    :cond_9
    add-int/lit8 v6, v6, 0x1

    .line 251
    .line 252
    goto :goto_7

    .line 253
    :cond_a
    aget-object v15, v1, v14

    .line 254
    .line 255
    invoke-virtual {v12, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    move-result v15

    .line 259
    if-eqz v15, :cond_b

    .line 260
    .line 261
    new-instance v3, Lhr/i0;

    .line 262
    .line 263
    xor-int/lit8 v11, v14, 0x1

    .line 264
    .line 265
    aget-object v13, v1, v11

    .line 266
    .line 267
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    invoke-direct {v3, v12, v9, v13}, Lhr/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    aput-object v9, v1, v11

    .line 274
    .line 275
    :goto_7
    add-int/lit8 v5, v5, 0x1

    .line 276
    .line 277
    goto :goto_5

    .line 278
    :cond_b
    add-int/lit8 v13, v13, 0x1

    .line 279
    .line 280
    goto :goto_6

    .line 281
    :cond_c
    if-ne v6, v0, :cond_d

    .line 282
    .line 283
    goto :goto_4

    .line 284
    :cond_d
    new-array v5, v10, [Ljava/lang/Object;

    .line 285
    .line 286
    aput-object v4, v5, v16

    .line 287
    .line 288
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 289
    .line 290
    .line 291
    move-result-object v4

    .line 292
    aput-object v4, v5, v17

    .line 293
    .line 294
    aput-object v3, v5, v7

    .line 295
    .line 296
    move-object v3, v5

    .line 297
    goto/16 :goto_0

    .line 298
    .line 299
    :cond_e
    new-array v4, v6, [I

    .line 300
    .line 301
    invoke-static {v4, v11}, Ljava/util/Arrays;->fill([II)V

    .line 302
    .line 303
    .line 304
    move/from16 v5, v16

    .line 305
    .line 306
    move v6, v5

    .line 307
    :goto_8
    if-ge v5, v0, :cond_12

    .line 308
    .line 309
    mul-int/lit8 v9, v5, 0x2

    .line 310
    .line 311
    mul-int/lit8 v12, v6, 0x2

    .line 312
    .line 313
    aget-object v13, v1, v9

    .line 314
    .line 315
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    xor-int/lit8 v9, v9, 0x1

    .line 319
    .line 320
    aget-object v9, v1, v9

    .line 321
    .line 322
    invoke-static {v9}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    invoke-virtual {v13}, Ljava/lang/Object;->hashCode()I

    .line 326
    .line 327
    .line 328
    move-result v14

    .line 329
    invoke-static {v14}, Lhr/q;->o(I)I

    .line 330
    .line 331
    .line 332
    move-result v14

    .line 333
    :goto_9
    and-int/2addr v14, v8

    .line 334
    aget v15, v4, v14

    .line 335
    .line 336
    if-ne v15, v11, :cond_10

    .line 337
    .line 338
    aput v12, v4, v14

    .line 339
    .line 340
    if-ge v6, v5, :cond_f

    .line 341
    .line 342
    aput-object v13, v1, v12

    .line 343
    .line 344
    xor-int/lit8 v12, v12, 0x1

    .line 345
    .line 346
    aput-object v9, v1, v12

    .line 347
    .line 348
    :cond_f
    add-int/lit8 v6, v6, 0x1

    .line 349
    .line 350
    move/from16 v18, v7

    .line 351
    .line 352
    goto :goto_a

    .line 353
    :cond_10
    move/from16 v18, v7

    .line 354
    .line 355
    aget-object v7, v1, v15

    .line 356
    .line 357
    invoke-virtual {v13, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 358
    .line 359
    .line 360
    move-result v7

    .line 361
    if-eqz v7, :cond_11

    .line 362
    .line 363
    new-instance v3, Lhr/i0;

    .line 364
    .line 365
    xor-int/lit8 v7, v15, 0x1

    .line 366
    .line 367
    aget-object v12, v1, v7

    .line 368
    .line 369
    invoke-static {v12}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    invoke-direct {v3, v13, v9, v12}, Lhr/i0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    aput-object v9, v1, v7

    .line 376
    .line 377
    :goto_a
    add-int/lit8 v5, v5, 0x1

    .line 378
    .line 379
    move/from16 v7, v18

    .line 380
    .line 381
    goto :goto_8

    .line 382
    :cond_11
    add-int/lit8 v14, v14, 0x1

    .line 383
    .line 384
    move/from16 v7, v18

    .line 385
    .line 386
    goto :goto_9

    .line 387
    :cond_12
    move/from16 v18, v7

    .line 388
    .line 389
    if-ne v6, v0, :cond_13

    .line 390
    .line 391
    move-object v3, v4

    .line 392
    goto :goto_b

    .line 393
    :cond_13
    new-array v5, v10, [Ljava/lang/Object;

    .line 394
    .line 395
    aput-object v4, v5, v16

    .line 396
    .line 397
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 398
    .line 399
    .line 400
    move-result-object v4

    .line 401
    aput-object v4, v5, v17

    .line 402
    .line 403
    aput-object v3, v5, v18

    .line 404
    .line 405
    move-object v3, v5

    .line 406
    :goto_b
    instance-of v4, v3, [Ljava/lang/Object;

    .line 407
    .line 408
    if-eqz v4, :cond_15

    .line 409
    .line 410
    check-cast v3, [Ljava/lang/Object;

    .line 411
    .line 412
    aget-object v0, v3, v18

    .line 413
    .line 414
    check-cast v0, Lhr/i0;

    .line 415
    .line 416
    if-eqz v2, :cond_14

    .line 417
    .line 418
    iput-object v0, v2, Lbb/g0;->g:Ljava/lang/Object;

    .line 419
    .line 420
    aget-object v0, v3, v16

    .line 421
    .line 422
    aget-object v2, v3, v17

    .line 423
    .line 424
    check-cast v2, Ljava/lang/Integer;

    .line 425
    .line 426
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 427
    .line 428
    .line 429
    move-result v2

    .line 430
    mul-int/lit8 v3, v2, 0x2

    .line 431
    .line 432
    invoke-static {v1, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    move-object v3, v0

    .line 437
    move v0, v2

    .line 438
    goto :goto_c

    .line 439
    :cond_14
    invoke-virtual {v0}, Lhr/i0;->a()Ljava/lang/IllegalArgumentException;

    .line 440
    .line 441
    .line 442
    move-result-object v0

    .line 443
    throw v0

    .line 444
    :cond_15
    :goto_c
    new-instance v2, Lhr/c1;

    .line 445
    .line 446
    invoke-direct {v2, v0, v3, v1}, Lhr/c1;-><init>(ILjava/lang/Object;[Ljava/lang/Object;)V

    .line 447
    .line 448
    .line 449
    return-object v2
.end method


# virtual methods
.method public final b()Lhr/k0;
    .locals 3

    .line 1
    iget-object v0, p0, Lhr/c1;->d:Lhr/z0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/z0;

    .line 6
    .line 7
    iget-object v1, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    iget v2, p0, Lhr/c1;->i:I

    .line 10
    .line 11
    invoke-direct {v0, p0, v1, v2}, Lhr/z0;-><init>(Lhr/c1;[Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lhr/c1;->d:Lhr/z0;

    .line 15
    .line 16
    :cond_0
    return-object v0
.end method

.method public final c()Lhr/k0;
    .locals 4

    .line 1
    iget-object v0, p0, Lhr/c1;->e:Lhr/a1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/b1;

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    iget v2, p0, Lhr/c1;->i:I

    .line 9
    .line 10
    iget-object v3, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 11
    .line 12
    invoke-direct {v0, v3, v1, v2}, Lhr/b1;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lhr/a1;

    .line 16
    .line 17
    invoke-direct {v1, p0, v0}, Lhr/a1;-><init>(Lhr/c1;Lhr/b1;)V

    .line 18
    .line 19
    .line 20
    iput-object v1, p0, Lhr/c1;->e:Lhr/a1;

    .line 21
    .line 22
    return-object v1

    .line 23
    :cond_0
    return-object v0
.end method

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
    invoke-virtual {p0, p1}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget-object v0, p0, Lhr/c1;->f:Lhr/b1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/b1;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iget v2, p0, Lhr/c1;->i:I

    .line 9
    .line 10
    iget-object v3, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 11
    .line 12
    invoke-direct {v0, v3, v1, v2}, Lhr/b1;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lhr/c1;->f:Lhr/b1;

    .line 16
    .line 17
    :cond_0
    invoke-virtual {v0, p1}, Lhr/h0;->contains(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final bridge synthetic entrySet()Ljava/util/Set;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/c1;->b()Lhr/k0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lhr/q;->e(Ljava/util/Map;Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

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
    iget-object v1, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 8
    .line 9
    iget v2, p0, Lhr/c1;->i:I

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    if-ne v2, v3, :cond_2

    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    aget-object p0, v1, p0

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
    aget-object p0, v1, v3

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
    iget-object p0, p0, Lhr/c1;->g:Ljava/lang/Object;

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
    if-eqz v2, :cond_6

    .line 41
    .line 42
    move-object v2, p0

    .line 43
    check-cast v2, [B

    .line 44
    .line 45
    array-length p0, v2

    .line 46
    add-int/lit8 v4, p0, -0x1

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    invoke-static {p0}, Lhr/q;->o(I)I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    :goto_1
    and-int/2addr p0, v4

    .line 57
    aget-byte v5, v2, p0

    .line 58
    .line 59
    const/16 v6, 0xff

    .line 60
    .line 61
    and-int/2addr v5, v6

    .line 62
    if-ne v5, v6, :cond_4

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_4
    aget-object v6, v1, v5

    .line 66
    .line 67
    invoke-virtual {p1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v6

    .line 71
    if-eqz v6, :cond_5

    .line 72
    .line 73
    xor-int/lit8 p0, v5, 0x1

    .line 74
    .line 75
    aget-object p0, v1, p0

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_5
    add-int/lit8 p0, p0, 0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_6
    instance-of v2, p0, [S

    .line 82
    .line 83
    if-eqz v2, :cond_9

    .line 84
    .line 85
    move-object v2, p0

    .line 86
    check-cast v2, [S

    .line 87
    .line 88
    array-length p0, v2

    .line 89
    add-int/lit8 v4, p0, -0x1

    .line 90
    .line 91
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result p0

    .line 95
    invoke-static {p0}, Lhr/q;->o(I)I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    :goto_2
    and-int/2addr p0, v4

    .line 100
    aget-short v5, v2, p0

    .line 101
    .line 102
    const v6, 0xffff

    .line 103
    .line 104
    .line 105
    and-int/2addr v5, v6

    .line 106
    if-ne v5, v6, :cond_7

    .line 107
    .line 108
    goto :goto_0

    .line 109
    :cond_7
    aget-object v6, v1, v5

    .line 110
    .line 111
    invoke-virtual {p1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 112
    .line 113
    .line 114
    move-result v6

    .line 115
    if-eqz v6, :cond_8

    .line 116
    .line 117
    xor-int/lit8 p0, v5, 0x1

    .line 118
    .line 119
    aget-object p0, v1, p0

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_8
    add-int/lit8 p0, p0, 0x1

    .line 123
    .line 124
    goto :goto_2

    .line 125
    :cond_9
    check-cast p0, [I

    .line 126
    .line 127
    array-length v2, p0

    .line 128
    sub-int/2addr v2, v3

    .line 129
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    invoke-static {v4}, Lhr/q;->o(I)I

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    :goto_3
    and-int/2addr v4, v2

    .line 138
    aget v5, p0, v4

    .line 139
    .line 140
    const/4 v6, -0x1

    .line 141
    if-ne v5, v6, :cond_a

    .line 142
    .line 143
    goto/16 :goto_0

    .line 144
    .line 145
    :cond_a
    aget-object v6, v1, v5

    .line 146
    .line 147
    invoke-virtual {p1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v6

    .line 151
    if-eqz v6, :cond_c

    .line 152
    .line 153
    xor-int/lit8 p0, v5, 0x1

    .line 154
    .line 155
    aget-object p0, v1, p0

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
    add-int/lit8 v4, v4, 0x1

    .line 162
    .line 163
    goto :goto_3
.end method

.method public final getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lhr/c1;->get(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/c1;->b()Lhr/k0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Lhr/q;->i(Ljava/util/Set;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/c1;->size()I

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

.method public final bridge synthetic keySet()Ljava/util/Set;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lhr/c1;->c()Lhr/k0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
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
    iget p0, p0, Lhr/c1;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "size"

    .line 2
    .line 3
    iget v1, p0, Lhr/c1;->i:I

    .line 4
    .line 5
    invoke-static {v1, v0}, Lhr/q;->c(ILjava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    int-to-long v1, v1

    .line 11
    const-wide/16 v3, 0x8

    .line 12
    .line 13
    mul-long/2addr v1, v3

    .line 14
    const-wide/32 v3, 0x40000000

    .line 15
    .line 16
    .line 17
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->min(JJ)J

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    long-to-int v1, v1

    .line 22
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 23
    .line 24
    .line 25
    const/16 v1, 0x7b

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0}, Lhr/c1;->b()Lhr/k0;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lhr/z0;

    .line 35
    .line 36
    invoke-virtual {p0}, Lhr/z0;->s()Lhr/l1;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const/4 v1, 0x1

    .line 41
    :goto_0
    move-object v2, p0

    .line 42
    check-cast v2, Lhr/f0;

    .line 43
    .line 44
    invoke-virtual {v2}, Lhr/f0;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_1

    .line 49
    .line 50
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Ljava/util/Map$Entry;

    .line 55
    .line 56
    if-nez v1, :cond_0

    .line 57
    .line 58
    const-string v1, ", "

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    :cond_0
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const/16 v1, 0x3d

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    const/4 v1, 0x0

    .line 83
    goto :goto_0

    .line 84
    :cond_1
    const/16 p0, 0x7d

    .line 85
    .line 86
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    return-object p0
.end method

.method public final values()Ljava/util/Collection;
    .locals 4

    .line 1
    iget-object v0, p0, Lhr/c1;->f:Lhr/b1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lhr/b1;

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    iget v2, p0, Lhr/c1;->i:I

    .line 9
    .line 10
    iget-object v3, p0, Lhr/c1;->h:[Ljava/lang/Object;

    .line 11
    .line 12
    invoke-direct {v0, v3, v1, v2}, Lhr/b1;-><init>([Ljava/lang/Object;II)V

    .line 13
    .line 14
    .line 15
    iput-object v0, p0, Lhr/c1;->f:Lhr/b1;

    .line 16
    .line 17
    :cond_0
    return-object v0
.end method
