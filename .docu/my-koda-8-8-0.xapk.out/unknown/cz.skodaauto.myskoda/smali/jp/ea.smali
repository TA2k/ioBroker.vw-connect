.class public abstract Ljp/ea;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lw7/p;)Ljava/util/ArrayList;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lw7/p;->w()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    :cond_0
    :goto_0
    move-object/from16 v20, v2

    .line 11
    .line 12
    goto/16 :goto_d

    .line 13
    .line 14
    :cond_1
    const/4 v1, 0x7

    .line 15
    invoke-virtual {v0, v1}, Lw7/p;->J(I)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const v4, 0x64666c38

    .line 23
    .line 24
    .line 25
    const/4 v5, 0x1

    .line 26
    if-ne v3, v4, :cond_3

    .line 27
    .line 28
    new-instance v3, Lw7/p;

    .line 29
    .line 30
    invoke-direct {v3}, Lw7/p;-><init>()V

    .line 31
    .line 32
    .line 33
    new-instance v4, Ljava/util/zip/Inflater;

    .line 34
    .line 35
    invoke-direct {v4, v5}, Ljava/util/zip/Inflater;-><init>(Z)V

    .line 36
    .line 37
    .line 38
    :try_start_0
    invoke-static {v0, v3, v4}, Lw7/w;->y(Lw7/p;Lw7/p;Ljava/util/zip/Inflater;)Z

    .line 39
    .line 40
    .line 41
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 42
    if-nez v0, :cond_2

    .line 43
    .line 44
    invoke-virtual {v4}, Ljava/util/zip/Inflater;->end()V

    .line 45
    .line 46
    .line 47
    return-object v2

    .line 48
    :cond_2
    invoke-virtual {v4}, Ljava/util/zip/Inflater;->end()V

    .line 49
    .line 50
    .line 51
    move-object v0, v3

    .line 52
    goto :goto_1

    .line 53
    :catchall_0
    move-exception v0

    .line 54
    invoke-virtual {v4}, Ljava/util/zip/Inflater;->end()V

    .line 55
    .line 56
    .line 57
    throw v0

    .line 58
    :cond_3
    const v4, 0x72617720

    .line 59
    .line 60
    .line 61
    if-eq v3, v4, :cond_4

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_4
    :goto_1
    new-instance v3, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 67
    .line 68
    .line 69
    iget v4, v0, Lw7/p;->b:I

    .line 70
    .line 71
    iget v6, v0, Lw7/p;->c:I

    .line 72
    .line 73
    :goto_2
    if-ge v4, v6, :cond_14

    .line 74
    .line 75
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 76
    .line 77
    .line 78
    move-result v7

    .line 79
    add-int/2addr v7, v4

    .line 80
    if-le v7, v4, :cond_0

    .line 81
    .line 82
    if-le v7, v6, :cond_5

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_5
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    const v8, 0x6d657368

    .line 90
    .line 91
    .line 92
    if-ne v4, v8, :cond_13

    .line 93
    .line 94
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    const/16 v8, 0x2710

    .line 99
    .line 100
    if-le v4, v8, :cond_6

    .line 101
    .line 102
    :goto_3
    move/from16 v16, v1

    .line 103
    .line 104
    move-object v1, v2

    .line 105
    move-object/from16 v20, v1

    .line 106
    .line 107
    move/from16 v17, v5

    .line 108
    .line 109
    move/from16 v24, v6

    .line 110
    .line 111
    goto/16 :goto_b

    .line 112
    .line 113
    :cond_6
    new-array v8, v4, [F

    .line 114
    .line 115
    const/4 v10, 0x0

    .line 116
    :goto_4
    if-ge v10, v4, :cond_7

    .line 117
    .line 118
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 119
    .line 120
    .line 121
    move-result v11

    .line 122
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 123
    .line 124
    .line 125
    move-result v11

    .line 126
    aput v11, v8, v10

    .line 127
    .line 128
    add-int/lit8 v10, v10, 0x1

    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_7
    invoke-virtual {v0}, Lw7/p;->j()I

    .line 132
    .line 133
    .line 134
    move-result v10

    .line 135
    const/16 v11, 0x7d00

    .line 136
    .line 137
    if-le v10, v11, :cond_8

    .line 138
    .line 139
    goto :goto_3

    .line 140
    :cond_8
    const-wide/high16 v11, 0x4000000000000000L    # 2.0

    .line 141
    .line 142
    invoke-static {v11, v12}, Ljava/lang/Math;->log(D)D

    .line 143
    .line 144
    .line 145
    move-result-wide v13

    .line 146
    move/from16 v16, v1

    .line 147
    .line 148
    move-object v15, v2

    .line 149
    int-to-double v1, v4

    .line 150
    mul-double/2addr v1, v11

    .line 151
    invoke-static {v1, v2}, Ljava/lang/Math;->log(D)D

    .line 152
    .line 153
    .line 154
    move-result-wide v1

    .line 155
    div-double/2addr v1, v13

    .line 156
    invoke-static {v1, v2}, Ljava/lang/Math;->ceil(D)D

    .line 157
    .line 158
    .line 159
    move-result-wide v1

    .line 160
    double-to-int v1, v1

    .line 161
    new-instance v2, Lm9/f;

    .line 162
    .line 163
    move/from16 v17, v5

    .line 164
    .line 165
    iget-object v5, v0, Lw7/p;->a:[B

    .line 166
    .line 167
    array-length v9, v5

    .line 168
    invoke-direct {v2, v9, v5}, Lm9/f;-><init>(I[B)V

    .line 169
    .line 170
    .line 171
    iget v5, v0, Lw7/p;->b:I

    .line 172
    .line 173
    const/16 v9, 0x8

    .line 174
    .line 175
    mul-int/2addr v5, v9

    .line 176
    invoke-virtual {v2, v5}, Lm9/f;->q(I)V

    .line 177
    .line 178
    .line 179
    mul-int/lit8 v5, v10, 0x5

    .line 180
    .line 181
    new-array v5, v5, [F

    .line 182
    .line 183
    move-wide/from16 v18, v11

    .line 184
    .line 185
    const/4 v11, 0x5

    .line 186
    new-array v12, v11, [I

    .line 187
    .line 188
    move-object/from16 v20, v15

    .line 189
    .line 190
    const/4 v15, 0x0

    .line 191
    const/16 v21, 0x0

    .line 192
    .line 193
    :goto_5
    if-ge v15, v10, :cond_d

    .line 194
    .line 195
    const/4 v9, 0x0

    .line 196
    :goto_6
    if-ge v9, v11, :cond_c

    .line 197
    .line 198
    aget v22, v12, v9

    .line 199
    .line 200
    invoke-virtual {v2, v1}, Lm9/f;->i(I)I

    .line 201
    .line 202
    .line 203
    move-result v23

    .line 204
    shr-int/lit8 v24, v23, 0x1

    .line 205
    .line 206
    and-int/lit8 v11, v23, 0x1

    .line 207
    .line 208
    neg-int v11, v11

    .line 209
    xor-int v11, v24, v11

    .line 210
    .line 211
    add-int v11, v11, v22

    .line 212
    .line 213
    if-ge v11, v4, :cond_a

    .line 214
    .line 215
    if-gez v11, :cond_9

    .line 216
    .line 217
    goto :goto_7

    .line 218
    :cond_9
    add-int/lit8 v22, v21, 0x1

    .line 219
    .line 220
    aget v23, v8, v11

    .line 221
    .line 222
    aput v23, v5, v21

    .line 223
    .line 224
    aput v11, v12, v9

    .line 225
    .line 226
    add-int/lit8 v9, v9, 0x1

    .line 227
    .line 228
    move/from16 v21, v22

    .line 229
    .line 230
    const/4 v11, 0x5

    .line 231
    goto :goto_6

    .line 232
    :cond_a
    :goto_7
    move/from16 v24, v6

    .line 233
    .line 234
    :cond_b
    :goto_8
    move-object/from16 v1, v20

    .line 235
    .line 236
    goto/16 :goto_b

    .line 237
    .line 238
    :cond_c
    add-int/lit8 v15, v15, 0x1

    .line 239
    .line 240
    const/16 v9, 0x8

    .line 241
    .line 242
    const/4 v11, 0x5

    .line 243
    goto :goto_5

    .line 244
    :cond_d
    invoke-virtual {v2}, Lm9/f;->g()I

    .line 245
    .line 246
    .line 247
    move-result v1

    .line 248
    add-int/lit8 v1, v1, 0x7

    .line 249
    .line 250
    and-int/lit8 v1, v1, -0x8

    .line 251
    .line 252
    invoke-virtual {v2, v1}, Lm9/f;->q(I)V

    .line 253
    .line 254
    .line 255
    const/16 v1, 0x20

    .line 256
    .line 257
    invoke-virtual {v2, v1}, Lm9/f;->i(I)I

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    new-array v8, v4, [Li4/c;

    .line 262
    .line 263
    const/4 v9, 0x0

    .line 264
    :goto_9
    if-ge v9, v4, :cond_11

    .line 265
    .line 266
    const/16 v11, 0x8

    .line 267
    .line 268
    invoke-virtual {v2, v11}, Lm9/f;->i(I)I

    .line 269
    .line 270
    .line 271
    move-result v12

    .line 272
    invoke-virtual {v2, v11}, Lm9/f;->i(I)I

    .line 273
    .line 274
    .line 275
    move-result v15

    .line 276
    invoke-virtual {v2, v1}, Lm9/f;->i(I)I

    .line 277
    .line 278
    .line 279
    move-result v11

    .line 280
    const v1, 0x1f400

    .line 281
    .line 282
    .line 283
    if-le v11, v1, :cond_e

    .line 284
    .line 285
    goto :goto_7

    .line 286
    :cond_e
    move/from16 v22, v4

    .line 287
    .line 288
    move-object v1, v5

    .line 289
    int-to-double v4, v10

    .line 290
    mul-double v4, v4, v18

    .line 291
    .line 292
    invoke-static {v4, v5}, Ljava/lang/Math;->log(D)D

    .line 293
    .line 294
    .line 295
    move-result-wide v4

    .line 296
    div-double/2addr v4, v13

    .line 297
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 298
    .line 299
    .line 300
    move-result-wide v4

    .line 301
    double-to-int v4, v4

    .line 302
    mul-int/lit8 v5, v11, 0x3

    .line 303
    .line 304
    new-array v5, v5, [F

    .line 305
    .line 306
    move-object/from16 v23, v1

    .line 307
    .line 308
    mul-int/lit8 v1, v11, 0x2

    .line 309
    .line 310
    new-array v1, v1, [F

    .line 311
    .line 312
    move/from16 v24, v6

    .line 313
    .line 314
    const/4 v6, 0x0

    .line 315
    const/16 v25, 0x0

    .line 316
    .line 317
    :goto_a
    if-ge v6, v11, :cond_10

    .line 318
    .line 319
    invoke-virtual {v2, v4}, Lm9/f;->i(I)I

    .line 320
    .line 321
    .line 322
    move-result v26

    .line 323
    shr-int/lit8 v27, v26, 0x1

    .line 324
    .line 325
    move-object/from16 v28, v2

    .line 326
    .line 327
    and-int/lit8 v2, v26, 0x1

    .line 328
    .line 329
    neg-int v2, v2

    .line 330
    xor-int v2, v27, v2

    .line 331
    .line 332
    add-int v2, v2, v25

    .line 333
    .line 334
    if-ltz v2, :cond_b

    .line 335
    .line 336
    if-lt v2, v10, :cond_f

    .line 337
    .line 338
    goto :goto_8

    .line 339
    :cond_f
    mul-int/lit8 v25, v6, 0x3

    .line 340
    .line 341
    mul-int/lit8 v26, v2, 0x5

    .line 342
    .line 343
    aget v27, v23, v26

    .line 344
    .line 345
    aput v27, v5, v25

    .line 346
    .line 347
    add-int/lit8 v27, v25, 0x1

    .line 348
    .line 349
    add-int/lit8 v29, v26, 0x1

    .line 350
    .line 351
    aget v29, v23, v29

    .line 352
    .line 353
    aput v29, v5, v27

    .line 354
    .line 355
    add-int/lit8 v25, v25, 0x2

    .line 356
    .line 357
    add-int/lit8 v27, v26, 0x2

    .line 358
    .line 359
    aget v27, v23, v27

    .line 360
    .line 361
    aput v27, v5, v25

    .line 362
    .line 363
    mul-int/lit8 v25, v6, 0x2

    .line 364
    .line 365
    add-int/lit8 v27, v26, 0x3

    .line 366
    .line 367
    aget v27, v23, v27

    .line 368
    .line 369
    aput v27, v1, v25

    .line 370
    .line 371
    add-int/lit8 v25, v25, 0x1

    .line 372
    .line 373
    add-int/lit8 v26, v26, 0x4

    .line 374
    .line 375
    aget v26, v23, v26

    .line 376
    .line 377
    aput v26, v1, v25

    .line 378
    .line 379
    add-int/lit8 v6, v6, 0x1

    .line 380
    .line 381
    move/from16 v25, v2

    .line 382
    .line 383
    move-object/from16 v2, v28

    .line 384
    .line 385
    goto :goto_a

    .line 386
    :cond_10
    move-object/from16 v28, v2

    .line 387
    .line 388
    new-instance v2, Li4/c;

    .line 389
    .line 390
    invoke-direct {v2, v12, v15, v5, v1}, Li4/c;-><init>(II[F[F)V

    .line 391
    .line 392
    .line 393
    aput-object v2, v8, v9

    .line 394
    .line 395
    add-int/lit8 v9, v9, 0x1

    .line 396
    .line 397
    move/from16 v4, v22

    .line 398
    .line 399
    move-object/from16 v5, v23

    .line 400
    .line 401
    move/from16 v6, v24

    .line 402
    .line 403
    move-object/from16 v2, v28

    .line 404
    .line 405
    const/16 v1, 0x20

    .line 406
    .line 407
    goto/16 :goto_9

    .line 408
    .line 409
    :cond_11
    move/from16 v24, v6

    .line 410
    .line 411
    new-instance v1, Ln8/e;

    .line 412
    .line 413
    invoke-direct {v1, v8}, Ln8/e;-><init>([Li4/c;)V

    .line 414
    .line 415
    .line 416
    :goto_b
    if-nez v1, :cond_12

    .line 417
    .line 418
    goto :goto_d

    .line 419
    :cond_12
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 420
    .line 421
    .line 422
    goto :goto_c

    .line 423
    :cond_13
    move/from16 v16, v1

    .line 424
    .line 425
    move-object/from16 v20, v2

    .line 426
    .line 427
    move/from16 v17, v5

    .line 428
    .line 429
    move/from16 v24, v6

    .line 430
    .line 431
    :goto_c
    invoke-virtual {v0, v7}, Lw7/p;->I(I)V

    .line 432
    .line 433
    .line 434
    move v4, v7

    .line 435
    move/from16 v1, v16

    .line 436
    .line 437
    move/from16 v5, v17

    .line 438
    .line 439
    move-object/from16 v2, v20

    .line 440
    .line 441
    move/from16 v6, v24

    .line 442
    .line 443
    goto/16 :goto_2

    .line 444
    .line 445
    :goto_d
    return-object v20

    .line 446
    :cond_14
    return-object v3
.end method

.method public static b(Lx2/s;FLe3/n0;ZJJI)Lx2/s;
    .locals 8

    .line 1
    and-int/lit8 v0, p8, 0x2

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object p2, Le3/j0;->a:Le3/i0;

    .line 6
    .line 7
    :cond_0
    move-object v2, p2

    .line 8
    and-int/lit8 p2, p8, 0x4

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    if-eqz p2, :cond_2

    .line 12
    .line 13
    int-to-float p2, v0

    .line 14
    invoke-static {p1, p2}, Ljava/lang/Float;->compare(FF)I

    .line 15
    .line 16
    .line 17
    move-result p2

    .line 18
    if-lez p2, :cond_1

    .line 19
    .line 20
    const/4 p2, 0x1

    .line 21
    move p3, p2

    .line 22
    goto :goto_0

    .line 23
    :cond_1
    move p3, v0

    .line 24
    :cond_2
    :goto_0
    move v3, p3

    .line 25
    and-int/lit8 p2, p8, 0x8

    .line 26
    .line 27
    if-eqz p2, :cond_3

    .line 28
    .line 29
    sget-wide p4, Le3/y;->a:J

    .line 30
    .line 31
    :cond_3
    move-wide v4, p4

    .line 32
    and-int/lit8 p2, p8, 0x10

    .line 33
    .line 34
    if-eqz p2, :cond_4

    .line 35
    .line 36
    sget-wide p2, Le3/y;->a:J

    .line 37
    .line 38
    move-wide v6, p2

    .line 39
    goto :goto_1

    .line 40
    :cond_4
    move-wide v6, p6

    .line 41
    :goto_1
    int-to-float p2, v0

    .line 42
    invoke-static {p1, p2}, Ljava/lang/Float;->compare(FF)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    if-gtz p2, :cond_6

    .line 47
    .line 48
    if-eqz v3, :cond_5

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_5
    return-object p0

    .line 52
    :cond_6
    :goto_2
    new-instance v0, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;

    .line 53
    .line 54
    move v1, p1

    .line 55
    invoke-direct/range {v0 .. v7}, Landroidx/compose/ui/draw/ShadowGraphicsLayerElement;-><init>(FLe3/n0;ZJJ)V

    .line 56
    .line 57
    .line 58
    invoke-interface {p0, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method
