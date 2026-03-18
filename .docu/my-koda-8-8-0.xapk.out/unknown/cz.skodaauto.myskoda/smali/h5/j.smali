.class public abstract Lh5/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [Z

    .line 3
    .line 4
    sput-object v0, Lh5/j;->a:[Z

    .line 5
    .line 6
    return-void
.end method

.method public static a(Lh5/e;La5/c;Ljava/util/ArrayList;I)V
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v10, p2

    .line 6
    .line 7
    if-nez p3, :cond_0

    .line 8
    .line 9
    iget v2, v0, Lh5/e;->A0:I

    .line 10
    .line 11
    iget-object v3, v0, Lh5/e;->D0:[Lh5/b;

    .line 12
    .line 13
    const/4 v15, 0x0

    .line 14
    :goto_0
    move v13, v2

    .line 15
    move-object v14, v3

    .line 16
    goto :goto_1

    .line 17
    :cond_0
    iget v2, v0, Lh5/e;->B0:I

    .line 18
    .line 19
    iget-object v3, v0, Lh5/e;->C0:[Lh5/b;

    .line 20
    .line 21
    const/4 v15, 0x2

    .line 22
    goto :goto_0

    .line 23
    :goto_1
    const/4 v2, 0x0

    .line 24
    :goto_2
    if-ge v2, v13, :cond_71

    .line 25
    .line 26
    aget-object v3, v14, v2

    .line 27
    .line 28
    iget-boolean v4, v3, Lh5/b;->q:Z

    .line 29
    .line 30
    iget-object v5, v3, Lh5/b;->a:Lh5/d;

    .line 31
    .line 32
    iget-object v6, v5, Lh5/d;->R:[Lh5/c;

    .line 33
    .line 34
    const/4 v7, 0x3

    .line 35
    const/16 v16, 0x0

    .line 36
    .line 37
    const/16 v8, 0x8

    .line 38
    .line 39
    const/16 v17, 0x0

    .line 40
    .line 41
    if-nez v4, :cond_19

    .line 42
    .line 43
    iget v4, v3, Lh5/b;->l:I

    .line 44
    .line 45
    mul-int/lit8 v18, v4, 0x2

    .line 46
    .line 47
    move-object v12, v5

    .line 48
    move-object/from16 v21, v12

    .line 49
    .line 50
    const/16 v19, 0x0

    .line 51
    .line 52
    :goto_3
    if-nez v19, :cond_14

    .line 53
    .line 54
    const/16 v22, 0x1

    .line 55
    .line 56
    iget v9, v3, Lh5/b;->i:I

    .line 57
    .line 58
    add-int/lit8 v9, v9, 0x1

    .line 59
    .line 60
    iput v9, v3, Lh5/b;->i:I

    .line 61
    .line 62
    iget-object v9, v12, Lh5/d;->n0:[Lh5/d;

    .line 63
    .line 64
    iget-object v11, v12, Lh5/d;->R:[Lh5/c;

    .line 65
    .line 66
    aput-object v16, v9, v4

    .line 67
    .line 68
    iget-object v9, v12, Lh5/d;->m0:[Lh5/d;

    .line 69
    .line 70
    aput-object v16, v9, v4

    .line 71
    .line 72
    iget v9, v12, Lh5/d;->h0:I

    .line 73
    .line 74
    if-eq v9, v8, :cond_f

    .line 75
    .line 76
    invoke-virtual {v12, v4}, Lh5/d;->k(I)I

    .line 77
    .line 78
    .line 79
    aget-object v9, v11, v18

    .line 80
    .line 81
    invoke-virtual {v9}, Lh5/c;->e()I

    .line 82
    .line 83
    .line 84
    add-int/lit8 v9, v18, 0x1

    .line 85
    .line 86
    aget-object v24, v11, v9

    .line 87
    .line 88
    invoke-virtual/range {v24 .. v24}, Lh5/c;->e()I

    .line 89
    .line 90
    .line 91
    aget-object v24, v11, v18

    .line 92
    .line 93
    invoke-virtual/range {v24 .. v24}, Lh5/c;->e()I

    .line 94
    .line 95
    .line 96
    aget-object v9, v11, v9

    .line 97
    .line 98
    invoke-virtual {v9}, Lh5/c;->e()I

    .line 99
    .line 100
    .line 101
    iget-object v9, v3, Lh5/b;->b:Lh5/d;

    .line 102
    .line 103
    if-nez v9, :cond_1

    .line 104
    .line 105
    iput-object v12, v3, Lh5/b;->b:Lh5/d;

    .line 106
    .line 107
    :cond_1
    iput-object v12, v3, Lh5/b;->d:Lh5/d;

    .line 108
    .line 109
    iget-object v9, v12, Lh5/d;->q0:[I

    .line 110
    .line 111
    aget v9, v9, v4

    .line 112
    .line 113
    if-ne v9, v7, :cond_f

    .line 114
    .line 115
    iget-object v8, v12, Lh5/d;->u:[I

    .line 116
    .line 117
    aget v8, v8, v4

    .line 118
    .line 119
    if-eqz v8, :cond_3

    .line 120
    .line 121
    if-eq v8, v7, :cond_3

    .line 122
    .line 123
    const/4 v7, 0x2

    .line 124
    if-ne v8, v7, :cond_2

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_2
    move/from16 v26, v2

    .line 128
    .line 129
    move/from16 v27, v4

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_3
    :goto_4
    iget v7, v3, Lh5/b;->j:I

    .line 133
    .line 134
    add-int/lit8 v7, v7, 0x1

    .line 135
    .line 136
    iput v7, v3, Lh5/b;->j:I

    .line 137
    .line 138
    iget-object v7, v12, Lh5/d;->l0:[F

    .line 139
    .line 140
    aget v7, v7, v4

    .line 141
    .line 142
    cmpl-float v26, v7, v17

    .line 143
    .line 144
    if-lez v26, :cond_4

    .line 145
    .line 146
    move/from16 v26, v2

    .line 147
    .line 148
    iget v2, v3, Lh5/b;->k:F

    .line 149
    .line 150
    add-float/2addr v2, v7

    .line 151
    iput v2, v3, Lh5/b;->k:F

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_4
    move/from16 v26, v2

    .line 155
    .line 156
    :goto_5
    iget v2, v12, Lh5/d;->h0:I

    .line 157
    .line 158
    move/from16 v27, v4

    .line 159
    .line 160
    const/16 v4, 0x8

    .line 161
    .line 162
    if-eq v2, v4, :cond_8

    .line 163
    .line 164
    const/4 v2, 0x3

    .line 165
    if-ne v9, v2, :cond_8

    .line 166
    .line 167
    if-eqz v8, :cond_5

    .line 168
    .line 169
    if-ne v8, v2, :cond_8

    .line 170
    .line 171
    :cond_5
    cmpg-float v2, v7, v17

    .line 172
    .line 173
    if-gez v2, :cond_6

    .line 174
    .line 175
    move/from16 v2, v22

    .line 176
    .line 177
    iput-boolean v2, v3, Lh5/b;->n:Z

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_6
    move/from16 v2, v22

    .line 181
    .line 182
    iput-boolean v2, v3, Lh5/b;->o:Z

    .line 183
    .line 184
    :goto_6
    iget-object v2, v3, Lh5/b;->h:Ljava/util/ArrayList;

    .line 185
    .line 186
    if-nez v2, :cond_7

    .line 187
    .line 188
    new-instance v2, Ljava/util/ArrayList;

    .line 189
    .line 190
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 191
    .line 192
    .line 193
    iput-object v2, v3, Lh5/b;->h:Ljava/util/ArrayList;

    .line 194
    .line 195
    :cond_7
    iget-object v2, v3, Lh5/b;->h:Ljava/util/ArrayList;

    .line 196
    .line 197
    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    :cond_8
    iget-object v2, v3, Lh5/b;->f:Lh5/d;

    .line 201
    .line 202
    if-nez v2, :cond_9

    .line 203
    .line 204
    iput-object v12, v3, Lh5/b;->f:Lh5/d;

    .line 205
    .line 206
    :cond_9
    iget-object v2, v3, Lh5/b;->g:Lh5/d;

    .line 207
    .line 208
    if-eqz v2, :cond_a

    .line 209
    .line 210
    iget-object v2, v2, Lh5/d;->m0:[Lh5/d;

    .line 211
    .line 212
    aput-object v12, v2, v27

    .line 213
    .line 214
    :cond_a
    iput-object v12, v3, Lh5/b;->g:Lh5/d;

    .line 215
    .line 216
    :goto_7
    if-nez v27, :cond_c

    .line 217
    .line 218
    iget v2, v12, Lh5/d;->s:I

    .line 219
    .line 220
    if-eqz v2, :cond_b

    .line 221
    .line 222
    goto :goto_8

    .line 223
    :cond_b
    iget v2, v12, Lh5/d;->v:I

    .line 224
    .line 225
    if-nez v2, :cond_e

    .line 226
    .line 227
    iget v2, v12, Lh5/d;->w:I

    .line 228
    .line 229
    goto :goto_8

    .line 230
    :cond_c
    iget v2, v12, Lh5/d;->t:I

    .line 231
    .line 232
    if-eqz v2, :cond_d

    .line 233
    .line 234
    goto :goto_8

    .line 235
    :cond_d
    iget v2, v12, Lh5/d;->y:I

    .line 236
    .line 237
    if-nez v2, :cond_e

    .line 238
    .line 239
    iget v2, v12, Lh5/d;->z:I

    .line 240
    .line 241
    :cond_e
    :goto_8
    move-object/from16 v2, v21

    .line 242
    .line 243
    goto :goto_9

    .line 244
    :cond_f
    move/from16 v26, v2

    .line 245
    .line 246
    move/from16 v27, v4

    .line 247
    .line 248
    goto :goto_8

    .line 249
    :goto_9
    if-eq v2, v12, :cond_10

    .line 250
    .line 251
    iget-object v2, v2, Lh5/d;->n0:[Lh5/d;

    .line 252
    .line 253
    aput-object v12, v2, v27

    .line 254
    .line 255
    :cond_10
    add-int/lit8 v2, v18, 0x1

    .line 256
    .line 257
    aget-object v2, v11, v2

    .line 258
    .line 259
    iget-object v2, v2, Lh5/c;->f:Lh5/c;

    .line 260
    .line 261
    if-eqz v2, :cond_11

    .line 262
    .line 263
    iget-object v2, v2, Lh5/c;->d:Lh5/d;

    .line 264
    .line 265
    iget-object v4, v2, Lh5/d;->R:[Lh5/c;

    .line 266
    .line 267
    aget-object v4, v4, v18

    .line 268
    .line 269
    iget-object v4, v4, Lh5/c;->f:Lh5/c;

    .line 270
    .line 271
    if-eqz v4, :cond_11

    .line 272
    .line 273
    iget-object v4, v4, Lh5/c;->d:Lh5/d;

    .line 274
    .line 275
    if-eq v4, v12, :cond_12

    .line 276
    .line 277
    :cond_11
    move-object/from16 v2, v16

    .line 278
    .line 279
    :cond_12
    if-eqz v2, :cond_13

    .line 280
    .line 281
    goto :goto_a

    .line 282
    :cond_13
    move-object v2, v12

    .line 283
    const/16 v19, 0x1

    .line 284
    .line 285
    :goto_a
    move-object/from16 v21, v12

    .line 286
    .line 287
    move/from16 v4, v27

    .line 288
    .line 289
    const/4 v7, 0x3

    .line 290
    const/16 v8, 0x8

    .line 291
    .line 292
    move-object v12, v2

    .line 293
    move/from16 v2, v26

    .line 294
    .line 295
    goto/16 :goto_3

    .line 296
    .line 297
    :cond_14
    move/from16 v26, v2

    .line 298
    .line 299
    move/from16 v27, v4

    .line 300
    .line 301
    iget-object v2, v3, Lh5/b;->b:Lh5/d;

    .line 302
    .line 303
    if-eqz v2, :cond_15

    .line 304
    .line 305
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 306
    .line 307
    aget-object v2, v2, v18

    .line 308
    .line 309
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 310
    .line 311
    .line 312
    :cond_15
    iget-object v2, v3, Lh5/b;->d:Lh5/d;

    .line 313
    .line 314
    if-eqz v2, :cond_16

    .line 315
    .line 316
    iget-object v2, v2, Lh5/d;->R:[Lh5/c;

    .line 317
    .line 318
    add-int/lit8 v18, v18, 0x1

    .line 319
    .line 320
    aget-object v2, v2, v18

    .line 321
    .line 322
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 323
    .line 324
    .line 325
    :cond_16
    iput-object v12, v3, Lh5/b;->c:Lh5/d;

    .line 326
    .line 327
    if-nez v27, :cond_17

    .line 328
    .line 329
    iget-boolean v2, v3, Lh5/b;->m:Z

    .line 330
    .line 331
    if-eqz v2, :cond_17

    .line 332
    .line 333
    iput-object v12, v3, Lh5/b;->e:Lh5/d;

    .line 334
    .line 335
    goto :goto_b

    .line 336
    :cond_17
    iput-object v5, v3, Lh5/b;->e:Lh5/d;

    .line 337
    .line 338
    :goto_b
    iget-boolean v2, v3, Lh5/b;->o:Z

    .line 339
    .line 340
    if-eqz v2, :cond_18

    .line 341
    .line 342
    iget-boolean v2, v3, Lh5/b;->n:Z

    .line 343
    .line 344
    if-eqz v2, :cond_18

    .line 345
    .line 346
    const/4 v2, 0x1

    .line 347
    goto :goto_c

    .line 348
    :cond_18
    const/4 v2, 0x0

    .line 349
    :goto_c
    iput-boolean v2, v3, Lh5/b;->p:Z

    .line 350
    .line 351
    :goto_d
    const/4 v2, 0x1

    .line 352
    goto :goto_e

    .line 353
    :cond_19
    move/from16 v26, v2

    .line 354
    .line 355
    goto :goto_d

    .line 356
    :goto_e
    iput-boolean v2, v3, Lh5/b;->q:Z

    .line 357
    .line 358
    if-eqz v10, :cond_1b

    .line 359
    .line 360
    invoke-virtual {v10, v5}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    move-result v2

    .line 364
    if-eqz v2, :cond_1a

    .line 365
    .line 366
    goto :goto_f

    .line 367
    :cond_1a
    move/from16 v17, v13

    .line 368
    .line 369
    const/16 v28, 0x2

    .line 370
    .line 371
    goto/16 :goto_48

    .line 372
    .line 373
    :cond_1b
    :goto_f
    iget-object v11, v3, Lh5/b;->c:Lh5/d;

    .line 374
    .line 375
    iget-object v12, v3, Lh5/b;->b:Lh5/d;

    .line 376
    .line 377
    iget-object v2, v3, Lh5/b;->d:Lh5/d;

    .line 378
    .line 379
    iget-object v4, v3, Lh5/b;->e:Lh5/d;

    .line 380
    .line 381
    iget v7, v3, Lh5/b;->k:F

    .line 382
    .line 383
    iget-object v8, v0, Lh5/d;->q0:[I

    .line 384
    .line 385
    iget-object v9, v0, Lh5/d;->R:[Lh5/c;

    .line 386
    .line 387
    aget v8, v8, p3

    .line 388
    .line 389
    move-object/from16 v18, v9

    .line 390
    .line 391
    const/4 v9, 0x2

    .line 392
    if-ne v8, v9, :cond_1c

    .line 393
    .line 394
    const/4 v8, 0x1

    .line 395
    goto :goto_10

    .line 396
    :cond_1c
    const/4 v8, 0x0

    .line 397
    :goto_10
    if-nez p3, :cond_20

    .line 398
    .line 399
    iget v9, v4, Lh5/d;->j0:I

    .line 400
    .line 401
    if-nez v9, :cond_1d

    .line 402
    .line 403
    const/16 v22, 0x1

    .line 404
    .line 405
    :goto_11
    move-object/from16 v19, v6

    .line 406
    .line 407
    const/4 v6, 0x1

    .line 408
    goto :goto_12

    .line 409
    :cond_1d
    const/16 v22, 0x0

    .line 410
    .line 411
    goto :goto_11

    .line 412
    :goto_12
    if-ne v9, v6, :cond_1e

    .line 413
    .line 414
    move/from16 v21, v6

    .line 415
    .line 416
    :goto_13
    const/4 v6, 0x2

    .line 417
    goto :goto_14

    .line 418
    :cond_1e
    const/16 v21, 0x0

    .line 419
    .line 420
    goto :goto_13

    .line 421
    :goto_14
    if-ne v9, v6, :cond_1f

    .line 422
    .line 423
    const/4 v9, 0x1

    .line 424
    goto :goto_15

    .line 425
    :cond_1f
    const/4 v9, 0x0

    .line 426
    :goto_15
    move-object v6, v5

    .line 427
    move/from16 v29, v7

    .line 428
    .line 429
    move/from16 v23, v21

    .line 430
    .line 431
    move/from16 v27, v22

    .line 432
    .line 433
    :goto_16
    const/16 v21, 0x0

    .line 434
    .line 435
    goto :goto_1c

    .line 436
    :cond_20
    move-object/from16 v19, v6

    .line 437
    .line 438
    move v6, v9

    .line 439
    iget v9, v4, Lh5/d;->k0:I

    .line 440
    .line 441
    if-nez v9, :cond_21

    .line 442
    .line 443
    const/16 v23, 0x1

    .line 444
    .line 445
    :goto_17
    const/4 v6, 0x1

    .line 446
    goto :goto_18

    .line 447
    :cond_21
    const/16 v23, 0x0

    .line 448
    .line 449
    goto :goto_17

    .line 450
    :goto_18
    if-ne v9, v6, :cond_22

    .line 451
    .line 452
    const/16 v21, 0x1

    .line 453
    .line 454
    :goto_19
    const/4 v6, 0x2

    .line 455
    goto :goto_1a

    .line 456
    :cond_22
    const/16 v21, 0x0

    .line 457
    .line 458
    goto :goto_19

    .line 459
    :goto_1a
    if-ne v9, v6, :cond_23

    .line 460
    .line 461
    const/4 v9, 0x1

    .line 462
    goto :goto_1b

    .line 463
    :cond_23
    const/4 v9, 0x0

    .line 464
    :goto_1b
    move-object v6, v5

    .line 465
    move/from16 v29, v7

    .line 466
    .line 467
    move/from16 v27, v23

    .line 468
    .line 469
    move/from16 v23, v21

    .line 470
    .line 471
    goto :goto_16

    .line 472
    :goto_1c
    if-nez v21, :cond_31

    .line 473
    .line 474
    iget-object v7, v6, Lh5/d;->R:[Lh5/c;

    .line 475
    .line 476
    move-object/from16 v33, v7

    .line 477
    .line 478
    iget-object v7, v6, Lh5/d;->q0:[I

    .line 479
    .line 480
    move-object/from16 v34, v7

    .line 481
    .line 482
    aget-object v7, v33, v15

    .line 483
    .line 484
    if-eqz v9, :cond_24

    .line 485
    .line 486
    const/16 v31, 0x1

    .line 487
    .line 488
    goto :goto_1d

    .line 489
    :cond_24
    const/16 v31, 0x4

    .line 490
    .line 491
    :goto_1d
    invoke-virtual {v7}, Lh5/c;->e()I

    .line 492
    .line 493
    .line 494
    move-result v35

    .line 495
    move/from16 v36, v8

    .line 496
    .line 497
    aget v8, v34, p3

    .line 498
    .line 499
    move/from16 v37, v9

    .line 500
    .line 501
    const/4 v9, 0x3

    .line 502
    if-ne v8, v9, :cond_25

    .line 503
    .line 504
    iget-object v8, v6, Lh5/d;->u:[I

    .line 505
    .line 506
    aget v8, v8, p3

    .line 507
    .line 508
    if-nez v8, :cond_25

    .line 509
    .line 510
    const/4 v8, 0x1

    .line 511
    goto :goto_1e

    .line 512
    :cond_25
    const/4 v8, 0x0

    .line 513
    :goto_1e
    iget-object v9, v7, Lh5/c;->f:Lh5/c;

    .line 514
    .line 515
    if-eqz v9, :cond_26

    .line 516
    .line 517
    if-eq v6, v5, :cond_26

    .line 518
    .line 519
    invoke-virtual {v9}, Lh5/c;->e()I

    .line 520
    .line 521
    .line 522
    move-result v9

    .line 523
    add-int v35, v9, v35

    .line 524
    .line 525
    :cond_26
    move/from16 v9, v35

    .line 526
    .line 527
    if-eqz v37, :cond_27

    .line 528
    .line 529
    if-eq v6, v5, :cond_27

    .line 530
    .line 531
    if-eq v6, v12, :cond_27

    .line 532
    .line 533
    const/16 v31, 0x8

    .line 534
    .line 535
    :cond_27
    move-object/from16 v35, v5

    .line 536
    .line 537
    iget-object v5, v7, Lh5/c;->f:Lh5/c;

    .line 538
    .line 539
    if-eqz v5, :cond_2b

    .line 540
    .line 541
    if-ne v6, v12, :cond_28

    .line 542
    .line 543
    move/from16 v38, v8

    .line 544
    .line 545
    iget-object v8, v7, Lh5/c;->i:La5/h;

    .line 546
    .line 547
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 548
    .line 549
    const/4 v10, 0x6

    .line 550
    invoke-virtual {v1, v8, v5, v9, v10}, La5/c;->f(La5/h;La5/h;II)V

    .line 551
    .line 552
    .line 553
    goto :goto_1f

    .line 554
    :cond_28
    move/from16 v38, v8

    .line 555
    .line 556
    iget-object v8, v7, Lh5/c;->i:La5/h;

    .line 557
    .line 558
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 559
    .line 560
    const/16 v10, 0x8

    .line 561
    .line 562
    invoke-virtual {v1, v8, v5, v9, v10}, La5/c;->f(La5/h;La5/h;II)V

    .line 563
    .line 564
    .line 565
    :goto_1f
    if-eqz v38, :cond_29

    .line 566
    .line 567
    if-nez v37, :cond_29

    .line 568
    .line 569
    const/16 v31, 0x5

    .line 570
    .line 571
    :cond_29
    if-ne v6, v12, :cond_2a

    .line 572
    .line 573
    if-eqz v37, :cond_2a

    .line 574
    .line 575
    iget-object v5, v6, Lh5/d;->T:[Z

    .line 576
    .line 577
    aget-boolean v5, v5, p3

    .line 578
    .line 579
    if-eqz v5, :cond_2a

    .line 580
    .line 581
    const/4 v5, 0x5

    .line 582
    goto :goto_20

    .line 583
    :cond_2a
    move/from16 v5, v31

    .line 584
    .line 585
    :goto_20
    iget-object v8, v7, Lh5/c;->i:La5/h;

    .line 586
    .line 587
    iget-object v7, v7, Lh5/c;->f:Lh5/c;

    .line 588
    .line 589
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 590
    .line 591
    invoke-virtual {v1, v8, v7, v9, v5}, La5/c;->e(La5/h;La5/h;II)V

    .line 592
    .line 593
    .line 594
    :cond_2b
    if-eqz v36, :cond_2d

    .line 595
    .line 596
    iget v5, v6, Lh5/d;->h0:I

    .line 597
    .line 598
    const/16 v10, 0x8

    .line 599
    .line 600
    if-eq v5, v10, :cond_2c

    .line 601
    .line 602
    aget v5, v34, p3

    .line 603
    .line 604
    const/4 v9, 0x3

    .line 605
    if-ne v5, v9, :cond_2c

    .line 606
    .line 607
    add-int/lit8 v5, v15, 0x1

    .line 608
    .line 609
    aget-object v5, v33, v5

    .line 610
    .line 611
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 612
    .line 613
    aget-object v7, v33, v15

    .line 614
    .line 615
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 616
    .line 617
    const/4 v8, 0x0

    .line 618
    const/4 v9, 0x5

    .line 619
    invoke-virtual {v1, v5, v7, v8, v9}, La5/c;->f(La5/h;La5/h;II)V

    .line 620
    .line 621
    .line 622
    goto :goto_21

    .line 623
    :cond_2c
    const/4 v8, 0x0

    .line 624
    :goto_21
    aget-object v5, v33, v15

    .line 625
    .line 626
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 627
    .line 628
    aget-object v7, v18, v15

    .line 629
    .line 630
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 631
    .line 632
    const/16 v10, 0x8

    .line 633
    .line 634
    invoke-virtual {v1, v5, v7, v8, v10}, La5/c;->f(La5/h;La5/h;II)V

    .line 635
    .line 636
    .line 637
    :cond_2d
    add-int/lit8 v5, v15, 0x1

    .line 638
    .line 639
    aget-object v5, v33, v5

    .line 640
    .line 641
    iget-object v5, v5, Lh5/c;->f:Lh5/c;

    .line 642
    .line 643
    if-eqz v5, :cond_2e

    .line 644
    .line 645
    iget-object v5, v5, Lh5/c;->d:Lh5/d;

    .line 646
    .line 647
    iget-object v7, v5, Lh5/d;->R:[Lh5/c;

    .line 648
    .line 649
    aget-object v7, v7, v15

    .line 650
    .line 651
    iget-object v7, v7, Lh5/c;->f:Lh5/c;

    .line 652
    .line 653
    if-eqz v7, :cond_2e

    .line 654
    .line 655
    iget-object v7, v7, Lh5/c;->d:Lh5/d;

    .line 656
    .line 657
    if-eq v7, v6, :cond_2f

    .line 658
    .line 659
    :cond_2e
    move-object/from16 v5, v16

    .line 660
    .line 661
    :cond_2f
    if-eqz v5, :cond_30

    .line 662
    .line 663
    move-object v6, v5

    .line 664
    goto :goto_22

    .line 665
    :cond_30
    const/16 v21, 0x1

    .line 666
    .line 667
    :goto_22
    move-object/from16 v10, p2

    .line 668
    .line 669
    move-object/from16 v5, v35

    .line 670
    .line 671
    move/from16 v8, v36

    .line 672
    .line 673
    move/from16 v9, v37

    .line 674
    .line 675
    goto/16 :goto_1c

    .line 676
    .line 677
    :cond_31
    move/from16 v36, v8

    .line 678
    .line 679
    move/from16 v37, v9

    .line 680
    .line 681
    if-eqz v2, :cond_34

    .line 682
    .line 683
    iget-object v5, v11, Lh5/d;->R:[Lh5/c;

    .line 684
    .line 685
    add-int/lit8 v6, v15, 0x1

    .line 686
    .line 687
    aget-object v5, v5, v6

    .line 688
    .line 689
    iget-object v5, v5, Lh5/c;->f:Lh5/c;

    .line 690
    .line 691
    if-eqz v5, :cond_34

    .line 692
    .line 693
    iget-object v5, v2, Lh5/d;->R:[Lh5/c;

    .line 694
    .line 695
    aget-object v5, v5, v6

    .line 696
    .line 697
    iget-object v7, v2, Lh5/d;->q0:[I

    .line 698
    .line 699
    aget v7, v7, p3

    .line 700
    .line 701
    const/4 v9, 0x3

    .line 702
    if-ne v7, v9, :cond_32

    .line 703
    .line 704
    iget-object v7, v2, Lh5/d;->u:[I

    .line 705
    .line 706
    aget v7, v7, p3

    .line 707
    .line 708
    if-nez v7, :cond_32

    .line 709
    .line 710
    if-nez v37, :cond_32

    .line 711
    .line 712
    iget-object v7, v5, Lh5/c;->f:Lh5/c;

    .line 713
    .line 714
    iget-object v8, v7, Lh5/c;->d:Lh5/d;

    .line 715
    .line 716
    if-ne v8, v0, :cond_32

    .line 717
    .line 718
    iget-object v8, v5, Lh5/c;->i:La5/h;

    .line 719
    .line 720
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 721
    .line 722
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 723
    .line 724
    .line 725
    move-result v9

    .line 726
    neg-int v9, v9

    .line 727
    const/4 v10, 0x5

    .line 728
    invoke-virtual {v1, v8, v7, v9, v10}, La5/c;->e(La5/h;La5/h;II)V

    .line 729
    .line 730
    .line 731
    goto :goto_23

    .line 732
    :cond_32
    const/4 v10, 0x5

    .line 733
    if-eqz v37, :cond_33

    .line 734
    .line 735
    iget-object v7, v5, Lh5/c;->f:Lh5/c;

    .line 736
    .line 737
    iget-object v8, v7, Lh5/c;->d:Lh5/d;

    .line 738
    .line 739
    if-ne v8, v0, :cond_33

    .line 740
    .line 741
    iget-object v8, v5, Lh5/c;->i:La5/h;

    .line 742
    .line 743
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 744
    .line 745
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 746
    .line 747
    .line 748
    move-result v9

    .line 749
    neg-int v9, v9

    .line 750
    const/4 v10, 0x4

    .line 751
    invoke-virtual {v1, v8, v7, v9, v10}, La5/c;->e(La5/h;La5/h;II)V

    .line 752
    .line 753
    .line 754
    :cond_33
    :goto_23
    iget-object v7, v5, Lh5/c;->i:La5/h;

    .line 755
    .line 756
    iget-object v8, v11, Lh5/d;->R:[Lh5/c;

    .line 757
    .line 758
    aget-object v6, v8, v6

    .line 759
    .line 760
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 761
    .line 762
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 763
    .line 764
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 765
    .line 766
    .line 767
    move-result v5

    .line 768
    neg-int v5, v5

    .line 769
    const/4 v10, 0x6

    .line 770
    invoke-virtual {v1, v7, v6, v5, v10}, La5/c;->g(La5/h;La5/h;II)V

    .line 771
    .line 772
    .line 773
    :cond_34
    if-eqz v36, :cond_35

    .line 774
    .line 775
    add-int/lit8 v5, v15, 0x1

    .line 776
    .line 777
    aget-object v6, v18, v5

    .line 778
    .line 779
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 780
    .line 781
    iget-object v7, v11, Lh5/d;->R:[Lh5/c;

    .line 782
    .line 783
    aget-object v5, v7, v5

    .line 784
    .line 785
    iget-object v7, v5, Lh5/c;->i:La5/h;

    .line 786
    .line 787
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 788
    .line 789
    .line 790
    move-result v5

    .line 791
    const/16 v10, 0x8

    .line 792
    .line 793
    invoke-virtual {v1, v6, v7, v5, v10}, La5/c;->f(La5/h;La5/h;II)V

    .line 794
    .line 795
    .line 796
    :cond_35
    iget-object v5, v3, Lh5/b;->h:Ljava/util/ArrayList;

    .line 797
    .line 798
    if-eqz v5, :cond_3f

    .line 799
    .line 800
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 801
    .line 802
    .line 803
    move-result v6

    .line 804
    const/4 v7, 0x1

    .line 805
    if-le v6, v7, :cond_3f

    .line 806
    .line 807
    iget-boolean v8, v3, Lh5/b;->n:Z

    .line 808
    .line 809
    if-eqz v8, :cond_36

    .line 810
    .line 811
    iget-boolean v8, v3, Lh5/b;->p:Z

    .line 812
    .line 813
    if-nez v8, :cond_36

    .line 814
    .line 815
    iget v8, v3, Lh5/b;->j:I

    .line 816
    .line 817
    int-to-float v8, v8

    .line 818
    move/from16 v29, v8

    .line 819
    .line 820
    :cond_36
    move-object/from16 v9, v16

    .line 821
    .line 822
    move/from16 v10, v17

    .line 823
    .line 824
    const/4 v8, 0x0

    .line 825
    :goto_24
    if-ge v8, v6, :cond_3f

    .line 826
    .line 827
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 828
    .line 829
    .line 830
    move-result-object v18

    .line 831
    move-object/from16 v7, v18

    .line 832
    .line 833
    check-cast v7, Lh5/d;

    .line 834
    .line 835
    iget-object v0, v7, Lh5/d;->l0:[F

    .line 836
    .line 837
    move-object/from16 v18, v0

    .line 838
    .line 839
    iget-object v0, v7, Lh5/d;->R:[Lh5/c;

    .line 840
    .line 841
    aget v18, v18, p3

    .line 842
    .line 843
    cmpg-float v21, v18, v17

    .line 844
    .line 845
    move-object/from16 v25, v0

    .line 846
    .line 847
    if-gez v21, :cond_38

    .line 848
    .line 849
    iget-boolean v0, v3, Lh5/b;->p:Z

    .line 850
    .line 851
    if-eqz v0, :cond_37

    .line 852
    .line 853
    add-int/lit8 v0, v15, 0x1

    .line 854
    .line 855
    aget-object v0, v25, v0

    .line 856
    .line 857
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 858
    .line 859
    aget-object v7, v25, v15

    .line 860
    .line 861
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 862
    .line 863
    move-object/from16 v30, v5

    .line 864
    .line 865
    move/from16 v31, v6

    .line 866
    .line 867
    const/4 v5, 0x0

    .line 868
    const/4 v6, 0x4

    .line 869
    invoke-virtual {v1, v0, v7, v5, v6}, La5/c;->e(La5/h;La5/h;II)V

    .line 870
    .line 871
    .line 872
    move/from16 v20, v10

    .line 873
    .line 874
    move v10, v5

    .line 875
    goto :goto_25

    .line 876
    :cond_37
    const/high16 v18, 0x3f800000    # 1.0f

    .line 877
    .line 878
    :cond_38
    move-object/from16 v30, v5

    .line 879
    .line 880
    move/from16 v31, v6

    .line 881
    .line 882
    const/4 v6, 0x4

    .line 883
    cmpl-float v0, v18, v17

    .line 884
    .line 885
    if-nez v0, :cond_39

    .line 886
    .line 887
    add-int/lit8 v0, v15, 0x1

    .line 888
    .line 889
    aget-object v0, v25, v0

    .line 890
    .line 891
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 892
    .line 893
    aget-object v5, v25, v15

    .line 894
    .line 895
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 896
    .line 897
    move/from16 v20, v10

    .line 898
    .line 899
    const/16 v7, 0x8

    .line 900
    .line 901
    const/4 v10, 0x0

    .line 902
    invoke-virtual {v1, v0, v5, v10, v7}, La5/c;->e(La5/h;La5/h;II)V

    .line 903
    .line 904
    .line 905
    :goto_25
    move/from16 v21, v8

    .line 906
    .line 907
    move/from16 v36, v17

    .line 908
    .line 909
    move/from16 v10, v20

    .line 910
    .line 911
    move/from16 v17, v13

    .line 912
    .line 913
    goto/16 :goto_2a

    .line 914
    .line 915
    :cond_39
    move/from16 v20, v10

    .line 916
    .line 917
    const/4 v10, 0x0

    .line 918
    if-eqz v9, :cond_3e

    .line 919
    .line 920
    iget-object v5, v9, Lh5/d;->R:[Lh5/c;

    .line 921
    .line 922
    aget-object v9, v5, v15

    .line 923
    .line 924
    iget-object v9, v9, Lh5/c;->i:La5/h;

    .line 925
    .line 926
    add-int/lit8 v33, v15, 0x1

    .line 927
    .line 928
    aget-object v5, v5, v33

    .line 929
    .line 930
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 931
    .line 932
    aget-object v6, v25, v15

    .line 933
    .line 934
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 935
    .line 936
    aget-object v10, v25, v33

    .line 937
    .line 938
    iget-object v10, v10, Lh5/c;->i:La5/h;

    .line 939
    .line 940
    move/from16 v25, v0

    .line 941
    .line 942
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 943
    .line 944
    .line 945
    move-result-object v0

    .line 946
    move-object/from16 v33, v7

    .line 947
    .line 948
    move/from16 v7, v17

    .line 949
    .line 950
    iput v7, v0, La5/b;->b:F

    .line 951
    .line 952
    cmpl-float v17, v29, v7

    .line 953
    .line 954
    move/from16 v36, v7

    .line 955
    .line 956
    const/high16 v7, -0x40800000    # -1.0f

    .line 957
    .line 958
    if-eqz v17, :cond_3a

    .line 959
    .line 960
    cmpl-float v17, v20, v18

    .line 961
    .line 962
    if-nez v17, :cond_3b

    .line 963
    .line 964
    :cond_3a
    move/from16 v21, v8

    .line 965
    .line 966
    move/from16 v17, v13

    .line 967
    .line 968
    move v13, v7

    .line 969
    const/high16 v7, 0x3f800000    # 1.0f

    .line 970
    .line 971
    goto :goto_27

    .line 972
    :cond_3b
    cmpl-float v17, v20, v36

    .line 973
    .line 974
    if-nez v17, :cond_3c

    .line 975
    .line 976
    iget-object v6, v0, La5/b;->d:La5/a;

    .line 977
    .line 978
    const/high16 v10, 0x3f800000    # 1.0f

    .line 979
    .line 980
    invoke-virtual {v6, v9, v10}, La5/a;->g(La5/h;F)V

    .line 981
    .line 982
    .line 983
    iget-object v6, v0, La5/b;->d:La5/a;

    .line 984
    .line 985
    invoke-virtual {v6, v5, v7}, La5/a;->g(La5/h;F)V

    .line 986
    .line 987
    .line 988
    :goto_26
    move/from16 v21, v8

    .line 989
    .line 990
    move/from16 v17, v13

    .line 991
    .line 992
    goto :goto_28

    .line 993
    :cond_3c
    const/high16 v7, 0x3f800000    # 1.0f

    .line 994
    .line 995
    if-nez v25, :cond_3d

    .line 996
    .line 997
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 998
    .line 999
    invoke-virtual {v5, v6, v7}, La5/a;->g(La5/h;F)V

    .line 1000
    .line 1001
    .line 1002
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 1003
    .line 1004
    const/high16 v6, -0x40800000    # -1.0f

    .line 1005
    .line 1006
    invoke-virtual {v5, v10, v6}, La5/a;->g(La5/h;F)V

    .line 1007
    .line 1008
    .line 1009
    goto :goto_26

    .line 1010
    :cond_3d
    div-float v17, v20, v29

    .line 1011
    .line 1012
    div-float v20, v18, v29

    .line 1013
    .line 1014
    move/from16 v21, v8

    .line 1015
    .line 1016
    div-float v8, v17, v20

    .line 1017
    .line 1018
    move/from16 v17, v13

    .line 1019
    .line 1020
    iget-object v13, v0, La5/b;->d:La5/a;

    .line 1021
    .line 1022
    invoke-virtual {v13, v9, v7}, La5/a;->g(La5/h;F)V

    .line 1023
    .line 1024
    .line 1025
    iget-object v7, v0, La5/b;->d:La5/a;

    .line 1026
    .line 1027
    const/high16 v13, -0x40800000    # -1.0f

    .line 1028
    .line 1029
    invoke-virtual {v7, v5, v13}, La5/a;->g(La5/h;F)V

    .line 1030
    .line 1031
    .line 1032
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 1033
    .line 1034
    invoke-virtual {v5, v10, v8}, La5/a;->g(La5/h;F)V

    .line 1035
    .line 1036
    .line 1037
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 1038
    .line 1039
    neg-float v7, v8

    .line 1040
    invoke-virtual {v5, v6, v7}, La5/a;->g(La5/h;F)V

    .line 1041
    .line 1042
    .line 1043
    goto :goto_28

    .line 1044
    :goto_27
    iget-object v8, v0, La5/b;->d:La5/a;

    .line 1045
    .line 1046
    invoke-virtual {v8, v9, v7}, La5/a;->g(La5/h;F)V

    .line 1047
    .line 1048
    .line 1049
    iget-object v8, v0, La5/b;->d:La5/a;

    .line 1050
    .line 1051
    invoke-virtual {v8, v5, v13}, La5/a;->g(La5/h;F)V

    .line 1052
    .line 1053
    .line 1054
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 1055
    .line 1056
    invoke-virtual {v5, v10, v7}, La5/a;->g(La5/h;F)V

    .line 1057
    .line 1058
    .line 1059
    iget-object v5, v0, La5/b;->d:La5/a;

    .line 1060
    .line 1061
    invoke-virtual {v5, v6, v13}, La5/a;->g(La5/h;F)V

    .line 1062
    .line 1063
    .line 1064
    :goto_28
    invoke-virtual {v1, v0}, La5/c;->c(La5/b;)V

    .line 1065
    .line 1066
    .line 1067
    goto :goto_29

    .line 1068
    :cond_3e
    move-object/from16 v33, v7

    .line 1069
    .line 1070
    move/from16 v21, v8

    .line 1071
    .line 1072
    move/from16 v36, v17

    .line 1073
    .line 1074
    move/from16 v17, v13

    .line 1075
    .line 1076
    :goto_29
    move/from16 v10, v18

    .line 1077
    .line 1078
    move-object/from16 v9, v33

    .line 1079
    .line 1080
    :goto_2a
    add-int/lit8 v8, v21, 0x1

    .line 1081
    .line 1082
    const/4 v7, 0x1

    .line 1083
    move-object/from16 v0, p0

    .line 1084
    .line 1085
    move/from16 v13, v17

    .line 1086
    .line 1087
    move-object/from16 v5, v30

    .line 1088
    .line 1089
    move/from16 v6, v31

    .line 1090
    .line 1091
    move/from16 v17, v36

    .line 1092
    .line 1093
    goto/16 :goto_24

    .line 1094
    .line 1095
    :cond_3f
    move/from16 v17, v13

    .line 1096
    .line 1097
    if-eqz v12, :cond_40

    .line 1098
    .line 1099
    if-eq v12, v2, :cond_41

    .line 1100
    .line 1101
    if-eqz v37, :cond_40

    .line 1102
    .line 1103
    goto :goto_2b

    .line 1104
    :cond_40
    move-object v0, v2

    .line 1105
    const/16 v28, 0x2

    .line 1106
    .line 1107
    goto :goto_31

    .line 1108
    :cond_41
    :goto_2b
    aget-object v0, v19, v15

    .line 1109
    .line 1110
    iget-object v3, v11, Lh5/d;->R:[Lh5/c;

    .line 1111
    .line 1112
    add-int/lit8 v5, v15, 0x1

    .line 1113
    .line 1114
    aget-object v3, v3, v5

    .line 1115
    .line 1116
    iget-object v0, v0, Lh5/c;->f:Lh5/c;

    .line 1117
    .line 1118
    if-eqz v0, :cond_42

    .line 1119
    .line 1120
    iget-object v0, v0, Lh5/c;->i:La5/h;

    .line 1121
    .line 1122
    goto :goto_2c

    .line 1123
    :cond_42
    move-object/from16 v0, v16

    .line 1124
    .line 1125
    :goto_2c
    iget-object v6, v3, Lh5/c;->f:Lh5/c;

    .line 1126
    .line 1127
    if-eqz v6, :cond_43

    .line 1128
    .line 1129
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 1130
    .line 1131
    goto :goto_2d

    .line 1132
    :cond_43
    move-object/from16 v6, v16

    .line 1133
    .line 1134
    :goto_2d
    iget-object v7, v12, Lh5/d;->R:[Lh5/c;

    .line 1135
    .line 1136
    aget-object v7, v7, v15

    .line 1137
    .line 1138
    if-eqz v2, :cond_44

    .line 1139
    .line 1140
    iget-object v3, v2, Lh5/d;->R:[Lh5/c;

    .line 1141
    .line 1142
    aget-object v3, v3, v5

    .line 1143
    .line 1144
    :cond_44
    if-eqz v0, :cond_46

    .line 1145
    .line 1146
    if-eqz v6, :cond_46

    .line 1147
    .line 1148
    if-nez p3, :cond_45

    .line 1149
    .line 1150
    iget v4, v4, Lh5/d;->e0:F

    .line 1151
    .line 1152
    :goto_2e
    move v5, v4

    .line 1153
    goto :goto_2f

    .line 1154
    :cond_45
    iget v4, v4, Lh5/d;->f0:F

    .line 1155
    .line 1156
    goto :goto_2e

    .line 1157
    :goto_2f
    invoke-virtual {v7}, Lh5/c;->e()I

    .line 1158
    .line 1159
    .line 1160
    move-result v4

    .line 1161
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 1162
    .line 1163
    .line 1164
    move-result v8

    .line 1165
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 1166
    .line 1167
    iget-object v3, v3, Lh5/c;->i:La5/h;

    .line 1168
    .line 1169
    const/4 v9, 0x7

    .line 1170
    move-object/from16 v28, v3

    .line 1171
    .line 1172
    move-object v3, v0

    .line 1173
    move-object v0, v2

    .line 1174
    move-object v2, v7

    .line 1175
    move-object/from16 v7, v28

    .line 1176
    .line 1177
    const/16 v28, 0x2

    .line 1178
    .line 1179
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    .line 1180
    .line 1181
    .line 1182
    goto :goto_30

    .line 1183
    :cond_46
    move-object v0, v2

    .line 1184
    const/16 v28, 0x2

    .line 1185
    .line 1186
    :cond_47
    :goto_30
    move-object/from16 v1, p1

    .line 1187
    .line 1188
    goto/16 :goto_45

    .line 1189
    .line 1190
    :goto_31
    if-eqz v27, :cond_59

    .line 1191
    .line 1192
    if-eqz v12, :cond_59

    .line 1193
    .line 1194
    iget v1, v3, Lh5/b;->j:I

    .line 1195
    .line 1196
    if-lez v1, :cond_48

    .line 1197
    .line 1198
    iget v2, v3, Lh5/b;->i:I

    .line 1199
    .line 1200
    if-ne v2, v1, :cond_48

    .line 1201
    .line 1202
    const/16 v22, 0x1

    .line 1203
    .line 1204
    goto :goto_32

    .line 1205
    :cond_48
    const/16 v22, 0x0

    .line 1206
    .line 1207
    :goto_32
    move-object v10, v12

    .line 1208
    move-object v13, v10

    .line 1209
    :goto_33
    if-eqz v10, :cond_47

    .line 1210
    .line 1211
    iget-object v1, v10, Lh5/d;->R:[Lh5/c;

    .line 1212
    .line 1213
    iget-object v2, v10, Lh5/d;->n0:[Lh5/d;

    .line 1214
    .line 1215
    aget-object v2, v2, p3

    .line 1216
    .line 1217
    :goto_34
    if-eqz v2, :cond_49

    .line 1218
    .line 1219
    iget v3, v2, Lh5/d;->h0:I

    .line 1220
    .line 1221
    const/16 v4, 0x8

    .line 1222
    .line 1223
    if-ne v3, v4, :cond_4a

    .line 1224
    .line 1225
    iget-object v2, v2, Lh5/d;->n0:[Lh5/d;

    .line 1226
    .line 1227
    aget-object v2, v2, p3

    .line 1228
    .line 1229
    goto :goto_34

    .line 1230
    :cond_49
    const/16 v4, 0x8

    .line 1231
    .line 1232
    :cond_4a
    if-nez v2, :cond_4c

    .line 1233
    .line 1234
    if-ne v10, v0, :cond_4b

    .line 1235
    .line 1236
    goto :goto_35

    .line 1237
    :cond_4b
    move-object/from16 v18, v2

    .line 1238
    .line 1239
    move-object/from16 v20, v19

    .line 1240
    .line 1241
    const/16 v32, 0x5

    .line 1242
    .line 1243
    move-object/from16 v19, v13

    .line 1244
    .line 1245
    move v13, v4

    .line 1246
    goto/16 :goto_3b

    .line 1247
    .line 1248
    :cond_4c
    :goto_35
    aget-object v3, v1, v15

    .line 1249
    .line 1250
    iget-object v5, v3, Lh5/c;->i:La5/h;

    .line 1251
    .line 1252
    iget-object v6, v3, Lh5/c;->f:Lh5/c;

    .line 1253
    .line 1254
    if-eqz v6, :cond_4d

    .line 1255
    .line 1256
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 1257
    .line 1258
    goto :goto_36

    .line 1259
    :cond_4d
    move-object/from16 v6, v16

    .line 1260
    .line 1261
    :goto_36
    if-eq v13, v10, :cond_4e

    .line 1262
    .line 1263
    iget-object v6, v13, Lh5/d;->R:[Lh5/c;

    .line 1264
    .line 1265
    add-int/lit8 v7, v15, 0x1

    .line 1266
    .line 1267
    aget-object v6, v6, v7

    .line 1268
    .line 1269
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 1270
    .line 1271
    goto :goto_37

    .line 1272
    :cond_4e
    if-ne v10, v12, :cond_50

    .line 1273
    .line 1274
    aget-object v6, v19, v15

    .line 1275
    .line 1276
    iget-object v6, v6, Lh5/c;->f:Lh5/c;

    .line 1277
    .line 1278
    if-eqz v6, :cond_4f

    .line 1279
    .line 1280
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 1281
    .line 1282
    goto :goto_37

    .line 1283
    :cond_4f
    move-object/from16 v6, v16

    .line 1284
    .line 1285
    :cond_50
    :goto_37
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 1286
    .line 1287
    .line 1288
    move-result v3

    .line 1289
    add-int/lit8 v7, v15, 0x1

    .line 1290
    .line 1291
    aget-object v8, v1, v7

    .line 1292
    .line 1293
    invoke-virtual {v8}, Lh5/c;->e()I

    .line 1294
    .line 1295
    .line 1296
    move-result v8

    .line 1297
    if-eqz v2, :cond_51

    .line 1298
    .line 1299
    iget-object v9, v2, Lh5/d;->R:[Lh5/c;

    .line 1300
    .line 1301
    aget-object v9, v9, v15

    .line 1302
    .line 1303
    iget-object v4, v9, Lh5/c;->i:La5/h;

    .line 1304
    .line 1305
    goto :goto_38

    .line 1306
    :cond_51
    iget-object v4, v11, Lh5/d;->R:[Lh5/c;

    .line 1307
    .line 1308
    aget-object v4, v4, v7

    .line 1309
    .line 1310
    iget-object v9, v4, Lh5/c;->f:Lh5/c;

    .line 1311
    .line 1312
    if-eqz v9, :cond_52

    .line 1313
    .line 1314
    iget-object v4, v9, Lh5/c;->i:La5/h;

    .line 1315
    .line 1316
    goto :goto_38

    .line 1317
    :cond_52
    move-object/from16 v4, v16

    .line 1318
    .line 1319
    :goto_38
    aget-object v1, v1, v7

    .line 1320
    .line 1321
    iget-object v1, v1, Lh5/c;->i:La5/h;

    .line 1322
    .line 1323
    if-eqz v9, :cond_53

    .line 1324
    .line 1325
    invoke-virtual {v9}, Lh5/c;->e()I

    .line 1326
    .line 1327
    .line 1328
    move-result v9

    .line 1329
    add-int/2addr v8, v9

    .line 1330
    :cond_53
    iget-object v9, v13, Lh5/d;->R:[Lh5/c;

    .line 1331
    .line 1332
    aget-object v9, v9, v7

    .line 1333
    .line 1334
    invoke-virtual {v9}, Lh5/c;->e()I

    .line 1335
    .line 1336
    .line 1337
    move-result v9

    .line 1338
    add-int/2addr v9, v3

    .line 1339
    if-eqz v5, :cond_57

    .line 1340
    .line 1341
    if-eqz v6, :cond_57

    .line 1342
    .line 1343
    if-eqz v4, :cond_57

    .line 1344
    .line 1345
    if-eqz v1, :cond_57

    .line 1346
    .line 1347
    if-ne v10, v12, :cond_54

    .line 1348
    .line 1349
    iget-object v3, v12, Lh5/d;->R:[Lh5/c;

    .line 1350
    .line 1351
    aget-object v3, v3, v15

    .line 1352
    .line 1353
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 1354
    .line 1355
    .line 1356
    move-result v9

    .line 1357
    :cond_54
    if-ne v10, v0, :cond_55

    .line 1358
    .line 1359
    iget-object v3, v0, Lh5/d;->R:[Lh5/c;

    .line 1360
    .line 1361
    aget-object v3, v3, v7

    .line 1362
    .line 1363
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 1364
    .line 1365
    .line 1366
    move-result v8

    .line 1367
    :cond_55
    move-object v3, v6

    .line 1368
    move-object v6, v4

    .line 1369
    move v4, v9

    .line 1370
    if-eqz v22, :cond_56

    .line 1371
    .line 1372
    const/16 v9, 0x8

    .line 1373
    .line 1374
    :goto_39
    move-object v7, v2

    .line 1375
    move-object v2, v5

    .line 1376
    goto :goto_3a

    .line 1377
    :cond_56
    const/4 v9, 0x5

    .line 1378
    goto :goto_39

    .line 1379
    :goto_3a
    const/high16 v5, 0x3f000000    # 0.5f

    .line 1380
    .line 1381
    move-object/from16 v18, v7

    .line 1382
    .line 1383
    move-object/from16 v20, v19

    .line 1384
    .line 1385
    const/16 v32, 0x5

    .line 1386
    .line 1387
    move-object v7, v1

    .line 1388
    move-object/from16 v19, v13

    .line 1389
    .line 1390
    const/16 v13, 0x8

    .line 1391
    .line 1392
    move-object/from16 v1, p1

    .line 1393
    .line 1394
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    .line 1395
    .line 1396
    .line 1397
    goto :goto_3b

    .line 1398
    :cond_57
    move-object/from16 v18, v2

    .line 1399
    .line 1400
    move-object/from16 v20, v19

    .line 1401
    .line 1402
    const/16 v32, 0x5

    .line 1403
    .line 1404
    move-object/from16 v19, v13

    .line 1405
    .line 1406
    const/16 v13, 0x8

    .line 1407
    .line 1408
    :goto_3b
    iget v1, v10, Lh5/d;->h0:I

    .line 1409
    .line 1410
    if-eq v1, v13, :cond_58

    .line 1411
    .line 1412
    move-object/from16 v19, v10

    .line 1413
    .line 1414
    :cond_58
    move-object/from16 v10, v18

    .line 1415
    .line 1416
    move-object/from16 v13, v19

    .line 1417
    .line 1418
    move-object/from16 v19, v20

    .line 1419
    .line 1420
    goto/16 :goto_33

    .line 1421
    .line 1422
    :cond_59
    move-object/from16 v20, v19

    .line 1423
    .line 1424
    const/16 v13, 0x8

    .line 1425
    .line 1426
    if-eqz v23, :cond_47

    .line 1427
    .line 1428
    if-eqz v12, :cond_47

    .line 1429
    .line 1430
    iget v1, v3, Lh5/b;->j:I

    .line 1431
    .line 1432
    if-lez v1, :cond_5a

    .line 1433
    .line 1434
    iget v2, v3, Lh5/b;->i:I

    .line 1435
    .line 1436
    if-ne v2, v1, :cond_5a

    .line 1437
    .line 1438
    const/16 v22, 0x1

    .line 1439
    .line 1440
    goto :goto_3c

    .line 1441
    :cond_5a
    const/16 v22, 0x0

    .line 1442
    .line 1443
    :goto_3c
    move-object v1, v12

    .line 1444
    move-object v10, v1

    .line 1445
    :goto_3d
    if-eqz v10, :cond_65

    .line 1446
    .line 1447
    iget-object v2, v10, Lh5/d;->R:[Lh5/c;

    .line 1448
    .line 1449
    iget-object v3, v10, Lh5/d;->n0:[Lh5/d;

    .line 1450
    .line 1451
    aget-object v3, v3, p3

    .line 1452
    .line 1453
    :goto_3e
    if-eqz v3, :cond_5b

    .line 1454
    .line 1455
    iget v4, v3, Lh5/d;->h0:I

    .line 1456
    .line 1457
    if-ne v4, v13, :cond_5b

    .line 1458
    .line 1459
    iget-object v3, v3, Lh5/d;->n0:[Lh5/d;

    .line 1460
    .line 1461
    aget-object v3, v3, p3

    .line 1462
    .line 1463
    goto :goto_3e

    .line 1464
    :cond_5b
    if-eq v10, v12, :cond_63

    .line 1465
    .line 1466
    if-eq v10, v0, :cond_63

    .line 1467
    .line 1468
    if-eqz v3, :cond_63

    .line 1469
    .line 1470
    if-ne v3, v0, :cond_5c

    .line 1471
    .line 1472
    move-object/from16 v3, v16

    .line 1473
    .line 1474
    :cond_5c
    aget-object v4, v2, v15

    .line 1475
    .line 1476
    move-object v5, v2

    .line 1477
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 1478
    .line 1479
    iget-object v6, v1, Lh5/d;->R:[Lh5/c;

    .line 1480
    .line 1481
    add-int/lit8 v7, v15, 0x1

    .line 1482
    .line 1483
    aget-object v6, v6, v7

    .line 1484
    .line 1485
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 1486
    .line 1487
    invoke-virtual {v4}, Lh5/c;->e()I

    .line 1488
    .line 1489
    .line 1490
    move-result v4

    .line 1491
    aget-object v8, v5, v7

    .line 1492
    .line 1493
    invoke-virtual {v8}, Lh5/c;->e()I

    .line 1494
    .line 1495
    .line 1496
    move-result v8

    .line 1497
    if-eqz v3, :cond_5e

    .line 1498
    .line 1499
    iget-object v5, v3, Lh5/d;->R:[Lh5/c;

    .line 1500
    .line 1501
    aget-object v5, v5, v15

    .line 1502
    .line 1503
    iget-object v9, v5, Lh5/c;->i:La5/h;

    .line 1504
    .line 1505
    iget-object v13, v5, Lh5/c;->f:Lh5/c;

    .line 1506
    .line 1507
    if-eqz v13, :cond_5d

    .line 1508
    .line 1509
    iget-object v13, v13, Lh5/c;->i:La5/h;

    .line 1510
    .line 1511
    goto :goto_40

    .line 1512
    :cond_5d
    move-object/from16 v13, v16

    .line 1513
    .line 1514
    goto :goto_40

    .line 1515
    :cond_5e
    iget-object v9, v0, Lh5/d;->R:[Lh5/c;

    .line 1516
    .line 1517
    aget-object v9, v9, v15

    .line 1518
    .line 1519
    if-eqz v9, :cond_5f

    .line 1520
    .line 1521
    iget-object v13, v9, Lh5/c;->i:La5/h;

    .line 1522
    .line 1523
    goto :goto_3f

    .line 1524
    :cond_5f
    move-object/from16 v13, v16

    .line 1525
    .line 1526
    :goto_3f
    aget-object v5, v5, v7

    .line 1527
    .line 1528
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 1529
    .line 1530
    move-object/from16 v39, v13

    .line 1531
    .line 1532
    move-object v13, v5

    .line 1533
    move-object v5, v9

    .line 1534
    move-object/from16 v9, v39

    .line 1535
    .line 1536
    :goto_40
    if-eqz v5, :cond_60

    .line 1537
    .line 1538
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 1539
    .line 1540
    .line 1541
    move-result v5

    .line 1542
    add-int/2addr v8, v5

    .line 1543
    :cond_60
    iget-object v5, v1, Lh5/d;->R:[Lh5/c;

    .line 1544
    .line 1545
    aget-object v5, v5, v7

    .line 1546
    .line 1547
    invoke-virtual {v5}, Lh5/c;->e()I

    .line 1548
    .line 1549
    .line 1550
    move-result v5

    .line 1551
    add-int/2addr v4, v5

    .line 1552
    move-object v5, v3

    .line 1553
    move-object v3, v6

    .line 1554
    move-object v6, v9

    .line 1555
    if-eqz v22, :cond_61

    .line 1556
    .line 1557
    const/16 v9, 0x8

    .line 1558
    .line 1559
    goto :goto_41

    .line 1560
    :cond_61
    const/4 v9, 0x4

    .line 1561
    :goto_41
    if-eqz v2, :cond_62

    .line 1562
    .line 1563
    if-eqz v3, :cond_62

    .line 1564
    .line 1565
    if-eqz v6, :cond_62

    .line 1566
    .line 1567
    if-eqz v13, :cond_62

    .line 1568
    .line 1569
    move-object v7, v5

    .line 1570
    const/high16 v5, 0x3f000000    # 0.5f

    .line 1571
    .line 1572
    move-object/from16 v18, v7

    .line 1573
    .line 1574
    move-object v7, v13

    .line 1575
    const/16 v31, 0x4

    .line 1576
    .line 1577
    move-object v13, v1

    .line 1578
    move-object/from16 v1, p1

    .line 1579
    .line 1580
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    .line 1581
    .line 1582
    .line 1583
    goto :goto_42

    .line 1584
    :cond_62
    move-object v13, v1

    .line 1585
    move-object/from16 v18, v5

    .line 1586
    .line 1587
    const/16 v31, 0x4

    .line 1588
    .line 1589
    move-object/from16 v1, p1

    .line 1590
    .line 1591
    :goto_42
    move-object/from16 v3, v18

    .line 1592
    .line 1593
    goto :goto_43

    .line 1594
    :cond_63
    move-object v13, v1

    .line 1595
    const/16 v31, 0x4

    .line 1596
    .line 1597
    move-object/from16 v1, p1

    .line 1598
    .line 1599
    :goto_43
    iget v2, v10, Lh5/d;->h0:I

    .line 1600
    .line 1601
    const/16 v4, 0x8

    .line 1602
    .line 1603
    if-eq v2, v4, :cond_64

    .line 1604
    .line 1605
    move-object v13, v10

    .line 1606
    :cond_64
    move-object v10, v3

    .line 1607
    move-object v1, v13

    .line 1608
    move v13, v4

    .line 1609
    goto/16 :goto_3d

    .line 1610
    .line 1611
    :cond_65
    move-object/from16 v1, p1

    .line 1612
    .line 1613
    iget-object v2, v12, Lh5/d;->R:[Lh5/c;

    .line 1614
    .line 1615
    aget-object v2, v2, v15

    .line 1616
    .line 1617
    aget-object v3, v20, v15

    .line 1618
    .line 1619
    iget-object v3, v3, Lh5/c;->f:Lh5/c;

    .line 1620
    .line 1621
    iget-object v4, v0, Lh5/d;->R:[Lh5/c;

    .line 1622
    .line 1623
    add-int/lit8 v5, v15, 0x1

    .line 1624
    .line 1625
    aget-object v10, v4, v5

    .line 1626
    .line 1627
    iget-object v4, v11, Lh5/d;->R:[Lh5/c;

    .line 1628
    .line 1629
    aget-object v4, v4, v5

    .line 1630
    .line 1631
    iget-object v13, v4, Lh5/c;->f:Lh5/c;

    .line 1632
    .line 1633
    const/4 v9, 0x5

    .line 1634
    if-eqz v3, :cond_67

    .line 1635
    .line 1636
    if-eq v12, v0, :cond_66

    .line 1637
    .line 1638
    iget-object v4, v2, Lh5/c;->i:La5/h;

    .line 1639
    .line 1640
    iget-object v3, v3, Lh5/c;->i:La5/h;

    .line 1641
    .line 1642
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 1643
    .line 1644
    .line 1645
    move-result v2

    .line 1646
    invoke-virtual {v1, v4, v3, v2, v9}, La5/c;->e(La5/h;La5/h;II)V

    .line 1647
    .line 1648
    .line 1649
    goto :goto_44

    .line 1650
    :cond_66
    if-eqz v13, :cond_67

    .line 1651
    .line 1652
    move-object v4, v2

    .line 1653
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 1654
    .line 1655
    iget-object v3, v3, Lh5/c;->i:La5/h;

    .line 1656
    .line 1657
    invoke-virtual {v4}, Lh5/c;->e()I

    .line 1658
    .line 1659
    .line 1660
    move-result v4

    .line 1661
    iget-object v6, v10, Lh5/c;->i:La5/h;

    .line 1662
    .line 1663
    iget-object v7, v13, Lh5/c;->i:La5/h;

    .line 1664
    .line 1665
    invoke-virtual {v10}, Lh5/c;->e()I

    .line 1666
    .line 1667
    .line 1668
    move-result v8

    .line 1669
    const/high16 v5, 0x3f000000    # 0.5f

    .line 1670
    .line 1671
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    .line 1672
    .line 1673
    .line 1674
    :cond_67
    :goto_44
    if-eqz v13, :cond_68

    .line 1675
    .line 1676
    if-eq v12, v0, :cond_68

    .line 1677
    .line 1678
    iget-object v2, v10, Lh5/c;->i:La5/h;

    .line 1679
    .line 1680
    iget-object v3, v13, Lh5/c;->i:La5/h;

    .line 1681
    .line 1682
    invoke-virtual {v10}, Lh5/c;->e()I

    .line 1683
    .line 1684
    .line 1685
    move-result v4

    .line 1686
    neg-int v4, v4

    .line 1687
    invoke-virtual {v1, v2, v3, v4, v9}, La5/c;->e(La5/h;La5/h;II)V

    .line 1688
    .line 1689
    .line 1690
    :cond_68
    :goto_45
    if-nez v27, :cond_69

    .line 1691
    .line 1692
    if-eqz v23, :cond_70

    .line 1693
    .line 1694
    :cond_69
    if-eqz v12, :cond_70

    .line 1695
    .line 1696
    if-eq v12, v0, :cond_70

    .line 1697
    .line 1698
    iget-object v2, v12, Lh5/d;->R:[Lh5/c;

    .line 1699
    .line 1700
    aget-object v3, v2, v15

    .line 1701
    .line 1702
    if-nez v0, :cond_6a

    .line 1703
    .line 1704
    move-object v0, v12

    .line 1705
    :cond_6a
    iget-object v4, v0, Lh5/d;->R:[Lh5/c;

    .line 1706
    .line 1707
    add-int/lit8 v5, v15, 0x1

    .line 1708
    .line 1709
    aget-object v6, v4, v5

    .line 1710
    .line 1711
    iget-object v7, v3, Lh5/c;->f:Lh5/c;

    .line 1712
    .line 1713
    if-eqz v7, :cond_6b

    .line 1714
    .line 1715
    iget-object v7, v7, Lh5/c;->i:La5/h;

    .line 1716
    .line 1717
    goto :goto_46

    .line 1718
    :cond_6b
    move-object/from16 v7, v16

    .line 1719
    .line 1720
    :goto_46
    iget-object v8, v6, Lh5/c;->f:Lh5/c;

    .line 1721
    .line 1722
    if-eqz v8, :cond_6c

    .line 1723
    .line 1724
    iget-object v8, v8, Lh5/c;->i:La5/h;

    .line 1725
    .line 1726
    goto :goto_47

    .line 1727
    :cond_6c
    move-object/from16 v8, v16

    .line 1728
    .line 1729
    :goto_47
    if-eq v11, v0, :cond_6e

    .line 1730
    .line 1731
    iget-object v8, v11, Lh5/d;->R:[Lh5/c;

    .line 1732
    .line 1733
    aget-object v8, v8, v5

    .line 1734
    .line 1735
    iget-object v8, v8, Lh5/c;->f:Lh5/c;

    .line 1736
    .line 1737
    if-eqz v8, :cond_6d

    .line 1738
    .line 1739
    iget-object v8, v8, Lh5/c;->i:La5/h;

    .line 1740
    .line 1741
    move-object/from16 v16, v8

    .line 1742
    .line 1743
    :cond_6d
    move-object/from16 v8, v16

    .line 1744
    .line 1745
    :cond_6e
    if-ne v12, v0, :cond_6f

    .line 1746
    .line 1747
    aget-object v6, v2, v5

    .line 1748
    .line 1749
    :cond_6f
    if-eqz v7, :cond_70

    .line 1750
    .line 1751
    if-eqz v8, :cond_70

    .line 1752
    .line 1753
    move-object v0, v4

    .line 1754
    invoke-virtual {v3}, Lh5/c;->e()I

    .line 1755
    .line 1756
    .line 1757
    move-result v4

    .line 1758
    aget-object v0, v0, v5

    .line 1759
    .line 1760
    invoke-virtual {v0}, Lh5/c;->e()I

    .line 1761
    .line 1762
    .line 1763
    move-result v0

    .line 1764
    iget-object v2, v3, Lh5/c;->i:La5/h;

    .line 1765
    .line 1766
    iget-object v3, v6, Lh5/c;->i:La5/h;

    .line 1767
    .line 1768
    const/4 v9, 0x5

    .line 1769
    const/high16 v5, 0x3f000000    # 0.5f

    .line 1770
    .line 1771
    move-object v6, v7

    .line 1772
    move-object v7, v3

    .line 1773
    move-object v3, v6

    .line 1774
    move-object v6, v8

    .line 1775
    move v8, v0

    .line 1776
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    .line 1777
    .line 1778
    .line 1779
    :cond_70
    :goto_48
    add-int/lit8 v2, v26, 0x1

    .line 1780
    .line 1781
    move-object/from16 v0, p0

    .line 1782
    .line 1783
    move-object/from16 v1, p1

    .line 1784
    .line 1785
    move-object/from16 v10, p2

    .line 1786
    .line 1787
    move/from16 v13, v17

    .line 1788
    .line 1789
    goto/16 :goto_2

    .line 1790
    .line 1791
    :cond_71
    return-void
.end method

.method public static b(Lh5/e;La5/c;Lh5/d;)V
    .locals 12

    .line 1
    const/4 v0, -0x1

    .line 2
    iput v0, p2, Lh5/d;->p:I

    .line 3
    .line 4
    iget-object v1, p2, Lh5/d;->N:Lh5/c;

    .line 5
    .line 6
    iget-object v2, p2, Lh5/d;->q0:[I

    .line 7
    .line 8
    iget-object v3, p2, Lh5/d;->M:Lh5/c;

    .line 9
    .line 10
    iget-object v4, p2, Lh5/d;->K:Lh5/c;

    .line 11
    .line 12
    iget-object v5, p2, Lh5/d;->L:Lh5/c;

    .line 13
    .line 14
    iget-object v6, p2, Lh5/d;->J:Lh5/c;

    .line 15
    .line 16
    iput v0, p2, Lh5/d;->q:I

    .line 17
    .line 18
    iget-object v0, p0, Lh5/d;->q0:[I

    .line 19
    .line 20
    const/4 v7, 0x0

    .line 21
    aget v8, v0, v7

    .line 22
    .line 23
    const/4 v9, 0x2

    .line 24
    const/4 v10, 0x4

    .line 25
    if-eq v8, v9, :cond_0

    .line 26
    .line 27
    aget v7, v2, v7

    .line 28
    .line 29
    if-ne v7, v10, :cond_0

    .line 30
    .line 31
    iget v7, v6, Lh5/c;->g:I

    .line 32
    .line 33
    invoke-virtual {p0}, Lh5/d;->r()I

    .line 34
    .line 35
    .line 36
    move-result v8

    .line 37
    iget v11, v5, Lh5/c;->g:I

    .line 38
    .line 39
    sub-int/2addr v8, v11

    .line 40
    invoke-virtual {p1, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 41
    .line 42
    .line 43
    move-result-object v11

    .line 44
    iput-object v11, v6, Lh5/c;->i:La5/h;

    .line 45
    .line 46
    invoke-virtual {p1, v5}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 47
    .line 48
    .line 49
    move-result-object v11

    .line 50
    iput-object v11, v5, Lh5/c;->i:La5/h;

    .line 51
    .line 52
    iget-object v6, v6, Lh5/c;->i:La5/h;

    .line 53
    .line 54
    invoke-virtual {p1, v6, v7}, La5/c;->d(La5/h;I)V

    .line 55
    .line 56
    .line 57
    iget-object v5, v5, Lh5/c;->i:La5/h;

    .line 58
    .line 59
    invoke-virtual {p1, v5, v8}, La5/c;->d(La5/h;I)V

    .line 60
    .line 61
    .line 62
    iput v9, p2, Lh5/d;->p:I

    .line 63
    .line 64
    iput v7, p2, Lh5/d;->Z:I

    .line 65
    .line 66
    sub-int/2addr v8, v7

    .line 67
    iput v8, p2, Lh5/d;->V:I

    .line 68
    .line 69
    iget v5, p2, Lh5/d;->c0:I

    .line 70
    .line 71
    if-ge v8, v5, :cond_0

    .line 72
    .line 73
    iput v5, p2, Lh5/d;->V:I

    .line 74
    .line 75
    :cond_0
    const/4 v5, 0x1

    .line 76
    aget v0, v0, v5

    .line 77
    .line 78
    if-eq v0, v9, :cond_3

    .line 79
    .line 80
    aget v0, v2, v5

    .line 81
    .line 82
    if-ne v0, v10, :cond_3

    .line 83
    .line 84
    iget v0, v4, Lh5/c;->g:I

    .line 85
    .line 86
    invoke-virtual {p0}, Lh5/d;->l()I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    iget v2, v3, Lh5/c;->g:I

    .line 91
    .line 92
    sub-int/2addr p0, v2

    .line 93
    invoke-virtual {p1, v4}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    iput-object v2, v4, Lh5/c;->i:La5/h;

    .line 98
    .line 99
    invoke-virtual {p1, v3}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    iput-object v2, v3, Lh5/c;->i:La5/h;

    .line 104
    .line 105
    iget-object v2, v4, Lh5/c;->i:La5/h;

    .line 106
    .line 107
    invoke-virtual {p1, v2, v0}, La5/c;->d(La5/h;I)V

    .line 108
    .line 109
    .line 110
    iget-object v2, v3, Lh5/c;->i:La5/h;

    .line 111
    .line 112
    invoke-virtual {p1, v2, p0}, La5/c;->d(La5/h;I)V

    .line 113
    .line 114
    .line 115
    iget v2, p2, Lh5/d;->b0:I

    .line 116
    .line 117
    if-gtz v2, :cond_1

    .line 118
    .line 119
    iget v2, p2, Lh5/d;->h0:I

    .line 120
    .line 121
    const/16 v3, 0x8

    .line 122
    .line 123
    if-ne v2, v3, :cond_2

    .line 124
    .line 125
    :cond_1
    invoke-virtual {p1, v1}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    iput-object v2, v1, Lh5/c;->i:La5/h;

    .line 130
    .line 131
    iget v1, p2, Lh5/d;->b0:I

    .line 132
    .line 133
    add-int/2addr v1, v0

    .line 134
    invoke-virtual {p1, v2, v1}, La5/c;->d(La5/h;I)V

    .line 135
    .line 136
    .line 137
    :cond_2
    iput v9, p2, Lh5/d;->q:I

    .line 138
    .line 139
    iput v0, p2, Lh5/d;->a0:I

    .line 140
    .line 141
    sub-int/2addr p0, v0

    .line 142
    iput p0, p2, Lh5/d;->W:I

    .line 143
    .line 144
    iget p1, p2, Lh5/d;->d0:I

    .line 145
    .line 146
    if-ge p0, p1, :cond_3

    .line 147
    .line 148
    iput p1, p2, Lh5/d;->W:I

    .line 149
    .line 150
    :cond_3
    return-void
.end method

.method public static final c(II)Z
    .locals 0

    .line 1
    and-int/2addr p0, p1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    const/4 p0, 0x1

    .line 5
    return p0

    .line 6
    :cond_0
    const/4 p0, 0x0

    .line 7
    return p0
.end method
