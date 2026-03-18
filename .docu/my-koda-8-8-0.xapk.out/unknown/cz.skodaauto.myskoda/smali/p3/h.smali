.class public final Lp3/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:I

.field public c:I

.field public final d:Ljava/lang/Object;

.field public e:Ljava/lang/Object;

.field public f:Ljava/io/Serializable;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Landroid/util/SparseLongArray;

    invoke-direct {v0}, Landroid/util/SparseLongArray;-><init>()V

    iput-object v0, p0, Lp3/h;->d:Ljava/lang/Object;

    .line 3
    new-instance v0, Landroid/util/SparseBooleanArray;

    invoke-direct {v0}, Landroid/util/SparseBooleanArray;-><init>()V

    iput-object v0, p0, Lp3/h;->e:Ljava/lang/Object;

    .line 4
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lp3/h;->f:Ljava/io/Serializable;

    const/4 v0, -0x1

    .line 5
    iput v0, p0, Lp3/h;->b:I

    .line 6
    iput v0, p0, Lp3/h;->c:I

    return-void
.end method

.method public constructor <init>(Ls11/d;J)V
    .locals 1

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/high16 v0, -0x80000000

    .line 8
    iput v0, p0, Lp3/h;->b:I

    .line 9
    iput v0, p0, Lp3/h;->c:I

    .line 10
    iput-wide p2, p0, Lp3/h;->a:J

    .line 11
    iput-object p1, p0, Lp3/h;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public a(Landroid/view/MotionEvent;Lw3/t;)Lc2/k;
    .locals 49

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v0, Lp3/h;->f:Ljava/io/Serializable;

    .line 8
    .line 9
    check-cast v3, Ljava/util/ArrayList;

    .line 10
    .line 11
    iget-object v4, v0, Lp3/h;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v4, Landroid/util/SparseLongArray;

    .line 14
    .line 15
    iget-object v5, v0, Lp3/h;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v5, Landroid/util/SparseBooleanArray;

    .line 18
    .line 19
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 20
    .line 21
    .line 22
    move-result v6

    .line 23
    const/4 v7, 0x3

    .line 24
    if-eq v6, v7, :cond_1f

    .line 25
    .line 26
    const/4 v8, 0x4

    .line 27
    if-eq v6, v8, :cond_1f

    .line 28
    .line 29
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 30
    .line 31
    .line 32
    move-result v9

    .line 33
    const/4 v10, 0x0

    .line 34
    const/4 v11, 0x1

    .line 35
    if-eq v9, v11, :cond_0

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    invoke-virtual {v1, v10}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 39
    .line 40
    .line 41
    move-result v9

    .line 42
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getSource()I

    .line 43
    .line 44
    .line 45
    move-result v12

    .line 46
    iget v13, v0, Lp3/h;->b:I

    .line 47
    .line 48
    if-ne v9, v13, :cond_1

    .line 49
    .line 50
    iget v13, v0, Lp3/h;->c:I

    .line 51
    .line 52
    if-eq v12, v13, :cond_2

    .line 53
    .line 54
    :cond_1
    iput v9, v0, Lp3/h;->b:I

    .line 55
    .line 56
    iput v12, v0, Lp3/h;->c:I

    .line 57
    .line 58
    invoke-virtual {v5}, Landroid/util/SparseBooleanArray;->clear()V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v4}, Landroid/util/SparseLongArray;->clear()V

    .line 62
    .line 63
    .line 64
    :cond_2
    :goto_0
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 65
    .line 66
    .line 67
    move-result v9

    .line 68
    const/16 v14, 0x9

    .line 69
    .line 70
    if-eqz v9, :cond_5

    .line 71
    .line 72
    const/4 v15, 0x5

    .line 73
    if-eq v9, v15, :cond_5

    .line 74
    .line 75
    if-eq v9, v14, :cond_4

    .line 76
    .line 77
    :cond_3
    const-wide/16 v17, 0x1

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_4
    invoke-virtual {v1, v10}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 81
    .line 82
    .line 83
    move-result v9

    .line 84
    invoke-virtual {v4, v9}, Landroid/util/SparseLongArray;->indexOfKey(I)I

    .line 85
    .line 86
    .line 87
    move-result v15

    .line 88
    if-gez v15, :cond_3

    .line 89
    .line 90
    const-wide/16 v15, 0x1

    .line 91
    .line 92
    iget-wide v12, v0, Lp3/h;->a:J

    .line 93
    .line 94
    move-wide/from16 v17, v15

    .line 95
    .line 96
    add-long v14, v12, v17

    .line 97
    .line 98
    iput-wide v14, v0, Lp3/h;->a:J

    .line 99
    .line 100
    invoke-virtual {v4, v9, v12, v13}, Landroid/util/SparseLongArray;->put(IJ)V

    .line 101
    .line 102
    .line 103
    goto :goto_1

    .line 104
    :cond_5
    const-wide/16 v17, 0x1

    .line 105
    .line 106
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 107
    .line 108
    .line 109
    move-result v9

    .line 110
    invoke-virtual {v1, v9}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 111
    .line 112
    .line 113
    move-result v12

    .line 114
    invoke-virtual {v4, v12}, Landroid/util/SparseLongArray;->indexOfKey(I)I

    .line 115
    .line 116
    .line 117
    move-result v13

    .line 118
    if-gez v13, :cond_6

    .line 119
    .line 120
    iget-wide v13, v0, Lp3/h;->a:J

    .line 121
    .line 122
    add-long v10, v13, v17

    .line 123
    .line 124
    iput-wide v10, v0, Lp3/h;->a:J

    .line 125
    .line 126
    invoke-virtual {v4, v12, v13, v14}, Landroid/util/SparseLongArray;->put(IJ)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v1, v9}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    if-ne v9, v7, :cond_6

    .line 134
    .line 135
    const/4 v9, 0x1

    .line 136
    invoke-virtual {v5, v12, v9}, Landroid/util/SparseBooleanArray;->put(IZ)V

    .line 137
    .line 138
    .line 139
    :cond_6
    :goto_1
    const/16 v9, 0xa

    .line 140
    .line 141
    const/16 v10, 0x9

    .line 142
    .line 143
    if-eq v6, v10, :cond_8

    .line 144
    .line 145
    const/4 v10, 0x7

    .line 146
    if-eq v6, v10, :cond_8

    .line 147
    .line 148
    if-ne v6, v9, :cond_7

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_7
    const/4 v10, 0x0

    .line 152
    goto :goto_3

    .line 153
    :cond_8
    :goto_2
    const/4 v10, 0x1

    .line 154
    :goto_3
    const/16 v11, 0x8

    .line 155
    .line 156
    if-ne v6, v11, :cond_9

    .line 157
    .line 158
    const/4 v12, 0x1

    .line 159
    goto :goto_4

    .line 160
    :cond_9
    const/4 v12, 0x0

    .line 161
    :goto_4
    if-eqz v10, :cond_a

    .line 162
    .line 163
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 164
    .line 165
    .line 166
    move-result v13

    .line 167
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 168
    .line 169
    .line 170
    move-result v13

    .line 171
    const/4 v14, 0x1

    .line 172
    invoke-virtual {v5, v13, v14}, Landroid/util/SparseBooleanArray;->put(IZ)V

    .line 173
    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_a
    const/4 v14, 0x1

    .line 177
    :goto_5
    const/4 v15, 0x6

    .line 178
    if-eq v6, v14, :cond_c

    .line 179
    .line 180
    if-eq v6, v15, :cond_b

    .line 181
    .line 182
    const/4 v6, -0x1

    .line 183
    goto :goto_6

    .line 184
    :cond_b
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 185
    .line 186
    .line 187
    move-result v6

    .line 188
    goto :goto_6

    .line 189
    :cond_c
    const/4 v6, 0x0

    .line 190
    :goto_6
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 194
    .line 195
    .line 196
    move-result v14

    .line 197
    const/4 v13, 0x0

    .line 198
    :goto_7
    if-ge v13, v14, :cond_19

    .line 199
    .line 200
    if-nez v10, :cond_e

    .line 201
    .line 202
    if-eq v13, v6, :cond_e

    .line 203
    .line 204
    if-eqz v12, :cond_d

    .line 205
    .line 206
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getButtonState()I

    .line 207
    .line 208
    .line 209
    move-result v19

    .line 210
    if-eqz v19, :cond_e

    .line 211
    .line 212
    :cond_d
    const/16 v29, 0x1

    .line 213
    .line 214
    goto :goto_8

    .line 215
    :cond_e
    const/16 v29, 0x0

    .line 216
    .line 217
    :goto_8
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 218
    .line 219
    .line 220
    move-result v15

    .line 221
    invoke-virtual {v4, v15}, Landroid/util/SparseLongArray;->indexOfKey(I)I

    .line 222
    .line 223
    .line 224
    move-result v9

    .line 225
    if-ltz v9, :cond_f

    .line 226
    .line 227
    invoke-virtual {v4, v9}, Landroid/util/SparseLongArray;->valueAt(I)J

    .line 228
    .line 229
    .line 230
    move-result-wide v20

    .line 231
    move/from16 v39, v10

    .line 232
    .line 233
    move/from16 v38, v12

    .line 234
    .line 235
    move-wide/from16 v21, v20

    .line 236
    .line 237
    goto :goto_9

    .line 238
    :cond_f
    move/from16 v38, v12

    .line 239
    .line 240
    iget-wide v11, v0, Lp3/h;->a:J

    .line 241
    .line 242
    move/from16 v39, v10

    .line 243
    .line 244
    add-long v9, v11, v17

    .line 245
    .line 246
    iput-wide v9, v0, Lp3/h;->a:J

    .line 247
    .line 248
    invoke-virtual {v4, v15, v11, v12}, Landroid/util/SparseLongArray;->put(IJ)V

    .line 249
    .line 250
    .line 251
    move-wide/from16 v21, v11

    .line 252
    .line 253
    :goto_9
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getPressure(I)F

    .line 254
    .line 255
    .line 256
    move-result v30

    .line 257
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getX(I)F

    .line 258
    .line 259
    .line 260
    move-result v9

    .line 261
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getY(I)F

    .line 262
    .line 263
    .line 264
    move-result v10

    .line 265
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 266
    .line 267
    .line 268
    move-result v9

    .line 269
    int-to-long v11, v9

    .line 270
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 271
    .line 272
    .line 273
    move-result v9

    .line 274
    int-to-long v9, v9

    .line 275
    const/16 v15, 0x20

    .line 276
    .line 277
    shl-long/2addr v11, v15

    .line 278
    const-wide v23, 0xffffffffL

    .line 279
    .line 280
    .line 281
    .line 282
    .line 283
    and-long v9, v9, v23

    .line 284
    .line 285
    or-long/2addr v9, v11

    .line 286
    const/4 v11, 0x0

    .line 287
    invoke-static {v9, v10, v7, v11}, Ld3/b;->a(JIF)J

    .line 288
    .line 289
    .line 290
    move-result-wide v36

    .line 291
    if-nez v13, :cond_10

    .line 292
    .line 293
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getRawX()F

    .line 294
    .line 295
    .line 296
    move-result v9

    .line 297
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getRawY()F

    .line 298
    .line 299
    .line 300
    move-result v10

    .line 301
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 302
    .line 303
    .line 304
    move-result v9

    .line 305
    move/from16 v25, v11

    .line 306
    .line 307
    int-to-long v11, v9

    .line 308
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 309
    .line 310
    .line 311
    move-result v9

    .line 312
    int-to-long v9, v9

    .line 313
    shl-long/2addr v11, v15

    .line 314
    and-long v9, v9, v23

    .line 315
    .line 316
    or-long/2addr v9, v11

    .line 317
    invoke-virtual {v2, v9, v10}, Lw3/t;->D(J)J

    .line 318
    .line 319
    .line 320
    move-result-wide v11

    .line 321
    :goto_a
    move-wide/from16 v27, v11

    .line 322
    .line 323
    goto :goto_b

    .line 324
    :cond_10
    move/from16 v25, v11

    .line 325
    .line 326
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getRawX(I)F

    .line 327
    .line 328
    .line 329
    move-result v9

    .line 330
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getRawY(I)F

    .line 331
    .line 332
    .line 333
    move-result v10

    .line 334
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 335
    .line 336
    .line 337
    move-result v9

    .line 338
    int-to-long v11, v9

    .line 339
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 340
    .line 341
    .line 342
    move-result v9

    .line 343
    int-to-long v9, v9

    .line 344
    shl-long/2addr v11, v15

    .line 345
    and-long v9, v9, v23

    .line 346
    .line 347
    or-long/2addr v9, v11

    .line 348
    invoke-virtual {v2, v9, v10}, Lw3/t;->D(J)J

    .line 349
    .line 350
    .line 351
    move-result-wide v11

    .line 352
    goto :goto_a

    .line 353
    :goto_b
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 354
    .line 355
    .line 356
    move-result v11

    .line 357
    if-eqz v11, :cond_11

    .line 358
    .line 359
    const/4 v12, 0x1

    .line 360
    if-eq v11, v12, :cond_15

    .line 361
    .line 362
    const/4 v12, 0x2

    .line 363
    if-eq v11, v12, :cond_14

    .line 364
    .line 365
    if-eq v11, v7, :cond_13

    .line 366
    .line 367
    if-eq v11, v8, :cond_12

    .line 368
    .line 369
    :cond_11
    const/16 v31, 0x0

    .line 370
    .line 371
    goto :goto_c

    .line 372
    :cond_12
    move/from16 v31, v8

    .line 373
    .line 374
    goto :goto_c

    .line 375
    :cond_13
    move/from16 v31, v12

    .line 376
    .line 377
    goto :goto_c

    .line 378
    :cond_14
    move/from16 v31, v7

    .line 379
    .line 380
    goto :goto_c

    .line 381
    :cond_15
    const/16 v31, 0x1

    .line 382
    .line 383
    :goto_c
    new-instance v11, Ljava/util/ArrayList;

    .line 384
    .line 385
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getHistorySize()I

    .line 386
    .line 387
    .line 388
    move-result v12

    .line 389
    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getHistorySize()I

    .line 393
    .line 394
    .line 395
    move-result v12

    .line 396
    const/4 v7, 0x0

    .line 397
    :goto_d
    if-ge v7, v12, :cond_17

    .line 398
    .line 399
    invoke-virtual {v1, v13, v7}, Landroid/view/MotionEvent;->getHistoricalX(II)F

    .line 400
    .line 401
    .line 402
    move-result v26

    .line 403
    invoke-virtual {v1, v13, v7}, Landroid/view/MotionEvent;->getHistoricalY(II)F

    .line 404
    .line 405
    .line 406
    move-result v32

    .line 407
    invoke-static/range {v26 .. v26}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 408
    .line 409
    .line 410
    move-result v33

    .line 411
    const v34, 0x7fffffff

    .line 412
    .line 413
    .line 414
    and-int v8, v33, v34

    .line 415
    .line 416
    move/from16 v33, v15

    .line 417
    .line 418
    const/high16 v15, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 419
    .line 420
    if-ge v8, v15, :cond_16

    .line 421
    .line 422
    invoke-static/range {v32 .. v32}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 423
    .line 424
    .line 425
    move-result v8

    .line 426
    and-int v8, v8, v34

    .line 427
    .line 428
    if-ge v8, v15, :cond_16

    .line 429
    .line 430
    invoke-static/range {v26 .. v26}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 431
    .line 432
    .line 433
    move-result v8

    .line 434
    move-wide/from16 v34, v9

    .line 435
    .line 436
    int-to-long v8, v8

    .line 437
    invoke-static/range {v32 .. v32}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 438
    .line 439
    .line 440
    move-result v10

    .line 441
    move-wide/from16 v40, v8

    .line 442
    .line 443
    int-to-long v8, v10

    .line 444
    shl-long v40, v40, v33

    .line 445
    .line 446
    and-long v8, v8, v23

    .line 447
    .line 448
    or-long v45, v40, v8

    .line 449
    .line 450
    new-instance v42, Lp3/c;

    .line 451
    .line 452
    invoke-virtual {v1, v7}, Landroid/view/MotionEvent;->getHistoricalEventTime(I)J

    .line 453
    .line 454
    .line 455
    move-result-wide v43

    .line 456
    move-wide/from16 v47, v45

    .line 457
    .line 458
    invoke-direct/range {v42 .. v48}, Lp3/c;-><init>(JJJ)V

    .line 459
    .line 460
    .line 461
    move-object/from16 v8, v42

    .line 462
    .line 463
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 464
    .line 465
    .line 466
    goto :goto_e

    .line 467
    :cond_16
    move-wide/from16 v34, v9

    .line 468
    .line 469
    :goto_e
    add-int/lit8 v7, v7, 0x1

    .line 470
    .line 471
    move/from16 v15, v33

    .line 472
    .line 473
    move-wide/from16 v9, v34

    .line 474
    .line 475
    const/4 v8, 0x4

    .line 476
    goto :goto_d

    .line 477
    :cond_17
    move-wide/from16 v34, v9

    .line 478
    .line 479
    move/from16 v33, v15

    .line 480
    .line 481
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 482
    .line 483
    .line 484
    move-result v7

    .line 485
    const/16 v9, 0x8

    .line 486
    .line 487
    if-ne v7, v9, :cond_18

    .line 488
    .line 489
    const/16 v7, 0xa

    .line 490
    .line 491
    invoke-virtual {v1, v7}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 492
    .line 493
    .line 494
    move-result v8

    .line 495
    const/16 v10, 0x9

    .line 496
    .line 497
    invoke-virtual {v1, v10}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 498
    .line 499
    .line 500
    move-result v12

    .line 501
    neg-float v12, v12

    .line 502
    add-float v12, v12, v25

    .line 503
    .line 504
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 505
    .line 506
    .line 507
    move-result v8

    .line 508
    int-to-long v7, v8

    .line 509
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 510
    .line 511
    .line 512
    move-result v12

    .line 513
    int-to-long v9, v12

    .line 514
    shl-long v7, v7, v33

    .line 515
    .line 516
    and-long v9, v9, v23

    .line 517
    .line 518
    or-long/2addr v7, v9

    .line 519
    goto :goto_f

    .line 520
    :cond_18
    const-wide/16 v7, 0x0

    .line 521
    .line 522
    :goto_f
    invoke-virtual {v1, v13}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 523
    .line 524
    .line 525
    move-result v9

    .line 526
    const/4 v10, 0x0

    .line 527
    invoke-virtual {v5, v9, v10}, Landroid/util/SparseBooleanArray;->get(IZ)Z

    .line 528
    .line 529
    .line 530
    move-result v32

    .line 531
    new-instance v20, Lp3/v;

    .line 532
    .line 533
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 534
    .line 535
    .line 536
    move-result-wide v23

    .line 537
    move-object/from16 v33, v11

    .line 538
    .line 539
    move-wide/from16 v25, v34

    .line 540
    .line 541
    move-wide/from16 v34, v7

    .line 542
    .line 543
    invoke-direct/range {v20 .. v37}, Lp3/v;-><init>(JJJJZFIZLjava/util/ArrayList;JJ)V

    .line 544
    .line 545
    .line 546
    move-object/from16 v7, v20

    .line 547
    .line 548
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    add-int/lit8 v13, v13, 0x1

    .line 552
    .line 553
    move/from16 v12, v38

    .line 554
    .line 555
    move/from16 v10, v39

    .line 556
    .line 557
    const/4 v7, 0x3

    .line 558
    const/4 v8, 0x4

    .line 559
    const/16 v9, 0xa

    .line 560
    .line 561
    const/16 v11, 0x8

    .line 562
    .line 563
    const/4 v15, 0x6

    .line 564
    goto/16 :goto_7

    .line 565
    .line 566
    :cond_19
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 567
    .line 568
    .line 569
    move-result v0

    .line 570
    const/4 v14, 0x1

    .line 571
    if-eq v0, v14, :cond_1a

    .line 572
    .line 573
    const/4 v2, 0x6

    .line 574
    if-eq v0, v2, :cond_1a

    .line 575
    .line 576
    const/4 v15, 0x0

    .line 577
    goto :goto_10

    .line 578
    :cond_1a
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 579
    .line 580
    .line 581
    move-result v0

    .line 582
    invoke-virtual {v1, v0}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 583
    .line 584
    .line 585
    move-result v0

    .line 586
    const/4 v15, 0x0

    .line 587
    invoke-virtual {v5, v0, v15}, Landroid/util/SparseBooleanArray;->get(IZ)Z

    .line 588
    .line 589
    .line 590
    move-result v2

    .line 591
    if-nez v2, :cond_1b

    .line 592
    .line 593
    invoke-virtual {v4, v0}, Landroid/util/SparseLongArray;->delete(I)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {v5, v0}, Landroid/util/SparseBooleanArray;->delete(I)V

    .line 597
    .line 598
    .line 599
    :cond_1b
    :goto_10
    invoke-virtual {v4}, Landroid/util/SparseLongArray;->size()I

    .line 600
    .line 601
    .line 602
    move-result v0

    .line 603
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 604
    .line 605
    .line 606
    move-result v2

    .line 607
    if-le v0, v2, :cond_1e

    .line 608
    .line 609
    invoke-virtual {v4}, Landroid/util/SparseLongArray;->size()I

    .line 610
    .line 611
    .line 612
    move-result v0

    .line 613
    const/16 v16, 0x1

    .line 614
    .line 615
    add-int/lit8 v0, v0, -0x1

    .line 616
    .line 617
    const/4 v2, -0x1

    .line 618
    :goto_11
    if-ge v2, v0, :cond_1e

    .line 619
    .line 620
    invoke-virtual {v4, v0}, Landroid/util/SparseLongArray;->keyAt(I)I

    .line 621
    .line 622
    .line 623
    move-result v6

    .line 624
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 625
    .line 626
    .line 627
    move-result v7

    .line 628
    move v8, v15

    .line 629
    :goto_12
    if-ge v8, v7, :cond_1d

    .line 630
    .line 631
    invoke-virtual {v1, v8}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 632
    .line 633
    .line 634
    move-result v9

    .line 635
    if-ne v9, v6, :cond_1c

    .line 636
    .line 637
    goto :goto_13

    .line 638
    :cond_1c
    add-int/lit8 v8, v8, 0x1

    .line 639
    .line 640
    goto :goto_12

    .line 641
    :cond_1d
    invoke-virtual {v4, v0}, Landroid/util/SparseLongArray;->removeAt(I)V

    .line 642
    .line 643
    .line 644
    invoke-virtual {v5, v6}, Landroid/util/SparseBooleanArray;->delete(I)V

    .line 645
    .line 646
    .line 647
    :goto_13
    add-int/lit8 v0, v0, -0x1

    .line 648
    .line 649
    goto :goto_11

    .line 650
    :cond_1e
    new-instance v0, Lc2/k;

    .line 651
    .line 652
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 653
    .line 654
    .line 655
    const/16 v2, 0x14

    .line 656
    .line 657
    invoke-direct {v0, v2, v3, v1}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 658
    .line 659
    .line 660
    return-object v0

    .line 661
    :cond_1f
    invoke-virtual {v4}, Landroid/util/SparseLongArray;->clear()V

    .line 662
    .line 663
    .line 664
    invoke-virtual {v5}, Landroid/util/SparseBooleanArray;->clear()V

    .line 665
    .line 666
    .line 667
    const/4 v0, 0x0

    .line 668
    return-object v0
.end method

.method public b(J)Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Lp3/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp3/h;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-wide v1, v0, Lp3/h;->a:J

    .line 8
    .line 9
    cmp-long v1, p1, v1

    .line 10
    .line 11
    if-gez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {v0, p1, p2}, Lp3/h;->b(J)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0

    .line 19
    :cond_1
    :goto_0
    iget-object p1, p0, Lp3/h;->f:Ljava/io/Serializable;

    .line 20
    .line 21
    check-cast p1, Ljava/lang/String;

    .line 22
    .line 23
    if-nez p1, :cond_2

    .line 24
    .line 25
    iget-object p1, p0, Lp3/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Ln11/f;

    .line 28
    .line 29
    iget-wide v0, p0, Lp3/h;->a:J

    .line 30
    .line 31
    invoke-virtual {p1, v0, v1}, Ln11/f;->g(J)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iput-object p1, p0, Lp3/h;->f:Ljava/io/Serializable;

    .line 36
    .line 37
    :cond_2
    iget-object p0, p0, Lp3/h;->f:Ljava/io/Serializable;

    .line 38
    .line 39
    check-cast p0, Ljava/lang/String;

    .line 40
    .line 41
    return-object p0
.end method

.method public c(J)I
    .locals 3

    .line 1
    iget-object v0, p0, Lp3/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp3/h;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-wide v1, v0, Lp3/h;->a:J

    .line 8
    .line 9
    cmp-long v1, p1, v1

    .line 10
    .line 11
    if-gez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {v0, p1, p2}, Lp3/h;->c(J)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_1
    :goto_0
    iget p1, p0, Lp3/h;->b:I

    .line 20
    .line 21
    const/high16 p2, -0x80000000

    .line 22
    .line 23
    if-ne p1, p2, :cond_2

    .line 24
    .line 25
    iget-object p1, p0, Lp3/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Ln11/f;

    .line 28
    .line 29
    iget-wide v0, p0, Lp3/h;->a:J

    .line 30
    .line 31
    invoke-virtual {p1, v0, v1}, Ln11/f;->i(J)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iput p1, p0, Lp3/h;->b:I

    .line 36
    .line 37
    :cond_2
    iget p0, p0, Lp3/h;->b:I

    .line 38
    .line 39
    return p0
.end method

.method public d(J)I
    .locals 3

    .line 1
    iget-object v0, p0, Lp3/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lp3/h;

    .line 4
    .line 5
    if-eqz v0, :cond_1

    .line 6
    .line 7
    iget-wide v1, v0, Lp3/h;->a:J

    .line 8
    .line 9
    cmp-long v1, p1, v1

    .line 10
    .line 11
    if-gez v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    invoke-virtual {v0, p1, p2}, Lp3/h;->d(J)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    return p0

    .line 19
    :cond_1
    :goto_0
    iget p1, p0, Lp3/h;->c:I

    .line 20
    .line 21
    const/high16 p2, -0x80000000

    .line 22
    .line 23
    if-ne p1, p2, :cond_2

    .line 24
    .line 25
    iget-object p1, p0, Lp3/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast p1, Ln11/f;

    .line 28
    .line 29
    iget-wide v0, p0, Lp3/h;->a:J

    .line 30
    .line 31
    invoke-virtual {p1, v0, v1}, Ln11/f;->l(J)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iput p1, p0, Lp3/h;->c:I

    .line 36
    .line 37
    :cond_2
    iget p0, p0, Lp3/h;->c:I

    .line 38
    .line 39
    return p0
.end method
