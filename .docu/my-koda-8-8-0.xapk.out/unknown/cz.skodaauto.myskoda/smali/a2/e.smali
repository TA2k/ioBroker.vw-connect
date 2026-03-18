.class public final synthetic La2/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, La2/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, La2/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 47

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, La2/e;->d:I

    .line 4
    .line 5
    iget-object v0, v0, La2/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lz71/g;

    .line 15
    .line 16
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFinishedViewModelController;->o(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;Lz71/g;)Llx0/b0;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    return-object v0

    .line 21
    :pswitch_0
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;

    .line 22
    .line 23
    move-object/from16 v1, p1

    .line 24
    .line 25
    check-cast v1, Lz71/e;

    .line 26
    .line 27
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ParkingFailedViewModelController;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFailedError;Lz71/e;)Llx0/b0;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    return-object v0

    .line 32
    :pswitch_1
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ConnectionEstablishmentViewModelController;

    .line 33
    .line 34
    move-object/from16 v1, p1

    .line 35
    .line 36
    check-cast v1, Lz71/a;

    .line 37
    .line 38
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ConnectionEstablishmentViewModelController;->c(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/viewmodel/ConnectionEstablishmentViewModelController;Lz71/a;)Llx0/b0;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    return-object v0

    .line 43
    :pswitch_2
    check-cast v0, Le1/a0;

    .line 44
    .line 45
    move-object/from16 v1, p1

    .line 46
    .line 47
    check-cast v1, Ld3/b;

    .line 48
    .line 49
    iget-boolean v1, v0, Le1/h;->y:Z

    .line 50
    .line 51
    if-eqz v1, :cond_0

    .line 52
    .line 53
    iget-object v0, v0, Le1/h;->z:Lay0/a;

    .line 54
    .line 55
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_3
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 62
    .line 63
    move-object/from16 v1, p1

    .line 64
    .line 65
    check-cast v1, Lv3/c2;

    .line 66
    .line 67
    iget-boolean v2, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 68
    .line 69
    const/4 v3, 0x1

    .line 70
    if-nez v2, :cond_2

    .line 71
    .line 72
    const-string v2, "null cannot be cast to non-null type androidx.compose.foundation.gestures.ScrollableContainerNode"

    .line 73
    .line 74
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    check-cast v1, Lg1/f2;

    .line 78
    .line 79
    iget-boolean v1, v1, Lg1/f2;->r:Z

    .line 80
    .line 81
    if-eqz v1, :cond_1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_1
    const/4 v1, 0x0

    .line 85
    goto :goto_1

    .line 86
    :cond_2
    :goto_0
    move v1, v3

    .line 87
    :goto_1
    iput-boolean v1, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 88
    .line 89
    xor-int/lit8 v0, v1, 0x1

    .line 90
    .line 91
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    return-object v0

    .line 96
    :pswitch_4
    check-cast v0, Le1/s;

    .line 97
    .line 98
    move-object/from16 v1, p1

    .line 99
    .line 100
    check-cast v1, Lb3/d;

    .line 101
    .line 102
    iget v2, v0, Le1/s;->u:F

    .line 103
    .line 104
    invoke-virtual {v1}, Lb3/d;->a()F

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    mul-float/2addr v3, v2

    .line 109
    const/4 v2, 0x0

    .line 110
    cmpl-float v3, v3, v2

    .line 111
    .line 112
    if-ltz v3, :cond_1d

    .line 113
    .line 114
    iget-object v3, v1, Lb3/d;->d:Lb3/b;

    .line 115
    .line 116
    invoke-interface {v3}, Lb3/b;->e()J

    .line 117
    .line 118
    .line 119
    move-result-wide v3

    .line 120
    invoke-static {v3, v4}, Ld3/e;->c(J)F

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    cmpl-float v3, v3, v2

    .line 125
    .line 126
    if-lez v3, :cond_1d

    .line 127
    .line 128
    iget v3, v0, Le1/s;->u:F

    .line 129
    .line 130
    invoke-static {v3, v2}, Lt4/f;->a(FF)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    const/high16 v3, 0x3f800000    # 1.0f

    .line 135
    .line 136
    if-eqz v2, :cond_3

    .line 137
    .line 138
    move v2, v3

    .line 139
    goto :goto_2

    .line 140
    :cond_3
    iget v2, v0, Le1/s;->u:F

    .line 141
    .line 142
    invoke-virtual {v1}, Lb3/d;->a()F

    .line 143
    .line 144
    .line 145
    move-result v4

    .line 146
    mul-float/2addr v4, v2

    .line 147
    float-to-double v4, v4

    .line 148
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 149
    .line 150
    .line 151
    move-result-wide v4

    .line 152
    double-to-float v2, v4

    .line 153
    :goto_2
    iget-object v4, v1, Lb3/d;->d:Lb3/b;

    .line 154
    .line 155
    invoke-interface {v4}, Lb3/b;->e()J

    .line 156
    .line 157
    .line 158
    move-result-wide v4

    .line 159
    invoke-static {v4, v5}, Ld3/e;->c(J)F

    .line 160
    .line 161
    .line 162
    move-result v4

    .line 163
    const/4 v5, 0x2

    .line 164
    int-to-float v5, v5

    .line 165
    div-float/2addr v4, v5

    .line 166
    float-to-double v6, v4

    .line 167
    invoke-static {v6, v7}, Ljava/lang/Math;->ceil(D)D

    .line 168
    .line 169
    .line 170
    move-result-wide v6

    .line 171
    double-to-float v4, v6

    .line 172
    invoke-static {v2, v4}, Ljava/lang/Math;->min(FF)F

    .line 173
    .line 174
    .line 175
    move-result v7

    .line 176
    div-float v2, v7, v5

    .line 177
    .line 178
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 179
    .line 180
    .line 181
    move-result v4

    .line 182
    int-to-long v8, v4

    .line 183
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 184
    .line 185
    .line 186
    move-result v4

    .line 187
    int-to-long v10, v4

    .line 188
    const/16 v4, 0x20

    .line 189
    .line 190
    shl-long/2addr v8, v4

    .line 191
    const-wide v12, 0xffffffffL

    .line 192
    .line 193
    .line 194
    .line 195
    .line 196
    and-long/2addr v10, v12

    .line 197
    or-long v14, v8, v10

    .line 198
    .line 199
    iget-object v6, v1, Lb3/d;->d:Lb3/b;

    .line 200
    .line 201
    invoke-interface {v6}, Lb3/b;->e()J

    .line 202
    .line 203
    .line 204
    move-result-wide v8

    .line 205
    shr-long/2addr v8, v4

    .line 206
    long-to-int v6, v8

    .line 207
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    sub-float/2addr v6, v7

    .line 212
    iget-object v8, v1, Lb3/d;->d:Lb3/b;

    .line 213
    .line 214
    invoke-interface {v8}, Lb3/b;->e()J

    .line 215
    .line 216
    .line 217
    move-result-wide v8

    .line 218
    and-long/2addr v8, v12

    .line 219
    long-to-int v8, v8

    .line 220
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 221
    .line 222
    .line 223
    move-result v8

    .line 224
    sub-float/2addr v8, v7

    .line 225
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 226
    .line 227
    .line 228
    move-result v6

    .line 229
    int-to-long v9, v6

    .line 230
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 231
    .line 232
    .line 233
    move-result v6

    .line 234
    move/from16 p0, v4

    .line 235
    .line 236
    move v8, v5

    .line 237
    int-to-long v4, v6

    .line 238
    shl-long v9, v9, p0

    .line 239
    .line 240
    and-long/2addr v4, v12

    .line 241
    or-long/2addr v4, v9

    .line 242
    mul-float v17, v7, v8

    .line 243
    .line 244
    iget-object v6, v1, Lb3/d;->d:Lb3/b;

    .line 245
    .line 246
    invoke-interface {v6}, Lb3/b;->e()J

    .line 247
    .line 248
    .line 249
    move-result-wide v8

    .line 250
    invoke-static {v8, v9}, Ld3/e;->c(J)F

    .line 251
    .line 252
    .line 253
    move-result v6

    .line 254
    cmpl-float v6, v17, v6

    .line 255
    .line 256
    const/4 v9, 0x0

    .line 257
    if-lez v6, :cond_4

    .line 258
    .line 259
    const/16 v16, 0x1

    .line 260
    .line 261
    goto :goto_3

    .line 262
    :cond_4
    move/from16 v16, v9

    .line 263
    .line 264
    :goto_3
    iget-object v6, v0, Le1/s;->w:Le3/n0;

    .line 265
    .line 266
    iget-object v10, v1, Lb3/d;->d:Lb3/b;

    .line 267
    .line 268
    invoke-interface {v10}, Lb3/b;->e()J

    .line 269
    .line 270
    .line 271
    move-result-wide v10

    .line 272
    move-wide/from16 v23, v12

    .line 273
    .line 274
    iget-object v12, v1, Lb3/d;->d:Lb3/b;

    .line 275
    .line 276
    invoke-interface {v12}, Lb3/b;->getLayoutDirection()Lt4/m;

    .line 277
    .line 278
    .line 279
    move-result-object v12

    .line 280
    invoke-interface {v6, v10, v11, v12, v1}, Le3/n0;->a(JLt4/m;Lt4/c;)Le3/g0;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    instance-of v10, v6, Le3/d0;

    .line 285
    .line 286
    if-eqz v10, :cond_13

    .line 287
    .line 288
    iget-object v2, v0, Le1/s;->v:Le3/p0;

    .line 289
    .line 290
    check-cast v6, Le3/d0;

    .line 291
    .line 292
    iget-object v4, v6, Le3/d0;->a:Le3/i;

    .line 293
    .line 294
    if-eqz v16, :cond_5

    .line 295
    .line 296
    new-instance v0, Laa/z;

    .line 297
    .line 298
    const/16 v3, 0x17

    .line 299
    .line 300
    invoke-direct {v0, v3, v6, v2}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v1, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 304
    .line 305
    .line 306
    move-result-object v0

    .line 307
    goto/16 :goto_10

    .line 308
    .line 309
    :cond_5
    if-eqz v2, :cond_6

    .line 310
    .line 311
    iget-wide v10, v2, Le3/p0;->a:J

    .line 312
    .line 313
    invoke-static {v10, v11, v3}, Le3/s;->b(JF)J

    .line 314
    .line 315
    .line 316
    move-result-wide v10

    .line 317
    new-instance v3, Le3/m;

    .line 318
    .line 319
    const/4 v7, 0x5

    .line 320
    invoke-direct {v3, v10, v11, v7}, Le3/m;-><init>(JI)V

    .line 321
    .line 322
    .line 323
    const/4 v7, 0x1

    .line 324
    goto :goto_4

    .line 325
    :cond_6
    move v7, v9

    .line 326
    const/4 v3, 0x0

    .line 327
    :goto_4
    invoke-virtual {v4}, Le3/i;->f()Ld3/c;

    .line 328
    .line 329
    .line 330
    move-result-object v10

    .line 331
    iget v11, v10, Ld3/c;->b:F

    .line 332
    .line 333
    iget v12, v10, Ld3/c;->a:F

    .line 334
    .line 335
    iget-object v13, v0, Le1/s;->t:Le1/o;

    .line 336
    .line 337
    if-nez v13, :cond_7

    .line 338
    .line 339
    new-instance v13, Le1/o;

    .line 340
    .line 341
    invoke-direct {v13}, Le1/o;-><init>()V

    .line 342
    .line 343
    .line 344
    iput-object v13, v0, Le1/s;->t:Le1/o;

    .line 345
    .line 346
    :cond_7
    iget-object v13, v0, Le1/s;->t:Le1/o;

    .line 347
    .line 348
    invoke-static {v13}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    iget-object v14, v13, Le1/o;->d:Le3/i;

    .line 352
    .line 353
    if-nez v14, :cond_8

    .line 354
    .line 355
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 356
    .line 357
    .line 358
    move-result-object v14

    .line 359
    iput-object v14, v13, Le1/o;->d:Le3/i;

    .line 360
    .line 361
    :cond_8
    invoke-virtual {v14}, Le3/i;->j()V

    .line 362
    .line 363
    .line 364
    invoke-static {v14, v10}, Le3/i;->b(Le3/i;Ld3/c;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v14, v14, v4, v9}, Le3/i;->i(Le3/i;Le3/i;I)Z

    .line 368
    .line 369
    .line 370
    new-instance v4, Lkotlin/jvm/internal/f0;

    .line 371
    .line 372
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 373
    .line 374
    .line 375
    iget v13, v10, Ld3/c;->c:F

    .line 376
    .line 377
    sub-float/2addr v13, v12

    .line 378
    float-to-double v8, v13

    .line 379
    invoke-static {v8, v9}, Ljava/lang/Math;->ceil(D)D

    .line 380
    .line 381
    .line 382
    move-result-wide v8

    .line 383
    double-to-float v8, v8

    .line 384
    float-to-int v8, v8

    .line 385
    iget v9, v10, Ld3/c;->d:F

    .line 386
    .line 387
    sub-float/2addr v9, v11

    .line 388
    move-object v13, v6

    .line 389
    float-to-double v5, v9

    .line 390
    invoke-static {v5, v6}, Ljava/lang/Math;->ceil(D)D

    .line 391
    .line 392
    .line 393
    move-result-wide v5

    .line 394
    double-to-float v5, v5

    .line 395
    float-to-int v5, v5

    .line 396
    int-to-long v8, v8

    .line 397
    shl-long v8, v8, p0

    .line 398
    .line 399
    int-to-long v5, v5

    .line 400
    and-long v5, v5, v23

    .line 401
    .line 402
    or-long/2addr v5, v8

    .line 403
    iget-object v0, v0, Le1/s;->t:Le1/o;

    .line 404
    .line 405
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 406
    .line 407
    .line 408
    iget-object v8, v0, Le1/o;->a:Le3/f;

    .line 409
    .line 410
    iget-object v9, v0, Le1/o;->b:Le3/a;

    .line 411
    .line 412
    if-eqz v8, :cond_9

    .line 413
    .line 414
    invoke-virtual {v8}, Le3/f;->a()I

    .line 415
    .line 416
    .line 417
    move-result v15

    .line 418
    move-object/from16 v27, v2

    .line 419
    .line 420
    new-instance v2, Le3/z;

    .line 421
    .line 422
    invoke-direct {v2, v15}, Le3/z;-><init>(I)V

    .line 423
    .line 424
    .line 425
    goto :goto_5

    .line 426
    :cond_9
    move-object/from16 v27, v2

    .line 427
    .line 428
    const/4 v2, 0x0

    .line 429
    :goto_5
    if-nez v2, :cond_a

    .line 430
    .line 431
    goto :goto_6

    .line 432
    :cond_a
    iget v2, v2, Le3/z;->a:I

    .line 433
    .line 434
    if-nez v2, :cond_b

    .line 435
    .line 436
    goto :goto_9

    .line 437
    :cond_b
    :goto_6
    if-eqz v8, :cond_c

    .line 438
    .line 439
    invoke-virtual {v8}, Le3/f;->a()I

    .line 440
    .line 441
    .line 442
    move-result v2

    .line 443
    new-instance v15, Le3/z;

    .line 444
    .line 445
    invoke-direct {v15, v2}, Le3/z;-><init>(I)V

    .line 446
    .line 447
    .line 448
    goto :goto_7

    .line 449
    :cond_c
    const/4 v15, 0x0

    .line 450
    :goto_7
    if-nez v15, :cond_d

    .line 451
    .line 452
    goto :goto_8

    .line 453
    :cond_d
    iget v2, v15, Le3/z;->a:I

    .line 454
    .line 455
    if-eq v7, v2, :cond_e

    .line 456
    .line 457
    :goto_8
    const/16 v18, 0x0

    .line 458
    .line 459
    goto :goto_a

    .line 460
    :cond_e
    :goto_9
    const/16 v18, 0x1

    .line 461
    .line 462
    :goto_a
    if-eqz v8, :cond_f

    .line 463
    .line 464
    if-eqz v9, :cond_f

    .line 465
    .line 466
    iget-object v2, v1, Lb3/d;->d:Lb3/b;

    .line 467
    .line 468
    invoke-interface {v2}, Lb3/b;->e()J

    .line 469
    .line 470
    .line 471
    move-result-wide v15

    .line 472
    move-object/from16 v31, v3

    .line 473
    .line 474
    shr-long v2, v15, p0

    .line 475
    .line 476
    long-to-int v2, v2

    .line 477
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 478
    .line 479
    .line 480
    move-result v2

    .line 481
    iget-object v3, v8, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 482
    .line 483
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 484
    .line 485
    .line 486
    move-result v15

    .line 487
    int-to-float v15, v15

    .line 488
    cmpl-float v2, v2, v15

    .line 489
    .line 490
    if-gtz v2, :cond_10

    .line 491
    .line 492
    iget-object v2, v1, Lb3/d;->d:Lb3/b;

    .line 493
    .line 494
    invoke-interface {v2}, Lb3/b;->e()J

    .line 495
    .line 496
    .line 497
    move-result-wide v15

    .line 498
    move-object/from16 v19, v3

    .line 499
    .line 500
    and-long v2, v15, v23

    .line 501
    .line 502
    long-to-int v2, v2

    .line 503
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 504
    .line 505
    .line 506
    move-result v2

    .line 507
    invoke-virtual/range {v19 .. v19}, Landroid/graphics/Bitmap;->getHeight()I

    .line 508
    .line 509
    .line 510
    move-result v3

    .line 511
    int-to-float v3, v3

    .line 512
    cmpl-float v2, v2, v3

    .line 513
    .line 514
    if-gtz v2, :cond_10

    .line 515
    .line 516
    if-nez v18, :cond_11

    .line 517
    .line 518
    goto :goto_b

    .line 519
    :cond_f
    move-object/from16 v31, v3

    .line 520
    .line 521
    :cond_10
    :goto_b
    shr-long v2, v5, p0

    .line 522
    .line 523
    long-to-int v2, v2

    .line 524
    and-long v8, v5, v23

    .line 525
    .line 526
    long-to-int v3, v8

    .line 527
    invoke-static {v2, v3, v7}, Le3/j0;->g(III)Le3/f;

    .line 528
    .line 529
    .line 530
    move-result-object v8

    .line 531
    iput-object v8, v0, Le1/o;->a:Le3/f;

    .line 532
    .line 533
    invoke-static {v8}, Le3/j0;->a(Le3/f;)Le3/a;

    .line 534
    .line 535
    .line 536
    move-result-object v9

    .line 537
    iput-object v9, v0, Le1/o;->b:Le3/a;

    .line 538
    .line 539
    :cond_11
    iget-object v2, v0, Le1/o;->c:Lg3/b;

    .line 540
    .line 541
    if-nez v2, :cond_12

    .line 542
    .line 543
    new-instance v2, Lg3/b;

    .line 544
    .line 545
    invoke-direct {v2}, Lg3/b;-><init>()V

    .line 546
    .line 547
    .line 548
    iput-object v2, v0, Le1/o;->c:Lg3/b;

    .line 549
    .line 550
    :cond_12
    iget-object v3, v2, Lg3/b;->e:Lgw0/c;

    .line 551
    .line 552
    iget-object v0, v2, Lg3/b;->d:Lg3/a;

    .line 553
    .line 554
    move-wide/from16 v43, v5

    .line 555
    .line 556
    invoke-static/range {v43 .. v44}, Lkp/f9;->c(J)J

    .line 557
    .line 558
    .line 559
    move-result-wide v5

    .line 560
    iget-object v7, v1, Lb3/d;->d:Lb3/b;

    .line 561
    .line 562
    invoke-interface {v7}, Lb3/b;->getLayoutDirection()Lt4/m;

    .line 563
    .line 564
    .line 565
    move-result-object v7

    .line 566
    iget-object v15, v0, Lg3/a;->a:Lt4/c;

    .line 567
    .line 568
    move-object/from16 v32, v2

    .line 569
    .line 570
    iget-object v2, v0, Lg3/a;->b:Lt4/m;

    .line 571
    .line 572
    move-object/from16 v45, v10

    .line 573
    .line 574
    iget-object v10, v0, Lg3/a;->c:Le3/r;

    .line 575
    .line 576
    move-object/from16 v16, v13

    .line 577
    .line 578
    move-object/from16 v46, v14

    .line 579
    .line 580
    iget-wide v13, v0, Lg3/a;->d:J

    .line 581
    .line 582
    iput-object v1, v0, Lg3/a;->a:Lt4/c;

    .line 583
    .line 584
    iput-object v7, v0, Lg3/a;->b:Lt4/m;

    .line 585
    .line 586
    iput-object v9, v0, Lg3/a;->c:Le3/r;

    .line 587
    .line 588
    iput-wide v5, v0, Lg3/a;->d:J

    .line 589
    .line 590
    invoke-virtual {v9}, Le3/a;->o()V

    .line 591
    .line 592
    .line 593
    sget-wide v33, Le3/s;->b:J

    .line 594
    .line 595
    const/16 v41, 0x0

    .line 596
    .line 597
    const/16 v42, 0x3a

    .line 598
    .line 599
    const-wide/16 v35, 0x0

    .line 600
    .line 601
    const/16 v39, 0x0

    .line 602
    .line 603
    const/16 v40, 0x0

    .line 604
    .line 605
    move-wide/from16 v37, v5

    .line 606
    .line 607
    invoke-static/range {v32 .. v42}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 608
    .line 609
    .line 610
    neg-float v5, v12

    .line 611
    neg-float v6, v11

    .line 612
    iget-object v7, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v7, Lbu/c;

    .line 615
    .line 616
    invoke-virtual {v7, v5, v6}, Lbu/c;->B(FF)V

    .line 617
    .line 618
    .line 619
    move-object/from16 v7, v16

    .line 620
    .line 621
    :try_start_0
    iget-object v7, v7, Le3/d0;->a:Le3/i;

    .line 622
    .line 623
    new-instance v16, Lg3/h;

    .line 624
    .line 625
    const/16 v21, 0x0

    .line 626
    .line 627
    const/16 v22, 0x1e

    .line 628
    .line 629
    const/16 v18, 0x0

    .line 630
    .line 631
    const/16 v19, 0x0

    .line 632
    .line 633
    const/16 v20, 0x0

    .line 634
    .line 635
    invoke-direct/range {v16 .. v22}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 636
    .line 637
    .line 638
    const/16 v30, 0x34

    .line 639
    .line 640
    const/16 v28, 0x0

    .line 641
    .line 642
    move-object/from16 v26, v7

    .line 643
    .line 644
    move-object/from16 v29, v16

    .line 645
    .line 646
    move-object/from16 v25, v32

    .line 647
    .line 648
    invoke-static/range {v25 .. v30}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 649
    .line 650
    .line 651
    invoke-interface/range {v32 .. v32}, Lg3/d;->e()J

    .line 652
    .line 653
    .line 654
    move-result-wide v11

    .line 655
    shr-long v11, v11, p0

    .line 656
    .line 657
    long-to-int v7, v11

    .line 658
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 659
    .line 660
    .line 661
    move-result v7

    .line 662
    const/4 v11, 0x1

    .line 663
    int-to-float v11, v11

    .line 664
    add-float/2addr v7, v11

    .line 665
    invoke-interface/range {v32 .. v32}, Lg3/d;->e()J

    .line 666
    .line 667
    .line 668
    move-result-wide v16

    .line 669
    move/from16 v18, v11

    .line 670
    .line 671
    shr-long v11, v16, p0

    .line 672
    .line 673
    long-to-int v11, v11

    .line 674
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 675
    .line 676
    .line 677
    move-result v11

    .line 678
    div-float/2addr v7, v11

    .line 679
    invoke-interface/range {v32 .. v32}, Lg3/d;->e()J

    .line 680
    .line 681
    .line 682
    move-result-wide v11

    .line 683
    and-long v11, v11, v23

    .line 684
    .line 685
    long-to-int v11, v11

    .line 686
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 687
    .line 688
    .line 689
    move-result v11

    .line 690
    add-float v11, v11, v18

    .line 691
    .line 692
    invoke-interface/range {v32 .. v32}, Lg3/d;->e()J

    .line 693
    .line 694
    .line 695
    move-result-wide v16

    .line 696
    move/from16 p0, v11

    .line 697
    .line 698
    and-long v11, v16, v23

    .line 699
    .line 700
    long-to-int v11, v11

    .line 701
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 702
    .line 703
    .line 704
    move-result v11

    .line 705
    div-float v11, p0, v11

    .line 706
    .line 707
    move-object v12, v8

    .line 708
    move-object/from16 v16, v9

    .line 709
    .line 710
    invoke-interface/range {v32 .. v32}, Lg3/d;->D0()J

    .line 711
    .line 712
    .line 713
    move-result-wide v8

    .line 714
    move-object/from16 p0, v12

    .line 715
    .line 716
    move-wide/from16 v17, v13

    .line 717
    .line 718
    invoke-virtual {v3}, Lgw0/c;->o()J

    .line 719
    .line 720
    .line 721
    move-result-wide v12

    .line 722
    invoke-virtual {v3}, Lgw0/c;->h()Le3/r;

    .line 723
    .line 724
    .line 725
    move-result-object v14

    .line 726
    invoke-interface {v14}, Le3/r;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 727
    .line 728
    .line 729
    :try_start_1
    iget-object v14, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 730
    .line 731
    check-cast v14, Lbu/c;

    .line 732
    .line 733
    invoke-virtual {v14, v8, v9, v7, v11}, Lbu/c;->A(JFF)V

    .line 734
    .line 735
    .line 736
    const/16 v29, 0x0

    .line 737
    .line 738
    const/16 v30, 0x1c

    .line 739
    .line 740
    const/16 v28, 0x0

    .line 741
    .line 742
    move-object/from16 v25, v32

    .line 743
    .line 744
    move-object/from16 v26, v46

    .line 745
    .line 746
    invoke-static/range {v25 .. v30}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 747
    .line 748
    .line 749
    :try_start_2
    invoke-virtual {v3}, Lgw0/c;->h()Le3/r;

    .line 750
    .line 751
    .line 752
    move-result-object v7

    .line 753
    invoke-interface {v7}, Le3/r;->i()V

    .line 754
    .line 755
    .line 756
    invoke-virtual {v3, v12, v13}, Lgw0/c;->B(J)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 757
    .line 758
    .line 759
    iget-object v3, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 760
    .line 761
    check-cast v3, Lbu/c;

    .line 762
    .line 763
    neg-float v5, v5

    .line 764
    neg-float v6, v6

    .line 765
    invoke-virtual {v3, v5, v6}, Lbu/c;->B(FF)V

    .line 766
    .line 767
    .line 768
    invoke-virtual/range {v16 .. v16}, Le3/a;->i()V

    .line 769
    .line 770
    .line 771
    iput-object v15, v0, Lg3/a;->a:Lt4/c;

    .line 772
    .line 773
    iput-object v2, v0, Lg3/a;->b:Lt4/m;

    .line 774
    .line 775
    iput-object v10, v0, Lg3/a;->c:Le3/r;

    .line 776
    .line 777
    move-wide/from16 v2, v17

    .line 778
    .line 779
    iput-wide v2, v0, Lg3/a;->d:J

    .line 780
    .line 781
    move-object/from16 v12, p0

    .line 782
    .line 783
    iget-object v0, v12, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 784
    .line 785
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->prepareToDraw()V

    .line 786
    .line 787
    .line 788
    iput-object v12, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 789
    .line 790
    new-instance v25, Le1/r;

    .line 791
    .line 792
    move-object/from16 v30, v31

    .line 793
    .line 794
    const/16 v31, 0x0

    .line 795
    .line 796
    move-object/from16 v27, v4

    .line 797
    .line 798
    move-wide/from16 v28, v43

    .line 799
    .line 800
    move-object/from16 v26, v45

    .line 801
    .line 802
    invoke-direct/range {v25 .. v31}, Le1/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;JLjava/lang/Object;I)V

    .line 803
    .line 804
    .line 805
    move-object/from16 v0, v25

    .line 806
    .line 807
    invoke-virtual {v1, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 808
    .line 809
    .line 810
    move-result-object v0

    .line 811
    goto/16 :goto_10

    .line 812
    .line 813
    :catchall_0
    move-exception v0

    .line 814
    goto :goto_c

    .line 815
    :catchall_1
    move-exception v0

    .line 816
    :try_start_3
    invoke-virtual {v3}, Lgw0/c;->h()Le3/r;

    .line 817
    .line 818
    .line 819
    move-result-object v1

    .line 820
    invoke-interface {v1}, Le3/r;->i()V

    .line 821
    .line 822
    .line 823
    invoke-virtual {v3, v12, v13}, Lgw0/c;->B(J)V

    .line 824
    .line 825
    .line 826
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 827
    :goto_c
    iget-object v1, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 828
    .line 829
    check-cast v1, Lbu/c;

    .line 830
    .line 831
    neg-float v2, v5

    .line 832
    neg-float v3, v6

    .line 833
    invoke-virtual {v1, v2, v3}, Lbu/c;->B(FF)V

    .line 834
    .line 835
    .line 836
    throw v0

    .line 837
    :cond_13
    instance-of v3, v6, Le3/f0;

    .line 838
    .line 839
    if-eqz v3, :cond_18

    .line 840
    .line 841
    iget-object v3, v0, Le1/s;->v:Le3/p0;

    .line 842
    .line 843
    check-cast v6, Le3/f0;

    .line 844
    .line 845
    iget-object v6, v6, Le3/f0;->a:Ld3/d;

    .line 846
    .line 847
    invoke-static {v6}, Ljp/df;->d(Ld3/d;)Z

    .line 848
    .line 849
    .line 850
    move-result v8

    .line 851
    if-eqz v8, :cond_14

    .line 852
    .line 853
    iget-wide v8, v6, Ld3/d;->e:J

    .line 854
    .line 855
    new-instance v17, Lg3/h;

    .line 856
    .line 857
    const/4 v11, 0x0

    .line 858
    const/16 v12, 0x1e

    .line 859
    .line 860
    move-wide v9, v8

    .line 861
    const/4 v8, 0x0

    .line 862
    move-wide/from16 v18, v9

    .line 863
    .line 864
    const/4 v9, 0x0

    .line 865
    const/4 v10, 0x0

    .line 866
    move-object/from16 v6, v17

    .line 867
    .line 868
    invoke-direct/range {v6 .. v12}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 869
    .line 870
    .line 871
    new-instance v6, Le1/q;

    .line 872
    .line 873
    move v11, v2

    .line 874
    move-object v8, v3

    .line 875
    move v12, v7

    .line 876
    move-wide v13, v14

    .line 877
    move/from16 v7, v16

    .line 878
    .line 879
    move-wide/from16 v9, v18

    .line 880
    .line 881
    move-wide v15, v4

    .line 882
    invoke-direct/range {v6 .. v17}, Le1/q;-><init>(ZLe3/p0;JFFJJLg3/h;)V

    .line 883
    .line 884
    .line 885
    invoke-virtual {v1, v6}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 886
    .line 887
    .line 888
    move-result-object v0

    .line 889
    goto/16 :goto_10

    .line 890
    .line 891
    :cond_14
    move-object v2, v3

    .line 892
    move/from16 v8, v16

    .line 893
    .line 894
    iget-object v3, v0, Le1/s;->t:Le1/o;

    .line 895
    .line 896
    if-nez v3, :cond_15

    .line 897
    .line 898
    new-instance v3, Le1/o;

    .line 899
    .line 900
    invoke-direct {v3}, Le1/o;-><init>()V

    .line 901
    .line 902
    .line 903
    iput-object v3, v0, Le1/s;->t:Le1/o;

    .line 904
    .line 905
    :cond_15
    iget-object v0, v0, Le1/s;->t:Le1/o;

    .line 906
    .line 907
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 908
    .line 909
    .line 910
    iget-object v3, v0, Le1/o;->d:Le3/i;

    .line 911
    .line 912
    if-nez v3, :cond_16

    .line 913
    .line 914
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 915
    .line 916
    .line 917
    move-result-object v3

    .line 918
    iput-object v3, v0, Le1/o;->d:Le3/i;

    .line 919
    .line 920
    :cond_16
    invoke-virtual {v3}, Le3/i;->j()V

    .line 921
    .line 922
    .line 923
    invoke-static {v3, v6}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 924
    .line 925
    .line 926
    if-nez v8, :cond_17

    .line 927
    .line 928
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 929
    .line 930
    .line 931
    move-result-object v0

    .line 932
    invoke-virtual {v6}, Ld3/d;->b()F

    .line 933
    .line 934
    .line 935
    move-result v4

    .line 936
    sub-float v9, v4, v7

    .line 937
    .line 938
    invoke-virtual {v6}, Ld3/d;->a()F

    .line 939
    .line 940
    .line 941
    move-result v4

    .line 942
    sub-float v10, v4, v7

    .line 943
    .line 944
    iget-wide v4, v6, Ld3/d;->e:J

    .line 945
    .line 946
    invoke-static {v4, v5, v7}, Lkp/g;->d(JF)J

    .line 947
    .line 948
    .line 949
    move-result-wide v11

    .line 950
    iget-wide v4, v6, Ld3/d;->f:J

    .line 951
    .line 952
    invoke-static {v4, v5, v7}, Lkp/g;->d(JF)J

    .line 953
    .line 954
    .line 955
    move-result-wide v13

    .line 956
    iget-wide v4, v6, Ld3/d;->h:J

    .line 957
    .line 958
    invoke-static {v4, v5, v7}, Lkp/g;->d(JF)J

    .line 959
    .line 960
    .line 961
    move-result-wide v4

    .line 962
    move-wide/from16 p0, v4

    .line 963
    .line 964
    iget-wide v4, v6, Ld3/d;->g:J

    .line 965
    .line 966
    invoke-static {v4, v5, v7}, Lkp/g;->d(JF)J

    .line 967
    .line 968
    .line 969
    move-result-wide v15

    .line 970
    new-instance v6, Ld3/d;

    .line 971
    .line 972
    move v8, v7

    .line 973
    move-wide/from16 v17, p0

    .line 974
    .line 975
    const/4 v4, 0x0

    .line 976
    invoke-direct/range {v6 .. v18}, Ld3/d;-><init>(FFFFJJJJ)V

    .line 977
    .line 978
    .line 979
    invoke-static {v0, v6}, Le3/i;->c(Le3/i;Ld3/d;)V

    .line 980
    .line 981
    .line 982
    invoke-virtual {v3, v3, v0, v4}, Le3/i;->i(Le3/i;Le3/i;I)Z

    .line 983
    .line 984
    .line 985
    :cond_17
    new-instance v0, Laa/z;

    .line 986
    .line 987
    const/16 v4, 0x16

    .line 988
    .line 989
    invoke-direct {v0, v4, v3, v2}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 990
    .line 991
    .line 992
    invoke-virtual {v1, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 993
    .line 994
    .line 995
    move-result-object v0

    .line 996
    goto :goto_10

    .line 997
    :cond_18
    move-wide v13, v14

    .line 998
    move/from16 v8, v16

    .line 999
    .line 1000
    move-wide v15, v4

    .line 1001
    instance-of v2, v6, Le3/e0;

    .line 1002
    .line 1003
    if-eqz v2, :cond_1c

    .line 1004
    .line 1005
    iget-object v0, v0, Le1/s;->v:Le3/p0;

    .line 1006
    .line 1007
    if-eqz v8, :cond_19

    .line 1008
    .line 1009
    const-wide/16 v2, 0x0

    .line 1010
    .line 1011
    move-wide/from16 v19, v2

    .line 1012
    .line 1013
    goto :goto_d

    .line 1014
    :cond_19
    move-wide/from16 v19, v13

    .line 1015
    .line 1016
    :goto_d
    if-eqz v8, :cond_1a

    .line 1017
    .line 1018
    iget-object v2, v1, Lb3/d;->d:Lb3/b;

    .line 1019
    .line 1020
    invoke-interface {v2}, Lb3/b;->e()J

    .line 1021
    .line 1022
    .line 1023
    move-result-wide v4

    .line 1024
    move-wide/from16 v21, v4

    .line 1025
    .line 1026
    goto :goto_e

    .line 1027
    :cond_1a
    move-wide/from16 v21, v15

    .line 1028
    .line 1029
    :goto_e
    if-eqz v8, :cond_1b

    .line 1030
    .line 1031
    sget-object v2, Lg3/g;->a:Lg3/g;

    .line 1032
    .line 1033
    move-object/from16 v23, v2

    .line 1034
    .line 1035
    goto :goto_f

    .line 1036
    :cond_1b
    new-instance v6, Lg3/h;

    .line 1037
    .line 1038
    const/4 v11, 0x0

    .line 1039
    const/16 v12, 0x1e

    .line 1040
    .line 1041
    const/4 v8, 0x0

    .line 1042
    const/4 v9, 0x0

    .line 1043
    const/4 v10, 0x0

    .line 1044
    invoke-direct/range {v6 .. v12}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 1045
    .line 1046
    .line 1047
    move-object/from16 v23, v6

    .line 1048
    .line 1049
    :goto_f
    new-instance v17, Le1/p;

    .line 1050
    .line 1051
    move-object/from16 v18, v0

    .line 1052
    .line 1053
    invoke-direct/range {v17 .. v23}, Le1/p;-><init>(Le3/p0;JJLg3/e;)V

    .line 1054
    .line 1055
    .line 1056
    move-object/from16 v0, v17

    .line 1057
    .line 1058
    invoke-virtual {v1, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v0

    .line 1062
    goto :goto_10

    .line 1063
    :cond_1c
    new-instance v0, La8/r0;

    .line 1064
    .line 1065
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1066
    .line 1067
    .line 1068
    throw v0

    .line 1069
    :cond_1d
    new-instance v0, Ldj/a;

    .line 1070
    .line 1071
    const/16 v2, 0xd

    .line 1072
    .line 1073
    invoke-direct {v0, v2}, Ldj/a;-><init>(I)V

    .line 1074
    .line 1075
    .line 1076
    invoke-virtual {v1, v0}, Lb3/d;->b(Lay0/k;)Lb3/g;

    .line 1077
    .line 1078
    .line 1079
    move-result-object v0

    .line 1080
    :goto_10
    return-object v0

    .line 1081
    :pswitch_5
    check-cast v0, Ld01/v0;

    .line 1082
    .line 1083
    move-object/from16 v1, p1

    .line 1084
    .line 1085
    check-cast v1, Ljava/lang/Throwable;

    .line 1086
    .line 1087
    invoke-virtual {v0}, Ld01/v0;->close()V

    .line 1088
    .line 1089
    .line 1090
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1091
    .line 1092
    return-object v0

    .line 1093
    :pswitch_6
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 1094
    .line 1095
    move-object/from16 v1, p1

    .line 1096
    .line 1097
    check-cast v1, Lorg/json/JSONObject;

    .line 1098
    .line 1099
    const-string v2, "$this$forEachObject"

    .line 1100
    .line 1101
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1102
    .line 1103
    .line 1104
    const-string v2, "licenses"

    .line 1105
    .line 1106
    invoke-virtual {v1, v2}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v2

    .line 1110
    const/4 v3, 0x0

    .line 1111
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 1112
    .line 1113
    if-nez v2, :cond_1e

    .line 1114
    .line 1115
    move-object v5, v4

    .line 1116
    goto :goto_12

    .line 1117
    :cond_1e
    new-instance v5, Ljava/util/ArrayList;

    .line 1118
    .line 1119
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 1120
    .line 1121
    .line 1122
    invoke-virtual {v2}, Lorg/json/JSONArray;->length()I

    .line 1123
    .line 1124
    .line 1125
    move-result v6

    .line 1126
    move v7, v3

    .line 1127
    :goto_11
    if-ge v7, v6, :cond_1f

    .line 1128
    .line 1129
    invoke-virtual {v2, v7}, Lorg/json/JSONArray;->getString(I)Ljava/lang/String;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v8

    .line 1133
    const-string v9, "getString(...)"

    .line 1134
    .line 1135
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1136
    .line 1137
    .line 1138
    invoke-virtual {v0, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1139
    .line 1140
    .line 1141
    move-result-object v8

    .line 1142
    check-cast v8, Lcw/l;

    .line 1143
    .line 1144
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1145
    .line 1146
    .line 1147
    add-int/lit8 v7, v7, 0x1

    .line 1148
    .line 1149
    goto :goto_11

    .line 1150
    :cond_1f
    :goto_12
    check-cast v5, Ljava/lang/Iterable;

    .line 1151
    .line 1152
    new-instance v0, Ljava/util/ArrayList;

    .line 1153
    .line 1154
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1155
    .line 1156
    .line 1157
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v2

    .line 1161
    :cond_20
    :goto_13
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1162
    .line 1163
    .line 1164
    move-result v5

    .line 1165
    if-eqz v5, :cond_21

    .line 1166
    .line 1167
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v5

    .line 1171
    check-cast v5, Lcw/l;

    .line 1172
    .line 1173
    if-eqz v5, :cond_20

    .line 1174
    .line 1175
    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1176
    .line 1177
    .line 1178
    goto :goto_13

    .line 1179
    :cond_21
    new-instance v2, Ljava/util/HashSet;

    .line 1180
    .line 1181
    const/16 v5, 0xc

    .line 1182
    .line 1183
    invoke-static {v0, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 1184
    .line 1185
    .line 1186
    move-result v5

    .line 1187
    invoke-static {v5}, Lmx0/x;->k(I)I

    .line 1188
    .line 1189
    .line 1190
    move-result v5

    .line 1191
    invoke-direct {v2, v5}, Ljava/util/HashSet;-><init>(I)V

    .line 1192
    .line 1193
    .line 1194
    invoke-static {v0, v2}, Lmx0/q;->u0(Ljava/lang/Iterable;Ljava/util/AbstractCollection;)V

    .line 1195
    .line 1196
    .line 1197
    const-string v0, "developers"

    .line 1198
    .line 1199
    invoke-virtual {v1, v0}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 1200
    .line 1201
    .line 1202
    move-result-object v0

    .line 1203
    const-string v5, "name"

    .line 1204
    .line 1205
    if-eqz v0, :cond_22

    .line 1206
    .line 1207
    new-instance v4, Ljava/util/ArrayList;

    .line 1208
    .line 1209
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1210
    .line 1211
    .line 1212
    invoke-virtual {v0}, Lorg/json/JSONArray;->length()I

    .line 1213
    .line 1214
    .line 1215
    move-result v6

    .line 1216
    :goto_14
    if-ge v3, v6, :cond_22

    .line 1217
    .line 1218
    invoke-virtual {v0, v3}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    .line 1219
    .line 1220
    .line 1221
    move-result-object v7

    .line 1222
    const-string v8, "getJSONObject(...)"

    .line 1223
    .line 1224
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1225
    .line 1226
    .line 1227
    new-instance v8, Lcw/c;

    .line 1228
    .line 1229
    invoke-virtual {v7, v5}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1230
    .line 1231
    .line 1232
    move-result-object v9

    .line 1233
    const-string v10, "organisationUrl"

    .line 1234
    .line 1235
    invoke-virtual {v7, v10}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v7

    .line 1239
    invoke-direct {v8, v9, v7}, Lcw/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1240
    .line 1241
    .line 1242
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1243
    .line 1244
    .line 1245
    add-int/lit8 v3, v3, 0x1

    .line 1246
    .line 1247
    goto :goto_14

    .line 1248
    :cond_22
    const-string v0, "organization"

    .line 1249
    .line 1250
    invoke-virtual {v1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v0

    .line 1254
    const/4 v3, 0x0

    .line 1255
    const-string v6, "url"

    .line 1256
    .line 1257
    if-eqz v0, :cond_24

    .line 1258
    .line 1259
    new-instance v7, Lcw/o;

    .line 1260
    .line 1261
    invoke-virtual {v0, v5}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v8

    .line 1265
    if-nez v8, :cond_23

    .line 1266
    .line 1267
    const-string v8, ""

    .line 1268
    .line 1269
    :cond_23
    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1270
    .line 1271
    .line 1272
    move-result-object v0

    .line 1273
    invoke-direct {v7, v8, v0}, Lcw/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1274
    .line 1275
    .line 1276
    move-object/from16 v16, v7

    .line 1277
    .line 1278
    goto :goto_15

    .line 1279
    :cond_24
    move-object/from16 v16, v3

    .line 1280
    .line 1281
    :goto_15
    const-string v0, "scm"

    .line 1282
    .line 1283
    invoke-virtual {v1, v0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 1284
    .line 1285
    .line 1286
    move-result-object v0

    .line 1287
    if-eqz v0, :cond_25

    .line 1288
    .line 1289
    new-instance v3, Lcw/r;

    .line 1290
    .line 1291
    const-string v7, "connection"

    .line 1292
    .line 1293
    invoke-virtual {v0, v7}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1294
    .line 1295
    .line 1296
    move-result-object v7

    .line 1297
    const-string v8, "developerConnection"

    .line 1298
    .line 1299
    invoke-virtual {v0, v8}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v8

    .line 1303
    invoke-virtual {v0, v6}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1304
    .line 1305
    .line 1306
    move-result-object v0

    .line 1307
    invoke-direct {v3, v7, v8, v0}, Lcw/r;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1308
    .line 1309
    .line 1310
    :cond_25
    move-object/from16 v17, v3

    .line 1311
    .line 1312
    const-string v0, "funding"

    .line 1313
    .line 1314
    invoke-virtual {v1, v0}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    .line 1315
    .line 1316
    .line 1317
    move-result-object v0

    .line 1318
    new-instance v3, Ldj/a;

    .line 1319
    .line 1320
    const/16 v6, 0x8

    .line 1321
    .line 1322
    invoke-direct {v3, v6}, Ldj/a;-><init>(I)V

    .line 1323
    .line 1324
    .line 1325
    invoke-static {v0, v3}, Ljp/kg;->a(Lorg/json/JSONArray;Lay0/k;)Ljava/util/List;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v0

    .line 1329
    check-cast v0, Ljava/lang/Iterable;

    .line 1330
    .line 1331
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 1332
    .line 1333
    .line 1334
    move-result-object v0

    .line 1335
    const-string v3, "uniqueId"

    .line 1336
    .line 1337
    invoke-virtual {v1, v3}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 1338
    .line 1339
    .line 1340
    move-result-object v10

    .line 1341
    new-instance v9, Lcw/i;

    .line 1342
    .line 1343
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 1344
    .line 1345
    .line 1346
    const-string v3, "artifactVersion"

    .line 1347
    .line 1348
    invoke-virtual {v1, v3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1349
    .line 1350
    .line 1351
    move-result-object v11

    .line 1352
    invoke-virtual {v1, v5, v10}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1353
    .line 1354
    .line 1355
    move-result-object v12

    .line 1356
    const-string v3, "optString(...)"

    .line 1357
    .line 1358
    invoke-static {v12, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1359
    .line 1360
    .line 1361
    const-string v3, "description"

    .line 1362
    .line 1363
    invoke-virtual {v1, v3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v13

    .line 1367
    const-string v3, "website"

    .line 1368
    .line 1369
    invoke-virtual {v1, v3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1370
    .line 1371
    .line 1372
    move-result-object v14

    .line 1373
    check-cast v4, Ljava/lang/Iterable;

    .line 1374
    .line 1375
    invoke-static {v4}, Ljp/kg;->c(Ljava/lang/Iterable;)Lqy0/b;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v15

    .line 1379
    invoke-static {v2}, Ljp/kg;->d(Ljava/lang/Iterable;)Lqy0/c;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v18

    .line 1383
    check-cast v0, Ljava/lang/Iterable;

    .line 1384
    .line 1385
    invoke-static {v0}, Ljp/kg;->d(Ljava/lang/Iterable;)Lqy0/c;

    .line 1386
    .line 1387
    .line 1388
    move-result-object v19

    .line 1389
    const-string v0, "tag"

    .line 1390
    .line 1391
    invoke-virtual {v1, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 1392
    .line 1393
    .line 1394
    move-result-object v20

    .line 1395
    invoke-direct/range {v9 .. v20}, Lcw/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqy0/b;Lcw/o;Lcw/r;Lqy0/c;Lqy0/c;Ljava/lang/String;)V

    .line 1396
    .line 1397
    .line 1398
    return-object v9

    .line 1399
    :pswitch_7
    check-cast v0, Le3/f;

    .line 1400
    .line 1401
    move-object/from16 v1, p1

    .line 1402
    .line 1403
    check-cast v1, Le3/k0;

    .line 1404
    .line 1405
    const-string v2, "$this$graphicsLayer"

    .line 1406
    .line 1407
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1408
    .line 1409
    .line 1410
    iget-object v0, v0, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 1411
    .line 1412
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1413
    .line 1414
    .line 1415
    move-result v0

    .line 1416
    int-to-float v0, v0

    .line 1417
    const/high16 v2, 0x40000000    # 2.0f

    .line 1418
    .line 1419
    div-float/2addr v0, v2

    .line 1420
    neg-float v0, v0

    .line 1421
    invoke-virtual {v1, v0}, Le3/k0;->D(F)V

    .line 1422
    .line 1423
    .line 1424
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1425
    .line 1426
    return-object v0

    .line 1427
    :pswitch_8
    check-cast v0, Ltb/w;

    .line 1428
    .line 1429
    move-object/from16 v1, p1

    .line 1430
    .line 1431
    check-cast v1, Lgi/c;

    .line 1432
    .line 1433
    const-string v2, "$this$log"

    .line 1434
    .line 1435
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1436
    .line 1437
    .line 1438
    iget-object v0, v0, Ltb/w;->d:Ljava/lang/String;

    .line 1439
    .line 1440
    const-string v1, "Unknown legal document "

    .line 1441
    .line 1442
    invoke-static {v1, v0}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1443
    .line 1444
    .line 1445
    move-result-object v0

    .line 1446
    return-object v0

    .line 1447
    :pswitch_9
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 1448
    .line 1449
    move-object/from16 v1, p1

    .line 1450
    .line 1451
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1452
    .line 1453
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;->b(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 1454
    .line 1455
    .line 1456
    move-result-object v0

    .line 1457
    return-object v0

    .line 1458
    :pswitch_a
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;

    .line 1459
    .line 1460
    move-object/from16 v1, p1

    .line 1461
    .line 1462
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1463
    .line 1464
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineState;

    .line 1465
    .line 1466
    .line 1467
    move-result-object v0

    .line 1468
    return-object v0

    .line 1469
    :pswitch_b
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;

    .line 1470
    .line 1471
    move-object/from16 v1, p1

    .line 1472
    .line 1473
    check-cast v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;

    .line 1474
    .line 1475
    invoke-static {v0, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Connecting;Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionEstablishmentState$Timeout;

    .line 1476
    .line 1477
    .line 1478
    move-result-object v0

    .line 1479
    return-object v0

    .line 1480
    :pswitch_c
    check-cast v0, Lc80/t;

    .line 1481
    .line 1482
    move-object/from16 v1, p1

    .line 1483
    .line 1484
    check-cast v1, Lql0/f;

    .line 1485
    .line 1486
    const-string v2, "it"

    .line 1487
    .line 1488
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1489
    .line 1490
    .line 1491
    invoke-virtual {v0}, Lc80/t;->h()V

    .line 1492
    .line 1493
    .line 1494
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1495
    .line 1496
    return-object v0

    .line 1497
    :pswitch_d
    check-cast v0, Lc80/m;

    .line 1498
    .line 1499
    move-object/from16 v1, p1

    .line 1500
    .line 1501
    check-cast v1, Lql0/f;

    .line 1502
    .line 1503
    const-string v2, "it"

    .line 1504
    .line 1505
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1506
    .line 1507
    .line 1508
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1509
    .line 1510
    .line 1511
    move-result-object v1

    .line 1512
    move-object v2, v1

    .line 1513
    check-cast v2, Lc80/k;

    .line 1514
    .line 1515
    const/4 v9, 0x0

    .line 1516
    const/16 v10, 0x7a

    .line 1517
    .line 1518
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 1519
    .line 1520
    const/4 v4, 0x0

    .line 1521
    const/4 v5, 0x0

    .line 1522
    const/4 v6, 0x0

    .line 1523
    const/4 v7, 0x0

    .line 1524
    const/4 v8, 0x0

    .line 1525
    invoke-static/range {v2 .. v10}, Lc80/k;->a(Lc80/k;Ljava/util/List;Ljava/lang/String;Lql0/g;Ljava/lang/String;Ljava/lang/String;ZZI)Lc80/k;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v1

    .line 1529
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1530
    .line 1531
    .line 1532
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1533
    .line 1534
    return-object v0

    .line 1535
    :pswitch_e
    check-cast v0, Lcm/d;

    .line 1536
    .line 1537
    move-object/from16 v1, p1

    .line 1538
    .line 1539
    check-cast v1, Ljava/io/IOException;

    .line 1540
    .line 1541
    const/4 v1, 0x1

    .line 1542
    iput-boolean v1, v0, Lcm/d;->o:Z

    .line 1543
    .line 1544
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1545
    .line 1546
    return-object v0

    .line 1547
    :pswitch_f
    check-cast v0, Lce/u;

    .line 1548
    .line 1549
    move-object/from16 v1, p1

    .line 1550
    .line 1551
    check-cast v1, Lgi/c;

    .line 1552
    .line 1553
    const-string v2, "$this$log"

    .line 1554
    .line 1555
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1556
    .line 1557
    .line 1558
    iget-object v0, v0, Lce/u;->d:Ljava/lang/String;

    .line 1559
    .line 1560
    const-string v1, "Failed to load CPOI "

    .line 1561
    .line 1562
    const-string v2, " data"

    .line 1563
    .line 1564
    invoke-static {v1, v0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1565
    .line 1566
    .line 1567
    move-result-object v0

    .line 1568
    return-object v0

    .line 1569
    :pswitch_10
    check-cast v0, Lba0/c;

    .line 1570
    .line 1571
    move-object/from16 v1, p1

    .line 1572
    .line 1573
    check-cast v1, Lm1/f;

    .line 1574
    .line 1575
    const-string v2, "$this$LazyColumn"

    .line 1576
    .line 1577
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1578
    .line 1579
    .line 1580
    iget-object v2, v0, Lba0/c;->b:Ljava/lang/String;

    .line 1581
    .line 1582
    const/4 v3, 0x1

    .line 1583
    if-eqz v2, :cond_26

    .line 1584
    .line 1585
    new-instance v4, La71/z0;

    .line 1586
    .line 1587
    const/4 v5, 0x2

    .line 1588
    invoke-direct {v4, v2, v5}, La71/z0;-><init>(Ljava/lang/String;I)V

    .line 1589
    .line 1590
    .line 1591
    new-instance v2, Lt2/b;

    .line 1592
    .line 1593
    const v5, 0x277716d0

    .line 1594
    .line 1595
    .line 1596
    invoke-direct {v2, v4, v3, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1597
    .line 1598
    .line 1599
    const/4 v4, 0x3

    .line 1600
    invoke-static {v1, v2, v4}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1601
    .line 1602
    .line 1603
    :cond_26
    iget-object v0, v0, Lba0/c;->c:Ljava/util/List;

    .line 1604
    .line 1605
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 1606
    .line 1607
    .line 1608
    move-result v2

    .line 1609
    new-instance v4, Lak/p;

    .line 1610
    .line 1611
    const/4 v5, 0x4

    .line 1612
    invoke-direct {v4, v0, v5}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1613
    .line 1614
    .line 1615
    new-instance v5, Lb60/h;

    .line 1616
    .line 1617
    const/4 v6, 0x1

    .line 1618
    invoke-direct {v5, v0, v6}, Lb60/h;-><init>(Ljava/lang/Object;I)V

    .line 1619
    .line 1620
    .line 1621
    new-instance v0, Lt2/b;

    .line 1622
    .line 1623
    const v6, 0x2fd4df92

    .line 1624
    .line 1625
    .line 1626
    invoke-direct {v0, v5, v3, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1627
    .line 1628
    .line 1629
    const/4 v3, 0x0

    .line 1630
    invoke-virtual {v1, v2, v3, v4, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1631
    .line 1632
    .line 1633
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1634
    .line 1635
    return-object v0

    .line 1636
    :pswitch_11
    check-cast v0, Lc81/d;

    .line 1637
    .line 1638
    move-object/from16 v1, p1

    .line 1639
    .line 1640
    check-cast v1, Ls71/q;

    .line 1641
    .line 1642
    const-string v2, "userAction"

    .line 1643
    .line 1644
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1645
    .line 1646
    .line 1647
    iget-object v2, v0, Lc81/d;->e:Lt71/a;

    .line 1648
    .line 1649
    if-eqz v2, :cond_27

    .line 1650
    .line 1651
    iput-object v1, v2, Lt71/a;->b:Ls71/q;

    .line 1652
    .line 1653
    iget-object v1, v2, Lt71/a;->g:Lt71/b;

    .line 1654
    .line 1655
    if-eqz v1, :cond_27

    .line 1656
    .line 1657
    invoke-interface {v1, v2}, Lt71/b;->userActionDidChange(Lt71/a;)V

    .line 1658
    .line 1659
    .line 1660
    :cond_27
    iget-object v1, v0, Lc81/d;->e:Lt71/a;

    .line 1661
    .line 1662
    if-eqz v1, :cond_28

    .line 1663
    .line 1664
    iget-object v0, v0, Lc81/d;->b:Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/RPAStateMachine;

    .line 1665
    .line 1666
    new-instance v2, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;

    .line 1667
    .line 1668
    invoke-direct {v2, v1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/MessageSentInput;-><init>(Ljava/lang/Object;)V

    .line 1669
    .line 1670
    .line 1671
    invoke-virtual {v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/StateMachine;->reactToInput(Ltechnology/cariad/cat/remoteparkassistcoremeb/core/statemachine/state/StateMachineInput;)Z

    .line 1672
    .line 1673
    .line 1674
    :cond_28
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1675
    .line 1676
    return-object v0

    .line 1677
    :pswitch_12
    check-cast v0, Landroidx/lifecycle/c1;

    .line 1678
    .line 1679
    move-object/from16 v1, p1

    .line 1680
    .line 1681
    check-cast v1, Ls71/q;

    .line 1682
    .line 1683
    const-string v2, "userAction"

    .line 1684
    .line 1685
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1686
    .line 1687
    .line 1688
    iget-object v2, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 1689
    .line 1690
    check-cast v2, Le81/x;

    .line 1691
    .line 1692
    invoke-virtual {v2}, Le81/x;->getAllSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v3

    .line 1696
    invoke-interface {v3, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1697
    .line 1698
    .line 1699
    move-result v3

    .line 1700
    if-nez v3, :cond_2a

    .line 1701
    .line 1702
    invoke-virtual {v2}, Le81/x;->getAllSupportedUserActions$remoteparkassistcoremeb_release()Ljava/util/Set;

    .line 1703
    .line 1704
    .line 1705
    move-result-object v3

    .line 1706
    check-cast v3, Ljava/lang/Iterable;

    .line 1707
    .line 1708
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1709
    .line 1710
    .line 1711
    move-result-object v4

    .line 1712
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1713
    .line 1714
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1715
    .line 1716
    .line 1717
    move-result-object v4

    .line 1718
    invoke-static {v3, v4}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 1719
    .line 1720
    .line 1721
    move-result v3

    .line 1722
    if-eqz v3, :cond_29

    .line 1723
    .line 1724
    goto :goto_16

    .line 1725
    :cond_29
    iget-object v0, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 1726
    .line 1727
    check-cast v0, Ll71/w;

    .line 1728
    .line 1729
    iget-object v0, v0, Ll71/w;->b:Lu61/b;

    .line 1730
    .line 1731
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1732
    .line 1733
    .line 1734
    move-result-object v2

    .line 1735
    invoke-virtual {v5, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1736
    .line 1737
    .line 1738
    move-result-object v2

    .line 1739
    invoke-interface {v2}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 1740
    .line 1741
    .line 1742
    move-result-object v2

    .line 1743
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1744
    .line 1745
    const-string v4, "Blocking user action "

    .line 1746
    .line 1747
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1748
    .line 1749
    .line 1750
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1751
    .line 1752
    .line 1753
    const-string v1, " as it is not supported for "

    .line 1754
    .line 1755
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1756
    .line 1757
    .line 1758
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1759
    .line 1760
    .line 1761
    const-string v1, "."

    .line 1762
    .line 1763
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1764
    .line 1765
    .line 1766
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1767
    .line 1768
    .line 1769
    move-result-object v1

    .line 1770
    invoke-static {v0, v1}, Lo71/a;->e(Lo71/a;Ljava/lang/String;)V

    .line 1771
    .line 1772
    .line 1773
    goto :goto_17

    .line 1774
    :cond_2a
    :goto_16
    iget-object v0, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 1775
    .line 1776
    check-cast v0, La2/e;

    .line 1777
    .line 1778
    if-eqz v0, :cond_2b

    .line 1779
    .line 1780
    invoke-virtual {v0, v1}, La2/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1781
    .line 1782
    .line 1783
    :cond_2b
    :goto_17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1784
    .line 1785
    return-object v0

    .line 1786
    :pswitch_13
    check-cast v0, Lb40/i;

    .line 1787
    .line 1788
    move-object/from16 v1, p1

    .line 1789
    .line 1790
    check-cast v1, Lql0/f;

    .line 1791
    .line 1792
    const-string v2, "it"

    .line 1793
    .line 1794
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1795
    .line 1796
    .line 1797
    invoke-virtual {v0}, Lb40/i;->h()V

    .line 1798
    .line 1799
    .line 1800
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1801
    .line 1802
    return-object v0

    .line 1803
    :pswitch_14
    check-cast v0, Lc2/q;

    .line 1804
    .line 1805
    move-object/from16 v1, p1

    .line 1806
    .line 1807
    check-cast v1, Ll4/g;

    .line 1808
    .line 1809
    invoke-virtual {v0, v1}, Lc2/q;->a(Ll4/g;)V

    .line 1810
    .line 1811
    .line 1812
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1813
    .line 1814
    return-object v0

    .line 1815
    :pswitch_15
    check-cast v0, Lc00/k1;

    .line 1816
    .line 1817
    move-object/from16 v1, p1

    .line 1818
    .line 1819
    check-cast v1, Ljava/lang/Boolean;

    .line 1820
    .line 1821
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1822
    .line 1823
    .line 1824
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1825
    .line 1826
    .line 1827
    move-result-object v1

    .line 1828
    move-object v2, v1

    .line 1829
    check-cast v2, Lc00/y0;

    .line 1830
    .line 1831
    const/16 v18, 0x0

    .line 1832
    .line 1833
    const v19, 0x7ffdf

    .line 1834
    .line 1835
    .line 1836
    const/4 v3, 0x0

    .line 1837
    const/4 v4, 0x0

    .line 1838
    const/4 v5, 0x0

    .line 1839
    const/4 v6, 0x0

    .line 1840
    const/4 v7, 0x0

    .line 1841
    const/4 v8, 0x0

    .line 1842
    const/4 v9, 0x0

    .line 1843
    const/4 v10, 0x0

    .line 1844
    const/4 v11, 0x0

    .line 1845
    const/4 v12, 0x0

    .line 1846
    const/4 v13, 0x0

    .line 1847
    const/4 v14, 0x0

    .line 1848
    const/4 v15, 0x0

    .line 1849
    const/16 v16, 0x0

    .line 1850
    .line 1851
    const/16 v17, 0x0

    .line 1852
    .line 1853
    invoke-static/range {v2 .. v19}, Lc00/y0;->a(Lc00/y0;ZZZLc00/u0;Lc00/w0;Lc00/x0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lc00/v0;Llf0/i;ZZLqr0/q;Lqr0/q;ZI)Lc00/y0;

    .line 1854
    .line 1855
    .line 1856
    move-result-object v1

    .line 1857
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1858
    .line 1859
    .line 1860
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1861
    .line 1862
    return-object v0

    .line 1863
    :pswitch_16
    check-cast v0, Lc00/i0;

    .line 1864
    .line 1865
    move-object/from16 v1, p1

    .line 1866
    .line 1867
    check-cast v1, Ljava/lang/Boolean;

    .line 1868
    .line 1869
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1870
    .line 1871
    .line 1872
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1873
    .line 1874
    .line 1875
    move-result-object v1

    .line 1876
    move-object v2, v1

    .line 1877
    check-cast v2, Lc00/d0;

    .line 1878
    .line 1879
    const/16 v23, 0x0

    .line 1880
    .line 1881
    const v24, 0x3ffdff

    .line 1882
    .line 1883
    .line 1884
    const/4 v3, 0x0

    .line 1885
    const/4 v4, 0x0

    .line 1886
    const/4 v5, 0x0

    .line 1887
    const/4 v6, 0x0

    .line 1888
    const/4 v7, 0x0

    .line 1889
    const/4 v8, 0x0

    .line 1890
    const/4 v9, 0x0

    .line 1891
    const/4 v10, 0x0

    .line 1892
    const/4 v11, 0x0

    .line 1893
    const/4 v12, 0x0

    .line 1894
    const/4 v13, 0x0

    .line 1895
    const/4 v14, 0x0

    .line 1896
    const/4 v15, 0x0

    .line 1897
    const/16 v16, 0x0

    .line 1898
    .line 1899
    const/16 v17, 0x0

    .line 1900
    .line 1901
    const/16 v18, 0x0

    .line 1902
    .line 1903
    const/16 v19, 0x0

    .line 1904
    .line 1905
    const/16 v20, 0x0

    .line 1906
    .line 1907
    const/16 v21, 0x0

    .line 1908
    .line 1909
    const/16 v22, 0x0

    .line 1910
    .line 1911
    invoke-static/range {v2 .. v24}, Lc00/d0;->a(Lc00/d0;Lc00/z;ZZLc00/a0;ZZZLc00/y;Lc00/c0;Lc00/b0;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;Llf0/i;ZZZZZZI)Lc00/d0;

    .line 1912
    .line 1913
    .line 1914
    move-result-object v1

    .line 1915
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1916
    .line 1917
    .line 1918
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1919
    .line 1920
    return-object v0

    .line 1921
    :pswitch_17
    check-cast v0, Lqw/b;

    .line 1922
    .line 1923
    move-object/from16 v1, p1

    .line 1924
    .line 1925
    check-cast v1, Ljava/lang/Integer;

    .line 1926
    .line 1927
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1928
    .line 1929
    .line 1930
    return-object v0

    .line 1931
    :pswitch_18
    check-cast v0, La60/i;

    .line 1932
    .line 1933
    move-object/from16 v1, p1

    .line 1934
    .line 1935
    check-cast v1, Lm1/f;

    .line 1936
    .line 1937
    const-string v2, "$this$LazyColumn"

    .line 1938
    .line 1939
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1940
    .line 1941
    .line 1942
    iget-object v0, v0, La60/i;->a:La60/h;

    .line 1943
    .line 1944
    if-eqz v0, :cond_2c

    .line 1945
    .line 1946
    new-instance v2, Lb50/c;

    .line 1947
    .line 1948
    const/4 v3, 0x2

    .line 1949
    invoke-direct {v2, v0, v3}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 1950
    .line 1951
    .line 1952
    new-instance v0, Lt2/b;

    .line 1953
    .line 1954
    const/4 v3, 0x1

    .line 1955
    const v4, -0x1f88a086    # -7.13004E19f

    .line 1956
    .line 1957
    .line 1958
    invoke-direct {v0, v2, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1959
    .line 1960
    .line 1961
    const/4 v2, 0x3

    .line 1962
    invoke-static {v1, v0, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1963
    .line 1964
    .line 1965
    :cond_2c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1966
    .line 1967
    return-object v0

    .line 1968
    :pswitch_19
    check-cast v0, Li91/r2;

    .line 1969
    .line 1970
    move-object/from16 v1, p1

    .line 1971
    .line 1972
    check-cast v1, Ljava/lang/Boolean;

    .line 1973
    .line 1974
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1975
    .line 1976
    .line 1977
    move-result v1

    .line 1978
    if-eqz v1, :cond_2d

    .line 1979
    .line 1980
    sget-object v1, Li91/s2;->d:Li91/s2;

    .line 1981
    .line 1982
    invoke-virtual {v0, v1}, Li91/r2;->f(Li91/s2;)V

    .line 1983
    .line 1984
    .line 1985
    :cond_2d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1986
    .line 1987
    return-object v0

    .line 1988
    :pswitch_1a
    check-cast v0, Lac0/w;

    .line 1989
    .line 1990
    move-object/from16 v1, p1

    .line 1991
    .line 1992
    check-cast v1, Ljava/lang/Throwable;

    .line 1993
    .line 1994
    new-instance v1, La2/m;

    .line 1995
    .line 1996
    const/4 v2, 0x3

    .line 1997
    invoke-direct {v1, v2}, La2/m;-><init>(I)V

    .line 1998
    .line 1999
    .line 2000
    const/4 v2, 0x0

    .line 2001
    invoke-static {v2, v0, v1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 2002
    .line 2003
    .line 2004
    iget-object v0, v0, Lac0/w;->k:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2005
    .line 2006
    invoke-virtual {v0, v2}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 2007
    .line 2008
    .line 2009
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2010
    .line 2011
    return-object v0

    .line 2012
    :pswitch_1b
    check-cast v0, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;

    .line 2013
    .line 2014
    move-object/from16 v1, p1

    .line 2015
    .line 2016
    check-cast v1, Ls71/k;

    .line 2017
    .line 2018
    const-string v2, "it"

    .line 2019
    .line 2020
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2021
    .line 2022
    .line 2023
    invoke-interface {v0, v1}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ScenarioSelectionAndDriveViewModel;->requestScenarioSelection(Ls71/k;)V

    .line 2024
    .line 2025
    .line 2026
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2027
    .line 2028
    return-object v0

    .line 2029
    :pswitch_1c
    check-cast v0, La2/d;

    .line 2030
    .line 2031
    move-object/from16 v1, p1

    .line 2032
    .line 2033
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 2034
    .line 2035
    new-instance v1, La2/j;

    .line 2036
    .line 2037
    const/4 v2, 0x0

    .line 2038
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 2039
    .line 2040
    .line 2041
    return-object v1

    .line 2042
    nop

    .line 2043
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
