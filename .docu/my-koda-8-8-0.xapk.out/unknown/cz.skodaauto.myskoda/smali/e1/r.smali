.class public final synthetic Le1/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:J

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(J[FLkotlin/jvm/internal/d0;Lkotlin/jvm/internal/c0;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Le1/r;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-wide p1, p0, Le1/r;->e:J

    iput-object p3, p0, Le1/r;->f:Ljava/lang/Object;

    iput-object p4, p0, Le1/r;->g:Ljava/lang/Object;

    iput-object p5, p0, Le1/r;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;JLjava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Le1/r;->d:I

    iput-object p1, p0, Le1/r;->f:Ljava/lang/Object;

    iput-object p2, p0, Le1/r;->g:Ljava/lang/Object;

    iput-wide p3, p0, Le1/r;->e:J

    iput-object p5, p0, Le1/r;->h:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Le1/r;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Le1/r;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Li2/l0;

    .line 11
    .line 12
    iget-object v2, v0, Le1/r;->g:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ll2/t2;

    .line 15
    .line 16
    iget-wide v4, v0, Le1/r;->e:J

    .line 17
    .line 18
    iget-object v0, v0, Le1/r;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v0, Le3/i;

    .line 21
    .line 22
    move-object/from16 v3, p1

    .line 23
    .line 24
    check-cast v3, Lg3/d;

    .line 25
    .line 26
    invoke-interface {v1}, Li2/l0;->invoke()F

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const/high16 v6, 0x3f800000    # 1.0f

    .line 31
    .line 32
    invoke-static {v6, v1}, Ljava/lang/Math;->min(FF)F

    .line 33
    .line 34
    .line 35
    move-result v7

    .line 36
    const v8, 0x3ecccccd    # 0.4f

    .line 37
    .line 38
    .line 39
    sub-float/2addr v7, v8

    .line 40
    const/4 v9, 0x0

    .line 41
    invoke-static {v7, v9}, Ljava/lang/Math;->max(FF)F

    .line 42
    .line 43
    .line 44
    move-result v7

    .line 45
    const/4 v10, 0x5

    .line 46
    int-to-float v10, v10

    .line 47
    mul-float/2addr v7, v10

    .line 48
    const/4 v10, 0x3

    .line 49
    int-to-float v10, v10

    .line 50
    div-float/2addr v7, v10

    .line 51
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    sub-float/2addr v1, v6

    .line 56
    const/high16 v10, 0x40000000    # 2.0f

    .line 57
    .line 58
    invoke-static {v1, v9, v10}, Lkp/r9;->d(FFF)F

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    float-to-double v11, v1

    .line 63
    const/4 v9, 0x2

    .line 64
    int-to-double v13, v9

    .line 65
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->pow(DD)D

    .line 66
    .line 67
    .line 68
    move-result-wide v11

    .line 69
    double-to-float v9, v11

    .line 70
    const/4 v11, 0x4

    .line 71
    int-to-float v11, v11

    .line 72
    div-float/2addr v9, v11

    .line 73
    sub-float/2addr v1, v9

    .line 74
    const v9, 0x3f4ccccd    # 0.8f

    .line 75
    .line 76
    .line 77
    mul-float/2addr v9, v7

    .line 78
    const/high16 v11, -0x41800000    # -0.25f

    .line 79
    .line 80
    mul-float/2addr v8, v7

    .line 81
    add-float/2addr v8, v11

    .line 82
    add-float/2addr v8, v1

    .line 83
    const/high16 v1, 0x3f000000    # 0.5f

    .line 84
    .line 85
    mul-float/2addr v8, v1

    .line 86
    const/16 v1, 0x168

    .line 87
    .line 88
    int-to-float v1, v1

    .line 89
    mul-float v11, v8, v1

    .line 90
    .line 91
    add-float/2addr v9, v8

    .line 92
    mul-float/2addr v9, v1

    .line 93
    invoke-static {v6, v7}, Ljava/lang/Math;->min(FF)F

    .line 94
    .line 95
    .line 96
    move-result v1

    .line 97
    new-instance v15, Lb1/x0;

    .line 98
    .line 99
    invoke-direct {v15}, Ljava/lang/Object;-><init>()V

    .line 100
    .line 101
    .line 102
    iput v9, v15, Lb1/x0;->d:F

    .line 103
    .line 104
    iput v1, v15, Lb1/x0;->e:F

    .line 105
    .line 106
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    check-cast v1, Ljava/lang/Number;

    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 113
    .line 114
    .line 115
    move-result v12

    .line 116
    invoke-interface {v3}, Lg3/d;->D0()J

    .line 117
    .line 118
    .line 119
    move-result-wide v1

    .line 120
    invoke-interface {v3}, Lg3/d;->x0()Lgw0/c;

    .line 121
    .line 122
    .line 123
    move-result-object v6

    .line 124
    invoke-virtual {v6}, Lgw0/c;->o()J

    .line 125
    .line 126
    .line 127
    move-result-wide v13

    .line 128
    invoke-virtual {v6}, Lgw0/c;->h()Le3/r;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    invoke-interface {v7}, Le3/r;->o()V

    .line 133
    .line 134
    .line 135
    :try_start_0
    iget-object v7, v6, Lgw0/c;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v7, Lbu/c;

    .line 138
    .line 139
    invoke-virtual {v7, v1, v2, v8}, Lbu/c;->z(JF)V

    .line 140
    .line 141
    .line 142
    sget v1, Lj2/i;->b:F

    .line 143
    .line 144
    invoke-interface {v3, v1}, Lt4/c;->w0(F)F

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    sget v2, Lj2/i;->a:F

    .line 149
    .line 150
    invoke-interface {v3, v2}, Lt4/c;->w0(F)F

    .line 151
    .line 152
    .line 153
    move-result v7

    .line 154
    div-float/2addr v7, v10

    .line 155
    add-float/2addr v7, v1

    .line 156
    invoke-interface {v3}, Lg3/d;->e()J

    .line 157
    .line 158
    .line 159
    move-result-wide v16

    .line 160
    move-object/from16 p0, v0

    .line 161
    .line 162
    invoke-static/range {v16 .. v17}, Ljp/ef;->d(J)J

    .line 163
    .line 164
    .line 165
    move-result-wide v0

    .line 166
    invoke-static {v0, v1, v7}, Ljp/cf;->b(JF)Ld3/c;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    sub-float v7, v9, v11

    .line 171
    .line 172
    invoke-virtual {v0}, Ld3/c;->d()J

    .line 173
    .line 174
    .line 175
    move-result-wide v8
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 176
    move-object v1, v6

    .line 177
    move v6, v11

    .line 178
    :try_start_1
    invoke-virtual {v0}, Ld3/c;->c()J

    .line 179
    .line 180
    .line 181
    move-result-wide v10

    .line 182
    new-instance v16, Lg3/h;

    .line 183
    .line 184
    invoke-interface {v3, v2}, Lt4/c;->w0(F)F

    .line 185
    .line 186
    .line 187
    move-result v17

    .line 188
    const/16 v21, 0x0

    .line 189
    .line 190
    const/16 v22, 0x1a

    .line 191
    .line 192
    const/16 v18, 0x0

    .line 193
    .line 194
    const/16 v19, 0x0

    .line 195
    .line 196
    const/16 v20, 0x0

    .line 197
    .line 198
    invoke-direct/range {v16 .. v22}, Lg3/h;-><init>(FFIILe3/j;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 199
    .line 200
    .line 201
    move-wide/from16 v17, v13

    .line 202
    .line 203
    const/16 v14, 0x300

    .line 204
    .line 205
    move-object/from16 v13, v16

    .line 206
    .line 207
    move-wide/from16 v23, v17

    .line 208
    .line 209
    :try_start_2
    invoke-static/range {v3 .. v14}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 210
    .line 211
    .line 212
    move-wide v6, v4

    .line 213
    move v8, v12

    .line 214
    move-object v9, v15

    .line 215
    move-object/from16 v4, p0

    .line 216
    .line 217
    move-object v5, v0

    .line 218
    invoke-static/range {v3 .. v9}, Lj2/i;->c(Lg3/d;Le3/i;Ld3/c;JFLb1/x0;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 219
    .line 220
    .line 221
    move-wide/from16 v2, v23

    .line 222
    .line 223
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 224
    .line 225
    .line 226
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object v0

    .line 229
    :catchall_0
    move-exception v0

    .line 230
    move-wide/from16 v2, v23

    .line 231
    .line 232
    goto :goto_2

    .line 233
    :catchall_1
    move-exception v0

    .line 234
    goto :goto_1

    .line 235
    :catchall_2
    move-exception v0

    .line 236
    move-object v1, v6

    .line 237
    :goto_1
    move-wide v2, v13

    .line 238
    :goto_2
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 239
    .line 240
    .line 241
    throw v0

    .line 242
    :pswitch_0
    iget-object v1, v0, Le1/r;->f:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v1, [F

    .line 245
    .line 246
    iget-object v2, v0, Le1/r;->g:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v2, Lkotlin/jvm/internal/d0;

    .line 249
    .line 250
    iget-object v3, v0, Le1/r;->h:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v3, Lkotlin/jvm/internal/c0;

    .line 253
    .line 254
    move-object/from16 v4, p1

    .line 255
    .line 256
    check-cast v4, Lg4/q;

    .line 257
    .line 258
    iget v5, v4, Lg4/q;->b:I

    .line 259
    .line 260
    iget-object v6, v4, Lg4/q;->a:Lg4/a;

    .line 261
    .line 262
    iget v7, v4, Lg4/q;->c:I

    .line 263
    .line 264
    iget-wide v8, v0, Le1/r;->e:J

    .line 265
    .line 266
    invoke-static {v8, v9}, Lg4/o0;->f(J)I

    .line 267
    .line 268
    .line 269
    move-result v0

    .line 270
    if-le v5, v0, :cond_0

    .line 271
    .line 272
    iget v0, v4, Lg4/q;->b:I

    .line 273
    .line 274
    goto :goto_3

    .line 275
    :cond_0
    invoke-static {v8, v9}, Lg4/o0;->f(J)I

    .line 276
    .line 277
    .line 278
    move-result v0

    .line 279
    :goto_3
    invoke-static {v8, v9}, Lg4/o0;->e(J)I

    .line 280
    .line 281
    .line 282
    move-result v5

    .line 283
    if-ge v7, v5, :cond_1

    .line 284
    .line 285
    goto :goto_4

    .line 286
    :cond_1
    invoke-static {v8, v9}, Lg4/o0;->e(J)I

    .line 287
    .line 288
    .line 289
    move-result v7

    .line 290
    :goto_4
    invoke-virtual {v4, v0}, Lg4/q;->d(I)I

    .line 291
    .line 292
    .line 293
    move-result v0

    .line 294
    invoke-virtual {v4, v7}, Lg4/q;->d(I)I

    .line 295
    .line 296
    .line 297
    move-result v4

    .line 298
    invoke-static {v0, v4}, Lg4/f0;->b(II)J

    .line 299
    .line 300
    .line 301
    move-result-wide v4

    .line 302
    iget v0, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 303
    .line 304
    iget-object v7, v6, Lg4/a;->d:Lh4/j;

    .line 305
    .line 306
    invoke-static {v4, v5}, Lg4/o0;->f(J)I

    .line 307
    .line 308
    .line 309
    move-result v8

    .line 310
    invoke-static {v4, v5}, Lg4/o0;->e(J)I

    .line 311
    .line 312
    .line 313
    move-result v9

    .line 314
    iget-object v10, v7, Lh4/j;->f:Landroid/text/Layout;

    .line 315
    .line 316
    invoke-virtual {v10}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 317
    .line 318
    .line 319
    move-result-object v11

    .line 320
    invoke-interface {v11}, Ljava/lang/CharSequence;->length()I

    .line 321
    .line 322
    .line 323
    move-result v11

    .line 324
    if-ltz v8, :cond_2

    .line 325
    .line 326
    goto :goto_5

    .line 327
    :cond_2
    const-string v12, "startOffset must be > 0"

    .line 328
    .line 329
    invoke-static {v12}, Lm4/a;->a(Ljava/lang/String;)V

    .line 330
    .line 331
    .line 332
    :goto_5
    if-ge v8, v11, :cond_3

    .line 333
    .line 334
    goto :goto_6

    .line 335
    :cond_3
    const-string v12, "startOffset must be less than text length"

    .line 336
    .line 337
    invoke-static {v12}, Lm4/a;->a(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    :goto_6
    if-le v9, v8, :cond_4

    .line 341
    .line 342
    goto :goto_7

    .line 343
    :cond_4
    const-string v12, "endOffset must be greater than startOffset"

    .line 344
    .line 345
    invoke-static {v12}, Lm4/a;->a(Ljava/lang/String;)V

    .line 346
    .line 347
    .line 348
    :goto_7
    if-gt v9, v11, :cond_5

    .line 349
    .line 350
    goto :goto_8

    .line 351
    :cond_5
    const-string v11, "endOffset must be smaller or equal to text length"

    .line 352
    .line 353
    invoke-static {v11}, Lm4/a;->a(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    :goto_8
    sub-int v11, v9, v8

    .line 357
    .line 358
    mul-int/lit8 v11, v11, 0x4

    .line 359
    .line 360
    array-length v12, v1

    .line 361
    sub-int/2addr v12, v0

    .line 362
    if-lt v12, v11, :cond_6

    .line 363
    .line 364
    goto :goto_9

    .line 365
    :cond_6
    const-string v11, "array.size - arrayStart must be greater or equal than (endOffset - startOffset) * 4"

    .line 366
    .line 367
    invoke-static {v11}, Lm4/a;->a(Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    :goto_9
    invoke-virtual {v10, v8}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 371
    .line 372
    .line 373
    move-result v11

    .line 374
    add-int/lit8 v12, v9, -0x1

    .line 375
    .line 376
    invoke-virtual {v10, v12}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 377
    .line 378
    .line 379
    move-result v12

    .line 380
    new-instance v13, Lc4/h;

    .line 381
    .line 382
    invoke-direct {v13, v7}, Lc4/h;-><init>(Lh4/j;)V

    .line 383
    .line 384
    .line 385
    if-gt v11, v12, :cond_c

    .line 386
    .line 387
    :goto_a
    invoke-virtual {v10, v11}, Landroid/text/Layout;->getLineStart(I)I

    .line 388
    .line 389
    .line 390
    move-result v14

    .line 391
    invoke-virtual {v7, v11}, Lh4/j;->f(I)I

    .line 392
    .line 393
    .line 394
    move-result v15

    .line 395
    invoke-static {v8, v14}, Ljava/lang/Math;->max(II)I

    .line 396
    .line 397
    .line 398
    move-result v14

    .line 399
    invoke-static {v9, v15}, Ljava/lang/Math;->min(II)I

    .line 400
    .line 401
    .line 402
    move-result v15

    .line 403
    invoke-virtual {v7, v11}, Lh4/j;->g(I)F

    .line 404
    .line 405
    .line 406
    move-result v16

    .line 407
    invoke-virtual {v7, v11}, Lh4/j;->e(I)F

    .line 408
    .line 409
    .line 410
    move-result v17

    .line 411
    move/from16 p0, v0

    .line 412
    .line 413
    invoke-virtual {v10, v11}, Landroid/text/Layout;->getParagraphDirection(I)I

    .line 414
    .line 415
    .line 416
    move-result v0

    .line 417
    move-object/from16 v18, v1

    .line 418
    .line 419
    const/4 v1, 0x1

    .line 420
    move-wide/from16 v19, v4

    .line 421
    .line 422
    const/4 v4, 0x0

    .line 423
    if-ne v0, v1, :cond_7

    .line 424
    .line 425
    move v0, v1

    .line 426
    goto :goto_b

    .line 427
    :cond_7
    move v0, v4

    .line 428
    :goto_b
    move/from16 v5, p0

    .line 429
    .line 430
    :goto_c
    if-ge v14, v15, :cond_b

    .line 431
    .line 432
    invoke-virtual {v10, v14}, Landroid/text/Layout;->isRtlCharAt(I)Z

    .line 433
    .line 434
    .line 435
    move-result v21

    .line 436
    if-eqz v0, :cond_8

    .line 437
    .line 438
    if-nez v21, :cond_8

    .line 439
    .line 440
    invoke-virtual {v13, v14, v4, v4, v1}, Lc4/h;->a(IZZZ)F

    .line 441
    .line 442
    .line 443
    move-result v21

    .line 444
    add-int/lit8 v4, v14, 0x1

    .line 445
    .line 446
    invoke-virtual {v13, v4, v1, v1, v1}, Lc4/h;->a(IZZZ)F

    .line 447
    .line 448
    .line 449
    move-result v4

    .line 450
    move/from16 p0, v0

    .line 451
    .line 452
    move v0, v4

    .line 453
    :goto_d
    const/4 v4, 0x0

    .line 454
    goto :goto_e

    .line 455
    :cond_8
    if-eqz v0, :cond_9

    .line 456
    .line 457
    if-eqz v21, :cond_9

    .line 458
    .line 459
    const/4 v4, 0x0

    .line 460
    invoke-virtual {v13, v14, v4, v4, v4}, Lc4/h;->a(IZZZ)F

    .line 461
    .line 462
    .line 463
    move-result v21

    .line 464
    move/from16 p0, v0

    .line 465
    .line 466
    add-int/lit8 v0, v14, 0x1

    .line 467
    .line 468
    invoke-virtual {v13, v0, v1, v1, v4}, Lc4/h;->a(IZZZ)F

    .line 469
    .line 470
    .line 471
    move-result v0

    .line 472
    move/from16 v25, v21

    .line 473
    .line 474
    move/from16 v21, v0

    .line 475
    .line 476
    move/from16 v0, v25

    .line 477
    .line 478
    goto :goto_e

    .line 479
    :cond_9
    move/from16 p0, v0

    .line 480
    .line 481
    const/4 v4, 0x0

    .line 482
    if-nez p0, :cond_a

    .line 483
    .line 484
    if-eqz v21, :cond_a

    .line 485
    .line 486
    invoke-virtual {v13, v14, v4, v4, v1}, Lc4/h;->a(IZZZ)F

    .line 487
    .line 488
    .line 489
    move-result v0

    .line 490
    add-int/lit8 v4, v14, 0x1

    .line 491
    .line 492
    invoke-virtual {v13, v4, v1, v1, v1}, Lc4/h;->a(IZZZ)F

    .line 493
    .line 494
    .line 495
    move-result v4

    .line 496
    move/from16 v21, v4

    .line 497
    .line 498
    goto :goto_d

    .line 499
    :cond_a
    invoke-virtual {v13, v14, v4, v4, v4}, Lc4/h;->a(IZZZ)F

    .line 500
    .line 501
    .line 502
    move-result v21

    .line 503
    add-int/lit8 v0, v14, 0x1

    .line 504
    .line 505
    invoke-virtual {v13, v0, v1, v1, v4}, Lc4/h;->a(IZZZ)F

    .line 506
    .line 507
    .line 508
    move-result v0

    .line 509
    :goto_e
    aput v21, v18, v5

    .line 510
    .line 511
    add-int/lit8 v21, v5, 0x1

    .line 512
    .line 513
    aput v16, v18, v21

    .line 514
    .line 515
    add-int/lit8 v21, v5, 0x2

    .line 516
    .line 517
    aput v0, v18, v21

    .line 518
    .line 519
    add-int/lit8 v0, v5, 0x3

    .line 520
    .line 521
    aput v17, v18, v0

    .line 522
    .line 523
    add-int/lit8 v5, v5, 0x4

    .line 524
    .line 525
    add-int/lit8 v14, v14, 0x1

    .line 526
    .line 527
    move/from16 v0, p0

    .line 528
    .line 529
    goto :goto_c

    .line 530
    :cond_b
    if-eq v11, v12, :cond_d

    .line 531
    .line 532
    add-int/lit8 v11, v11, 0x1

    .line 533
    .line 534
    move v0, v5

    .line 535
    move-object/from16 v1, v18

    .line 536
    .line 537
    move-wide/from16 v4, v19

    .line 538
    .line 539
    goto/16 :goto_a

    .line 540
    .line 541
    :cond_c
    move-object/from16 v18, v1

    .line 542
    .line 543
    move-wide/from16 v19, v4

    .line 544
    .line 545
    :cond_d
    iget v0, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 546
    .line 547
    invoke-static/range {v19 .. v20}, Lg4/o0;->d(J)I

    .line 548
    .line 549
    .line 550
    move-result v1

    .line 551
    mul-int/lit8 v1, v1, 0x4

    .line 552
    .line 553
    add-int/2addr v1, v0

    .line 554
    iget v0, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 555
    .line 556
    :goto_f
    if-ge v0, v1, :cond_e

    .line 557
    .line 558
    add-int/lit8 v4, v0, 0x1

    .line 559
    .line 560
    aget v5, v18, v4

    .line 561
    .line 562
    iget v7, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 563
    .line 564
    add-float/2addr v5, v7

    .line 565
    aput v5, v18, v4

    .line 566
    .line 567
    add-int/lit8 v4, v0, 0x3

    .line 568
    .line 569
    aget v5, v18, v4

    .line 570
    .line 571
    add-float/2addr v5, v7

    .line 572
    aput v5, v18, v4

    .line 573
    .line 574
    add-int/lit8 v0, v0, 0x4

    .line 575
    .line 576
    goto :goto_f

    .line 577
    :cond_e
    iput v1, v2, Lkotlin/jvm/internal/d0;->d:I

    .line 578
    .line 579
    iget v0, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 580
    .line 581
    invoke-virtual {v6}, Lg4/a;->b()F

    .line 582
    .line 583
    .line 584
    move-result v1

    .line 585
    add-float/2addr v1, v0

    .line 586
    iput v1, v3, Lkotlin/jvm/internal/c0;->d:F

    .line 587
    .line 588
    goto/16 :goto_0

    .line 589
    .line 590
    :pswitch_1
    iget-object v1, v0, Le1/r;->f:Ljava/lang/Object;

    .line 591
    .line 592
    check-cast v1, Ld3/c;

    .line 593
    .line 594
    iget-object v2, v0, Le1/r;->g:Ljava/lang/Object;

    .line 595
    .line 596
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 597
    .line 598
    iget-wide v5, v0, Le1/r;->e:J

    .line 599
    .line 600
    iget-object v0, v0, Le1/r;->h:Ljava/lang/Object;

    .line 601
    .line 602
    move-object v10, v0

    .line 603
    check-cast v10, Le3/m;

    .line 604
    .line 605
    move-object/from16 v3, p1

    .line 606
    .line 607
    check-cast v3, Lv3/j0;

    .line 608
    .line 609
    invoke-virtual {v3}, Lv3/j0;->b()V

    .line 610
    .line 611
    .line 612
    iget v13, v1, Ld3/c;->a:F

    .line 613
    .line 614
    iget v1, v1, Ld3/c;->b:F

    .line 615
    .line 616
    iget-object v14, v3, Lv3/j0;->d:Lg3/b;

    .line 617
    .line 618
    iget-object v0, v14, Lg3/b;->e:Lgw0/c;

    .line 619
    .line 620
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast v0, Lbu/c;

    .line 623
    .line 624
    invoke-virtual {v0, v13, v1}, Lbu/c;->B(FF)V

    .line 625
    .line 626
    .line 627
    :try_start_3
    iget-object v0, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 628
    .line 629
    move-object v4, v0

    .line 630
    check-cast v4, Le3/f;

    .line 631
    .line 632
    const/4 v11, 0x0

    .line 633
    const/16 v12, 0x37a

    .line 634
    .line 635
    const-wide/16 v7, 0x0

    .line 636
    .line 637
    const/4 v9, 0x0

    .line 638
    invoke-static/range {v3 .. v12}, Lg3/d;->g0(Lg3/d;Le3/f;JJFLe3/m;II)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 639
    .line 640
    .line 641
    iget-object v0, v14, Lg3/b;->e:Lgw0/c;

    .line 642
    .line 643
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 644
    .line 645
    check-cast v0, Lbu/c;

    .line 646
    .line 647
    neg-float v2, v13

    .line 648
    neg-float v1, v1

    .line 649
    invoke-virtual {v0, v2, v1}, Lbu/c;->B(FF)V

    .line 650
    .line 651
    .line 652
    goto/16 :goto_0

    .line 653
    .line 654
    :catchall_3
    move-exception v0

    .line 655
    iget-object v2, v14, Lg3/b;->e:Lgw0/c;

    .line 656
    .line 657
    iget-object v2, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 658
    .line 659
    check-cast v2, Lbu/c;

    .line 660
    .line 661
    neg-float v3, v13

    .line 662
    neg-float v1, v1

    .line 663
    invoke-virtual {v2, v3, v1}, Lbu/c;->B(FF)V

    .line 664
    .line 665
    .line 666
    throw v0

    .line 667
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
