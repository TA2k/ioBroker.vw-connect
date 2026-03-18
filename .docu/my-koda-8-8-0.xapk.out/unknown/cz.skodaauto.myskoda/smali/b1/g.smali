.class public final Lb1/g;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/g;->f:I

    iput-object p1, p0, Lb1/g;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Lw3/a;II)V
    .locals 0

    .line 2
    iput p3, p0, Lb1/g;->f:I

    iput-object p1, p0, Lb1/g;->g:Ljava/lang/Object;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lb1/g;->f:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    move-object/from16 v2, p2

    .line 17
    .line 18
    check-cast v2, Ld4/q;

    .line 19
    .line 20
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lz2/e;

    .line 23
    .line 24
    invoke-virtual {v0, v1, v2}, Lz2/e;->i(ILd4/q;)V

    .line 25
    .line 26
    .line 27
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object v0

    .line 30
    :pswitch_0
    move-object/from16 v1, p1

    .line 31
    .line 32
    check-cast v1, Ll2/o;

    .line 33
    .line 34
    move-object/from16 v2, p2

    .line 35
    .line 36
    check-cast v2, Ljava/lang/Number;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 39
    .line 40
    .line 41
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Lx4/t;

    .line 44
    .line 45
    const/4 v2, 0x1

    .line 46
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    invoke-virtual {v0, v1, v2}, Lx4/t;->a(Ll2/o;I)V

    .line 51
    .line 52
    .line 53
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_1
    move-object/from16 v1, p1

    .line 57
    .line 58
    check-cast v1, Ll2/o;

    .line 59
    .line 60
    move-object/from16 v2, p2

    .line 61
    .line 62
    check-cast v2, Ljava/lang/Number;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 65
    .line 66
    .line 67
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lx4/o;

    .line 70
    .line 71
    const/4 v2, 0x1

    .line 72
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    invoke-virtual {v0, v1, v2}, Lx4/o;->a(Ll2/o;I)V

    .line 77
    .line 78
    .line 79
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object v0

    .line 82
    :pswitch_2
    move-object/from16 v1, p1

    .line 83
    .line 84
    check-cast v1, Ll2/o;

    .line 85
    .line 86
    move-object/from16 v2, p2

    .line 87
    .line 88
    check-cast v2, Ljava/lang/Number;

    .line 89
    .line 90
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v2

    .line 94
    and-int/lit8 v3, v2, 0x3

    .line 95
    .line 96
    const/4 v4, 0x2

    .line 97
    const/4 v5, 0x1

    .line 98
    const/4 v6, 0x0

    .line 99
    if-eq v3, v4, :cond_0

    .line 100
    .line 101
    move v3, v5

    .line 102
    goto :goto_0

    .line 103
    :cond_0
    move v3, v6

    .line 104
    :goto_0
    and-int/2addr v2, v5

    .line 105
    check-cast v1, Ll2/t;

    .line 106
    .line 107
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-eqz v2, :cond_2

    .line 112
    .line 113
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v2

    .line 117
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 118
    .line 119
    if-ne v2, v3, :cond_1

    .line 120
    .line 121
    sget-object v2, Lx4/c;->g:Lx4/c;

    .line 122
    .line 123
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    :cond_1
    check-cast v2, Lay0/k;

    .line 127
    .line 128
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 129
    .line 130
    invoke-static {v3, v6, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Ll2/b1;

    .line 137
    .line 138
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    check-cast v0, Lay0/n;

    .line 143
    .line 144
    invoke-static {v2, v0, v1, v6}, Llp/ge;->b(Lx2/s;Lay0/n;Ll2/o;I)V

    .line 145
    .line 146
    .line 147
    goto :goto_1

    .line 148
    :cond_2
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 149
    .line 150
    .line 151
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 152
    .line 153
    return-object v0

    .line 154
    :pswitch_3
    move-object/from16 v1, p1

    .line 155
    .line 156
    check-cast v1, Lp3/t;

    .line 157
    .line 158
    move-object/from16 v2, p2

    .line 159
    .line 160
    check-cast v2, Ld3/b;

    .line 161
    .line 162
    iget-wide v2, v2, Ld3/b;->a:J

    .line 163
    .line 164
    const-string v4, "change"

    .line 165
    .line 166
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v1}, Lp3/t;->a()V

    .line 170
    .line 171
    .line 172
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v0, Lx21/k;

    .line 175
    .line 176
    iget-object v4, v0, Lx21/k;->a:Lx21/y;

    .line 177
    .line 178
    iget-object v0, v4, Lx21/y;->j:Lez0/c;

    .line 179
    .line 180
    iget-object v1, v4, Lx21/y;->f:Lx21/g0;

    .line 181
    .line 182
    iget-object v5, v4, Lx21/y;->a:Lt1/j0;

    .line 183
    .line 184
    iget-object v6, v4, Lx21/y;->m:Ll2/j1;

    .line 185
    .line 186
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    check-cast v7, Ld3/b;

    .line 191
    .line 192
    iget-wide v7, v7, Ld3/b;->a:J

    .line 193
    .line 194
    invoke-static {v7, v8, v2, v3}, Ld3/b;->h(JJ)J

    .line 195
    .line 196
    .line 197
    move-result-wide v2

    .line 198
    new-instance v7, Ld3/b;

    .line 199
    .line 200
    invoke-direct {v7, v2, v3}, Ld3/b;-><init>(J)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v6, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v4}, Lx21/y;->d()Lx21/x;

    .line 207
    .line 208
    .line 209
    move-result-object v2

    .line 210
    if-nez v2, :cond_3

    .line 211
    .line 212
    goto/16 :goto_8

    .line 213
    .line 214
    :cond_3
    invoke-virtual {v4}, Lx21/y;->e()J

    .line 215
    .line 216
    .line 217
    move-result-wide v6

    .line 218
    invoke-virtual {v4, v6, v7}, Lx21/y;->i(J)J

    .line 219
    .line 220
    .line 221
    move-result-wide v6

    .line 222
    invoke-virtual {v4, v6, v7}, Lx21/y;->j(J)J

    .line 223
    .line 224
    .line 225
    invoke-virtual {v2}, Lx21/x;->b()J

    .line 226
    .line 227
    .line 228
    move-result-wide v8

    .line 229
    const/16 v3, 0x20

    .line 230
    .line 231
    shr-long v10, v8, v3

    .line 232
    .line 233
    long-to-int v10, v10

    .line 234
    int-to-float v10, v10

    .line 235
    const-wide v11, 0xffffffffL

    .line 236
    .line 237
    .line 238
    .line 239
    .line 240
    and-long/2addr v8, v11

    .line 241
    long-to-int v8, v8

    .line 242
    int-to-float v8, v8

    .line 243
    invoke-static {v10, v8}, Ljp/bf;->a(FF)J

    .line 244
    .line 245
    .line 246
    move-result-wide v8

    .line 247
    invoke-static {v8, v9, v6, v7}, Ld3/b;->h(JJ)J

    .line 248
    .line 249
    .line 250
    move-result-wide v6

    .line 251
    invoke-virtual {v2}, Lx21/x;->c()J

    .line 252
    .line 253
    .line 254
    move-result-wide v8

    .line 255
    invoke-static {v8, v9}, Lkp/f9;->c(J)J

    .line 256
    .line 257
    .line 258
    move-result-wide v8

    .line 259
    invoke-static {v6, v7}, Ld3/b;->e(J)F

    .line 260
    .line 261
    .line 262
    move-result v10

    .line 263
    invoke-static {v8, v9}, Ld3/e;->d(J)F

    .line 264
    .line 265
    .line 266
    move-result v13

    .line 267
    add-float/2addr v13, v10

    .line 268
    invoke-static {v6, v7}, Ld3/b;->f(J)F

    .line 269
    .line 270
    .line 271
    move-result v10

    .line 272
    invoke-static {v8, v9}, Ld3/e;->b(J)F

    .line 273
    .line 274
    .line 275
    move-result v8

    .line 276
    add-float/2addr v8, v10

    .line 277
    invoke-static {v13, v8}, Ljp/bf;->a(FF)J

    .line 278
    .line 279
    .line 280
    move-result-wide v8

    .line 281
    invoke-virtual {v5}, Lt1/j0;->m()Lpv/g;

    .line 282
    .line 283
    .line 284
    move-result-object v10

    .line 285
    iget-object v13, v4, Lx21/y;->e:Lx21/a;

    .line 286
    .line 287
    const-string v14, "padding"

    .line 288
    .line 289
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v10}, Lpv/g;->g()Lg1/w1;

    .line 293
    .line 294
    .line 295
    move-result-object v14

    .line 296
    iget-object v15, v10, Lpv/g;->e:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast v15, Lm1/l;

    .line 299
    .line 300
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 301
    .line 302
    .line 303
    const-string v15, "orientation"

    .line 304
    .line 305
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 309
    .line 310
    .line 311
    move-result v14

    .line 312
    const/4 v15, 0x1

    .line 313
    if-eqz v14, :cond_5

    .line 314
    .line 315
    if-ne v14, v15, :cond_4

    .line 316
    .line 317
    new-instance v14, Lx21/b;

    .line 318
    .line 319
    move/from16 p0, v3

    .line 320
    .line 321
    iget v3, v13, Lx21/a;->a:F

    .line 322
    .line 323
    iget v13, v13, Lx21/a;->b:F

    .line 324
    .line 325
    invoke-direct {v14, v3, v13}, Lx21/b;-><init>(FF)V

    .line 326
    .line 327
    .line 328
    goto :goto_2

    .line 329
    :cond_4
    new-instance v0, La8/r0;

    .line 330
    .line 331
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 332
    .line 333
    .line 334
    throw v0

    .line 335
    :cond_5
    move/from16 p0, v3

    .line 336
    .line 337
    new-instance v14, Lx21/b;

    .line 338
    .line 339
    iget v3, v13, Lx21/a;->c:F

    .line 340
    .line 341
    iget v13, v13, Lx21/a;->d:F

    .line 342
    .line 343
    invoke-direct {v14, v3, v13}, Lx21/b;-><init>(FF)V

    .line 344
    .line 345
    .line 346
    :goto_2
    invoke-virtual {v10, v14}, Lpv/g;->h(Lx21/b;)Lx21/z;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    iget v10, v3, Lx21/z;->a:F

    .line 351
    .line 352
    iget v3, v3, Lx21/z;->b:F

    .line 353
    .line 354
    invoke-virtual {v5}, Lt1/j0;->m()Lpv/g;

    .line 355
    .line 356
    .line 357
    move-result-object v13

    .line 358
    iget-object v13, v13, Lpv/g;->e:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast v13, Lm1/l;

    .line 361
    .line 362
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 363
    .line 364
    .line 365
    iget-object v13, v4, Lx21/y;->h:Lt4/m;

    .line 366
    .line 367
    sget-object v14, Lt4/m;->e:Lt4/m;

    .line 368
    .line 369
    const/16 v16, 0x0

    .line 370
    .line 371
    if-ne v13, v14, :cond_6

    .line 372
    .line 373
    invoke-virtual {v4}, Lx21/y;->f()Lg1/w1;

    .line 374
    .line 375
    .line 376
    move-result-object v13

    .line 377
    sget-object v14, Lg1/w1;->e:Lg1/w1;

    .line 378
    .line 379
    if-ne v13, v14, :cond_6

    .line 380
    .line 381
    move v13, v15

    .line 382
    goto :goto_3

    .line 383
    :cond_6
    move/from16 v13, v16

    .line 384
    .line 385
    :goto_3
    if-ne v13, v15, :cond_7

    .line 386
    .line 387
    iget-wide v13, v4, Lx21/y;->q:J

    .line 388
    .line 389
    invoke-static {v8, v9, v13, v14}, Ld3/b;->g(JJ)J

    .line 390
    .line 391
    .line 392
    move-result-wide v13

    .line 393
    :goto_4
    move-wide/from16 p1, v11

    .line 394
    .line 395
    goto :goto_5

    .line 396
    :cond_7
    if-nez v13, :cond_f

    .line 397
    .line 398
    iget-wide v13, v4, Lx21/y;->q:J

    .line 399
    .line 400
    invoke-static {v6, v7, v13, v14}, Ld3/b;->h(JJ)J

    .line 401
    .line 402
    .line 403
    move-result-wide v13

    .line 404
    goto :goto_4

    .line 405
    :goto_5
    invoke-virtual {v4}, Lx21/y;->f()Lg1/w1;

    .line 406
    .line 407
    .line 408
    move-result-object v11

    .line 409
    invoke-virtual {v5}, Lt1/j0;->m()Lpv/g;

    .line 410
    .line 411
    .line 412
    move-result-object v12

    .line 413
    iget-object v12, v12, Lpv/g;->e:Ljava/lang/Object;

    .line 414
    .line 415
    check-cast v12, Lm1/l;

    .line 416
    .line 417
    iget v12, v12, Lm1/l;->l:I

    .line 418
    .line 419
    neg-int v12, v12

    .line 420
    invoke-static {v11, v12}, Llp/ee;->b(Lg1/w1;I)J

    .line 421
    .line 422
    .line 423
    move-result-wide v11

    .line 424
    move/from16 v17, v10

    .line 425
    .line 426
    move-wide/from16 v18, v11

    .line 427
    .line 428
    shr-long v10, v18, p0

    .line 429
    .line 430
    long-to-int v10, v10

    .line 431
    int-to-float v10, v10

    .line 432
    and-long v11, v18, p1

    .line 433
    .line 434
    long-to-int v11, v11

    .line 435
    int-to-float v11, v11

    .line 436
    invoke-static {v10, v11}, Ljp/bf;->a(FF)J

    .line 437
    .line 438
    .line 439
    move-result-wide v10

    .line 440
    invoke-static {v13, v14, v10, v11}, Ld3/b;->h(JJ)J

    .line 441
    .line 442
    .line 443
    move-result-wide v10

    .line 444
    invoke-virtual {v4}, Lx21/y;->f()Lg1/w1;

    .line 445
    .line 446
    .line 447
    move-result-object v12

    .line 448
    invoke-static {v10, v11, v12}, Llp/ee;->c(JLg1/w1;)F

    .line 449
    .line 450
    .line 451
    move-result v12

    .line 452
    sub-float v12, v12, v17

    .line 453
    .line 454
    const/4 v13, 0x0

    .line 455
    cmpg-float v14, v12, v13

    .line 456
    .line 457
    if-gez v14, :cond_8

    .line 458
    .line 459
    move v12, v13

    .line 460
    :cond_8
    invoke-virtual {v4}, Lx21/y;->f()Lg1/w1;

    .line 461
    .line 462
    .line 463
    move-result-object v14

    .line 464
    invoke-static {v10, v11, v14}, Llp/ee;->c(JLg1/w1;)F

    .line 465
    .line 466
    .line 467
    move-result v10

    .line 468
    sub-float/2addr v3, v10

    .line 469
    cmpg-float v10, v3, v13

    .line 470
    .line 471
    if-gez v10, :cond_9

    .line 472
    .line 473
    move v3, v13

    .line 474
    :cond_9
    iget v10, v4, Lx21/y;->d:F

    .line 475
    .line 476
    cmpg-float v11, v12, v10

    .line 477
    .line 478
    const/4 v13, 0x2

    .line 479
    const/4 v14, 0x0

    .line 480
    if-gez v11, :cond_a

    .line 481
    .line 482
    sget-object v3, Lx21/b0;->d:Lx21/b0;

    .line 483
    .line 484
    int-to-float v11, v15

    .line 485
    add-float/2addr v12, v10

    .line 486
    int-to-float v13, v13

    .line 487
    mul-float/2addr v10, v13

    .line 488
    div-float/2addr v12, v10

    .line 489
    const/high16 v10, 0x3f800000    # 1.0f

    .line 490
    .line 491
    const/4 v13, 0x0

    .line 492
    invoke-static {v12, v13, v10}, Lkp/r9;->d(FFF)F

    .line 493
    .line 494
    .line 495
    move-result v10

    .line 496
    sub-float/2addr v11, v10

    .line 497
    const/16 v10, 0xa

    .line 498
    .line 499
    int-to-float v10, v10

    .line 500
    mul-float/2addr v11, v10

    .line 501
    new-instance v10, Lx21/n;

    .line 502
    .line 503
    const/4 v12, 0x2

    .line 504
    invoke-direct {v10, v4, v12}, Lx21/n;-><init>(Lx21/y;I)V

    .line 505
    .line 506
    .line 507
    new-instance v12, Lx21/r;

    .line 508
    .line 509
    const/4 v13, 0x0

    .line 510
    invoke-direct {v12, v4, v14, v13}, Lx21/r;-><init>(Lx21/y;Lkotlin/coroutines/Continuation;I)V

    .line 511
    .line 512
    .line 513
    invoke-virtual {v1, v3, v11, v10, v12}, Lx21/g0;->b(Lx21/b0;FLay0/a;Lay0/k;)Z

    .line 514
    .line 515
    .line 516
    move-result v16

    .line 517
    goto :goto_6

    .line 518
    :cond_a
    cmpg-float v11, v3, v10

    .line 519
    .line 520
    if-gez v11, :cond_b

    .line 521
    .line 522
    sget-object v11, Lx21/b0;->e:Lx21/b0;

    .line 523
    .line 524
    int-to-float v12, v15

    .line 525
    add-float/2addr v3, v10

    .line 526
    int-to-float v13, v13

    .line 527
    mul-float/2addr v10, v13

    .line 528
    div-float/2addr v3, v10

    .line 529
    const/high16 v10, 0x3f800000    # 1.0f

    .line 530
    .line 531
    const/4 v13, 0x0

    .line 532
    invoke-static {v3, v13, v10}, Lkp/r9;->d(FFF)F

    .line 533
    .line 534
    .line 535
    move-result v3

    .line 536
    sub-float/2addr v12, v3

    .line 537
    const/16 v10, 0xa

    .line 538
    .line 539
    int-to-float v3, v10

    .line 540
    mul-float/2addr v12, v3

    .line 541
    new-instance v3, Lx21/n;

    .line 542
    .line 543
    const/4 v10, 0x3

    .line 544
    invoke-direct {v3, v4, v10}, Lx21/n;-><init>(Lx21/y;I)V

    .line 545
    .line 546
    .line 547
    new-instance v10, Lx21/r;

    .line 548
    .line 549
    const/4 v13, 0x1

    .line 550
    invoke-direct {v10, v4, v14, v13}, Lx21/r;-><init>(Lx21/y;Lkotlin/coroutines/Continuation;I)V

    .line 551
    .line 552
    .line 553
    invoke-virtual {v1, v11, v12, v3, v10}, Lx21/g0;->b(Lx21/b0;FLay0/a;Lay0/k;)Z

    .line 554
    .line 555
    .line 556
    move-result v16

    .line 557
    goto :goto_6

    .line 558
    :cond_b
    iget-object v3, v1, Lx21/g0;->b:Lvy0/b0;

    .line 559
    .line 560
    new-instance v10, Lx21/e0;

    .line 561
    .line 562
    const/4 v11, 0x1

    .line 563
    invoke-direct {v10, v1, v14, v11}, Lx21/e0;-><init>(Lx21/g0;Lkotlin/coroutines/Continuation;I)V

    .line 564
    .line 565
    .line 566
    const/4 v11, 0x3

    .line 567
    invoke-static {v3, v14, v14, v10, v11}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 568
    .line 569
    .line 570
    :goto_6
    invoke-virtual {v0}, Lez0/c;->tryLock()Z

    .line 571
    .line 572
    .line 573
    move-result v3

    .line 574
    if-nez v3, :cond_c

    .line 575
    .line 576
    goto :goto_8

    .line 577
    :cond_c
    iget-object v1, v1, Lx21/g0;->d:Lvy0/x1;

    .line 578
    .line 579
    if-eqz v1, :cond_e

    .line 580
    .line 581
    invoke-virtual {v1}, Lvy0/p1;->a()Z

    .line 582
    .line 583
    .line 584
    move-result v1

    .line 585
    if-ne v1, v15, :cond_e

    .line 586
    .line 587
    :cond_d
    move-object v8, v14

    .line 588
    goto :goto_7

    .line 589
    :cond_e
    if-nez v16, :cond_d

    .line 590
    .line 591
    invoke-static {v6, v7, v8, v9}, Ljp/cf;->a(JJ)Ld3/c;

    .line 592
    .line 593
    .line 594
    move-result-object v1

    .line 595
    invoke-virtual {v5}, Lt1/j0;->m()Lpv/g;

    .line 596
    .line 597
    .line 598
    move-result-object v3

    .line 599
    invoke-virtual {v3}, Lpv/g;->i()Ljava/util/ArrayList;

    .line 600
    .line 601
    .line 602
    move-result-object v6

    .line 603
    new-instance v8, Lw3/a0;

    .line 604
    .line 605
    const/4 v3, 0x7

    .line 606
    invoke-direct {v8, v2, v3}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 607
    .line 608
    .line 609
    const/4 v9, 0x4

    .line 610
    const/4 v7, 0x0

    .line 611
    move-object v5, v1

    .line 612
    invoke-static/range {v4 .. v9}, Lx21/y;->c(Lx21/y;Ld3/c;Ljava/util/ArrayList;Lx21/b0;Lw3/a0;I)Lx21/x;

    .line 613
    .line 614
    .line 615
    move-result-object v7

    .line 616
    if-eqz v7, :cond_d

    .line 617
    .line 618
    iget-object v1, v4, Lx21/y;->b:Lvy0/b0;

    .line 619
    .line 620
    move-object v5, v4

    .line 621
    new-instance v4, Lx21/p;

    .line 622
    .line 623
    const/4 v9, 0x1

    .line 624
    move-object v6, v2

    .line 625
    move-object v8, v14

    .line 626
    invoke-direct/range {v4 .. v9}, Lx21/p;-><init>(Lx21/y;Lx21/x;Lx21/x;Lkotlin/coroutines/Continuation;I)V

    .line 627
    .line 628
    .line 629
    const/4 v11, 0x3

    .line 630
    invoke-static {v1, v8, v8, v4, v11}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 631
    .line 632
    .line 633
    :goto_7
    invoke-virtual {v0, v8}, Lez0/c;->d(Ljava/lang/Object;)V

    .line 634
    .line 635
    .line 636
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 637
    .line 638
    return-object v0

    .line 639
    :cond_f
    new-instance v0, La8/r0;

    .line 640
    .line 641
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 642
    .line 643
    .line 644
    throw v0

    .line 645
    :pswitch_4
    move-object/from16 v1, p1

    .line 646
    .line 647
    check-cast v1, Lx2/s;

    .line 648
    .line 649
    move-object/from16 v2, p2

    .line 650
    .line 651
    check-cast v2, Lx2/q;

    .line 652
    .line 653
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 654
    .line 655
    check-cast v0, Ll2/o;

    .line 656
    .line 657
    instance-of v3, v2, Lx2/m;

    .line 658
    .line 659
    if-eqz v3, :cond_10

    .line 660
    .line 661
    check-cast v2, Lx2/m;

    .line 662
    .line 663
    iget-object v2, v2, Lx2/m;->c:Lay0/o;

    .line 664
    .line 665
    const/4 v3, 0x3

    .line 666
    invoke-static {v3, v2}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 667
    .line 668
    .line 669
    const/4 v3, 0x0

    .line 670
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 671
    .line 672
    .line 673
    move-result-object v3

    .line 674
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 675
    .line 676
    invoke-interface {v2, v4, v0, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 677
    .line 678
    .line 679
    move-result-object v2

    .line 680
    check-cast v2, Lx2/s;

    .line 681
    .line 682
    invoke-static {v0, v2}, Lx2/a;->b(Ll2/o;Lx2/s;)Lx2/s;

    .line 683
    .line 684
    .line 685
    move-result-object v2

    .line 686
    :cond_10
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 687
    .line 688
    .line 689
    move-result-object v0

    .line 690
    return-object v0

    .line 691
    :pswitch_5
    move-object/from16 v1, p1

    .line 692
    .line 693
    check-cast v1, Ll2/o;

    .line 694
    .line 695
    move-object/from16 v2, p2

    .line 696
    .line 697
    check-cast v2, Ljava/lang/Number;

    .line 698
    .line 699
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 700
    .line 701
    .line 702
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 703
    .line 704
    check-cast v0, Lw3/g1;

    .line 705
    .line 706
    const/4 v2, 0x1

    .line 707
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 708
    .line 709
    .line 710
    move-result v2

    .line 711
    invoke-virtual {v0, v1, v2}, Lw3/g1;->a(Ll2/o;I)V

    .line 712
    .line 713
    .line 714
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 715
    .line 716
    return-object v0

    .line 717
    :pswitch_6
    move-object/from16 v1, p1

    .line 718
    .line 719
    check-cast v1, Ll2/o;

    .line 720
    .line 721
    move-object/from16 v2, p2

    .line 722
    .line 723
    check-cast v2, Ljava/lang/Number;

    .line 724
    .line 725
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 726
    .line 727
    .line 728
    move-result v2

    .line 729
    and-int/lit8 v3, v2, 0x3

    .line 730
    .line 731
    const/4 v4, 0x2

    .line 732
    const/4 v5, 0x0

    .line 733
    const/4 v6, 0x1

    .line 734
    if-eq v3, v4, :cond_11

    .line 735
    .line 736
    move v3, v6

    .line 737
    goto :goto_9

    .line 738
    :cond_11
    move v3, v5

    .line 739
    :goto_9
    and-int/2addr v2, v6

    .line 740
    check-cast v1, Ll2/t;

    .line 741
    .line 742
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 743
    .line 744
    .line 745
    move-result v2

    .line 746
    if-eqz v2, :cond_12

    .line 747
    .line 748
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 749
    .line 750
    check-cast v0, Lw3/a;

    .line 751
    .line 752
    invoke-virtual {v0, v1, v5}, Lw3/a;->a(Ll2/o;I)V

    .line 753
    .line 754
    .line 755
    goto :goto_a

    .line 756
    :cond_12
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 757
    .line 758
    .line 759
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 760
    .line 761
    return-object v0

    .line 762
    :pswitch_7
    move-object/from16 v1, p1

    .line 763
    .line 764
    check-cast v1, Ll2/o;

    .line 765
    .line 766
    move-object/from16 v2, p2

    .line 767
    .line 768
    check-cast v2, Ljava/lang/Number;

    .line 769
    .line 770
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 771
    .line 772
    .line 773
    move-result v2

    .line 774
    and-int/lit8 v3, v2, 0x3

    .line 775
    .line 776
    const/4 v4, 0x2

    .line 777
    const/4 v5, 0x0

    .line 778
    const/4 v6, 0x1

    .line 779
    if-eq v3, v4, :cond_13

    .line 780
    .line 781
    move v3, v6

    .line 782
    goto :goto_b

    .line 783
    :cond_13
    move v3, v5

    .line 784
    :goto_b
    and-int/2addr v2, v6

    .line 785
    check-cast v1, Ll2/t;

    .line 786
    .line 787
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 788
    .line 789
    .line 790
    move-result v2

    .line 791
    if-eqz v2, :cond_17

    .line 792
    .line 793
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 794
    .line 795
    check-cast v0, Ljava/util/List;

    .line 796
    .line 797
    move-object v2, v0

    .line 798
    check-cast v2, Ljava/util/Collection;

    .line 799
    .line 800
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 801
    .line 802
    .line 803
    move-result v2

    .line 804
    move v3, v5

    .line 805
    :goto_c
    if-ge v3, v2, :cond_18

    .line 806
    .line 807
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    move-result-object v4

    .line 811
    check-cast v4, Lay0/n;

    .line 812
    .line 813
    iget-wide v7, v1, Ll2/t;->T:J

    .line 814
    .line 815
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 816
    .line 817
    .line 818
    move-result v7

    .line 819
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 820
    .line 821
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 822
    .line 823
    .line 824
    sget-object v8, Lv3/j;->c:Lv3/i;

    .line 825
    .line 826
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 827
    .line 828
    .line 829
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 830
    .line 831
    if-eqz v9, :cond_14

    .line 832
    .line 833
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 834
    .line 835
    .line 836
    goto :goto_d

    .line 837
    :cond_14
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 838
    .line 839
    .line 840
    :goto_d
    sget-object v8, Lv3/j;->j:Lv3/h;

    .line 841
    .line 842
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 843
    .line 844
    if-nez v9, :cond_15

    .line 845
    .line 846
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 847
    .line 848
    .line 849
    move-result-object v9

    .line 850
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 851
    .line 852
    .line 853
    move-result-object v10

    .line 854
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 855
    .line 856
    .line 857
    move-result v9

    .line 858
    if-nez v9, :cond_16

    .line 859
    .line 860
    :cond_15
    invoke-static {v7, v1, v7, v8}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 861
    .line 862
    .line 863
    :cond_16
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 864
    .line 865
    .line 866
    move-result-object v7

    .line 867
    invoke-interface {v4, v1, v7}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 868
    .line 869
    .line 870
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 871
    .line 872
    .line 873
    add-int/lit8 v3, v3, 0x1

    .line 874
    .line 875
    goto :goto_c

    .line 876
    :cond_17
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 877
    .line 878
    .line 879
    :cond_18
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 880
    .line 881
    return-object v0

    .line 882
    :pswitch_8
    move-object/from16 v1, p1

    .line 883
    .line 884
    check-cast v1, Ll2/o;

    .line 885
    .line 886
    move-object/from16 v2, p2

    .line 887
    .line 888
    check-cast v2, Ljava/lang/Number;

    .line 889
    .line 890
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 891
    .line 892
    .line 893
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 894
    .line 895
    check-cast v0, Lkn/n0;

    .line 896
    .line 897
    const/4 v2, 0x1

    .line 898
    invoke-static {v2}, Ll2/b;->x(I)I

    .line 899
    .line 900
    .line 901
    move-result v2

    .line 902
    invoke-virtual {v0, v1, v2}, Lkn/n0;->a(Ll2/o;I)V

    .line 903
    .line 904
    .line 905
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 906
    .line 907
    return-object v0

    .line 908
    :pswitch_9
    move-object/from16 v1, p1

    .line 909
    .line 910
    check-cast v1, Lb1/i0;

    .line 911
    .line 912
    move-object/from16 v2, p2

    .line 913
    .line 914
    check-cast v2, Lb1/i0;

    .line 915
    .line 916
    sget-object v3, Lb1/i0;->f:Lb1/i0;

    .line 917
    .line 918
    if-ne v1, v3, :cond_19

    .line 919
    .line 920
    if-ne v2, v3, :cond_19

    .line 921
    .line 922
    iget-object v0, v0, Lb1/g;->g:Ljava/lang/Object;

    .line 923
    .line 924
    check-cast v0, Lb1/u0;

    .line 925
    .line 926
    iget-object v0, v0, Lb1/u0;->a:Lb1/i1;

    .line 927
    .line 928
    iget-boolean v0, v0, Lb1/i1;->d:Z

    .line 929
    .line 930
    if-nez v0, :cond_19

    .line 931
    .line 932
    const/4 v0, 0x1

    .line 933
    goto :goto_e

    .line 934
    :cond_19
    const/4 v0, 0x0

    .line 935
    :goto_e
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    return-object v0

    .line 940
    nop

    .line 941
    :pswitch_data_0
    .packed-switch 0x0
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
