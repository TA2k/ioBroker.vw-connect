.class public abstract Lc71/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, La71/a;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    invoke-direct {v0, v1}, La71/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Lt2/b;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const v3, -0x5a003e9c

    .line 12
    .line 13
    .line 14
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lc71/a;->a:Lt2/b;

    .line 18
    .line 19
    new-instance v0, La71/a;

    .line 20
    .line 21
    const/16 v1, 0xa

    .line 22
    .line 23
    invoke-direct {v0, v1}, La71/a;-><init>(I)V

    .line 24
    .line 25
    .line 26
    new-instance v1, Lt2/b;

    .line 27
    .line 28
    const v3, 0x75e52605

    .line 29
    .line 30
    .line 31
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method public static final a(Lx2/s;Lay0/o;Lt2/b;Ll2/o;II)V
    .locals 20

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move/from16 v4, p4

    .line 6
    .line 7
    const-string v0, "modifier"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v0, p3

    .line 13
    .line 14
    check-cast v0, Ll2/t;

    .line 15
    .line 16
    const v2, -0x3287740c

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v2, v4, 0x6

    .line 23
    .line 24
    if-nez v2, :cond_1

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_0

    .line 31
    .line 32
    const/4 v2, 0x4

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v2, 0x2

    .line 35
    :goto_0
    or-int/2addr v2, v4

    .line 36
    goto :goto_1

    .line 37
    :cond_1
    move v2, v4

    .line 38
    :goto_1
    and-int/lit8 v5, p5, 0x2

    .line 39
    .line 40
    if-eqz v5, :cond_3

    .line 41
    .line 42
    or-int/lit8 v2, v2, 0x30

    .line 43
    .line 44
    :cond_2
    move-object/from16 v7, p1

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_3
    and-int/lit8 v7, v4, 0x30

    .line 48
    .line 49
    if-nez v7, :cond_2

    .line 50
    .line 51
    move-object/from16 v7, p1

    .line 52
    .line 53
    invoke-virtual {v0, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    if-eqz v8, :cond_4

    .line 58
    .line 59
    const/16 v8, 0x20

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_4
    const/16 v8, 0x10

    .line 63
    .line 64
    :goto_2
    or-int/2addr v2, v8

    .line 65
    :goto_3
    and-int/lit16 v8, v4, 0x180

    .line 66
    .line 67
    if-nez v8, :cond_6

    .line 68
    .line 69
    invoke-virtual {v0, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v8

    .line 73
    if-eqz v8, :cond_5

    .line 74
    .line 75
    const/16 v8, 0x100

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_5
    const/16 v8, 0x80

    .line 79
    .line 80
    :goto_4
    or-int/2addr v2, v8

    .line 81
    :cond_6
    and-int/lit16 v8, v2, 0x93

    .line 82
    .line 83
    const/16 v9, 0x92

    .line 84
    .line 85
    if-eq v8, v9, :cond_7

    .line 86
    .line 87
    const/4 v8, 0x1

    .line 88
    goto :goto_5

    .line 89
    :cond_7
    const/4 v8, 0x0

    .line 90
    :goto_5
    and-int/lit8 v9, v2, 0x1

    .line 91
    .line 92
    invoke-virtual {v0, v9, v8}, Ll2/t;->O(IZ)Z

    .line 93
    .line 94
    .line 95
    move-result v8

    .line 96
    if-eqz v8, :cond_1e

    .line 97
    .line 98
    if-eqz v5, :cond_8

    .line 99
    .line 100
    sget-object v5, Lc71/a;->a:Lt2/b;

    .line 101
    .line 102
    goto :goto_6

    .line 103
    :cond_8
    move-object v5, v7

    .line 104
    :goto_6
    sget-object v7, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 105
    .line 106
    invoke-virtual {v0, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    check-cast v7, Landroid/content/Context;

    .line 111
    .line 112
    sget-object v8, Lw3/q1;->a:Ll2/u2;

    .line 113
    .line 114
    invoke-virtual {v0, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v8

    .line 118
    check-cast v8, Ljava/lang/Boolean;

    .line 119
    .line 120
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 121
    .line 122
    .line 123
    move-result v8

    .line 124
    sget-object v9, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 125
    .line 126
    invoke-virtual {v0, v9}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v9

    .line 130
    check-cast v9, Landroid/content/res/Configuration;

    .line 131
    .line 132
    sget-object v12, Lw3/h1;->h:Ll2/u2;

    .line 133
    .line 134
    invoke-virtual {v0, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v13

    .line 138
    check-cast v13, Lt4/c;

    .line 139
    .line 140
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v14

    .line 144
    const-wide v15, 0xffffffffL

    .line 145
    .line 146
    .line 147
    .line 148
    .line 149
    const/16 p3, 0x20

    .line 150
    .line 151
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 152
    .line 153
    if-ne v14, v6, :cond_a

    .line 154
    .line 155
    if-eqz v8, :cond_9

    .line 156
    .line 157
    iget v7, v9, Landroid/content/res/Configuration;->screenWidthDp:I

    .line 158
    .line 159
    int-to-float v7, v7

    .line 160
    invoke-interface {v13, v7}, Lt4/c;->w0(F)F

    .line 161
    .line 162
    .line 163
    move-result v7

    .line 164
    float-to-int v7, v7

    .line 165
    iget v9, v9, Landroid/content/res/Configuration;->screenHeightDp:I

    .line 166
    .line 167
    int-to-float v9, v9

    .line 168
    invoke-interface {v13, v9}, Lt4/c;->w0(F)F

    .line 169
    .line 170
    .line 171
    move-result v9

    .line 172
    float-to-int v9, v9

    .line 173
    int-to-long v13, v7

    .line 174
    shl-long v13, v13, p3

    .line 175
    .line 176
    int-to-long v10, v9

    .line 177
    and-long v9, v10, v15

    .line 178
    .line 179
    or-long/2addr v9, v13

    .line 180
    goto :goto_7

    .line 181
    :cond_9
    const-string v9, "context"

    .line 182
    .line 183
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-static {v7}, Llp/wc;->b(Landroid/content/Context;)I

    .line 187
    .line 188
    .line 189
    move-result v9

    .line 190
    invoke-static {v7}, Llp/wc;->c(Landroid/content/Context;)I

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    const-string v11, "status_bar_height"

    .line 195
    .line 196
    invoke-static {v7, v11}, Llp/wc;->e(Landroid/content/Context;Ljava/lang/String;)I

    .line 197
    .line 198
    .line 199
    const-string v11, "app_bar_height"

    .line 200
    .line 201
    invoke-static {v7, v11}, Llp/wc;->e(Landroid/content/Context;Ljava/lang/String;)I

    .line 202
    .line 203
    .line 204
    const-string v11, "navigation_bar_height"

    .line 205
    .line 206
    invoke-static {v7, v11}, Llp/wc;->e(Landroid/content/Context;Ljava/lang/String;)I

    .line 207
    .line 208
    .line 209
    int-to-long v10, v10

    .line 210
    shl-long v10, v10, p3

    .line 211
    .line 212
    int-to-long v13, v9

    .line 213
    and-long/2addr v13, v15

    .line 214
    or-long v9, v10, v13

    .line 215
    .line 216
    :goto_7
    new-instance v14, Lt4/l;

    .line 217
    .line 218
    invoke-direct {v14, v9, v10}, Lt4/l;-><init>(J)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v0, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    :cond_a
    check-cast v14, Lt4/l;

    .line 225
    .line 226
    iget-wide v9, v14, Lt4/l;->a:J

    .line 227
    .line 228
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v7

    .line 232
    if-ne v7, v6, :cond_c

    .line 233
    .line 234
    if-eqz v8, :cond_b

    .line 235
    .line 236
    shr-long v7, v9, p3

    .line 237
    .line 238
    long-to-int v7, v7

    .line 239
    int-to-float v7, v7

    .line 240
    and-long v13, v9, v15

    .line 241
    .line 242
    long-to-int v8, v13

    .line 243
    int-to-float v8, v8

    .line 244
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 245
    .line 246
    .line 247
    move-result v7

    .line 248
    int-to-long v13, v7

    .line 249
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 250
    .line 251
    .line 252
    move-result v7

    .line 253
    int-to-long v7, v7

    .line 254
    shl-long v13, v13, p3

    .line 255
    .line 256
    and-long/2addr v7, v15

    .line 257
    or-long/2addr v7, v13

    .line 258
    const-wide/16 v13, 0x0

    .line 259
    .line 260
    invoke-static {v13, v14, v7, v8}, Ljp/cf;->a(JJ)Ld3/c;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    move-wide/from16 v17, v9

    .line 265
    .line 266
    goto :goto_8

    .line 267
    :cond_b
    const/4 v7, 0x0

    .line 268
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 269
    .line 270
    .line 271
    move-result v8

    .line 272
    int-to-long v13, v8

    .line 273
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 274
    .line 275
    .line 276
    move-result v8

    .line 277
    move/from16 p1, v7

    .line 278
    .line 279
    int-to-long v7, v8

    .line 280
    shl-long v13, v13, p3

    .line 281
    .line 282
    and-long/2addr v7, v15

    .line 283
    or-long/2addr v7, v13

    .line 284
    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 285
    .line 286
    .line 287
    move-result v11

    .line 288
    int-to-long v13, v11

    .line 289
    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 290
    .line 291
    .line 292
    move-result v11

    .line 293
    move-wide/from16 v17, v9

    .line 294
    .line 295
    int-to-long v9, v11

    .line 296
    shl-long v13, v13, p3

    .line 297
    .line 298
    and-long/2addr v9, v15

    .line 299
    or-long/2addr v9, v13

    .line 300
    invoke-static {v7, v8, v9, v10}, Ljp/cf;->c(JJ)Ld3/c;

    .line 301
    .line 302
    .line 303
    move-result-object v7

    .line 304
    :goto_8
    invoke-static {v7}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 305
    .line 306
    .line 307
    move-result-object v7

    .line 308
    invoke-virtual {v0, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    goto :goto_9

    .line 312
    :cond_c
    move-wide/from16 v17, v9

    .line 313
    .line 314
    :goto_9
    check-cast v7, Ll2/b1;

    .line 315
    .line 316
    invoke-virtual {v0, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v8

    .line 320
    check-cast v8, Lt4/c;

    .line 321
    .line 322
    and-long v9, v17, v15

    .line 323
    .line 324
    long-to-int v9, v9

    .line 325
    int-to-float v9, v9

    .line 326
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v10

    .line 330
    check-cast v10, Ld3/c;

    .line 331
    .line 332
    iget v10, v10, Ld3/c;->b:F

    .line 333
    .line 334
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v11

    .line 338
    check-cast v11, Ld3/c;

    .line 339
    .line 340
    iget v11, v11, Ld3/c;->d:F

    .line 341
    .line 342
    invoke-static {v9, v10, v11}, Lkp/r9;->d(FFF)F

    .line 343
    .line 344
    .line 345
    move-result v10

    .line 346
    const/16 v11, 0x1f

    .line 347
    .line 348
    int-to-float v11, v11

    .line 349
    div-float v11, v9, v11

    .line 350
    .line 351
    const/4 v13, 0x6

    .line 352
    int-to-float v14, v13

    .line 353
    mul-float/2addr v11, v14

    .line 354
    sub-float/2addr v9, v11

    .line 355
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object v14

    .line 359
    check-cast v14, Ld3/c;

    .line 360
    .line 361
    iget v14, v14, Ld3/c;->b:F

    .line 362
    .line 363
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v15

    .line 367
    check-cast v15, Ld3/c;

    .line 368
    .line 369
    iget v15, v15, Ld3/c;->d:F

    .line 370
    .line 371
    invoke-static {v9, v14, v15}, Lkp/r9;->d(FFF)F

    .line 372
    .line 373
    .line 374
    move-result v14

    .line 375
    sub-float/2addr v10, v14

    .line 376
    invoke-interface {v8, v10}, Lt4/c;->o0(F)F

    .line 377
    .line 378
    .line 379
    move-result v8

    .line 380
    invoke-virtual {v0, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v10

    .line 384
    check-cast v10, Lt4/c;

    .line 385
    .line 386
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v12

    .line 390
    check-cast v12, Ld3/c;

    .line 391
    .line 392
    iget v12, v12, Ld3/c;->b:F

    .line 393
    .line 394
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v14

    .line 398
    check-cast v14, Ld3/c;

    .line 399
    .line 400
    iget v14, v14, Ld3/c;->d:F

    .line 401
    .line 402
    invoke-static {v9, v12, v14}, Lkp/r9;->d(FFF)F

    .line 403
    .line 404
    .line 405
    move-result v12

    .line 406
    sub-float/2addr v9, v11

    .line 407
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v11

    .line 411
    check-cast v11, Ld3/c;

    .line 412
    .line 413
    iget v11, v11, Ld3/c;->b:F

    .line 414
    .line 415
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v14

    .line 419
    check-cast v14, Ld3/c;

    .line 420
    .line 421
    iget v14, v14, Ld3/c;->d:F

    .line 422
    .line 423
    invoke-static {v9, v11, v14}, Lkp/r9;->d(FFF)F

    .line 424
    .line 425
    .line 426
    move-result v9

    .line 427
    sub-float/2addr v12, v9

    .line 428
    invoke-interface {v10, v12}, Lt4/c;->o0(F)F

    .line 429
    .line 430
    .line 431
    move-result v9

    .line 432
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v10

    .line 436
    if-ne v10, v6, :cond_d

    .line 437
    .line 438
    new-instance v10, La2/g;

    .line 439
    .line 440
    const/4 v6, 0x6

    .line 441
    invoke-direct {v10, v7, v6}, La2/g;-><init>(Ll2/b1;I)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {v0, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    :cond_d
    check-cast v10, Lay0/k;

    .line 448
    .line 449
    invoke-static {v1, v10}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 450
    .line 451
    .line 452
    move-result-object v6

    .line 453
    sget-object v7, Lx2/c;->d:Lx2/j;

    .line 454
    .line 455
    const/4 v10, 0x0

    .line 456
    invoke-static {v7, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 457
    .line 458
    .line 459
    move-result-object v11

    .line 460
    iget-wide v14, v0, Ll2/t;->T:J

    .line 461
    .line 462
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 463
    .line 464
    .line 465
    move-result v10

    .line 466
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 467
    .line 468
    .line 469
    move-result-object v12

    .line 470
    invoke-static {v0, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 471
    .line 472
    .line 473
    move-result-object v6

    .line 474
    sget-object v14, Lv3/k;->m1:Lv3/j;

    .line 475
    .line 476
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 477
    .line 478
    .line 479
    sget-object v14, Lv3/j;->b:Lv3/i;

    .line 480
    .line 481
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 482
    .line 483
    .line 484
    iget-boolean v15, v0, Ll2/t;->S:Z

    .line 485
    .line 486
    if-eqz v15, :cond_e

    .line 487
    .line 488
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 489
    .line 490
    .line 491
    goto :goto_a

    .line 492
    :cond_e
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 493
    .line 494
    .line 495
    :goto_a
    sget-object v15, Lv3/j;->g:Lv3/h;

    .line 496
    .line 497
    invoke-static {v15, v11, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 498
    .line 499
    .line 500
    sget-object v11, Lv3/j;->f:Lv3/h;

    .line 501
    .line 502
    invoke-static {v11, v12, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 503
    .line 504
    .line 505
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 506
    .line 507
    move/from16 p1, v13

    .line 508
    .line 509
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 510
    .line 511
    if-nez v13, :cond_f

    .line 512
    .line 513
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v13

    .line 517
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 518
    .line 519
    .line 520
    move-result-object v1

    .line 521
    invoke-static {v13, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 522
    .line 523
    .line 524
    move-result v1

    .line 525
    if-nez v1, :cond_10

    .line 526
    .line 527
    :cond_f
    invoke-static {v10, v0, v10, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 528
    .line 529
    .line 530
    :cond_10
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 531
    .line 532
    invoke-static {v1, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 533
    .line 534
    .line 535
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 536
    .line 537
    const/high16 v10, 0x3f800000    # 1.0f

    .line 538
    .line 539
    invoke-static {v6, v10}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 540
    .line 541
    .line 542
    move-result-object v13

    .line 543
    sget-object v10, Lx2/c;->k:Lx2/j;

    .line 544
    .line 545
    move/from16 v16, v2

    .line 546
    .line 547
    sget-object v2, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 548
    .line 549
    invoke-virtual {v2, v13, v10}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 550
    .line 551
    .line 552
    move-result-object v10

    .line 553
    sget-object v13, Lk1/j;->c:Lk1/e;

    .line 554
    .line 555
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 556
    .line 557
    const/4 v3, 0x0

    .line 558
    invoke-static {v13, v4, v0, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 559
    .line 560
    .line 561
    move-result-object v4

    .line 562
    move-object v13, v2

    .line 563
    iget-wide v2, v0, Ll2/t;->T:J

    .line 564
    .line 565
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 566
    .line 567
    .line 568
    move-result v2

    .line 569
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 570
    .line 571
    .line 572
    move-result-object v3

    .line 573
    invoke-static {v0, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 574
    .line 575
    .line 576
    move-result-object v10

    .line 577
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 578
    .line 579
    .line 580
    move-object/from16 v17, v13

    .line 581
    .line 582
    iget-boolean v13, v0, Ll2/t;->S:Z

    .line 583
    .line 584
    if-eqz v13, :cond_11

    .line 585
    .line 586
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 587
    .line 588
    .line 589
    goto :goto_b

    .line 590
    :cond_11
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 591
    .line 592
    .line 593
    :goto_b
    invoke-static {v15, v4, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 594
    .line 595
    .line 596
    invoke-static {v11, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 597
    .line 598
    .line 599
    iget-boolean v3, v0, Ll2/t;->S:Z

    .line 600
    .line 601
    if-nez v3, :cond_12

    .line 602
    .line 603
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    move-result-object v3

    .line 607
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 608
    .line 609
    .line 610
    move-result-object v4

    .line 611
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 612
    .line 613
    .line 614
    move-result v3

    .line 615
    if-nez v3, :cond_13

    .line 616
    .line 617
    :cond_12
    invoke-static {v2, v0, v2, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 618
    .line 619
    .line 620
    :cond_13
    invoke-static {v1, v10, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 621
    .line 622
    .line 623
    const/4 v10, 0x0

    .line 624
    int-to-float v2, v10

    .line 625
    invoke-static {v9, v2}, Ljava/lang/Float;->compare(FF)I

    .line 626
    .line 627
    .line 628
    move-result v3

    .line 629
    if-lez v3, :cond_18

    .line 630
    .line 631
    const v3, -0x2fc5121a

    .line 632
    .line 633
    .line 634
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 635
    .line 636
    .line 637
    const/high16 v3, 0x3f800000    # 1.0f

    .line 638
    .line 639
    invoke-static {v6, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 640
    .line 641
    .line 642
    move-result-object v10

    .line 643
    cmpg-float v3, v9, v2

    .line 644
    .line 645
    if-gez v3, :cond_14

    .line 646
    .line 647
    move v9, v2

    .line 648
    :cond_14
    invoke-static {v10, v9}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 649
    .line 650
    .line 651
    move-result-object v3

    .line 652
    shl-int/lit8 v9, v16, 0x6

    .line 653
    .line 654
    and-int/lit16 v9, v9, 0x1c00

    .line 655
    .line 656
    const/4 v10, 0x0

    .line 657
    invoke-static {v7, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 658
    .line 659
    .line 660
    move-result-object v13

    .line 661
    move-object v10, v5

    .line 662
    iget-wide v4, v0, Ll2/t;->T:J

    .line 663
    .line 664
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 665
    .line 666
    .line 667
    move-result v4

    .line 668
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 669
    .line 670
    .line 671
    move-result-object v5

    .line 672
    invoke-static {v0, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 673
    .line 674
    .line 675
    move-result-object v3

    .line 676
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 677
    .line 678
    .line 679
    move/from16 v19, v9

    .line 680
    .line 681
    iget-boolean v9, v0, Ll2/t;->S:Z

    .line 682
    .line 683
    if-eqz v9, :cond_15

    .line 684
    .line 685
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 686
    .line 687
    .line 688
    goto :goto_c

    .line 689
    :cond_15
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 690
    .line 691
    .line 692
    :goto_c
    invoke-static {v15, v13, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 693
    .line 694
    .line 695
    invoke-static {v11, v5, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 696
    .line 697
    .line 698
    iget-boolean v5, v0, Ll2/t;->S:Z

    .line 699
    .line 700
    if-nez v5, :cond_16

    .line 701
    .line 702
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 703
    .line 704
    .line 705
    move-result-object v5

    .line 706
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 707
    .line 708
    .line 709
    move-result-object v9

    .line 710
    invoke-static {v5, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 711
    .line 712
    .line 713
    move-result v5

    .line 714
    if-nez v5, :cond_17

    .line 715
    .line 716
    :cond_16
    invoke-static {v4, v0, v4, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 717
    .line 718
    .line 719
    :cond_17
    invoke-static {v1, v3, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 720
    .line 721
    .line 722
    shr-int/lit8 v3, v19, 0x6

    .line 723
    .line 724
    and-int/lit8 v3, v3, 0x70

    .line 725
    .line 726
    or-int/lit8 v3, v3, 0x6

    .line 727
    .line 728
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 729
    .line 730
    .line 731
    move-result-object v3

    .line 732
    move-object/from16 v13, v17

    .line 733
    .line 734
    invoke-interface {v10, v13, v0, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    const/4 v3, 0x1

    .line 738
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 739
    .line 740
    .line 741
    const/4 v3, 0x0

    .line 742
    :goto_d
    invoke-virtual {v0, v3}, Ll2/t;->q(Z)V

    .line 743
    .line 744
    .line 745
    goto :goto_e

    .line 746
    :cond_18
    move-object v10, v5

    .line 747
    move-object/from16 v13, v17

    .line 748
    .line 749
    const/4 v3, 0x0

    .line 750
    const v4, -0x3005a64e

    .line 751
    .line 752
    .line 753
    invoke-virtual {v0, v4}, Ll2/t;->Y(I)V

    .line 754
    .line 755
    .line 756
    goto :goto_d

    .line 757
    :goto_e
    invoke-static {v8, v2}, Ljava/lang/Float;->compare(FF)I

    .line 758
    .line 759
    .line 760
    move-result v3

    .line 761
    if-lez v3, :cond_1d

    .line 762
    .line 763
    const v3, -0x2fc04294

    .line 764
    .line 765
    .line 766
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 767
    .line 768
    .line 769
    const/high16 v3, 0x3f800000    # 1.0f

    .line 770
    .line 771
    invoke-static {v6, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 772
    .line 773
    .line 774
    move-result-object v3

    .line 775
    cmpg-float v4, v8, v2

    .line 776
    .line 777
    if-gez v4, :cond_19

    .line 778
    .line 779
    move v8, v2

    .line 780
    :cond_19
    invoke-static {v3, v8}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 781
    .line 782
    .line 783
    move-result-object v2

    .line 784
    shl-int/lit8 v3, v16, 0x3

    .line 785
    .line 786
    and-int/lit16 v3, v3, 0x1c00

    .line 787
    .line 788
    const/4 v4, 0x0

    .line 789
    invoke-static {v7, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 790
    .line 791
    .line 792
    move-result-object v5

    .line 793
    iget-wide v6, v0, Ll2/t;->T:J

    .line 794
    .line 795
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 796
    .line 797
    .line 798
    move-result v4

    .line 799
    invoke-virtual {v0}, Ll2/t;->m()Ll2/p1;

    .line 800
    .line 801
    .line 802
    move-result-object v6

    .line 803
    invoke-static {v0, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 804
    .line 805
    .line 806
    move-result-object v2

    .line 807
    invoke-virtual {v0}, Ll2/t;->c0()V

    .line 808
    .line 809
    .line 810
    iget-boolean v7, v0, Ll2/t;->S:Z

    .line 811
    .line 812
    if-eqz v7, :cond_1a

    .line 813
    .line 814
    invoke-virtual {v0, v14}, Ll2/t;->l(Lay0/a;)V

    .line 815
    .line 816
    .line 817
    goto :goto_f

    .line 818
    :cond_1a
    invoke-virtual {v0}, Ll2/t;->m0()V

    .line 819
    .line 820
    .line 821
    :goto_f
    invoke-static {v15, v5, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 822
    .line 823
    .line 824
    invoke-static {v11, v6, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 825
    .line 826
    .line 827
    iget-boolean v5, v0, Ll2/t;->S:Z

    .line 828
    .line 829
    if-nez v5, :cond_1b

    .line 830
    .line 831
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 832
    .line 833
    .line 834
    move-result-object v5

    .line 835
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 836
    .line 837
    .line 838
    move-result-object v6

    .line 839
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 840
    .line 841
    .line 842
    move-result v5

    .line 843
    if-nez v5, :cond_1c

    .line 844
    .line 845
    :cond_1b
    invoke-static {v4, v0, v4, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 846
    .line 847
    .line 848
    :cond_1c
    invoke-static {v1, v2, v0}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 849
    .line 850
    .line 851
    shr-int/lit8 v1, v3, 0x6

    .line 852
    .line 853
    and-int/lit8 v1, v1, 0x70

    .line 854
    .line 855
    or-int/lit8 v1, v1, 0x6

    .line 856
    .line 857
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 858
    .line 859
    .line 860
    move-result-object v1

    .line 861
    move-object/from16 v3, p2

    .line 862
    .line 863
    invoke-virtual {v3, v13, v0, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 864
    .line 865
    .line 866
    const/4 v1, 0x1

    .line 867
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 868
    .line 869
    .line 870
    const/4 v4, 0x0

    .line 871
    :goto_10
    invoke-virtual {v0, v4}, Ll2/t;->q(Z)V

    .line 872
    .line 873
    .line 874
    goto :goto_11

    .line 875
    :cond_1d
    move-object/from16 v3, p2

    .line 876
    .line 877
    const/4 v1, 0x1

    .line 878
    const v2, -0x3005a64e

    .line 879
    .line 880
    .line 881
    const/4 v4, 0x0

    .line 882
    invoke-virtual {v0, v2}, Ll2/t;->Y(I)V

    .line 883
    .line 884
    .line 885
    goto :goto_10

    .line 886
    :goto_11
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 887
    .line 888
    .line 889
    invoke-virtual {v0, v1}, Ll2/t;->q(Z)V

    .line 890
    .line 891
    .line 892
    move-object v2, v10

    .line 893
    goto :goto_12

    .line 894
    :cond_1e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 895
    .line 896
    .line 897
    move-object v2, v7

    .line 898
    :goto_12
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 899
    .line 900
    .line 901
    move-result-object v7

    .line 902
    if-eqz v7, :cond_1f

    .line 903
    .line 904
    new-instance v0, Lc71/c;

    .line 905
    .line 906
    const/4 v6, 0x0

    .line 907
    move-object/from16 v1, p0

    .line 908
    .line 909
    move/from16 v4, p4

    .line 910
    .line 911
    move/from16 v5, p5

    .line 912
    .line 913
    invoke-direct/range {v0 .. v6}, Lc71/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;III)V

    .line 914
    .line 915
    .line 916
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 917
    .line 918
    :cond_1f
    return-void
.end method

.method public static final b(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;Ll2/o;III)V
    .locals 44

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v0, p2

    move/from16 v15, p4

    move-object/from16 v3, p6

    move-object/from16 v8, p10

    move/from16 v10, p12

    move/from16 v11, p13

    move/from16 v12, p14

    sget-object v4, Lx2/c;->p:Lx2/h;

    sget-object v13, Lh71/a;->d:Lh71/a;

    const-string v5, "modifier"

    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "toolbarTitle"

    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "onCloseClicked"

    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    move-object/from16 v14, p11

    check-cast v14, Ll2/t;

    const v5, -0x5bd6741f

    invoke-virtual {v14, v5}, Ll2/t;->a0(I)Ll2/t;

    and-int/lit8 v5, v10, 0x6

    if-nez v5, :cond_1

    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v10

    goto :goto_1

    :cond_1
    move v5, v10

    :goto_1
    and-int/lit8 v9, v10, 0x30

    const/16 v16, 0x20

    move/from16 p11, v5

    if-nez v9, :cond_3

    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_2

    move/from16 v9, v16

    goto :goto_2

    :cond_2
    const/16 v9, 0x10

    :goto_2
    or-int v9, p11, v9

    goto :goto_3

    :cond_3
    move/from16 v9, p11

    :goto_3
    and-int/lit16 v5, v10, 0x180

    const/16 v17, 0x80

    const/16 v18, 0x100

    move/from16 v19, v5

    const/4 v5, 0x0

    if-nez v19, :cond_5

    invoke-virtual {v14, v5}, Ll2/t;->e(I)Z

    move-result v19

    if-eqz v19, :cond_4

    move/from16 v19, v18

    goto :goto_4

    :cond_4
    move/from16 v19, v17

    :goto_4
    or-int v9, v9, v19

    :cond_5
    and-int/lit16 v6, v10, 0xc00

    if-nez v6, :cond_7

    invoke-virtual {v14, v0}, Ll2/t;->h(Z)Z

    move-result v6

    if-eqz v6, :cond_6

    const/16 v6, 0x800

    goto :goto_5

    :cond_6
    const/16 v6, 0x400

    :goto_5
    or-int/2addr v9, v6

    :cond_7
    and-int/lit8 v6, v12, 0x10

    if-eqz v6, :cond_9

    or-int/lit16 v9, v9, 0x6000

    :cond_8
    move-object/from16 v7, p3

    goto :goto_7

    :cond_9
    and-int/lit16 v7, v10, 0x6000

    if-nez v7, :cond_8

    move-object/from16 v7, p3

    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v21

    if-eqz v21, :cond_a

    const/16 v21, 0x4000

    goto :goto_6

    :cond_a
    const/16 v21, 0x2000

    :goto_6
    or-int v9, v9, v21

    :goto_7
    const/high16 v21, 0x30000

    and-int v21, v10, v21

    if-nez v21, :cond_c

    invoke-virtual {v14, v15}, Ll2/t;->h(Z)Z

    move-result v21

    if-eqz v21, :cond_b

    const/high16 v21, 0x20000

    goto :goto_8

    :cond_b
    const/high16 v21, 0x10000

    :goto_8
    or-int v9, v9, v21

    :cond_c
    and-int/lit8 v21, v12, 0x40

    const/high16 v22, 0x180000

    if-eqz v21, :cond_d

    or-int v9, v9, v22

    move/from16 v5, p5

    goto :goto_a

    :cond_d
    and-int v22, v10, v22

    move/from16 v5, p5

    if-nez v22, :cond_f

    invoke-virtual {v14, v5}, Ll2/t;->h(Z)Z

    move-result v23

    if-eqz v23, :cond_e

    const/high16 v23, 0x100000

    goto :goto_9

    :cond_e
    const/high16 v23, 0x80000

    :goto_9
    or-int v9, v9, v23

    :cond_f
    :goto_a
    and-int/lit16 v0, v12, 0x80

    move/from16 v23, v0

    const/4 v0, 0x0

    const/high16 v24, 0xc00000

    if-eqz v23, :cond_10

    or-int v9, v9, v24

    goto :goto_c

    :cond_10
    and-int v23, v10, v24

    if-nez v23, :cond_12

    invoke-virtual {v14, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_11

    const/high16 v23, 0x800000

    goto :goto_b

    :cond_11
    const/high16 v23, 0x400000

    :goto_b
    or-int v9, v9, v23

    :cond_12
    :goto_c
    const/high16 v23, 0x6000000

    and-int v23, v10, v23

    if-nez v23, :cond_14

    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v23

    if-eqz v23, :cond_13

    const/high16 v23, 0x4000000

    goto :goto_d

    :cond_13
    const/high16 v23, 0x2000000

    :goto_d
    or-int v9, v9, v23

    :cond_14
    and-int/lit16 v0, v12, 0x200

    const/high16 v24, 0x30000000

    if-eqz v0, :cond_15

    or-int v9, v9, v24

    move/from16 v24, v0

    move/from16 v29, v9

    move-object/from16 v0, p7

    goto :goto_10

    :cond_15
    and-int v24, v10, v24

    if-nez v24, :cond_17

    move/from16 v24, v0

    move-object/from16 v0, p7

    invoke-virtual {v14, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_16

    const/high16 v25, 0x20000000

    goto :goto_e

    :cond_16
    const/high16 v25, 0x10000000

    :goto_e
    or-int v9, v9, v25

    :goto_f
    move/from16 v29, v9

    goto :goto_10

    :cond_17
    move/from16 v24, v0

    move-object/from16 v0, p7

    goto :goto_f

    :goto_10
    and-int/lit16 v9, v12, 0x400

    if-eqz v9, :cond_18

    or-int/lit8 v19, v11, 0x6

    move-object/from16 v0, p8

    goto :goto_12

    :cond_18
    and-int/lit8 v25, v11, 0x6

    move-object/from16 v0, p8

    if-nez v25, :cond_1a

    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v25

    if-eqz v25, :cond_19

    const/16 v19, 0x4

    goto :goto_11

    :cond_19
    const/16 v19, 0x2

    :goto_11
    or-int v19, v11, v19

    goto :goto_12

    :cond_1a
    move/from16 v19, v11

    :goto_12
    and-int/lit16 v0, v12, 0x800

    if-eqz v0, :cond_1c

    or-int/lit8 v19, v19, 0x30

    :cond_1b
    move/from16 v25, v0

    move-object/from16 v0, p9

    goto :goto_14

    :cond_1c
    and-int/lit8 v25, v11, 0x30

    if-nez v25, :cond_1b

    move/from16 v25, v0

    move-object/from16 v0, p9

    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_1d

    goto :goto_13

    :cond_1d
    const/16 v16, 0x10

    :goto_13
    or-int v19, v19, v16

    :goto_14
    and-int/lit16 v0, v11, 0x180

    if-nez v0, :cond_1f

    invoke-virtual {v14, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1e

    move/from16 v17, v18

    :cond_1e
    or-int v19, v19, v17

    :cond_1f
    move/from16 v0, v19

    const v16, 0x12492493

    and-int v2, v29, v16

    const v3, 0x12492492

    if-ne v2, v3, :cond_21

    and-int/lit16 v2, v0, 0x93

    const/16 v3, 0x92

    if-eq v2, v3, :cond_20

    goto :goto_15

    :cond_20
    const/4 v2, 0x0

    goto :goto_16

    :cond_21
    :goto_15
    const/4 v2, 0x1

    :goto_16
    and-int/lit8 v3, v29, 0x1

    invoke-virtual {v14, v3, v2}, Ll2/t;->O(IZ)Z

    move-result v2

    if-eqz v2, :cond_3f

    if-eqz v6, :cond_22

    const/16 v26, 0x0

    goto :goto_17

    :cond_22
    move-object/from16 v26, v7

    :goto_17
    if-eqz v21, :cond_23

    const/16 v30, 0x1

    goto :goto_18

    :cond_23
    move/from16 v30, p5

    :goto_18
    if-eqz v24, :cond_24

    const/4 v2, 0x0

    goto :goto_19

    :cond_24
    move-object/from16 v2, p7

    :goto_19
    if-eqz v9, :cond_25

    .line 2
    sget-object v3, Lk1/j;->c:Lk1/e;

    goto :goto_1a

    :cond_25
    move-object/from16 v3, p8

    :goto_1a
    if-eqz v25, :cond_26

    move-object v6, v4

    goto :goto_1b

    :cond_26
    move-object/from16 v6, p9

    .line 3
    :goto_1b
    sget-object v7, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 4
    invoke-virtual {v14, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v7

    .line 5
    check-cast v7, Landroid/content/Context;

    .line 6
    invoke-virtual {v14, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    move-result v9

    .line 7
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v5

    if-nez v9, :cond_28

    .line 8
    sget-object v9, Ll2/n;->a:Ll2/x0;

    if-ne v5, v9, :cond_27

    goto :goto_1c

    :cond_27
    move/from16 v24, v0

    goto :goto_1d

    .line 9
    :cond_28
    :goto_1c
    new-instance v5, La71/d0;

    const/4 v9, 0x1

    move/from16 v24, v0

    const/4 v0, 0x0

    invoke-direct {v5, v7, v0, v9}, La71/d0;-><init>(Landroid/content/Context;Lkotlin/coroutines/Continuation;I)V

    .line 10
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 11
    :goto_1d
    check-cast v5, Lay0/n;

    invoke-static {v5, v7, v14}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 12
    invoke-static {v14}, Llp/q0;->e(Ll2/o;)Lh71/l;

    move-result-object v0

    .line 13
    iget-object v0, v0, Lh71/l;->a:Lh71/e;

    move-object/from16 p3, v2

    move-object/from16 p5, v3

    .line 14
    iget-wide v2, v0, Lh71/e;->a:J

    .line 15
    sget-object v0, Le3/j0;->a:Le3/i0;

    .line 16
    invoke-static {v1, v2, v3, v0}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    move-result-object v0

    .line 17
    invoke-static {v0}, Lk1/d;->n(Lx2/s;)Lx2/s;

    move-result-object v0

    .line 18
    invoke-static {v0}, Lk1/d;->m(Lx2/s;)Lx2/s;

    move-result-object v0

    .line 19
    sget-object v2, Lk1/j;->c:Lk1/e;

    const/4 v3, 0x0

    .line 20
    invoke-static {v2, v4, v14, v3}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    move-result-object v2

    .line 21
    iget-wide v4, v14, Ll2/t;->T:J

    .line 22
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    move-result v4

    .line 23
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    move-result-object v5

    .line 24
    invoke-static {v14, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v0

    .line 25
    sget-object v7, Lv3/k;->m1:Lv3/j;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 27
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 28
    iget-boolean v9, v14, Ll2/t;->S:Z

    if-eqz v9, :cond_29

    .line 29
    invoke-virtual {v14, v7}, Ll2/t;->l(Lay0/a;)V

    goto :goto_1e

    .line 30
    :cond_29
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 31
    :goto_1e
    sget-object v9, Lv3/j;->g:Lv3/h;

    .line 32
    invoke-static {v9, v2, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 33
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 34
    invoke-static {v2, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 35
    sget-object v5, Lv3/j;->j:Lv3/h;

    .line 36
    iget-boolean v3, v14, Ll2/t;->S:Z

    if-nez v3, :cond_2a

    .line 37
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2b

    .line 38
    :cond_2a
    invoke-static {v4, v14, v4, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 39
    :cond_2b
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 40
    invoke-static {v1, v0, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 41
    sget-object v0, Lx2/p;->b:Lx2/p;

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    move-result-object v4

    .line 42
    invoke-static {v14}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v3

    .line 43
    iget v3, v3, Lh71/t;->e:F

    move-object/from16 p8, v6

    .line 44
    invoke-static {v14}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v6

    .line 45
    iget v6, v6, Lh71/t;->c:F

    .line 46
    invoke-static {v4, v3, v6}, Landroidx/compose/foundation/layout/a;->n(Lx2/s;FF)Lx2/s;

    move-result-object v3

    .line 47
    sget-object v4, Lx2/c;->n:Lx2/i;

    .line 48
    invoke-static {v14}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v6

    .line 49
    iget v6, v6, Lh71/t;->e:F

    .line 50
    invoke-static {v6}, Lk1/j;->g(F)Lk1/h;

    move-result-object v6

    const/16 v8, 0x30

    .line 51
    invoke-static {v6, v4, v14, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    move-result-object v4

    .line 52
    iget-wide v10, v14, Ll2/t;->T:J

    .line 53
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    move-result v6

    .line 54
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    move-result-object v8

    .line 55
    invoke-static {v14, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v3

    .line 56
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 57
    iget-boolean v10, v14, Ll2/t;->S:Z

    if-eqz v10, :cond_2c

    .line 58
    invoke-virtual {v14, v7}, Ll2/t;->l(Lay0/a;)V

    goto :goto_1f

    .line 59
    :cond_2c
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 60
    :goto_1f
    invoke-static {v9, v4, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 61
    invoke-static {v2, v8, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 62
    iget-boolean v4, v14, Ll2/t;->S:Z

    if-nez v4, :cond_2d

    .line 63
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_2e

    .line 64
    :cond_2d
    invoke-static {v6, v14, v6, v5}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 65
    :cond_2e
    invoke-static {v1, v3, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    if-eqz p2, :cond_2f

    const v4, -0xef389b1

    .line 66
    invoke-virtual {v14, v4}, Ll2/t;->Y(I)V

    .line 67
    invoke-static {v14}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v4

    .line 68
    iget v4, v4, Lh71/t;->f:F

    .line 69
    invoke-static {v0, v4}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    move-result-object v4

    move-object v6, v7

    const/4 v7, 0x0

    move-object v8, v9

    const/16 v9, 0xf

    move-object v10, v5

    const/4 v5, 0x0

    move-object v11, v6

    const/4 v6, 0x0

    move-object/from16 v31, v8

    move-object/from16 v32, v10

    const/4 v3, 0x0

    move-object/from16 v10, p8

    move-object/from16 v8, p10

    .line 70
    invoke-static/range {v4 .. v9}, Landroidx/compose/foundation/a;->f(Lx2/s;ZLjava/lang/String;Ld4/i;Lay0/a;I)Lx2/s;

    move-result-object v16

    .line 71
    sget-object v4, Lh71/q;->a:Ll2/e0;

    .line 72
    invoke-virtual {v14, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v4

    .line 73
    check-cast v4, Lh71/p;

    .line 74
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const v4, 0x7f0800ca

    .line 75
    invoke-static {v4, v3, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    move-result-object v17

    .line 76
    invoke-static {v14}, Llp/q0;->e(Ll2/o;)Lh71/l;

    move-result-object v4

    .line 77
    iget-object v4, v4, Lh71/l;->c:Lh71/f;

    .line 78
    iget-wide v4, v4, Lh71/f;->a:J

    const/16 v21, 0x0

    move-wide/from16 v18, v4

    move-object/from16 v20, v14

    .line 79
    invoke-static/range {v16 .. v21}, Lkp/i0;->b(Lx2/s;Li3/c;JLl2/o;I)V

    move-object/from16 v4, v20

    .line 80
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    const v5, -0xf35f819

    :goto_20
    const/high16 v6, 0x3f800000    # 1.0f

    goto :goto_21

    :cond_2f
    move-object/from16 v10, p8

    move-object/from16 v32, v5

    move-object v11, v7

    move-object/from16 v31, v9

    move-object v4, v14

    const/4 v3, 0x0

    const v5, -0xf35f819

    .line 81
    invoke-virtual {v4, v5}, Ll2/t;->Y(I)V

    .line 82
    invoke-virtual {v4, v3}, Ll2/t;->q(Z)V

    goto :goto_20

    :goto_21
    float-to-double v7, v6

    const-wide/16 v16, 0x0

    cmpl-double v7, v7, v16

    if-lez v7, :cond_30

    goto :goto_22

    .line 83
    :cond_30
    const-string v7, "invalid weight; must be greater than zero"

    .line 84
    invoke-static {v7}, Ll1/a;->a(Ljava/lang/String;)V

    .line 85
    :goto_22
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v8, 0x1

    invoke-direct {v7, v6, v8}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    move-object v14, v10

    .line 86
    invoke-virtual {v13, v4}, Lh71/a;->d(Ll2/o;)J

    move-result-wide v9

    .line 87
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 88
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v16

    .line 89
    check-cast v16, Lj91/f;

    .line 90
    invoke-virtual/range {v16 .. v16}, Lj91/f;->l()Lg4/p0;

    move-result-object v16

    move-object/from16 v17, v11

    .line 91
    new-instance v11, Lr4/k;

    move-object/from16 p7, v5

    const/4 v5, 0x3

    invoke-direct {v11, v5}, Lr4/k;-><init>(I)V

    shr-int/lit8 v18, v29, 0x3

    move-object/from16 v19, v13

    and-int/lit8 v13, v18, 0xe

    move-object/from16 v20, v14

    const/16 v14, 0x78

    move/from16 v21, v5

    const/4 v5, 0x0

    move/from16 v22, v6

    const/4 v6, 0x0

    move-object v12, v4

    move-object v4, v7

    const/4 v7, 0x0

    move/from16 v33, v8

    const/4 v8, 0x0

    move-object/from16 v34, p3

    move-object/from16 v35, p5

    move-object/from16 v37, p7

    move-object/from16 p3, v1

    move v1, v3

    move-object/from16 v3, v16

    move-object/from16 v15, v17

    move-object/from16 v36, v20

    move-object/from16 v16, v2

    move-object/from16 v2, p1

    .line 92
    invoke-static/range {v2 .. v14}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    if-eqz p2, :cond_31

    const v2, -0xee9caeb

    .line 93
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 94
    invoke-static {v12}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v2

    .line 95
    iget v2, v2, Lh71/t;->f:F

    .line 96
    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    move-result-object v2

    invoke-static {v2, v12, v1}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 97
    :goto_23
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    const/4 v8, 0x1

    goto :goto_24

    :cond_31
    const v5, -0xf35f819

    .line 98
    invoke-virtual {v12, v5}, Ll2/t;->Y(I)V

    goto :goto_23

    .line 99
    :goto_24
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    const/high16 v6, 0x3f800000    # 1.0f

    .line 100
    invoke-static {v0, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    move-result-object v2

    .line 101
    sget-object v3, Lk1/t;->a:Lk1/t;

    invoke-virtual {v3, v2, v8}, Lk1/t;->b(Lx2/s;Z)Lx2/s;

    move-result-object v2

    .line 102
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 103
    invoke-static {v4, v1}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    move-result-object v4

    .line 104
    iget-wide v9, v12, Ll2/t;->T:J

    .line 105
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    move-result v5

    .line 106
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    move-result-object v7

    .line 107
    invoke-static {v12, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v2

    .line 108
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 109
    iget-boolean v9, v12, Ll2/t;->S:Z

    if-eqz v9, :cond_32

    .line 110
    invoke-virtual {v12, v15}, Ll2/t;->l(Lay0/a;)V

    :goto_25
    move-object/from16 v9, v31

    goto :goto_26

    .line 111
    :cond_32
    invoke-virtual {v12}, Ll2/t;->m0()V

    goto :goto_25

    .line 112
    :goto_26
    invoke-static {v9, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    move-object/from16 v4, v16

    .line 113
    invoke-static {v4, v7, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    iget-boolean v7, v12, Ll2/t;->S:Z

    if-nez v7, :cond_33

    .line 115
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_34

    :cond_33
    move-object/from16 v10, v32

    goto :goto_28

    :cond_34
    move-object/from16 v10, v32

    :goto_27
    move-object/from16 v5, p3

    goto :goto_29

    .line 116
    :goto_28
    invoke-static {v5, v12, v5, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    goto :goto_27

    .line 117
    :goto_29
    invoke-static {v5, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 118
    invoke-static {v0, v6}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    move-result-object v2

    and-int/lit8 v6, v18, 0x70

    const/4 v7, 0x6

    or-int/2addr v6, v7

    move-object/from16 v11, v19

    .line 119
    invoke-static {v2, v11, v12, v6}, Ld71/b;->b(Lx2/s;Lh71/a;Ll2/o;I)V

    const v2, 0x7d7ea4d2

    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 120
    sget-object v2, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    if-nez p4, :cond_35

    const v6, -0x6cd83ddb

    .line 121
    invoke-virtual {v12, v6}, Ll2/t;->Y(I)V

    .line 122
    invoke-static {v1, v8, v12}, Lkp/n;->b(IILl2/o;)Le1/n1;

    move-result-object v6

    const/16 v11, 0xe

    invoke-static {v2, v6, v11}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    move-result-object v2

    .line 123
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    goto :goto_2a

    :cond_35
    const v6, -0x6ccf9e51

    .line 124
    invoke-virtual {v12, v6}, Ll2/t;->Y(I)V

    .line 125
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 126
    :goto_2a
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    .line 127
    invoke-static {v12}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v6

    .line 128
    iget v6, v6, Lh71/t;->e:F

    const/4 v11, 0x0

    const/4 v13, 0x2

    .line 129
    invoke-static {v2, v6, v11, v13}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    move-result-object v38

    if-eqz v30, :cond_38

    const v2, 0x7d7f0e5e

    .line 130
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 131
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->a:Ll2/e0;

    .line 132
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v2

    .line 133
    check-cast v2, Landroid/content/res/Configuration;

    .line 134
    iget v2, v2, Landroid/content/res/Configuration;->screenWidthDp:I

    const/16 v6, 0x168

    if-ge v2, v6, :cond_36

    const/16 v2, 0xc

    :goto_2b
    int-to-float v2, v2

    goto :goto_2c

    :cond_36
    const/16 v6, 0x19e

    if-ge v2, v6, :cond_37

    const/16 v2, 0x10

    goto :goto_2b

    :cond_37
    const/16 v2, 0x14

    goto :goto_2b

    .line 135
    :goto_2c
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    :goto_2d
    move/from16 v40, v2

    goto :goto_2e

    :cond_38
    const v2, 0x7d7f0f7f    # 2.11896E37f

    .line 136
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 137
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    int-to-float v2, v1

    goto :goto_2d

    :goto_2e
    const/16 v42, 0x0

    const/16 v43, 0xd

    const/16 v39, 0x0

    const/16 v41, 0x0

    .line 138
    invoke-static/range {v38 .. v43}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    move-result-object v2

    shl-int/lit8 v6, v24, 0x3

    and-int/lit16 v6, v6, 0x3f0

    shr-int/lit8 v6, v6, 0x3

    and-int/lit8 v6, v6, 0x7e

    move-object/from16 v11, v35

    move-object/from16 v14, v36

    .line 139
    invoke-static {v11, v14, v12, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    move-result-object v6

    move/from16 p3, v7

    .line 140
    iget-wide v7, v12, Ll2/t;->T:J

    .line 141
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    move-result v7

    .line 142
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    move-result-object v8

    .line 143
    invoke-static {v12, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    move-result-object v2

    .line 144
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 145
    iget-boolean v13, v12, Ll2/t;->S:Z

    if-eqz v13, :cond_39

    .line 146
    invoke-virtual {v12, v15}, Ll2/t;->l(Lay0/a;)V

    goto :goto_2f

    .line 147
    :cond_39
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 148
    :goto_2f
    invoke-static {v9, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 149
    invoke-static {v4, v8, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 150
    iget-boolean v4, v12, Ll2/t;->S:Z

    if-nez v4, :cond_3a

    .line 151
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_3b

    .line 152
    :cond_3a
    invoke-static {v7, v12, v7, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 153
    :cond_3b
    invoke-static {v5, v2, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    const v2, -0x5dafb33

    .line 154
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    .line 155
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    if-nez v26, :cond_3c

    const v0, -0x5d8886b

    .line 156
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 157
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    move-object/from16 v16, v26

    goto :goto_30

    :cond_3c
    const v2, -0x5d8886a

    .line 158
    invoke-virtual {v12, v2}, Ll2/t;->Y(I)V

    move-object/from16 v2, v37

    .line 159
    invoke-virtual {v12, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    move-result-object v2

    .line 160
    check-cast v2, Lj91/f;

    .line 161
    invoke-virtual {v2}, Lj91/f;->i()Lg4/p0;

    move-result-object v17

    const/16 v27, 0x0

    const/16 v28, 0x1fc

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const-wide/16 v23, 0x0

    const/16 v25, 0x0

    move-object/from16 v16, v26

    move-object/from16 v26, v12

    .line 162
    invoke-static/range {v16 .. v28}, Lkp/x5;->a(Ljava/lang/String;Lg4/p0;Lx2/s;Lay0/k;IZIJLr4/k;Ll2/o;II)V

    .line 163
    invoke-static {v12}, Llp/q0;->f(Ll2/o;)Lh71/t;

    move-result-object v2

    .line 164
    iget v2, v2, Lh71/t;->f:F

    .line 165
    invoke-static {v0, v2, v12, v1}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    :goto_30
    if-nez p6, :cond_3d

    const v0, -0x5d47ea4

    .line 166
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 167
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    move-object/from16 v2, p6

    :goto_31
    const/4 v8, 0x1

    goto :goto_32

    :cond_3d
    const v0, -0x5d47ea3

    .line 168
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    shr-int/lit8 v0, v29, 0x15

    and-int/lit8 v0, v0, 0x70

    or-int v0, p3, v0

    .line 169
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    move-object/from16 v2, p6

    invoke-interface {v2, v3, v12, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 170
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    goto :goto_31

    .line 171
    :goto_32
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    .line 172
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    move-object/from16 v0, v34

    if-nez v0, :cond_3e

    const v3, 0x6b8ed446

    .line 173
    invoke-virtual {v12, v3}, Ll2/t;->Y(I)V

    .line 174
    :goto_33
    invoke-virtual {v12, v1}, Ll2/t;->q(Z)V

    const/4 v8, 0x1

    goto :goto_34

    :cond_3e
    const v4, 0x6b8ed447

    .line 175
    invoke-virtual {v12, v4}, Ll2/t;->Y(I)V

    shr-int/lit8 v4, v29, 0x18

    and-int/lit8 v4, v4, 0x70

    or-int v4, p3, v4

    .line 176
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-interface {v0, v3, v12, v4}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_33

    .line 177
    :goto_34
    invoke-virtual {v12, v8}, Ll2/t;->q(Z)V

    move-object v8, v0

    move-object v9, v11

    move-object v10, v14

    move-object/from16 v4, v16

    move/from16 v6, v30

    goto :goto_35

    :cond_3f
    move-object/from16 v2, p6

    move-object v12, v14

    .line 178
    invoke-virtual {v12}, Ll2/t;->R()V

    move/from16 v6, p5

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move-object/from16 v10, p9

    move-object v4, v7

    .line 179
    :goto_35
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    move-result-object v15

    if-eqz v15, :cond_40

    new-instance v0, Lc71/f;

    move-object/from16 v1, p0

    move/from16 v3, p2

    move/from16 v5, p4

    move-object/from16 v11, p10

    move/from16 v12, p12

    move/from16 v13, p13

    move/from16 v14, p14

    move-object v7, v2

    move-object/from16 v2, p1

    invoke-direct/range {v0 .. v14}, Lc71/f;-><init>(Lx2/s;Ljava/lang/String;ZLjava/lang/String;ZZLay0/o;Lay0/o;Lk1/i;Lx2/d;Lay0/a;III)V

    .line 180
    iput-object v0, v15, Ll2/u1;->d:Lay0/n;

    :cond_40
    return-void
.end method
