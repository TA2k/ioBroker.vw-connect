.class public abstract Lh2/n7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:Lc1/s;

.field public static final e:Lc1/s;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0xf0

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh2/n7;->a:F

    .line 5
    .line 6
    sget v0, Lk2/t;->a:F

    .line 7
    .line 8
    sget v0, Lk2/t;->a:F

    .line 9
    .line 10
    sput v0, Lh2/n7;->b:F

    .line 11
    .line 12
    sget v0, Lk2/i;->a:F

    .line 13
    .line 14
    sget v0, Lk2/i;->a:F

    .line 15
    .line 16
    sput v0, Lh2/n7;->c:F

    .line 17
    .line 18
    sget-object v0, Lk2/x;->a:Lc1/s;

    .line 19
    .line 20
    sget-object v0, Lk2/x;->a:Lc1/s;

    .line 21
    .line 22
    sput-object v0, Lh2/n7;->d:Lc1/s;

    .line 23
    .line 24
    sget-object v0, Lk2/x;->c:Lc1/s;

    .line 25
    .line 26
    sput-object v0, Lh2/n7;->e:Lc1/s;

    .line 27
    .line 28
    return-void
.end method

.method public static final a(Lx2/s;JFJIFLl2/o;II)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v12, p1

    .line 4
    .line 5
    move/from16 v6, p3

    .line 6
    .line 7
    move/from16 v0, p9

    .line 8
    .line 9
    move-object/from16 v2, p8

    .line 10
    .line 11
    check-cast v2, Ll2/t;

    .line 12
    .line 13
    const v3, 0x13db87c1

    .line 14
    .line 15
    .line 16
    invoke-virtual {v2, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v3, v0, 0x6

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    if-nez v3, :cond_1

    .line 23
    .line 24
    invoke-virtual {v2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    if-eqz v3, :cond_0

    .line 29
    .line 30
    const/4 v3, 0x4

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    move v3, v4

    .line 33
    :goto_0
    or-int/2addr v3, v0

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v3, v0

    .line 36
    :goto_1
    and-int/lit8 v5, v0, 0x30

    .line 37
    .line 38
    if-nez v5, :cond_3

    .line 39
    .line 40
    invoke-virtual {v2, v12, v13}, Ll2/t;->f(J)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_2

    .line 45
    .line 46
    const/16 v5, 0x20

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v5, 0x10

    .line 50
    .line 51
    :goto_2
    or-int/2addr v3, v5

    .line 52
    :cond_3
    and-int/lit16 v5, v0, 0x180

    .line 53
    .line 54
    if-nez v5, :cond_5

    .line 55
    .line 56
    invoke-virtual {v2, v6}, Ll2/t;->d(F)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_4

    .line 61
    .line 62
    const/16 v5, 0x100

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_4
    const/16 v5, 0x80

    .line 66
    .line 67
    :goto_3
    or-int/2addr v3, v5

    .line 68
    :cond_5
    and-int/lit16 v5, v0, 0xc00

    .line 69
    .line 70
    if-nez v5, :cond_7

    .line 71
    .line 72
    and-int/lit8 v5, p10, 0x8

    .line 73
    .line 74
    move-wide/from16 v14, p4

    .line 75
    .line 76
    if-nez v5, :cond_6

    .line 77
    .line 78
    invoke-virtual {v2, v14, v15}, Ll2/t;->f(J)Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    if-eqz v5, :cond_6

    .line 83
    .line 84
    const/16 v5, 0x800

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_6
    const/16 v5, 0x400

    .line 88
    .line 89
    :goto_4
    or-int/2addr v3, v5

    .line 90
    goto :goto_5

    .line 91
    :cond_7
    move-wide/from16 v14, p4

    .line 92
    .line 93
    :goto_5
    and-int/lit8 v5, p10, 0x10

    .line 94
    .line 95
    if-eqz v5, :cond_9

    .line 96
    .line 97
    or-int/lit16 v3, v3, 0x6000

    .line 98
    .line 99
    :cond_8
    move/from16 v8, p6

    .line 100
    .line 101
    goto :goto_7

    .line 102
    :cond_9
    and-int/lit16 v8, v0, 0x6000

    .line 103
    .line 104
    if-nez v8, :cond_8

    .line 105
    .line 106
    move/from16 v8, p6

    .line 107
    .line 108
    invoke-virtual {v2, v8}, Ll2/t;->e(I)Z

    .line 109
    .line 110
    .line 111
    move-result v16

    .line 112
    if-eqz v16, :cond_a

    .line 113
    .line 114
    const/16 v16, 0x4000

    .line 115
    .line 116
    goto :goto_6

    .line 117
    :cond_a
    const/16 v16, 0x2000

    .line 118
    .line 119
    :goto_6
    or-int v3, v3, v16

    .line 120
    .line 121
    :goto_7
    const/high16 v16, 0x30000

    .line 122
    .line 123
    or-int v3, v3, v16

    .line 124
    .line 125
    const v16, 0x12493

    .line 126
    .line 127
    .line 128
    and-int v10, v3, v16

    .line 129
    .line 130
    const v9, 0x12492

    .line 131
    .line 132
    .line 133
    const/4 v11, 0x0

    .line 134
    const/4 v7, 0x1

    .line 135
    if-eq v10, v9, :cond_b

    .line 136
    .line 137
    move v9, v7

    .line 138
    goto :goto_8

    .line 139
    :cond_b
    move v9, v11

    .line 140
    :goto_8
    and-int/lit8 v10, v3, 0x1

    .line 141
    .line 142
    invoke-virtual {v2, v10, v9}, Ll2/t;->O(IZ)Z

    .line 143
    .line 144
    .line 145
    move-result v9

    .line 146
    if-eqz v9, :cond_1c

    .line 147
    .line 148
    invoke-virtual {v2}, Ll2/t;->T()V

    .line 149
    .line 150
    .line 151
    and-int/lit8 v9, v0, 0x1

    .line 152
    .line 153
    if-eqz v9, :cond_e

    .line 154
    .line 155
    invoke-virtual {v2}, Ll2/t;->y()Z

    .line 156
    .line 157
    .line 158
    move-result v9

    .line 159
    if-eqz v9, :cond_c

    .line 160
    .line 161
    goto :goto_9

    .line 162
    :cond_c
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 163
    .line 164
    .line 165
    and-int/lit8 v5, p10, 0x8

    .line 166
    .line 167
    if-eqz v5, :cond_d

    .line 168
    .line 169
    and-int/lit16 v3, v3, -0x1c01

    .line 170
    .line 171
    :cond_d
    move/from16 v5, p7

    .line 172
    .line 173
    move/from16 v17, v8

    .line 174
    .line 175
    move-wide v9, v14

    .line 176
    goto :goto_c

    .line 177
    :cond_e
    :goto_9
    and-int/lit8 v9, p10, 0x8

    .line 178
    .line 179
    if-eqz v9, :cond_f

    .line 180
    .line 181
    sget v9, Lh2/f7;->a:I

    .line 182
    .line 183
    sget-wide v9, Le3/s;->h:J

    .line 184
    .line 185
    and-int/lit16 v3, v3, -0x1c01

    .line 186
    .line 187
    goto :goto_a

    .line 188
    :cond_f
    move-wide v9, v14

    .line 189
    :goto_a
    if-eqz v5, :cond_10

    .line 190
    .line 191
    sget v5, Lh2/f7;->c:I

    .line 192
    .line 193
    goto :goto_b

    .line 194
    :cond_10
    move v5, v8

    .line 195
    :goto_b
    sget v8, Lh2/f7;->e:F

    .line 196
    .line 197
    move/from16 v17, v5

    .line 198
    .line 199
    move v5, v8

    .line 200
    :goto_c
    invoke-virtual {v2}, Ll2/t;->r()V

    .line 201
    .line 202
    .line 203
    sget-object v8, Lw3/h1;->h:Ll2/u2;

    .line 204
    .line 205
    invoke-virtual {v2, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v8

    .line 209
    check-cast v8, Lt4/c;

    .line 210
    .line 211
    new-instance v14, Lg3/h;

    .line 212
    .line 213
    invoke-interface {v8, v6}, Lt4/c;->w0(F)F

    .line 214
    .line 215
    .line 216
    move-result v15

    .line 217
    const/16 v19, 0x0

    .line 218
    .line 219
    const/16 v20, 0x1a

    .line 220
    .line 221
    const/16 v16, 0x0

    .line 222
    .line 223
    const/16 v18, 0x0

    .line 224
    .line 225
    invoke-direct/range {v14 .. v20}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 226
    .line 227
    .line 228
    move/from16 v8, v17

    .line 229
    .line 230
    const/4 v15, 0x0

    .line 231
    move-object/from16 v16, v14

    .line 232
    .line 233
    invoke-static {v15, v2, v7}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 234
    .line 235
    .line 236
    move-result-object v14

    .line 237
    sget-object v7, Lc1/z;->d:Lc1/y;

    .line 238
    .line 239
    const/16 v15, 0x1770

    .line 240
    .line 241
    invoke-static {v15, v11, v7, v4}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 242
    .line 243
    .line 244
    move-result-object v4

    .line 245
    const/4 v7, 0x6

    .line 246
    const/4 v11, 0x0

    .line 247
    invoke-static {v4, v11, v7}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 248
    .line 249
    .line 250
    move-result-object v17

    .line 251
    const/16 v21, 0x8

    .line 252
    .line 253
    move v4, v15

    .line 254
    const/4 v15, 0x0

    .line 255
    move-object/from16 v18, v16

    .line 256
    .line 257
    const/high16 v16, 0x44870000    # 1080.0f

    .line 258
    .line 259
    move-object/from16 v19, v18

    .line 260
    .line 261
    const/16 v18, 0x0

    .line 262
    .line 263
    const/16 v20, 0x11b8

    .line 264
    .line 265
    move-object/from16 v23, v19

    .line 266
    .line 267
    move-object/from16 v19, v2

    .line 268
    .line 269
    move-object v2, v11

    .line 270
    move-object/from16 v11, v23

    .line 271
    .line 272
    invoke-static/range {v14 .. v21}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 273
    .line 274
    .line 275
    move-result-object v15

    .line 276
    new-instance v4, Lh10/d;

    .line 277
    .line 278
    const/16 v2, 0x10

    .line 279
    .line 280
    invoke-direct {v4, v2}, Lh10/d;-><init>(I)V

    .line 281
    .line 282
    .line 283
    new-instance v2, Lc1/m0;

    .line 284
    .line 285
    new-instance v7, Lc1/l0;

    .line 286
    .line 287
    invoke-direct {v7}, Lc1/l0;-><init>()V

    .line 288
    .line 289
    .line 290
    invoke-virtual {v4, v7}, Lh10/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    invoke-direct {v2, v7}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 294
    .line 295
    .line 296
    const/4 v4, 0x0

    .line 297
    const/4 v7, 0x6

    .line 298
    invoke-static {v2, v4, v7}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 299
    .line 300
    .line 301
    move-result-object v17

    .line 302
    move-object v7, v15

    .line 303
    const/4 v15, 0x0

    .line 304
    const/high16 v16, 0x43b40000    # 360.0f

    .line 305
    .line 306
    invoke-static/range {v14 .. v21}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 307
    .line 308
    .line 309
    move-result-object v2

    .line 310
    new-instance v4, Lc1/m0;

    .line 311
    .line 312
    new-instance v15, Lc1/l0;

    .line 313
    .line 314
    invoke-direct {v15}, Lc1/l0;-><init>()V

    .line 315
    .line 316
    .line 317
    const/16 v0, 0x1770

    .line 318
    .line 319
    iput v0, v15, Lc1/l0;->a:I

    .line 320
    .line 321
    const v16, 0x3f5eb852    # 0.87f

    .line 322
    .line 323
    .line 324
    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 325
    .line 326
    .line 327
    move-result-object v0

    .line 328
    move/from16 p7, v5

    .line 329
    .line 330
    const/16 v5, 0xbb8

    .line 331
    .line 332
    invoke-virtual {v15, v5, v0}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    sget-object v5, Lh2/n7;->e:Lc1/s;

    .line 337
    .line 338
    iput-object v5, v0, Lc1/k0;->b:Lc1/w;

    .line 339
    .line 340
    const v0, 0x3dcccccd    # 0.1f

    .line 341
    .line 342
    .line 343
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 344
    .line 345
    .line 346
    move-result-object v0

    .line 347
    const/16 v5, 0x1770

    .line 348
    .line 349
    invoke-virtual {v15, v5, v0}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 350
    .line 351
    .line 352
    invoke-direct {v4, v15}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 353
    .line 354
    .line 355
    const/4 v0, 0x0

    .line 356
    const/4 v5, 0x6

    .line 357
    invoke-static {v4, v0, v5}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 358
    .line 359
    .line 360
    move-result-object v17

    .line 361
    const v15, 0x3dcccccd    # 0.1f

    .line 362
    .line 363
    .line 364
    invoke-static/range {v14 .. v21}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    move-object/from16 v14, v19

    .line 369
    .line 370
    new-instance v4, Ldj/a;

    .line 371
    .line 372
    const/16 v5, 0x11

    .line 373
    .line 374
    invoke-direct {v4, v5}, Ldj/a;-><init>(I)V

    .line 375
    .line 376
    .line 377
    const/4 v5, 0x1

    .line 378
    invoke-static {v1, v5, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 379
    .line 380
    .line 381
    move-result-object v4

    .line 382
    sget v15, Lh2/n7;->c:F

    .line 383
    .line 384
    invoke-static {v4, v15}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 385
    .line 386
    .line 387
    move-result-object v15

    .line 388
    invoke-virtual {v14, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 389
    .line 390
    .line 391
    move-result v4

    .line 392
    const v16, 0xe000

    .line 393
    .line 394
    .line 395
    and-int v5, v3, v16

    .line 396
    .line 397
    move-object/from16 p4, v0

    .line 398
    .line 399
    const/16 v0, 0x4000

    .line 400
    .line 401
    if-ne v5, v0, :cond_11

    .line 402
    .line 403
    const/4 v0, 0x1

    .line 404
    goto :goto_d

    .line 405
    :cond_11
    const/4 v0, 0x0

    .line 406
    :goto_d
    or-int/2addr v0, v4

    .line 407
    const/high16 v4, 0x70000

    .line 408
    .line 409
    and-int/2addr v4, v3

    .line 410
    const/high16 v5, 0x20000

    .line 411
    .line 412
    if-ne v4, v5, :cond_12

    .line 413
    .line 414
    const/4 v4, 0x1

    .line 415
    goto :goto_e

    .line 416
    :cond_12
    const/4 v4, 0x0

    .line 417
    :goto_e
    or-int/2addr v0, v4

    .line 418
    and-int/lit16 v4, v3, 0x380

    .line 419
    .line 420
    const/16 v5, 0x100

    .line 421
    .line 422
    if-ne v4, v5, :cond_13

    .line 423
    .line 424
    const/4 v4, 0x1

    .line 425
    goto :goto_f

    .line 426
    :cond_13
    const/4 v4, 0x0

    .line 427
    :goto_f
    or-int/2addr v0, v4

    .line 428
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 429
    .line 430
    .line 431
    move-result v4

    .line 432
    or-int/2addr v0, v4

    .line 433
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 434
    .line 435
    .line 436
    move-result v4

    .line 437
    or-int/2addr v0, v4

    .line 438
    and-int/lit16 v4, v3, 0x1c00

    .line 439
    .line 440
    xor-int/lit16 v4, v4, 0xc00

    .line 441
    .line 442
    const/16 v5, 0x800

    .line 443
    .line 444
    if-le v4, v5, :cond_14

    .line 445
    .line 446
    invoke-virtual {v14, v9, v10}, Ll2/t;->f(J)Z

    .line 447
    .line 448
    .line 449
    move-result v4

    .line 450
    if-nez v4, :cond_15

    .line 451
    .line 452
    :cond_14
    and-int/lit16 v4, v3, 0xc00

    .line 453
    .line 454
    if-ne v4, v5, :cond_16

    .line 455
    .line 456
    :cond_15
    const/4 v4, 0x1

    .line 457
    goto :goto_10

    .line 458
    :cond_16
    const/4 v4, 0x0

    .line 459
    :goto_10
    or-int/2addr v0, v4

    .line 460
    invoke-virtual {v14, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    move-result v4

    .line 464
    or-int/2addr v0, v4

    .line 465
    and-int/lit8 v4, v3, 0x70

    .line 466
    .line 467
    xor-int/lit8 v4, v4, 0x30

    .line 468
    .line 469
    const/16 v5, 0x20

    .line 470
    .line 471
    if-le v4, v5, :cond_17

    .line 472
    .line 473
    invoke-virtual {v14, v12, v13}, Ll2/t;->f(J)Z

    .line 474
    .line 475
    .line 476
    move-result v4

    .line 477
    if-nez v4, :cond_18

    .line 478
    .line 479
    :cond_17
    and-int/lit8 v3, v3, 0x30

    .line 480
    .line 481
    if-ne v3, v5, :cond_19

    .line 482
    .line 483
    :cond_18
    const/16 v22, 0x1

    .line 484
    .line 485
    goto :goto_11

    .line 486
    :cond_19
    const/16 v22, 0x0

    .line 487
    .line 488
    :goto_11
    or-int v0, v0, v22

    .line 489
    .line 490
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v3

    .line 494
    if-nez v0, :cond_1a

    .line 495
    .line 496
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 497
    .line 498
    if-ne v3, v0, :cond_1b

    .line 499
    .line 500
    :cond_1a
    move/from16 v17, v8

    .line 501
    .line 502
    move-object v8, v2

    .line 503
    goto :goto_12

    .line 504
    :cond_1b
    move/from16 v5, p7

    .line 505
    .line 506
    move/from16 v17, v8

    .line 507
    .line 508
    const/4 v0, 0x0

    .line 509
    goto :goto_13

    .line 510
    :goto_12
    new-instance v2, Lh2/i7;

    .line 511
    .line 512
    move-object/from16 v3, p4

    .line 513
    .line 514
    move/from16 v5, p7

    .line 515
    .line 516
    move/from16 v4, v17

    .line 517
    .line 518
    const/4 v0, 0x0

    .line 519
    invoke-direct/range {v2 .. v13}, Lh2/i7;-><init>(Lc1/g0;IFFLc1/g0;Lc1/g0;JLg3/h;J)V

    .line 520
    .line 521
    .line 522
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 523
    .line 524
    .line 525
    move-object v3, v2

    .line 526
    :goto_13
    check-cast v3, Lay0/k;

    .line 527
    .line 528
    invoke-static {v15, v3, v14, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 529
    .line 530
    .line 531
    move v8, v5

    .line 532
    move-wide v5, v9

    .line 533
    move-object/from16 v19, v14

    .line 534
    .line 535
    move/from16 v7, v17

    .line 536
    .line 537
    goto :goto_14

    .line 538
    :cond_1c
    move-object/from16 v19, v2

    .line 539
    .line 540
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 541
    .line 542
    .line 543
    move v7, v8

    .line 544
    move-wide v5, v14

    .line 545
    move/from16 v8, p7

    .line 546
    .line 547
    :goto_14
    invoke-virtual/range {v19 .. v19}, Ll2/t;->s()Ll2/u1;

    .line 548
    .line 549
    .line 550
    move-result-object v11

    .line 551
    if-eqz v11, :cond_1d

    .line 552
    .line 553
    new-instance v0, Lh2/j7;

    .line 554
    .line 555
    move-wide/from16 v2, p1

    .line 556
    .line 557
    move/from16 v4, p3

    .line 558
    .line 559
    move/from16 v9, p9

    .line 560
    .line 561
    move/from16 v10, p10

    .line 562
    .line 563
    invoke-direct/range {v0 .. v10}, Lh2/j7;-><init>(Lx2/s;JFJIFII)V

    .line 564
    .line 565
    .line 566
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 567
    .line 568
    :cond_1d
    return-void
.end method

.method public static final b(Lay0/a;Lx2/s;JFJIFLl2/o;II)V
    .locals 29

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-wide/from16 v11, p2

    .line 6
    .line 7
    move/from16 v5, p4

    .line 8
    .line 9
    move-wide/from16 v6, p5

    .line 10
    .line 11
    move/from16 v0, p10

    .line 12
    .line 13
    move-object/from16 v13, p9

    .line 14
    .line 15
    check-cast v13, Ll2/t;

    .line 16
    .line 17
    const v3, -0x6b38c90b

    .line 18
    .line 19
    .line 20
    invoke-virtual {v13, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v3, v0, 0x6

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    invoke-virtual {v13, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    const/4 v3, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    const/4 v3, 0x2

    .line 36
    :goto_0
    or-int/2addr v3, v0

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v3, v0

    .line 39
    :goto_1
    and-int/lit8 v8, v0, 0x30

    .line 40
    .line 41
    if-nez v8, :cond_3

    .line 42
    .line 43
    invoke-virtual {v13, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v8

    .line 47
    if-eqz v8, :cond_2

    .line 48
    .line 49
    const/16 v8, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v8, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v3, v8

    .line 55
    :cond_3
    and-int/lit16 v8, v0, 0x180

    .line 56
    .line 57
    if-nez v8, :cond_5

    .line 58
    .line 59
    invoke-virtual {v13, v11, v12}, Ll2/t;->f(J)Z

    .line 60
    .line 61
    .line 62
    move-result v8

    .line 63
    if-eqz v8, :cond_4

    .line 64
    .line 65
    const/16 v8, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    const/16 v8, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v3, v8

    .line 71
    :cond_5
    and-int/lit16 v8, v0, 0xc00

    .line 72
    .line 73
    if-nez v8, :cond_7

    .line 74
    .line 75
    invoke-virtual {v13, v5}, Ll2/t;->d(F)Z

    .line 76
    .line 77
    .line 78
    move-result v8

    .line 79
    if-eqz v8, :cond_6

    .line 80
    .line 81
    const/16 v8, 0x800

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_6
    const/16 v8, 0x400

    .line 85
    .line 86
    :goto_4
    or-int/2addr v3, v8

    .line 87
    :cond_7
    and-int/lit16 v8, v0, 0x6000

    .line 88
    .line 89
    if-nez v8, :cond_9

    .line 90
    .line 91
    invoke-virtual {v13, v6, v7}, Ll2/t;->f(J)Z

    .line 92
    .line 93
    .line 94
    move-result v8

    .line 95
    if-eqz v8, :cond_8

    .line 96
    .line 97
    const/16 v8, 0x4000

    .line 98
    .line 99
    goto :goto_5

    .line 100
    :cond_8
    const/16 v8, 0x2000

    .line 101
    .line 102
    :goto_5
    or-int/2addr v3, v8

    .line 103
    :cond_9
    and-int/lit8 v8, p11, 0x20

    .line 104
    .line 105
    const/high16 v16, 0x30000

    .line 106
    .line 107
    if-eqz v8, :cond_a

    .line 108
    .line 109
    or-int v3, v3, v16

    .line 110
    .line 111
    move/from16 v9, p7

    .line 112
    .line 113
    goto :goto_7

    .line 114
    :cond_a
    and-int v16, v0, v16

    .line 115
    .line 116
    move/from16 v9, p7

    .line 117
    .line 118
    if-nez v16, :cond_c

    .line 119
    .line 120
    invoke-virtual {v13, v9}, Ll2/t;->e(I)Z

    .line 121
    .line 122
    .line 123
    move-result v16

    .line 124
    if-eqz v16, :cond_b

    .line 125
    .line 126
    const/high16 v16, 0x20000

    .line 127
    .line 128
    goto :goto_6

    .line 129
    :cond_b
    const/high16 v16, 0x10000

    .line 130
    .line 131
    :goto_6
    or-int v3, v3, v16

    .line 132
    .line 133
    :cond_c
    :goto_7
    and-int/lit8 v16, p11, 0x40

    .line 134
    .line 135
    const/high16 v17, 0x180000

    .line 136
    .line 137
    if-eqz v16, :cond_d

    .line 138
    .line 139
    or-int v3, v3, v17

    .line 140
    .line 141
    move/from16 v10, p8

    .line 142
    .line 143
    goto :goto_9

    .line 144
    :cond_d
    and-int v17, v0, v17

    .line 145
    .line 146
    move/from16 v10, p8

    .line 147
    .line 148
    if-nez v17, :cond_f

    .line 149
    .line 150
    invoke-virtual {v13, v10}, Ll2/t;->d(F)Z

    .line 151
    .line 152
    .line 153
    move-result v18

    .line 154
    if-eqz v18, :cond_e

    .line 155
    .line 156
    const/high16 v18, 0x100000

    .line 157
    .line 158
    goto :goto_8

    .line 159
    :cond_e
    const/high16 v18, 0x80000

    .line 160
    .line 161
    :goto_8
    or-int v3, v3, v18

    .line 162
    .line 163
    :cond_f
    :goto_9
    const v18, 0x92493

    .line 164
    .line 165
    .line 166
    and-int v14, v3, v18

    .line 167
    .line 168
    const v15, 0x92492

    .line 169
    .line 170
    .line 171
    if-eq v14, v15, :cond_10

    .line 172
    .line 173
    const/4 v14, 0x1

    .line 174
    goto :goto_a

    .line 175
    :cond_10
    const/4 v14, 0x0

    .line 176
    :goto_a
    and-int/lit8 v15, v3, 0x1

    .line 177
    .line 178
    invoke-virtual {v13, v15, v14}, Ll2/t;->O(IZ)Z

    .line 179
    .line 180
    .line 181
    move-result v14

    .line 182
    if-eqz v14, :cond_25

    .line 183
    .line 184
    invoke-virtual {v13}, Ll2/t;->T()V

    .line 185
    .line 186
    .line 187
    and-int/lit8 v14, v0, 0x1

    .line 188
    .line 189
    if-eqz v14, :cond_12

    .line 190
    .line 191
    invoke-virtual {v13}, Ll2/t;->y()Z

    .line 192
    .line 193
    .line 194
    move-result v14

    .line 195
    if-eqz v14, :cond_11

    .line 196
    .line 197
    goto :goto_b

    .line 198
    :cond_11
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 199
    .line 200
    .line 201
    move/from16 v23, v9

    .line 202
    .line 203
    goto :goto_d

    .line 204
    :cond_12
    :goto_b
    if-eqz v8, :cond_13

    .line 205
    .line 206
    sget v8, Lh2/f7;->b:I

    .line 207
    .line 208
    goto :goto_c

    .line 209
    :cond_13
    move v8, v9

    .line 210
    :goto_c
    if-eqz v16, :cond_14

    .line 211
    .line 212
    sget v9, Lh2/f7;->e:F

    .line 213
    .line 214
    move/from16 v23, v8

    .line 215
    .line 216
    move v10, v9

    .line 217
    goto :goto_d

    .line 218
    :cond_14
    move/from16 v23, v8

    .line 219
    .line 220
    :goto_d
    invoke-virtual {v13}, Ll2/t;->r()V

    .line 221
    .line 222
    .line 223
    and-int/lit8 v8, v3, 0xe

    .line 224
    .line 225
    const/4 v9, 0x4

    .line 226
    if-ne v8, v9, :cond_15

    .line 227
    .line 228
    const/4 v8, 0x1

    .line 229
    goto :goto_e

    .line 230
    :cond_15
    const/4 v8, 0x0

    .line 231
    :goto_e
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v9

    .line 235
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 236
    .line 237
    if-nez v8, :cond_16

    .line 238
    .line 239
    if-ne v9, v14, :cond_17

    .line 240
    .line 241
    :cond_16
    new-instance v9, Lb71/i;

    .line 242
    .line 243
    const/16 v8, 0x1a

    .line 244
    .line 245
    invoke-direct {v9, v1, v8}, Lb71/i;-><init>(Lay0/a;I)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v13, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    :cond_17
    check-cast v9, Lay0/a;

    .line 252
    .line 253
    sget-object v8, Lw3/h1;->h:Ll2/u2;

    .line 254
    .line 255
    invoke-virtual {v13, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v8

    .line 259
    check-cast v8, Lt4/c;

    .line 260
    .line 261
    new-instance v20, Lg3/h;

    .line 262
    .line 263
    invoke-interface {v8, v5}, Lt4/c;->w0(F)F

    .line 264
    .line 265
    .line 266
    move-result v21

    .line 267
    const/16 v25, 0x0

    .line 268
    .line 269
    const/16 v26, 0x1a

    .line 270
    .line 271
    const/16 v22, 0x0

    .line 272
    .line 273
    const/16 v24, 0x0

    .line 274
    .line 275
    invoke-direct/range {v20 .. v26}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 276
    .line 277
    .line 278
    move v8, v10

    .line 279
    move-object/from16 v10, v20

    .line 280
    .line 281
    invoke-virtual {v13, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v15

    .line 285
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v4

    .line 289
    if-nez v15, :cond_18

    .line 290
    .line 291
    if-ne v4, v14, :cond_19

    .line 292
    .line 293
    :cond_18
    new-instance v4, Laj0/c;

    .line 294
    .line 295
    const/16 v15, 0x1d

    .line 296
    .line 297
    invoke-direct {v4, v9, v15}, Laj0/c;-><init>(Lay0/a;I)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v13, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    :cond_19
    check-cast v4, Lay0/k;

    .line 304
    .line 305
    const/4 v15, 0x1

    .line 306
    invoke-static {v2, v15, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 307
    .line 308
    .line 309
    move-result-object v4

    .line 310
    sget v15, Lh2/n7;->c:F

    .line 311
    .line 312
    invoke-static {v4, v15}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 313
    .line 314
    .line 315
    move-result-object v15

    .line 316
    invoke-virtual {v13, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    move-result v4

    .line 320
    const/high16 v19, 0x70000

    .line 321
    .line 322
    and-int v0, v3, v19

    .line 323
    .line 324
    const/high16 v1, 0x20000

    .line 325
    .line 326
    if-ne v0, v1, :cond_1a

    .line 327
    .line 328
    const/4 v0, 0x1

    .line 329
    goto :goto_f

    .line 330
    :cond_1a
    const/4 v0, 0x0

    .line 331
    :goto_f
    or-int/2addr v0, v4

    .line 332
    const/high16 v1, 0x380000

    .line 333
    .line 334
    and-int/2addr v1, v3

    .line 335
    const/high16 v4, 0x100000

    .line 336
    .line 337
    if-ne v1, v4, :cond_1b

    .line 338
    .line 339
    const/4 v1, 0x1

    .line 340
    goto :goto_10

    .line 341
    :cond_1b
    const/4 v1, 0x0

    .line 342
    :goto_10
    or-int/2addr v0, v1

    .line 343
    and-int/lit16 v1, v3, 0x1c00

    .line 344
    .line 345
    const/16 v4, 0x800

    .line 346
    .line 347
    if-ne v1, v4, :cond_1c

    .line 348
    .line 349
    const/4 v1, 0x1

    .line 350
    goto :goto_11

    .line 351
    :cond_1c
    const/4 v1, 0x0

    .line 352
    :goto_11
    or-int/2addr v0, v1

    .line 353
    const v1, 0xe000

    .line 354
    .line 355
    .line 356
    and-int/2addr v1, v3

    .line 357
    xor-int/lit16 v1, v1, 0x6000

    .line 358
    .line 359
    const/16 v4, 0x4000

    .line 360
    .line 361
    if-le v1, v4, :cond_1d

    .line 362
    .line 363
    invoke-virtual {v13, v6, v7}, Ll2/t;->f(J)Z

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    if-nez v1, :cond_1e

    .line 368
    .line 369
    :cond_1d
    and-int/lit16 v1, v3, 0x6000

    .line 370
    .line 371
    if-ne v1, v4, :cond_1f

    .line 372
    .line 373
    :cond_1e
    const/4 v1, 0x1

    .line 374
    goto :goto_12

    .line 375
    :cond_1f
    const/4 v1, 0x0

    .line 376
    :goto_12
    or-int/2addr v0, v1

    .line 377
    invoke-virtual {v13, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 378
    .line 379
    .line 380
    move-result v1

    .line 381
    or-int/2addr v0, v1

    .line 382
    and-int/lit16 v1, v3, 0x380

    .line 383
    .line 384
    xor-int/lit16 v1, v1, 0x180

    .line 385
    .line 386
    const/16 v4, 0x100

    .line 387
    .line 388
    if-le v1, v4, :cond_20

    .line 389
    .line 390
    invoke-virtual {v13, v11, v12}, Ll2/t;->f(J)Z

    .line 391
    .line 392
    .line 393
    move-result v1

    .line 394
    if-nez v1, :cond_21

    .line 395
    .line 396
    :cond_20
    and-int/lit16 v1, v3, 0x180

    .line 397
    .line 398
    if-ne v1, v4, :cond_22

    .line 399
    .line 400
    :cond_21
    const/4 v4, 0x1

    .line 401
    goto :goto_13

    .line 402
    :cond_22
    const/4 v4, 0x0

    .line 403
    :goto_13
    or-int/2addr v0, v4

    .line 404
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    if-nez v0, :cond_24

    .line 409
    .line 410
    if-ne v1, v14, :cond_23

    .line 411
    .line 412
    goto :goto_14

    .line 413
    :cond_23
    move v6, v8

    .line 414
    const/4 v0, 0x0

    .line 415
    goto :goto_15

    .line 416
    :cond_24
    :goto_14
    new-instance v3, Lh2/m7;

    .line 417
    .line 418
    move-object v4, v9

    .line 419
    const/4 v0, 0x0

    .line 420
    move-wide/from16 v27, v6

    .line 421
    .line 422
    move v7, v5

    .line 423
    move v6, v8

    .line 424
    move/from16 v5, v23

    .line 425
    .line 426
    move-wide/from16 v8, v27

    .line 427
    .line 428
    invoke-direct/range {v3 .. v12}, Lh2/m7;-><init>(Lay0/a;IFFJLg3/h;J)V

    .line 429
    .line 430
    .line 431
    invoke-virtual {v13, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 432
    .line 433
    .line 434
    move-object v1, v3

    .line 435
    :goto_15
    check-cast v1, Lay0/k;

    .line 436
    .line 437
    invoke-static {v15, v1, v13, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 438
    .line 439
    .line 440
    move v9, v6

    .line 441
    move/from16 v8, v23

    .line 442
    .line 443
    goto :goto_16

    .line 444
    :cond_25
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 445
    .line 446
    .line 447
    move v8, v9

    .line 448
    move v9, v10

    .line 449
    :goto_16
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 450
    .line 451
    .line 452
    move-result-object v12

    .line 453
    if-eqz v12, :cond_26

    .line 454
    .line 455
    new-instance v0, Lh2/h7;

    .line 456
    .line 457
    move-object/from16 v1, p0

    .line 458
    .line 459
    move-wide/from16 v3, p2

    .line 460
    .line 461
    move/from16 v5, p4

    .line 462
    .line 463
    move-wide/from16 v6, p5

    .line 464
    .line 465
    move/from16 v10, p10

    .line 466
    .line 467
    move/from16 v11, p11

    .line 468
    .line 469
    invoke-direct/range {v0 .. v11}, Lh2/h7;-><init>(Lay0/a;Lx2/s;JFJIFII)V

    .line 470
    .line 471
    .line 472
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 473
    .line 474
    :cond_26
    return-void
.end method

.method public static final c(Lay0/a;Lx2/s;JJIFLay0/k;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-wide/from16 v9, p2

    .line 6
    .line 7
    move-wide/from16 v5, p4

    .line 8
    .line 9
    move-object/from16 v11, p8

    .line 10
    .line 11
    move/from16 v0, p10

    .line 12
    .line 13
    move-object/from16 v12, p9

    .line 14
    .line 15
    check-cast v12, Ll2/t;

    .line 16
    .line 17
    const v3, -0x144387f6

    .line 18
    .line 19
    .line 20
    invoke-virtual {v12, v3}, Ll2/t;->a0(I)Ll2/t;

    .line 21
    .line 22
    .line 23
    and-int/lit8 v3, v0, 0x6

    .line 24
    .line 25
    const/4 v4, 0x4

    .line 26
    if-nez v3, :cond_1

    .line 27
    .line 28
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v3, 0x2

    .line 37
    :goto_0
    or-int/2addr v3, v0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v3, v0

    .line 40
    :goto_1
    and-int/lit8 v7, v0, 0x30

    .line 41
    .line 42
    if-nez v7, :cond_3

    .line 43
    .line 44
    invoke-virtual {v12, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v7

    .line 48
    if-eqz v7, :cond_2

    .line 49
    .line 50
    const/16 v7, 0x20

    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    const/16 v7, 0x10

    .line 54
    .line 55
    :goto_2
    or-int/2addr v3, v7

    .line 56
    :cond_3
    and-int/lit16 v7, v0, 0x180

    .line 57
    .line 58
    if-nez v7, :cond_5

    .line 59
    .line 60
    invoke-virtual {v12, v9, v10}, Ll2/t;->f(J)Z

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    if-eqz v7, :cond_4

    .line 65
    .line 66
    const/16 v7, 0x100

    .line 67
    .line 68
    goto :goto_3

    .line 69
    :cond_4
    const/16 v7, 0x80

    .line 70
    .line 71
    :goto_3
    or-int/2addr v3, v7

    .line 72
    :cond_5
    and-int/lit16 v7, v0, 0xc00

    .line 73
    .line 74
    if-nez v7, :cond_7

    .line 75
    .line 76
    invoke-virtual {v12, v5, v6}, Ll2/t;->f(J)Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-eqz v7, :cond_6

    .line 81
    .line 82
    const/16 v7, 0x800

    .line 83
    .line 84
    goto :goto_4

    .line 85
    :cond_6
    const/16 v7, 0x400

    .line 86
    .line 87
    :goto_4
    or-int/2addr v3, v7

    .line 88
    :cond_7
    and-int/lit16 v7, v0, 0x6000

    .line 89
    .line 90
    if-nez v7, :cond_9

    .line 91
    .line 92
    move/from16 v7, p6

    .line 93
    .line 94
    invoke-virtual {v12, v7}, Ll2/t;->e(I)Z

    .line 95
    .line 96
    .line 97
    move-result v15

    .line 98
    if-eqz v15, :cond_8

    .line 99
    .line 100
    const/16 v15, 0x4000

    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_8
    const/16 v15, 0x2000

    .line 104
    .line 105
    :goto_5
    or-int/2addr v3, v15

    .line 106
    goto :goto_6

    .line 107
    :cond_9
    move/from16 v7, p6

    .line 108
    .line 109
    :goto_6
    const/high16 v15, 0x30000

    .line 110
    .line 111
    and-int/2addr v15, v0

    .line 112
    if-nez v15, :cond_b

    .line 113
    .line 114
    move/from16 v15, p7

    .line 115
    .line 116
    invoke-virtual {v12, v15}, Ll2/t;->d(F)Z

    .line 117
    .line 118
    .line 119
    move-result v16

    .line 120
    if-eqz v16, :cond_a

    .line 121
    .line 122
    const/high16 v16, 0x20000

    .line 123
    .line 124
    goto :goto_7

    .line 125
    :cond_a
    const/high16 v16, 0x10000

    .line 126
    .line 127
    :goto_7
    or-int v3, v3, v16

    .line 128
    .line 129
    goto :goto_8

    .line 130
    :cond_b
    move/from16 v15, p7

    .line 131
    .line 132
    :goto_8
    const/high16 v16, 0x180000

    .line 133
    .line 134
    and-int v17, v0, v16

    .line 135
    .line 136
    if-nez v17, :cond_d

    .line 137
    .line 138
    invoke-virtual {v12, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v17

    .line 142
    if-eqz v17, :cond_c

    .line 143
    .line 144
    const/high16 v17, 0x100000

    .line 145
    .line 146
    goto :goto_9

    .line 147
    :cond_c
    const/high16 v17, 0x80000

    .line 148
    .line 149
    :goto_9
    or-int v3, v3, v17

    .line 150
    .line 151
    :cond_d
    const v17, 0x92493

    .line 152
    .line 153
    .line 154
    and-int v13, v3, v17

    .line 155
    .line 156
    const v8, 0x92492

    .line 157
    .line 158
    .line 159
    if-eq v13, v8, :cond_e

    .line 160
    .line 161
    const/4 v8, 0x1

    .line 162
    goto :goto_a

    .line 163
    :cond_e
    const/4 v8, 0x0

    .line 164
    :goto_a
    and-int/lit8 v13, v3, 0x1

    .line 165
    .line 166
    invoke-virtual {v12, v13, v8}, Ll2/t;->O(IZ)Z

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    if-eqz v8, :cond_23

    .line 171
    .line 172
    invoke-virtual {v12}, Ll2/t;->T()V

    .line 173
    .line 174
    .line 175
    and-int/lit8 v8, v0, 0x1

    .line 176
    .line 177
    if-eqz v8, :cond_10

    .line 178
    .line 179
    invoke-virtual {v12}, Ll2/t;->y()Z

    .line 180
    .line 181
    .line 182
    move-result v8

    .line 183
    if-eqz v8, :cond_f

    .line 184
    .line 185
    goto :goto_b

    .line 186
    :cond_f
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 187
    .line 188
    .line 189
    :cond_10
    :goto_b
    invoke-virtual {v12}, Ll2/t;->r()V

    .line 190
    .line 191
    .line 192
    and-int/lit8 v8, v3, 0xe

    .line 193
    .line 194
    if-ne v8, v4, :cond_11

    .line 195
    .line 196
    const/4 v4, 0x1

    .line 197
    goto :goto_c

    .line 198
    :cond_11
    const/4 v4, 0x0

    .line 199
    :goto_c
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v8

    .line 203
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 204
    .line 205
    if-nez v4, :cond_12

    .line 206
    .line 207
    if-ne v8, v13, :cond_13

    .line 208
    .line 209
    :cond_12
    new-instance v8, Lb71/i;

    .line 210
    .line 211
    const/16 v4, 0x19

    .line 212
    .line 213
    invoke-direct {v8, v1, v4}, Lb71/i;-><init>(Lay0/a;I)V

    .line 214
    .line 215
    .line 216
    invoke-virtual {v12, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    :cond_13
    check-cast v8, Lay0/a;

    .line 220
    .line 221
    sget-object v4, Li2/b;->d:Lx2/s;

    .line 222
    .line 223
    invoke-interface {v2, v4}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    invoke-virtual {v12, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    move-result v18

    .line 231
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v14

    .line 235
    if-nez v18, :cond_14

    .line 236
    .line 237
    if-ne v14, v13, :cond_15

    .line 238
    .line 239
    :cond_14
    new-instance v14, Laj0/c;

    .line 240
    .line 241
    const/16 v0, 0x1c

    .line 242
    .line 243
    invoke-direct {v14, v8, v0}, Laj0/c;-><init>(Lay0/a;I)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v12, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    :cond_15
    check-cast v14, Lay0/k;

    .line 250
    .line 251
    const/4 v0, 0x1

    .line 252
    invoke-static {v4, v0, v14}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    sget v14, Lh2/n7;->a:F

    .line 257
    .line 258
    sget v0, Lh2/n7;->b:F

    .line 259
    .line 260
    invoke-static {v4, v14, v0}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 261
    .line 262
    .line 263
    move-result-object v0

    .line 264
    const v4, 0xe000

    .line 265
    .line 266
    .line 267
    and-int/2addr v4, v3

    .line 268
    const/16 v14, 0x4000

    .line 269
    .line 270
    if-ne v4, v14, :cond_16

    .line 271
    .line 272
    const/4 v4, 0x1

    .line 273
    goto :goto_d

    .line 274
    :cond_16
    const/4 v4, 0x0

    .line 275
    :goto_d
    const/high16 v14, 0x70000

    .line 276
    .line 277
    and-int/2addr v14, v3

    .line 278
    const/high16 v1, 0x20000

    .line 279
    .line 280
    if-ne v14, v1, :cond_17

    .line 281
    .line 282
    const/4 v1, 0x1

    .line 283
    goto :goto_e

    .line 284
    :cond_17
    const/4 v1, 0x0

    .line 285
    :goto_e
    or-int/2addr v1, v4

    .line 286
    invoke-virtual {v12, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v4

    .line 290
    or-int/2addr v1, v4

    .line 291
    and-int/lit16 v4, v3, 0x1c00

    .line 292
    .line 293
    xor-int/lit16 v4, v4, 0xc00

    .line 294
    .line 295
    const/16 v14, 0x800

    .line 296
    .line 297
    if-le v4, v14, :cond_18

    .line 298
    .line 299
    invoke-virtual {v12, v5, v6}, Ll2/t;->f(J)Z

    .line 300
    .line 301
    .line 302
    move-result v4

    .line 303
    if-nez v4, :cond_19

    .line 304
    .line 305
    :cond_18
    and-int/lit16 v4, v3, 0xc00

    .line 306
    .line 307
    if-ne v4, v14, :cond_1a

    .line 308
    .line 309
    :cond_19
    const/4 v4, 0x1

    .line 310
    goto :goto_f

    .line 311
    :cond_1a
    const/4 v4, 0x0

    .line 312
    :goto_f
    or-int/2addr v1, v4

    .line 313
    and-int/lit16 v4, v3, 0x380

    .line 314
    .line 315
    xor-int/lit16 v4, v4, 0x180

    .line 316
    .line 317
    const/16 v14, 0x100

    .line 318
    .line 319
    if-le v4, v14, :cond_1b

    .line 320
    .line 321
    invoke-virtual {v12, v9, v10}, Ll2/t;->f(J)Z

    .line 322
    .line 323
    .line 324
    move-result v4

    .line 325
    if-nez v4, :cond_1c

    .line 326
    .line 327
    :cond_1b
    and-int/lit16 v4, v3, 0x180

    .line 328
    .line 329
    if-ne v4, v14, :cond_1d

    .line 330
    .line 331
    :cond_1c
    const/4 v4, 0x1

    .line 332
    goto :goto_10

    .line 333
    :cond_1d
    const/4 v4, 0x0

    .line 334
    :goto_10
    or-int/2addr v1, v4

    .line 335
    const/high16 v4, 0x380000

    .line 336
    .line 337
    and-int/2addr v4, v3

    .line 338
    xor-int v4, v4, v16

    .line 339
    .line 340
    const/high16 v14, 0x100000

    .line 341
    .line 342
    if-le v4, v14, :cond_1e

    .line 343
    .line 344
    invoke-virtual {v12, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    move-result v4

    .line 348
    if-nez v4, :cond_1f

    .line 349
    .line 350
    :cond_1e
    and-int v3, v3, v16

    .line 351
    .line 352
    if-ne v3, v14, :cond_20

    .line 353
    .line 354
    :cond_1f
    const/4 v14, 0x1

    .line 355
    goto :goto_11

    .line 356
    :cond_20
    const/4 v14, 0x0

    .line 357
    :goto_11
    or-int/2addr v1, v14

    .line 358
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object v3

    .line 362
    if-nez v1, :cond_21

    .line 363
    .line 364
    if-ne v3, v13, :cond_22

    .line 365
    .line 366
    :cond_21
    new-instance v3, Lh2/l7;

    .line 367
    .line 368
    move v4, v7

    .line 369
    move-wide/from16 v19, v5

    .line 370
    .line 371
    move-object v6, v8

    .line 372
    move-wide/from16 v7, v19

    .line 373
    .line 374
    move v5, v15

    .line 375
    invoke-direct/range {v3 .. v11}, Lh2/l7;-><init>(IFLay0/a;JJLay0/k;)V

    .line 376
    .line 377
    .line 378
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    :cond_22
    check-cast v3, Lay0/k;

    .line 382
    .line 383
    const/4 v1, 0x0

    .line 384
    invoke-static {v0, v3, v12, v1}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 385
    .line 386
    .line 387
    goto :goto_12

    .line 388
    :cond_23
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 389
    .line 390
    .line 391
    :goto_12
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 392
    .line 393
    .line 394
    move-result-object v11

    .line 395
    if-eqz v11, :cond_24

    .line 396
    .line 397
    new-instance v0, Lf2/n0;

    .line 398
    .line 399
    move-object/from16 v1, p0

    .line 400
    .line 401
    move-wide/from16 v3, p2

    .line 402
    .line 403
    move-wide/from16 v5, p4

    .line 404
    .line 405
    move/from16 v7, p6

    .line 406
    .line 407
    move/from16 v8, p7

    .line 408
    .line 409
    move-object/from16 v9, p8

    .line 410
    .line 411
    move/from16 v10, p10

    .line 412
    .line 413
    invoke-direct/range {v0 .. v10}, Lf2/n0;-><init>(Lay0/a;Lx2/s;JJIFLay0/k;I)V

    .line 414
    .line 415
    .line 416
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 417
    .line 418
    :cond_24
    return-void
.end method

.method public static final d(Lx2/s;JJIFLl2/o;II)V
    .locals 29

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-wide/from16 v9, p1

    .line 4
    .line 5
    move-wide/from16 v6, p3

    .line 6
    .line 7
    move/from16 v0, p8

    .line 8
    .line 9
    const/high16 v2, 0x3f800000    # 1.0f

    .line 10
    .line 11
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    const/4 v3, 0x0

    .line 16
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    move-object/from16 v4, p7

    .line 21
    .line 22
    check-cast v4, Ll2/t;

    .line 23
    .line 24
    const v5, 0x21d4b971

    .line 25
    .line 26
    .line 27
    invoke-virtual {v4, v5}, Ll2/t;->a0(I)Ll2/t;

    .line 28
    .line 29
    .line 30
    and-int/lit8 v5, v0, 0x6

    .line 31
    .line 32
    if-nez v5, :cond_1

    .line 33
    .line 34
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_0

    .line 39
    .line 40
    const/4 v5, 0x4

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v5, 0x2

    .line 43
    :goto_0
    or-int/2addr v5, v0

    .line 44
    goto :goto_1

    .line 45
    :cond_1
    move v5, v0

    .line 46
    :goto_1
    invoke-virtual {v4, v9, v10}, Ll2/t;->f(J)Z

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    if-eqz v8, :cond_2

    .line 51
    .line 52
    const/16 v8, 0x20

    .line 53
    .line 54
    goto :goto_2

    .line 55
    :cond_2
    const/16 v8, 0x10

    .line 56
    .line 57
    :goto_2
    or-int/2addr v5, v8

    .line 58
    invoke-virtual {v4, v6, v7}, Ll2/t;->f(J)Z

    .line 59
    .line 60
    .line 61
    move-result v8

    .line 62
    if-eqz v8, :cond_3

    .line 63
    .line 64
    const/16 v8, 0x100

    .line 65
    .line 66
    goto :goto_3

    .line 67
    :cond_3
    const/16 v8, 0x80

    .line 68
    .line 69
    :goto_3
    or-int/2addr v5, v8

    .line 70
    and-int/lit8 v8, p9, 0x8

    .line 71
    .line 72
    if-eqz v8, :cond_4

    .line 73
    .line 74
    or-int/lit16 v5, v5, 0xc00

    .line 75
    .line 76
    move/from16 v14, p5

    .line 77
    .line 78
    goto :goto_5

    .line 79
    :cond_4
    move/from16 v14, p5

    .line 80
    .line 81
    invoke-virtual {v4, v14}, Ll2/t;->e(I)Z

    .line 82
    .line 83
    .line 84
    move-result v15

    .line 85
    if-eqz v15, :cond_5

    .line 86
    .line 87
    const/16 v15, 0x800

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_5
    const/16 v15, 0x400

    .line 91
    .line 92
    :goto_4
    or-int/2addr v5, v15

    .line 93
    :goto_5
    and-int/lit8 v15, p9, 0x10

    .line 94
    .line 95
    if-eqz v15, :cond_7

    .line 96
    .line 97
    or-int/lit16 v5, v5, 0x6000

    .line 98
    .line 99
    :cond_6
    move/from16 v11, p6

    .line 100
    .line 101
    goto :goto_7

    .line 102
    :cond_7
    and-int/lit16 v11, v0, 0x6000

    .line 103
    .line 104
    if-nez v11, :cond_6

    .line 105
    .line 106
    move/from16 v11, p6

    .line 107
    .line 108
    invoke-virtual {v4, v11}, Ll2/t;->d(F)Z

    .line 109
    .line 110
    .line 111
    move-result v17

    .line 112
    if-eqz v17, :cond_8

    .line 113
    .line 114
    const/16 v17, 0x4000

    .line 115
    .line 116
    goto :goto_6

    .line 117
    :cond_8
    const/16 v17, 0x2000

    .line 118
    .line 119
    :goto_6
    or-int v5, v5, v17

    .line 120
    .line 121
    :goto_7
    and-int/lit16 v12, v5, 0x2493

    .line 122
    .line 123
    const/16 v13, 0x2492

    .line 124
    .line 125
    move/from16 v19, v15

    .line 126
    .line 127
    const/4 v15, 0x1

    .line 128
    if-eq v12, v13, :cond_9

    .line 129
    .line 130
    move v12, v15

    .line 131
    goto :goto_8

    .line 132
    :cond_9
    const/4 v12, 0x0

    .line 133
    :goto_8
    and-int/lit8 v13, v5, 0x1

    .line 134
    .line 135
    invoke-virtual {v4, v13, v12}, Ll2/t;->O(IZ)Z

    .line 136
    .line 137
    .line 138
    move-result v12

    .line 139
    if-eqz v12, :cond_18

    .line 140
    .line 141
    invoke-virtual {v4}, Ll2/t;->T()V

    .line 142
    .line 143
    .line 144
    and-int/lit8 v12, v0, 0x1

    .line 145
    .line 146
    if-eqz v12, :cond_b

    .line 147
    .line 148
    invoke-virtual {v4}, Ll2/t;->y()Z

    .line 149
    .line 150
    .line 151
    move-result v12

    .line 152
    if-eqz v12, :cond_a

    .line 153
    .line 154
    goto :goto_9

    .line 155
    :cond_a
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 156
    .line 157
    .line 158
    move/from16 v19, v11

    .line 159
    .line 160
    move v8, v14

    .line 161
    goto :goto_b

    .line 162
    :cond_b
    :goto_9
    if-eqz v8, :cond_c

    .line 163
    .line 164
    sget v8, Lh2/f7;->a:I

    .line 165
    .line 166
    goto :goto_a

    .line 167
    :cond_c
    move v8, v14

    .line 168
    :goto_a
    if-eqz v19, :cond_d

    .line 169
    .line 170
    sget v11, Lh2/f7;->d:F

    .line 171
    .line 172
    :cond_d
    move/from16 v19, v11

    .line 173
    .line 174
    :goto_b
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 175
    .line 176
    .line 177
    const/4 v11, 0x0

    .line 178
    invoke-static {v11, v4, v15}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    new-instance v13, Lc1/m0;

    .line 183
    .line 184
    new-instance v14, Lc1/l0;

    .line 185
    .line 186
    invoke-direct {v14}, Lc1/l0;-><init>()V

    .line 187
    .line 188
    .line 189
    move-object/from16 p5, v12

    .line 190
    .line 191
    const/16 v12, 0x6d6

    .line 192
    .line 193
    iput v12, v14, Lc1/l0;->a:I

    .line 194
    .line 195
    const/4 v12, 0x0

    .line 196
    invoke-virtual {v14, v12, v3}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 197
    .line 198
    .line 199
    move-result-object v15

    .line 200
    sget-object v12, Lh2/n7;->d:Lc1/s;

    .line 201
    .line 202
    iput-object v12, v15, Lc1/k0;->b:Lc1/w;

    .line 203
    .line 204
    const/16 v15, 0x3e8

    .line 205
    .line 206
    invoke-virtual {v14, v15, v2}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 207
    .line 208
    .line 209
    invoke-direct {v13, v14}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 210
    .line 211
    .line 212
    const/4 v14, 0x6

    .line 213
    invoke-static {v13, v11, v14}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 214
    .line 215
    .line 216
    move-result-object v13

    .line 217
    const/16 v15, 0x800

    .line 218
    .line 219
    const/16 v18, 0x8

    .line 220
    .line 221
    move-object/from16 v22, v12

    .line 222
    .line 223
    const/4 v12, 0x0

    .line 224
    move/from16 v23, v14

    .line 225
    .line 226
    move-object v14, v13

    .line 227
    const/high16 v13, 0x3f800000    # 1.0f

    .line 228
    .line 229
    move/from16 v24, v15

    .line 230
    .line 231
    const/4 v15, 0x0

    .line 232
    const/16 v25, 0x4000

    .line 233
    .line 234
    const/16 v17, 0x11b8

    .line 235
    .line 236
    move-object/from16 v11, p5

    .line 237
    .line 238
    move-object/from16 v16, v4

    .line 239
    .line 240
    move-object/from16 v4, v22

    .line 241
    .line 242
    const/16 v0, 0x6d6

    .line 243
    .line 244
    const/16 v20, 0x0

    .line 245
    .line 246
    invoke-static/range {v11 .. v18}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 247
    .line 248
    .line 249
    move-result-object v12

    .line 250
    new-instance v13, Lc1/m0;

    .line 251
    .line 252
    new-instance v14, Lc1/l0;

    .line 253
    .line 254
    invoke-direct {v14}, Lc1/l0;-><init>()V

    .line 255
    .line 256
    .line 257
    iput v0, v14, Lc1/l0;->a:I

    .line 258
    .line 259
    const/16 v15, 0xfa

    .line 260
    .line 261
    invoke-virtual {v14, v15, v3}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 262
    .line 263
    .line 264
    move-result-object v15

    .line 265
    iput-object v4, v15, Lc1/k0;->b:Lc1/w;

    .line 266
    .line 267
    const/16 v15, 0x4e2

    .line 268
    .line 269
    invoke-virtual {v14, v15, v2}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 270
    .line 271
    .line 272
    invoke-direct {v13, v14}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 273
    .line 274
    .line 275
    const/4 v14, 0x6

    .line 276
    const/4 v15, 0x0

    .line 277
    invoke-static {v13, v15, v14}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 278
    .line 279
    .line 280
    move-result-object v13

    .line 281
    move-object/from16 v26, v15

    .line 282
    .line 283
    const/4 v15, 0x0

    .line 284
    move-object/from16 v21, v12

    .line 285
    .line 286
    const/4 v12, 0x0

    .line 287
    move/from16 v23, v14

    .line 288
    .line 289
    move-object v14, v13

    .line 290
    const/high16 v13, 0x3f800000    # 1.0f

    .line 291
    .line 292
    move-object/from16 v27, v21

    .line 293
    .line 294
    invoke-static/range {v11 .. v18}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 295
    .line 296
    .line 297
    move-result-object v12

    .line 298
    new-instance v13, Lc1/m0;

    .line 299
    .line 300
    new-instance v14, Lc1/l0;

    .line 301
    .line 302
    invoke-direct {v14}, Lc1/l0;-><init>()V

    .line 303
    .line 304
    .line 305
    iput v0, v14, Lc1/l0;->a:I

    .line 306
    .line 307
    const/16 v15, 0x28a

    .line 308
    .line 309
    invoke-virtual {v14, v15, v3}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 310
    .line 311
    .line 312
    move-result-object v15

    .line 313
    iput-object v4, v15, Lc1/k0;->b:Lc1/w;

    .line 314
    .line 315
    const/16 v15, 0x5dc

    .line 316
    .line 317
    invoke-virtual {v14, v15, v2}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 318
    .line 319
    .line 320
    invoke-direct {v13, v14}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 321
    .line 322
    .line 323
    const/4 v14, 0x6

    .line 324
    const/4 v15, 0x0

    .line 325
    invoke-static {v13, v15, v14}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 326
    .line 327
    .line 328
    move-result-object v13

    .line 329
    move-object/from16 v26, v15

    .line 330
    .line 331
    const/4 v15, 0x0

    .line 332
    move-object/from16 v21, v12

    .line 333
    .line 334
    const/4 v12, 0x0

    .line 335
    move/from16 v23, v14

    .line 336
    .line 337
    move-object v14, v13

    .line 338
    const/high16 v13, 0x3f800000    # 1.0f

    .line 339
    .line 340
    move-object/from16 v28, v21

    .line 341
    .line 342
    invoke-static/range {v11 .. v18}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 343
    .line 344
    .line 345
    move-result-object v12

    .line 346
    new-instance v13, Lc1/m0;

    .line 347
    .line 348
    new-instance v14, Lc1/l0;

    .line 349
    .line 350
    invoke-direct {v14}, Lc1/l0;-><init>()V

    .line 351
    .line 352
    .line 353
    iput v0, v14, Lc1/l0;->a:I

    .line 354
    .line 355
    const/16 v15, 0x384

    .line 356
    .line 357
    invoke-virtual {v14, v15, v3}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 358
    .line 359
    .line 360
    move-result-object v3

    .line 361
    iput-object v4, v3, Lc1/k0;->b:Lc1/w;

    .line 362
    .line 363
    invoke-virtual {v14, v0, v2}, Lc1/l0;->a(ILjava/lang/Float;)Lc1/k0;

    .line 364
    .line 365
    .line 366
    invoke-direct {v13, v14}, Lc1/m0;-><init>(Lc1/l0;)V

    .line 367
    .line 368
    .line 369
    const/4 v14, 0x6

    .line 370
    const/4 v15, 0x0

    .line 371
    invoke-static {v13, v15, v14}, Lc1/d;->q(Lc1/v;Lc1/t0;I)Lc1/f0;

    .line 372
    .line 373
    .line 374
    move-result-object v14

    .line 375
    const/4 v15, 0x0

    .line 376
    move-object v0, v12

    .line 377
    const/4 v12, 0x0

    .line 378
    const/high16 v13, 0x3f800000    # 1.0f

    .line 379
    .line 380
    invoke-static/range {v11 .. v18}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 381
    .line 382
    .line 383
    move-result-object v12

    .line 384
    move-object/from16 v13, v16

    .line 385
    .line 386
    sget-object v2, Li2/b;->d:Lx2/s;

    .line 387
    .line 388
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 389
    .line 390
    .line 391
    move-result-object v2

    .line 392
    new-instance v3, Ldj/a;

    .line 393
    .line 394
    const/16 v4, 0x11

    .line 395
    .line 396
    invoke-direct {v3, v4}, Ldj/a;-><init>(I)V

    .line 397
    .line 398
    .line 399
    const/4 v4, 0x1

    .line 400
    invoke-static {v2, v4, v3}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 401
    .line 402
    .line 403
    move-result-object v2

    .line 404
    sget v3, Lh2/n7;->a:F

    .line 405
    .line 406
    sget v11, Lh2/n7;->b:F

    .line 407
    .line 408
    invoke-static {v2, v3, v11}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 409
    .line 410
    .line 411
    move-result-object v14

    .line 412
    and-int/lit16 v2, v5, 0x1c00

    .line 413
    .line 414
    const/16 v15, 0x800

    .line 415
    .line 416
    if-ne v2, v15, :cond_e

    .line 417
    .line 418
    move v15, v4

    .line 419
    goto :goto_c

    .line 420
    :cond_e
    move/from16 v15, v20

    .line 421
    .line 422
    :goto_c
    const v2, 0xe000

    .line 423
    .line 424
    .line 425
    and-int/2addr v2, v5

    .line 426
    const/16 v3, 0x4000

    .line 427
    .line 428
    if-ne v2, v3, :cond_f

    .line 429
    .line 430
    move v2, v4

    .line 431
    goto :goto_d

    .line 432
    :cond_f
    move/from16 v2, v20

    .line 433
    .line 434
    :goto_d
    or-int/2addr v2, v15

    .line 435
    move-object/from16 v3, v27

    .line 436
    .line 437
    invoke-virtual {v13, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    move-result v11

    .line 441
    or-int/2addr v2, v11

    .line 442
    and-int/lit16 v11, v5, 0x380

    .line 443
    .line 444
    xor-int/lit16 v11, v11, 0x180

    .line 445
    .line 446
    const/16 v15, 0x100

    .line 447
    .line 448
    if-le v11, v15, :cond_10

    .line 449
    .line 450
    invoke-virtual {v13, v6, v7}, Ll2/t;->f(J)Z

    .line 451
    .line 452
    .line 453
    move-result v11

    .line 454
    if-nez v11, :cond_11

    .line 455
    .line 456
    :cond_10
    and-int/lit16 v11, v5, 0x180

    .line 457
    .line 458
    if-ne v11, v15, :cond_12

    .line 459
    .line 460
    :cond_11
    move v15, v4

    .line 461
    goto :goto_e

    .line 462
    :cond_12
    move/from16 v15, v20

    .line 463
    .line 464
    :goto_e
    or-int/2addr v2, v15

    .line 465
    move-object/from16 v11, v28

    .line 466
    .line 467
    invoke-virtual {v13, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v15

    .line 471
    or-int/2addr v2, v15

    .line 472
    and-int/lit8 v15, v5, 0x70

    .line 473
    .line 474
    xor-int/lit8 v15, v15, 0x30

    .line 475
    .line 476
    const/16 v4, 0x20

    .line 477
    .line 478
    if-le v15, v4, :cond_13

    .line 479
    .line 480
    invoke-virtual {v13, v9, v10}, Ll2/t;->f(J)Z

    .line 481
    .line 482
    .line 483
    move-result v15

    .line 484
    if-nez v15, :cond_14

    .line 485
    .line 486
    :cond_13
    and-int/lit8 v5, v5, 0x30

    .line 487
    .line 488
    if-ne v5, v4, :cond_15

    .line 489
    .line 490
    :cond_14
    const/4 v15, 0x1

    .line 491
    goto :goto_f

    .line 492
    :cond_15
    move/from16 v15, v20

    .line 493
    .line 494
    :goto_f
    or-int/2addr v2, v15

    .line 495
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 496
    .line 497
    .line 498
    move-result v4

    .line 499
    or-int/2addr v2, v4

    .line 500
    invoke-virtual {v13, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 501
    .line 502
    .line 503
    move-result v4

    .line 504
    or-int/2addr v2, v4

    .line 505
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object v4

    .line 509
    if-nez v2, :cond_17

    .line 510
    .line 511
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 512
    .line 513
    if-ne v4, v2, :cond_16

    .line 514
    .line 515
    goto :goto_10

    .line 516
    :cond_16
    move-object v2, v4

    .line 517
    move v3, v8

    .line 518
    move/from16 v4, v19

    .line 519
    .line 520
    move/from16 v0, v20

    .line 521
    .line 522
    goto :goto_11

    .line 523
    :cond_17
    :goto_10
    new-instance v2, Lh2/g7;

    .line 524
    .line 525
    move-object v5, v3

    .line 526
    move v3, v8

    .line 527
    move-object v8, v11

    .line 528
    move/from16 v4, v19

    .line 529
    .line 530
    move-object v11, v0

    .line 531
    move/from16 v0, v20

    .line 532
    .line 533
    invoke-direct/range {v2 .. v12}, Lh2/g7;-><init>(IFLc1/g0;JLc1/g0;JLc1/g0;Lc1/g0;)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v13, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 537
    .line 538
    .line 539
    :goto_11
    check-cast v2, Lay0/k;

    .line 540
    .line 541
    invoke-static {v14, v2, v13, v0}, Lkp/i;->a(Lx2/s;Lay0/k;Ll2/o;I)V

    .line 542
    .line 543
    .line 544
    move v6, v3

    .line 545
    move v7, v4

    .line 546
    goto :goto_12

    .line 547
    :cond_18
    move-object v13, v4

    .line 548
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 549
    .line 550
    .line 551
    move v7, v11

    .line 552
    move v6, v14

    .line 553
    :goto_12
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 554
    .line 555
    .line 556
    move-result-object v10

    .line 557
    if-eqz v10, :cond_19

    .line 558
    .line 559
    new-instance v0, Lh2/k7;

    .line 560
    .line 561
    move-wide/from16 v2, p1

    .line 562
    .line 563
    move-wide/from16 v4, p3

    .line 564
    .line 565
    move/from16 v8, p8

    .line 566
    .line 567
    move/from16 v9, p9

    .line 568
    .line 569
    invoke-direct/range {v0 .. v9}, Lh2/k7;-><init>(Lx2/s;JJIFII)V

    .line 570
    .line 571
    .line 572
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 573
    .line 574
    :cond_19
    return-void
.end method

.method public static final e(Lg3/d;FFJLg3/h;)V
    .locals 12

    .line 1
    move-object/from16 v10, p5

    .line 2
    .line 3
    iget v0, v10, Lg3/h;->a:F

    .line 4
    .line 5
    const/4 v1, 0x2

    .line 6
    int-to-float v1, v1

    .line 7
    div-float/2addr v0, v1

    .line 8
    invoke-interface {p0}, Lg3/d;->e()J

    .line 9
    .line 10
    .line 11
    move-result-wide v2

    .line 12
    const/16 v4, 0x20

    .line 13
    .line 14
    shr-long/2addr v2, v4

    .line 15
    long-to-int v2, v2

    .line 16
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    mul-float/2addr v1, v0

    .line 21
    sub-float/2addr v2, v1

    .line 22
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    int-to-long v5, v1

    .line 27
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    int-to-long v0, v0

    .line 32
    shl-long/2addr v5, v4

    .line 33
    const-wide v7, 0xffffffffL

    .line 34
    .line 35
    .line 36
    .line 37
    .line 38
    and-long/2addr v0, v7

    .line 39
    or-long/2addr v5, v0

    .line 40
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    int-to-long v0, v0

    .line 45
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    int-to-long v2, v2

    .line 50
    shl-long/2addr v0, v4

    .line 51
    and-long/2addr v2, v7

    .line 52
    or-long v7, v0, v2

    .line 53
    .line 54
    const/4 v9, 0x0

    .line 55
    const/16 v11, 0x340

    .line 56
    .line 57
    move-object v0, p0

    .line 58
    move v3, p1

    .line 59
    move v4, p2

    .line 60
    move-wide v1, p3

    .line 61
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public static final f(Lg3/d;FFJFI)V
    .locals 22

    .line 1
    invoke-interface/range {p0 .. p0}, Lg3/d;->e()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    shr-long/2addr v0, v2

    .line 8
    long-to-int v0, v0

    .line 9
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-interface/range {p0 .. p0}, Lg3/d;->e()J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    const-wide v5, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long/2addr v3, v5

    .line 23
    long-to-int v1, v3

    .line 24
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    const/4 v3, 0x2

    .line 29
    int-to-float v3, v3

    .line 30
    div-float v4, v1, v3

    .line 31
    .line 32
    invoke-interface/range {p0 .. p0}, Lg3/d;->getLayoutDirection()Lt4/m;

    .line 33
    .line 34
    .line 35
    move-result-object v7

    .line 36
    sget-object v8, Lt4/m;->d:Lt4/m;

    .line 37
    .line 38
    if-ne v7, v8, :cond_0

    .line 39
    .line 40
    const/4 v7, 0x1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const/4 v7, 0x0

    .line 43
    :goto_0
    const/high16 v8, 0x3f800000    # 1.0f

    .line 44
    .line 45
    if-eqz v7, :cond_1

    .line 46
    .line 47
    move/from16 v9, p1

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    sub-float v9, v8, p2

    .line 51
    .line 52
    :goto_1
    mul-float/2addr v9, v0

    .line 53
    if-eqz v7, :cond_2

    .line 54
    .line 55
    move/from16 v8, p2

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    sub-float v8, v8, p1

    .line 59
    .line 60
    :goto_2
    mul-float/2addr v8, v0

    .line 61
    if-nez p6, :cond_3

    .line 62
    .line 63
    goto :goto_3

    .line 64
    :cond_3
    cmpl-float v1, v1, v0

    .line 65
    .line 66
    if-lez v1, :cond_4

    .line 67
    .line 68
    :goto_3
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    int-to-long v0, v0

    .line 73
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    int-to-long v9, v3

    .line 78
    shl-long/2addr v0, v2

    .line 79
    and-long/2addr v9, v5

    .line 80
    or-long v14, v0, v9

    .line 81
    .line 82
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 83
    .line 84
    .line 85
    move-result v0

    .line 86
    int-to-long v0, v0

    .line 87
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    int-to-long v3, v3

    .line 92
    shl-long/2addr v0, v2

    .line 93
    and-long v2, v3, v5

    .line 94
    .line 95
    or-long v16, v0, v2

    .line 96
    .line 97
    const/16 v20, 0x0

    .line 98
    .line 99
    const/16 v21, 0x1f0

    .line 100
    .line 101
    const/16 v19, 0x0

    .line 102
    .line 103
    move-object/from16 v11, p0

    .line 104
    .line 105
    move-wide/from16 v12, p3

    .line 106
    .line 107
    move/from16 v18, p5

    .line 108
    .line 109
    invoke-static/range {v11 .. v21}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 110
    .line 111
    .line 112
    return-void

    .line 113
    :cond_4
    div-float v1, p5, v3

    .line 114
    .line 115
    sub-float/2addr v0, v1

    .line 116
    cmpg-float v3, v9, v1

    .line 117
    .line 118
    if-gez v3, :cond_5

    .line 119
    .line 120
    move v9, v1

    .line 121
    :cond_5
    cmpl-float v3, v9, v0

    .line 122
    .line 123
    if-lez v3, :cond_6

    .line 124
    .line 125
    move v9, v0

    .line 126
    :cond_6
    cmpg-float v3, v8, v1

    .line 127
    .line 128
    if-gez v3, :cond_7

    .line 129
    .line 130
    move v8, v1

    .line 131
    :cond_7
    cmpl-float v1, v8, v0

    .line 132
    .line 133
    if-lez v1, :cond_8

    .line 134
    .line 135
    goto :goto_4

    .line 136
    :cond_8
    move v0, v8

    .line 137
    :goto_4
    sub-float v1, p2, p1

    .line 138
    .line 139
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    const/4 v3, 0x0

    .line 144
    cmpl-float v1, v1, v3

    .line 145
    .line 146
    if-lez v1, :cond_9

    .line 147
    .line 148
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    int-to-long v7, v1

    .line 153
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    int-to-long v9, v1

    .line 158
    shl-long/2addr v7, v2

    .line 159
    and-long/2addr v9, v5

    .line 160
    or-long/2addr v7, v9

    .line 161
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    int-to-long v0, v0

    .line 166
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    int-to-long v3, v3

    .line 171
    shl-long/2addr v0, v2

    .line 172
    and-long v2, v3, v5

    .line 173
    .line 174
    or-long v5, v0, v2

    .line 175
    .line 176
    const/4 v9, 0x0

    .line 177
    const/16 v10, 0x1e0

    .line 178
    .line 179
    move-object/from16 v0, p0

    .line 180
    .line 181
    move-wide/from16 v1, p3

    .line 182
    .line 183
    move-wide v3, v7

    .line 184
    move/from16 v7, p5

    .line 185
    .line 186
    move/from16 v8, p6

    .line 187
    .line 188
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 189
    .line 190
    .line 191
    :cond_9
    return-void
.end method
