.class public abstract Li91/y3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/16 v0, 0x36

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li91/y3;->a:F

    .line 5
    .line 6
    const/16 v0, 0x18

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li91/y3;->b:F

    .line 10
    .line 11
    const/4 v1, 0x3

    .line 12
    int-to-float v1, v1

    .line 13
    sput v1, Li91/y3;->c:F

    .line 14
    .line 15
    add-float/2addr v1, v1

    .line 16
    sub-float/2addr v0, v1

    .line 17
    sput v0, Li91/y3;->d:F

    .line 18
    .line 19
    sput v0, Li91/y3;->e:F

    .line 20
    .line 21
    return-void
.end method

.method public static final a(IILay0/a;Lay0/k;Ljava/lang/String;Ll2/o;Lx2/s;ZZ)V
    .locals 34

    .line 1
    move/from16 v7, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v8, p3

    .line 6
    .line 7
    move-object/from16 v9, p4

    .line 8
    .line 9
    move-object/from16 v10, p6

    .line 10
    .line 11
    const-string v0, "text"

    .line 12
    .line 13
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "onClick"

    .line 17
    .line 18
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "onCheckedChange"

    .line 22
    .line 23
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    move-object/from16 v11, p5

    .line 27
    .line 28
    check-cast v11, Ll2/t;

    .line 29
    .line 30
    const v0, -0x4b121da8

    .line 31
    .line 32
    .line 33
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 34
    .line 35
    .line 36
    and-int/lit8 v0, v7, 0x6

    .line 37
    .line 38
    const/4 v1, 0x2

    .line 39
    if-nez v0, :cond_1

    .line 40
    .line 41
    invoke-virtual {v11, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    const/4 v0, 0x4

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    move v0, v1

    .line 50
    :goto_0
    or-int/2addr v0, v7

    .line 51
    goto :goto_1

    .line 52
    :cond_1
    move v0, v7

    .line 53
    :goto_1
    and-int/lit8 v2, v7, 0x30

    .line 54
    .line 55
    move/from16 v12, p7

    .line 56
    .line 57
    if-nez v2, :cond_3

    .line 58
    .line 59
    invoke-virtual {v11, v12}, Ll2/t;->h(Z)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_2

    .line 64
    .line 65
    const/16 v2, 0x20

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_2
    const/16 v2, 0x10

    .line 69
    .line 70
    :goto_2
    or-int/2addr v0, v2

    .line 71
    :cond_3
    and-int/lit16 v2, v7, 0x180

    .line 72
    .line 73
    if-nez v2, :cond_5

    .line 74
    .line 75
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_4

    .line 80
    .line 81
    const/16 v2, 0x100

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_4
    const/16 v2, 0x80

    .line 85
    .line 86
    :goto_3
    or-int/2addr v0, v2

    .line 87
    :cond_5
    and-int/lit16 v2, v7, 0xc00

    .line 88
    .line 89
    if-nez v2, :cond_7

    .line 90
    .line 91
    invoke-virtual {v11, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v2

    .line 95
    if-eqz v2, :cond_6

    .line 96
    .line 97
    const/16 v2, 0x800

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_6
    const/16 v2, 0x400

    .line 101
    .line 102
    :goto_4
    or-int/2addr v0, v2

    .line 103
    :cond_7
    and-int/lit16 v2, v7, 0x6000

    .line 104
    .line 105
    if-nez v2, :cond_9

    .line 106
    .line 107
    invoke-virtual {v11, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-eqz v2, :cond_8

    .line 112
    .line 113
    const/16 v2, 0x4000

    .line 114
    .line 115
    goto :goto_5

    .line 116
    :cond_8
    const/16 v2, 0x2000

    .line 117
    .line 118
    :goto_5
    or-int/2addr v0, v2

    .line 119
    :cond_9
    and-int/lit8 v2, p1, 0x20

    .line 120
    .line 121
    const/high16 v4, 0x30000

    .line 122
    .line 123
    if-eqz v2, :cond_b

    .line 124
    .line 125
    or-int/2addr v0, v4

    .line 126
    :cond_a
    move/from16 v4, p8

    .line 127
    .line 128
    :goto_6
    move v13, v0

    .line 129
    goto :goto_8

    .line 130
    :cond_b
    and-int/2addr v4, v7

    .line 131
    if-nez v4, :cond_a

    .line 132
    .line 133
    move/from16 v4, p8

    .line 134
    .line 135
    invoke-virtual {v11, v4}, Ll2/t;->h(Z)Z

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    if-eqz v5, :cond_c

    .line 140
    .line 141
    const/high16 v5, 0x20000

    .line 142
    .line 143
    goto :goto_7

    .line 144
    :cond_c
    const/high16 v5, 0x10000

    .line 145
    .line 146
    :goto_7
    or-int/2addr v0, v5

    .line 147
    goto :goto_6

    .line 148
    :goto_8
    const v0, 0x12493

    .line 149
    .line 150
    .line 151
    and-int/2addr v0, v13

    .line 152
    const v5, 0x12492

    .line 153
    .line 154
    .line 155
    const/4 v15, 0x0

    .line 156
    if-eq v0, v5, :cond_d

    .line 157
    .line 158
    const/4 v0, 0x1

    .line 159
    goto :goto_9

    .line 160
    :cond_d
    move v0, v15

    .line 161
    :goto_9
    and-int/lit8 v5, v13, 0x1

    .line 162
    .line 163
    invoke-virtual {v11, v5, v0}, Ll2/t;->O(IZ)Z

    .line 164
    .line 165
    .line 166
    move-result v0

    .line 167
    if-eqz v0, :cond_15

    .line 168
    .line 169
    if-eqz v2, :cond_e

    .line 170
    .line 171
    const/16 v31, 0x1

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_e
    move/from16 v31, v4

    .line 175
    .line 176
    :goto_a
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 181
    .line 182
    if-ne v0, v2, :cond_f

    .line 183
    .line 184
    invoke-static {v11}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->g(Ll2/t;)Li1/l;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    :cond_f
    check-cast v0, Li1/l;

    .line 189
    .line 190
    sget-object v2, Lx2/c;->n:Lx2/i;

    .line 191
    .line 192
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 193
    .line 194
    invoke-virtual {v11, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v4

    .line 198
    check-cast v4, Lj91/c;

    .line 199
    .line 200
    iget v4, v4, Lj91/c;->m:F

    .line 201
    .line 202
    const/4 v5, 0x0

    .line 203
    invoke-static {v10, v4, v5, v1}, Landroidx/compose/foundation/layout/d;->g(Lx2/s;FFI)Lx2/s;

    .line 204
    .line 205
    .line 206
    move-result-object v1

    .line 207
    const/4 v4, 0x0

    .line 208
    const/16 v6, 0x1c

    .line 209
    .line 210
    move-object v5, v2

    .line 211
    const/4 v2, 0x0

    .line 212
    const/4 v3, 0x0

    .line 213
    move-object v14, v1

    .line 214
    move-object v1, v0

    .line 215
    move-object v0, v14

    .line 216
    move-object v14, v5

    .line 217
    move-object/from16 v5, p2

    .line 218
    .line 219
    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/a;->d(Lx2/s;Li1/l;Le1/s0;ZLd4/i;Lay0/a;I)Lx2/s;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    sget-object v1, Lk1/j;->a:Lk1/c;

    .line 224
    .line 225
    const/16 v2, 0x30

    .line 226
    .line 227
    invoke-static {v1, v14, v11, v2}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    iget-wide v2, v11, Ll2/t;->T:J

    .line 232
    .line 233
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 234
    .line 235
    .line 236
    move-result v2

    .line 237
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    invoke-static {v11, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 246
    .line 247
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 248
    .line 249
    .line 250
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 251
    .line 252
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 253
    .line 254
    .line 255
    iget-boolean v5, v11, Ll2/t;->S:Z

    .line 256
    .line 257
    if-eqz v5, :cond_10

    .line 258
    .line 259
    invoke-virtual {v11, v4}, Ll2/t;->l(Lay0/a;)V

    .line 260
    .line 261
    .line 262
    goto :goto_b

    .line 263
    :cond_10
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 264
    .line 265
    .line 266
    :goto_b
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 267
    .line 268
    invoke-static {v4, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 269
    .line 270
    .line 271
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 272
    .line 273
    invoke-static {v1, v3, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 274
    .line 275
    .line 276
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 277
    .line 278
    iget-boolean v3, v11, Ll2/t;->S:Z

    .line 279
    .line 280
    if-nez v3, :cond_11

    .line 281
    .line 282
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v3

    .line 286
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 287
    .line 288
    .line 289
    move-result-object v4

    .line 290
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    move-result v3

    .line 294
    if-nez v3, :cond_12

    .line 295
    .line 296
    :cond_11
    invoke-static {v2, v11, v2, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 297
    .line 298
    .line 299
    :cond_12
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 300
    .line 301
    invoke-static {v1, v0, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 302
    .line 303
    .line 304
    if-eqz v31, :cond_13

    .line 305
    .line 306
    const v0, -0x41be7359

    .line 307
    .line 308
    .line 309
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 310
    .line 311
    .line 312
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 313
    .line 314
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    check-cast v0, Lj91/e;

    .line 319
    .line 320
    invoke-virtual {v0}, Lj91/e;->q()J

    .line 321
    .line 322
    .line 323
    move-result-wide v0

    .line 324
    :goto_c
    invoke-virtual {v11, v15}, Ll2/t;->q(Z)V

    .line 325
    .line 326
    .line 327
    goto :goto_d

    .line 328
    :cond_13
    const v0, -0x41be6f16

    .line 329
    .line 330
    .line 331
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 332
    .line 333
    .line 334
    sget-object v0, Lj91/h;->a:Ll2/u2;

    .line 335
    .line 336
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object v0

    .line 340
    check-cast v0, Lj91/e;

    .line 341
    .line 342
    invoke-virtual {v0}, Lj91/e;->r()J

    .line 343
    .line 344
    .line 345
    move-result-wide v0

    .line 346
    goto :goto_c

    .line 347
    :goto_d
    sget-object v2, Lj91/j;->a:Ll2/u2;

    .line 348
    .line 349
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v2

    .line 353
    check-cast v2, Lj91/f;

    .line 354
    .line 355
    invoke-virtual {v2}, Lj91/f;->b()Lg4/p0;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    const/high16 v3, 0x3f800000    # 1.0f

    .line 360
    .line 361
    float-to-double v4, v3

    .line 362
    const-wide/16 v14, 0x0

    .line 363
    .line 364
    cmpl-double v4, v4, v14

    .line 365
    .line 366
    if-lez v4, :cond_14

    .line 367
    .line 368
    :goto_e
    move-object/from16 v27, v11

    .line 369
    .line 370
    goto :goto_f

    .line 371
    :cond_14
    const-string v4, "invalid weight; must be greater than zero"

    .line 372
    .line 373
    invoke-static {v4}, Ll1/a;->a(Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    goto :goto_e

    .line 377
    :goto_f
    new-instance v11, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 378
    .line 379
    const/4 v4, 0x1

    .line 380
    invoke-direct {v11, v3, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 381
    .line 382
    .line 383
    and-int/lit8 v28, v13, 0xe

    .line 384
    .line 385
    const/16 v29, 0x0

    .line 386
    .line 387
    const v30, 0xfff0

    .line 388
    .line 389
    .line 390
    const-wide/16 v14, 0x0

    .line 391
    .line 392
    const/16 v16, 0x0

    .line 393
    .line 394
    const-wide/16 v17, 0x0

    .line 395
    .line 396
    const/16 v19, 0x0

    .line 397
    .line 398
    const/16 v20, 0x0

    .line 399
    .line 400
    const-wide/16 v21, 0x0

    .line 401
    .line 402
    const/16 v23, 0x0

    .line 403
    .line 404
    const/16 v24, 0x0

    .line 405
    .line 406
    const/16 v25, 0x0

    .line 407
    .line 408
    const/16 v26, 0x0

    .line 409
    .line 410
    move-wide/from16 v32, v0

    .line 411
    .line 412
    move v0, v13

    .line 413
    move-wide/from16 v12, v32

    .line 414
    .line 415
    move-object v10, v2

    .line 416
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 417
    .line 418
    .line 419
    shr-int/lit8 v1, v0, 0x3

    .line 420
    .line 421
    and-int/lit8 v1, v1, 0xe

    .line 422
    .line 423
    shr-int/lit8 v2, v0, 0x9

    .line 424
    .line 425
    and-int/lit16 v2, v2, 0x380

    .line 426
    .line 427
    or-int/2addr v1, v2

    .line 428
    and-int/lit16 v0, v0, 0x1c00

    .line 429
    .line 430
    or-int v5, v1, v0

    .line 431
    .line 432
    const/4 v6, 0x2

    .line 433
    const/4 v1, 0x0

    .line 434
    move/from16 v0, p7

    .line 435
    .line 436
    move-object v3, v8

    .line 437
    move/from16 v2, v31

    .line 438
    .line 439
    move v8, v4

    .line 440
    move-object/from16 v4, v27

    .line 441
    .line 442
    invoke-static/range {v0 .. v6}, Li91/y3;->b(ZLx2/s;ZLay0/k;Ll2/o;II)V

    .line 443
    .line 444
    .line 445
    move-object v0, v4

    .line 446
    invoke-virtual {v0, v8}, Ll2/t;->q(Z)V

    .line 447
    .line 448
    .line 449
    move v6, v2

    .line 450
    goto :goto_10

    .line 451
    :cond_15
    move-object v0, v11

    .line 452
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 453
    .line 454
    .line 455
    move v6, v4

    .line 456
    :goto_10
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 457
    .line 458
    .line 459
    move-result-object v9

    .line 460
    if-eqz v9, :cond_16

    .line 461
    .line 462
    new-instance v0, Li91/x3;

    .line 463
    .line 464
    move/from16 v8, p1

    .line 465
    .line 466
    move-object/from16 v3, p2

    .line 467
    .line 468
    move-object/from16 v4, p3

    .line 469
    .line 470
    move-object/from16 v1, p4

    .line 471
    .line 472
    move-object/from16 v5, p6

    .line 473
    .line 474
    move/from16 v2, p7

    .line 475
    .line 476
    invoke-direct/range {v0 .. v8}, Li91/x3;-><init>(Ljava/lang/String;ZLay0/a;Lay0/k;Lx2/s;ZII)V

    .line 477
    .line 478
    .line 479
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 480
    .line 481
    :cond_16
    return-void
.end method

.method public static final b(ZLx2/s;ZLay0/k;Ll2/o;II)V
    .locals 19

    .line 1
    move/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v4, p3

    .line 4
    .line 5
    move/from16 v5, p5

    .line 6
    .line 7
    const-string v0, "onCheckedChange"

    .line 8
    .line 9
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    move-object/from16 v9, p4

    .line 13
    .line 14
    check-cast v9, Ll2/t;

    .line 15
    .line 16
    const v0, -0x487ae709

    .line 17
    .line 18
    .line 19
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 20
    .line 21
    .line 22
    and-int/lit8 v0, v5, 0x6

    .line 23
    .line 24
    const/4 v2, 0x2

    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    invoke-virtual {v9, v1}, Ll2/t;->h(Z)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    const/4 v0, 0x4

    .line 34
    goto :goto_0

    .line 35
    :cond_0
    move v0, v2

    .line 36
    :goto_0
    or-int/2addr v0, v5

    .line 37
    goto :goto_1

    .line 38
    :cond_1
    move v0, v5

    .line 39
    :goto_1
    and-int/lit8 v3, p6, 0x2

    .line 40
    .line 41
    if-eqz v3, :cond_3

    .line 42
    .line 43
    or-int/lit8 v0, v0, 0x30

    .line 44
    .line 45
    :cond_2
    move-object/from16 v6, p1

    .line 46
    .line 47
    goto :goto_3

    .line 48
    :cond_3
    and-int/lit8 v6, v5, 0x30

    .line 49
    .line 50
    if-nez v6, :cond_2

    .line 51
    .line 52
    move-object/from16 v6, p1

    .line 53
    .line 54
    invoke-virtual {v9, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    if-eqz v7, :cond_4

    .line 59
    .line 60
    const/16 v7, 0x20

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_4
    const/16 v7, 0x10

    .line 64
    .line 65
    :goto_2
    or-int/2addr v0, v7

    .line 66
    :goto_3
    and-int/lit8 v7, p6, 0x4

    .line 67
    .line 68
    if-eqz v7, :cond_6

    .line 69
    .line 70
    or-int/lit16 v0, v0, 0x180

    .line 71
    .line 72
    :cond_5
    move/from16 v8, p2

    .line 73
    .line 74
    goto :goto_5

    .line 75
    :cond_6
    and-int/lit16 v8, v5, 0x180

    .line 76
    .line 77
    if-nez v8, :cond_5

    .line 78
    .line 79
    move/from16 v8, p2

    .line 80
    .line 81
    invoke-virtual {v9, v8}, Ll2/t;->h(Z)Z

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    if-eqz v10, :cond_7

    .line 86
    .line 87
    const/16 v10, 0x100

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_7
    const/16 v10, 0x80

    .line 91
    .line 92
    :goto_4
    or-int/2addr v0, v10

    .line 93
    :goto_5
    and-int/lit16 v10, v5, 0xc00

    .line 94
    .line 95
    if-nez v10, :cond_9

    .line 96
    .line 97
    invoke-virtual {v9, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v10

    .line 101
    if-eqz v10, :cond_8

    .line 102
    .line 103
    const/16 v10, 0x800

    .line 104
    .line 105
    goto :goto_6

    .line 106
    :cond_8
    const/16 v10, 0x400

    .line 107
    .line 108
    :goto_6
    or-int/2addr v0, v10

    .line 109
    :cond_9
    and-int/lit16 v10, v0, 0x493

    .line 110
    .line 111
    const/16 v11, 0x492

    .line 112
    .line 113
    const/4 v13, 0x1

    .line 114
    const/4 v14, 0x0

    .line 115
    if-eq v10, v11, :cond_a

    .line 116
    .line 117
    move v10, v13

    .line 118
    goto :goto_7

    .line 119
    :cond_a
    move v10, v14

    .line 120
    :goto_7
    and-int/2addr v0, v13

    .line 121
    invoke-virtual {v9, v0, v10}, Ll2/t;->O(IZ)Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-eqz v0, :cond_17

    .line 126
    .line 127
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 128
    .line 129
    if-eqz v3, :cond_b

    .line 130
    .line 131
    move-object v3, v0

    .line 132
    goto :goto_8

    .line 133
    :cond_b
    move-object v3, v6

    .line 134
    :goto_8
    if-eqz v7, :cond_c

    .line 135
    .line 136
    move v15, v13

    .line 137
    goto :goto_9

    .line 138
    :cond_c
    move v15, v8

    .line 139
    :goto_9
    if-eqz v1, :cond_d

    .line 140
    .line 141
    sget-object v6, Li91/o0;->f:Li91/o0;

    .line 142
    .line 143
    goto :goto_a

    .line 144
    :cond_d
    sget-object v6, Li91/o0;->e:Li91/o0;

    .line 145
    .line 146
    :goto_a
    iget v6, v6, Li91/o0;->d:F

    .line 147
    .line 148
    const/16 v10, 0xc00

    .line 149
    .line 150
    const/16 v11, 0x16

    .line 151
    .line 152
    const/4 v7, 0x0

    .line 153
    const-string v8, "switch_animation_horizontal"

    .line 154
    .line 155
    invoke-static/range {v6 .. v11}, Lc1/e;->b(FLc1/a0;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    new-instance v7, Lx2/h;

    .line 160
    .line 161
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v6

    .line 165
    check-cast v6, Ljava/lang/Number;

    .line 166
    .line 167
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 168
    .line 169
    .line 170
    move-result v6

    .line 171
    invoke-direct {v7, v6}, Lx2/h;-><init>(F)V

    .line 172
    .line 173
    .line 174
    if-eqz v15, :cond_f

    .line 175
    .line 176
    const v6, 0x69b90466

    .line 177
    .line 178
    .line 179
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 180
    .line 181
    .line 182
    if-eqz v1, :cond_e

    .line 183
    .line 184
    const v6, 0x69b9606e

    .line 185
    .line 186
    .line 187
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 188
    .line 189
    .line 190
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 191
    .line 192
    invoke-virtual {v9, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v6

    .line 196
    check-cast v6, Lj91/e;

    .line 197
    .line 198
    invoke-virtual {v6}, Lj91/e;->e()J

    .line 199
    .line 200
    .line 201
    move-result-wide v10

    .line 202
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 203
    .line 204
    .line 205
    goto :goto_b

    .line 206
    :cond_e
    const v6, 0x69ba640e

    .line 207
    .line 208
    .line 209
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 210
    .line 211
    .line 212
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 213
    .line 214
    invoke-virtual {v9, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v6

    .line 218
    check-cast v6, Lj91/e;

    .line 219
    .line 220
    invoke-virtual {v6}, Lj91/e;->t()J

    .line 221
    .line 222
    .line 223
    move-result-wide v10

    .line 224
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 225
    .line 226
    .line 227
    :goto_b
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 228
    .line 229
    .line 230
    goto :goto_c

    .line 231
    :cond_f
    const v6, 0x69bb8db4

    .line 232
    .line 233
    .line 234
    invoke-virtual {v9, v6}, Ll2/t;->Y(I)V

    .line 235
    .line 236
    .line 237
    sget-object v6, Lj91/h;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v9, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    check-cast v6, Lj91/e;

    .line 244
    .line 245
    invoke-virtual {v6}, Lj91/e;->r()J

    .line 246
    .line 247
    .line 248
    move-result-wide v10

    .line 249
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    :goto_c
    const/16 v6, 0x180

    .line 253
    .line 254
    const/16 v12, 0xa

    .line 255
    .line 256
    const/4 v8, 0x0

    .line 257
    move/from16 v16, v6

    .line 258
    .line 259
    move-wide/from16 v17, v10

    .line 260
    .line 261
    move-object v11, v7

    .line 262
    move-object v10, v9

    .line 263
    move-wide/from16 v6, v17

    .line 264
    .line 265
    const-string v9, "switch_animation_colors"

    .line 266
    .line 267
    move-object v13, v11

    .line 268
    move/from16 v11, v16

    .line 269
    .line 270
    invoke-static/range {v6 .. v12}, Lb1/a1;->a(JLc1/f1;Ljava/lang/String;Ll2/o;II)Ll2/t2;

    .line 271
    .line 272
    .line 273
    move-result-object v6

    .line 274
    move-object v9, v10

    .line 275
    sget-object v7, Lk1/j;->e:Lk1/f;

    .line 276
    .line 277
    sget v8, Li91/y3;->a:F

    .line 278
    .line 279
    sget v10, Li91/y3;->b:F

    .line 280
    .line 281
    invoke-static {v3, v8, v10}, Landroidx/compose/foundation/layout/d;->k(Lx2/s;FF)Lx2/s;

    .line 282
    .line 283
    .line 284
    move-result-object v8

    .line 285
    invoke-static {}, Ls1/f;->a()Ls1/e;

    .line 286
    .line 287
    .line 288
    move-result-object v10

    .line 289
    invoke-static {v8, v10}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 290
    .line 291
    .line 292
    move-result-object v8

    .line 293
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 294
    .line 295
    .line 296
    move-result-object v6

    .line 297
    check-cast v6, Le3/s;

    .line 298
    .line 299
    iget-wide v10, v6, Le3/s;->a:J

    .line 300
    .line 301
    sget-object v6, Le3/j0;->a:Le3/i0;

    .line 302
    .line 303
    invoke-static {v8, v10, v11, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 304
    .line 305
    .line 306
    move-result-object v6

    .line 307
    new-instance v8, Ld4/i;

    .line 308
    .line 309
    invoke-direct {v8, v2}, Ld4/i;-><init>(I)V

    .line 310
    .line 311
    .line 312
    invoke-static {v6, v1, v15, v8, v4}, Landroidx/compose/foundation/selection/b;->b(Lx2/s;ZZLd4/i;Lay0/k;)Lx2/s;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    sget v6, Li91/y3;->c:F

    .line 317
    .line 318
    invoke-static {v2, v6}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    const/4 v6, 0x6

    .line 323
    invoke-static {v7, v13, v9, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 324
    .line 325
    .line 326
    move-result-object v6

    .line 327
    iget-wide v7, v9, Ll2/t;->T:J

    .line 328
    .line 329
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 330
    .line 331
    .line 332
    move-result v7

    .line 333
    invoke-virtual {v9}, Ll2/t;->m()Ll2/p1;

    .line 334
    .line 335
    .line 336
    move-result-object v8

    .line 337
    invoke-static {v9, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 338
    .line 339
    .line 340
    move-result-object v2

    .line 341
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 342
    .line 343
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 344
    .line 345
    .line 346
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 347
    .line 348
    invoke-virtual {v9}, Ll2/t;->c0()V

    .line 349
    .line 350
    .line 351
    iget-boolean v11, v9, Ll2/t;->S:Z

    .line 352
    .line 353
    if-eqz v11, :cond_10

    .line 354
    .line 355
    invoke-virtual {v9, v10}, Ll2/t;->l(Lay0/a;)V

    .line 356
    .line 357
    .line 358
    goto :goto_d

    .line 359
    :cond_10
    invoke-virtual {v9}, Ll2/t;->m0()V

    .line 360
    .line 361
    .line 362
    :goto_d
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 363
    .line 364
    invoke-static {v10, v6, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 365
    .line 366
    .line 367
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 368
    .line 369
    invoke-static {v6, v8, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 370
    .line 371
    .line 372
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 373
    .line 374
    iget-boolean v8, v9, Ll2/t;->S:Z

    .line 375
    .line 376
    if-nez v8, :cond_11

    .line 377
    .line 378
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object v8

    .line 382
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 383
    .line 384
    .line 385
    move-result-object v10

    .line 386
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 387
    .line 388
    .line 389
    move-result v8

    .line 390
    if-nez v8, :cond_12

    .line 391
    .line 392
    :cond_11
    invoke-static {v7, v9, v7, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 393
    .line 394
    .line 395
    :cond_12
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 396
    .line 397
    invoke-static {v6, v2, v9}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 398
    .line 399
    .line 400
    if-eqz v15, :cond_13

    .line 401
    .line 402
    if-nez v1, :cond_14

    .line 403
    .line 404
    :cond_13
    if-eqz v15, :cond_15

    .line 405
    .line 406
    sget-boolean v2, Llp/nb;->a:Z

    .line 407
    .line 408
    if-nez v2, :cond_15

    .line 409
    .line 410
    :cond_14
    const v2, 0x2742f992

    .line 411
    .line 412
    .line 413
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 414
    .line 415
    .line 416
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 417
    .line 418
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 419
    .line 420
    .line 421
    move-result-object v2

    .line 422
    check-cast v2, Lj91/e;

    .line 423
    .line 424
    invoke-virtual {v2}, Lj91/e;->b()J

    .line 425
    .line 426
    .line 427
    move-result-wide v6

    .line 428
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 429
    .line 430
    .line 431
    goto :goto_e

    .line 432
    :cond_15
    if-eqz v15, :cond_16

    .line 433
    .line 434
    sget-boolean v2, Llp/nb;->a:Z

    .line 435
    .line 436
    if-eqz v2, :cond_16

    .line 437
    .line 438
    const v2, 0x274304ac

    .line 439
    .line 440
    .line 441
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 442
    .line 443
    .line 444
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 445
    .line 446
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v2

    .line 450
    check-cast v2, Lj91/e;

    .line 451
    .line 452
    invoke-virtual {v2}, Lj91/e;->q()J

    .line 453
    .line 454
    .line 455
    move-result-wide v6

    .line 456
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 457
    .line 458
    .line 459
    goto :goto_e

    .line 460
    :cond_16
    const v2, 0x27430acd

    .line 461
    .line 462
    .line 463
    invoke-virtual {v9, v2}, Ll2/t;->Y(I)V

    .line 464
    .line 465
    .line 466
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 467
    .line 468
    invoke-virtual {v9, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v2

    .line 472
    check-cast v2, Lj91/e;

    .line 473
    .line 474
    invoke-virtual {v2}, Lj91/e;->t()J

    .line 475
    .line 476
    .line 477
    move-result-wide v6

    .line 478
    invoke-virtual {v9, v14}, Ll2/t;->q(Z)V

    .line 479
    .line 480
    .line 481
    :goto_e
    sget v2, Li91/y3;->e:F

    .line 482
    .line 483
    sget v8, Li91/y3;->d:F

    .line 484
    .line 485
    invoke-static {v0, v2, v8}, Landroidx/compose/foundation/layout/d;->k(Lx2/s;FF)Lx2/s;

    .line 486
    .line 487
    .line 488
    move-result-object v0

    .line 489
    invoke-static {}, Ls1/f;->a()Ls1/e;

    .line 490
    .line 491
    .line 492
    move-result-object v2

    .line 493
    invoke-static {v0, v6, v7, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    invoke-static {v0, v9, v14}, Lk1/n;->a(Lx2/s;Ll2/o;I)V

    .line 498
    .line 499
    .line 500
    const/4 v0, 0x1

    .line 501
    invoke-virtual {v9, v0}, Ll2/t;->q(Z)V

    .line 502
    .line 503
    .line 504
    move-object v2, v3

    .line 505
    move v3, v15

    .line 506
    goto :goto_f

    .line 507
    :cond_17
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 508
    .line 509
    .line 510
    move-object v2, v6

    .line 511
    move v3, v8

    .line 512
    :goto_f
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 513
    .line 514
    .line 515
    move-result-object v7

    .line 516
    if-eqz v7, :cond_18

    .line 517
    .line 518
    new-instance v0, Lh60/d;

    .line 519
    .line 520
    move/from16 v6, p6

    .line 521
    .line 522
    invoke-direct/range {v0 .. v6}, Lh60/d;-><init>(ZLx2/s;ZLay0/k;II)V

    .line 523
    .line 524
    .line 525
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 526
    .line 527
    :cond_18
    return-void
.end method
