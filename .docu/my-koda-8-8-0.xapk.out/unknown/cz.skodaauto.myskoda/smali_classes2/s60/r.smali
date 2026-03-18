.class public final synthetic Ls60/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr60/w;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lr60/w;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Ls60/r;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ls60/r;->e:Lr60/w;

    .line 4
    .line 5
    iput-object p2, p0, Ls60/r;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ls60/r;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lb1/a0;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 21
    .line 22
    .line 23
    const-string v3, "$this$AnimatedVisibility"

    .line 24
    .line 25
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object v1, v0, Ls60/r;->e:Lr60/w;

    .line 29
    .line 30
    iget-object v3, v1, Lr60/w;->b:Lon0/e;

    .line 31
    .line 32
    const/4 v4, 0x0

    .line 33
    check-cast v2, Ll2/t;

    .line 34
    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    const v3, 0x35d75e68

    .line 38
    .line 39
    .line 40
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 41
    .line 42
    .line 43
    iget-object v1, v1, Lr60/w;->b:Lon0/e;

    .line 44
    .line 45
    const/16 v3, 0x8

    .line 46
    .line 47
    iget-object v0, v0, Ls60/r;->f:Lay0/k;

    .line 48
    .line 49
    invoke-static {v1, v0, v2, v3}, Ls60/a;->I(Lon0/e;Lay0/k;Ll2/o;I)V

    .line 50
    .line 51
    .line 52
    :goto_0
    invoke-virtual {v2, v4}, Ll2/t;->q(Z)V

    .line 53
    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_0
    const v0, 0x35921761

    .line 57
    .line 58
    .line 59
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object v0

    .line 66
    :pswitch_0
    move-object/from16 v1, p1

    .line 67
    .line 68
    check-cast v1, Landroidx/compose/foundation/lazy/a;

    .line 69
    .line 70
    move-object/from16 v2, p2

    .line 71
    .line 72
    check-cast v2, Ll2/o;

    .line 73
    .line 74
    move-object/from16 v3, p3

    .line 75
    .line 76
    check-cast v3, Ljava/lang/Integer;

    .line 77
    .line 78
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 79
    .line 80
    .line 81
    move-result v3

    .line 82
    const-string v4, "$this$item"

    .line 83
    .line 84
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    and-int/lit8 v1, v3, 0x11

    .line 88
    .line 89
    const/16 v4, 0x10

    .line 90
    .line 91
    const/4 v5, 0x0

    .line 92
    const/4 v6, 0x1

    .line 93
    if-eq v1, v4, :cond_1

    .line 94
    .line 95
    move v1, v6

    .line 96
    goto :goto_2

    .line 97
    :cond_1
    move v1, v5

    .line 98
    :goto_2
    and-int/2addr v3, v6

    .line 99
    move-object v13, v2

    .line 100
    check-cast v13, Ll2/t;

    .line 101
    .line 102
    invoke-virtual {v13, v3, v1}, Ll2/t;->O(IZ)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    if-eqz v1, :cond_3

    .line 107
    .line 108
    iget-object v1, v0, Ls60/r;->e:Lr60/w;

    .line 109
    .line 110
    iget-object v2, v1, Lr60/w;->b:Lon0/e;

    .line 111
    .line 112
    if-eqz v2, :cond_2

    .line 113
    .line 114
    move v7, v6

    .line 115
    goto :goto_3

    .line 116
    :cond_2
    move v7, v5

    .line 117
    :goto_3
    new-instance v2, Ls60/r;

    .line 118
    .line 119
    const/4 v3, 0x2

    .line 120
    iget-object v0, v0, Ls60/r;->f:Lay0/k;

    .line 121
    .line 122
    invoke-direct {v2, v1, v0, v3}, Ls60/r;-><init>(Lr60/w;Lay0/k;I)V

    .line 123
    .line 124
    .line 125
    const v0, 0x8bdb821

    .line 126
    .line 127
    .line 128
    invoke-static {v0, v13, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 129
    .line 130
    .line 131
    move-result-object v12

    .line 132
    const/high16 v14, 0x180000

    .line 133
    .line 134
    const/16 v15, 0x1e

    .line 135
    .line 136
    const/4 v8, 0x0

    .line 137
    const/4 v9, 0x0

    .line 138
    const/4 v10, 0x0

    .line 139
    const/4 v11, 0x0

    .line 140
    invoke-static/range {v7 .. v15}, Landroidx/compose/animation/b;->e(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 141
    .line 142
    .line 143
    goto :goto_4

    .line 144
    :cond_3
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 145
    .line 146
    .line 147
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object v0

    .line 150
    :pswitch_1
    move-object/from16 v1, p1

    .line 151
    .line 152
    check-cast v1, Lk1/z0;

    .line 153
    .line 154
    move-object/from16 v2, p2

    .line 155
    .line 156
    check-cast v2, Ll2/o;

    .line 157
    .line 158
    move-object/from16 v3, p3

    .line 159
    .line 160
    check-cast v3, Ljava/lang/Integer;

    .line 161
    .line 162
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 163
    .line 164
    .line 165
    move-result v3

    .line 166
    const-string v4, "paddingValues"

    .line 167
    .line 168
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    and-int/lit8 v4, v3, 0x6

    .line 172
    .line 173
    const/4 v5, 0x2

    .line 174
    if-nez v4, :cond_5

    .line 175
    .line 176
    move-object v4, v2

    .line 177
    check-cast v4, Ll2/t;

    .line 178
    .line 179
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v4

    .line 183
    if-eqz v4, :cond_4

    .line 184
    .line 185
    const/4 v4, 0x4

    .line 186
    goto :goto_5

    .line 187
    :cond_4
    move v4, v5

    .line 188
    :goto_5
    or-int/2addr v3, v4

    .line 189
    :cond_5
    and-int/lit8 v4, v3, 0x13

    .line 190
    .line 191
    const/16 v6, 0x12

    .line 192
    .line 193
    const/4 v7, 0x1

    .line 194
    const/4 v8, 0x0

    .line 195
    if-eq v4, v6, :cond_6

    .line 196
    .line 197
    move v4, v7

    .line 198
    goto :goto_6

    .line 199
    :cond_6
    move v4, v8

    .line 200
    :goto_6
    and-int/2addr v3, v7

    .line 201
    check-cast v2, Ll2/t;

    .line 202
    .line 203
    invoke-virtual {v2, v3, v4}, Ll2/t;->O(IZ)Z

    .line 204
    .line 205
    .line 206
    move-result v3

    .line 207
    if-eqz v3, :cond_f

    .line 208
    .line 209
    invoke-interface {v1}, Lk1/z0;->d()F

    .line 210
    .line 211
    .line 212
    move-result v11

    .line 213
    const/4 v13, 0x0

    .line 214
    const/16 v14, 0xd

    .line 215
    .line 216
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 217
    .line 218
    const/4 v10, 0x0

    .line 219
    const/4 v12, 0x0

    .line 220
    invoke-static/range {v9 .. v14}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    sget-object v3, Lj91/h;->a:Ll2/u2;

    .line 225
    .line 226
    invoke-virtual {v2, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v3

    .line 230
    check-cast v3, Lj91/e;

    .line 231
    .line 232
    invoke-virtual {v3}, Lj91/e;->b()J

    .line 233
    .line 234
    .line 235
    move-result-wide v3

    .line 236
    sget-object v6, Le3/j0;->a:Le3/i0;

    .line 237
    .line 238
    invoke-static {v1, v3, v4, v6}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 239
    .line 240
    .line 241
    move-result-object v1

    .line 242
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 243
    .line 244
    invoke-interface {v1, v3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 245
    .line 246
    .line 247
    move-result-object v1

    .line 248
    sget-object v3, Lk1/j;->c:Lk1/e;

    .line 249
    .line 250
    sget-object v4, Lx2/c;->p:Lx2/h;

    .line 251
    .line 252
    invoke-static {v3, v4, v2, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 253
    .line 254
    .line 255
    move-result-object v3

    .line 256
    iget-wide v10, v2, Ll2/t;->T:J

    .line 257
    .line 258
    invoke-static {v10, v11}, Ljava/lang/Long;->hashCode(J)I

    .line 259
    .line 260
    .line 261
    move-result v4

    .line 262
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 263
    .line 264
    .line 265
    move-result-object v6

    .line 266
    invoke-static {v2, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 267
    .line 268
    .line 269
    move-result-object v1

    .line 270
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 271
    .line 272
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 276
    .line 277
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 278
    .line 279
    .line 280
    iget-boolean v11, v2, Ll2/t;->S:Z

    .line 281
    .line 282
    if-eqz v11, :cond_7

    .line 283
    .line 284
    invoke-virtual {v2, v10}, Ll2/t;->l(Lay0/a;)V

    .line 285
    .line 286
    .line 287
    goto :goto_7

    .line 288
    :cond_7
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 289
    .line 290
    .line 291
    :goto_7
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 292
    .line 293
    invoke-static {v10, v3, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 294
    .line 295
    .line 296
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 297
    .line 298
    invoke-static {v3, v6, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 299
    .line 300
    .line 301
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 302
    .line 303
    iget-boolean v6, v2, Ll2/t;->S:Z

    .line 304
    .line 305
    if-nez v6, :cond_8

    .line 306
    .line 307
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v6

    .line 311
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 312
    .line 313
    .line 314
    move-result-object v10

    .line 315
    invoke-static {v6, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    move-result v6

    .line 319
    if-nez v6, :cond_9

    .line 320
    .line 321
    :cond_8
    invoke-static {v4, v2, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 322
    .line 323
    .line 324
    :cond_9
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 325
    .line 326
    invoke-static {v3, v1, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 327
    .line 328
    .line 329
    iget-object v1, v0, Ls60/r;->e:Lr60/w;

    .line 330
    .line 331
    iget-object v3, v1, Lr60/w;->a:Ljava/util/List;

    .line 332
    .line 333
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 334
    .line 335
    .line 336
    move-result v3

    .line 337
    if-eqz v3, :cond_c

    .line 338
    .line 339
    const v0, 0x341fd7c

    .line 340
    .line 341
    .line 342
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 343
    .line 344
    .line 345
    const/high16 v0, 0x3f800000    # 1.0f

    .line 346
    .line 347
    float-to-double v3, v0

    .line 348
    const-wide/16 v31, 0x0

    .line 349
    .line 350
    cmpl-double v1, v3, v31

    .line 351
    .line 352
    const-string v3, "invalid weight; must be greater than zero"

    .line 353
    .line 354
    if-lez v1, :cond_a

    .line 355
    .line 356
    goto :goto_8

    .line 357
    :cond_a
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    :goto_8
    new-instance v1, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 361
    .line 362
    invoke-direct {v1, v0, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 363
    .line 364
    .line 365
    invoke-static {v2, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 366
    .line 367
    .line 368
    const v1, 0x7f120e39

    .line 369
    .line 370
    .line 371
    invoke-static {v2, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v1

    .line 375
    sget-object v4, Lj91/j;->a:Ll2/u2;

    .line 376
    .line 377
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    check-cast v4, Lj91/f;

    .line 382
    .line 383
    invoke-virtual {v4}, Lj91/f;->b()Lg4/p0;

    .line 384
    .line 385
    .line 386
    move-result-object v10

    .line 387
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 388
    .line 389
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    move-result-object v4

    .line 393
    check-cast v4, Lj91/c;

    .line 394
    .line 395
    iget v4, v4, Lj91/c;->d:F

    .line 396
    .line 397
    const/4 v6, 0x0

    .line 398
    invoke-static {v9, v4, v6, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 399
    .line 400
    .line 401
    move-result-object v4

    .line 402
    sget-object v5, Lx2/c;->q:Lx2/h;

    .line 403
    .line 404
    invoke-static {v5, v4}, Lia/b;->p(Lx2/h;Lx2/s;)Lx2/s;

    .line 405
    .line 406
    .line 407
    move-result-object v11

    .line 408
    const/16 v29, 0x0

    .line 409
    .line 410
    const v30, 0xfff8

    .line 411
    .line 412
    .line 413
    const-wide/16 v12, 0x0

    .line 414
    .line 415
    const-wide/16 v14, 0x0

    .line 416
    .line 417
    const/16 v16, 0x0

    .line 418
    .line 419
    const-wide/16 v17, 0x0

    .line 420
    .line 421
    const/16 v19, 0x0

    .line 422
    .line 423
    const/16 v20, 0x0

    .line 424
    .line 425
    const-wide/16 v21, 0x0

    .line 426
    .line 427
    const/16 v23, 0x0

    .line 428
    .line 429
    const/16 v24, 0x0

    .line 430
    .line 431
    const/16 v25, 0x0

    .line 432
    .line 433
    const/16 v26, 0x0

    .line 434
    .line 435
    const/16 v28, 0x0

    .line 436
    .line 437
    move-object v9, v1

    .line 438
    move-object/from16 v27, v2

    .line 439
    .line 440
    invoke-static/range {v9 .. v30}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 441
    .line 442
    .line 443
    float-to-double v4, v0

    .line 444
    cmpl-double v1, v4, v31

    .line 445
    .line 446
    if-lez v1, :cond_b

    .line 447
    .line 448
    goto :goto_9

    .line 449
    :cond_b
    invoke-static {v3}, Ll1/a;->a(Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    :goto_9
    new-instance v1, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 453
    .line 454
    invoke-direct {v1, v0, v7}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 455
    .line 456
    .line 457
    invoke-static {v2, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v2, v8}, Ll2/t;->q(Z)V

    .line 461
    .line 462
    .line 463
    goto :goto_a

    .line 464
    :cond_c
    const v3, 0x34a8053

    .line 465
    .line 466
    .line 467
    invoke-virtual {v2, v3}, Ll2/t;->Y(I)V

    .line 468
    .line 469
    .line 470
    invoke-virtual {v2, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    move-result v3

    .line 474
    iget-object v0, v0, Ls60/r;->f:Lay0/k;

    .line 475
    .line 476
    invoke-virtual {v2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 477
    .line 478
    .line 479
    move-result v4

    .line 480
    or-int/2addr v3, v4

    .line 481
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object v4

    .line 485
    if-nez v3, :cond_d

    .line 486
    .line 487
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 488
    .line 489
    if-ne v4, v3, :cond_e

    .line 490
    .line 491
    :cond_d
    new-instance v4, Lod0/n;

    .line 492
    .line 493
    const/16 v3, 0x13

    .line 494
    .line 495
    invoke-direct {v4, v3, v1, v0}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 496
    .line 497
    .line 498
    invoke-virtual {v2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    :cond_e
    move-object/from16 v17, v4

    .line 502
    .line 503
    check-cast v17, Lay0/k;

    .line 504
    .line 505
    const/16 v19, 0x0

    .line 506
    .line 507
    const/16 v20, 0x1ff

    .line 508
    .line 509
    const/4 v9, 0x0

    .line 510
    const/4 v10, 0x0

    .line 511
    const/4 v11, 0x0

    .line 512
    const/4 v12, 0x0

    .line 513
    const/4 v13, 0x0

    .line 514
    const/4 v14, 0x0

    .line 515
    const/4 v15, 0x0

    .line 516
    const/16 v16, 0x0

    .line 517
    .line 518
    move-object/from16 v18, v2

    .line 519
    .line 520
    invoke-static/range {v9 .. v20}, La/a;->a(Lx2/s;Lm1/t;Lk1/z0;Lk1/i;Lx2/d;Lg1/j1;ZLe1/j;Lay0/k;Ll2/o;II)V

    .line 521
    .line 522
    .line 523
    invoke-virtual {v2, v8}, Ll2/t;->q(Z)V

    .line 524
    .line 525
    .line 526
    :goto_a
    invoke-virtual {v2, v7}, Ll2/t;->q(Z)V

    .line 527
    .line 528
    .line 529
    goto :goto_b

    .line 530
    :cond_f
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 531
    .line 532
    .line 533
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 534
    .line 535
    return-object v0

    .line 536
    nop

    .line 537
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
