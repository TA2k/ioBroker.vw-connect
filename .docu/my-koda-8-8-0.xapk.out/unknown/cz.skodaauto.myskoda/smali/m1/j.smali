.class public final Lm1/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/c0;


# instance fields
.field public final synthetic a:Lm1/t;

.field public final synthetic b:Z

.field public final synthetic c:Lk1/z0;

.field public final synthetic d:Lay0/a;

.field public final synthetic e:Lk1/i;

.field public final synthetic f:Lk1/g;

.field public final synthetic g:Lvy0/b0;

.field public final synthetic h:Le3/w;

.field public final synthetic i:Lo1/f0;

.field public final synthetic j:Lx2/d;

.field public final synthetic k:Lx2/i;


# direct methods
.method public constructor <init>(Lm1/t;ZLk1/z0;Lhy0/u;Lk1/i;Lk1/g;Lvy0/b0;Le3/w;Lo1/f0;Lx2/d;Lx2/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm1/j;->a:Lm1/t;

    .line 5
    .line 6
    iput-boolean p2, p0, Lm1/j;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lm1/j;->c:Lk1/z0;

    .line 9
    .line 10
    iput-object p4, p0, Lm1/j;->d:Lay0/a;

    .line 11
    .line 12
    iput-object p5, p0, Lm1/j;->e:Lk1/i;

    .line 13
    .line 14
    iput-object p6, p0, Lm1/j;->f:Lk1/g;

    .line 15
    .line 16
    iput-object p7, p0, Lm1/j;->g:Lvy0/b0;

    .line 17
    .line 18
    iput-object p8, p0, Lm1/j;->h:Le3/w;

    .line 19
    .line 20
    iput-object p9, p0, Lm1/j;->i:Lo1/f0;

    .line 21
    .line 22
    iput-object p10, p0, Lm1/j;->j:Lx2/d;

    .line 23
    .line 24
    iput-object p11, p0, Lm1/j;->k:Lx2/i;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a(Lo1/d0;J)Lt3/r0;
    .locals 60

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    move-wide/from16 v1, p2

    .line 6
    .line 7
    iget-object v3, v9, Lo1/d0;->e:Lt3/p1;

    .line 8
    .line 9
    iget-object v4, v0, Lm1/j;->a:Lm1/t;

    .line 10
    .line 11
    iget-object v5, v4, Lm1/t;->s:Ll2/b1;

    .line 12
    .line 13
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    iget-boolean v5, v4, Lm1/t;->b:Z

    .line 17
    .line 18
    const/16 v16, 0x1

    .line 19
    .line 20
    if-nez v5, :cond_1

    .line 21
    .line 22
    invoke-interface {v3}, Lt3/t;->I()Z

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    if-eqz v5, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/16 v27, 0x0

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    :goto_0
    move/from16 v27, v16

    .line 33
    .line 34
    :goto_1
    iget-boolean v5, v0, Lm1/j;->b:Z

    .line 35
    .line 36
    if-eqz v5, :cond_2

    .line 37
    .line 38
    sget-object v7, Lg1/w1;->d:Lg1/w1;

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    sget-object v7, Lg1/w1;->e:Lg1/w1;

    .line 42
    .line 43
    :goto_2
    invoke-static {v1, v2, v7}, Lkp/j;->a(JLg1/w1;)V

    .line 44
    .line 45
    .line 46
    iget-object v7, v0, Lm1/j;->c:Lk1/z0;

    .line 47
    .line 48
    if-eqz v5, :cond_3

    .line 49
    .line 50
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 51
    .line 52
    .line 53
    move-result-object v8

    .line 54
    invoke-interface {v7, v8}, Lk1/z0;->b(Lt4/m;)F

    .line 55
    .line 56
    .line 57
    move-result v8

    .line 58
    invoke-interface {v3, v8}, Lt4/c;->Q(F)I

    .line 59
    .line 60
    .line 61
    move-result v8

    .line 62
    goto :goto_3

    .line 63
    :cond_3
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    invoke-static {v7, v8}, Landroidx/compose/foundation/layout/a;->f(Lk1/z0;Lt4/m;)F

    .line 68
    .line 69
    .line 70
    move-result v8

    .line 71
    invoke-interface {v3, v8}, Lt4/c;->Q(F)I

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    :goto_3
    if-eqz v5, :cond_4

    .line 76
    .line 77
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 78
    .line 79
    .line 80
    move-result-object v10

    .line 81
    invoke-interface {v7, v10}, Lk1/z0;->a(Lt4/m;)F

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    invoke-interface {v3, v10}, Lt4/c;->Q(F)I

    .line 86
    .line 87
    .line 88
    move-result v10

    .line 89
    goto :goto_4

    .line 90
    :cond_4
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 91
    .line 92
    .line 93
    move-result-object v10

    .line 94
    invoke-static {v7, v10}, Landroidx/compose/foundation/layout/a;->e(Lk1/z0;Lt4/m;)F

    .line 95
    .line 96
    .line 97
    move-result v10

    .line 98
    invoke-interface {v3, v10}, Lt4/c;->Q(F)I

    .line 99
    .line 100
    .line 101
    move-result v10

    .line 102
    :goto_4
    invoke-interface {v7}, Lk1/z0;->d()F

    .line 103
    .line 104
    .line 105
    move-result v11

    .line 106
    invoke-interface {v3, v11}, Lt4/c;->Q(F)I

    .line 107
    .line 108
    .line 109
    move-result v11

    .line 110
    invoke-interface {v7}, Lk1/z0;->c()F

    .line 111
    .line 112
    .line 113
    move-result v7

    .line 114
    invoke-interface {v3, v7}, Lt4/c;->Q(F)I

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    add-int/2addr v7, v11

    .line 119
    add-int v12, v8, v10

    .line 120
    .line 121
    if-eqz v5, :cond_5

    .line 122
    .line 123
    move v13, v7

    .line 124
    goto :goto_5

    .line 125
    :cond_5
    move v13, v12

    .line 126
    :goto_5
    if-eqz v5, :cond_6

    .line 127
    .line 128
    move/from16 v22, v11

    .line 129
    .line 130
    goto :goto_6

    .line 131
    :cond_6
    if-nez v5, :cond_7

    .line 132
    .line 133
    move/from16 v22, v8

    .line 134
    .line 135
    goto :goto_6

    .line 136
    :cond_7
    move/from16 v22, v10

    .line 137
    .line 138
    :goto_6
    sub-int v17, v13, v22

    .line 139
    .line 140
    neg-int v10, v12

    .line 141
    neg-int v13, v7

    .line 142
    invoke-static {v1, v2, v10, v13}, Lt4/b;->i(JII)J

    .line 143
    .line 144
    .line 145
    move-result-wide v13

    .line 146
    iget-object v10, v0, Lm1/j;->d:Lay0/a;

    .line 147
    .line 148
    invoke-interface {v10}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v10

    .line 152
    check-cast v10, Lm1/h;

    .line 153
    .line 154
    iget-object v15, v10, Lm1/h;->c:Landroidx/compose/foundation/lazy/a;

    .line 155
    .line 156
    invoke-static {v13, v14}, Lt4/a;->h(J)I

    .line 157
    .line 158
    .line 159
    move-result v6

    .line 160
    invoke-static {v13, v14}, Lt4/a;->g(J)I

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    iget-object v2, v15, Landroidx/compose/foundation/lazy/a;->a:Ll2/g1;

    .line 165
    .line 166
    invoke-virtual {v2, v6}, Ll2/g1;->p(I)V

    .line 167
    .line 168
    .line 169
    iget-object v2, v15, Landroidx/compose/foundation/lazy/a;->b:Ll2/g1;

    .line 170
    .line 171
    invoke-virtual {v2, v1}, Ll2/g1;->p(I)V

    .line 172
    .line 173
    .line 174
    iget-object v1, v0, Lm1/j;->f:Lk1/g;

    .line 175
    .line 176
    const-string v19, "null verticalArrangement when isVertical == true"

    .line 177
    .line 178
    iget-object v2, v0, Lm1/j;->e:Lk1/i;

    .line 179
    .line 180
    if-eqz v5, :cond_9

    .line 181
    .line 182
    if-eqz v2, :cond_8

    .line 183
    .line 184
    invoke-interface {v2}, Lk1/i;->a()F

    .line 185
    .line 186
    .line 187
    move-result v6

    .line 188
    goto :goto_7

    .line 189
    :cond_8
    invoke-static/range {v19 .. v19}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 190
    .line 191
    .line 192
    new-instance v0, La8/r0;

    .line 193
    .line 194
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 195
    .line 196
    .line 197
    throw v0

    .line 198
    :cond_9
    if-eqz v1, :cond_71

    .line 199
    .line 200
    invoke-interface {v1}, Lk1/g;->a()F

    .line 201
    .line 202
    .line 203
    move-result v6

    .line 204
    :goto_7
    invoke-interface {v3, v6}, Lt4/c;->Q(F)I

    .line 205
    .line 206
    .line 207
    move-result v6

    .line 208
    iget-object v15, v10, Lm1/h;->b:Lm1/f;

    .line 209
    .line 210
    invoke-virtual {v15}, Lm1/f;->k()Lbb/g0;

    .line 211
    .line 212
    .line 213
    move-result-object v15

    .line 214
    iget v15, v15, Lbb/g0;->e:I

    .line 215
    .line 216
    if-eqz v5, :cond_a

    .line 217
    .line 218
    invoke-static/range {p2 .. p3}, Lt4/a;->g(J)I

    .line 219
    .line 220
    .line 221
    move-result v5

    .line 222
    sub-int/2addr v5, v7

    .line 223
    :goto_8
    move-object/from16 v20, v1

    .line 224
    .line 225
    move-object/from16 v21, v2

    .line 226
    .line 227
    goto :goto_9

    .line 228
    :cond_a
    invoke-static/range {p2 .. p3}, Lt4/a;->h(J)I

    .line 229
    .line 230
    .line 231
    move-result v5

    .line 232
    sub-int/2addr v5, v12

    .line 233
    goto :goto_8

    .line 234
    :goto_9
    int-to-long v1, v8

    .line 235
    const/16 v32, 0x20

    .line 236
    .line 237
    shl-long v1, v1, v32

    .line 238
    .line 239
    move-wide/from16 v23, v1

    .line 240
    .line 241
    int-to-long v1, v11

    .line 242
    const-wide v33, 0xffffffffL

    .line 243
    .line 244
    .line 245
    .line 246
    .line 247
    and-long v1, v1, v33

    .line 248
    .line 249
    or-long v1, v23, v1

    .line 250
    .line 251
    new-instance v23, Lm1/i;

    .line 252
    .line 253
    move v8, v5

    .line 254
    move-object v5, v10

    .line 255
    iget-object v10, v0, Lm1/j;->k:Lx2/i;

    .line 256
    .line 257
    move v11, v7

    .line 258
    move v7, v15

    .line 259
    iget-object v15, v0, Lm1/j;->a:Lm1/t;

    .line 260
    .line 261
    move-object/from16 v24, v4

    .line 262
    .line 263
    iget-boolean v4, v0, Lm1/j;->b:Z

    .line 264
    .line 265
    iget-object v9, v0, Lm1/j;->j:Lx2/d;

    .line 266
    .line 267
    move-object/from16 v36, v3

    .line 268
    .line 269
    move/from16 v39, v8

    .line 270
    .line 271
    move/from16 v37, v11

    .line 272
    .line 273
    move/from16 v38, v12

    .line 274
    .line 275
    move/from16 v12, v17

    .line 276
    .line 277
    move-object/from16 v40, v21

    .line 278
    .line 279
    move/from16 v11, v22

    .line 280
    .line 281
    move-object/from16 v0, v24

    .line 282
    .line 283
    move v8, v6

    .line 284
    move-object/from16 v6, p1

    .line 285
    .line 286
    move-wide/from16 v58, v1

    .line 287
    .line 288
    move-object/from16 v1, v23

    .line 289
    .line 290
    move-wide v2, v13

    .line 291
    move-wide/from16 v13, v58

    .line 292
    .line 293
    invoke-direct/range {v1 .. v15}, Lm1/i;-><init>(JZLm1/h;Lo1/d0;IILx2/d;Lx2/i;IIJLm1/t;)V

    .line 294
    .line 295
    .line 296
    move v15, v7

    .line 297
    move-wide/from16 v58, v2

    .line 298
    .line 299
    move-object v2, v1

    .line 300
    move v1, v8

    .line 301
    move-wide/from16 v7, v58

    .line 302
    .line 303
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 304
    .line 305
    .line 306
    move-result-object v3

    .line 307
    if-eqz v3, :cond_b

    .line 308
    .line 309
    invoke-virtual {v3}, Lv2/f;->e()Lay0/k;

    .line 310
    .line 311
    .line 312
    move-result-object v4

    .line 313
    goto :goto_a

    .line 314
    :cond_b
    const/4 v4, 0x0

    .line 315
    :goto_a
    invoke-static {v3}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 316
    .line 317
    .line 318
    move-result-object v6

    .line 319
    :try_start_0
    iget-object v10, v0, Lm1/t;->e:Lm1/o;

    .line 320
    .line 321
    iget-object v13, v10, Lm1/o;->b:Ll2/g1;

    .line 322
    .line 323
    invoke-virtual {v13}, Ll2/g1;->o()I

    .line 324
    .line 325
    .line 326
    move-result v13

    .line 327
    iget-object v14, v10, Lm1/o;->e:Ljava/lang/Object;

    .line 328
    .line 329
    invoke-static {v13, v14, v5}, Lo1/y;->i(ILjava/lang/Object;Lo1/b0;)I

    .line 330
    .line 331
    .line 332
    move-result v14

    .line 333
    if-eq v13, v14, :cond_c

    .line 334
    .line 335
    iget-object v9, v10, Lm1/o;->b:Ll2/g1;

    .line 336
    .line 337
    invoke-virtual {v9, v14}, Ll2/g1;->p(I)V

    .line 338
    .line 339
    .line 340
    iget-object v9, v10, Lm1/o;->f:Lo1/g0;

    .line 341
    .line 342
    invoke-virtual {v9, v13}, Lo1/g0;->a(I)V

    .line 343
    .line 344
    .line 345
    goto :goto_b

    .line 346
    :catchall_0
    move-exception v0

    .line 347
    goto/16 :goto_59

    .line 348
    .line 349
    :cond_c
    :goto_b
    iget-object v9, v10, Lm1/o;->c:Ll2/g1;

    .line 350
    .line 351
    invoke-virtual {v9}, Ll2/g1;->o()I

    .line 352
    .line 353
    .line 354
    move-result v9
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 355
    invoke-static {v3, v6, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 356
    .line 357
    .line 358
    iget-object v3, v0, Lm1/t;->r:Lo1/i0;

    .line 359
    .line 360
    iget-object v4, v0, Lm1/t;->o:Lg1/r;

    .line 361
    .line 362
    invoke-static {v5, v3, v4}, Lo1/y;->g(Lo1/b0;Lo1/i0;Lg1/r;)Ljava/util/List;

    .line 363
    .line 364
    .line 365
    move-result-object v3

    .line 366
    invoke-interface/range {v36 .. v36}, Lt3/t;->I()Z

    .line 367
    .line 368
    .line 369
    move-result v4

    .line 370
    if-nez v4, :cond_e

    .line 371
    .line 372
    if-nez v27, :cond_d

    .line 373
    .line 374
    goto :goto_c

    .line 375
    :cond_d
    iget-object v4, v0, Lm1/t;->w:Lb81/a;

    .line 376
    .line 377
    iget-object v4, v4, Lb81/a;->f:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast v4, Lc1/k;

    .line 380
    .line 381
    iget-object v4, v4, Lc1/k;->e:Ll2/j1;

    .line 382
    .line 383
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    check-cast v4, Ljava/lang/Number;

    .line 388
    .line 389
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 390
    .line 391
    .line 392
    move-result v4

    .line 393
    goto :goto_d

    .line 394
    :cond_e
    :goto_c
    iget v4, v0, Lm1/t;->h:F

    .line 395
    .line 396
    :goto_d
    iget-object v5, v0, Lm1/t;->n:Landroidx/compose/foundation/lazy/layout/b;

    .line 397
    .line 398
    invoke-interface/range {v36 .. v36}, Lt3/t;->I()Z

    .line 399
    .line 400
    .line 401
    move-result v25

    .line 402
    iget-object v6, v0, Lm1/t;->c:Lm1/l;

    .line 403
    .line 404
    iget-object v10, v0, Lm1/t;->v:Ll2/b1;

    .line 405
    .line 406
    if-ltz v11, :cond_f

    .line 407
    .line 408
    goto :goto_e

    .line 409
    :cond_f
    const-string v13, "invalid beforeContentPadding"

    .line 410
    .line 411
    invoke-static {v13}, Lj1/b;->a(Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    :goto_e
    if-ltz v12, :cond_10

    .line 415
    .line 416
    goto :goto_f

    .line 417
    :cond_10
    const-string v13, "invalid afterContentPadding"

    .line 418
    .line 419
    invoke-static {v13}, Lj1/b;->a(Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    :goto_f
    sget-object v13, Lmx0/t;->d:Lmx0/t;

    .line 423
    .line 424
    move-object/from16 v41, v0

    .line 425
    .line 426
    iget-object v0, v2, Lm1/i;->f:Lm1/h;

    .line 427
    .line 428
    move/from16 v42, v1

    .line 429
    .line 430
    move/from16 v17, v9

    .line 431
    .line 432
    move-object/from16 v9, p0

    .line 433
    .line 434
    iget-boolean v1, v9, Lm1/j;->b:Z

    .line 435
    .line 436
    move/from16 v24, v1

    .line 437
    .line 438
    iget-object v1, v9, Lm1/j;->g:Lvy0/b0;

    .line 439
    .line 440
    move-object/from16 v30, v1

    .line 441
    .line 442
    iget-object v1, v9, Lm1/j;->h:Le3/w;

    .line 443
    .line 444
    move-object/from16 v43, v10

    .line 445
    .line 446
    const-wide/16 v9, 0x0

    .line 447
    .line 448
    move/from16 v44, v12

    .line 449
    .line 450
    sget-object v12, Lmx0/s;->d:Lmx0/s;

    .line 451
    .line 452
    if-gtz v15, :cond_13

    .line 453
    .line 454
    invoke-static {v7, v8}, Lt4/a;->j(J)I

    .line 455
    .line 456
    .line 457
    move-result v19

    .line 458
    invoke-static {v7, v8}, Lt4/a;->i(J)I

    .line 459
    .line 460
    .line 461
    move-result v20

    .line 462
    new-instance v21, Ljava/util/ArrayList;

    .line 463
    .line 464
    invoke-direct/range {v21 .. v21}, Ljava/util/ArrayList;-><init>()V

    .line 465
    .line 466
    .line 467
    iget-object v0, v0, Lm1/h;->d:Lbb/g0;

    .line 468
    .line 469
    const/16 v28, 0x0

    .line 470
    .line 471
    const/16 v29, 0x0

    .line 472
    .line 473
    const/16 v18, 0x0

    .line 474
    .line 475
    const/16 v26, 0x1

    .line 476
    .line 477
    move-object/from16 v22, v0

    .line 478
    .line 479
    move-object/from16 v31, v1

    .line 480
    .line 481
    move-object/from16 v23, v2

    .line 482
    .line 483
    move-object/from16 v17, v5

    .line 484
    .line 485
    invoke-virtual/range {v17 .. v31}, Landroidx/compose/foundation/lazy/layout/b;->d(IIILjava/util/ArrayList;Lbb/g0;Lap0/o;ZZIZIILvy0/b0;Le3/w;)V

    .line 486
    .line 487
    .line 488
    move-object/from16 v18, v17

    .line 489
    .line 490
    move-object/from16 v1, v23

    .line 491
    .line 492
    if-nez v25, :cond_11

    .line 493
    .line 494
    invoke-virtual/range {v18 .. v18}, Landroidx/compose/foundation/lazy/layout/b;->b()J

    .line 495
    .line 496
    .line 497
    move-result-wide v2

    .line 498
    invoke-static {v2, v3, v9, v10}, Lt4/l;->a(JJ)Z

    .line 499
    .line 500
    .line 501
    move-result v0

    .line 502
    if-nez v0, :cond_11

    .line 503
    .line 504
    shr-long v4, v2, v32

    .line 505
    .line 506
    long-to-int v0, v4

    .line 507
    invoke-static {v0, v7, v8}, Lt4/b;->g(IJ)I

    .line 508
    .line 509
    .line 510
    move-result v19

    .line 511
    and-long v2, v2, v33

    .line 512
    .line 513
    long-to-int v0, v2

    .line 514
    invoke-static {v0, v7, v8}, Lt4/b;->f(IJ)I

    .line 515
    .line 516
    .line 517
    move-result v20

    .line 518
    :cond_11
    new-instance v0, Ldj/a;

    .line 519
    .line 520
    const/16 v2, 0xe

    .line 521
    .line 522
    invoke-direct {v0, v2}, Ldj/a;-><init>(I)V

    .line 523
    .line 524
    .line 525
    add-int v2, v19, v38

    .line 526
    .line 527
    move-wide/from16 v3, p2

    .line 528
    .line 529
    invoke-static {v2, v3, v4}, Lt4/b;->g(IJ)I

    .line 530
    .line 531
    .line 532
    move-result v2

    .line 533
    add-int v5, v20, v37

    .line 534
    .line 535
    invoke-static {v5, v3, v4}, Lt4/b;->f(IJ)I

    .line 536
    .line 537
    .line 538
    move-result v3

    .line 539
    move-object/from16 v4, v36

    .line 540
    .line 541
    invoke-interface {v4, v2, v3, v13, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 542
    .line 543
    .line 544
    move-result-object v5

    .line 545
    neg-int v13, v11

    .line 546
    move/from16 v2, v39

    .line 547
    .line 548
    add-int v14, v2, v44

    .line 549
    .line 550
    if-eqz v24, :cond_12

    .line 551
    .line 552
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 553
    .line 554
    :goto_10
    move-object/from16 v16, v0

    .line 555
    .line 556
    goto :goto_11

    .line 557
    :cond_12
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 558
    .line 559
    goto :goto_10

    .line 560
    :goto_11
    new-instance v0, Lm1/l;

    .line 561
    .line 562
    const/4 v7, 0x0

    .line 563
    const/4 v15, 0x0

    .line 564
    const/4 v2, 0x0

    .line 565
    move-object v3, v2

    .line 566
    const/4 v2, 0x0

    .line 567
    move-object v6, v3

    .line 568
    const/4 v3, 0x0

    .line 569
    move-object/from16 v36, v4

    .line 570
    .line 571
    const/4 v4, 0x0

    .line 572
    move-object v8, v6

    .line 573
    const/4 v6, 0x0

    .line 574
    iget-wide v10, v1, Lm1/i;->h:J

    .line 575
    .line 576
    move-object/from16 v9, p1

    .line 577
    .line 578
    move-object v1, v8

    .line 579
    move-object/from16 v8, v30

    .line 580
    .line 581
    move-object/from16 v45, v36

    .line 582
    .line 583
    move-object/from16 v46, v41

    .line 584
    .line 585
    move/from16 v18, v42

    .line 586
    .line 587
    move/from16 v17, v44

    .line 588
    .line 589
    invoke-direct/range {v0 .. v18}, Lm1/l;-><init>(Lm1/m;IZFLt3/r0;FZLvy0/b0;Lt4/c;JLjava/util/List;IIILg1/w1;II)V

    .line 590
    .line 591
    .line 592
    goto/16 :goto_58

    .line 593
    .line 594
    :cond_13
    move-object/from16 v31, v1

    .line 595
    .line 596
    move-object v1, v2

    .line 597
    move-object/from16 v18, v5

    .line 598
    .line 599
    move-object/from16 v45, v36

    .line 600
    .line 601
    move/from16 v2, v39

    .line 602
    .line 603
    move-object/from16 v46, v41

    .line 604
    .line 605
    if-lt v14, v15, :cond_14

    .line 606
    .line 607
    add-int/lit8 v14, v15, -0x1

    .line 608
    .line 609
    const/16 v17, 0x0

    .line 610
    .line 611
    :cond_14
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 612
    .line 613
    .line 614
    move-result v21

    .line 615
    sub-int v17, v17, v21

    .line 616
    .line 617
    if-nez v14, :cond_15

    .line 618
    .line 619
    if-gez v17, :cond_15

    .line 620
    .line 621
    add-int v21, v21, v17

    .line 622
    .line 623
    const/16 v17, 0x0

    .line 624
    .line 625
    :cond_15
    new-instance v9, Lmx0/l;

    .line 626
    .line 627
    invoke-direct {v9}, Lmx0/l;-><init>()V

    .line 628
    .line 629
    .line 630
    neg-int v10, v11

    .line 631
    if-gez v42, :cond_16

    .line 632
    .line 633
    move/from16 v22, v42

    .line 634
    .line 635
    :goto_12
    move/from16 v23, v4

    .line 636
    .line 637
    goto :goto_13

    .line 638
    :cond_16
    const/16 v22, 0x0

    .line 639
    .line 640
    goto :goto_12

    .line 641
    :goto_13
    add-int v4, v10, v22

    .line 642
    .line 643
    add-int v17, v17, v4

    .line 644
    .line 645
    move/from16 v36, v10

    .line 646
    .line 647
    move-object/from16 v22, v12

    .line 648
    .line 649
    move-object/from16 v39, v13

    .line 650
    .line 651
    move/from16 v10, v17

    .line 652
    .line 653
    move/from16 v17, v14

    .line 654
    .line 655
    const/4 v14, 0x0

    .line 656
    :goto_14
    iget-wide v12, v1, Lm1/i;->h:J

    .line 657
    .line 658
    if-gez v10, :cond_17

    .line 659
    .line 660
    if-lez v17, :cond_17

    .line 661
    .line 662
    move-object/from16 v41, v0

    .line 663
    .line 664
    add-int/lit8 v0, v17, -0x1

    .line 665
    .line 666
    invoke-virtual {v1, v0, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 667
    .line 668
    .line 669
    move-result-object v12

    .line 670
    const/4 v13, 0x0

    .line 671
    invoke-virtual {v9, v13, v12}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 672
    .line 673
    .line 674
    iget v13, v12, Lm1/m;->r:I

    .line 675
    .line 676
    invoke-static {v14, v13}, Ljava/lang/Math;->max(II)I

    .line 677
    .line 678
    .line 679
    move-result v14

    .line 680
    iget v12, v12, Lm1/m;->q:I

    .line 681
    .line 682
    add-int/2addr v10, v12

    .line 683
    move/from16 v17, v0

    .line 684
    .line 685
    move-object/from16 v0, v41

    .line 686
    .line 687
    goto :goto_14

    .line 688
    :cond_17
    move-object/from16 v41, v0

    .line 689
    .line 690
    const/4 v0, 0x0

    .line 691
    if-ge v10, v4, :cond_18

    .line 692
    .line 693
    sub-int v10, v4, v10

    .line 694
    .line 695
    sub-int v21, v21, v10

    .line 696
    .line 697
    move v10, v4

    .line 698
    :cond_18
    move/from16 v47, v21

    .line 699
    .line 700
    sub-int/2addr v10, v4

    .line 701
    move/from16 v35, v14

    .line 702
    .line 703
    add-int v14, v2, v44

    .line 704
    .line 705
    if-gez v14, :cond_19

    .line 706
    .line 707
    move/from16 v48, v14

    .line 708
    .line 709
    goto :goto_15

    .line 710
    :cond_19
    move v0, v14

    .line 711
    move/from16 v48, v0

    .line 712
    .line 713
    :goto_15
    neg-int v14, v10

    .line 714
    move/from16 v26, v10

    .line 715
    .line 716
    move v10, v14

    .line 717
    move/from16 v28, v17

    .line 718
    .line 719
    const/4 v14, 0x0

    .line 720
    const/16 v21, 0x0

    .line 721
    .line 722
    :goto_16
    iget v5, v9, Lmx0/l;->f:I

    .line 723
    .line 724
    if-ge v14, v5, :cond_1b

    .line 725
    .line 726
    if-lt v10, v0, :cond_1a

    .line 727
    .line 728
    invoke-virtual {v9, v14}, Lmx0/l;->e(I)Ljava/lang/Object;

    .line 729
    .line 730
    .line 731
    move/from16 v21, v16

    .line 732
    .line 733
    goto :goto_16

    .line 734
    :cond_1a
    add-int/lit8 v28, v28, 0x1

    .line 735
    .line 736
    invoke-virtual {v9, v14}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 737
    .line 738
    .line 739
    move-result-object v5

    .line 740
    check-cast v5, Lm1/m;

    .line 741
    .line 742
    iget v5, v5, Lm1/m;->q:I

    .line 743
    .line 744
    add-int/2addr v10, v5

    .line 745
    add-int/lit8 v14, v14, 0x1

    .line 746
    .line 747
    goto :goto_16

    .line 748
    :cond_1b
    move/from16 v5, v28

    .line 749
    .line 750
    move/from16 v14, v35

    .line 751
    .line 752
    move/from16 v35, v21

    .line 753
    .line 754
    :goto_17
    if-ge v5, v15, :cond_1d

    .line 755
    .line 756
    if-lt v10, v0, :cond_1c

    .line 757
    .line 758
    if-lez v10, :cond_1c

    .line 759
    .line 760
    invoke-virtual {v9}, Lmx0/l;->isEmpty()Z

    .line 761
    .line 762
    .line 763
    move-result v21

    .line 764
    if-eqz v21, :cond_1d

    .line 765
    .line 766
    :cond_1c
    move/from16 v21, v0

    .line 767
    .line 768
    goto :goto_18

    .line 769
    :cond_1d
    move-wide/from16 v49, v7

    .line 770
    .line 771
    goto :goto_1a

    .line 772
    :goto_18
    invoke-virtual {v1, v5, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 773
    .line 774
    .line 775
    move-result-object v0

    .line 776
    move-wide/from16 v49, v7

    .line 777
    .line 778
    iget v7, v0, Lm1/m;->q:I

    .line 779
    .line 780
    add-int/2addr v10, v7

    .line 781
    if-gt v10, v4, :cond_1e

    .line 782
    .line 783
    add-int/lit8 v8, v15, -0x1

    .line 784
    .line 785
    if-eq v5, v8, :cond_1e

    .line 786
    .line 787
    add-int/lit8 v0, v5, 0x1

    .line 788
    .line 789
    sub-int v26, v26, v7

    .line 790
    .line 791
    move/from16 v17, v0

    .line 792
    .line 793
    move/from16 v35, v16

    .line 794
    .line 795
    goto :goto_19

    .line 796
    :cond_1e
    iget v7, v0, Lm1/m;->r:I

    .line 797
    .line 798
    invoke-static {v14, v7}, Ljava/lang/Math;->max(II)I

    .line 799
    .line 800
    .line 801
    move-result v7

    .line 802
    invoke-virtual {v9, v0}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 803
    .line 804
    .line 805
    move v14, v7

    .line 806
    :goto_19
    add-int/lit8 v5, v5, 0x1

    .line 807
    .line 808
    move/from16 v0, v21

    .line 809
    .line 810
    move-wide/from16 v7, v49

    .line 811
    .line 812
    goto :goto_17

    .line 813
    :goto_1a
    if-ge v10, v2, :cond_21

    .line 814
    .line 815
    sub-int v0, v2, v10

    .line 816
    .line 817
    sub-int v26, v26, v0

    .line 818
    .line 819
    add-int/2addr v10, v0

    .line 820
    move/from16 v4, v26

    .line 821
    .line 822
    :goto_1b
    if-ge v4, v11, :cond_1f

    .line 823
    .line 824
    if-lez v17, :cond_1f

    .line 825
    .line 826
    add-int/lit8 v7, v17, -0x1

    .line 827
    .line 828
    invoke-virtual {v1, v7, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 829
    .line 830
    .line 831
    move-result-object v8

    .line 832
    move/from16 v21, v0

    .line 833
    .line 834
    const/4 v0, 0x0

    .line 835
    invoke-virtual {v9, v0, v8}, Lmx0/l;->add(ILjava/lang/Object;)V

    .line 836
    .line 837
    .line 838
    iget v0, v8, Lm1/m;->r:I

    .line 839
    .line 840
    invoke-static {v14, v0}, Ljava/lang/Math;->max(II)I

    .line 841
    .line 842
    .line 843
    move-result v14

    .line 844
    iget v0, v8, Lm1/m;->q:I

    .line 845
    .line 846
    add-int/2addr v4, v0

    .line 847
    move/from16 v17, v7

    .line 848
    .line 849
    move/from16 v0, v21

    .line 850
    .line 851
    goto :goto_1b

    .line 852
    :cond_1f
    move/from16 v21, v0

    .line 853
    .line 854
    move/from16 v0, v47

    .line 855
    .line 856
    add-int v47, v0, v21

    .line 857
    .line 858
    if-gez v4, :cond_20

    .line 859
    .line 860
    add-int v47, v47, v4

    .line 861
    .line 862
    add-int/2addr v10, v4

    .line 863
    move/from16 v7, v17

    .line 864
    .line 865
    move/from16 v8, v47

    .line 866
    .line 867
    const/4 v4, 0x0

    .line 868
    goto :goto_1c

    .line 869
    :cond_20
    move/from16 v7, v17

    .line 870
    .line 871
    move/from16 v8, v47

    .line 872
    .line 873
    goto :goto_1c

    .line 874
    :cond_21
    move/from16 v0, v47

    .line 875
    .line 876
    move v8, v0

    .line 877
    move/from16 v7, v17

    .line 878
    .line 879
    move/from16 v4, v26

    .line 880
    .line 881
    :goto_1c
    invoke-static/range {v23 .. v23}, Ljava/lang/Math;->round(F)I

    .line 882
    .line 883
    .line 884
    move-result v17

    .line 885
    move/from16 v21, v5

    .line 886
    .line 887
    invoke-static/range {v17 .. v17}, Ljava/lang/Integer;->signum(I)I

    .line 888
    .line 889
    .line 890
    move-result v5

    .line 891
    move/from16 v47, v11

    .line 892
    .line 893
    invoke-static {v8}, Ljava/lang/Integer;->signum(I)I

    .line 894
    .line 895
    .line 896
    move-result v11

    .line 897
    if-ne v5, v11, :cond_22

    .line 898
    .line 899
    invoke-static/range {v23 .. v23}, Ljava/lang/Math;->round(F)I

    .line 900
    .line 901
    .line 902
    move-result v5

    .line 903
    invoke-static {v5}, Ljava/lang/Math;->abs(I)I

    .line 904
    .line 905
    .line 906
    move-result v5

    .line 907
    invoke-static {v8}, Ljava/lang/Math;->abs(I)I

    .line 908
    .line 909
    .line 910
    move-result v11

    .line 911
    if-lt v5, v11, :cond_22

    .line 912
    .line 913
    int-to-float v5, v8

    .line 914
    move v11, v5

    .line 915
    goto :goto_1d

    .line 916
    :cond_22
    move/from16 v11, v23

    .line 917
    .line 918
    :goto_1d
    sub-float v5, v23, v11

    .line 919
    .line 920
    const/16 v17, 0x0

    .line 921
    .line 922
    if-eqz v25, :cond_23

    .line 923
    .line 924
    if-le v8, v0, :cond_23

    .line 925
    .line 926
    cmpg-float v23, v5, v17

    .line 927
    .line 928
    if-gtz v23, :cond_23

    .line 929
    .line 930
    sub-int/2addr v8, v0

    .line 931
    int-to-float v0, v8

    .line 932
    add-float/2addr v0, v5

    .line 933
    goto :goto_1e

    .line 934
    :cond_23
    move/from16 v0, v17

    .line 935
    .line 936
    :goto_1e
    if-ltz v4, :cond_24

    .line 937
    .line 938
    goto :goto_1f

    .line 939
    :cond_24
    const-string v5, "negative currentFirstItemScrollOffset"

    .line 940
    .line 941
    invoke-static {v5}, Lj1/b;->a(Ljava/lang/String;)V

    .line 942
    .line 943
    .line 944
    :goto_1f
    neg-int v5, v4

    .line 945
    invoke-virtual {v9}, Lmx0/l;->first()Ljava/lang/Object;

    .line 946
    .line 947
    .line 948
    move-result-object v8

    .line 949
    check-cast v8, Lm1/m;

    .line 950
    .line 951
    if-gtz v47, :cond_25

    .line 952
    .line 953
    if-gez v42, :cond_26

    .line 954
    .line 955
    :cond_25
    move/from16 v51, v0

    .line 956
    .line 957
    goto :goto_21

    .line 958
    :cond_26
    move/from16 v51, v0

    .line 959
    .line 960
    :goto_20
    move/from16 v28, v4

    .line 961
    .line 962
    const/4 v0, 0x0

    .line 963
    goto :goto_23

    .line 964
    :goto_21
    invoke-virtual {v9}, Lmx0/l;->c()I

    .line 965
    .line 966
    .line 967
    move-result v0

    .line 968
    move-object/from16 v23, v8

    .line 969
    .line 970
    const/4 v8, 0x0

    .line 971
    :goto_22
    if-ge v8, v0, :cond_27

    .line 972
    .line 973
    invoke-virtual {v9, v8}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 974
    .line 975
    .line 976
    move-result-object v26

    .line 977
    move/from16 v28, v0

    .line 978
    .line 979
    move-object/from16 v0, v26

    .line 980
    .line 981
    check-cast v0, Lm1/m;

    .line 982
    .line 983
    iget v0, v0, Lm1/m;->q:I

    .line 984
    .line 985
    if-eqz v4, :cond_27

    .line 986
    .line 987
    if-gt v0, v4, :cond_27

    .line 988
    .line 989
    move/from16 v26, v0

    .line 990
    .line 991
    invoke-static {v9}, Ljp/k1;->h(Ljava/util/List;)I

    .line 992
    .line 993
    .line 994
    move-result v0

    .line 995
    if-eq v8, v0, :cond_27

    .line 996
    .line 997
    sub-int v4, v4, v26

    .line 998
    .line 999
    add-int/lit8 v8, v8, 0x1

    .line 1000
    .line 1001
    invoke-virtual {v9, v8}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v0

    .line 1005
    move-object/from16 v23, v0

    .line 1006
    .line 1007
    check-cast v23, Lm1/m;

    .line 1008
    .line 1009
    move/from16 v0, v28

    .line 1010
    .line 1011
    goto :goto_22

    .line 1012
    :cond_27
    move-object/from16 v8, v23

    .line 1013
    .line 1014
    goto :goto_20

    .line 1015
    :goto_23
    invoke-static {v0, v7}, Ljava/lang/Math;->max(II)I

    .line 1016
    .line 1017
    .line 1018
    move-result v4

    .line 1019
    add-int/lit8 v7, v7, -0x1

    .line 1020
    .line 1021
    if-gt v4, v7, :cond_29

    .line 1022
    .line 1023
    const/16 v23, 0x0

    .line 1024
    .line 1025
    :goto_24
    if-nez v23, :cond_28

    .line 1026
    .line 1027
    new-instance v23, Ljava/util/ArrayList;

    .line 1028
    .line 1029
    invoke-direct/range {v23 .. v23}, Ljava/util/ArrayList;-><init>()V

    .line 1030
    .line 1031
    .line 1032
    :cond_28
    move-object/from16 v0, v23

    .line 1033
    .line 1034
    move/from16 v23, v5

    .line 1035
    .line 1036
    invoke-virtual {v1, v7, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v5

    .line 1040
    invoke-interface {v0, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1041
    .line 1042
    .line 1043
    if-eq v7, v4, :cond_2a

    .line 1044
    .line 1045
    add-int/lit8 v7, v7, -0x1

    .line 1046
    .line 1047
    move/from16 v5, v23

    .line 1048
    .line 1049
    move-object/from16 v23, v0

    .line 1050
    .line 1051
    const/4 v0, 0x0

    .line 1052
    goto :goto_24

    .line 1053
    :cond_29
    move/from16 v23, v5

    .line 1054
    .line 1055
    const/4 v0, 0x0

    .line 1056
    :cond_2a
    move-object v5, v3

    .line 1057
    check-cast v5, Ljava/util/Collection;

    .line 1058
    .line 1059
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 1060
    .line 1061
    .line 1062
    move-result v7

    .line 1063
    move-object/from16 v26, v0

    .line 1064
    .line 1065
    const/4 v0, -0x1

    .line 1066
    add-int/2addr v7, v0

    .line 1067
    if-ltz v7, :cond_2e

    .line 1068
    .line 1069
    :goto_25
    add-int/lit8 v29, v7, -0x1

    .line 1070
    .line 1071
    invoke-interface {v3, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v7

    .line 1075
    check-cast v7, Ljava/lang/Number;

    .line 1076
    .line 1077
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 1078
    .line 1079
    .line 1080
    move-result v7

    .line 1081
    if-ge v7, v4, :cond_2c

    .line 1082
    .line 1083
    if-nez v26, :cond_2b

    .line 1084
    .line 1085
    new-instance v26, Ljava/util/ArrayList;

    .line 1086
    .line 1087
    invoke-direct/range {v26 .. v26}, Ljava/util/ArrayList;-><init>()V

    .line 1088
    .line 1089
    .line 1090
    :cond_2b
    move-object/from16 v0, v26

    .line 1091
    .line 1092
    invoke-virtual {v1, v7, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v7

    .line 1096
    invoke-interface {v0, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1097
    .line 1098
    .line 1099
    move-object/from16 v26, v0

    .line 1100
    .line 1101
    :cond_2c
    if-gez v29, :cond_2d

    .line 1102
    .line 1103
    goto :goto_26

    .line 1104
    :cond_2d
    move/from16 v7, v29

    .line 1105
    .line 1106
    const/4 v0, -0x1

    .line 1107
    goto :goto_25

    .line 1108
    :cond_2e
    :goto_26
    if-nez v26, :cond_2f

    .line 1109
    .line 1110
    move-object/from16 v0, v22

    .line 1111
    .line 1112
    goto :goto_27

    .line 1113
    :cond_2f
    move-object/from16 v0, v26

    .line 1114
    .line 1115
    :goto_27
    move-object v4, v0

    .line 1116
    check-cast v4, Ljava/util/Collection;

    .line 1117
    .line 1118
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 1119
    .line 1120
    .line 1121
    move-result v7

    .line 1122
    move-object/from16 v26, v4

    .line 1123
    .line 1124
    move v4, v14

    .line 1125
    const/4 v14, 0x0

    .line 1126
    :goto_28
    if-ge v14, v7, :cond_30

    .line 1127
    .line 1128
    invoke-interface {v0, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1129
    .line 1130
    .line 1131
    move-result-object v29

    .line 1132
    move-object/from16 v53, v5

    .line 1133
    .line 1134
    move-object/from16 v5, v29

    .line 1135
    .line 1136
    check-cast v5, Lm1/m;

    .line 1137
    .line 1138
    iget v5, v5, Lm1/m;->r:I

    .line 1139
    .line 1140
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 1141
    .line 1142
    .line 1143
    move-result v4

    .line 1144
    add-int/lit8 v14, v14, 0x1

    .line 1145
    .line 1146
    move-object/from16 v5, v53

    .line 1147
    .line 1148
    goto :goto_28

    .line 1149
    :cond_30
    move-object/from16 v53, v5

    .line 1150
    .line 1151
    invoke-static {v9}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1152
    .line 1153
    .line 1154
    move-result-object v5

    .line 1155
    check-cast v5, Lm1/m;

    .line 1156
    .line 1157
    iget v5, v5, Lm1/m;->a:I

    .line 1158
    .line 1159
    add-int/lit8 v7, v15, -0x1

    .line 1160
    .line 1161
    invoke-static {v5, v7}, Ljava/lang/Math;->min(II)I

    .line 1162
    .line 1163
    .line 1164
    move-result v5

    .line 1165
    invoke-static {v9}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1166
    .line 1167
    .line 1168
    move-result-object v14

    .line 1169
    check-cast v14, Lm1/m;

    .line 1170
    .line 1171
    iget v14, v14, Lm1/m;->a:I

    .line 1172
    .line 1173
    add-int/lit8 v14, v14, 0x1

    .line 1174
    .line 1175
    if-gt v14, v5, :cond_32

    .line 1176
    .line 1177
    const/16 v29, 0x0

    .line 1178
    .line 1179
    :goto_29
    if-nez v29, :cond_31

    .line 1180
    .line 1181
    new-instance v29, Ljava/util/ArrayList;

    .line 1182
    .line 1183
    invoke-direct/range {v29 .. v29}, Ljava/util/ArrayList;-><init>()V

    .line 1184
    .line 1185
    .line 1186
    :cond_31
    move/from16 v54, v4

    .line 1187
    .line 1188
    move/from16 v55, v11

    .line 1189
    .line 1190
    move-object/from16 v4, v29

    .line 1191
    .line 1192
    invoke-virtual {v1, v14, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1193
    .line 1194
    .line 1195
    move-result-object v11

    .line 1196
    invoke-interface {v4, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1197
    .line 1198
    .line 1199
    if-eq v14, v5, :cond_33

    .line 1200
    .line 1201
    add-int/lit8 v14, v14, 0x1

    .line 1202
    .line 1203
    move-object/from16 v29, v4

    .line 1204
    .line 1205
    move/from16 v4, v54

    .line 1206
    .line 1207
    move/from16 v11, v55

    .line 1208
    .line 1209
    goto :goto_29

    .line 1210
    :cond_32
    move/from16 v54, v4

    .line 1211
    .line 1212
    move/from16 v55, v11

    .line 1213
    .line 1214
    const/4 v4, 0x0

    .line 1215
    :cond_33
    if-eqz v25, :cond_46

    .line 1216
    .line 1217
    if-eqz v6, :cond_46

    .line 1218
    .line 1219
    iget-object v11, v6, Lm1/l;->k:Ljava/lang/Object;

    .line 1220
    .line 1221
    move-object v14, v11

    .line 1222
    check-cast v14, Ljava/util/Collection;

    .line 1223
    .line 1224
    invoke-interface {v14}, Ljava/util/Collection;->isEmpty()Z

    .line 1225
    .line 1226
    .line 1227
    move-result v14

    .line 1228
    if-nez v14, :cond_46

    .line 1229
    .line 1230
    invoke-interface {v11}, Ljava/util/List;->size()I

    .line 1231
    .line 1232
    .line 1233
    move-result v14

    .line 1234
    add-int/lit8 v14, v14, -0x1

    .line 1235
    .line 1236
    move-object/from16 v29, v4

    .line 1237
    .line 1238
    :goto_2a
    const/4 v4, -0x1

    .line 1239
    if-ge v4, v14, :cond_36

    .line 1240
    .line 1241
    invoke-interface {v11, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1242
    .line 1243
    .line 1244
    move-result-object v52

    .line 1245
    move-object/from16 v4, v52

    .line 1246
    .line 1247
    check-cast v4, Lm1/m;

    .line 1248
    .line 1249
    iget v4, v4, Lm1/m;->a:I

    .line 1250
    .line 1251
    if-le v4, v5, :cond_35

    .line 1252
    .line 1253
    if-eqz v14, :cond_34

    .line 1254
    .line 1255
    add-int/lit8 v4, v14, -0x1

    .line 1256
    .line 1257
    invoke-interface {v11, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1258
    .line 1259
    .line 1260
    move-result-object v4

    .line 1261
    check-cast v4, Lm1/m;

    .line 1262
    .line 1263
    iget v4, v4, Lm1/m;->a:I

    .line 1264
    .line 1265
    if-gt v4, v5, :cond_35

    .line 1266
    .line 1267
    :cond_34
    invoke-interface {v11, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v4

    .line 1271
    check-cast v4, Lm1/m;

    .line 1272
    .line 1273
    goto :goto_2b

    .line 1274
    :cond_35
    add-int/lit8 v14, v14, -0x1

    .line 1275
    .line 1276
    goto :goto_2a

    .line 1277
    :cond_36
    const/4 v4, 0x0

    .line 1278
    :goto_2b
    invoke-static {v11}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1279
    .line 1280
    .line 1281
    move-result-object v11

    .line 1282
    check-cast v11, Lm1/m;

    .line 1283
    .line 1284
    if-eqz v4, :cond_3c

    .line 1285
    .line 1286
    iget v4, v4, Lm1/m;->a:I

    .line 1287
    .line 1288
    iget v14, v11, Lm1/m;->a:I

    .line 1289
    .line 1290
    invoke-static {v14, v7}, Ljava/lang/Math;->min(II)I

    .line 1291
    .line 1292
    .line 1293
    move-result v7

    .line 1294
    if-gt v4, v7, :cond_3c

    .line 1295
    .line 1296
    move v14, v4

    .line 1297
    move-object/from16 v4, v29

    .line 1298
    .line 1299
    :goto_2c
    move-object/from16 v52, v0

    .line 1300
    .line 1301
    if-eqz v4, :cond_39

    .line 1302
    .line 1303
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 1304
    .line 1305
    .line 1306
    move-result v0

    .line 1307
    move/from16 v56, v10

    .line 1308
    .line 1309
    const/4 v10, 0x0

    .line 1310
    :goto_2d
    if-ge v10, v0, :cond_38

    .line 1311
    .line 1312
    invoke-interface {v4, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v29

    .line 1316
    move/from16 v57, v0

    .line 1317
    .line 1318
    move-object/from16 v0, v29

    .line 1319
    .line 1320
    check-cast v0, Lm1/m;

    .line 1321
    .line 1322
    iget v0, v0, Lm1/m;->a:I

    .line 1323
    .line 1324
    if-ne v0, v14, :cond_37

    .line 1325
    .line 1326
    goto :goto_2e

    .line 1327
    :cond_37
    add-int/lit8 v10, v10, 0x1

    .line 1328
    .line 1329
    move/from16 v0, v57

    .line 1330
    .line 1331
    goto :goto_2d

    .line 1332
    :cond_38
    const/16 v29, 0x0

    .line 1333
    .line 1334
    :goto_2e
    check-cast v29, Lm1/m;

    .line 1335
    .line 1336
    goto :goto_2f

    .line 1337
    :cond_39
    move/from16 v56, v10

    .line 1338
    .line 1339
    const/16 v29, 0x0

    .line 1340
    .line 1341
    :goto_2f
    if-nez v29, :cond_3b

    .line 1342
    .line 1343
    if-nez v4, :cond_3a

    .line 1344
    .line 1345
    new-instance v4, Ljava/util/ArrayList;

    .line 1346
    .line 1347
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1348
    .line 1349
    .line 1350
    :cond_3a
    invoke-virtual {v1, v14, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v0

    .line 1354
    invoke-interface {v4, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1355
    .line 1356
    .line 1357
    :cond_3b
    if-eq v14, v7, :cond_3d

    .line 1358
    .line 1359
    add-int/lit8 v14, v14, 0x1

    .line 1360
    .line 1361
    move-object/from16 v0, v52

    .line 1362
    .line 1363
    move/from16 v10, v56

    .line 1364
    .line 1365
    goto :goto_2c

    .line 1366
    :cond_3c
    move-object/from16 v52, v0

    .line 1367
    .line 1368
    move/from16 v56, v10

    .line 1369
    .line 1370
    move-object/from16 v4, v29

    .line 1371
    .line 1372
    :cond_3d
    iget v0, v6, Lm1/l;->m:I

    .line 1373
    .line 1374
    iget v6, v11, Lm1/m;->o:I

    .line 1375
    .line 1376
    sub-int/2addr v0, v6

    .line 1377
    iget v6, v11, Lm1/m;->p:I

    .line 1378
    .line 1379
    sub-int/2addr v0, v6

    .line 1380
    int-to-float v0, v0

    .line 1381
    sub-float v0, v0, v55

    .line 1382
    .line 1383
    cmpl-float v6, v0, v17

    .line 1384
    .line 1385
    if-lez v6, :cond_47

    .line 1386
    .line 1387
    iget v6, v11, Lm1/m;->a:I

    .line 1388
    .line 1389
    add-int/lit8 v6, v6, 0x1

    .line 1390
    .line 1391
    const/4 v7, 0x0

    .line 1392
    :goto_30
    if-ge v6, v15, :cond_47

    .line 1393
    .line 1394
    int-to-float v10, v7

    .line 1395
    cmpg-float v10, v10, v0

    .line 1396
    .line 1397
    if-gez v10, :cond_47

    .line 1398
    .line 1399
    if-gt v6, v5, :cond_40

    .line 1400
    .line 1401
    invoke-virtual {v9}, Lmx0/l;->c()I

    .line 1402
    .line 1403
    .line 1404
    move-result v10

    .line 1405
    const/4 v11, 0x0

    .line 1406
    :goto_31
    if-ge v11, v10, :cond_3f

    .line 1407
    .line 1408
    invoke-virtual {v9, v11}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1409
    .line 1410
    .line 1411
    move-result-object v14

    .line 1412
    move/from16 v17, v0

    .line 1413
    .line 1414
    move-object v0, v14

    .line 1415
    check-cast v0, Lm1/m;

    .line 1416
    .line 1417
    iget v0, v0, Lm1/m;->a:I

    .line 1418
    .line 1419
    if-ne v0, v6, :cond_3e

    .line 1420
    .line 1421
    goto :goto_32

    .line 1422
    :cond_3e
    add-int/lit8 v11, v11, 0x1

    .line 1423
    .line 1424
    move/from16 v0, v17

    .line 1425
    .line 1426
    goto :goto_31

    .line 1427
    :cond_3f
    move/from16 v17, v0

    .line 1428
    .line 1429
    const/4 v14, 0x0

    .line 1430
    :goto_32
    check-cast v14, Lm1/m;

    .line 1431
    .line 1432
    goto :goto_35

    .line 1433
    :cond_40
    move/from16 v17, v0

    .line 1434
    .line 1435
    if-eqz v4, :cond_43

    .line 1436
    .line 1437
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 1438
    .line 1439
    .line 1440
    move-result v0

    .line 1441
    const/4 v10, 0x0

    .line 1442
    :goto_33
    if-ge v10, v0, :cond_42

    .line 1443
    .line 1444
    invoke-interface {v4, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1445
    .line 1446
    .line 1447
    move-result-object v11

    .line 1448
    move-object v14, v11

    .line 1449
    check-cast v14, Lm1/m;

    .line 1450
    .line 1451
    iget v14, v14, Lm1/m;->a:I

    .line 1452
    .line 1453
    if-ne v14, v6, :cond_41

    .line 1454
    .line 1455
    goto :goto_34

    .line 1456
    :cond_41
    add-int/lit8 v10, v10, 0x1

    .line 1457
    .line 1458
    goto :goto_33

    .line 1459
    :cond_42
    const/4 v11, 0x0

    .line 1460
    :goto_34
    move-object v14, v11

    .line 1461
    check-cast v14, Lm1/m;

    .line 1462
    .line 1463
    goto :goto_35

    .line 1464
    :cond_43
    const/4 v14, 0x0

    .line 1465
    :goto_35
    if-eqz v14, :cond_44

    .line 1466
    .line 1467
    add-int/lit8 v6, v6, 0x1

    .line 1468
    .line 1469
    iget v0, v14, Lm1/m;->q:I

    .line 1470
    .line 1471
    :goto_36
    add-int/2addr v7, v0

    .line 1472
    move/from16 v0, v17

    .line 1473
    .line 1474
    goto :goto_30

    .line 1475
    :cond_44
    if-nez v4, :cond_45

    .line 1476
    .line 1477
    new-instance v4, Ljava/util/ArrayList;

    .line 1478
    .line 1479
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1480
    .line 1481
    .line 1482
    :cond_45
    invoke-virtual {v1, v6, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1483
    .line 1484
    .line 1485
    move-result-object v0

    .line 1486
    invoke-interface {v4, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1487
    .line 1488
    .line 1489
    add-int/lit8 v6, v6, 0x1

    .line 1490
    .line 1491
    invoke-static {v4}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1492
    .line 1493
    .line 1494
    move-result-object v0

    .line 1495
    check-cast v0, Lm1/m;

    .line 1496
    .line 1497
    iget v0, v0, Lm1/m;->q:I

    .line 1498
    .line 1499
    goto :goto_36

    .line 1500
    :cond_46
    move-object/from16 v52, v0

    .line 1501
    .line 1502
    move-object/from16 v29, v4

    .line 1503
    .line 1504
    move/from16 v56, v10

    .line 1505
    .line 1506
    move-object/from16 v4, v29

    .line 1507
    .line 1508
    :cond_47
    if-eqz v4, :cond_48

    .line 1509
    .line 1510
    invoke-static {v4}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1511
    .line 1512
    .line 1513
    move-result-object v0

    .line 1514
    check-cast v0, Lm1/m;

    .line 1515
    .line 1516
    iget v0, v0, Lm1/m;->a:I

    .line 1517
    .line 1518
    if-le v0, v5, :cond_48

    .line 1519
    .line 1520
    invoke-static {v4}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 1521
    .line 1522
    .line 1523
    move-result-object v0

    .line 1524
    check-cast v0, Lm1/m;

    .line 1525
    .line 1526
    iget v5, v0, Lm1/m;->a:I

    .line 1527
    .line 1528
    :cond_48
    invoke-interface/range {v53 .. v53}, Ljava/util/Collection;->size()I

    .line 1529
    .line 1530
    .line 1531
    move-result v0

    .line 1532
    const/4 v6, 0x0

    .line 1533
    :goto_37
    if-ge v6, v0, :cond_4b

    .line 1534
    .line 1535
    invoke-interface {v3, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v7

    .line 1539
    check-cast v7, Ljava/lang/Number;

    .line 1540
    .line 1541
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 1542
    .line 1543
    .line 1544
    move-result v7

    .line 1545
    if-le v7, v5, :cond_4a

    .line 1546
    .line 1547
    if-nez v4, :cond_49

    .line 1548
    .line 1549
    new-instance v4, Ljava/util/ArrayList;

    .line 1550
    .line 1551
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 1552
    .line 1553
    .line 1554
    :cond_49
    invoke-virtual {v1, v7, v12, v13}, Lm1/i;->b0(IJ)Lm1/m;

    .line 1555
    .line 1556
    .line 1557
    move-result-object v7

    .line 1558
    invoke-interface {v4, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1559
    .line 1560
    .line 1561
    :cond_4a
    add-int/lit8 v6, v6, 0x1

    .line 1562
    .line 1563
    goto :goto_37

    .line 1564
    :cond_4b
    if-nez v4, :cond_4c

    .line 1565
    .line 1566
    move-object/from16 v12, v22

    .line 1567
    .line 1568
    goto :goto_38

    .line 1569
    :cond_4c
    move-object v12, v4

    .line 1570
    :goto_38
    move-object v0, v12

    .line 1571
    check-cast v0, Ljava/util/Collection;

    .line 1572
    .line 1573
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 1574
    .line 1575
    .line 1576
    move-result v3

    .line 1577
    move/from16 v4, v54

    .line 1578
    .line 1579
    const/4 v6, 0x0

    .line 1580
    :goto_39
    if-ge v6, v3, :cond_4d

    .line 1581
    .line 1582
    invoke-interface {v12, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1583
    .line 1584
    .line 1585
    move-result-object v5

    .line 1586
    check-cast v5, Lm1/m;

    .line 1587
    .line 1588
    iget v5, v5, Lm1/m;->r:I

    .line 1589
    .line 1590
    invoke-static {v4, v5}, Ljava/lang/Math;->max(II)I

    .line 1591
    .line 1592
    .line 1593
    move-result v4

    .line 1594
    add-int/lit8 v6, v6, 0x1

    .line 1595
    .line 1596
    goto :goto_39

    .line 1597
    :cond_4d
    invoke-virtual {v9}, Lmx0/l;->first()Ljava/lang/Object;

    .line 1598
    .line 1599
    .line 1600
    move-result-object v3

    .line 1601
    invoke-static {v8, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1602
    .line 1603
    .line 1604
    move-result v3

    .line 1605
    if-eqz v3, :cond_4e

    .line 1606
    .line 1607
    invoke-interface/range {v52 .. v52}, Ljava/util/List;->isEmpty()Z

    .line 1608
    .line 1609
    .line 1610
    move-result v3

    .line 1611
    if-eqz v3, :cond_4e

    .line 1612
    .line 1613
    invoke-interface {v12}, Ljava/util/List;->isEmpty()Z

    .line 1614
    .line 1615
    .line 1616
    move-result v3

    .line 1617
    if-eqz v3, :cond_4e

    .line 1618
    .line 1619
    move/from16 v7, v16

    .line 1620
    .line 1621
    goto :goto_3a

    .line 1622
    :cond_4e
    const/4 v7, 0x0

    .line 1623
    :goto_3a
    if-eqz v24, :cond_4f

    .line 1624
    .line 1625
    move v3, v4

    .line 1626
    :goto_3b
    move-wide/from16 v10, v49

    .line 1627
    .line 1628
    goto :goto_3c

    .line 1629
    :cond_4f
    move/from16 v3, v56

    .line 1630
    .line 1631
    goto :goto_3b

    .line 1632
    :goto_3c
    invoke-static {v3, v10, v11}, Lt4/b;->g(IJ)I

    .line 1633
    .line 1634
    .line 1635
    move-result v13

    .line 1636
    if-eqz v24, :cond_50

    .line 1637
    .line 1638
    move/from16 v4, v56

    .line 1639
    .line 1640
    :cond_50
    invoke-static {v4, v10, v11}, Lt4/b;->f(IJ)I

    .line 1641
    .line 1642
    .line 1643
    move-result v14

    .line 1644
    if-eqz v24, :cond_51

    .line 1645
    .line 1646
    move v3, v14

    .line 1647
    goto :goto_3d

    .line 1648
    :cond_51
    move v3, v13

    .line 1649
    :goto_3d
    invoke-static {v3, v2}, Ljava/lang/Math;->min(II)I

    .line 1650
    .line 1651
    .line 1652
    move-result v4

    .line 1653
    move/from16 v5, v56

    .line 1654
    .line 1655
    if-ge v5, v4, :cond_52

    .line 1656
    .line 1657
    move/from16 v6, v16

    .line 1658
    .line 1659
    goto :goto_3e

    .line 1660
    :cond_52
    const/4 v6, 0x0

    .line 1661
    :goto_3e
    if-eqz v6, :cond_54

    .line 1662
    .line 1663
    if-nez v23, :cond_53

    .line 1664
    .line 1665
    goto :goto_3f

    .line 1666
    :cond_53
    const-string v4, "non-zero itemsScrollOffset"

    .line 1667
    .line 1668
    invoke-static {v4}, Lj1/b;->c(Ljava/lang/String;)V

    .line 1669
    .line 1670
    .line 1671
    :cond_54
    :goto_3f
    new-instance v4, Ljava/util/ArrayList;

    .line 1672
    .line 1673
    invoke-virtual {v9}, Lmx0/l;->c()I

    .line 1674
    .line 1675
    .line 1676
    move-result v17

    .line 1677
    invoke-interface/range {v52 .. v52}, Ljava/util/List;->size()I

    .line 1678
    .line 1679
    .line 1680
    move-result v22

    .line 1681
    add-int v22, v22, v17

    .line 1682
    .line 1683
    invoke-interface {v12}, Ljava/util/List;->size()I

    .line 1684
    .line 1685
    .line 1686
    move-result v17

    .line 1687
    move-object/from16 v29, v0

    .line 1688
    .line 1689
    add-int v0, v17, v22

    .line 1690
    .line 1691
    invoke-direct {v4, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 1692
    .line 1693
    .line 1694
    if-eqz v6, :cond_5e

    .line 1695
    .line 1696
    invoke-interface/range {v52 .. v52}, Ljava/util/List;->isEmpty()Z

    .line 1697
    .line 1698
    .line 1699
    move-result v0

    .line 1700
    if-eqz v0, :cond_55

    .line 1701
    .line 1702
    invoke-interface {v12}, Ljava/util/List;->isEmpty()Z

    .line 1703
    .line 1704
    .line 1705
    move-result v0

    .line 1706
    if-eqz v0, :cond_55

    .line 1707
    .line 1708
    goto :goto_40

    .line 1709
    :cond_55
    const-string v0, "no extra items"

    .line 1710
    .line 1711
    invoke-static {v0}, Lj1/b;->a(Ljava/lang/String;)V

    .line 1712
    .line 1713
    .line 1714
    :goto_40
    invoke-virtual {v9}, Lmx0/l;->c()I

    .line 1715
    .line 1716
    .line 1717
    move-result v0

    .line 1718
    move-object/from16 v23, v4

    .line 1719
    .line 1720
    new-array v4, v0, [I

    .line 1721
    .line 1722
    const/4 v6, 0x0

    .line 1723
    :goto_41
    if-ge v6, v0, :cond_56

    .line 1724
    .line 1725
    invoke-virtual {v9, v6}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1726
    .line 1727
    .line 1728
    move-result-object v12

    .line 1729
    check-cast v12, Lm1/m;

    .line 1730
    .line 1731
    iget v12, v12, Lm1/m;->p:I

    .line 1732
    .line 1733
    aput v12, v4, v6

    .line 1734
    .line 1735
    add-int/lit8 v6, v6, 0x1

    .line 1736
    .line 1737
    goto :goto_41

    .line 1738
    :cond_56
    new-array v6, v0, [I

    .line 1739
    .line 1740
    if-eqz v24, :cond_58

    .line 1741
    .line 1742
    move-object/from16 v0, v40

    .line 1743
    .line 1744
    if-eqz v0, :cond_57

    .line 1745
    .line 1746
    move-object/from16 v12, p1

    .line 1747
    .line 1748
    invoke-interface {v0, v12, v3, v4, v6}, Lk1/i;->b(Lt4/c;I[I[I)V

    .line 1749
    .line 1750
    .line 1751
    move-object/from16 v17, v1

    .line 1752
    .line 1753
    move v0, v2

    .line 1754
    move/from16 v56, v5

    .line 1755
    .line 1756
    move-object/from16 v12, v23

    .line 1757
    .line 1758
    goto :goto_42

    .line 1759
    :cond_57
    invoke-static/range {v19 .. v19}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 1760
    .line 1761
    .line 1762
    new-instance v0, La8/r0;

    .line 1763
    .line 1764
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1765
    .line 1766
    .line 1767
    throw v0

    .line 1768
    :cond_58
    move-object/from16 v12, p1

    .line 1769
    .line 1770
    if-eqz v20, :cond_5d

    .line 1771
    .line 1772
    move/from16 v56, v5

    .line 1773
    .line 1774
    sget-object v5, Lt4/m;->d:Lt4/m;

    .line 1775
    .line 1776
    move-object/from16 v17, v1

    .line 1777
    .line 1778
    move v0, v2

    .line 1779
    move-object v2, v12

    .line 1780
    move-object/from16 v1, v20

    .line 1781
    .line 1782
    move-object/from16 v12, v23

    .line 1783
    .line 1784
    invoke-interface/range {v1 .. v6}, Lk1/g;->c(Lt4/c;I[ILt4/m;[I)V

    .line 1785
    .line 1786
    .line 1787
    :goto_42
    invoke-static {v6}, Lmx0/n;->z([I)Lgy0/j;

    .line 1788
    .line 1789
    .line 1790
    move-result-object v1

    .line 1791
    iget v2, v1, Lgy0/h;->d:I

    .line 1792
    .line 1793
    iget v3, v1, Lgy0/h;->e:I

    .line 1794
    .line 1795
    iget v1, v1, Lgy0/h;->f:I

    .line 1796
    .line 1797
    if-lez v1, :cond_59

    .line 1798
    .line 1799
    if-le v2, v3, :cond_5a

    .line 1800
    .line 1801
    :cond_59
    if-gez v1, :cond_5b

    .line 1802
    .line 1803
    if-gt v3, v2, :cond_5b

    .line 1804
    .line 1805
    :cond_5a
    :goto_43
    aget v4, v6, v2

    .line 1806
    .line 1807
    invoke-virtual {v9, v2}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v5

    .line 1811
    check-cast v5, Lm1/m;

    .line 1812
    .line 1813
    invoke-virtual {v5, v4, v13, v14}, Lm1/m;->n(III)V

    .line 1814
    .line 1815
    .line 1816
    invoke-virtual {v12, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1817
    .line 1818
    .line 1819
    if-eq v2, v3, :cond_5b

    .line 1820
    .line 1821
    add-int/2addr v2, v1

    .line 1822
    goto :goto_43

    .line 1823
    :cond_5b
    move-object v1, v12

    .line 1824
    move/from16 v5, v21

    .line 1825
    .line 1826
    :cond_5c
    move/from16 v4, v55

    .line 1827
    .line 1828
    goto/16 :goto_47

    .line 1829
    .line 1830
    :cond_5d
    const-string v0, "null horizontalArrangement when isVertical == false"

    .line 1831
    .line 1832
    invoke-static {v0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 1833
    .line 1834
    .line 1835
    new-instance v0, La8/r0;

    .line 1836
    .line 1837
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1838
    .line 1839
    .line 1840
    throw v0

    .line 1841
    :cond_5e
    move-object/from16 v17, v1

    .line 1842
    .line 1843
    move v0, v2

    .line 1844
    move-object v1, v4

    .line 1845
    move/from16 v56, v5

    .line 1846
    .line 1847
    move/from16 v5, v21

    .line 1848
    .line 1849
    invoke-interface/range {v26 .. v26}, Ljava/util/Collection;->size()I

    .line 1850
    .line 1851
    .line 1852
    move-result v2

    .line 1853
    move/from16 v3, v23

    .line 1854
    .line 1855
    const/4 v6, 0x0

    .line 1856
    :goto_44
    if-ge v6, v2, :cond_5f

    .line 1857
    .line 1858
    move-object/from16 v4, v52

    .line 1859
    .line 1860
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1861
    .line 1862
    .line 1863
    move-result-object v19

    .line 1864
    move/from16 v20, v2

    .line 1865
    .line 1866
    move-object/from16 v2, v19

    .line 1867
    .line 1868
    check-cast v2, Lm1/m;

    .line 1869
    .line 1870
    move/from16 v19, v3

    .line 1871
    .line 1872
    iget v3, v2, Lm1/m;->q:I

    .line 1873
    .line 1874
    sub-int v3, v19, v3

    .line 1875
    .line 1876
    invoke-virtual {v2, v3, v13, v14}, Lm1/m;->n(III)V

    .line 1877
    .line 1878
    .line 1879
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1880
    .line 1881
    .line 1882
    add-int/lit8 v6, v6, 0x1

    .line 1883
    .line 1884
    move/from16 v2, v20

    .line 1885
    .line 1886
    goto :goto_44

    .line 1887
    :cond_5f
    invoke-virtual {v9}, Lmx0/l;->c()I

    .line 1888
    .line 1889
    .line 1890
    move-result v2

    .line 1891
    move/from16 v3, v23

    .line 1892
    .line 1893
    const/4 v6, 0x0

    .line 1894
    :goto_45
    if-ge v6, v2, :cond_60

    .line 1895
    .line 1896
    invoke-virtual {v9, v6}, Lmx0/l;->get(I)Ljava/lang/Object;

    .line 1897
    .line 1898
    .line 1899
    move-result-object v4

    .line 1900
    check-cast v4, Lm1/m;

    .line 1901
    .line 1902
    invoke-virtual {v4, v3, v13, v14}, Lm1/m;->n(III)V

    .line 1903
    .line 1904
    .line 1905
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1906
    .line 1907
    .line 1908
    iget v4, v4, Lm1/m;->q:I

    .line 1909
    .line 1910
    add-int/2addr v3, v4

    .line 1911
    add-int/lit8 v6, v6, 0x1

    .line 1912
    .line 1913
    goto :goto_45

    .line 1914
    :cond_60
    invoke-interface/range {v29 .. v29}, Ljava/util/Collection;->size()I

    .line 1915
    .line 1916
    .line 1917
    move-result v2

    .line 1918
    const/4 v6, 0x0

    .line 1919
    :goto_46
    if-ge v6, v2, :cond_5c

    .line 1920
    .line 1921
    invoke-interface {v12, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1922
    .line 1923
    .line 1924
    move-result-object v4

    .line 1925
    check-cast v4, Lm1/m;

    .line 1926
    .line 1927
    invoke-virtual {v4, v3, v13, v14}, Lm1/m;->n(III)V

    .line 1928
    .line 1929
    .line 1930
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1931
    .line 1932
    .line 1933
    iget v4, v4, Lm1/m;->q:I

    .line 1934
    .line 1935
    add-int/2addr v3, v4

    .line 1936
    add-int/lit8 v6, v6, 0x1

    .line 1937
    .line 1938
    goto :goto_46

    .line 1939
    :goto_47
    float-to-int v2, v4

    .line 1940
    move-object/from16 v3, v41

    .line 1941
    .line 1942
    iget-object v6, v3, Lm1/h;->d:Lbb/g0;

    .line 1943
    .line 1944
    const/16 v26, 0x1

    .line 1945
    .line 1946
    move-object/from16 v21, v1

    .line 1947
    .line 1948
    move-object/from16 v22, v6

    .line 1949
    .line 1950
    move/from16 v19, v13

    .line 1951
    .line 1952
    move/from16 v20, v14

    .line 1953
    .line 1954
    move-object/from16 v23, v17

    .line 1955
    .line 1956
    move-object/from16 v17, v18

    .line 1957
    .line 1958
    move/from16 v29, v56

    .line 1959
    .line 1960
    move/from16 v18, v2

    .line 1961
    .line 1962
    invoke-virtual/range {v17 .. v31}, Landroidx/compose/foundation/lazy/layout/b;->d(IIILjava/util/ArrayList;Lbb/g0;Lap0/o;ZZIZIILvy0/b0;Le3/w;)V

    .line 1963
    .line 1964
    .line 1965
    move/from16 v1, v20

    .line 1966
    .line 1967
    move-object/from16 v14, v21

    .line 1968
    .line 1969
    move-object/from16 v2, v23

    .line 1970
    .line 1971
    move/from16 v27, v24

    .line 1972
    .line 1973
    move/from16 v6, v25

    .line 1974
    .line 1975
    move/from16 v12, v29

    .line 1976
    .line 1977
    move/from16 v29, v6

    .line 1978
    .line 1979
    move/from16 v26, v7

    .line 1980
    .line 1981
    if-nez v6, :cond_64

    .line 1982
    .line 1983
    invoke-virtual/range {v17 .. v17}, Landroidx/compose/foundation/lazy/layout/b;->b()J

    .line 1984
    .line 1985
    .line 1986
    move-result-wide v6

    .line 1987
    move-object/from16 v40, v8

    .line 1988
    .line 1989
    move-object/from16 v31, v9

    .line 1990
    .line 1991
    const-wide/16 v8, 0x0

    .line 1992
    .line 1993
    invoke-static {v6, v7, v8, v9}, Lt4/l;->a(JJ)Z

    .line 1994
    .line 1995
    .line 1996
    move-result v8

    .line 1997
    if-nez v8, :cond_63

    .line 1998
    .line 1999
    if-eqz v27, :cond_61

    .line 2000
    .line 2001
    move v8, v1

    .line 2002
    :goto_48
    move-wide/from16 v17, v6

    .line 2003
    .line 2004
    goto :goto_49

    .line 2005
    :cond_61
    move v8, v13

    .line 2006
    goto :goto_48

    .line 2007
    :goto_49
    shr-long v6, v17, v32

    .line 2008
    .line 2009
    long-to-int v6, v6

    .line 2010
    invoke-static {v13, v6}, Ljava/lang/Math;->max(II)I

    .line 2011
    .line 2012
    .line 2013
    move-result v6

    .line 2014
    invoke-static {v6, v10, v11}, Lt4/b;->g(IJ)I

    .line 2015
    .line 2016
    .line 2017
    move-result v13

    .line 2018
    and-long v6, v17, v33

    .line 2019
    .line 2020
    long-to-int v6, v6

    .line 2021
    invoke-static {v1, v6}, Ljava/lang/Math;->max(II)I

    .line 2022
    .line 2023
    .line 2024
    move-result v1

    .line 2025
    invoke-static {v1, v10, v11}, Lt4/b;->f(IJ)I

    .line 2026
    .line 2027
    .line 2028
    move-result v1

    .line 2029
    if-eqz v27, :cond_62

    .line 2030
    .line 2031
    move v6, v1

    .line 2032
    goto :goto_4a

    .line 2033
    :cond_62
    move v6, v13

    .line 2034
    :goto_4a
    if-eq v6, v8, :cond_63

    .line 2035
    .line 2036
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 2037
    .line 2038
    .line 2039
    move-result v7

    .line 2040
    const/4 v8, 0x0

    .line 2041
    :goto_4b
    if-ge v8, v7, :cond_63

    .line 2042
    .line 2043
    invoke-virtual {v14, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 2044
    .line 2045
    .line 2046
    move-result-object v9

    .line 2047
    check-cast v9, Lm1/m;

    .line 2048
    .line 2049
    iput v6, v9, Lm1/m;->t:I

    .line 2050
    .line 2051
    iget v10, v9, Lm1/m;->h:I

    .line 2052
    .line 2053
    add-int/2addr v10, v6

    .line 2054
    iput v10, v9, Lm1/m;->v:I

    .line 2055
    .line 2056
    add-int/lit8 v8, v8, 0x1

    .line 2057
    .line 2058
    goto :goto_4b

    .line 2059
    :cond_63
    :goto_4c
    move/from16 v24, v1

    .line 2060
    .line 2061
    move/from16 v23, v13

    .line 2062
    .line 2063
    goto :goto_4d

    .line 2064
    :cond_64
    move-object/from16 v40, v8

    .line 2065
    .line 2066
    move-object/from16 v31, v9

    .line 2067
    .line 2068
    goto :goto_4c

    .line 2069
    :goto_4d
    invoke-virtual/range {v31 .. v31}, Lmx0/l;->k()Ljava/lang/Object;

    .line 2070
    .line 2071
    .line 2072
    move-result-object v1

    .line 2073
    check-cast v1, Lm1/m;

    .line 2074
    .line 2075
    if-eqz v1, :cond_65

    .line 2076
    .line 2077
    iget v6, v1, Lm1/m;->a:I

    .line 2078
    .line 2079
    move/from16 v18, v6

    .line 2080
    .line 2081
    goto :goto_4e

    .line 2082
    :cond_65
    const/16 v18, 0x0

    .line 2083
    .line 2084
    :goto_4e
    invoke-virtual/range {v31 .. v31}, Lmx0/l;->n()Ljava/lang/Object;

    .line 2085
    .line 2086
    .line 2087
    move-result-object v1

    .line 2088
    check-cast v1, Lm1/m;

    .line 2089
    .line 2090
    if-eqz v1, :cond_66

    .line 2091
    .line 2092
    iget v6, v1, Lm1/m;->a:I

    .line 2093
    .line 2094
    move/from16 v19, v6

    .line 2095
    .line 2096
    goto :goto_4f

    .line 2097
    :cond_66
    const/16 v19, 0x0

    .line 2098
    .line 2099
    :goto_4f
    iget-object v1, v3, Lm1/h;->b:Lm1/f;

    .line 2100
    .line 2101
    iget-object v1, v1, Lm1/f;->d:Landroidx/collection/a0;

    .line 2102
    .line 2103
    if-eqz v1, :cond_67

    .line 2104
    .line 2105
    :goto_50
    move-object/from16 v21, v1

    .line 2106
    .line 2107
    goto :goto_51

    .line 2108
    :cond_67
    sget-object v1, Landroidx/collection/o;->a:Landroidx/collection/a0;

    .line 2109
    .line 2110
    goto :goto_50

    .line 2111
    :goto_51
    new-instance v1, Lla/p;

    .line 2112
    .line 2113
    const/4 v3, 0x2

    .line 2114
    invoke-direct {v1, v2, v3}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 2115
    .line 2116
    .line 2117
    move-object/from16 v9, p0

    .line 2118
    .line 2119
    iget-object v3, v9, Lm1/j;->i:Lo1/f0;

    .line 2120
    .line 2121
    move-object/from16 v25, v1

    .line 2122
    .line 2123
    move-object/from16 v17, v3

    .line 2124
    .line 2125
    move-object/from16 v20, v14

    .line 2126
    .line 2127
    move/from16 v22, v47

    .line 2128
    .line 2129
    invoke-static/range {v17 .. v25}, Lo1/y;->f(Lo1/f0;IILjava/util/ArrayList;Landroidx/collection/a0;IIILay0/k;)Ljava/util/List;

    .line 2130
    .line 2131
    .line 2132
    move-result-object v1

    .line 2133
    move/from16 v13, v23

    .line 2134
    .line 2135
    move/from16 v3, v24

    .line 2136
    .line 2137
    move-object/from16 v23, v20

    .line 2138
    .line 2139
    if-eqz v26, :cond_69

    .line 2140
    .line 2141
    invoke-static/range {v23 .. v23}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 2142
    .line 2143
    .line 2144
    move-result-object v6

    .line 2145
    check-cast v6, Lm1/m;

    .line 2146
    .line 2147
    if-eqz v6, :cond_68

    .line 2148
    .line 2149
    iget v6, v6, Lm1/m;->a:I

    .line 2150
    .line 2151
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2152
    .line 2153
    .line 2154
    move-result-object v6

    .line 2155
    goto :goto_52

    .line 2156
    :cond_68
    const/4 v6, 0x0

    .line 2157
    goto :goto_52

    .line 2158
    :cond_69
    invoke-virtual/range {v31 .. v31}, Lmx0/l;->k()Ljava/lang/Object;

    .line 2159
    .line 2160
    .line 2161
    move-result-object v6

    .line 2162
    check-cast v6, Lm1/m;

    .line 2163
    .line 2164
    if-eqz v6, :cond_68

    .line 2165
    .line 2166
    iget v6, v6, Lm1/m;->a:I

    .line 2167
    .line 2168
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2169
    .line 2170
    .line 2171
    move-result-object v6

    .line 2172
    :goto_52
    if-eqz v26, :cond_6b

    .line 2173
    .line 2174
    invoke-static/range {v23 .. v23}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 2175
    .line 2176
    .line 2177
    move-result-object v7

    .line 2178
    check-cast v7, Lm1/m;

    .line 2179
    .line 2180
    if-eqz v7, :cond_6a

    .line 2181
    .line 2182
    iget v7, v7, Lm1/m;->a:I

    .line 2183
    .line 2184
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2185
    .line 2186
    .line 2187
    move-result-object v9

    .line 2188
    goto :goto_53

    .line 2189
    :cond_6a
    const/4 v9, 0x0

    .line 2190
    goto :goto_53

    .line 2191
    :cond_6b
    invoke-virtual/range {v31 .. v31}, Lmx0/l;->n()Ljava/lang/Object;

    .line 2192
    .line 2193
    .line 2194
    move-result-object v7

    .line 2195
    check-cast v7, Lm1/m;

    .line 2196
    .line 2197
    if-eqz v7, :cond_6a

    .line 2198
    .line 2199
    iget v7, v7, Lm1/m;->a:I

    .line 2200
    .line 2201
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2202
    .line 2203
    .line 2204
    move-result-object v9

    .line 2205
    :goto_53
    if-lt v5, v15, :cond_6d

    .line 2206
    .line 2207
    if-le v12, v0, :cond_6c

    .line 2208
    .line 2209
    goto :goto_54

    .line 2210
    :cond_6c
    const/16 v16, 0x0

    .line 2211
    .line 2212
    :cond_6d
    :goto_54
    new-instance v21, Lm1/k;

    .line 2213
    .line 2214
    const/16 v26, 0x0

    .line 2215
    .line 2216
    move-object/from16 v24, v1

    .line 2217
    .line 2218
    move/from16 v25, v29

    .line 2219
    .line 2220
    move-object/from16 v22, v43

    .line 2221
    .line 2222
    invoke-direct/range {v21 .. v26}, Lm1/k;-><init>(Ll2/b1;Ljava/util/ArrayList;Ljava/util/List;ZI)V

    .line 2223
    .line 2224
    .line 2225
    move-object/from16 v1, v21

    .line 2226
    .line 2227
    move-object/from16 v12, v23

    .line 2228
    .line 2229
    move-object/from16 v0, v24

    .line 2230
    .line 2231
    add-int v5, v13, v38

    .line 2232
    .line 2233
    move-wide/from16 v7, p2

    .line 2234
    .line 2235
    invoke-static {v5, v7, v8}, Lt4/b;->g(IJ)I

    .line 2236
    .line 2237
    .line 2238
    move-result v5

    .line 2239
    add-int v3, v3, v37

    .line 2240
    .line 2241
    invoke-static {v3, v7, v8}, Lt4/b;->f(IJ)I

    .line 2242
    .line 2243
    .line 2244
    move-result v3

    .line 2245
    move-object/from16 v8, v39

    .line 2246
    .line 2247
    move-object/from16 v7, v45

    .line 2248
    .line 2249
    invoke-interface {v7, v5, v3, v8, v1}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 2250
    .line 2251
    .line 2252
    move-result-object v5

    .line 2253
    if-eqz v6, :cond_6e

    .line 2254
    .line 2255
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 2256
    .line 2257
    .line 2258
    move-result v6

    .line 2259
    goto :goto_55

    .line 2260
    :cond_6e
    const/4 v6, 0x0

    .line 2261
    :goto_55
    if-eqz v9, :cond_6f

    .line 2262
    .line 2263
    invoke-virtual {v9}, Ljava/lang/Integer;->intValue()I

    .line 2264
    .line 2265
    .line 2266
    move-result v1

    .line 2267
    goto :goto_56

    .line 2268
    :cond_6f
    const/4 v1, 0x0

    .line 2269
    :goto_56
    invoke-static {v6, v1, v12, v0}, Lo1/y;->m(IILjava/util/ArrayList;Ljava/util/List;)Ljava/util/List;

    .line 2270
    .line 2271
    .line 2272
    move-result-object v12

    .line 2273
    if-eqz v27, :cond_70

    .line 2274
    .line 2275
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2276
    .line 2277
    goto :goto_57

    .line 2278
    :cond_70
    sget-object v0, Lg1/w1;->e:Lg1/w1;

    .line 2279
    .line 2280
    :goto_57
    new-instance v1, Lm1/l;

    .line 2281
    .line 2282
    iget-wide v10, v2, Lm1/i;->h:J

    .line 2283
    .line 2284
    move-object/from16 v9, p1

    .line 2285
    .line 2286
    move/from16 v3, v16

    .line 2287
    .line 2288
    move/from16 v2, v28

    .line 2289
    .line 2290
    move-object/from16 v8, v30

    .line 2291
    .line 2292
    move/from16 v13, v36

    .line 2293
    .line 2294
    move/from16 v18, v42

    .line 2295
    .line 2296
    move/from16 v17, v44

    .line 2297
    .line 2298
    move/from16 v14, v48

    .line 2299
    .line 2300
    move/from16 v6, v51

    .line 2301
    .line 2302
    move-object/from16 v16, v0

    .line 2303
    .line 2304
    move-object v0, v1

    .line 2305
    move-object/from16 v36, v7

    .line 2306
    .line 2307
    move/from16 v7, v35

    .line 2308
    .line 2309
    move-object/from16 v1, v40

    .line 2310
    .line 2311
    invoke-direct/range {v0 .. v18}, Lm1/l;-><init>(Lm1/m;IZFLt3/r0;FZLvy0/b0;Lt4/c;JLjava/util/List;IIILg1/w1;II)V

    .line 2312
    .line 2313
    .line 2314
    :goto_58
    invoke-interface/range {v36 .. v36}, Lt3/t;->I()Z

    .line 2315
    .line 2316
    .line 2317
    move-result v1

    .line 2318
    move-object/from16 v2, v46

    .line 2319
    .line 2320
    const/4 v13, 0x0

    .line 2321
    invoke-virtual {v2, v0, v1, v13}, Lm1/t;->g(Lm1/l;ZZ)V

    .line 2322
    .line 2323
    .line 2324
    return-object v0

    .line 2325
    :goto_59
    invoke-static {v3, v6, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 2326
    .line 2327
    .line 2328
    throw v0

    .line 2329
    :cond_71
    const-string v0, "null horizontalAlignment when isVertical == false"

    .line 2330
    .line 2331
    invoke-static {v0}, Lj1/b;->b(Ljava/lang/String;)Ljava/lang/Void;

    .line 2332
    .line 2333
    .line 2334
    new-instance v0, La8/r0;

    .line 2335
    .line 2336
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2337
    .line 2338
    .line 2339
    throw v0
.end method
