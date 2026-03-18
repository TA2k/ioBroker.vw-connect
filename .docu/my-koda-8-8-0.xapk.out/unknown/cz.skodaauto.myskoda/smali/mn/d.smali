.class public final Lmn/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:Lay0/o;

.field public final synthetic g:Lay0/o;

.field public final synthetic h:Lmn/a;

.field public final synthetic i:Z

.field public final synthetic j:J

.field public final synthetic k:Le3/n0;


# direct methods
.method public constructor <init>(Lay0/o;Lay0/o;Lmn/a;ZJLe3/n0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lmn/d;->f:Lay0/o;

    .line 2
    .line 3
    iput-object p2, p0, Lmn/d;->g:Lay0/o;

    .line 4
    .line 5
    iput-object p3, p0, Lmn/d;->h:Lmn/a;

    .line 6
    .line 7
    iput-boolean p4, p0, Lmn/d;->i:Z

    .line 8
    .line 9
    iput-wide p5, p0, Lmn/d;->j:J

    .line 10
    .line 11
    iput-object p7, p0, Lmn/d;->k:Le3/n0;

    .line 12
    .line 13
    const/4 p1, 0x3

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lx2/s;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Number;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 16
    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    const-string v5, "$this$composed"

    .line 24
    .line 25
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    move-object v11, v2

    .line 29
    check-cast v11, Ll2/t;

    .line 30
    .line 31
    const v2, -0x4865c6b8

    .line 32
    .line 33
    .line 34
    invoke-virtual {v11, v2}, Ll2/t;->Z(I)V

    .line 35
    .line 36
    .line 37
    const v2, 0x2fee86f2

    .line 38
    .line 39
    .line 40
    invoke-virtual {v11, v2}, Ll2/t;->Z(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 48
    .line 49
    if-ne v2, v5, :cond_0

    .line 50
    .line 51
    new-instance v2, Lv3/u1;

    .line 52
    .line 53
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :cond_0
    move-object/from16 v20, v2

    .line 60
    .line 61
    check-cast v20, Lv3/u1;

    .line 62
    .line 63
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    const v2, 0x2fee8729

    .line 67
    .line 68
    .line 69
    invoke-virtual {v11, v2}, Ll2/t;->Z(I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    if-ne v2, v5, :cond_1

    .line 77
    .line 78
    new-instance v2, Lv3/u1;

    .line 79
    .line 80
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    :cond_1
    move-object/from16 v19, v2

    .line 87
    .line 88
    check-cast v19, Lv3/u1;

    .line 89
    .line 90
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 91
    .line 92
    .line 93
    const v2, 0x2fee8763

    .line 94
    .line 95
    .line 96
    invoke-virtual {v11, v2}, Ll2/t;->Z(I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    if-ne v2, v5, :cond_2

    .line 104
    .line 105
    new-instance v2, Lv3/u1;

    .line 106
    .line 107
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 108
    .line 109
    .line 110
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_2
    move-object v14, v2

    .line 114
    check-cast v14, Lv3/u1;

    .line 115
    .line 116
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 117
    .line 118
    .line 119
    const v2, 0x2fee87d4

    .line 120
    .line 121
    .line 122
    invoke-virtual {v11, v2}, Ll2/t;->Z(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    const/4 v13, 0x0

    .line 130
    if-ne v2, v5, :cond_3

    .line 131
    .line 132
    invoke-static {v13}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    invoke-static {v2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 137
    .line 138
    .line 139
    move-result-object v2

    .line 140
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    :cond_3
    check-cast v2, Ll2/b1;

    .line 144
    .line 145
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 146
    .line 147
    .line 148
    const v6, 0x2fee8837

    .line 149
    .line 150
    .line 151
    invoke-virtual {v11, v6}, Ll2/t;->Z(I)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v6

    .line 158
    iget-boolean v15, v0, Lmn/d;->i:Z

    .line 159
    .line 160
    if-ne v6, v5, :cond_4

    .line 161
    .line 162
    new-instance v6, Lc1/n0;

    .line 163
    .line 164
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    invoke-direct {v6, v7}, Lc1/n0;-><init>(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    :cond_4
    check-cast v6, Lc1/n0;

    .line 175
    .line 176
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 180
    .line 181
    .line 182
    move-result-object v7

    .line 183
    invoke-virtual {v6, v7}, Lc1/n0;->b0(Ljava/lang/Boolean;)V

    .line 184
    .line 185
    .line 186
    const-string v7, "placeholder_crossfade"

    .line 187
    .line 188
    const/16 v8, 0x30

    .line 189
    .line 190
    invoke-static {v6, v7, v11, v8}, Lc1/z1;->e(Lc1/n0;Ljava/lang/String;Ll2/o;I)Lc1/w1;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    sget-object v10, Lc1/d;->j:Lc1/b2;

    .line 195
    .line 196
    iget-object v7, v6, Lc1/w1;->a:Lap0/o;

    .line 197
    .line 198
    iget-object v8, v6, Lc1/w1;->d:Ll2/j1;

    .line 199
    .line 200
    invoke-virtual {v7}, Lap0/o;->D()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    check-cast v7, Ljava/lang/Boolean;

    .line 205
    .line 206
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 207
    .line 208
    .line 209
    move-result v7

    .line 210
    const v9, -0x7c493a53

    .line 211
    .line 212
    .line 213
    invoke-virtual {v11, v9}, Ll2/t;->Z(I)V

    .line 214
    .line 215
    .line 216
    const/high16 v16, 0x3f800000    # 1.0f

    .line 217
    .line 218
    if-eqz v7, :cond_5

    .line 219
    .line 220
    move/from16 v7, v16

    .line 221
    .line 222
    goto :goto_0

    .line 223
    :cond_5
    move v7, v13

    .line 224
    :goto_0
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 225
    .line 226
    .line 227
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 228
    .line 229
    .line 230
    move-result-object v7

    .line 231
    invoke-virtual {v8}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v12

    .line 235
    check-cast v12, Ljava/lang/Boolean;

    .line 236
    .line 237
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 238
    .line 239
    .line 240
    move-result v12

    .line 241
    invoke-virtual {v11, v9}, Ll2/t;->Z(I)V

    .line 242
    .line 243
    .line 244
    if-eqz v12, :cond_6

    .line 245
    .line 246
    move/from16 v9, v16

    .line 247
    .line 248
    goto :goto_1

    .line 249
    :cond_6
    move v9, v13

    .line 250
    :goto_1
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 251
    .line 252
    .line 253
    invoke-static {v9}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 254
    .line 255
    .line 256
    move-result-object v9

    .line 257
    invoke-virtual {v6}, Lc1/w1;->f()Lc1/r1;

    .line 258
    .line 259
    .line 260
    move-result-object v12

    .line 261
    iget-object v13, v0, Lmn/d;->f:Lay0/o;

    .line 262
    .line 263
    invoke-interface {v13, v12, v11, v4}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v12

    .line 267
    check-cast v12, Lc1/a0;

    .line 268
    .line 269
    move-object v13, v8

    .line 270
    move-object v8, v9

    .line 271
    move-object v9, v12

    .line 272
    const/high16 v12, 0x30000

    .line 273
    .line 274
    invoke-static/range {v6 .. v12}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 275
    .line 276
    .line 277
    move-result-object v22

    .line 278
    iget-object v7, v6, Lc1/w1;->a:Lap0/o;

    .line 279
    .line 280
    invoke-virtual {v7}, Lap0/o;->D()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v7

    .line 284
    check-cast v7, Ljava/lang/Boolean;

    .line 285
    .line 286
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 287
    .line 288
    .line 289
    move-result v7

    .line 290
    const v8, 0x3b2ccfe7

    .line 291
    .line 292
    .line 293
    invoke-virtual {v11, v8}, Ll2/t;->Z(I)V

    .line 294
    .line 295
    .line 296
    if-eqz v7, :cond_7

    .line 297
    .line 298
    const/4 v7, 0x0

    .line 299
    goto :goto_2

    .line 300
    :cond_7
    move/from16 v7, v16

    .line 301
    .line 302
    :goto_2
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 303
    .line 304
    .line 305
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 306
    .line 307
    .line 308
    move-result-object v7

    .line 309
    invoke-virtual {v13}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v9

    .line 313
    check-cast v9, Ljava/lang/Boolean;

    .line 314
    .line 315
    invoke-virtual {v9}, Ljava/lang/Boolean;->booleanValue()Z

    .line 316
    .line 317
    .line 318
    move-result v9

    .line 319
    invoke-virtual {v11, v8}, Ll2/t;->Z(I)V

    .line 320
    .line 321
    .line 322
    if-eqz v9, :cond_8

    .line 323
    .line 324
    const/4 v13, 0x0

    .line 325
    goto :goto_3

    .line 326
    :cond_8
    move/from16 v13, v16

    .line 327
    .line 328
    :goto_3
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 329
    .line 330
    .line 331
    invoke-static {v13}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 332
    .line 333
    .line 334
    move-result-object v8

    .line 335
    invoke-virtual {v6}, Lc1/w1;->f()Lc1/r1;

    .line 336
    .line 337
    .line 338
    move-result-object v9

    .line 339
    iget-object v13, v0, Lmn/d;->g:Lay0/o;

    .line 340
    .line 341
    invoke-interface {v13, v9, v11, v4}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v4

    .line 345
    move-object v9, v4

    .line 346
    check-cast v9, Lc1/a0;

    .line 347
    .line 348
    invoke-static/range {v6 .. v12}, Lc1/z1;->c(Lc1/w1;Ljava/lang/Object;Ljava/lang/Object;Lc1/a0;Lc1/b2;Ll2/o;I)Lc1/t1;

    .line 349
    .line 350
    .line 351
    move-result-object v21

    .line 352
    iget-object v4, v0, Lmn/d;->h:Lmn/a;

    .line 353
    .line 354
    const/4 v6, 0x0

    .line 355
    if-eqz v4, :cond_9

    .line 356
    .line 357
    iget-object v7, v4, Lmn/a;->b:Lc1/f0;

    .line 358
    .line 359
    move-object v9, v7

    .line 360
    goto :goto_4

    .line 361
    :cond_9
    move-object v9, v6

    .line 362
    :goto_4
    const v7, 0x2fee8b4a

    .line 363
    .line 364
    .line 365
    invoke-virtual {v11, v7}, Ll2/t;->Z(I)V

    .line 366
    .line 367
    .line 368
    if-eqz v9, :cond_b

    .line 369
    .line 370
    if-nez v15, :cond_a

    .line 371
    .line 372
    invoke-virtual/range {v22 .. v22}, Lc1/t1;->getValue()Ljava/lang/Object;

    .line 373
    .line 374
    .line 375
    move-result-object v7

    .line 376
    check-cast v7, Ljava/lang/Number;

    .line 377
    .line 378
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 379
    .line 380
    .line 381
    move-result v7

    .line 382
    const v8, 0x3c23d70a    # 0.01f

    .line 383
    .line 384
    .line 385
    cmpl-float v7, v7, v8

    .line 386
    .line 387
    if-ltz v7, :cond_b

    .line 388
    .line 389
    :cond_a
    const/4 v7, 0x1

    .line 390
    invoke-static {v6, v11, v7}, Lc1/d;->r(Ljava/lang/String;Ll2/o;I)Lc1/i0;

    .line 391
    .line 392
    .line 393
    move-result-object v6

    .line 394
    const/16 v12, 0x11b8

    .line 395
    .line 396
    const/16 v13, 0x8

    .line 397
    .line 398
    const/4 v7, 0x0

    .line 399
    const/high16 v8, 0x3f800000    # 1.0f

    .line 400
    .line 401
    const/4 v10, 0x0

    .line 402
    invoke-static/range {v6 .. v13}, Lc1/d;->g(Lc1/i0;FFLc1/f0;Ljava/lang/String;Ll2/o;II)Lc1/g0;

    .line 403
    .line 404
    .line 405
    move-result-object v6

    .line 406
    iget-object v6, v6, Lc1/g0;->g:Ll2/j1;

    .line 407
    .line 408
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    check-cast v6, Ljava/lang/Number;

    .line 413
    .line 414
    invoke-virtual {v6}, Ljava/lang/Number;->floatValue()F

    .line 415
    .line 416
    .line 417
    move-result v6

    .line 418
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 419
    .line 420
    .line 421
    move-result-object v6

    .line 422
    invoke-interface {v2, v6}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 423
    .line 424
    .line 425
    :cond_b
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 426
    .line 427
    .line 428
    const v6, 0x2fee8c9b

    .line 429
    .line 430
    .line 431
    invoke-virtual {v11, v6}, Ll2/t;->Z(I)V

    .line 432
    .line 433
    .line 434
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 435
    .line 436
    .line 437
    move-result-object v6

    .line 438
    if-ne v6, v5, :cond_c

    .line 439
    .line 440
    invoke-static {}, Le3/j0;->h()Le3/g;

    .line 441
    .line 442
    .line 443
    move-result-object v6

    .line 444
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 445
    .line 446
    .line 447
    :cond_c
    move-object v13, v6

    .line 448
    check-cast v13, Le3/g;

    .line 449
    .line 450
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 451
    .line 452
    .line 453
    const v6, 0x2fee8cb4

    .line 454
    .line 455
    .line 456
    invoke-virtual {v11, v6}, Ll2/t;->Z(I)V

    .line 457
    .line 458
    .line 459
    iget-wide v6, v0, Lmn/d;->j:J

    .line 460
    .line 461
    invoke-virtual {v11, v6, v7}, Ll2/t;->f(J)Z

    .line 462
    .line 463
    .line 464
    move-result v6

    .line 465
    iget-object v7, v0, Lmn/d;->k:Le3/n0;

    .line 466
    .line 467
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v7

    .line 471
    or-int/2addr v6, v7

    .line 472
    invoke-virtual {v11, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    move-result v4

    .line 476
    or-int/2addr v4, v6

    .line 477
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 478
    .line 479
    .line 480
    move-result-object v6

    .line 481
    if-nez v4, :cond_d

    .line 482
    .line 483
    if-ne v6, v5, :cond_e

    .line 484
    .line 485
    :cond_d
    new-instance v12, Lmn/c;

    .line 486
    .line 487
    iget-object v15, v0, Lmn/d;->k:Le3/n0;

    .line 488
    .line 489
    iget-wide v4, v0, Lmn/d;->j:J

    .line 490
    .line 491
    iget-object v0, v0, Lmn/d;->h:Lmn/a;

    .line 492
    .line 493
    move-object/from16 v18, v0

    .line 494
    .line 495
    move-object/from16 v23, v2

    .line 496
    .line 497
    move-wide/from16 v16, v4

    .line 498
    .line 499
    invoke-direct/range {v12 .. v23}, Lmn/c;-><init>(Le3/g;Lv3/u1;Le3/n0;JLmn/a;Lv3/u1;Lv3/u1;Lc1/t1;Lc1/t1;Ll2/b1;)V

    .line 500
    .line 501
    .line 502
    invoke-static {v1, v12}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 503
    .line 504
    .line 505
    move-result-object v6

    .line 506
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 507
    .line 508
    .line 509
    :cond_e
    check-cast v6, Lx2/s;

    .line 510
    .line 511
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 512
    .line 513
    .line 514
    invoke-virtual {v11, v3}, Ll2/t;->q(Z)V

    .line 515
    .line 516
    .line 517
    return-object v6
.end method
