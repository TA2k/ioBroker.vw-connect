.class public abstract Li40/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0xaa

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Li40/w;->a:F

    .line 5
    .line 6
    const/16 v0, 0x36

    .line 7
    .line 8
    int-to-float v0, v0

    .line 9
    sput v0, Li40/w;->b:F

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Landroid/net/Uri;ZLay0/k;Ll2/o;I)V
    .locals 45

    .line 1
    move/from16 v4, p3

    .line 2
    .line 3
    move/from16 v6, p6

    .line 4
    .line 5
    move-object/from16 v14, p5

    .line 6
    .line 7
    check-cast v14, Ll2/t;

    .line 8
    .line 9
    const v0, -0x7fb65ceb

    .line 10
    .line 11
    .line 12
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v0, v6, 0x6

    .line 16
    .line 17
    move-object/from16 v1, p0

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    const/4 v0, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v6

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v6

    .line 33
    :goto_1
    and-int/lit8 v2, v6, 0x30

    .line 34
    .line 35
    if-nez v2, :cond_3

    .line 36
    .line 37
    move-object/from16 v2, p1

    .line 38
    .line 39
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v3

    .line 43
    if-eqz v3, :cond_2

    .line 44
    .line 45
    const/16 v3, 0x20

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_2
    const/16 v3, 0x10

    .line 49
    .line 50
    :goto_2
    or-int/2addr v0, v3

    .line 51
    goto :goto_3

    .line 52
    :cond_3
    move-object/from16 v2, p1

    .line 53
    .line 54
    :goto_3
    and-int/lit16 v3, v6, 0x180

    .line 55
    .line 56
    if-nez v3, :cond_5

    .line 57
    .line 58
    move-object/from16 v3, p2

    .line 59
    .line 60
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_4

    .line 65
    .line 66
    const/16 v5, 0x100

    .line 67
    .line 68
    goto :goto_4

    .line 69
    :cond_4
    const/16 v5, 0x80

    .line 70
    .line 71
    :goto_4
    or-int/2addr v0, v5

    .line 72
    goto :goto_5

    .line 73
    :cond_5
    move-object/from16 v3, p2

    .line 74
    .line 75
    :goto_5
    and-int/lit16 v5, v6, 0xc00

    .line 76
    .line 77
    if-nez v5, :cond_7

    .line 78
    .line 79
    invoke-virtual {v14, v4}, Ll2/t;->h(Z)Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_6

    .line 84
    .line 85
    const/16 v5, 0x800

    .line 86
    .line 87
    goto :goto_6

    .line 88
    :cond_6
    const/16 v5, 0x400

    .line 89
    .line 90
    :goto_6
    or-int/2addr v0, v5

    .line 91
    :cond_7
    and-int/lit16 v5, v6, 0x6000

    .line 92
    .line 93
    const/16 v7, 0x4000

    .line 94
    .line 95
    move-object/from16 v12, p4

    .line 96
    .line 97
    if-nez v5, :cond_9

    .line 98
    .line 99
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 100
    .line 101
    .line 102
    move-result v5

    .line 103
    if-eqz v5, :cond_8

    .line 104
    .line 105
    move v5, v7

    .line 106
    goto :goto_7

    .line 107
    :cond_8
    const/16 v5, 0x2000

    .line 108
    .line 109
    :goto_7
    or-int/2addr v0, v5

    .line 110
    :cond_9
    and-int/lit16 v5, v0, 0x2493

    .line 111
    .line 112
    const/16 v8, 0x2492

    .line 113
    .line 114
    if-eq v5, v8, :cond_a

    .line 115
    .line 116
    const/4 v5, 0x1

    .line 117
    goto :goto_8

    .line 118
    :cond_a
    const/4 v5, 0x0

    .line 119
    :goto_8
    and-int/lit8 v8, v0, 0x1

    .line 120
    .line 121
    invoke-virtual {v14, v8, v5}, Ll2/t;->O(IZ)Z

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    if-eqz v5, :cond_1a

    .line 126
    .line 127
    sget v5, Le3/y;->b:I

    .line 128
    .line 129
    sget-object v5, Lw3/h1;->g:Ll2/u2;

    .line 130
    .line 131
    invoke-virtual {v14, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v5

    .line 135
    check-cast v5, Le3/w;

    .line 136
    .line 137
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v8

    .line 141
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 142
    .line 143
    if-ne v8, v10, :cond_b

    .line 144
    .line 145
    new-instance v8, Le3/x;

    .line 146
    .line 147
    invoke-direct {v8, v5}, Le3/x;-><init>(Le3/w;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :cond_b
    check-cast v8, Le3/x;

    .line 154
    .line 155
    iget-object v11, v8, Le3/x;->e:Lh3/c;

    .line 156
    .line 157
    if-eqz v4, :cond_10

    .line 158
    .line 159
    const v5, -0x6c365ab

    .line 160
    .line 161
    .line 162
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v5

    .line 169
    if-ne v5, v10, :cond_c

    .line 170
    .line 171
    invoke-static {v14}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 172
    .line 173
    .line 174
    move-result-object v5

    .line 175
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :cond_c
    check-cast v5, Lvy0/b0;

    .line 179
    .line 180
    sget-object v8, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 181
    .line 182
    invoke-virtual {v14, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v13

    .line 186
    invoke-virtual {v14, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 187
    .line 188
    .line 189
    move-result v16

    .line 190
    or-int v13, v13, v16

    .line 191
    .line 192
    const v16, 0xe000

    .line 193
    .line 194
    .line 195
    and-int v9, v0, v16

    .line 196
    .line 197
    if-ne v9, v7, :cond_d

    .line 198
    .line 199
    const/4 v7, 0x1

    .line 200
    goto :goto_9

    .line 201
    :cond_d
    const/4 v7, 0x0

    .line 202
    :goto_9
    or-int/2addr v7, v13

    .line 203
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v9

    .line 207
    if-nez v7, :cond_e

    .line 208
    .line 209
    if-ne v9, v10, :cond_f

    .line 210
    .line 211
    :cond_e
    move-object v7, v8

    .line 212
    goto :goto_a

    .line 213
    :cond_f
    move-object v7, v8

    .line 214
    move-object v5, v10

    .line 215
    const/4 v15, 0x0

    .line 216
    goto :goto_b

    .line 217
    :goto_a
    new-instance v8, Laa/s;

    .line 218
    .line 219
    const/16 v9, 0xa

    .line 220
    .line 221
    const/4 v13, 0x0

    .line 222
    move-object v15, v10

    .line 223
    move-object v10, v5

    .line 224
    move-object v5, v15

    .line 225
    const/4 v15, 0x0

    .line 226
    invoke-direct/range {v8 .. v13}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v14, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 230
    .line 231
    .line 232
    move-object v9, v8

    .line 233
    :goto_b
    check-cast v9, Lay0/n;

    .line 234
    .line 235
    invoke-static {v9, v7, v14}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 236
    .line 237
    .line 238
    :goto_c
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 239
    .line 240
    .line 241
    goto :goto_d

    .line 242
    :cond_10
    move-object v5, v10

    .line 243
    const/4 v15, 0x0

    .line 244
    const v7, -0x6e074b3

    .line 245
    .line 246
    .line 247
    invoke-virtual {v14, v7}, Ll2/t;->Y(I)V

    .line 248
    .line 249
    .line 250
    goto :goto_c

    .line 251
    :goto_d
    invoke-static {v14}, Lxf0/y1;->F(Ll2/o;)Z

    .line 252
    .line 253
    .line 254
    move-result v7

    .line 255
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 256
    .line 257
    if-eqz v7, :cond_11

    .line 258
    .line 259
    const v5, -0x6bc2493

    .line 260
    .line 261
    .line 262
    invoke-virtual {v14, v5}, Ll2/t;->Y(I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 266
    .line 267
    .line 268
    move-object v5, v8

    .line 269
    goto :goto_e

    .line 270
    :cond_11
    const v7, -0x6bb7ba6

    .line 271
    .line 272
    .line 273
    invoke-virtual {v14, v7}, Ll2/t;->Y(I)V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v14, v11}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v9

    .line 284
    if-nez v7, :cond_12

    .line 285
    .line 286
    if-ne v9, v5, :cond_13

    .line 287
    .line 288
    :cond_12
    new-instance v9, Le81/w;

    .line 289
    .line 290
    const/16 v5, 0x1c

    .line 291
    .line 292
    invoke-direct {v9, v11, v5}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 293
    .line 294
    .line 295
    invoke-virtual {v14, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    :cond_13
    check-cast v9, Lay0/k;

    .line 299
    .line 300
    invoke-static {v8, v9}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 301
    .line 302
    .line 303
    move-result-object v5

    .line 304
    invoke-virtual {v14, v15}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    :goto_e
    sget-object v7, Lx2/c;->d:Lx2/j;

    .line 308
    .line 309
    invoke-static {v7, v15}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 310
    .line 311
    .line 312
    move-result-object v7

    .line 313
    iget-wide v9, v14, Ll2/t;->T:J

    .line 314
    .line 315
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 316
    .line 317
    .line 318
    move-result v9

    .line 319
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 320
    .line 321
    .line 322
    move-result-object v10

    .line 323
    invoke-static {v14, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 324
    .line 325
    .line 326
    move-result-object v5

    .line 327
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 328
    .line 329
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 333
    .line 334
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 335
    .line 336
    .line 337
    iget-boolean v12, v14, Ll2/t;->S:Z

    .line 338
    .line 339
    if-eqz v12, :cond_14

    .line 340
    .line 341
    invoke-virtual {v14, v11}, Ll2/t;->l(Lay0/a;)V

    .line 342
    .line 343
    .line 344
    goto :goto_f

    .line 345
    :cond_14
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 346
    .line 347
    .line 348
    :goto_f
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 349
    .line 350
    invoke-static {v12, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 351
    .line 352
    .line 353
    sget-object v7, Lv3/j;->f:Lv3/h;

    .line 354
    .line 355
    invoke-static {v7, v10, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 356
    .line 357
    .line 358
    sget-object v10, Lv3/j;->j:Lv3/h;

    .line 359
    .line 360
    iget-boolean v13, v14, Ll2/t;->S:Z

    .line 361
    .line 362
    if-nez v13, :cond_15

    .line 363
    .line 364
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v13

    .line 368
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 369
    .line 370
    .line 371
    move-result-object v15

    .line 372
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    move-result v13

    .line 376
    if-nez v13, :cond_16

    .line 377
    .line 378
    :cond_15
    invoke-static {v9, v14, v9, v10}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 379
    .line 380
    .line 381
    :cond_16
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 382
    .line 383
    invoke-static {v9, v5, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 384
    .line 385
    .line 386
    const v5, 0x7f08023f

    .line 387
    .line 388
    .line 389
    const/4 v15, 0x0

    .line 390
    invoke-static {v5, v15, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 391
    .line 392
    .line 393
    move-result-object v5

    .line 394
    move/from16 v16, v15

    .line 395
    .line 396
    const/16 v15, 0x30

    .line 397
    .line 398
    move/from16 v13, v16

    .line 399
    .line 400
    const/16 v16, 0x7c

    .line 401
    .line 402
    move-object/from16 v17, v8

    .line 403
    .line 404
    const/4 v8, 0x0

    .line 405
    move-object/from16 v18, v9

    .line 406
    .line 407
    const/4 v9, 0x0

    .line 408
    move-object/from16 v19, v10

    .line 409
    .line 410
    const/4 v10, 0x0

    .line 411
    move-object/from16 v20, v11

    .line 412
    .line 413
    const/4 v11, 0x0

    .line 414
    move-object/from16 v21, v12

    .line 415
    .line 416
    const/4 v12, 0x0

    .line 417
    move/from16 v22, v13

    .line 418
    .line 419
    const/4 v13, 0x0

    .line 420
    move/from16 p5, v0

    .line 421
    .line 422
    move-object v1, v7

    .line 423
    move-object/from16 v4, v17

    .line 424
    .line 425
    move-object/from16 v3, v18

    .line 426
    .line 427
    move-object/from16 v2, v19

    .line 428
    .line 429
    move-object/from16 v0, v21

    .line 430
    .line 431
    move/from16 v6, v22

    .line 432
    .line 433
    move-object v7, v5

    .line 434
    move-object/from16 v5, v20

    .line 435
    .line 436
    invoke-static/range {v7 .. v16}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 437
    .line 438
    .line 439
    const/high16 v7, 0x3f800000    # 1.0f

    .line 440
    .line 441
    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 442
    .line 443
    .line 444
    move-result-object v8

    .line 445
    const/16 v13, 0xd

    .line 446
    .line 447
    const/4 v9, 0x0

    .line 448
    sget v10, Li40/w;->b:F

    .line 449
    .line 450
    const/4 v11, 0x0

    .line 451
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 452
    .line 453
    .line 454
    move-result-object v7

    .line 455
    sget-object v8, Lx2/c;->q:Lx2/h;

    .line 456
    .line 457
    sget-object v9, Lk1/j;->c:Lk1/e;

    .line 458
    .line 459
    const/16 v10, 0x30

    .line 460
    .line 461
    invoke-static {v9, v8, v14, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 462
    .line 463
    .line 464
    move-result-object v8

    .line 465
    iget-wide v11, v14, Ll2/t;->T:J

    .line 466
    .line 467
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 468
    .line 469
    .line 470
    move-result v9

    .line 471
    invoke-virtual {v14}, Ll2/t;->m()Ll2/p1;

    .line 472
    .line 473
    .line 474
    move-result-object v11

    .line 475
    invoke-static {v14, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 476
    .line 477
    .line 478
    move-result-object v7

    .line 479
    invoke-virtual {v14}, Ll2/t;->c0()V

    .line 480
    .line 481
    .line 482
    iget-boolean v12, v14, Ll2/t;->S:Z

    .line 483
    .line 484
    if-eqz v12, :cond_17

    .line 485
    .line 486
    invoke-virtual {v14, v5}, Ll2/t;->l(Lay0/a;)V

    .line 487
    .line 488
    .line 489
    goto :goto_10

    .line 490
    :cond_17
    invoke-virtual {v14}, Ll2/t;->m0()V

    .line 491
    .line 492
    .line 493
    :goto_10
    invoke-static {v0, v8, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 494
    .line 495
    .line 496
    invoke-static {v1, v11, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 497
    .line 498
    .line 499
    iget-boolean v0, v14, Ll2/t;->S:Z

    .line 500
    .line 501
    if-nez v0, :cond_18

    .line 502
    .line 503
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 508
    .line 509
    .line 510
    move-result-object v1

    .line 511
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result v0

    .line 515
    if-nez v0, :cond_19

    .line 516
    .line 517
    :cond_18
    invoke-static {v9, v14, v9, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 518
    .line 519
    .line 520
    :cond_19
    invoke-static {v3, v7, v14}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 521
    .line 522
    .line 523
    sget v0, Li40/w;->a:F

    .line 524
    .line 525
    invoke-static {v4, v0}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 526
    .line 527
    .line 528
    move-result-object v8

    .line 529
    invoke-static {v14}, Li40/l1;->x0(Ll2/o;)I

    .line 530
    .line 531
    .line 532
    move-result v0

    .line 533
    invoke-static {v0, v6, v14}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 534
    .line 535
    .line 536
    move-result-object v16

    .line 537
    shr-int/lit8 v0, p5, 0x6

    .line 538
    .line 539
    and-int/lit8 v0, v0, 0xe

    .line 540
    .line 541
    or-int/lit8 v23, v0, 0x30

    .line 542
    .line 543
    const/16 v24, 0x0

    .line 544
    .line 545
    const v25, 0x1f7fc

    .line 546
    .line 547
    .line 548
    const/4 v9, 0x0

    .line 549
    const/4 v10, 0x0

    .line 550
    const/4 v11, 0x0

    .line 551
    const/4 v12, 0x0

    .line 552
    const/4 v13, 0x0

    .line 553
    move-object/from16 v22, v14

    .line 554
    .line 555
    const/4 v14, 0x0

    .line 556
    const/4 v15, 0x0

    .line 557
    const/16 v17, 0x0

    .line 558
    .line 559
    const/16 v18, 0x0

    .line 560
    .line 561
    const/16 v19, 0x0

    .line 562
    .line 563
    const/16 v20, 0x0

    .line 564
    .line 565
    const/16 v21, 0x0

    .line 566
    .line 567
    move-object/from16 v7, p2

    .line 568
    .line 569
    invoke-static/range {v7 .. v25}, Lxf0/i0;->c(Landroid/net/Uri;Lx2/s;Lay0/a;Lay0/a;Lay0/a;Ld01/h0;Lx2/e;Lt3/k;Ljava/util/List;Li3/c;Li3/c;Li3/c;ZZLe3/m;Ll2/o;III)V

    .line 570
    .line 571
    .line 572
    move-object/from16 v14, v22

    .line 573
    .line 574
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 575
    .line 576
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v1

    .line 580
    check-cast v1, Lj91/c;

    .line 581
    .line 582
    iget v1, v1, Lj91/c;->f:F

    .line 583
    .line 584
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 585
    .line 586
    .line 587
    move-result-object v1

    .line 588
    invoke-static {v14, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 589
    .line 590
    .line 591
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 592
    .line 593
    invoke-virtual {v14, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    move-result-object v2

    .line 597
    check-cast v2, Lj91/f;

    .line 598
    .line 599
    invoke-virtual {v2}, Lj91/f;->k()Lg4/p0;

    .line 600
    .line 601
    .line 602
    move-result-object v29

    .line 603
    sget-wide v30, Le3/s;->e:J

    .line 604
    .line 605
    const/16 v42, 0x0

    .line 606
    .line 607
    const v43, 0xfffffe

    .line 608
    .line 609
    .line 610
    const-wide/16 v32, 0x0

    .line 611
    .line 612
    const/16 v34, 0x0

    .line 613
    .line 614
    const/16 v35, 0x0

    .line 615
    .line 616
    const-wide/16 v36, 0x0

    .line 617
    .line 618
    const/16 v38, 0x0

    .line 619
    .line 620
    const-wide/16 v39, 0x0

    .line 621
    .line 622
    const/16 v41, 0x0

    .line 623
    .line 624
    invoke-static/range {v29 .. v43}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 625
    .line 626
    .line 627
    move-result-object v8

    .line 628
    and-int/lit8 v26, p5, 0xe

    .line 629
    .line 630
    const/16 v27, 0x0

    .line 631
    .line 632
    const v28, 0xfffc

    .line 633
    .line 634
    .line 635
    const-wide/16 v10, 0x0

    .line 636
    .line 637
    const-wide/16 v12, 0x0

    .line 638
    .line 639
    move-object/from16 v25, v14

    .line 640
    .line 641
    const/4 v14, 0x0

    .line 642
    const-wide/16 v15, 0x0

    .line 643
    .line 644
    const-wide/16 v19, 0x0

    .line 645
    .line 646
    const/16 v21, 0x0

    .line 647
    .line 648
    const/16 v22, 0x0

    .line 649
    .line 650
    const/16 v23, 0x0

    .line 651
    .line 652
    const/16 v24, 0x0

    .line 653
    .line 654
    move-object/from16 v7, p0

    .line 655
    .line 656
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 657
    .line 658
    .line 659
    move-object/from16 v14, v25

    .line 660
    .line 661
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 662
    .line 663
    .line 664
    move-result-object v0

    .line 665
    check-cast v0, Lj91/c;

    .line 666
    .line 667
    iget v0, v0, Lj91/c;->c:F

    .line 668
    .line 669
    invoke-static {v4, v0, v14, v1}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v0

    .line 673
    check-cast v0, Lj91/f;

    .line 674
    .line 675
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 676
    .line 677
    .line 678
    move-result-object v0

    .line 679
    const/16 v43, 0x0

    .line 680
    .line 681
    const v44, 0xfffffe

    .line 682
    .line 683
    .line 684
    const-wide/16 v33, 0x0

    .line 685
    .line 686
    const/16 v36, 0x0

    .line 687
    .line 688
    const-wide/16 v37, 0x0

    .line 689
    .line 690
    const/16 v39, 0x0

    .line 691
    .line 692
    const-wide/16 v40, 0x0

    .line 693
    .line 694
    move-wide/from16 v31, v30

    .line 695
    .line 696
    move-object/from16 v30, v0

    .line 697
    .line 698
    invoke-static/range {v30 .. v44}, Lg4/p0;->a(Lg4/p0;JJLk4/x;Lk4/n;JIJLg4/y;Lr4/i;I)Lg4/p0;

    .line 699
    .line 700
    .line 701
    move-result-object v8

    .line 702
    const-string v0, "loyalty_program_badge_share_club_name"

    .line 703
    .line 704
    invoke-static {v4, v0}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 705
    .line 706
    .line 707
    move-result-object v9

    .line 708
    shr-int/lit8 v0, p5, 0x3

    .line 709
    .line 710
    and-int/lit8 v0, v0, 0xe

    .line 711
    .line 712
    or-int/lit16 v0, v0, 0x180

    .line 713
    .line 714
    const v28, 0xfff8

    .line 715
    .line 716
    .line 717
    const/4 v14, 0x0

    .line 718
    move-object/from16 v7, p1

    .line 719
    .line 720
    move/from16 v26, v0

    .line 721
    .line 722
    invoke-static/range {v7 .. v28}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 723
    .line 724
    .line 725
    move-object/from16 v14, v25

    .line 726
    .line 727
    const/4 v0, 0x1

    .line 728
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 729
    .line 730
    .line 731
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 732
    .line 733
    .line 734
    goto :goto_11

    .line 735
    :cond_1a
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 736
    .line 737
    .line 738
    :goto_11
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 739
    .line 740
    .line 741
    move-result-object v8

    .line 742
    if-eqz v8, :cond_1b

    .line 743
    .line 744
    new-instance v0, Ld80/k;

    .line 745
    .line 746
    const/4 v7, 0x3

    .line 747
    move-object/from16 v1, p0

    .line 748
    .line 749
    move-object/from16 v2, p1

    .line 750
    .line 751
    move-object/from16 v3, p2

    .line 752
    .line 753
    move/from16 v4, p3

    .line 754
    .line 755
    move-object/from16 v5, p4

    .line 756
    .line 757
    move/from16 v6, p6

    .line 758
    .line 759
    invoke-direct/range {v0 .. v7}, Ld80/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;ZLlx0/e;II)V

    .line 760
    .line 761
    .line 762
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 763
    .line 764
    :cond_1b
    return-void
.end method
