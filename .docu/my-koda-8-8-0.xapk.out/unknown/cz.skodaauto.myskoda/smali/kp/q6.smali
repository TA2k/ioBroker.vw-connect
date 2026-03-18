.class public abstract Lkp/q6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;ZLay0/a;Le1/n1;Ll2/o;I)V
    .locals 28

    .line 1
    move/from16 v2, p1

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move/from16 v5, p5

    .line 8
    .line 9
    move-object/from16 v13, p4

    .line 10
    .line 11
    check-cast v13, Ll2/t;

    .line 12
    .line 13
    const v0, 0x76f49253

    .line 14
    .line 15
    .line 16
    invoke-virtual {v13, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    and-int/lit8 v0, v5, 0x6

    .line 20
    .line 21
    if-nez v0, :cond_1

    .line 22
    .line 23
    move-object/from16 v0, p0

    .line 24
    .line 25
    invoke-virtual {v13, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v6

    .line 29
    if-eqz v6, :cond_0

    .line 30
    .line 31
    const/4 v6, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v6, 0x2

    .line 34
    :goto_0
    or-int/2addr v6, v5

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move-object/from16 v0, p0

    .line 37
    .line 38
    move v6, v5

    .line 39
    :goto_1
    and-int/lit8 v7, v5, 0x30

    .line 40
    .line 41
    if-nez v7, :cond_3

    .line 42
    .line 43
    invoke-virtual {v13, v2}, Ll2/t;->h(Z)Z

    .line 44
    .line 45
    .line 46
    move-result v7

    .line 47
    if-eqz v7, :cond_2

    .line 48
    .line 49
    const/16 v7, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v7, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v6, v7

    .line 55
    :cond_3
    and-int/lit16 v7, v5, 0x180

    .line 56
    .line 57
    if-nez v7, :cond_5

    .line 58
    .line 59
    invoke-virtual {v13, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v7

    .line 63
    if-eqz v7, :cond_4

    .line 64
    .line 65
    const/16 v7, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_4
    const/16 v7, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v6, v7

    .line 71
    :cond_5
    invoke-virtual {v13, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v7

    .line 75
    const/16 v8, 0x800

    .line 76
    .line 77
    if-eqz v7, :cond_6

    .line 78
    .line 79
    move v7, v8

    .line 80
    goto :goto_4

    .line 81
    :cond_6
    const/16 v7, 0x400

    .line 82
    .line 83
    :goto_4
    or-int/2addr v6, v7

    .line 84
    and-int/lit16 v7, v6, 0x493

    .line 85
    .line 86
    const/16 v9, 0x492

    .line 87
    .line 88
    const/4 v10, 0x0

    .line 89
    if-eq v7, v9, :cond_7

    .line 90
    .line 91
    const/4 v7, 0x1

    .line 92
    goto :goto_5

    .line 93
    :cond_7
    move v7, v10

    .line 94
    :goto_5
    and-int/lit8 v9, v6, 0x1

    .line 95
    .line 96
    invoke-virtual {v13, v9, v7}, Ll2/t;->O(IZ)Z

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    if-eqz v7, :cond_12

    .line 101
    .line 102
    new-array v7, v10, [Ljava/lang/Object;

    .line 103
    .line 104
    sget-object v9, Leq0/c;->d:Lu2/l;

    .line 105
    .line 106
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v12

    .line 110
    sget-object v14, Ll2/n;->a:Ll2/x0;

    .line 111
    .line 112
    if-ne v12, v14, :cond_8

    .line 113
    .line 114
    new-instance v12, Le31/t0;

    .line 115
    .line 116
    const/16 v15, 0x16

    .line 117
    .line 118
    invoke-direct {v12, v15}, Le31/t0;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v13, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_8
    check-cast v12, Lay0/a;

    .line 125
    .line 126
    const/16 v15, 0x180

    .line 127
    .line 128
    invoke-static {v7, v9, v12, v13, v15}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    check-cast v7, Leq0/c;

    .line 133
    .line 134
    iget-object v9, v4, Le1/n1;->a:Ll2/g1;

    .line 135
    .line 136
    invoke-virtual {v9}, Ll2/g1;->o()I

    .line 137
    .line 138
    .line 139
    move-result v9

    .line 140
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 141
    .line 142
    .line 143
    move-result-object v9

    .line 144
    and-int/lit16 v12, v6, 0x1c00

    .line 145
    .line 146
    if-ne v12, v8, :cond_9

    .line 147
    .line 148
    const/4 v8, 0x1

    .line 149
    goto :goto_6

    .line 150
    :cond_9
    move v8, v10

    .line 151
    :goto_6
    invoke-virtual {v13, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v12

    .line 155
    or-int/2addr v8, v12

    .line 156
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v12

    .line 160
    if-nez v8, :cond_a

    .line 161
    .line 162
    if-ne v12, v14, :cond_b

    .line 163
    .line 164
    :cond_a
    new-instance v12, Le30/p;

    .line 165
    .line 166
    const/4 v8, 0x2

    .line 167
    const/4 v14, 0x0

    .line 168
    invoke-direct {v12, v8, v4, v7, v14}, Le30/p;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v13, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 172
    .line 173
    .line 174
    :cond_b
    check-cast v12, Lay0/n;

    .line 175
    .line 176
    invoke-static {v12, v9, v13}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 177
    .line 178
    .line 179
    iget-object v8, v7, Leq0/c;->c:Ll2/j1;

    .line 180
    .line 181
    invoke-virtual {v8}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v8

    .line 185
    check-cast v8, Lt4/f;

    .line 186
    .line 187
    iget v8, v8, Lt4/f;->d:F

    .line 188
    .line 189
    sget-object v9, Lx2/p;->b:Lx2/p;

    .line 190
    .line 191
    invoke-static {v9, v8}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object v8

    .line 195
    sget-object v12, Lj91/h;->a:Ll2/u2;

    .line 196
    .line 197
    invoke-virtual {v13, v12}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v12

    .line 201
    check-cast v12, Lj91/e;

    .line 202
    .line 203
    invoke-virtual {v12}, Lj91/e;->b()J

    .line 204
    .line 205
    .line 206
    move-result-wide v14

    .line 207
    sget-object v12, Le3/j0;->a:Le3/i0;

    .line 208
    .line 209
    invoke-static {v8, v14, v15, v12}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 210
    .line 211
    .line 212
    move-result-object v8

    .line 213
    sget-object v12, Lx2/c;->d:Lx2/j;

    .line 214
    .line 215
    invoke-static {v12, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 216
    .line 217
    .line 218
    move-result-object v12

    .line 219
    iget-wide v14, v13, Ll2/t;->T:J

    .line 220
    .line 221
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 222
    .line 223
    .line 224
    move-result v14

    .line 225
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 226
    .line 227
    .line 228
    move-result-object v15

    .line 229
    invoke-static {v13, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 230
    .line 231
    .line 232
    move-result-object v8

    .line 233
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 234
    .line 235
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    sget-object v1, Lv3/j;->b:Lv3/i;

    .line 239
    .line 240
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 241
    .line 242
    .line 243
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 244
    .line 245
    if-eqz v10, :cond_c

    .line 246
    .line 247
    invoke-virtual {v13, v1}, Ll2/t;->l(Lay0/a;)V

    .line 248
    .line 249
    .line 250
    goto :goto_7

    .line 251
    :cond_c
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 252
    .line 253
    .line 254
    :goto_7
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 255
    .line 256
    invoke-static {v10, v12, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 257
    .line 258
    .line 259
    sget-object v12, Lv3/j;->f:Lv3/h;

    .line 260
    .line 261
    invoke-static {v12, v15, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 262
    .line 263
    .line 264
    sget-object v15, Lv3/j;->j:Lv3/h;

    .line 265
    .line 266
    iget-boolean v11, v13, Ll2/t;->S:Z

    .line 267
    .line 268
    if-nez v11, :cond_d

    .line 269
    .line 270
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v11

    .line 274
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 275
    .line 276
    .line 277
    move-result-object v0

    .line 278
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v0

    .line 282
    if-nez v0, :cond_e

    .line 283
    .line 284
    :cond_d
    invoke-static {v14, v13, v14, v15}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 285
    .line 286
    .line 287
    :cond_e
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 288
    .line 289
    invoke-static {v0, v8, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 290
    .line 291
    .line 292
    move-object v8, v9

    .line 293
    new-instance v9, Li91/w2;

    .line 294
    .line 295
    const/4 v11, 0x3

    .line 296
    invoke-direct {v9, v3, v11}, Li91/w2;-><init>(Lay0/a;I)V

    .line 297
    .line 298
    .line 299
    const/4 v14, 0x0

    .line 300
    move-object v11, v15

    .line 301
    const/16 v15, 0x3bf

    .line 302
    .line 303
    move/from16 v18, v6

    .line 304
    .line 305
    const/4 v6, 0x0

    .line 306
    move-object/from16 v19, v7

    .line 307
    .line 308
    const/4 v7, 0x0

    .line 309
    move-object/from16 v20, v8

    .line 310
    .line 311
    const/4 v8, 0x0

    .line 312
    move-object/from16 v21, v10

    .line 313
    .line 314
    const/4 v10, 0x0

    .line 315
    move-object/from16 v22, v11

    .line 316
    .line 317
    const/4 v11, 0x0

    .line 318
    move-object/from16 v23, v12

    .line 319
    .line 320
    const/4 v12, 0x0

    .line 321
    move-object/from16 v3, v20

    .line 322
    .line 323
    move-object/from16 v4, v21

    .line 324
    .line 325
    move-object/from16 v2, v22

    .line 326
    .line 327
    move-object/from16 v5, v23

    .line 328
    .line 329
    invoke-static/range {v6 .. v15}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 330
    .line 331
    .line 332
    sget-object v6, Lx2/c;->g:Lx2/j;

    .line 333
    .line 334
    sget v7, Leq0/c;->e:F

    .line 335
    .line 336
    invoke-static {v3, v7}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 337
    .line 338
    .line 339
    move-result-object v7

    .line 340
    sget-object v8, Lj91/a;->a:Ll2/u2;

    .line 341
    .line 342
    invoke-virtual {v13, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v8

    .line 346
    check-cast v8, Lj91/c;

    .line 347
    .line 348
    iget v8, v8, Lj91/c;->d:F

    .line 349
    .line 350
    const/4 v9, 0x0

    .line 351
    const/4 v10, 0x2

    .line 352
    invoke-static {v7, v8, v9, v10}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 353
    .line 354
    .line 355
    move-result-object v7

    .line 356
    sget-object v8, Lx2/c;->j:Lx2/j;

    .line 357
    .line 358
    sget-object v9, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 359
    .line 360
    invoke-virtual {v9, v7, v8}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 361
    .line 362
    .line 363
    move-result-object v7

    .line 364
    const/4 v8, 0x0

    .line 365
    invoke-static {v6, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 366
    .line 367
    .line 368
    move-result-object v6

    .line 369
    iget-wide v8, v13, Ll2/t;->T:J

    .line 370
    .line 371
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 372
    .line 373
    .line 374
    move-result v8

    .line 375
    invoke-virtual {v13}, Ll2/t;->m()Ll2/p1;

    .line 376
    .line 377
    .line 378
    move-result-object v9

    .line 379
    invoke-static {v13, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 380
    .line 381
    .line 382
    move-result-object v7

    .line 383
    invoke-virtual {v13}, Ll2/t;->c0()V

    .line 384
    .line 385
    .line 386
    iget-boolean v10, v13, Ll2/t;->S:Z

    .line 387
    .line 388
    if-eqz v10, :cond_f

    .line 389
    .line 390
    invoke-virtual {v13, v1}, Ll2/t;->l(Lay0/a;)V

    .line 391
    .line 392
    .line 393
    goto :goto_8

    .line 394
    :cond_f
    invoke-virtual {v13}, Ll2/t;->m0()V

    .line 395
    .line 396
    .line 397
    :goto_8
    invoke-static {v4, v6, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 398
    .line 399
    .line 400
    invoke-static {v5, v9, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 401
    .line 402
    .line 403
    iget-boolean v1, v13, Ll2/t;->S:Z

    .line 404
    .line 405
    if-nez v1, :cond_10

    .line 406
    .line 407
    invoke-virtual {v13}, Ll2/t;->L()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 412
    .line 413
    .line 414
    move-result-object v4

    .line 415
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 416
    .line 417
    .line 418
    move-result v1

    .line 419
    if-nez v1, :cond_11

    .line 420
    .line 421
    :cond_10
    invoke-static {v8, v13, v8, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 422
    .line 423
    .line 424
    :cond_11
    invoke-static {v0, v7, v13}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 425
    .line 426
    .line 427
    sget-object v0, Lj91/j;->a:Ll2/u2;

    .line 428
    .line 429
    invoke-virtual {v13, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    move-result-object v0

    .line 433
    check-cast v0, Lj91/f;

    .line 434
    .line 435
    invoke-virtual {v0}, Lj91/f;->k()Lg4/p0;

    .line 436
    .line 437
    .line 438
    move-result-object v7

    .line 439
    const/high16 v0, 0x3f800000    # 1.0f

    .line 440
    .line 441
    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 442
    .line 443
    .line 444
    move-result-object v20

    .line 445
    move-object/from16 v0, v19

    .line 446
    .line 447
    iget-object v0, v0, Leq0/c;->b:Ll2/j1;

    .line 448
    .line 449
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    check-cast v0, Lt4/f;

    .line 454
    .line 455
    iget v0, v0, Lt4/f;->d:F

    .line 456
    .line 457
    const/16 v24, 0x0

    .line 458
    .line 459
    const/16 v25, 0xe

    .line 460
    .line 461
    const/16 v22, 0x0

    .line 462
    .line 463
    const/16 v23, 0x0

    .line 464
    .line 465
    move/from16 v21, v0

    .line 466
    .line 467
    invoke-static/range {v20 .. v25}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    move/from16 v2, p1

    .line 472
    .line 473
    invoke-static {v0, v2}, Lxf0/y1;->H(Lx2/s;Z)Lx2/s;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    const-string v1, "collapsable_toolbar_title"

    .line 478
    .line 479
    invoke-static {v0, v1}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 480
    .line 481
    .line 482
    move-result-object v8

    .line 483
    and-int/lit8 v25, v18, 0xe

    .line 484
    .line 485
    const/16 v26, 0x6180

    .line 486
    .line 487
    const v27, 0xaff8

    .line 488
    .line 489
    .line 490
    const-wide/16 v9, 0x0

    .line 491
    .line 492
    const-wide/16 v11, 0x0

    .line 493
    .line 494
    move-object/from16 v24, v13

    .line 495
    .line 496
    const/4 v13, 0x0

    .line 497
    const-wide/16 v14, 0x0

    .line 498
    .line 499
    const/16 v16, 0x0

    .line 500
    .line 501
    const/16 v17, 0x0

    .line 502
    .line 503
    const-wide/16 v18, 0x0

    .line 504
    .line 505
    const/16 v20, 0x2

    .line 506
    .line 507
    const/16 v21, 0x0

    .line 508
    .line 509
    const/16 v22, 0x1

    .line 510
    .line 511
    const/16 v23, 0x0

    .line 512
    .line 513
    move-object/from16 v6, p0

    .line 514
    .line 515
    invoke-static/range {v6 .. v27}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 516
    .line 517
    .line 518
    move-object/from16 v13, v24

    .line 519
    .line 520
    const/4 v0, 0x1

    .line 521
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 522
    .line 523
    .line 524
    invoke-virtual {v13, v0}, Ll2/t;->q(Z)V

    .line 525
    .line 526
    .line 527
    goto :goto_9

    .line 528
    :cond_12
    invoke-virtual {v13}, Ll2/t;->R()V

    .line 529
    .line 530
    .line 531
    :goto_9
    invoke-virtual {v13}, Ll2/t;->s()Ll2/u1;

    .line 532
    .line 533
    .line 534
    move-result-object v7

    .line 535
    if-eqz v7, :cond_13

    .line 536
    .line 537
    new-instance v0, Lbl/d;

    .line 538
    .line 539
    const/4 v6, 0x5

    .line 540
    move-object/from16 v1, p0

    .line 541
    .line 542
    move-object/from16 v3, p2

    .line 543
    .line 544
    move-object/from16 v4, p3

    .line 545
    .line 546
    move/from16 v5, p5

    .line 547
    .line 548
    invoke-direct/range {v0 .. v6}, Lbl/d;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;II)V

    .line 549
    .line 550
    .line 551
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 552
    .line 553
    :cond_13
    return-void
.end method

.method public static final b(Ljava/lang/String;ZLay0/a;Lt2/b;Ll2/o;II)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    const-string v1, "title"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "onBack"

    .line 11
    .line 12
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v4, p4

    .line 16
    .line 17
    check-cast v4, Ll2/t;

    .line 18
    .line 19
    const v1, 0x30188b31

    .line 20
    .line 21
    .line 22
    invoke-virtual {v4, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v4, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    const/4 v1, 0x4

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v1, 0x2

    .line 34
    :goto_0
    or-int v1, p5, v1

    .line 35
    .line 36
    and-int/lit8 v3, p6, 0x2

    .line 37
    .line 38
    if-eqz v3, :cond_1

    .line 39
    .line 40
    or-int/lit8 v1, v1, 0x30

    .line 41
    .line 42
    move/from16 v5, p1

    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    move/from16 v5, p1

    .line 46
    .line 47
    invoke-virtual {v4, v5}, Ll2/t;->h(Z)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-eqz v6, :cond_2

    .line 52
    .line 53
    const/16 v6, 0x20

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    const/16 v6, 0x10

    .line 57
    .line 58
    :goto_1
    or-int/2addr v1, v6

    .line 59
    :goto_2
    invoke-virtual {v4, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-eqz v6, :cond_3

    .line 64
    .line 65
    const/16 v6, 0x100

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    const/16 v6, 0x80

    .line 69
    .line 70
    :goto_3
    or-int/2addr v1, v6

    .line 71
    and-int/lit16 v6, v1, 0x493

    .line 72
    .line 73
    const/16 v7, 0x492

    .line 74
    .line 75
    const/4 v8, 0x0

    .line 76
    const/4 v9, 0x1

    .line 77
    if-eq v6, v7, :cond_4

    .line 78
    .line 79
    move v6, v9

    .line 80
    goto :goto_4

    .line 81
    :cond_4
    move v6, v8

    .line 82
    :goto_4
    and-int/lit8 v7, v1, 0x1

    .line 83
    .line 84
    invoke-virtual {v4, v7, v6}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    if-eqz v6, :cond_c

    .line 89
    .line 90
    if-eqz v3, :cond_5

    .line 91
    .line 92
    move v5, v8

    .line 93
    :cond_5
    invoke-static {v8, v9, v4}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    sget-object v6, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 98
    .line 99
    sget-object v7, Lj91/h;->a:Ll2/u2;

    .line 100
    .line 101
    invoke-virtual {v4, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    check-cast v7, Lj91/e;

    .line 106
    .line 107
    invoke-virtual {v7}, Lj91/e;->b()J

    .line 108
    .line 109
    .line 110
    move-result-wide v10

    .line 111
    sget-object v7, Le3/j0;->a:Le3/i0;

    .line 112
    .line 113
    invoke-static {v6, v10, v11, v7}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    sget-object v10, Lx2/c;->d:Lx2/j;

    .line 118
    .line 119
    invoke-static {v10, v8}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 120
    .line 121
    .line 122
    move-result-object v10

    .line 123
    iget-wide v11, v4, Ll2/t;->T:J

    .line 124
    .line 125
    invoke-static {v11, v12}, Ljava/lang/Long;->hashCode(J)I

    .line 126
    .line 127
    .line 128
    move-result v11

    .line 129
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 130
    .line 131
    .line 132
    move-result-object v12

    .line 133
    invoke-static {v4, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    sget-object v13, Lv3/k;->m1:Lv3/j;

    .line 138
    .line 139
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    sget-object v13, Lv3/j;->b:Lv3/i;

    .line 143
    .line 144
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 145
    .line 146
    .line 147
    iget-boolean v14, v4, Ll2/t;->S:Z

    .line 148
    .line 149
    if-eqz v14, :cond_6

    .line 150
    .line 151
    invoke-virtual {v4, v13}, Ll2/t;->l(Lay0/a;)V

    .line 152
    .line 153
    .line 154
    goto :goto_5

    .line 155
    :cond_6
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 156
    .line 157
    .line 158
    :goto_5
    sget-object v14, Lv3/j;->g:Lv3/h;

    .line 159
    .line 160
    invoke-static {v14, v10, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 161
    .line 162
    .line 163
    sget-object v10, Lv3/j;->f:Lv3/h;

    .line 164
    .line 165
    invoke-static {v10, v12, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 166
    .line 167
    .line 168
    sget-object v12, Lv3/j;->j:Lv3/h;

    .line 169
    .line 170
    iget-boolean v15, v4, Ll2/t;->S:Z

    .line 171
    .line 172
    if-nez v15, :cond_7

    .line 173
    .line 174
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v15

    .line 178
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    invoke-static {v15, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v9

    .line 186
    if-nez v9, :cond_8

    .line 187
    .line 188
    :cond_7
    invoke-static {v11, v4, v11, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 189
    .line 190
    .line 191
    :cond_8
    sget-object v9, Lv3/j;->d:Lv3/h;

    .line 192
    .line 193
    invoke-static {v9, v7, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 194
    .line 195
    .line 196
    const/16 v7, 0xe

    .line 197
    .line 198
    invoke-static {v6, v3, v7}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    sget-object v7, Lk1/r0;->e:Lk1/r0;

    .line 203
    .line 204
    invoke-static {v6, v7}, Landroidx/compose/foundation/layout/a;->g(Lx2/s;Lk1/r0;)Lx2/s;

    .line 205
    .line 206
    .line 207
    move-result-object v15

    .line 208
    sget v17, Leq0/c;->f:F

    .line 209
    .line 210
    const/16 v19, 0x0

    .line 211
    .line 212
    const/16 v20, 0xd

    .line 213
    .line 214
    const/16 v16, 0x0

    .line 215
    .line 216
    const/16 v18, 0x0

    .line 217
    .line 218
    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 219
    .line 220
    .line 221
    move-result-object v6

    .line 222
    sget-object v7, Lk1/j;->c:Lk1/e;

    .line 223
    .line 224
    sget-object v11, Lx2/c;->p:Lx2/h;

    .line 225
    .line 226
    invoke-static {v7, v11, v4, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 227
    .line 228
    .line 229
    move-result-object v7

    .line 230
    move-object/from16 p1, v3

    .line 231
    .line 232
    iget-wide v2, v4, Ll2/t;->T:J

    .line 233
    .line 234
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 239
    .line 240
    .line 241
    move-result-object v3

    .line 242
    invoke-static {v4, v6}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 243
    .line 244
    .line 245
    move-result-object v6

    .line 246
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 247
    .line 248
    .line 249
    iget-boolean v8, v4, Ll2/t;->S:Z

    .line 250
    .line 251
    if-eqz v8, :cond_9

    .line 252
    .line 253
    invoke-virtual {v4, v13}, Ll2/t;->l(Lay0/a;)V

    .line 254
    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_9
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 258
    .line 259
    .line 260
    :goto_6
    invoke-static {v14, v7, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 261
    .line 262
    .line 263
    invoke-static {v10, v3, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 264
    .line 265
    .line 266
    iget-boolean v3, v4, Ll2/t;->S:Z

    .line 267
    .line 268
    if-nez v3, :cond_a

    .line 269
    .line 270
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object v3

    .line 274
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 275
    .line 276
    .line 277
    move-result-object v7

    .line 278
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v3

    .line 282
    if-nez v3, :cond_b

    .line 283
    .line 284
    :cond_a
    invoke-static {v2, v4, v2, v12}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 285
    .line 286
    .line 287
    :cond_b
    invoke-static {v9, v6, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 288
    .line 289
    .line 290
    const/4 v2, 0x6

    .line 291
    move-object/from16 v6, p3

    .line 292
    .line 293
    const/4 v7, 0x1

    .line 294
    invoke-static {v2, v6, v4, v7}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 295
    .line 296
    .line 297
    and-int/lit16 v1, v1, 0x3fe

    .line 298
    .line 299
    move v2, v5

    .line 300
    move v5, v1

    .line 301
    move v1, v2

    .line 302
    move-object/from16 v3, p1

    .line 303
    .line 304
    move-object/from16 v2, p2

    .line 305
    .line 306
    invoke-static/range {v0 .. v5}, Lkp/q6;->a(Ljava/lang/String;ZLay0/a;Le1/n1;Ll2/o;I)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v4, v7}, Ll2/t;->q(Z)V

    .line 310
    .line 311
    .line 312
    move v2, v1

    .line 313
    goto :goto_7

    .line 314
    :cond_c
    move-object/from16 v6, p3

    .line 315
    .line 316
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 317
    .line 318
    .line 319
    move v2, v5

    .line 320
    :goto_7
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 321
    .line 322
    .line 323
    move-result-object v7

    .line 324
    if-eqz v7, :cond_d

    .line 325
    .line 326
    new-instance v0, Lbl/d;

    .line 327
    .line 328
    move-object/from16 v1, p0

    .line 329
    .line 330
    move-object/from16 v3, p2

    .line 331
    .line 332
    move/from16 v5, p5

    .line 333
    .line 334
    move-object v4, v6

    .line 335
    move/from16 v6, p6

    .line 336
    .line 337
    invoke-direct/range {v0 .. v6}, Lbl/d;-><init>(Ljava/lang/String;ZLay0/a;Lt2/b;II)V

    .line 338
    .line 339
    .line 340
    iput-object v0, v7, Ll2/u1;->d:Lay0/n;

    .line 341
    .line 342
    :cond_d
    return-void
.end method

.method public static c(I)I
    .locals 0

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    :pswitch_0
    const/4 p0, 0x0

    .line 5
    return p0

    .line 6
    :pswitch_1
    const/16 p0, 0x11

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_2
    const/16 p0, 0xf

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_3
    const/16 p0, 0xe

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_4
    const/16 p0, 0xd

    .line 16
    .line 17
    return p0

    .line 18
    :pswitch_5
    const/16 p0, 0xc

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_6
    const/16 p0, 0xb

    .line 22
    .line 23
    return p0

    .line 24
    :pswitch_7
    const/16 p0, 0xa

    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_8
    const/16 p0, 0x9

    .line 28
    .line 29
    return p0

    .line 30
    :pswitch_9
    const/16 p0, 0x8

    .line 31
    .line 32
    return p0

    .line 33
    :pswitch_a
    const/4 p0, 0x7

    .line 34
    return p0

    .line 35
    :pswitch_b
    const/4 p0, 0x6

    .line 36
    return p0

    .line 37
    :pswitch_c
    const/4 p0, 0x5

    .line 38
    return p0

    .line 39
    :pswitch_d
    const/4 p0, 0x4

    .line 40
    return p0

    .line 41
    :pswitch_e
    const/4 p0, 0x3

    .line 42
    return p0

    .line 43
    :pswitch_f
    const/4 p0, 0x2

    .line 44
    return p0

    .line 45
    :pswitch_10
    const/4 p0, 0x1

    .line 46
    return p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x0
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
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method
