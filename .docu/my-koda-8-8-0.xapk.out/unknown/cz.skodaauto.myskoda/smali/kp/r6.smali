.class public abstract Lkp/r6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/List;Ll2/o;I)V
    .locals 38

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v2, Lx2/c;->m:Lx2/i;

    .line 4
    .line 5
    const-string v3, "openingHours"

    .line 6
    .line 7
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v3, p1

    .line 11
    .line 12
    check-cast v3, Ll2/t;

    .line 13
    .line 14
    const v4, -0x59b13135

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3, v4}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v3, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    const/4 v5, 0x2

    .line 25
    if-eqz v4, :cond_0

    .line 26
    .line 27
    const/4 v4, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v4, v5

    .line 30
    :goto_0
    or-int v4, p2, v4

    .line 31
    .line 32
    and-int/lit8 v6, v4, 0x3

    .line 33
    .line 34
    const/4 v7, 0x1

    .line 35
    const/4 v8, 0x0

    .line 36
    if-eq v6, v5, :cond_1

    .line 37
    .line 38
    move v5, v7

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    move v5, v8

    .line 41
    :goto_1
    and-int/2addr v4, v7

    .line 42
    invoke-virtual {v3, v4, v5}, Ll2/t;->O(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-eqz v4, :cond_12

    .line 47
    .line 48
    sget-object v4, Lk1/j;->c:Lk1/e;

    .line 49
    .line 50
    sget-object v5, Lx2/c;->p:Lx2/h;

    .line 51
    .line 52
    invoke-static {v4, v5, v3, v8}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    iget-wide v9, v3, Ll2/t;->T:J

    .line 57
    .line 58
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 59
    .line 60
    .line 61
    move-result v6

    .line 62
    invoke-virtual {v3}, Ll2/t;->m()Ll2/p1;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 67
    .line 68
    invoke-static {v3, v10}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 69
    .line 70
    .line 71
    move-result-object v11

    .line 72
    sget-object v12, Lv3/k;->m1:Lv3/j;

    .line 73
    .line 74
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    sget-object v12, Lv3/j;->b:Lv3/i;

    .line 78
    .line 79
    invoke-virtual {v3}, Ll2/t;->c0()V

    .line 80
    .line 81
    .line 82
    iget-boolean v13, v3, Ll2/t;->S:Z

    .line 83
    .line 84
    if-eqz v13, :cond_2

    .line 85
    .line 86
    invoke-virtual {v3, v12}, Ll2/t;->l(Lay0/a;)V

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_2
    invoke-virtual {v3}, Ll2/t;->m0()V

    .line 91
    .line 92
    .line 93
    :goto_2
    sget-object v13, Lv3/j;->g:Lv3/h;

    .line 94
    .line 95
    invoke-static {v13, v4, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 96
    .line 97
    .line 98
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 99
    .line 100
    invoke-static {v4, v9, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 101
    .line 102
    .line 103
    sget-object v9, Lv3/j;->j:Lv3/h;

    .line 104
    .line 105
    iget-boolean v14, v3, Ll2/t;->S:Z

    .line 106
    .line 107
    if-nez v14, :cond_3

    .line 108
    .line 109
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v14

    .line 113
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v15

    .line 117
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v14

    .line 121
    if-nez v14, :cond_4

    .line 122
    .line 123
    :cond_3
    invoke-static {v6, v3, v6, v9}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 124
    .line 125
    .line 126
    :cond_4
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 127
    .line 128
    invoke-static {v6, v11, v3}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 129
    .line 130
    .line 131
    const/4 v11, 0x0

    .line 132
    invoke-static {v8, v7, v3, v11}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 133
    .line 134
    .line 135
    sget-object v11, Lj91/a;->a:Ll2/u2;

    .line 136
    .line 137
    invoke-virtual {v3, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v14

    .line 141
    check-cast v14, Lj91/c;

    .line 142
    .line 143
    iget v14, v14, Lj91/c;->d:F

    .line 144
    .line 145
    const v15, 0x7f1211bb

    .line 146
    .line 147
    .line 148
    invoke-static {v10, v14, v3, v15, v3}, Lvj/b;->m(Lx2/p;FLl2/t;ILl2/t;)Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v14

    .line 152
    sget-object v7, Lj91/j;->a:Ll2/u2;

    .line 153
    .line 154
    invoke-virtual {v3, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v7

    .line 158
    check-cast v7, Lj91/f;

    .line 159
    .line 160
    invoke-virtual {v7}, Lj91/f;->l()Lg4/p0;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    invoke-static {v10, v15}, Lxf0/i0;->M(Lx2/s;I)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v15

    .line 168
    const/16 v24, 0x0

    .line 169
    .line 170
    const v25, 0xfff8

    .line 171
    .line 172
    .line 173
    move-object/from16 v16, v5

    .line 174
    .line 175
    move-object v5, v7

    .line 176
    move/from16 v17, v8

    .line 177
    .line 178
    const-wide/16 v7, 0x0

    .line 179
    .line 180
    move-object/from16 v18, v9

    .line 181
    .line 182
    move-object/from16 v19, v10

    .line 183
    .line 184
    const-wide/16 v9, 0x0

    .line 185
    .line 186
    move-object/from16 v20, v11

    .line 187
    .line 188
    const/4 v11, 0x0

    .line 189
    move-object/from16 v21, v12

    .line 190
    .line 191
    move-object/from16 v22, v13

    .line 192
    .line 193
    const-wide/16 v12, 0x0

    .line 194
    .line 195
    move-object/from16 v23, v4

    .line 196
    .line 197
    move-object v4, v14

    .line 198
    const/4 v14, 0x0

    .line 199
    move-object/from16 v26, v6

    .line 200
    .line 201
    move-object v6, v15

    .line 202
    const/4 v15, 0x0

    .line 203
    move-object/from16 v27, v16

    .line 204
    .line 205
    move/from16 v28, v17

    .line 206
    .line 207
    const-wide/16 v16, 0x0

    .line 208
    .line 209
    move-object/from16 v29, v18

    .line 210
    .line 211
    const/16 v18, 0x0

    .line 212
    .line 213
    move-object/from16 v30, v19

    .line 214
    .line 215
    const/16 v19, 0x0

    .line 216
    .line 217
    move-object/from16 v31, v20

    .line 218
    .line 219
    const/16 v20, 0x0

    .line 220
    .line 221
    move-object/from16 v32, v21

    .line 222
    .line 223
    const/16 v21, 0x0

    .line 224
    .line 225
    move-object/from16 v33, v23

    .line 226
    .line 227
    const/16 v23, 0x0

    .line 228
    .line 229
    move-object/from16 v0, v22

    .line 230
    .line 231
    move-object/from16 v22, v3

    .line 232
    .line 233
    move-object/from16 v3, v27

    .line 234
    .line 235
    move-object/from16 v27, v0

    .line 236
    .line 237
    move-object/from16 v35, v26

    .line 238
    .line 239
    move/from16 v0, v28

    .line 240
    .line 241
    move-object/from16 v34, v29

    .line 242
    .line 243
    move-object/from16 v1, v30

    .line 244
    .line 245
    move-object/from16 v26, v2

    .line 246
    .line 247
    move-object/from16 v2, v31

    .line 248
    .line 249
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 250
    .line 251
    .line 252
    move-object/from16 v4, v22

    .line 253
    .line 254
    invoke-virtual {v4, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v5

    .line 258
    check-cast v5, Lj91/c;

    .line 259
    .line 260
    iget v5, v5, Lj91/c;->b:F

    .line 261
    .line 262
    invoke-static {v1, v5, v4, v2}, Lvj/b;->e(Lx2/p;FLl2/t;Ll2/u2;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v2

    .line 266
    check-cast v2, Lj91/c;

    .line 267
    .line 268
    iget v2, v2, Lj91/c;->b:F

    .line 269
    .line 270
    invoke-static {v2}, Lk1/j;->g(F)Lk1/h;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    invoke-static {v2, v3, v4, v0}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    iget-wide v5, v4, Ll2/t;->T:J

    .line 279
    .line 280
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 281
    .line 282
    .line 283
    move-result v3

    .line 284
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    invoke-static {v4, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 289
    .line 290
    .line 291
    move-result-object v6

    .line 292
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 293
    .line 294
    .line 295
    iget-boolean v7, v4, Ll2/t;->S:Z

    .line 296
    .line 297
    if-eqz v7, :cond_5

    .line 298
    .line 299
    move-object/from16 v7, v32

    .line 300
    .line 301
    invoke-virtual {v4, v7}, Ll2/t;->l(Lay0/a;)V

    .line 302
    .line 303
    .line 304
    :goto_3
    move-object/from16 v7, v27

    .line 305
    .line 306
    goto :goto_4

    .line 307
    :cond_5
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 308
    .line 309
    .line 310
    goto :goto_3

    .line 311
    :goto_4
    invoke-static {v7, v2, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 312
    .line 313
    .line 314
    move-object/from16 v2, v33

    .line 315
    .line 316
    invoke-static {v2, v5, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 317
    .line 318
    .line 319
    iget-boolean v2, v4, Ll2/t;->S:Z

    .line 320
    .line 321
    if-nez v2, :cond_6

    .line 322
    .line 323
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 328
    .line 329
    .line 330
    move-result-object v5

    .line 331
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 332
    .line 333
    .line 334
    move-result v2

    .line 335
    if-nez v2, :cond_7

    .line 336
    .line 337
    :cond_6
    move-object/from16 v2, v34

    .line 338
    .line 339
    goto :goto_6

    .line 340
    :cond_7
    :goto_5
    move-object/from16 v2, v35

    .line 341
    .line 342
    goto :goto_7

    .line 343
    :goto_6
    invoke-static {v3, v4, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 344
    .line 345
    .line 346
    goto :goto_5

    .line 347
    :goto_7
    invoke-static {v2, v6, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 348
    .line 349
    .line 350
    const v2, 0x636042e2

    .line 351
    .line 352
    .line 353
    invoke-virtual {v4, v2}, Ll2/t;->Y(I)V

    .line 354
    .line 355
    .line 356
    move-object/from16 v2, p0

    .line 357
    .line 358
    check-cast v2, Ljava/lang/Iterable;

    .line 359
    .line 360
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 361
    .line 362
    .line 363
    move-result-object v2

    .line 364
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 365
    .line 366
    .line 367
    move-result v3

    .line 368
    if-eqz v3, :cond_11

    .line 369
    .line 370
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v3

    .line 374
    check-cast v3, Lcq0/f;

    .line 375
    .line 376
    const-string v5, "opening_hours_row"

    .line 377
    .line 378
    invoke-static {v1, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 379
    .line 380
    .line 381
    move-result-object v5

    .line 382
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 383
    .line 384
    move-object/from16 v7, v26

    .line 385
    .line 386
    invoke-static {v6, v7, v4, v0}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 387
    .line 388
    .line 389
    move-result-object v6

    .line 390
    iget-wide v8, v4, Ll2/t;->T:J

    .line 391
    .line 392
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 393
    .line 394
    .line 395
    move-result v8

    .line 396
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 397
    .line 398
    .line 399
    move-result-object v9

    .line 400
    invoke-static {v4, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 401
    .line 402
    .line 403
    move-result-object v5

    .line 404
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 405
    .line 406
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 407
    .line 408
    .line 409
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 410
    .line 411
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 412
    .line 413
    .line 414
    iget-boolean v11, v4, Ll2/t;->S:Z

    .line 415
    .line 416
    if-eqz v11, :cond_8

    .line 417
    .line 418
    invoke-virtual {v4, v10}, Ll2/t;->l(Lay0/a;)V

    .line 419
    .line 420
    .line 421
    goto :goto_9

    .line 422
    :cond_8
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 423
    .line 424
    .line 425
    :goto_9
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 426
    .line 427
    invoke-static {v10, v6, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 428
    .line 429
    .line 430
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 431
    .line 432
    invoke-static {v6, v9, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 433
    .line 434
    .line 435
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 436
    .line 437
    iget-boolean v9, v4, Ll2/t;->S:Z

    .line 438
    .line 439
    if-nez v9, :cond_9

    .line 440
    .line 441
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    move-result-object v9

    .line 445
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 446
    .line 447
    .line 448
    move-result-object v10

    .line 449
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 450
    .line 451
    .line 452
    move-result v9

    .line 453
    if-nez v9, :cond_a

    .line 454
    .line 455
    :cond_9
    invoke-static {v8, v4, v8, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 456
    .line 457
    .line 458
    :cond_a
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 459
    .line 460
    invoke-static {v6, v5, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 461
    .line 462
    .line 463
    iget-object v5, v3, Lcq0/f;->a:Ljava/lang/String;

    .line 464
    .line 465
    sget-object v6, Lj91/j;->a:Ll2/u2;

    .line 466
    .line 467
    invoke-virtual {v4, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 468
    .line 469
    .line 470
    move-result-object v8

    .line 471
    check-cast v8, Lj91/f;

    .line 472
    .line 473
    invoke-virtual {v8}, Lj91/f;->b()Lg4/p0;

    .line 474
    .line 475
    .line 476
    move-result-object v8

    .line 477
    const/high16 v9, 0x3f800000    # 1.0f

    .line 478
    .line 479
    float-to-double v10, v9

    .line 480
    const-wide/16 v12, 0x0

    .line 481
    .line 482
    cmpl-double v10, v10, v12

    .line 483
    .line 484
    if-lez v10, :cond_b

    .line 485
    .line 486
    goto :goto_a

    .line 487
    :cond_b
    const-string v10, "invalid weight; must be greater than zero"

    .line 488
    .line 489
    invoke-static {v10}, Ll1/a;->a(Ljava/lang/String;)V

    .line 490
    .line 491
    .line 492
    :goto_a
    new-instance v10, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 493
    .line 494
    const/4 v11, 0x1

    .line 495
    invoke-direct {v10, v9, v11}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 496
    .line 497
    .line 498
    const-string v9, "opening_hours_row_day_range"

    .line 499
    .line 500
    invoke-static {v10, v9}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 501
    .line 502
    .line 503
    move-result-object v9

    .line 504
    const/16 v24, 0x0

    .line 505
    .line 506
    const v25, 0xfff8

    .line 507
    .line 508
    .line 509
    move-object/from16 v22, v4

    .line 510
    .line 511
    move-object v4, v5

    .line 512
    move-object/from16 v26, v7

    .line 513
    .line 514
    move-object v5, v8

    .line 515
    const-wide/16 v7, 0x0

    .line 516
    .line 517
    move-object v12, v6

    .line 518
    move-object v6, v9

    .line 519
    const-wide/16 v9, 0x0

    .line 520
    .line 521
    move/from16 v36, v11

    .line 522
    .line 523
    const/4 v11, 0x0

    .line 524
    move-object v14, v12

    .line 525
    const-wide/16 v12, 0x0

    .line 526
    .line 527
    move-object v15, v14

    .line 528
    const/4 v14, 0x0

    .line 529
    move-object/from16 v16, v15

    .line 530
    .line 531
    const/4 v15, 0x0

    .line 532
    move-object/from16 v18, v16

    .line 533
    .line 534
    const-wide/16 v16, 0x0

    .line 535
    .line 536
    move-object/from16 v19, v18

    .line 537
    .line 538
    const/16 v18, 0x0

    .line 539
    .line 540
    move-object/from16 v20, v19

    .line 541
    .line 542
    const/16 v19, 0x0

    .line 543
    .line 544
    move-object/from16 v21, v20

    .line 545
    .line 546
    const/16 v20, 0x0

    .line 547
    .line 548
    move-object/from16 v23, v21

    .line 549
    .line 550
    const/16 v21, 0x0

    .line 551
    .line 552
    move-object/from16 v27, v23

    .line 553
    .line 554
    const/16 v23, 0x0

    .line 555
    .line 556
    move-object/from16 p1, v2

    .line 557
    .line 558
    move-object/from16 v37, v26

    .line 559
    .line 560
    move-object/from16 v0, v27

    .line 561
    .line 562
    move/from16 v2, v36

    .line 563
    .line 564
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 565
    .line 566
    .line 567
    move-object/from16 v4, v22

    .line 568
    .line 569
    iget-object v5, v3, Lcq0/f;->b:Ljava/lang/String;

    .line 570
    .line 571
    invoke-virtual {v4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 572
    .line 573
    .line 574
    move-result-object v0

    .line 575
    check-cast v0, Lj91/f;

    .line 576
    .line 577
    invoke-virtual {v0}, Lj91/f;->b()Lg4/p0;

    .line 578
    .line 579
    .line 580
    move-result-object v0

    .line 581
    const-string v6, "opening_hours_row_first_opening_hours"

    .line 582
    .line 583
    invoke-static {v1, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 584
    .line 585
    .line 586
    move-result-object v6

    .line 587
    const/16 v23, 0x180

    .line 588
    .line 589
    move-object v4, v5

    .line 590
    move-object v5, v0

    .line 591
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 592
    .line 593
    .line 594
    move-object/from16 v4, v22

    .line 595
    .line 596
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 597
    .line 598
    .line 599
    iget-object v0, v3, Lcq0/f;->c:Ljava/util/List;

    .line 600
    .line 601
    if-nez v0, :cond_c

    .line 602
    .line 603
    const v0, 0x97fa5e3

    .line 604
    .line 605
    .line 606
    invoke-virtual {v4, v0}, Ll2/t;->Y(I)V

    .line 607
    .line 608
    .line 609
    const/4 v0, 0x0

    .line 610
    invoke-virtual {v4, v0}, Ll2/t;->q(Z)V

    .line 611
    .line 612
    .line 613
    move v8, v0

    .line 614
    move-object/from16 v26, v37

    .line 615
    .line 616
    goto/16 :goto_d

    .line 617
    .line 618
    :cond_c
    const v3, 0x97fa5e4

    .line 619
    .line 620
    .line 621
    invoke-virtual {v4, v3}, Ll2/t;->Y(I)V

    .line 622
    .line 623
    .line 624
    check-cast v0, Ljava/lang/Iterable;

    .line 625
    .line 626
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 627
    .line 628
    .line 629
    move-result-object v0

    .line 630
    :goto_b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 631
    .line 632
    .line 633
    move-result v3

    .line 634
    if-eqz v3, :cond_10

    .line 635
    .line 636
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    move-result-object v3

    .line 640
    check-cast v3, Ljava/lang/String;

    .line 641
    .line 642
    sget-object v5, Lx2/c;->r:Lx2/h;

    .line 643
    .line 644
    new-instance v6, Landroidx/compose/foundation/layout/HorizontalAlignElement;

    .line 645
    .line 646
    invoke-direct {v6, v5}, Landroidx/compose/foundation/layout/HorizontalAlignElement;-><init>(Lx2/h;)V

    .line 647
    .line 648
    .line 649
    const-string v5, "other_opening_hours_row"

    .line 650
    .line 651
    invoke-static {v6, v5}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 652
    .line 653
    .line 654
    move-result-object v5

    .line 655
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 656
    .line 657
    move-object/from16 v7, v37

    .line 658
    .line 659
    const/4 v8, 0x0

    .line 660
    invoke-static {v6, v7, v4, v8}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 661
    .line 662
    .line 663
    move-result-object v6

    .line 664
    iget-wide v8, v4, Ll2/t;->T:J

    .line 665
    .line 666
    invoke-static {v8, v9}, Ljava/lang/Long;->hashCode(J)I

    .line 667
    .line 668
    .line 669
    move-result v8

    .line 670
    invoke-virtual {v4}, Ll2/t;->m()Ll2/p1;

    .line 671
    .line 672
    .line 673
    move-result-object v9

    .line 674
    invoke-static {v4, v5}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 675
    .line 676
    .line 677
    move-result-object v5

    .line 678
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 679
    .line 680
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 681
    .line 682
    .line 683
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 684
    .line 685
    invoke-virtual {v4}, Ll2/t;->c0()V

    .line 686
    .line 687
    .line 688
    iget-boolean v11, v4, Ll2/t;->S:Z

    .line 689
    .line 690
    if-eqz v11, :cond_d

    .line 691
    .line 692
    invoke-virtual {v4, v10}, Ll2/t;->l(Lay0/a;)V

    .line 693
    .line 694
    .line 695
    goto :goto_c

    .line 696
    :cond_d
    invoke-virtual {v4}, Ll2/t;->m0()V

    .line 697
    .line 698
    .line 699
    :goto_c
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 700
    .line 701
    invoke-static {v10, v6, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 702
    .line 703
    .line 704
    sget-object v6, Lv3/j;->f:Lv3/h;

    .line 705
    .line 706
    invoke-static {v6, v9, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 707
    .line 708
    .line 709
    sget-object v6, Lv3/j;->j:Lv3/h;

    .line 710
    .line 711
    iget-boolean v9, v4, Ll2/t;->S:Z

    .line 712
    .line 713
    if-nez v9, :cond_e

    .line 714
    .line 715
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 716
    .line 717
    .line 718
    move-result-object v9

    .line 719
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 720
    .line 721
    .line 722
    move-result-object v10

    .line 723
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 724
    .line 725
    .line 726
    move-result v9

    .line 727
    if-nez v9, :cond_f

    .line 728
    .line 729
    :cond_e
    invoke-static {v8, v4, v8, v6}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 730
    .line 731
    .line 732
    :cond_f
    sget-object v6, Lv3/j;->d:Lv3/h;

    .line 733
    .line 734
    invoke-static {v6, v5, v4}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 735
    .line 736
    .line 737
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 738
    .line 739
    invoke-virtual {v4, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 740
    .line 741
    .line 742
    move-result-object v5

    .line 743
    check-cast v5, Lj91/f;

    .line 744
    .line 745
    invoke-virtual {v5}, Lj91/f;->b()Lg4/p0;

    .line 746
    .line 747
    .line 748
    move-result-object v5

    .line 749
    const-string v6, "other_opening_hours_row_time_range"

    .line 750
    .line 751
    invoke-static {v1, v6}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 752
    .line 753
    .line 754
    move-result-object v6

    .line 755
    const/16 v24, 0x0

    .line 756
    .line 757
    const v25, 0xfff8

    .line 758
    .line 759
    .line 760
    move-object/from16 v26, v7

    .line 761
    .line 762
    const-wide/16 v7, 0x0

    .line 763
    .line 764
    const-wide/16 v9, 0x0

    .line 765
    .line 766
    const/4 v11, 0x0

    .line 767
    const-wide/16 v12, 0x0

    .line 768
    .line 769
    const/4 v14, 0x0

    .line 770
    const/4 v15, 0x0

    .line 771
    const-wide/16 v16, 0x0

    .line 772
    .line 773
    const/16 v18, 0x0

    .line 774
    .line 775
    const/16 v19, 0x0

    .line 776
    .line 777
    const/16 v20, 0x0

    .line 778
    .line 779
    const/16 v21, 0x0

    .line 780
    .line 781
    const/16 v23, 0x180

    .line 782
    .line 783
    move-object/from16 v22, v4

    .line 784
    .line 785
    move-object v4, v3

    .line 786
    invoke-static/range {v4 .. v25}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 787
    .line 788
    .line 789
    move-object/from16 v4, v22

    .line 790
    .line 791
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 792
    .line 793
    .line 794
    move-object/from16 v37, v26

    .line 795
    .line 796
    goto/16 :goto_b

    .line 797
    .line 798
    :cond_10
    move-object/from16 v26, v37

    .line 799
    .line 800
    const/4 v8, 0x0

    .line 801
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 802
    .line 803
    .line 804
    :goto_d
    move-object/from16 v2, p1

    .line 805
    .line 806
    move v0, v8

    .line 807
    goto/16 :goto_8

    .line 808
    .line 809
    :cond_11
    move v8, v0

    .line 810
    const/4 v2, 0x1

    .line 811
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 812
    .line 813
    .line 814
    invoke-virtual {v4, v2}, Ll2/t;->q(Z)V

    .line 815
    .line 816
    .line 817
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 818
    .line 819
    invoke-virtual {v4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 820
    .line 821
    .line 822
    move-result-object v0

    .line 823
    check-cast v0, Lj91/c;

    .line 824
    .line 825
    iget v0, v0, Lj91/c;->d:F

    .line 826
    .line 827
    invoke-static {v1, v0, v4, v2}, Lvj/b;->z(Lx2/p;FLl2/t;Z)V

    .line 828
    .line 829
    .line 830
    goto :goto_e

    .line 831
    :cond_12
    move-object v4, v3

    .line 832
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 833
    .line 834
    .line 835
    :goto_e
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 836
    .line 837
    .line 838
    move-result-object v0

    .line 839
    if-eqz v0, :cond_13

    .line 840
    .line 841
    new-instance v1, Leq0/a;

    .line 842
    .line 843
    const/4 v2, 0x0

    .line 844
    move-object/from16 v3, p0

    .line 845
    .line 846
    move/from16 v4, p2

    .line 847
    .line 848
    invoke-direct {v1, v4, v2, v3}, Leq0/a;-><init>(IILjava/util/List;)V

    .line 849
    .line 850
    .line 851
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 852
    .line 853
    :cond_13
    return-void
.end method

.method public static b(I)I
    .locals 0

    .line 1
    packed-switch p0, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0

    .line 6
    :pswitch_0
    const/16 p0, 0xe

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_1
    const/16 p0, 0xd

    .line 10
    .line 11
    return p0

    .line 12
    :pswitch_2
    const/16 p0, 0xc

    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_3
    const/16 p0, 0xb

    .line 16
    .line 17
    return p0

    .line 18
    :pswitch_4
    const/16 p0, 0xa

    .line 19
    .line 20
    return p0

    .line 21
    :pswitch_5
    const/16 p0, 0x9

    .line 22
    .line 23
    return p0

    .line 24
    :pswitch_6
    const/16 p0, 0x8

    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_7
    const/4 p0, 0x7

    .line 28
    return p0

    .line 29
    :pswitch_8
    const/4 p0, 0x6

    .line 30
    return p0

    .line 31
    :pswitch_9
    const/4 p0, 0x5

    .line 32
    return p0

    .line 33
    :pswitch_a
    const/4 p0, 0x4

    .line 34
    return p0

    .line 35
    :pswitch_b
    const/4 p0, 0x3

    .line 36
    return p0

    .line 37
    :pswitch_c
    const/4 p0, 0x2

    .line 38
    return p0

    .line 39
    :pswitch_d
    const/4 p0, 0x1

    .line 40
    return p0

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
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
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
