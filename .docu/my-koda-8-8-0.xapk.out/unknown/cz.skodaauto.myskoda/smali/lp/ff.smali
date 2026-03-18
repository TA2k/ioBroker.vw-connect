.class public abstract Llp/ff;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIILl2/o;II)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v10, p1

    .line 4
    .line 5
    move/from16 v11, p8

    .line 6
    .line 7
    const-string v1, "$this$Text"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "text"

    .line 13
    .line 14
    invoke-static {v10, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, v10, Lxv/o;->b:Ljava/util/Map;

    .line 18
    .line 19
    move-object/from16 v6, p7

    .line 20
    .line 21
    check-cast v6, Ll2/t;

    .line 22
    .line 23
    const v2, 0x2756a87a

    .line 24
    .line 25
    .line 26
    invoke-virtual {v6, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v2, v11, 0xe

    .line 30
    .line 31
    if-nez v2, :cond_1

    .line 32
    .line 33
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_0

    .line 38
    .line 39
    const/4 v2, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v2, 0x2

    .line 42
    :goto_0
    or-int/2addr v2, v11

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v2, v11

    .line 45
    :goto_1
    and-int/lit8 v3, v11, 0x70

    .line 46
    .line 47
    if-nez v3, :cond_3

    .line 48
    .line 49
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_2

    .line 54
    .line 55
    const/16 v3, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v3, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v2, v3

    .line 61
    :cond_3
    and-int/lit8 v3, p9, 0x2

    .line 62
    .line 63
    if-eqz v3, :cond_5

    .line 64
    .line 65
    or-int/lit16 v2, v2, 0x180

    .line 66
    .line 67
    :cond_4
    move-object/from16 v4, p2

    .line 68
    .line 69
    goto :goto_4

    .line 70
    :cond_5
    and-int/lit16 v4, v11, 0x380

    .line 71
    .line 72
    if-nez v4, :cond_4

    .line 73
    .line 74
    move-object/from16 v4, p2

    .line 75
    .line 76
    invoke-virtual {v6, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_6

    .line 81
    .line 82
    const/16 v5, 0x100

    .line 83
    .line 84
    goto :goto_3

    .line 85
    :cond_6
    const/16 v5, 0x80

    .line 86
    .line 87
    :goto_3
    or-int/2addr v2, v5

    .line 88
    :goto_4
    const v5, 0x1b6c00

    .line 89
    .line 90
    .line 91
    or-int/2addr v2, v5

    .line 92
    const v5, 0x2db6db

    .line 93
    .line 94
    .line 95
    and-int/2addr v5, v2

    .line 96
    const v7, 0x92492

    .line 97
    .line 98
    .line 99
    if-ne v5, v7, :cond_8

    .line 100
    .line 101
    invoke-virtual {v6}, Ll2/t;->A()Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-nez v5, :cond_7

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_7
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 109
    .line 110
    .line 111
    move/from16 v5, p4

    .line 112
    .line 113
    move/from16 v7, p6

    .line 114
    .line 115
    move-object v3, v4

    .line 116
    move-object v8, v6

    .line 117
    move-object/from16 v4, p3

    .line 118
    .line 119
    move/from16 v6, p5

    .line 120
    .line 121
    goto/16 :goto_12

    .line 122
    .line 123
    :cond_8
    :goto_5
    if-eqz v3, :cond_9

    .line 124
    .line 125
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 126
    .line 127
    move-object v12, v3

    .line 128
    goto :goto_6

    .line 129
    :cond_9
    move-object v12, v4

    .line 130
    :goto_6
    sget-object v3, Lxv/b;->i:Lxv/b;

    .line 131
    .line 132
    and-int/lit8 v4, v2, 0xe

    .line 133
    .line 134
    invoke-static {v0, v6}, Lvv/o0;->b(Lvv/m0;Ll2/o;)Lvv/n0;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    iget-object v5, v5, Lvv/n0;->h:Lxv/p;

    .line 139
    .line 140
    invoke-static {v0, v6}, Lvv/l0;->d(Lvv/m0;Ll2/o;)J

    .line 141
    .line 142
    .line 143
    move-result-wide v7

    .line 144
    new-instance v9, Le3/s;

    .line 145
    .line 146
    invoke-direct {v9, v7, v8}, Le3/s;-><init>(J)V

    .line 147
    .line 148
    .line 149
    shr-int/lit8 v7, v2, 0x3

    .line 150
    .line 151
    const v8, 0x607fb4c4

    .line 152
    .line 153
    .line 154
    invoke-virtual {v6, v8}, Ll2/t;->Z(I)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    move-result v8

    .line 161
    invoke-virtual {v6, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v13

    .line 165
    or-int/2addr v8, v13

    .line 166
    invoke-virtual {v6, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v9

    .line 170
    or-int/2addr v8, v9

    .line 171
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v9

    .line 175
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 176
    .line 177
    const/4 v14, 0x0

    .line 178
    if-nez v8, :cond_b

    .line 179
    .line 180
    if-ne v9, v13, :cond_a

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :cond_a
    move v0, v14

    .line 184
    goto :goto_a

    .line 185
    :cond_b
    :goto_7
    if-nez v5, :cond_c

    .line 186
    .line 187
    sget-object v5, Lxv/p;->i:Lxv/p;

    .line 188
    .line 189
    :cond_c
    invoke-virtual {v5}, Lxv/p;->a()Lxv/p;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    new-instance v8, Lg4/d;

    .line 194
    .line 195
    invoke-direct {v8}, Lg4/d;-><init>()V

    .line 196
    .line 197
    .line 198
    iget-object v9, v10, Lxv/o;->a:Lg4/g;

    .line 199
    .line 200
    invoke-virtual {v8, v9}, Lg4/d;->c(Lg4/g;)V

    .line 201
    .line 202
    .line 203
    sget-object v15, Lxv/n;->b:Ljava/lang/String;

    .line 204
    .line 205
    iget-object v0, v9, Lg4/g;->e:Ljava/lang/String;

    .line 206
    .line 207
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 208
    .line 209
    .line 210
    move-result v0

    .line 211
    invoke-virtual {v9, v14, v0, v15}, Lg4/g;->b(IILjava/lang/String;)Ljava/util/List;

    .line 212
    .line 213
    .line 214
    move-result-object v0

    .line 215
    check-cast v0, Ljava/lang/Iterable;

    .line 216
    .line 217
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    :goto_8
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 222
    .line 223
    .line 224
    move-result v9

    .line 225
    if-eqz v9, :cond_f

    .line 226
    .line 227
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    check-cast v9, Lg4/e;

    .line 232
    .line 233
    sget-object v15, Lxv/n;->b:Ljava/lang/String;

    .line 234
    .line 235
    iget-object v15, v9, Lg4/e;->a:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v15, Ljava/lang/String;

    .line 238
    .line 239
    invoke-static {v15, v1}, Llp/ef;->c(Ljava/lang/String;Ljava/util/Map;)Lxv/n;

    .line 240
    .line 241
    .line 242
    move-result-object v15

    .line 243
    if-nez v15, :cond_d

    .line 244
    .line 245
    goto :goto_9

    .line 246
    :cond_d
    invoke-virtual {v15, v5}, Lxv/n;->a(Lxv/p;)Lg4/g0;

    .line 247
    .line 248
    .line 249
    move-result-object v15

    .line 250
    if-eqz v15, :cond_e

    .line 251
    .line 252
    iget v14, v9, Lg4/e;->b:I

    .line 253
    .line 254
    iget v9, v9, Lg4/e;->c:I

    .line 255
    .line 256
    invoke-virtual {v8, v15, v14, v9}, Lg4/d;->b(Lg4/g0;II)V

    .line 257
    .line 258
    .line 259
    :cond_e
    :goto_9
    const/4 v14, 0x0

    .line 260
    goto :goto_8

    .line 261
    :cond_f
    invoke-virtual {v8}, Lg4/d;->j()Lg4/g;

    .line 262
    .line 263
    .line 264
    move-result-object v9

    .line 265
    invoke-virtual {v6, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    const/4 v0, 0x0

    .line 269
    :goto_a
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 270
    .line 271
    .line 272
    check-cast v9, Lg4/g;

    .line 273
    .line 274
    const v0, 0x44faf204

    .line 275
    .line 276
    .line 277
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v0

    .line 284
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    if-nez v0, :cond_11

    .line 289
    .line 290
    if-ne v5, v13, :cond_10

    .line 291
    .line 292
    goto :goto_c

    .line 293
    :cond_10
    :goto_b
    const/4 v0, 0x0

    .line 294
    goto :goto_e

    .line 295
    :cond_11
    :goto_c
    invoke-interface {v1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    check-cast v0, Ljava/lang/Iterable;

    .line 300
    .line 301
    invoke-static {v0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 302
    .line 303
    .line 304
    move-result-object v0

    .line 305
    sget-object v1, Lxv/b;->h:Lxv/b;

    .line 306
    .line 307
    invoke-static {v0, v1}, Lky0/l;->o(Lky0/j;Lay0/k;)Lky0/g;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    new-instance v1, Ljava/util/LinkedHashMap;

    .line 312
    .line 313
    invoke-direct {v1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 314
    .line 315
    .line 316
    new-instance v5, Lky0/f;

    .line 317
    .line 318
    invoke-direct {v5, v0}, Lky0/f;-><init>(Lky0/g;)V

    .line 319
    .line 320
    .line 321
    :goto_d
    invoke-virtual {v5}, Lky0/f;->hasNext()Z

    .line 322
    .line 323
    .line 324
    move-result v0

    .line 325
    if-eqz v0, :cond_12

    .line 326
    .line 327
    invoke-virtual {v5}, Lky0/f;->next()Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    check-cast v0, Llx0/l;

    .line 332
    .line 333
    iget-object v8, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 334
    .line 335
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 336
    .line 337
    invoke-interface {v1, v8, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    goto :goto_d

    .line 341
    :cond_12
    invoke-static {v1}, Lmx0/x;->o(Ljava/util/LinkedHashMap;)Ljava/util/Map;

    .line 342
    .line 343
    .line 344
    move-result-object v5

    .line 345
    invoke-virtual {v6, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    goto :goto_b

    .line 349
    :goto_e
    invoke-virtual {v6, v0}, Ll2/t;->q(Z)V

    .line 350
    .line 351
    .line 352
    check-cast v5, Ljava/util/Map;

    .line 353
    .line 354
    invoke-interface {v5}, Ljava/util/Map;->isEmpty()Z

    .line 355
    .line 356
    .line 357
    move-result v0

    .line 358
    if-eqz v0, :cond_16

    .line 359
    .line 360
    const v0, -0x40a90b0c

    .line 361
    .line 362
    .line 363
    invoke-virtual {v6, v0}, Ll2/t;->Z(I)V

    .line 364
    .line 365
    .line 366
    sget-object v0, Lvv/e0;->a:Ll2/e0;

    .line 367
    .line 368
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    check-cast v0, Lxf0/b2;

    .line 373
    .line 374
    const v1, -0x40a90add

    .line 375
    .line 376
    .line 377
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 378
    .line 379
    .line 380
    if-nez v0, :cond_13

    .line 381
    .line 382
    sget-object v0, Lw3/h1;->r:Ll2/u2;

    .line 383
    .line 384
    invoke-virtual {v6, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 385
    .line 386
    .line 387
    move-result-object v0

    .line 388
    :cond_13
    const/4 v1, 0x0

    .line 389
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 390
    .line 391
    .line 392
    const v1, 0x7cbd92a

    .line 393
    .line 394
    .line 395
    invoke-virtual {v6, v1}, Ll2/t;->Z(I)V

    .line 396
    .line 397
    .line 398
    invoke-virtual {v6, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 403
    .line 404
    .line 405
    move-result v5

    .line 406
    or-int/2addr v1, v5

    .line 407
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 408
    .line 409
    .line 410
    move-result-object v5

    .line 411
    if-nez v1, :cond_15

    .line 412
    .line 413
    if-ne v5, v13, :cond_14

    .line 414
    .line 415
    goto :goto_f

    .line 416
    :cond_14
    const/4 v1, 0x0

    .line 417
    goto :goto_10

    .line 418
    :cond_15
    :goto_f
    new-instance v5, Lxv/q;

    .line 419
    .line 420
    const/4 v1, 0x0

    .line 421
    invoke-direct {v5, v9, v10, v1}, Lxv/q;-><init>(Lg4/g;Lxv/o;I)V

    .line 422
    .line 423
    .line 424
    invoke-virtual {v6, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 425
    .line 426
    .line 427
    :goto_10
    check-cast v5, Lay0/k;

    .line 428
    .line 429
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 430
    .line 431
    .line 432
    move-object v8, v6

    .line 433
    new-instance v6, Lxv/r;

    .line 434
    .line 435
    invoke-direct {v6, v9, v10, v0, v1}, Lxv/r;-><init>(Lg4/g;Lxv/o;Ljava/lang/Object;I)V

    .line 436
    .line 437
    .line 438
    and-int/lit16 v0, v7, 0x1c00

    .line 439
    .line 440
    or-int/2addr v0, v4

    .line 441
    const v1, 0xe000

    .line 442
    .line 443
    .line 444
    and-int/2addr v1, v7

    .line 445
    or-int/2addr v0, v1

    .line 446
    const/high16 v1, 0x70000

    .line 447
    .line 448
    and-int/2addr v1, v7

    .line 449
    or-int/2addr v0, v1

    .line 450
    shl-int/lit8 v1, v2, 0x9

    .line 451
    .line 452
    const/high16 v2, 0x380000

    .line 453
    .line 454
    and-int/2addr v1, v2

    .line 455
    or-int/2addr v0, v1

    .line 456
    move-object v1, v9

    .line 457
    const/16 v9, 0x42

    .line 458
    .line 459
    const/4 v2, 0x0

    .line 460
    const/4 v4, 0x0

    .line 461
    move-object v7, v8

    .line 462
    move v8, v0

    .line 463
    move-object/from16 v0, p0

    .line 464
    .line 465
    invoke-static/range {v0 .. v9}, Lvv/l0;->a(Lvv/m0;Lg4/g;Lx2/s;Lay0/k;Ljava/util/Map;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 466
    .line 467
    .line 468
    move-object v0, v3

    .line 469
    move-object v6, v7

    .line 470
    const/4 v1, 0x0

    .line 471
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 472
    .line 473
    .line 474
    move-object v2, v12

    .line 475
    goto :goto_11

    .line 476
    :cond_16
    move-object v0, v3

    .line 477
    move-object v1, v9

    .line 478
    const v3, -0x40a90802

    .line 479
    .line 480
    .line 481
    invoke-virtual {v6, v3}, Ll2/t;->Z(I)V

    .line 482
    .line 483
    .line 484
    new-instance v3, Lb1/h;

    .line 485
    .line 486
    const/4 v4, 0x2

    .line 487
    move-object/from16 p4, p0

    .line 488
    .line 489
    move-object/from16 p5, v1

    .line 490
    .line 491
    move-object/from16 p2, v3

    .line 492
    .line 493
    move/from16 p7, v4

    .line 494
    .line 495
    move-object/from16 p3, v5

    .line 496
    .line 497
    move-object/from16 p6, v10

    .line 498
    .line 499
    invoke-direct/range {p2 .. p7}, Lb1/h;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 500
    .line 501
    .line 502
    move-object/from16 v1, p2

    .line 503
    .line 504
    const v3, -0x1b3e110c

    .line 505
    .line 506
    .line 507
    invoke-static {v3, v6, v1}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 508
    .line 509
    .line 510
    move-result-object v5

    .line 511
    shr-int/lit8 v1, v2, 0x6

    .line 512
    .line 513
    and-int/lit8 v1, v1, 0xe

    .line 514
    .line 515
    or-int/lit16 v7, v1, 0xc00

    .line 516
    .line 517
    const/4 v8, 0x6

    .line 518
    const/4 v3, 0x0

    .line 519
    const/4 v4, 0x0

    .line 520
    move-object v2, v12

    .line 521
    invoke-static/range {v2 .. v8}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 522
    .line 523
    .line 524
    const/4 v1, 0x0

    .line 525
    invoke-virtual {v6, v1}, Ll2/t;->q(Z)V

    .line 526
    .line 527
    .line 528
    :goto_11
    const/4 v1, 0x1

    .line 529
    const v3, 0x7fffffff

    .line 530
    .line 531
    .line 532
    move-object v4, v0

    .line 533
    move v5, v1

    .line 534
    move v7, v3

    .line 535
    move-object v8, v6

    .line 536
    move v6, v5

    .line 537
    move-object v3, v2

    .line 538
    :goto_12
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 539
    .line 540
    .line 541
    move-result-object v10

    .line 542
    if-eqz v10, :cond_17

    .line 543
    .line 544
    new-instance v0, Lxv/s;

    .line 545
    .line 546
    move-object/from16 v1, p0

    .line 547
    .line 548
    move-object/from16 v2, p1

    .line 549
    .line 550
    move/from16 v9, p9

    .line 551
    .line 552
    move v8, v11

    .line 553
    invoke-direct/range {v0 .. v9}, Lxv/s;-><init>(Lvv/m0;Lxv/o;Lx2/s;Lay0/k;ZIIII)V

    .line 554
    .line 555
    .line 556
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 557
    .line 558
    :cond_17
    return-void
.end method

.method public static final b(Lg4/g;Ljava/util/Map;I)Lky0/g;
    .locals 1

    .line 1
    sget-object v0, Lxv/n;->b:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0, p2, p2, v0}, Lg4/g;->b(IILjava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Iterable;

    .line 8
    .line 9
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance p2, Lw3/a0;

    .line 14
    .line 15
    const/16 v0, 0x8

    .line 16
    .line 17
    invoke-direct {p2, p1, v0}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {p0, p2}, Lky0/l;->o(Lky0/j;Lay0/k;)Lky0/g;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public static final c(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Lla/s;
    .locals 1

    .line 1
    if-eqz p2, :cond_1

    .line 2
    .line 3
    invoke-static {p2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    const-string v0, ":memory:"

    .line 10
    .line 11
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    new-instance v0, Lla/s;

    .line 18
    .line 19
    invoke-direct {v0, p0, p1, p2}, Lla/s;-><init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    return-object v0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 24
    .line 25
    const-string p1, "Cannot build a database with the special name \':memory:\'. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 32
    .line 33
    const-string p1, "Cannot build a database with null or empty name. If you are trying to create an in memory database, use Room.inMemoryDatabaseBuilder"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0
.end method
