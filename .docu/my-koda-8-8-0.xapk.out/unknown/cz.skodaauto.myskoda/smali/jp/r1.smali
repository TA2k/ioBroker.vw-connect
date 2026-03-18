.class public abstract Ljp/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ln1/v;Ln1/c;Lk1/z0;Lg1/j1;ZLe1/j;Lk1/i;Lk1/g;Lay0/k;Ll2/o;II)V
    .locals 36

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    move-object/from16 v6, p2

    .line 6
    .line 7
    move-object/from16 v4, p3

    .line 8
    .line 9
    move/from16 v0, p5

    .line 10
    .line 11
    move-object/from16 v7, p7

    .line 12
    .line 13
    move-object/from16 v8, p8

    .line 14
    .line 15
    move-object/from16 v12, p9

    .line 16
    .line 17
    move/from16 v13, p11

    .line 18
    .line 19
    move-object/from16 v14, p10

    .line 20
    .line 21
    check-cast v14, Ll2/t;

    .line 22
    .line 23
    const v2, 0x2a3e8512

    .line 24
    .line 25
    .line 26
    invoke-virtual {v14, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v2, v13, 0x6

    .line 30
    .line 31
    if-nez v2, :cond_1

    .line 32
    .line 33
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v2, v13

    .line 43
    goto :goto_1

    .line 44
    :cond_1
    move v2, v13

    .line 45
    :goto_1
    and-int/lit8 v9, v13, 0x30

    .line 46
    .line 47
    if-nez v9, :cond_3

    .line 48
    .line 49
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v9

    .line 53
    if-eqz v9, :cond_2

    .line 54
    .line 55
    const/16 v9, 0x20

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    const/16 v9, 0x10

    .line 59
    .line 60
    :goto_2
    or-int/2addr v2, v9

    .line 61
    :cond_3
    and-int/lit16 v9, v13, 0x180

    .line 62
    .line 63
    if-nez v9, :cond_6

    .line 64
    .line 65
    and-int/lit16 v9, v13, 0x200

    .line 66
    .line 67
    if-nez v9, :cond_4

    .line 68
    .line 69
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    goto :goto_3

    .line 74
    :cond_4
    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v9

    .line 78
    :goto_3
    if-eqz v9, :cond_5

    .line 79
    .line 80
    const/16 v9, 0x100

    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    const/16 v9, 0x80

    .line 84
    .line 85
    :goto_4
    or-int/2addr v2, v9

    .line 86
    :cond_6
    and-int/lit16 v9, v13, 0xc00

    .line 87
    .line 88
    if-nez v9, :cond_8

    .line 89
    .line 90
    invoke-virtual {v14, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v9

    .line 94
    if-eqz v9, :cond_7

    .line 95
    .line 96
    const/16 v9, 0x800

    .line 97
    .line 98
    goto :goto_5

    .line 99
    :cond_7
    const/16 v9, 0x400

    .line 100
    .line 101
    :goto_5
    or-int/2addr v2, v9

    .line 102
    :cond_8
    and-int/lit16 v9, v13, 0x6000

    .line 103
    .line 104
    const/4 v10, 0x0

    .line 105
    if-nez v9, :cond_a

    .line 106
    .line 107
    invoke-virtual {v14, v10}, Ll2/t;->h(Z)Z

    .line 108
    .line 109
    .line 110
    move-result v9

    .line 111
    if-eqz v9, :cond_9

    .line 112
    .line 113
    const/16 v9, 0x4000

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_9
    const/16 v9, 0x2000

    .line 117
    .line 118
    :goto_6
    or-int/2addr v2, v9

    .line 119
    :cond_a
    const/high16 v9, 0x30000

    .line 120
    .line 121
    and-int v17, v13, v9

    .line 122
    .line 123
    move/from16 v18, v9

    .line 124
    .line 125
    const/4 v9, 0x1

    .line 126
    if-nez v17, :cond_c

    .line 127
    .line 128
    invoke-virtual {v14, v9}, Ll2/t;->h(Z)Z

    .line 129
    .line 130
    .line 131
    move-result v17

    .line 132
    if-eqz v17, :cond_b

    .line 133
    .line 134
    const/high16 v17, 0x20000

    .line 135
    .line 136
    goto :goto_7

    .line 137
    :cond_b
    const/high16 v17, 0x10000

    .line 138
    .line 139
    :goto_7
    or-int v2, v2, v17

    .line 140
    .line 141
    :cond_c
    const/high16 v17, 0x180000

    .line 142
    .line 143
    and-int v19, v13, v17

    .line 144
    .line 145
    move-object/from16 v10, p4

    .line 146
    .line 147
    if-nez v19, :cond_e

    .line 148
    .line 149
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v20

    .line 153
    if-eqz v20, :cond_d

    .line 154
    .line 155
    const/high16 v20, 0x100000

    .line 156
    .line 157
    goto :goto_8

    .line 158
    :cond_d
    const/high16 v20, 0x80000

    .line 159
    .line 160
    :goto_8
    or-int v2, v2, v20

    .line 161
    .line 162
    :cond_e
    const/high16 v20, 0xc00000

    .line 163
    .line 164
    and-int v21, v13, v20

    .line 165
    .line 166
    if-nez v21, :cond_10

    .line 167
    .line 168
    invoke-virtual {v14, v0}, Ll2/t;->h(Z)Z

    .line 169
    .line 170
    .line 171
    move-result v21

    .line 172
    if-eqz v21, :cond_f

    .line 173
    .line 174
    const/high16 v21, 0x800000

    .line 175
    .line 176
    goto :goto_9

    .line 177
    :cond_f
    const/high16 v21, 0x400000

    .line 178
    .line 179
    :goto_9
    or-int v2, v2, v21

    .line 180
    .line 181
    :cond_10
    const/high16 v21, 0x6000000

    .line 182
    .line 183
    and-int v21, v13, v21

    .line 184
    .line 185
    move-object/from16 v9, p6

    .line 186
    .line 187
    if-nez v21, :cond_12

    .line 188
    .line 189
    invoke-virtual {v14, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 190
    .line 191
    .line 192
    move-result v23

    .line 193
    if-eqz v23, :cond_11

    .line 194
    .line 195
    const/high16 v23, 0x4000000

    .line 196
    .line 197
    goto :goto_a

    .line 198
    :cond_11
    const/high16 v23, 0x2000000

    .line 199
    .line 200
    :goto_a
    or-int v2, v2, v23

    .line 201
    .line 202
    :cond_12
    const/high16 v23, 0x30000000

    .line 203
    .line 204
    and-int v23, v13, v23

    .line 205
    .line 206
    if-nez v23, :cond_14

    .line 207
    .line 208
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v23

    .line 212
    if-eqz v23, :cond_13

    .line 213
    .line 214
    const/high16 v23, 0x20000000

    .line 215
    .line 216
    goto :goto_b

    .line 217
    :cond_13
    const/high16 v23, 0x10000000

    .line 218
    .line 219
    :goto_b
    or-int v2, v2, v23

    .line 220
    .line 221
    :cond_14
    and-int/lit8 v23, p12, 0x6

    .line 222
    .line 223
    if-nez v23, :cond_16

    .line 224
    .line 225
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v23

    .line 229
    if-eqz v23, :cond_15

    .line 230
    .line 231
    const/16 v23, 0x4

    .line 232
    .line 233
    goto :goto_c

    .line 234
    :cond_15
    const/16 v23, 0x2

    .line 235
    .line 236
    :goto_c
    or-int v23, p12, v23

    .line 237
    .line 238
    goto :goto_d

    .line 239
    :cond_16
    move/from16 v23, p12

    .line 240
    .line 241
    :goto_d
    and-int/lit8 v24, p12, 0x30

    .line 242
    .line 243
    if-nez v24, :cond_18

    .line 244
    .line 245
    invoke-virtual {v14, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v24

    .line 249
    if-eqz v24, :cond_17

    .line 250
    .line 251
    const/16 v16, 0x20

    .line 252
    .line 253
    goto :goto_e

    .line 254
    :cond_17
    const/16 v16, 0x10

    .line 255
    .line 256
    :goto_e
    or-int v23, v23, v16

    .line 257
    .line 258
    :cond_18
    const v16, 0x12492493

    .line 259
    .line 260
    .line 261
    and-int v5, v2, v16

    .line 262
    .line 263
    const v11, 0x12492492

    .line 264
    .line 265
    .line 266
    const/16 v15, 0x12

    .line 267
    .line 268
    if-ne v5, v11, :cond_1a

    .line 269
    .line 270
    and-int/lit8 v5, v23, 0x13

    .line 271
    .line 272
    if-eq v5, v15, :cond_19

    .line 273
    .line 274
    goto :goto_f

    .line 275
    :cond_19
    const/4 v5, 0x0

    .line 276
    goto :goto_10

    .line 277
    :cond_1a
    :goto_f
    const/4 v5, 0x1

    .line 278
    :goto_10
    and-int/lit8 v11, v2, 0x1

    .line 279
    .line 280
    invoke-virtual {v14, v11, v5}, Ll2/t;->O(IZ)Z

    .line 281
    .line 282
    .line 283
    move-result v5

    .line 284
    if-eqz v5, :cond_49

    .line 285
    .line 286
    invoke-virtual {v14}, Ll2/t;->T()V

    .line 287
    .line 288
    .line 289
    and-int/lit8 v5, v13, 0x1

    .line 290
    .line 291
    if-eqz v5, :cond_1c

    .line 292
    .line 293
    invoke-virtual {v14}, Ll2/t;->y()Z

    .line 294
    .line 295
    .line 296
    move-result v5

    .line 297
    if-eqz v5, :cond_1b

    .line 298
    .line 299
    goto :goto_11

    .line 300
    :cond_1b
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 301
    .line 302
    .line 303
    :cond_1c
    :goto_11
    invoke-virtual {v14}, Ll2/t;->r()V

    .line 304
    .line 305
    .line 306
    shr-int/lit8 v25, v2, 0x3

    .line 307
    .line 308
    and-int/lit8 v26, v25, 0xe

    .line 309
    .line 310
    and-int/lit8 v5, v23, 0x70

    .line 311
    .line 312
    or-int v5, v26, v5

    .line 313
    .line 314
    invoke-static {v12, v14}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 315
    .line 316
    .line 317
    move-result-object v11

    .line 318
    and-int/lit8 v27, v5, 0xe

    .line 319
    .line 320
    move/from16 v28, v15

    .line 321
    .line 322
    xor-int/lit8 v15, v27, 0x6

    .line 323
    .line 324
    const/4 v0, 0x4

    .line 325
    if-le v15, v0, :cond_1d

    .line 326
    .line 327
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v15

    .line 331
    if-nez v15, :cond_1e

    .line 332
    .line 333
    :cond_1d
    and-int/lit8 v5, v5, 0x6

    .line 334
    .line 335
    if-ne v5, v0, :cond_1f

    .line 336
    .line 337
    :cond_1e
    const/4 v0, 0x1

    .line 338
    goto :goto_12

    .line 339
    :cond_1f
    const/4 v0, 0x0

    .line 340
    :goto_12
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 341
    .line 342
    .line 343
    move-result-object v5

    .line 344
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 345
    .line 346
    if-nez v0, :cond_21

    .line 347
    .line 348
    if-ne v5, v15, :cond_20

    .line 349
    .line 350
    goto :goto_13

    .line 351
    :cond_20
    move/from16 v27, v2

    .line 352
    .line 353
    goto :goto_14

    .line 354
    :cond_21
    :goto_13
    sget-object v0, Ll2/x0;->g:Ll2/x0;

    .line 355
    .line 356
    new-instance v5, Lio0/f;

    .line 357
    .line 358
    move/from16 v27, v2

    .line 359
    .line 360
    const/4 v2, 0x3

    .line 361
    invoke-direct {v5, v11, v2}, Lio0/f;-><init>(Ll2/b1;I)V

    .line 362
    .line 363
    .line 364
    invoke-static {v5, v0}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 365
    .line 366
    .line 367
    move-result-object v2

    .line 368
    new-instance v5, Llk/j;

    .line 369
    .line 370
    const/4 v11, 0x7

    .line 371
    invoke-direct {v5, v11, v2, v3}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 372
    .line 373
    .line 374
    invoke-static {v5, v0}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 375
    .line 376
    .line 377
    move-result-object v33

    .line 378
    new-instance v29, La90/r;

    .line 379
    .line 380
    const/16 v30, 0x0

    .line 381
    .line 382
    const/16 v31, 0x15

    .line 383
    .line 384
    const-class v32, Ll2/t2;

    .line 385
    .line 386
    const-string v34, "value"

    .line 387
    .line 388
    const-string v35, "getValue()Ljava/lang/Object;"

    .line 389
    .line 390
    invoke-direct/range {v29 .. v35}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    move-object/from16 v5, v29

    .line 394
    .line 395
    invoke-virtual {v14, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 396
    .line 397
    .line 398
    :goto_14
    check-cast v5, Lhy0/u;

    .line 399
    .line 400
    shr-int/lit8 v0, v27, 0x9

    .line 401
    .line 402
    and-int/lit8 v0, v0, 0x70

    .line 403
    .line 404
    or-int v0, v26, v0

    .line 405
    .line 406
    and-int/lit8 v2, v0, 0xe

    .line 407
    .line 408
    xor-int/lit8 v2, v2, 0x6

    .line 409
    .line 410
    const/4 v11, 0x4

    .line 411
    if-le v2, v11, :cond_22

    .line 412
    .line 413
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 414
    .line 415
    .line 416
    move-result v2

    .line 417
    if-nez v2, :cond_23

    .line 418
    .line 419
    :cond_22
    and-int/lit8 v2, v0, 0x6

    .line 420
    .line 421
    if-ne v2, v11, :cond_24

    .line 422
    .line 423
    :cond_23
    const/4 v2, 0x1

    .line 424
    goto :goto_15

    .line 425
    :cond_24
    const/4 v2, 0x0

    .line 426
    :goto_15
    and-int/lit8 v11, v0, 0x70

    .line 427
    .line 428
    xor-int/lit8 v11, v11, 0x30

    .line 429
    .line 430
    move/from16 v29, v0

    .line 431
    .line 432
    const/4 v0, 0x0

    .line 433
    move/from16 v30, v2

    .line 434
    .line 435
    const/16 v2, 0x20

    .line 436
    .line 437
    if-le v11, v2, :cond_25

    .line 438
    .line 439
    invoke-virtual {v14, v0}, Ll2/t;->h(Z)Z

    .line 440
    .line 441
    .line 442
    move-result v11

    .line 443
    if-nez v11, :cond_26

    .line 444
    .line 445
    :cond_25
    and-int/lit8 v11, v29, 0x30

    .line 446
    .line 447
    if-ne v11, v2, :cond_27

    .line 448
    .line 449
    :cond_26
    const/4 v2, 0x1

    .line 450
    goto :goto_16

    .line 451
    :cond_27
    const/4 v2, 0x0

    .line 452
    :goto_16
    or-int v2, v30, v2

    .line 453
    .line 454
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v11

    .line 458
    if-nez v2, :cond_28

    .line 459
    .line 460
    if-ne v11, v15, :cond_29

    .line 461
    .line 462
    :cond_28
    new-instance v11, Ln1/y;

    .line 463
    .line 464
    invoke-direct {v11, v3}, Ln1/y;-><init>(Ln1/v;)V

    .line 465
    .line 466
    .line 467
    invoke-virtual {v14, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 468
    .line 469
    .line 470
    :cond_29
    move-object/from16 v29, v11

    .line 471
    .line 472
    check-cast v29, Ln1/y;

    .line 473
    .line 474
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 475
    .line 476
    .line 477
    move-result-object v2

    .line 478
    if-ne v2, v15, :cond_2a

    .line 479
    .line 480
    invoke-static {v14}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 481
    .line 482
    .line 483
    move-result-object v2

    .line 484
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 485
    .line 486
    .line 487
    :cond_2a
    check-cast v2, Lvy0/b0;

    .line 488
    .line 489
    sget-object v11, Lw3/h1;->g:Ll2/u2;

    .line 490
    .line 491
    invoke-virtual {v14, v11}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 492
    .line 493
    .line 494
    move-result-object v11

    .line 495
    check-cast v11, Le3/w;

    .line 496
    .line 497
    sget-object v0, Lw3/h1;->v:Ll2/e0;

    .line 498
    .line 499
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    check-cast v0, Ljava/lang/Boolean;

    .line 504
    .line 505
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 506
    .line 507
    .line 508
    move-result v0

    .line 509
    if-nez v0, :cond_2b

    .line 510
    .line 511
    sget-object v0, Lo1/d1;->a:Lo1/f0;

    .line 512
    .line 513
    goto :goto_17

    .line 514
    :cond_2b
    const/4 v0, 0x0

    .line 515
    :goto_17
    const v31, 0x7fff0

    .line 516
    .line 517
    .line 518
    and-int v31, v27, v31

    .line 519
    .line 520
    shl-int/lit8 v23, v23, 0x12

    .line 521
    .line 522
    const/high16 v28, 0x380000

    .line 523
    .line 524
    and-int v23, v23, v28

    .line 525
    .line 526
    or-int v23, v31, v23

    .line 527
    .line 528
    shr-int/lit8 v27, v27, 0x6

    .line 529
    .line 530
    const/high16 v31, 0x1c00000

    .line 531
    .line 532
    and-int v27, v27, v31

    .line 533
    .line 534
    move-object/from16 v32, v0

    .line 535
    .line 536
    or-int v0, v23, v27

    .line 537
    .line 538
    and-int/lit8 v23, v0, 0x70

    .line 539
    .line 540
    move-object/from16 v27, v2

    .line 541
    .line 542
    xor-int/lit8 v2, v23, 0x30

    .line 543
    .line 544
    move-object/from16 v23, v5

    .line 545
    .line 546
    const/16 v5, 0x20

    .line 547
    .line 548
    if-le v2, v5, :cond_2c

    .line 549
    .line 550
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 551
    .line 552
    .line 553
    move-result v2

    .line 554
    if-nez v2, :cond_2d

    .line 555
    .line 556
    :cond_2c
    and-int/lit8 v2, v0, 0x30

    .line 557
    .line 558
    if-ne v2, v5, :cond_2e

    .line 559
    .line 560
    :cond_2d
    const/4 v2, 0x1

    .line 561
    goto :goto_18

    .line 562
    :cond_2e
    const/4 v2, 0x0

    .line 563
    :goto_18
    and-int/lit16 v5, v0, 0x380

    .line 564
    .line 565
    xor-int/lit16 v5, v5, 0x180

    .line 566
    .line 567
    move/from16 v16, v2

    .line 568
    .line 569
    const/16 v2, 0x100

    .line 570
    .line 571
    if-le v5, v2, :cond_2f

    .line 572
    .line 573
    invoke-virtual {v14, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    move-result v5

    .line 577
    if-nez v5, :cond_30

    .line 578
    .line 579
    :cond_2f
    and-int/lit16 v5, v0, 0x180

    .line 580
    .line 581
    if-ne v5, v2, :cond_31

    .line 582
    .line 583
    :cond_30
    const/4 v2, 0x1

    .line 584
    goto :goto_19

    .line 585
    :cond_31
    const/4 v2, 0x0

    .line 586
    :goto_19
    or-int v2, v16, v2

    .line 587
    .line 588
    and-int/lit16 v5, v0, 0x1c00

    .line 589
    .line 590
    xor-int/lit16 v5, v5, 0xc00

    .line 591
    .line 592
    move/from16 p10, v2

    .line 593
    .line 594
    const/16 v2, 0x800

    .line 595
    .line 596
    if-le v5, v2, :cond_32

    .line 597
    .line 598
    invoke-virtual {v14, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 599
    .line 600
    .line 601
    move-result v5

    .line 602
    if-nez v5, :cond_33

    .line 603
    .line 604
    :cond_32
    and-int/lit16 v5, v0, 0xc00

    .line 605
    .line 606
    if-ne v5, v2, :cond_34

    .line 607
    .line 608
    :cond_33
    const/4 v2, 0x1

    .line 609
    goto :goto_1a

    .line 610
    :cond_34
    const/4 v2, 0x0

    .line 611
    :goto_1a
    or-int v2, p10, v2

    .line 612
    .line 613
    const v5, 0xe000

    .line 614
    .line 615
    .line 616
    and-int/2addr v5, v0

    .line 617
    xor-int/lit16 v5, v5, 0x6000

    .line 618
    .line 619
    move/from16 p10, v2

    .line 620
    .line 621
    const/16 v2, 0x4000

    .line 622
    .line 623
    if-le v5, v2, :cond_35

    .line 624
    .line 625
    const/4 v5, 0x0

    .line 626
    invoke-virtual {v14, v5}, Ll2/t;->h(Z)Z

    .line 627
    .line 628
    .line 629
    move-result v16

    .line 630
    if-nez v16, :cond_36

    .line 631
    .line 632
    :cond_35
    and-int/lit16 v5, v0, 0x6000

    .line 633
    .line 634
    if-ne v5, v2, :cond_37

    .line 635
    .line 636
    :cond_36
    const/4 v2, 0x1

    .line 637
    goto :goto_1b

    .line 638
    :cond_37
    const/4 v2, 0x0

    .line 639
    :goto_1b
    or-int v2, p10, v2

    .line 640
    .line 641
    const/high16 v5, 0x70000

    .line 642
    .line 643
    and-int/2addr v5, v0

    .line 644
    xor-int v5, v5, v18

    .line 645
    .line 646
    move/from16 p10, v0

    .line 647
    .line 648
    const/high16 v0, 0x20000

    .line 649
    .line 650
    if-le v5, v0, :cond_38

    .line 651
    .line 652
    const/4 v5, 0x1

    .line 653
    invoke-virtual {v14, v5}, Ll2/t;->h(Z)Z

    .line 654
    .line 655
    .line 656
    move-result v16

    .line 657
    if-nez v16, :cond_39

    .line 658
    .line 659
    :cond_38
    and-int v5, p10, v18

    .line 660
    .line 661
    if-ne v5, v0, :cond_3a

    .line 662
    .line 663
    :cond_39
    const/4 v0, 0x1

    .line 664
    goto :goto_1c

    .line 665
    :cond_3a
    const/4 v0, 0x0

    .line 666
    :goto_1c
    or-int/2addr v0, v2

    .line 667
    and-int v2, p10, v28

    .line 668
    .line 669
    xor-int v2, v2, v17

    .line 670
    .line 671
    const/high16 v5, 0x100000

    .line 672
    .line 673
    if-le v2, v5, :cond_3b

    .line 674
    .line 675
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 676
    .line 677
    .line 678
    move-result v2

    .line 679
    if-nez v2, :cond_3c

    .line 680
    .line 681
    :cond_3b
    and-int v2, p10, v17

    .line 682
    .line 683
    if-ne v2, v5, :cond_3d

    .line 684
    .line 685
    :cond_3c
    const/4 v2, 0x1

    .line 686
    goto :goto_1d

    .line 687
    :cond_3d
    const/4 v2, 0x0

    .line 688
    :goto_1d
    or-int/2addr v0, v2

    .line 689
    and-int v2, p10, v31

    .line 690
    .line 691
    xor-int v2, v2, v20

    .line 692
    .line 693
    const/high16 v5, 0x800000

    .line 694
    .line 695
    if-le v2, v5, :cond_3e

    .line 696
    .line 697
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 698
    .line 699
    .line 700
    move-result v2

    .line 701
    if-nez v2, :cond_3f

    .line 702
    .line 703
    :cond_3e
    and-int v2, p10, v20

    .line 704
    .line 705
    if-ne v2, v5, :cond_40

    .line 706
    .line 707
    :cond_3f
    const/4 v2, 0x1

    .line 708
    goto :goto_1e

    .line 709
    :cond_40
    const/4 v2, 0x0

    .line 710
    :goto_1e
    or-int/2addr v0, v2

    .line 711
    invoke-virtual {v14, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 712
    .line 713
    .line 714
    move-result v2

    .line 715
    or-int/2addr v0, v2

    .line 716
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 717
    .line 718
    .line 719
    move-result-object v2

    .line 720
    if-nez v0, :cond_42

    .line 721
    .line 722
    if-ne v2, v15, :cond_41

    .line 723
    .line 724
    goto :goto_1f

    .line 725
    :cond_41
    move-object v8, v3

    .line 726
    move-object/from16 v3, v23

    .line 727
    .line 728
    const/4 v0, 0x0

    .line 729
    const/16 v22, 0x1

    .line 730
    .line 731
    goto :goto_20

    .line 732
    :cond_42
    :goto_1f
    new-instance v2, Ln1/m;

    .line 733
    .line 734
    move-object v10, v11

    .line 735
    move-object/from16 v5, v23

    .line 736
    .line 737
    move-object/from16 v9, v27

    .line 738
    .line 739
    move-object/from16 v11, v32

    .line 740
    .line 741
    const/4 v0, 0x0

    .line 742
    const/16 v22, 0x1

    .line 743
    .line 744
    invoke-direct/range {v2 .. v11}, Ln1/m;-><init>(Ln1/v;Lk1/z0;Lhy0/u;Ln1/c;Lk1/i;Lk1/g;Lvy0/b0;Le3/w;Lo1/f0;)V

    .line 745
    .line 746
    .line 747
    move-object v8, v3

    .line 748
    move-object v3, v5

    .line 749
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 750
    .line 751
    .line 752
    :goto_20
    move-object/from16 v16, v2

    .line 753
    .line 754
    check-cast v16, Lo1/c0;

    .line 755
    .line 756
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 757
    .line 758
    if-eqz p5, :cond_48

    .line 759
    .line 760
    const v2, 0x1a13923

    .line 761
    .line 762
    .line 763
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 764
    .line 765
    .line 766
    xor-int/lit8 v2, v26, 0x6

    .line 767
    .line 768
    const/4 v11, 0x4

    .line 769
    if-le v2, v11, :cond_43

    .line 770
    .line 771
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 772
    .line 773
    .line 774
    move-result v2

    .line 775
    if-nez v2, :cond_44

    .line 776
    .line 777
    :cond_43
    and-int/lit8 v2, v25, 0x6

    .line 778
    .line 779
    if-ne v2, v11, :cond_45

    .line 780
    .line 781
    :cond_44
    move/from16 v10, v22

    .line 782
    .line 783
    goto :goto_21

    .line 784
    :cond_45
    move v10, v0

    .line 785
    :goto_21
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 786
    .line 787
    .line 788
    move-result-object v2

    .line 789
    if-nez v10, :cond_46

    .line 790
    .line 791
    if-ne v2, v15, :cond_47

    .line 792
    .line 793
    :cond_46
    new-instance v2, Ln1/d;

    .line 794
    .line 795
    invoke-direct {v2, v8}, Ln1/d;-><init>(Ln1/v;)V

    .line 796
    .line 797
    .line 798
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 799
    .line 800
    .line 801
    :cond_47
    check-cast v2, Ln1/d;

    .line 802
    .line 803
    iget-object v5, v8, Ln1/v;->n:Lg1/r;

    .line 804
    .line 805
    const/4 v6, 0x0

    .line 806
    invoke-static {v2, v5, v6, v4}, Landroidx/compose/foundation/lazy/layout/a;->a(Lo1/o;Lg1/r;ZLg1/w1;)Lx2/s;

    .line 807
    .line 808
    .line 809
    move-result-object v2

    .line 810
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 811
    .line 812
    .line 813
    :goto_22
    move-object v0, v2

    .line 814
    goto :goto_23

    .line 815
    :cond_48
    const/4 v6, 0x0

    .line 816
    const v2, 0x1a5be30

    .line 817
    .line 818
    .line 819
    invoke-virtual {v14, v2}, Ll2/t;->Y(I)V

    .line 820
    .line 821
    .line 822
    invoke-virtual {v14, v0}, Ll2/t;->q(Z)V

    .line 823
    .line 824
    .line 825
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 826
    .line 827
    goto :goto_22

    .line 828
    :goto_23
    iget-object v2, v8, Ln1/v;->k:Lm1/r;

    .line 829
    .line 830
    invoke-interface {v1, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 831
    .line 832
    .line 833
    move-result-object v2

    .line 834
    iget-object v5, v8, Ln1/v;->l:Lo1/d;

    .line 835
    .line 836
    invoke-interface {v2, v5}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 837
    .line 838
    .line 839
    move-result-object v2

    .line 840
    move-object v5, v4

    .line 841
    move v7, v6

    .line 842
    move-object/from16 v4, v29

    .line 843
    .line 844
    move/from16 v6, p5

    .line 845
    .line 846
    invoke-static/range {v2 .. v7}, Landroidx/compose/foundation/lazy/layout/a;->b(Lx2/s;Lhy0/u;Lo1/r0;Lg1/w1;ZZ)Lx2/s;

    .line 847
    .line 848
    .line 849
    move-result-object v2

    .line 850
    move-object/from16 v23, v3

    .line 851
    .line 852
    move-object v4, v5

    .line 853
    move v6, v7

    .line 854
    invoke-interface {v2, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 855
    .line 856
    .line 857
    move-result-object v0

    .line 858
    iget-object v2, v8, Ln1/v;->m:Landroidx/compose/foundation/lazy/layout/b;

    .line 859
    .line 860
    iget-object v2, v2, Landroidx/compose/foundation/lazy/layout/b;->k:Lx2/s;

    .line 861
    .line 862
    invoke-interface {v0, v2}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 863
    .line 864
    .line 865
    move-result-object v2

    .line 866
    move-object v3, v8

    .line 867
    iget-object v8, v3, Ln1/v;->f:Li1/l;

    .line 868
    .line 869
    const/4 v9, 0x0

    .line 870
    const/4 v11, 0x0

    .line 871
    move-object/from16 v7, p4

    .line 872
    .line 873
    move/from16 v5, p5

    .line 874
    .line 875
    move-object/from16 v10, p6

    .line 876
    .line 877
    invoke-static/range {v2 .. v11}, Landroidx/compose/foundation/a;->l(Lx2/s;Lg1/q2;Lg1/w1;ZZLg1/j1;Li1/l;ZLe1/j;Lp1/h;)Lx2/s;

    .line 878
    .line 879
    .line 880
    move-result-object v0

    .line 881
    move-object v8, v3

    .line 882
    iget-object v4, v8, Ln1/v;->o:Lo1/l0;

    .line 883
    .line 884
    const/4 v7, 0x0

    .line 885
    move-object v3, v0

    .line 886
    move-object v6, v14

    .line 887
    move-object/from16 v5, v16

    .line 888
    .line 889
    move-object/from16 v2, v23

    .line 890
    .line 891
    invoke-static/range {v2 .. v7}, Lo1/y;->a(Lay0/a;Lx2/s;Lo1/l0;Lo1/c0;Ll2/o;I)V

    .line 892
    .line 893
    .line 894
    goto :goto_24

    .line 895
    :cond_49
    move-object v8, v3

    .line 896
    move-object v6, v14

    .line 897
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 898
    .line 899
    .line 900
    :goto_24
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 901
    .line 902
    .line 903
    move-result-object v14

    .line 904
    if-eqz v14, :cond_4a

    .line 905
    .line 906
    new-instance v0, Ln1/j;

    .line 907
    .line 908
    move-object/from16 v3, p2

    .line 909
    .line 910
    move-object/from16 v4, p3

    .line 911
    .line 912
    move-object/from16 v5, p4

    .line 913
    .line 914
    move/from16 v6, p5

    .line 915
    .line 916
    move-object/from16 v7, p6

    .line 917
    .line 918
    move-object/from16 v9, p8

    .line 919
    .line 920
    move-object v2, v8

    .line 921
    move-object v10, v12

    .line 922
    move v11, v13

    .line 923
    move-object/from16 v8, p7

    .line 924
    .line 925
    move/from16 v12, p12

    .line 926
    .line 927
    invoke-direct/range {v0 .. v12}, Ln1/j;-><init>(Lx2/s;Ln1/v;Ln1/c;Lk1/z0;Lg1/j1;ZLe1/j;Lk1/i;Lk1/g;Lay0/k;II)V

    .line 928
    .line 929
    .line 930
    iput-object v0, v14, Ll2/u1;->d:Lay0/n;

    .line 931
    .line 932
    :cond_4a
    return-void
.end method

.method public static final b(Ljava/nio/charset/CharsetDecoder;Lnz0/i;)Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "input"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const v0, 0x7fffffff

    .line 12
    .line 13
    .line 14
    int-to-long v0, v0

    .line 15
    invoke-interface {p1}, Lnz0/i;->n()Lnz0/a;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget-wide v2, v2, Lnz0/a;->f:J

    .line 20
    .line 21
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    long-to-int v0, v0

    .line 26
    new-instance v1, Ljava/lang/StringBuilder;

    .line 27
    .line 28
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0}, Ljava/nio/charset/CharsetDecoder;->charset()Ljava/nio/charset/Charset;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    sget-object v2, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 39
    .line 40
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    invoke-static {p1}, Lnz0/j;->g(Lnz0/i;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-static {p1}, Ljp/hb;->c(Lnz0/i;)J

    .line 55
    .line 56
    .line 57
    const/4 v0, -0x1

    .line 58
    invoke-static {p1, v0}, Lnz0/j;->f(Lnz0/i;I)[B

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    new-instance v0, Loz0/a;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/nio/charset/CharsetDecoder;->charset()Ljava/nio/charset/Charset;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    new-instance v0, Ljava/lang/String;

    .line 72
    .line 73
    invoke-direct {v0, p1, p0}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/Appendable;

    .line 77
    .line 78
    .line 79
    :goto_0
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    return-object p0
.end method
