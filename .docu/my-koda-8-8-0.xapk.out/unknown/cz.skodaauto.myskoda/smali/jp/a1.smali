.class public abstract Ljp/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lqe/a;Lqe/d;Lgf/a;Ljava/util/List;Lay0/k;Lxc/b;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v5, p4

    .line 6
    .line 7
    move-object/from16 v6, p5

    .line 8
    .line 9
    move-object/from16 v8, p7

    .line 10
    .line 11
    move-object/from16 v9, p8

    .line 12
    .line 13
    const-string v0, "vin"

    .line 14
    .line 15
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v0, "season"

    .line 19
    .line 20
    move-object/from16 v2, p1

    .line 21
    .line 22
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v0, "wizardData"

    .line 26
    .line 27
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    const-string v0, "slotsPerDay"

    .line 31
    .line 32
    move-object/from16 v4, p3

    .line 33
    .line 34
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const-string v0, "selectedDays"

    .line 38
    .line 39
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string v0, "goToIntermediaryDaySuccess"

    .line 43
    .line 44
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v0, "goToSeasonSuccess"

    .line 48
    .line 49
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string v0, "goToSuccess"

    .line 53
    .line 54
    invoke-static {v9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    move-object/from16 v12, p9

    .line 58
    .line 59
    check-cast v12, Ll2/t;

    .line 60
    .line 61
    const v0, 0x415af53c

    .line 62
    .line 63
    .line 64
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 65
    .line 66
    .line 67
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    const/4 v7, 0x4

    .line 72
    if-eqz v0, :cond_0

    .line 73
    .line 74
    move v0, v7

    .line 75
    goto :goto_0

    .line 76
    :cond_0
    const/4 v0, 0x2

    .line 77
    :goto_0
    or-int v0, p10, v0

    .line 78
    .line 79
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 80
    .line 81
    .line 82
    move-result v10

    .line 83
    invoke-virtual {v12, v10}, Ll2/t;->e(I)Z

    .line 84
    .line 85
    .line 86
    move-result v10

    .line 87
    const/16 v11, 0x20

    .line 88
    .line 89
    if-eqz v10, :cond_1

    .line 90
    .line 91
    move v10, v11

    .line 92
    goto :goto_1

    .line 93
    :cond_1
    const/16 v10, 0x10

    .line 94
    .line 95
    :goto_1
    or-int/2addr v0, v10

    .line 96
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v10

    .line 100
    if-eqz v10, :cond_2

    .line 101
    .line 102
    const/16 v10, 0x100

    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_2
    const/16 v10, 0x80

    .line 106
    .line 107
    :goto_2
    or-int/2addr v0, v10

    .line 108
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 109
    .line 110
    .line 111
    move-result v10

    .line 112
    invoke-virtual {v12, v10}, Ll2/t;->e(I)Z

    .line 113
    .line 114
    .line 115
    move-result v10

    .line 116
    if-eqz v10, :cond_3

    .line 117
    .line 118
    const/16 v10, 0x800

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_3
    const/16 v10, 0x400

    .line 122
    .line 123
    :goto_3
    or-int/2addr v0, v10

    .line 124
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v10

    .line 128
    if-eqz v10, :cond_4

    .line 129
    .line 130
    const/16 v10, 0x4000

    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_4
    const/16 v10, 0x2000

    .line 134
    .line 135
    :goto_4
    or-int/2addr v0, v10

    .line 136
    invoke-virtual {v12, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v10

    .line 140
    if-eqz v10, :cond_5

    .line 141
    .line 142
    const/high16 v10, 0x20000

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_5
    const/high16 v10, 0x10000

    .line 146
    .line 147
    :goto_5
    or-int/2addr v0, v10

    .line 148
    move-object/from16 v10, p6

    .line 149
    .line 150
    invoke-virtual {v12, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v15

    .line 154
    if-eqz v15, :cond_6

    .line 155
    .line 156
    const/high16 v15, 0x100000

    .line 157
    .line 158
    goto :goto_6

    .line 159
    :cond_6
    const/high16 v15, 0x80000

    .line 160
    .line 161
    :goto_6
    or-int/2addr v0, v15

    .line 162
    invoke-virtual {v12, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v15

    .line 166
    if-eqz v15, :cond_7

    .line 167
    .line 168
    const/high16 v15, 0x800000

    .line 169
    .line 170
    goto :goto_7

    .line 171
    :cond_7
    const/high16 v15, 0x400000

    .line 172
    .line 173
    :goto_7
    or-int/2addr v0, v15

    .line 174
    invoke-virtual {v12, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v15

    .line 178
    if-eqz v15, :cond_8

    .line 179
    .line 180
    const/high16 v15, 0x4000000

    .line 181
    .line 182
    goto :goto_8

    .line 183
    :cond_8
    const/high16 v15, 0x2000000

    .line 184
    .line 185
    :goto_8
    or-int/2addr v0, v15

    .line 186
    const v15, 0x2492493

    .line 187
    .line 188
    .line 189
    and-int/2addr v15, v0

    .line 190
    const v14, 0x2492492

    .line 191
    .line 192
    .line 193
    const/16 v16, 0x1

    .line 194
    .line 195
    if-eq v15, v14, :cond_9

    .line 196
    .line 197
    move/from16 v14, v16

    .line 198
    .line 199
    goto :goto_9

    .line 200
    :cond_9
    const/4 v14, 0x0

    .line 201
    :goto_9
    and-int/lit8 v15, v0, 0x1

    .line 202
    .line 203
    invoke-virtual {v12, v15, v14}, Ll2/t;->O(IZ)Z

    .line 204
    .line 205
    .line 206
    move-result v14

    .line 207
    if-eqz v14, :cond_18

    .line 208
    .line 209
    sget-object v14, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 210
    .line 211
    invoke-virtual {v12, v14}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v14

    .line 215
    check-cast v14, Landroid/content/Context;

    .line 216
    .line 217
    invoke-virtual {v12, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v15

    .line 221
    and-int/lit8 v13, v0, 0xe

    .line 222
    .line 223
    if-ne v13, v7, :cond_a

    .line 224
    .line 225
    move/from16 v7, v16

    .line 226
    .line 227
    goto :goto_a

    .line 228
    :cond_a
    const/4 v7, 0x0

    .line 229
    :goto_a
    or-int/2addr v7, v15

    .line 230
    and-int/lit8 v13, v0, 0x70

    .line 231
    .line 232
    if-ne v13, v11, :cond_b

    .line 233
    .line 234
    move/from16 v11, v16

    .line 235
    .line 236
    goto :goto_b

    .line 237
    :cond_b
    const/4 v11, 0x0

    .line 238
    :goto_b
    or-int/2addr v7, v11

    .line 239
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v11

    .line 243
    or-int/2addr v7, v11

    .line 244
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    or-int/2addr v7, v11

    .line 249
    and-int/lit16 v11, v0, 0x1c00

    .line 250
    .line 251
    const/16 v13, 0x800

    .line 252
    .line 253
    if-ne v11, v13, :cond_c

    .line 254
    .line 255
    move/from16 v11, v16

    .line 256
    .line 257
    goto :goto_c

    .line 258
    :cond_c
    const/4 v11, 0x0

    .line 259
    :goto_c
    or-int/2addr v7, v11

    .line 260
    const/high16 v11, 0x70000

    .line 261
    .line 262
    and-int/2addr v11, v0

    .line 263
    const/high16 v13, 0x20000

    .line 264
    .line 265
    if-ne v11, v13, :cond_d

    .line 266
    .line 267
    move/from16 v11, v16

    .line 268
    .line 269
    goto :goto_d

    .line 270
    :cond_d
    const/4 v11, 0x0

    .line 271
    :goto_d
    or-int/2addr v7, v11

    .line 272
    const/high16 v11, 0x380000

    .line 273
    .line 274
    and-int/2addr v11, v0

    .line 275
    const/high16 v13, 0x100000

    .line 276
    .line 277
    if-ne v11, v13, :cond_e

    .line 278
    .line 279
    move/from16 v11, v16

    .line 280
    .line 281
    goto :goto_e

    .line 282
    :cond_e
    const/4 v11, 0x0

    .line 283
    :goto_e
    or-int/2addr v7, v11

    .line 284
    const/high16 v11, 0x1c00000

    .line 285
    .line 286
    and-int/2addr v11, v0

    .line 287
    const/high16 v13, 0x800000

    .line 288
    .line 289
    if-ne v11, v13, :cond_f

    .line 290
    .line 291
    move/from16 v11, v16

    .line 292
    .line 293
    goto :goto_f

    .line 294
    :cond_f
    const/4 v11, 0x0

    .line 295
    :goto_f
    or-int/2addr v7, v11

    .line 296
    const/high16 v11, 0xe000000

    .line 297
    .line 298
    and-int/2addr v0, v11

    .line 299
    const/high16 v11, 0x4000000

    .line 300
    .line 301
    if-ne v0, v11, :cond_10

    .line 302
    .line 303
    goto :goto_10

    .line 304
    :cond_10
    const/16 v16, 0x0

    .line 305
    .line 306
    :goto_10
    or-int v0, v7, v16

    .line 307
    .line 308
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v7

    .line 312
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 313
    .line 314
    if-nez v0, :cond_11

    .line 315
    .line 316
    if-ne v7, v13, :cond_12

    .line 317
    .line 318
    :cond_11
    new-instance v0, Lew/c;

    .line 319
    .line 320
    const/4 v11, 0x4

    .line 321
    move-object v7, v9

    .line 322
    move-object v9, v8

    .line 323
    move-object v8, v10

    .line 324
    move-object v10, v7

    .line 325
    move-object v7, v6

    .line 326
    move-object v6, v4

    .line 327
    move-object v4, v3

    .line 328
    move-object v3, v2

    .line 329
    move-object v2, v1

    .line 330
    move-object v1, v14

    .line 331
    invoke-direct/range {v0 .. v11}, Lew/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v12, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 335
    .line 336
    .line 337
    move-object v7, v0

    .line 338
    :cond_12
    check-cast v7, Lay0/k;

    .line 339
    .line 340
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 341
    .line 342
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    check-cast v0, Ljava/lang/Boolean;

    .line 347
    .line 348
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 349
    .line 350
    .line 351
    move-result v0

    .line 352
    if-eqz v0, :cond_13

    .line 353
    .line 354
    const v0, -0x105bcaaa

    .line 355
    .line 356
    .line 357
    invoke-virtual {v12, v0}, Ll2/t;->Y(I)V

    .line 358
    .line 359
    .line 360
    const/4 v0, 0x0

    .line 361
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 362
    .line 363
    .line 364
    const/4 v1, 0x0

    .line 365
    goto :goto_11

    .line 366
    :cond_13
    const/4 v0, 0x0

    .line 367
    const v1, 0x31054eee

    .line 368
    .line 369
    .line 370
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 371
    .line 372
    .line 373
    sget-object v1, Lzb/x;->a:Ll2/u2;

    .line 374
    .line 375
    invoke-virtual {v12, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v1

    .line 379
    check-cast v1, Lhi/a;

    .line 380
    .line 381
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 382
    .line 383
    .line 384
    :goto_11
    new-instance v4, Lvh/i;

    .line 385
    .line 386
    const/16 v0, 0xb

    .line 387
    .line 388
    invoke-direct {v4, v0, v1, v7}, Lvh/i;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 389
    .line 390
    .line 391
    invoke-static {v12}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    if-eqz v2, :cond_17

    .line 396
    .line 397
    instance-of v0, v2, Landroidx/lifecycle/k;

    .line 398
    .line 399
    if-eqz v0, :cond_14

    .line 400
    .line 401
    move-object v0, v2

    .line 402
    check-cast v0, Landroidx/lifecycle/k;

    .line 403
    .line 404
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    :goto_12
    move-object v5, v0

    .line 409
    goto :goto_13

    .line 410
    :cond_14
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 411
    .line 412
    goto :goto_12

    .line 413
    :goto_13
    const-class v0, Lze/e;

    .line 414
    .line 415
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 416
    .line 417
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 418
    .line 419
    .line 420
    move-result-object v1

    .line 421
    const/4 v3, 0x0

    .line 422
    move-object v6, v12

    .line 423
    invoke-static/range {v1 .. v6}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 424
    .line 425
    .line 426
    move-result-object v0

    .line 427
    check-cast v0, Lze/e;

    .line 428
    .line 429
    iget-object v1, v0, Lze/e;->m:Lyy0/l1;

    .line 430
    .line 431
    invoke-static {v1, v6}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 432
    .line 433
    .line 434
    move-result-object v1

    .line 435
    invoke-static {v6}, Llp/nf;->a(Ll2/o;)Lle/c;

    .line 436
    .line 437
    .line 438
    move-result-object v2

    .line 439
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v1

    .line 443
    check-cast v1, Lze/d;

    .line 444
    .line 445
    invoke-virtual {v6, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 446
    .line 447
    .line 448
    move-result v3

    .line 449
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v4

    .line 453
    if-nez v3, :cond_15

    .line 454
    .line 455
    if-ne v4, v13, :cond_16

    .line 456
    .line 457
    :cond_15
    new-instance v17, Lz70/u;

    .line 458
    .line 459
    const/16 v23, 0x0

    .line 460
    .line 461
    const/16 v24, 0x9

    .line 462
    .line 463
    const/16 v18, 0x1

    .line 464
    .line 465
    const-class v20, Lze/e;

    .line 466
    .line 467
    const-string v21, "onUiEvent"

    .line 468
    .line 469
    const-string v22, "onUiEvent(Lcariad/charging/multicharge/kitten/kola/presentation/wizard/multiplefixedrate/enterslots/EnterSlotsUiEvent;)V"

    .line 470
    .line 471
    move-object/from16 v19, v0

    .line 472
    .line 473
    invoke-direct/range {v17 .. v24}, Lz70/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 474
    .line 475
    .line 476
    move-object/from16 v4, v17

    .line 477
    .line 478
    invoke-virtual {v6, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 479
    .line 480
    .line 481
    :cond_16
    check-cast v4, Lhy0/g;

    .line 482
    .line 483
    check-cast v4, Lay0/k;

    .line 484
    .line 485
    const/4 v0, 0x0

    .line 486
    invoke-interface {v2, v1, v4, v6, v0}, Lle/c;->R(Lze/d;Lay0/k;Ll2/o;I)V

    .line 487
    .line 488
    .line 489
    goto :goto_14

    .line 490
    :cond_17
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 491
    .line 492
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 493
    .line 494
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 495
    .line 496
    .line 497
    throw v0

    .line 498
    :cond_18
    move-object v6, v12

    .line 499
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 500
    .line 501
    .line 502
    :goto_14
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 503
    .line 504
    .line 505
    move-result-object v11

    .line 506
    if-eqz v11, :cond_19

    .line 507
    .line 508
    new-instance v0, Lco0/j;

    .line 509
    .line 510
    move-object/from16 v1, p0

    .line 511
    .line 512
    move-object/from16 v2, p1

    .line 513
    .line 514
    move-object/from16 v3, p2

    .line 515
    .line 516
    move-object/from16 v4, p3

    .line 517
    .line 518
    move-object/from16 v5, p4

    .line 519
    .line 520
    move-object/from16 v6, p5

    .line 521
    .line 522
    move-object/from16 v7, p6

    .line 523
    .line 524
    move-object/from16 v8, p7

    .line 525
    .line 526
    move-object/from16 v9, p8

    .line 527
    .line 528
    move/from16 v10, p10

    .line 529
    .line 530
    invoke-direct/range {v0 .. v10}, Lco0/j;-><init>(Ljava/lang/String;Lqe/a;Lqe/d;Lgf/a;Ljava/util/List;Lay0/k;Lxc/b;Lay0/k;Lay0/a;I)V

    .line 531
    .line 532
    .line 533
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 534
    .line 535
    :cond_19
    return-void
.end method

.method public static final b(Lmb0/e;)Z
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v0, 0x1

    .line 11
    if-eq p0, v0, :cond_0

    .line 12
    .line 13
    const/4 v1, 0x2

    .line 14
    if-eq p0, v1, :cond_0

    .line 15
    .line 16
    const/4 v1, 0x3

    .line 17
    if-eq p0, v1, :cond_0

    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    if-eq p0, v1, :cond_0

    .line 21
    .line 22
    const/16 v1, 0x8

    .line 23
    .line 24
    if-eq p0, v1, :cond_0

    .line 25
    .line 26
    const/16 v1, 0x9

    .line 27
    .line 28
    if-eq p0, v1, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return p0

    .line 32
    :cond_0
    return v0
.end method

.method public static final c(Lmb0/e;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    packed-switch p0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    new-instance p0, La8/r0;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :pswitch_0
    const/4 p0, 0x0

    .line 20
    return p0

    .line 21
    :pswitch_1
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_1
        :pswitch_1
        :pswitch_1
    .end packed-switch
.end method
