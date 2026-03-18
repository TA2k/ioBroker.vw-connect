.class public abstract Ljp/md;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lmg/b;Lyj/b;Lxh/e;Ljava/lang/String;Lyj/b;Lyj/b;Lyj/b;Lh2/d6;Lxh/e;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v11, p9

    .line 4
    .line 5
    check-cast v11, Ll2/t;

    .line 6
    .line 7
    const v0, 0x6096587b

    .line 8
    .line 9
    .line 10
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p10, v0

    .line 23
    .line 24
    move-object/from16 v2, p1

    .line 25
    .line 26
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    const/16 v4, 0x20

    .line 31
    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    move v3, v4

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    const/16 v3, 0x10

    .line 37
    .line 38
    :goto_1
    or-int/2addr v0, v3

    .line 39
    move-object/from16 v3, p2

    .line 40
    .line 41
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    const/16 v6, 0x100

    .line 46
    .line 47
    if-eqz v5, :cond_2

    .line 48
    .line 49
    move v5, v6

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v5, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v0, v5

    .line 54
    move-object/from16 v5, p3

    .line 55
    .line 56
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    if-eqz v7, :cond_3

    .line 61
    .line 62
    const/16 v7, 0x800

    .line 63
    .line 64
    goto :goto_3

    .line 65
    :cond_3
    const/16 v7, 0x400

    .line 66
    .line 67
    :goto_3
    or-int/2addr v0, v7

    .line 68
    move-object/from16 v7, p4

    .line 69
    .line 70
    invoke-virtual {v11, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v9

    .line 74
    if-eqz v9, :cond_4

    .line 75
    .line 76
    const/16 v9, 0x4000

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_4
    const/16 v9, 0x2000

    .line 80
    .line 81
    :goto_4
    or-int/2addr v0, v9

    .line 82
    move-object/from16 v9, p5

    .line 83
    .line 84
    invoke-virtual {v11, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v12

    .line 88
    if-eqz v12, :cond_5

    .line 89
    .line 90
    const/high16 v12, 0x20000

    .line 91
    .line 92
    goto :goto_5

    .line 93
    :cond_5
    const/high16 v12, 0x10000

    .line 94
    .line 95
    :goto_5
    or-int/2addr v0, v12

    .line 96
    move-object/from16 v12, p6

    .line 97
    .line 98
    invoke-virtual {v11, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v14

    .line 102
    if-eqz v14, :cond_6

    .line 103
    .line 104
    const/high16 v14, 0x100000

    .line 105
    .line 106
    goto :goto_6

    .line 107
    :cond_6
    const/high16 v14, 0x80000

    .line 108
    .line 109
    :goto_6
    or-int/2addr v0, v14

    .line 110
    move-object/from16 v14, p7

    .line 111
    .line 112
    invoke-virtual {v11, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v16

    .line 116
    if-eqz v16, :cond_7

    .line 117
    .line 118
    const/high16 v16, 0x800000

    .line 119
    .line 120
    goto :goto_7

    .line 121
    :cond_7
    const/high16 v16, 0x400000

    .line 122
    .line 123
    :goto_7
    or-int v0, v0, v16

    .line 124
    .line 125
    move-object/from16 v15, p8

    .line 126
    .line 127
    invoke-virtual {v11, v15}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v17

    .line 131
    if-eqz v17, :cond_8

    .line 132
    .line 133
    const/high16 v17, 0x4000000

    .line 134
    .line 135
    goto :goto_8

    .line 136
    :cond_8
    const/high16 v17, 0x2000000

    .line 137
    .line 138
    :goto_8
    or-int v0, v0, v17

    .line 139
    .line 140
    const v17, 0x2492493

    .line 141
    .line 142
    .line 143
    and-int v13, v0, v17

    .line 144
    .line 145
    const v10, 0x2492492

    .line 146
    .line 147
    .line 148
    const/16 v20, 0x1

    .line 149
    .line 150
    const/4 v8, 0x0

    .line 151
    if-eq v13, v10, :cond_9

    .line 152
    .line 153
    move/from16 v10, v20

    .line 154
    .line 155
    goto :goto_9

    .line 156
    :cond_9
    move v10, v8

    .line 157
    :goto_9
    and-int/lit8 v13, v0, 0x1

    .line 158
    .line 159
    invoke-virtual {v11, v13, v10}, Ll2/t;->O(IZ)Z

    .line 160
    .line 161
    .line 162
    move-result v10

    .line 163
    if-eqz v10, :cond_19

    .line 164
    .line 165
    and-int/lit16 v10, v0, 0x380

    .line 166
    .line 167
    if-ne v10, v6, :cond_a

    .line 168
    .line 169
    move/from16 v6, v20

    .line 170
    .line 171
    goto :goto_a

    .line 172
    :cond_a
    move v6, v8

    .line 173
    :goto_a
    and-int/lit8 v10, v0, 0x70

    .line 174
    .line 175
    if-ne v10, v4, :cond_b

    .line 176
    .line 177
    move/from16 v4, v20

    .line 178
    .line 179
    goto :goto_b

    .line 180
    :cond_b
    move v4, v8

    .line 181
    :goto_b
    or-int/2addr v4, v6

    .line 182
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result v6

    .line 186
    or-int/2addr v4, v6

    .line 187
    and-int/lit16 v6, v0, 0x1c00

    .line 188
    .line 189
    const/16 v10, 0x800

    .line 190
    .line 191
    if-ne v6, v10, :cond_c

    .line 192
    .line 193
    move/from16 v6, v20

    .line 194
    .line 195
    goto :goto_c

    .line 196
    :cond_c
    move v6, v8

    .line 197
    :goto_c
    or-int/2addr v4, v6

    .line 198
    const v6, 0xe000

    .line 199
    .line 200
    .line 201
    and-int/2addr v6, v0

    .line 202
    const/16 v10, 0x4000

    .line 203
    .line 204
    if-ne v6, v10, :cond_d

    .line 205
    .line 206
    move/from16 v6, v20

    .line 207
    .line 208
    goto :goto_d

    .line 209
    :cond_d
    move v6, v8

    .line 210
    :goto_d
    or-int/2addr v4, v6

    .line 211
    const/high16 v6, 0x70000

    .line 212
    .line 213
    and-int/2addr v6, v0

    .line 214
    const/high16 v10, 0x20000

    .line 215
    .line 216
    if-ne v6, v10, :cond_e

    .line 217
    .line 218
    move/from16 v6, v20

    .line 219
    .line 220
    goto :goto_e

    .line 221
    :cond_e
    move v6, v8

    .line 222
    :goto_e
    or-int/2addr v4, v6

    .line 223
    const/high16 v6, 0x380000

    .line 224
    .line 225
    and-int/2addr v6, v0

    .line 226
    const/high16 v10, 0x100000

    .line 227
    .line 228
    if-ne v6, v10, :cond_f

    .line 229
    .line 230
    move/from16 v6, v20

    .line 231
    .line 232
    goto :goto_f

    .line 233
    :cond_f
    move v6, v8

    .line 234
    :goto_f
    or-int/2addr v4, v6

    .line 235
    const/high16 v6, 0x1c00000

    .line 236
    .line 237
    and-int/2addr v6, v0

    .line 238
    const/high16 v10, 0x800000

    .line 239
    .line 240
    if-ne v6, v10, :cond_10

    .line 241
    .line 242
    move/from16 v6, v20

    .line 243
    .line 244
    goto :goto_10

    .line 245
    :cond_10
    move v6, v8

    .line 246
    :goto_10
    or-int/2addr v4, v6

    .line 247
    const/high16 v6, 0xe000000

    .line 248
    .line 249
    and-int/2addr v0, v6

    .line 250
    const/high16 v6, 0x4000000

    .line 251
    .line 252
    if-ne v0, v6, :cond_11

    .line 253
    .line 254
    goto :goto_11

    .line 255
    :cond_11
    move/from16 v20, v8

    .line 256
    .line 257
    :goto_11
    or-int v0, v4, v20

    .line 258
    .line 259
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v4

    .line 263
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 264
    .line 265
    if-nez v0, :cond_13

    .line 266
    .line 267
    if-ne v4, v13, :cond_12

    .line 268
    .line 269
    goto :goto_12

    .line 270
    :cond_12
    move v12, v8

    .line 271
    goto :goto_13

    .line 272
    :cond_13
    :goto_12
    new-instance v0, Lh2/b3;

    .line 273
    .line 274
    const/4 v10, 0x2

    .line 275
    move-object v4, v3

    .line 276
    move-object v3, v1

    .line 277
    move-object v1, v4

    .line 278
    move-object v4, v5

    .line 279
    move-object v5, v7

    .line 280
    move-object v6, v9

    .line 281
    move-object v7, v12

    .line 282
    move-object v9, v15

    .line 283
    move v12, v8

    .line 284
    move-object v8, v14

    .line 285
    invoke-direct/range {v0 .. v10}, Lh2/b3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    move-object v4, v0

    .line 292
    :goto_13
    check-cast v4, Lay0/k;

    .line 293
    .line 294
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 295
    .line 296
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v0

    .line 300
    check-cast v0, Ljava/lang/Boolean;

    .line 301
    .line 302
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 303
    .line 304
    .line 305
    move-result v0

    .line 306
    if-eqz v0, :cond_14

    .line 307
    .line 308
    const v0, -0x105bcaaa

    .line 309
    .line 310
    .line 311
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 315
    .line 316
    .line 317
    const/4 v0, 0x0

    .line 318
    goto :goto_14

    .line 319
    :cond_14
    const v0, 0x31054eee

    .line 320
    .line 321
    .line 322
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 323
    .line 324
    .line 325
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 326
    .line 327
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object v0

    .line 331
    check-cast v0, Lhi/a;

    .line 332
    .line 333
    invoke-virtual {v11, v12}, Ll2/t;->q(Z)V

    .line 334
    .line 335
    .line 336
    :goto_14
    new-instance v3, Lnd/e;

    .line 337
    .line 338
    const/16 v1, 0x8

    .line 339
    .line 340
    invoke-direct {v3, v0, v4, v1}, Lnd/e;-><init>(Lhi/a;Lay0/k;I)V

    .line 341
    .line 342
    .line 343
    invoke-static {v11}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    if-eqz v1, :cond_18

    .line 348
    .line 349
    instance-of v0, v1, Landroidx/lifecycle/k;

    .line 350
    .line 351
    if-eqz v0, :cond_15

    .line 352
    .line 353
    move-object v0, v1

    .line 354
    check-cast v0, Landroidx/lifecycle/k;

    .line 355
    .line 356
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    :goto_15
    move-object v4, v0

    .line 361
    goto :goto_16

    .line 362
    :cond_15
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 363
    .line 364
    goto :goto_15

    .line 365
    :goto_16
    const-class v0, Lpg/n;

    .line 366
    .line 367
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 368
    .line 369
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 370
    .line 371
    .line 372
    move-result-object v0

    .line 373
    const/4 v2, 0x0

    .line 374
    move-object v5, v11

    .line 375
    invoke-static/range {v0 .. v5}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 376
    .line 377
    .line 378
    move-result-object v0

    .line 379
    check-cast v0, Lpg/n;

    .line 380
    .line 381
    invoke-static {v5}, Lmg/a;->c(Ll2/o;)Lmg/k;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    iget-object v2, v0, Lpg/n;->q:Lyy0/c2;

    .line 386
    .line 387
    invoke-static {v2, v5}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 388
    .line 389
    .line 390
    move-result-object v2

    .line 391
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v2

    .line 395
    check-cast v2, Llc/q;

    .line 396
    .line 397
    invoke-virtual {v5, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    move-result v3

    .line 401
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v4

    .line 405
    if-nez v3, :cond_16

    .line 406
    .line 407
    if-ne v4, v13, :cond_17

    .line 408
    .line 409
    :cond_16
    new-instance v14, Lo90/f;

    .line 410
    .line 411
    const/16 v20, 0x0

    .line 412
    .line 413
    const/16 v21, 0x7

    .line 414
    .line 415
    const/4 v15, 0x1

    .line 416
    const-class v17, Lpg/n;

    .line 417
    .line 418
    const-string v18, "onUiEvent"

    .line 419
    .line 420
    const-string v19, "onUiEvent(Lcariad/charging/multicharge/kitten/subscription/presentation/confirmation/TariffConfirmationUiEvent;)V"

    .line 421
    .line 422
    move-object/from16 v16, v0

    .line 423
    .line 424
    invoke-direct/range {v14 .. v21}, Lo90/f;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 425
    .line 426
    .line 427
    invoke-virtual {v5, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 428
    .line 429
    .line 430
    move-object v4, v14

    .line 431
    :cond_17
    check-cast v4, Lhy0/g;

    .line 432
    .line 433
    check-cast v4, Lay0/k;

    .line 434
    .line 435
    const/16 v0, 0x8

    .line 436
    .line 437
    invoke-interface {v1, v2, v4, v5, v0}, Lmg/k;->h(Llc/q;Lay0/k;Ll2/o;I)V

    .line 438
    .line 439
    .line 440
    goto :goto_17

    .line 441
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 442
    .line 443
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 444
    .line 445
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    throw v0

    .line 449
    :cond_19
    move-object v5, v11

    .line 450
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 451
    .line 452
    .line 453
    :goto_17
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 454
    .line 455
    .line 456
    move-result-object v12

    .line 457
    if-eqz v12, :cond_1a

    .line 458
    .line 459
    new-instance v0, Lco0/j;

    .line 460
    .line 461
    const/4 v11, 0x7

    .line 462
    move-object/from16 v1, p0

    .line 463
    .line 464
    move-object/from16 v2, p1

    .line 465
    .line 466
    move-object/from16 v3, p2

    .line 467
    .line 468
    move-object/from16 v4, p3

    .line 469
    .line 470
    move-object/from16 v5, p4

    .line 471
    .line 472
    move-object/from16 v6, p5

    .line 473
    .line 474
    move-object/from16 v7, p6

    .line 475
    .line 476
    move-object/from16 v8, p7

    .line 477
    .line 478
    move-object/from16 v9, p8

    .line 479
    .line 480
    move/from16 v10, p10

    .line 481
    .line 482
    invoke-direct/range {v0 .. v11}, Lco0/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llx0/e;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 483
    .line 484
    .line 485
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 486
    .line 487
    :cond_1a
    return-void
.end method

.method public static final b(Ldi0/b;)Z
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "NO_VEHICLE_INFORMATION"

    .line 7
    .line 8
    const-string v1, "UNKNOWN"

    .line 9
    .line 10
    const-string v2, "NO_MOD_1_4_VEHICLES"

    .line 11
    .line 12
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    check-cast v0, Ljava/lang/Iterable;

    .line 21
    .line 22
    instance-of v1, v0, Ljava/util/Collection;

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    move-object v1, v0

    .line 28
    check-cast v1, Ljava/util/Collection;

    .line 29
    .line 30
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_0

    .line 35
    .line 36
    return v2

    .line 37
    :cond_0
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_4

    .line 46
    .line 47
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Ljava/lang/String;

    .line 52
    .line 53
    const-string v3, "type"

    .line 54
    .line 55
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    iget-object v3, p0, Ldi0/b;->c:Ljava/util/List;

    .line 59
    .line 60
    if-eqz v3, :cond_1

    .line 61
    .line 62
    check-cast v3, Ljava/lang/Iterable;

    .line 63
    .line 64
    instance-of v4, v3, Ljava/util/Collection;

    .line 65
    .line 66
    if-eqz v4, :cond_2

    .line 67
    .line 68
    move-object v4, v3

    .line 69
    check-cast v4, Ljava/util/Collection;

    .line 70
    .line 71
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_2

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_2
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    :cond_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    if-eqz v4, :cond_1

    .line 87
    .line 88
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    check-cast v4, Ldi0/a;

    .line 93
    .line 94
    iget-object v4, v4, Ldi0/a;->a:Ljava/lang/String;

    .line 95
    .line 96
    invoke-virtual {v4, v1}, Ljava/lang/String;->contentEquals(Ljava/lang/CharSequence;)Z

    .line 97
    .line 98
    .line 99
    move-result v4

    .line 100
    if-eqz v4, :cond_3

    .line 101
    .line 102
    const/4 p0, 0x1

    .line 103
    return p0

    .line 104
    :cond_4
    return v2
.end method
