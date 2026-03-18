.class public abstract Lx4/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Lx4/d;->h:Lx4/d;

    .line 2
    .line 3
    new-instance v1, Ll2/e0;

    .line 4
    .line 5
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 6
    .line 7
    .line 8
    sput-object v1, Lx4/i;->a:Ll2/e0;

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v8, p3

    .line 4
    .line 5
    move/from16 v9, p5

    .line 6
    .line 7
    move-object/from16 v10, p4

    .line 8
    .line 9
    check-cast v10, Ll2/t;

    .line 10
    .line 11
    const v0, -0x699ff8ef

    .line 12
    .line 13
    .line 14
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v0, v9, 0x6

    .line 18
    .line 19
    if-nez v0, :cond_1

    .line 20
    .line 21
    invoke-virtual {v10, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

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
    or-int/2addr v0, v9

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v0, v9

    .line 33
    :goto_1
    and-int/lit8 v2, p6, 0x2

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    or-int/lit8 v0, v0, 0x30

    .line 38
    .line 39
    :cond_2
    move-object/from16 v3, p1

    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_3
    and-int/lit8 v3, v9, 0x30

    .line 43
    .line 44
    if-nez v3, :cond_2

    .line 45
    .line 46
    move-object/from16 v3, p1

    .line 47
    .line 48
    invoke-virtual {v10, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-eqz v4, :cond_4

    .line 53
    .line 54
    const/16 v4, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_4
    const/16 v4, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr v0, v4

    .line 60
    :goto_3
    and-int/lit8 v4, p6, 0x4

    .line 61
    .line 62
    if-eqz v4, :cond_6

    .line 63
    .line 64
    or-int/lit16 v0, v0, 0x180

    .line 65
    .line 66
    :cond_5
    move-object/from16 v5, p2

    .line 67
    .line 68
    goto :goto_5

    .line 69
    :cond_6
    and-int/lit16 v5, v9, 0x180

    .line 70
    .line 71
    if-nez v5, :cond_5

    .line 72
    .line 73
    move-object/from16 v5, p2

    .line 74
    .line 75
    invoke-virtual {v10, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v6

    .line 79
    if-eqz v6, :cond_7

    .line 80
    .line 81
    const/16 v6, 0x100

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_7
    const/16 v6, 0x80

    .line 85
    .line 86
    :goto_4
    or-int/2addr v0, v6

    .line 87
    :goto_5
    and-int/lit16 v6, v9, 0xc00

    .line 88
    .line 89
    if-nez v6, :cond_9

    .line 90
    .line 91
    invoke-virtual {v10, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-eqz v6, :cond_8

    .line 96
    .line 97
    const/16 v6, 0x800

    .line 98
    .line 99
    goto :goto_6

    .line 100
    :cond_8
    const/16 v6, 0x400

    .line 101
    .line 102
    :goto_6
    or-int/2addr v0, v6

    .line 103
    :cond_9
    move v14, v0

    .line 104
    and-int/lit16 v0, v14, 0x493

    .line 105
    .line 106
    const/16 v6, 0x492

    .line 107
    .line 108
    const/4 v15, 0x0

    .line 109
    if-eq v0, v6, :cond_a

    .line 110
    .line 111
    const/4 v0, 0x1

    .line 112
    goto :goto_7

    .line 113
    :cond_a
    move v0, v15

    .line 114
    :goto_7
    and-int/lit8 v6, v14, 0x1

    .line 115
    .line 116
    invoke-virtual {v10, v6, v0}, Ll2/t;->O(IZ)Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_23

    .line 121
    .line 122
    if-eqz v2, :cond_b

    .line 123
    .line 124
    const/16 v18, 0x0

    .line 125
    .line 126
    goto :goto_8

    .line 127
    :cond_b
    move-object/from16 v18, v3

    .line 128
    .line 129
    :goto_8
    if-eqz v4, :cond_c

    .line 130
    .line 131
    new-instance v2, Lx4/w;

    .line 132
    .line 133
    const/16 v3, 0xf

    .line 134
    .line 135
    invoke-direct {v2, v3, v15}, Lx4/w;-><init>(IZ)V

    .line 136
    .line 137
    .line 138
    move-object/from16 v19, v2

    .line 139
    .line 140
    goto :goto_9

    .line 141
    :cond_c
    move-object/from16 v19, v5

    .line 142
    .line 143
    :goto_9
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->f:Ll2/u2;

    .line 144
    .line 145
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    move-object v4, v2

    .line 150
    check-cast v4, Landroid/view/View;

    .line 151
    .line 152
    sget-object v2, Lw3/h1;->h:Ll2/u2;

    .line 153
    .line 154
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    move-object v5, v2

    .line 159
    check-cast v5, Lt4/c;

    .line 160
    .line 161
    sget-object v2, Lx4/i;->a:Ll2/e0;

    .line 162
    .line 163
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v2

    .line 167
    move-object/from16 v20, v2

    .line 168
    .line 169
    check-cast v20, Ljava/lang/String;

    .line 170
    .line 171
    sget-object v2, Lw3/h1;->n:Ll2/u2;

    .line 172
    .line 173
    invoke-virtual {v10, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v2

    .line 177
    move-object/from16 v21, v2

    .line 178
    .line 179
    check-cast v21, Lt4/m;

    .line 180
    .line 181
    invoke-static {v10}, Ll2/b;->r(Ll2/o;)Ll2/r;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    invoke-static {v8, v10}, Ll2/b;->s(Ljava/lang/Object;Ll2/o;)Ll2/b1;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    new-array v6, v15, [Ljava/lang/Object;

    .line 190
    .line 191
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    sget-object v15, Ll2/n;->a:Ll2/x0;

    .line 196
    .line 197
    if-ne v0, v15, :cond_d

    .line 198
    .line 199
    sget-object v0, Lx4/d;->i:Lx4/d;

    .line 200
    .line 201
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    :cond_d
    check-cast v0, Lay0/a;

    .line 205
    .line 206
    const/16 v7, 0x30

    .line 207
    .line 208
    invoke-static {v6, v0, v10, v7}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v0

    .line 212
    move-object v7, v0

    .line 213
    check-cast v7, Ljava/util/UUID;

    .line 214
    .line 215
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    if-ne v0, v15, :cond_e

    .line 220
    .line 221
    new-instance v0, Lx4/t;

    .line 222
    .line 223
    move-object v6, v1

    .line 224
    move-object v13, v2

    .line 225
    move-object v12, v3

    .line 226
    move-object/from16 v1, v18

    .line 227
    .line 228
    move-object/from16 v2, v19

    .line 229
    .line 230
    move-object/from16 v3, v20

    .line 231
    .line 232
    const/4 v11, 0x1

    .line 233
    invoke-direct/range {v0 .. v7}, Lx4/t;-><init>(Lay0/a;Lx4/w;Ljava/lang/String;Landroid/view/View;Lt4/c;Lx4/v;Ljava/util/UUID;)V

    .line 234
    .line 235
    .line 236
    move-object v1, v6

    .line 237
    new-instance v2, Lkn/i0;

    .line 238
    .line 239
    const/4 v4, 0x7

    .line 240
    invoke-direct {v2, v4, v0, v12}, Lkn/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    new-instance v4, Lt2/b;

    .line 244
    .line 245
    const v5, -0x11bbdae4

    .line 246
    .line 247
    .line 248
    invoke-direct {v4, v2, v11, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 249
    .line 250
    .line 251
    invoke-virtual {v0, v13, v4}, Lx4/t;->j(Ll2/x;Lay0/n;)V

    .line 252
    .line 253
    .line 254
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    goto :goto_a

    .line 258
    :cond_e
    move-object/from16 v3, v20

    .line 259
    .line 260
    const/4 v11, 0x1

    .line 261
    :goto_a
    check-cast v0, Lx4/t;

    .line 262
    .line 263
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    move-result v2

    .line 267
    and-int/lit8 v4, v14, 0x70

    .line 268
    .line 269
    const/16 v5, 0x20

    .line 270
    .line 271
    if-ne v4, v5, :cond_f

    .line 272
    .line 273
    move v7, v11

    .line 274
    goto :goto_b

    .line 275
    :cond_f
    const/4 v7, 0x0

    .line 276
    :goto_b
    or-int/2addr v2, v7

    .line 277
    and-int/lit16 v5, v14, 0x380

    .line 278
    .line 279
    const/16 v6, 0x100

    .line 280
    .line 281
    if-ne v5, v6, :cond_10

    .line 282
    .line 283
    move v7, v11

    .line 284
    goto :goto_c

    .line 285
    :cond_10
    const/4 v7, 0x0

    .line 286
    :goto_c
    or-int/2addr v2, v7

    .line 287
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    move-result v6

    .line 291
    or-int/2addr v2, v6

    .line 292
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Enum;->ordinal()I

    .line 293
    .line 294
    .line 295
    move-result v6

    .line 296
    invoke-virtual {v10, v6}, Ll2/t;->e(I)Z

    .line 297
    .line 298
    .line 299
    move-result v6

    .line 300
    or-int/2addr v2, v6

    .line 301
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v6

    .line 305
    if-nez v2, :cond_11

    .line 306
    .line 307
    if-ne v6, v15, :cond_12

    .line 308
    .line 309
    :cond_11
    new-instance v16, Lnn/m;

    .line 310
    .line 311
    const/16 v22, 0x2

    .line 312
    .line 313
    move-object/from16 v17, v0

    .line 314
    .line 315
    move-object/from16 v20, v3

    .line 316
    .line 317
    invoke-direct/range {v16 .. v22}, Lnn/m;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 318
    .line 319
    .line 320
    move-object/from16 v6, v16

    .line 321
    .line 322
    invoke-virtual {v10, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 323
    .line 324
    .line 325
    :cond_12
    check-cast v6, Lay0/k;

    .line 326
    .line 327
    invoke-static {v0, v6, v10}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    move-result v2

    .line 334
    const/16 v6, 0x20

    .line 335
    .line 336
    if-ne v4, v6, :cond_13

    .line 337
    .line 338
    move v7, v11

    .line 339
    goto :goto_d

    .line 340
    :cond_13
    const/4 v7, 0x0

    .line 341
    :goto_d
    or-int/2addr v2, v7

    .line 342
    const/16 v6, 0x100

    .line 343
    .line 344
    if-ne v5, v6, :cond_14

    .line 345
    .line 346
    move v7, v11

    .line 347
    goto :goto_e

    .line 348
    :cond_14
    const/4 v7, 0x0

    .line 349
    :goto_e
    or-int/2addr v2, v7

    .line 350
    invoke-virtual {v10, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 351
    .line 352
    .line 353
    move-result v4

    .line 354
    or-int/2addr v2, v4

    .line 355
    invoke-virtual/range {v21 .. v21}, Ljava/lang/Enum;->ordinal()I

    .line 356
    .line 357
    .line 358
    move-result v4

    .line 359
    invoke-virtual {v10, v4}, Ll2/t;->e(I)Z

    .line 360
    .line 361
    .line 362
    move-result v4

    .line 363
    or-int/2addr v2, v4

    .line 364
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v4

    .line 368
    if-nez v2, :cond_16

    .line 369
    .line 370
    if-ne v4, v15, :cond_15

    .line 371
    .line 372
    goto :goto_f

    .line 373
    :cond_15
    move-object/from16 v2, v21

    .line 374
    .line 375
    goto :goto_10

    .line 376
    :cond_16
    :goto_f
    new-instance v16, Lkn/j;

    .line 377
    .line 378
    const/16 v22, 0x1

    .line 379
    .line 380
    move-object/from16 v17, v0

    .line 381
    .line 382
    move-object/from16 v20, v3

    .line 383
    .line 384
    invoke-direct/range {v16 .. v22}, Lkn/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 385
    .line 386
    .line 387
    move-object/from16 v4, v16

    .line 388
    .line 389
    move-object/from16 v2, v21

    .line 390
    .line 391
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 392
    .line 393
    .line 394
    :goto_10
    check-cast v4, Lay0/a;

    .line 395
    .line 396
    invoke-static {v4, v10}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 400
    .line 401
    .line 402
    move-result v3

    .line 403
    and-int/lit8 v4, v14, 0xe

    .line 404
    .line 405
    const/4 v5, 0x4

    .line 406
    if-ne v4, v5, :cond_17

    .line 407
    .line 408
    move/from16 v23, v11

    .line 409
    .line 410
    goto :goto_11

    .line 411
    :cond_17
    const/16 v23, 0x0

    .line 412
    .line 413
    :goto_11
    or-int v3, v3, v23

    .line 414
    .line 415
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v4

    .line 419
    if-nez v3, :cond_18

    .line 420
    .line 421
    if-ne v4, v15, :cond_19

    .line 422
    .line 423
    :cond_18
    new-instance v4, Lb1/e;

    .line 424
    .line 425
    const/16 v3, 0x18

    .line 426
    .line 427
    invoke-direct {v4, v3, v0, v1}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 428
    .line 429
    .line 430
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    :cond_19
    check-cast v4, Lay0/k;

    .line 434
    .line 435
    invoke-static {v1, v4, v10}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 439
    .line 440
    .line 441
    move-result v3

    .line 442
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 443
    .line 444
    .line 445
    move-result-object v4

    .line 446
    if-nez v3, :cond_1a

    .line 447
    .line 448
    if-ne v4, v15, :cond_1b

    .line 449
    .line 450
    :cond_1a
    new-instance v4, Lwp0/c;

    .line 451
    .line 452
    const/4 v3, 0x4

    .line 453
    const/4 v5, 0x0

    .line 454
    invoke-direct {v4, v0, v5, v3}, Lwp0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 455
    .line 456
    .line 457
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    :cond_1b
    check-cast v4, Lay0/n;

    .line 461
    .line 462
    invoke-static {v4, v0, v10}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 463
    .line 464
    .line 465
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 466
    .line 467
    .line 468
    move-result v3

    .line 469
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 470
    .line 471
    .line 472
    move-result-object v4

    .line 473
    if-nez v3, :cond_1c

    .line 474
    .line 475
    if-ne v4, v15, :cond_1d

    .line 476
    .line 477
    :cond_1c
    new-instance v4, Lx4/h;

    .line 478
    .line 479
    const/4 v3, 0x0

    .line 480
    invoke-direct {v4, v0, v3}, Lx4/h;-><init>(Lx4/t;I)V

    .line 481
    .line 482
    .line 483
    invoke-virtual {v10, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 484
    .line 485
    .line 486
    :cond_1d
    check-cast v4, Lay0/k;

    .line 487
    .line 488
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 489
    .line 490
    invoke-static {v3, v4}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 491
    .line 492
    .line 493
    move-result-object v3

    .line 494
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 495
    .line 496
    .line 497
    move-result v4

    .line 498
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 499
    .line 500
    .line 501
    move-result v5

    .line 502
    invoke-virtual {v10, v5}, Ll2/t;->e(I)Z

    .line 503
    .line 504
    .line 505
    move-result v5

    .line 506
    or-int/2addr v4, v5

    .line 507
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 508
    .line 509
    .line 510
    move-result-object v5

    .line 511
    if-nez v4, :cond_1e

    .line 512
    .line 513
    if-ne v5, v15, :cond_1f

    .line 514
    .line 515
    :cond_1e
    new-instance v5, Lt1/l1;

    .line 516
    .line 517
    const/4 v4, 0x1

    .line 518
    invoke-direct {v5, v4, v0, v2}, Lt1/l1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 519
    .line 520
    .line 521
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 522
    .line 523
    .line 524
    :cond_1f
    check-cast v5, Lt3/q0;

    .line 525
    .line 526
    iget-wide v6, v10, Ll2/t;->T:J

    .line 527
    .line 528
    invoke-static {v6, v7}, Ljava/lang/Long;->hashCode(J)I

    .line 529
    .line 530
    .line 531
    move-result v0

    .line 532
    invoke-virtual {v10}, Ll2/t;->m()Ll2/p1;

    .line 533
    .line 534
    .line 535
    move-result-object v2

    .line 536
    invoke-static {v10, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 537
    .line 538
    .line 539
    move-result-object v3

    .line 540
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 541
    .line 542
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 543
    .line 544
    .line 545
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 546
    .line 547
    invoke-virtual {v10}, Ll2/t;->c0()V

    .line 548
    .line 549
    .line 550
    iget-boolean v6, v10, Ll2/t;->S:Z

    .line 551
    .line 552
    if-eqz v6, :cond_20

    .line 553
    .line 554
    invoke-virtual {v10, v4}, Ll2/t;->l(Lay0/a;)V

    .line 555
    .line 556
    .line 557
    goto :goto_12

    .line 558
    :cond_20
    invoke-virtual {v10}, Ll2/t;->m0()V

    .line 559
    .line 560
    .line 561
    :goto_12
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 562
    .line 563
    invoke-static {v4, v5, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 564
    .line 565
    .line 566
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 567
    .line 568
    invoke-static {v4, v2, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 569
    .line 570
    .line 571
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 572
    .line 573
    iget-boolean v4, v10, Ll2/t;->S:Z

    .line 574
    .line 575
    if-nez v4, :cond_21

    .line 576
    .line 577
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 578
    .line 579
    .line 580
    move-result-object v4

    .line 581
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 582
    .line 583
    .line 584
    move-result-object v5

    .line 585
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 586
    .line 587
    .line 588
    move-result v4

    .line 589
    if-nez v4, :cond_22

    .line 590
    .line 591
    :cond_21
    invoke-static {v0, v10, v0, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 592
    .line 593
    .line 594
    :cond_22
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 595
    .line 596
    invoke-static {v0, v3, v10}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 597
    .line 598
    .line 599
    invoke-virtual {v10, v11}, Ll2/t;->q(Z)V

    .line 600
    .line 601
    .line 602
    move-object/from16 v2, v18

    .line 603
    .line 604
    move-object/from16 v3, v19

    .line 605
    .line 606
    goto :goto_13

    .line 607
    :cond_23
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 608
    .line 609
    .line 610
    move-object v2, v3

    .line 611
    move-object v3, v5

    .line 612
    :goto_13
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 613
    .line 614
    .line 615
    move-result-object v10

    .line 616
    if-eqz v10, :cond_24

    .line 617
    .line 618
    new-instance v0, Lvv/a;

    .line 619
    .line 620
    const/4 v7, 0x1

    .line 621
    move/from16 v6, p6

    .line 622
    .line 623
    move-object v4, v8

    .line 624
    move v5, v9

    .line 625
    invoke-direct/range {v0 .. v7}, Lvv/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lay0/o;III)V

    .line 626
    .line 627
    .line 628
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 629
    .line 630
    :cond_24
    return-void
.end method

.method public static final b(Lx2/j;JLay0/a;Lx4/w;Lt2/b;Ll2/o;I)V
    .locals 13

    .line 1
    move-object/from16 v4, p6

    .line 2
    .line 3
    check-cast v4, Ll2/t;

    .line 4
    .line 5
    const v0, 0x43b737e

    .line 6
    .line 7
    .line 8
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    or-int/lit8 v0, p7, 0x30

    .line 12
    .line 13
    move-object/from16 v9, p3

    .line 14
    .line 15
    invoke-virtual {v4, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    const/16 v1, 0x100

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/16 v1, 0x80

    .line 25
    .line 26
    :goto_0
    or-int/2addr v0, v1

    .line 27
    move-object/from16 v10, p4

    .line 28
    .line 29
    invoke-virtual {v4, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    if-eqz v1, :cond_1

    .line 34
    .line 35
    const/16 v1, 0x800

    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    const/16 v1, 0x400

    .line 39
    .line 40
    :goto_1
    or-int/2addr v0, v1

    .line 41
    and-int/lit16 v1, v0, 0x2493

    .line 42
    .line 43
    const/16 v2, 0x2492

    .line 44
    .line 45
    const/4 v3, 0x0

    .line 46
    if-eq v1, v2, :cond_2

    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v1, v3

    .line 51
    :goto_2
    and-int/lit8 v2, v0, 0x1

    .line 52
    .line 53
    invoke-virtual {v4, v2, v1}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    if-eqz v1, :cond_4

    .line 58
    .line 59
    int-to-long p1, v3

    .line 60
    const/16 v1, 0x20

    .line 61
    .line 62
    shl-long v1, p1, v1

    .line 63
    .line 64
    const-wide v5, 0xffffffffL

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    and-long/2addr p1, v5

    .line 70
    or-long/2addr p1, v1

    .line 71
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 76
    .line 77
    if-ne v1, v2, :cond_3

    .line 78
    .line 79
    new-instance v1, Lx4/a;

    .line 80
    .line 81
    invoke-direct {v1, p0, p1, p2}, Lx4/a;-><init>(Lx2/j;J)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v4, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    :cond_3
    check-cast v1, Lx4/a;

    .line 88
    .line 89
    shr-int/lit8 v0, v0, 0x3

    .line 90
    .line 91
    and-int/lit16 v5, v0, 0x1ff0

    .line 92
    .line 93
    const/4 v6, 0x0

    .line 94
    move-object/from16 v3, p5

    .line 95
    .line 96
    move-object v0, v1

    .line 97
    move-object v1, v9

    .line 98
    move-object v2, v10

    .line 99
    invoke-static/range {v0 .. v6}, Lx4/i;->a(Lx4/v;Lay0/a;Lx4/w;Lt2/b;Ll2/o;II)V

    .line 100
    .line 101
    .line 102
    :goto_3
    move-wide v7, p1

    .line 103
    goto :goto_4

    .line 104
    :cond_4
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 105
    .line 106
    .line 107
    goto :goto_3

    .line 108
    :goto_4
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    if-eqz p1, :cond_5

    .line 113
    .line 114
    new-instance v5, Lx4/f;

    .line 115
    .line 116
    move-object v6, p0

    .line 117
    move-object/from16 v9, p3

    .line 118
    .line 119
    move-object/from16 v10, p4

    .line 120
    .line 121
    move-object/from16 v11, p5

    .line 122
    .line 123
    move/from16 v12, p7

    .line 124
    .line 125
    invoke-direct/range {v5 .. v12}, Lx4/f;-><init>(Lx2/j;JLay0/a;Lx4/w;Lt2/b;I)V

    .line 126
    .line 127
    .line 128
    iput-object v5, p1, Ll2/u1;->d:Lay0/n;

    .line 129
    .line 130
    :cond_5
    return-void
.end method

.method public static final c(Landroid/view/View;)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    instance-of v0, p0, Landroid/view/WindowManager$LayoutParams;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    check-cast p0, Landroid/view/WindowManager$LayoutParams;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    :goto_0
    const/4 v0, 0x0

    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    iget p0, p0, Landroid/view/WindowManager$LayoutParams;->flags:I

    .line 21
    .line 22
    and-int/lit16 p0, p0, 0x2000

    .line 23
    .line 24
    if-eqz p0, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_1
    return v0
.end method
