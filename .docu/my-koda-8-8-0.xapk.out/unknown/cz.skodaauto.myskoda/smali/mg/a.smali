.class public abstract Lmg/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt2/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, La71/c;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, La71/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    new-instance v1, Lt2/b;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    const v3, 0x2d731652

    .line 11
    .line 12
    .line 13
    invoke-direct {v1, v0, v2, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 14
    .line 15
    .line 16
    sput-object v1, Lmg/a;->a:Lt2/b;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Ljava/lang/String;Lay0/k;Ll2/o;I)V
    .locals 28

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    const-string v1, "onSuccess"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v1, p2

    .line 11
    .line 12
    check-cast v1, Ll2/t;

    .line 13
    .line 14
    const v2, 0x412e45b4

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    const/4 v2, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v2, 0x2

    .line 29
    :goto_0
    or-int v2, p3, v2

    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    const/16 v6, 0x20

    .line 36
    .line 37
    if-eqz v5, :cond_1

    .line 38
    .line 39
    move v5, v6

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/16 v5, 0x10

    .line 42
    .line 43
    :goto_1
    or-int/2addr v2, v5

    .line 44
    and-int/lit8 v5, v2, 0x13

    .line 45
    .line 46
    const/16 v7, 0x12

    .line 47
    .line 48
    const/4 v9, 0x0

    .line 49
    if-eq v5, v7, :cond_2

    .line 50
    .line 51
    const/4 v5, 0x1

    .line 52
    goto :goto_2

    .line 53
    :cond_2
    move v5, v9

    .line 54
    :goto_2
    and-int/lit8 v7, v2, 0x1

    .line 55
    .line 56
    invoke-virtual {v1, v7, v5}, Ll2/t;->O(IZ)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_21

    .line 61
    .line 62
    const-string v5, "SubscribeFlowScreen"

    .line 63
    .line 64
    invoke-static {v5, v1}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    new-array v7, v9, [Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v10

    .line 74
    sget-object v11, Ll2/n;->a:Ll2/x0;

    .line 75
    .line 76
    if-ne v10, v11, :cond_3

    .line 77
    .line 78
    new-instance v10, Ll31/b;

    .line 79
    .line 80
    const/16 v12, 0x11

    .line 81
    .line 82
    invoke-direct {v10, v12}, Ll31/b;-><init>(I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :cond_3
    check-cast v10, Lay0/a;

    .line 89
    .line 90
    const/16 v12, 0x30

    .line 91
    .line 92
    invoke-static {v7, v10, v1, v12}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    check-cast v7, Ll2/b1;

    .line 97
    .line 98
    new-array v10, v9, [Ljava/lang/Object;

    .line 99
    .line 100
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object v13

    .line 104
    if-ne v13, v11, :cond_4

    .line 105
    .line 106
    new-instance v13, Ll31/b;

    .line 107
    .line 108
    const/16 v14, 0x12

    .line 109
    .line 110
    invoke-direct {v13, v14}, Ll31/b;-><init>(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_4
    check-cast v13, Lay0/a;

    .line 117
    .line 118
    invoke-static {v10, v13, v1, v12}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v10

    .line 122
    check-cast v10, Ll2/b1;

    .line 123
    .line 124
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v12

    .line 128
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v13

    .line 132
    if-nez v12, :cond_5

    .line 133
    .line 134
    if-ne v13, v11, :cond_6

    .line 135
    .line 136
    :cond_5
    new-instance v13, Leh/c;

    .line 137
    .line 138
    const/16 v12, 0xf

    .line 139
    .line 140
    invoke-direct {v13, v7, v12}, Leh/c;-><init>(Ll2/b1;I)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v1, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    :cond_6
    check-cast v13, Lay0/n;

    .line 147
    .line 148
    invoke-virtual {v5, v13}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 149
    .line 150
    .line 151
    move-result-object v12

    .line 152
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v13

    .line 156
    if-ne v13, v11, :cond_7

    .line 157
    .line 158
    new-instance v13, Lm40/e;

    .line 159
    .line 160
    const/16 v14, 0x1c

    .line 161
    .line 162
    invoke-direct {v13, v14}, Lm40/e;-><init>(I)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v1, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    :cond_7
    check-cast v13, Lay0/k;

    .line 169
    .line 170
    invoke-virtual {v5, v13}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 171
    .line 172
    .line 173
    move-result-object v13

    .line 174
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v14

    .line 178
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v15

    .line 182
    if-nez v14, :cond_8

    .line 183
    .line 184
    if-ne v15, v11, :cond_9

    .line 185
    .line 186
    :cond_8
    new-instance v15, Leh/c;

    .line 187
    .line 188
    const/16 v14, 0x10

    .line 189
    .line 190
    invoke-direct {v15, v7, v14}, Leh/c;-><init>(Ll2/b1;I)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v1, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    :cond_9
    check-cast v15, Lay0/n;

    .line 197
    .line 198
    invoke-virtual {v5, v15}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 199
    .line 200
    .line 201
    move-result-object v14

    .line 202
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v15

    .line 206
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v8

    .line 210
    if-nez v15, :cond_a

    .line 211
    .line 212
    if-ne v8, v11, :cond_b

    .line 213
    .line 214
    :cond_a
    new-instance v8, Leh/c;

    .line 215
    .line 216
    const/16 v15, 0x11

    .line 217
    .line 218
    invoke-direct {v8, v7, v15}, Leh/c;-><init>(Ll2/b1;I)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v1, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    :cond_b
    check-cast v8, Lay0/n;

    .line 225
    .line 226
    invoke-virtual {v5, v8}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 227
    .line 228
    .line 229
    move-result-object v8

    .line 230
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v15

    .line 234
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v9

    .line 238
    if-nez v15, :cond_c

    .line 239
    .line 240
    if-ne v9, v11, :cond_d

    .line 241
    .line 242
    :cond_c
    new-instance v9, Leh/c;

    .line 243
    .line 244
    const/16 v15, 0x12

    .line 245
    .line 246
    invoke-direct {v9, v7, v15}, Leh/c;-><init>(Ll2/b1;I)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v1, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    :cond_d
    check-cast v9, Lay0/n;

    .line 253
    .line 254
    invoke-virtual {v5, v9}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 255
    .line 256
    .line 257
    move-result-object v9

    .line 258
    invoke-virtual {v1, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v15

    .line 262
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v4

    .line 266
    if-nez v15, :cond_e

    .line 267
    .line 268
    if-ne v4, v11, :cond_f

    .line 269
    .line 270
    :cond_e
    new-instance v4, Leh/c;

    .line 271
    .line 272
    const/16 v15, 0x13

    .line 273
    .line 274
    invoke-direct {v4, v10, v15}, Leh/c;-><init>(Ll2/b1;I)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    :cond_f
    check-cast v4, Lay0/n;

    .line 281
    .line 282
    invoke-virtual {v5, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 283
    .line 284
    .line 285
    move-result-object v4

    .line 286
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 287
    .line 288
    .line 289
    move-result v15

    .line 290
    move/from16 v18, v2

    .line 291
    .line 292
    and-int/lit8 v2, v18, 0x70

    .line 293
    .line 294
    if-ne v2, v6, :cond_10

    .line 295
    .line 296
    const/4 v2, 0x1

    .line 297
    goto :goto_3

    .line 298
    :cond_10
    const/4 v2, 0x0

    .line 299
    :goto_3
    or-int/2addr v2, v15

    .line 300
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object v6

    .line 304
    if-nez v2, :cond_11

    .line 305
    .line 306
    if-ne v6, v11, :cond_12

    .line 307
    .line 308
    :cond_11
    new-instance v6, Lmg/d;

    .line 309
    .line 310
    const/4 v2, 0x0

    .line 311
    invoke-direct {v6, v0, v7, v2}, Lmg/d;-><init>(Lay0/k;Ll2/b1;I)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v1, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    :cond_12
    check-cast v6, Lay0/k;

    .line 318
    .line 319
    invoke-virtual {v5, v6}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 320
    .line 321
    .line 322
    move-result-object v15

    .line 323
    invoke-static {v1}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    invoke-interface {v2, v1}, Lzb/j;->u(Ll2/o;)J

    .line 328
    .line 329
    .line 330
    move-result-wide v2

    .line 331
    new-instance v6, Lh2/d6;

    .line 332
    .line 333
    const/4 v0, 0x4

    .line 334
    invoke-direct {v6, v5, v2, v3, v0}, Lh2/d6;-><init>(Ljava/lang/Object;JI)V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    if-ne v0, v11, :cond_13

    .line 342
    .line 343
    new-instance v0, Ll20/f;

    .line 344
    .line 345
    const/16 v2, 0xf

    .line 346
    .line 347
    invoke-direct {v0, v2}, Ll20/f;-><init>(I)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    :cond_13
    check-cast v0, Lay0/n;

    .line 354
    .line 355
    invoke-virtual {v5, v0}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 360
    .line 361
    .line 362
    move-result-object v2

    .line 363
    if-ne v2, v11, :cond_14

    .line 364
    .line 365
    new-instance v2, Ll20/f;

    .line 366
    .line 367
    const/16 v3, 0x10

    .line 368
    .line 369
    invoke-direct {v2, v3}, Ll20/f;-><init>(I)V

    .line 370
    .line 371
    .line 372
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    :cond_14
    check-cast v2, Lay0/n;

    .line 376
    .line 377
    move-object v3, v2

    .line 378
    new-instance v2, Ly1/i;

    .line 379
    .line 380
    move-object/from16 v19, v3

    .line 381
    .line 382
    const/16 v3, 0x11

    .line 383
    .line 384
    invoke-direct {v2, v5, v3}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 385
    .line 386
    .line 387
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v3

    .line 391
    if-ne v3, v11, :cond_15

    .line 392
    .line 393
    new-instance v3, Lmg/i;

    .line 394
    .line 395
    move-object/from16 v20, v10

    .line 396
    .line 397
    const/4 v10, 0x0

    .line 398
    invoke-direct {v3, v10}, Lmg/i;-><init>(I)V

    .line 399
    .line 400
    .line 401
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 402
    .line 403
    .line 404
    goto :goto_4

    .line 405
    :cond_15
    move-object/from16 v20, v10

    .line 406
    .line 407
    :goto_4
    check-cast v3, Lay0/k;

    .line 408
    .line 409
    invoke-virtual {v5, v3}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 410
    .line 411
    .line 412
    move-result-object v3

    .line 413
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object v10

    .line 417
    if-ne v10, v11, :cond_16

    .line 418
    .line 419
    new-instance v10, Lmg/i;

    .line 420
    .line 421
    move-object/from16 v21, v3

    .line 422
    .line 423
    const/16 v3, 0x9

    .line 424
    .line 425
    invoke-direct {v10, v3}, Lmg/i;-><init>(I)V

    .line 426
    .line 427
    .line 428
    invoke-virtual {v1, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    goto :goto_5

    .line 432
    :cond_16
    move-object/from16 v21, v3

    .line 433
    .line 434
    :goto_5
    check-cast v10, Lay0/k;

    .line 435
    .line 436
    invoke-virtual {v5, v10}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 437
    .line 438
    .line 439
    move-result-object v3

    .line 440
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 441
    .line 442
    .line 443
    move-result-object v10

    .line 444
    if-ne v10, v11, :cond_17

    .line 445
    .line 446
    new-instance v10, Lmg/i;

    .line 447
    .line 448
    move-object/from16 v22, v3

    .line 449
    .line 450
    const/16 v3, 0xa

    .line 451
    .line 452
    invoke-direct {v10, v3}, Lmg/i;-><init>(I)V

    .line 453
    .line 454
    .line 455
    invoke-virtual {v1, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 456
    .line 457
    .line 458
    goto :goto_6

    .line 459
    :cond_17
    move-object/from16 v22, v3

    .line 460
    .line 461
    :goto_6
    check-cast v10, Lay0/k;

    .line 462
    .line 463
    invoke-virtual {v5, v10}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 464
    .line 465
    .line 466
    move-result-object v3

    .line 467
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 468
    .line 469
    .line 470
    move-result v10

    .line 471
    move/from16 v23, v10

    .line 472
    .line 473
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v10

    .line 477
    if-nez v23, :cond_19

    .line 478
    .line 479
    if-ne v10, v11, :cond_18

    .line 480
    .line 481
    goto :goto_7

    .line 482
    :cond_18
    move-object/from16 v23, v3

    .line 483
    .line 484
    goto :goto_8

    .line 485
    :cond_19
    :goto_7
    new-instance v10, Leh/c;

    .line 486
    .line 487
    move-object/from16 v23, v3

    .line 488
    .line 489
    const/16 v3, 0x14

    .line 490
    .line 491
    invoke-direct {v10, v7, v3}, Leh/c;-><init>(Ll2/b1;I)V

    .line 492
    .line 493
    .line 494
    invoke-virtual {v1, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 495
    .line 496
    .line 497
    :goto_8
    check-cast v10, Lay0/n;

    .line 498
    .line 499
    invoke-virtual {v5, v10}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 500
    .line 501
    .line 502
    move-result-object v10

    .line 503
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 504
    .line 505
    .line 506
    move-result v3

    .line 507
    move/from16 v24, v3

    .line 508
    .line 509
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    move-result-object v3

    .line 513
    if-nez v24, :cond_1b

    .line 514
    .line 515
    if-ne v3, v11, :cond_1a

    .line 516
    .line 517
    goto :goto_9

    .line 518
    :cond_1a
    move-object/from16 v24, v4

    .line 519
    .line 520
    goto :goto_a

    .line 521
    :cond_1b
    :goto_9
    new-instance v3, Leh/c;

    .line 522
    .line 523
    move-object/from16 v24, v4

    .line 524
    .line 525
    const/16 v4, 0x15

    .line 526
    .line 527
    invoke-direct {v3, v7, v4}, Leh/c;-><init>(Ll2/b1;I)V

    .line 528
    .line 529
    .line 530
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 531
    .line 532
    .line 533
    :goto_a
    check-cast v3, Lay0/n;

    .line 534
    .line 535
    invoke-virtual {v5, v3}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 536
    .line 537
    .line 538
    move-result-object v3

    .line 539
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 540
    .line 541
    .line 542
    move-result v4

    .line 543
    move/from16 v25, v4

    .line 544
    .line 545
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    move-result-object v4

    .line 549
    if-nez v25, :cond_1d

    .line 550
    .line 551
    if-ne v4, v11, :cond_1c

    .line 552
    .line 553
    goto :goto_b

    .line 554
    :cond_1c
    move-object/from16 v25, v11

    .line 555
    .line 556
    goto :goto_c

    .line 557
    :cond_1d
    :goto_b
    new-instance v4, Leh/c;

    .line 558
    .line 559
    move-object/from16 v25, v11

    .line 560
    .line 561
    const/16 v11, 0x16

    .line 562
    .line 563
    invoke-direct {v4, v7, v11}, Leh/c;-><init>(Ll2/b1;I)V

    .line 564
    .line 565
    .line 566
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 567
    .line 568
    .line 569
    :goto_c
    check-cast v4, Lay0/n;

    .line 570
    .line 571
    invoke-virtual {v5, v4}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 572
    .line 573
    .line 574
    move-result-object v4

    .line 575
    invoke-virtual {v5}, Lzb/v0;->b()Lz9/y;

    .line 576
    .line 577
    .line 578
    move-result-object v26

    .line 579
    and-int/lit8 v5, v18, 0xe

    .line 580
    .line 581
    const/4 v11, 0x4

    .line 582
    if-ne v5, v11, :cond_1e

    .line 583
    .line 584
    const/16 v16, 0x1

    .line 585
    .line 586
    goto :goto_d

    .line 587
    :cond_1e
    const/16 v16, 0x0

    .line 588
    .line 589
    :goto_d
    invoke-virtual {v1, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 590
    .line 591
    .line 592
    move-result v5

    .line 593
    or-int v5, v16, v5

    .line 594
    .line 595
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 596
    .line 597
    .line 598
    move-result v11

    .line 599
    or-int/2addr v5, v11

    .line 600
    invoke-virtual {v1, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 601
    .line 602
    .line 603
    move-result v11

    .line 604
    or-int/2addr v5, v11

    .line 605
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 606
    .line 607
    .line 608
    move-result v11

    .line 609
    or-int/2addr v5, v11

    .line 610
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 611
    .line 612
    .line 613
    move-result v11

    .line 614
    or-int/2addr v5, v11

    .line 615
    invoke-virtual {v1, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 616
    .line 617
    .line 618
    move-result v11

    .line 619
    or-int/2addr v5, v11

    .line 620
    invoke-virtual {v1, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 621
    .line 622
    .line 623
    move-result v11

    .line 624
    or-int/2addr v5, v11

    .line 625
    invoke-virtual {v1, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 626
    .line 627
    .line 628
    move-result v11

    .line 629
    or-int/2addr v5, v11

    .line 630
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 631
    .line 632
    .line 633
    move-result v11

    .line 634
    or-int/2addr v5, v11

    .line 635
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    move-result v11

    .line 639
    or-int/2addr v5, v11

    .line 640
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 641
    .line 642
    .line 643
    move-result v11

    .line 644
    or-int/2addr v5, v11

    .line 645
    invoke-virtual {v1, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 646
    .line 647
    .line 648
    move-result v11

    .line 649
    or-int/2addr v5, v11

    .line 650
    invoke-virtual {v1, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 651
    .line 652
    .line 653
    move-result v11

    .line 654
    or-int/2addr v5, v11

    .line 655
    move-object/from16 v11, v24

    .line 656
    .line 657
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 658
    .line 659
    .line 660
    move-result v16

    .line 661
    or-int v5, v5, v16

    .line 662
    .line 663
    move-object/from16 p2, v0

    .line 664
    .line 665
    move-object/from16 v0, v21

    .line 666
    .line 667
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 668
    .line 669
    .line 670
    move-result v16

    .line 671
    or-int v5, v5, v16

    .line 672
    .line 673
    move-object/from16 v0, v22

    .line 674
    .line 675
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 676
    .line 677
    .line 678
    move-result v16

    .line 679
    or-int v5, v5, v16

    .line 680
    .line 681
    move-object/from16 v0, v23

    .line 682
    .line 683
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 684
    .line 685
    .line 686
    move-result v16

    .line 687
    or-int v5, v5, v16

    .line 688
    .line 689
    move-object/from16 v0, v20

    .line 690
    .line 691
    invoke-virtual {v1, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 692
    .line 693
    .line 694
    move-result v16

    .line 695
    or-int v5, v5, v16

    .line 696
    .line 697
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 698
    .line 699
    .line 700
    move-result-object v0

    .line 701
    if-nez v5, :cond_20

    .line 702
    .line 703
    move-object/from16 v5, v25

    .line 704
    .line 705
    if-ne v0, v5, :cond_1f

    .line 706
    .line 707
    goto :goto_e

    .line 708
    :cond_1f
    move-object v11, v1

    .line 709
    move-object/from16 v1, p0

    .line 710
    .line 711
    goto :goto_f

    .line 712
    :cond_20
    :goto_e
    new-instance v0, Lmg/j;

    .line 713
    .line 714
    move-object/from16 v27, v1

    .line 715
    .line 716
    move-object/from16 v16, v11

    .line 717
    .line 718
    move-object v5, v13

    .line 719
    move-object/from16 v1, v19

    .line 720
    .line 721
    move-object/from16 v17, v21

    .line 722
    .line 723
    move-object/from16 v18, v22

    .line 724
    .line 725
    move-object/from16 v19, v23

    .line 726
    .line 727
    move-object v11, v8

    .line 728
    move-object v13, v9

    .line 729
    move-object v9, v14

    .line 730
    move-object v14, v4

    .line 731
    move-object v8, v7

    .line 732
    move-object v4, v12

    .line 733
    move-object v12, v3

    .line 734
    move-object v7, v6

    .line 735
    move-object/from16 v3, p0

    .line 736
    .line 737
    move-object/from16 v6, p2

    .line 738
    .line 739
    invoke-direct/range {v0 .. v20}, Lmg/j;-><init>(Lay0/n;Ly1/i;Ljava/lang/String;Lxh/e;Lyj/b;Lxh/e;Lh2/d6;Ll2/b1;Lxh/e;Lxh/e;Lxh/e;Lxh/e;Lxh/e;Lxh/e;Lyj/b;Lxh/e;Lyj/b;Lyj/b;Lyj/b;Ll2/b1;)V

    .line 740
    .line 741
    .line 742
    move-object v1, v3

    .line 743
    move-object/from16 v11, v27

    .line 744
    .line 745
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 746
    .line 747
    .line 748
    :goto_f
    move-object v10, v0

    .line 749
    check-cast v10, Lay0/k;

    .line 750
    .line 751
    const/4 v13, 0x0

    .line 752
    const/16 v14, 0x3fc

    .line 753
    .line 754
    const-string v3, "/tariff_selection"

    .line 755
    .line 756
    const/4 v4, 0x0

    .line 757
    const/4 v5, 0x0

    .line 758
    const/4 v6, 0x0

    .line 759
    const/4 v7, 0x0

    .line 760
    const/4 v8, 0x0

    .line 761
    const/4 v9, 0x0

    .line 762
    const/16 v12, 0x30

    .line 763
    .line 764
    move-object/from16 v2, v26

    .line 765
    .line 766
    invoke-static/range {v2 .. v14}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 767
    .line 768
    .line 769
    goto :goto_10

    .line 770
    :cond_21
    move-object v11, v1

    .line 771
    move-object v1, v3

    .line 772
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 773
    .line 774
    .line 775
    :goto_10
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 776
    .line 777
    .line 778
    move-result-object v0

    .line 779
    if-eqz v0, :cond_22

    .line 780
    .line 781
    new-instance v2, Ll2/u;

    .line 782
    .line 783
    const/4 v3, 0x6

    .line 784
    move-object/from16 v4, p1

    .line 785
    .line 786
    move/from16 v5, p3

    .line 787
    .line 788
    invoke-direct {v2, v5, v3, v1, v4}, Ll2/u;-><init>(IILjava/lang/Object;Ljava/lang/Object;)V

    .line 789
    .line 790
    .line 791
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 792
    .line 793
    :cond_22
    return-void
.end method

.method public static final b(Ljava/lang/String;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v10, p2

    .line 4
    .line 5
    move-object/from16 v11, p1

    .line 6
    .line 7
    check-cast v11, Ll2/t;

    .line 8
    .line 9
    const v0, 0x7de5ce1b

    .line 10
    .line 11
    .line 12
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    const/4 v2, 0x2

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v0, v2

    .line 25
    :goto_0
    or-int/2addr v0, v10

    .line 26
    and-int/lit8 v3, v0, 0x3

    .line 27
    .line 28
    const/4 v8, 0x0

    .line 29
    if-eq v3, v2, :cond_1

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    goto :goto_1

    .line 33
    :cond_1
    move v2, v8

    .line 34
    :goto_1
    and-int/lit8 v3, v0, 0x1

    .line 35
    .line 36
    invoke-virtual {v11, v3, v2}, Ll2/t;->O(IZ)Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_10

    .line 41
    .line 42
    const-string v2, "PaymentFlowScreen"

    .line 43
    .line 44
    invoke-static {v2, v11}, Lzb/b;->C(Ljava/lang/String;Ll2/o;)Lzb/v0;

    .line 45
    .line 46
    .line 47
    move-result-object v12

    .line 48
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 53
    .line 54
    if-ne v2, v13, :cond_2

    .line 55
    .line 56
    new-instance v2, Lmg/i;

    .line 57
    .line 58
    const/16 v3, 0xb

    .line 59
    .line 60
    invoke-direct {v2, v3}, Lmg/i;-><init>(I)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    check-cast v2, Lay0/k;

    .line 67
    .line 68
    invoke-virtual {v12, v2}, Lzb/v0;->f(Lay0/k;)Lyj/b;

    .line 69
    .line 70
    .line 71
    move-result-object v14

    .line 72
    invoke-static {v11}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-interface {v2, v11}, Lzb/j;->u(Ll2/o;)J

    .line 77
    .line 78
    .line 79
    move-result-wide v2

    .line 80
    new-instance v15, Lh2/d6;

    .line 81
    .line 82
    const/4 v4, 0x4

    .line 83
    invoke-direct {v15, v12, v2, v3, v4}, Lh2/d6;-><init>(Ljava/lang/Object;JI)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    if-ne v2, v13, :cond_3

    .line 91
    .line 92
    new-instance v2, Ll20/f;

    .line 93
    .line 94
    const/16 v3, 0x11

    .line 95
    .line 96
    invoke-direct {v2, v3}, Ll20/f;-><init>(I)V

    .line 97
    .line 98
    .line 99
    invoke-virtual {v11, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    :cond_3
    check-cast v2, Lay0/n;

    .line 103
    .line 104
    invoke-virtual {v12, v2}, Lzb/v0;->d(Lay0/n;)Lxh/e;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    if-ne v3, v13, :cond_4

    .line 113
    .line 114
    new-instance v3, Ll20/f;

    .line 115
    .line 116
    const/16 v4, 0x12

    .line 117
    .line 118
    invoke-direct {v3, v4}, Ll20/f;-><init>(I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v11, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    :cond_4
    move-object/from16 v16, v3

    .line 125
    .line 126
    check-cast v16, Lay0/n;

    .line 127
    .line 128
    new-instance v3, Ly1/i;

    .line 129
    .line 130
    const/16 v4, 0x11

    .line 131
    .line 132
    invoke-direct {v3, v12, v4}, Ly1/i;-><init>(Ljava/lang/Object;I)V

    .line 133
    .line 134
    .line 135
    and-int/lit8 v4, v0, 0xe

    .line 136
    .line 137
    new-array v5, v8, [Ljava/lang/Object;

    .line 138
    .line 139
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v6

    .line 143
    if-ne v6, v13, :cond_5

    .line 144
    .line 145
    new-instance v6, Ll31/b;

    .line 146
    .line 147
    const/16 v9, 0x13

    .line 148
    .line 149
    invoke-direct {v6, v9}, Ll31/b;-><init>(I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v11, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    :cond_5
    check-cast v6, Lay0/a;

    .line 156
    .line 157
    const/16 v9, 0x30

    .line 158
    .line 159
    invoke-static {v5, v6, v11, v9}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object v5

    .line 163
    check-cast v5, Ll2/b1;

    .line 164
    .line 165
    new-array v6, v8, [Ljava/lang/Object;

    .line 166
    .line 167
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    if-ne v7, v13, :cond_6

    .line 172
    .line 173
    new-instance v7, Ll31/b;

    .line 174
    .line 175
    const/16 v8, 0x14

    .line 176
    .line 177
    invoke-direct {v7, v8}, Ll31/b;-><init>(I)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    :cond_6
    check-cast v7, Lay0/a;

    .line 184
    .line 185
    invoke-static {v6, v7, v11, v9}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    check-cast v6, Ll2/b1;

    .line 190
    .line 191
    const/4 v7, 0x0

    .line 192
    new-array v8, v7, [Ljava/lang/Object;

    .line 193
    .line 194
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v7

    .line 198
    if-ne v7, v13, :cond_7

    .line 199
    .line 200
    new-instance v7, Ll31/b;

    .line 201
    .line 202
    const/16 v9, 0x15

    .line 203
    .line 204
    invoke-direct {v7, v9}, Ll31/b;-><init>(I)V

    .line 205
    .line 206
    .line 207
    invoke-virtual {v11, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    :cond_7
    check-cast v7, Lay0/a;

    .line 211
    .line 212
    const/16 v9, 0x30

    .line 213
    .line 214
    invoke-static {v8, v7, v11, v9}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v7

    .line 218
    check-cast v7, Ll2/b1;

    .line 219
    .line 220
    sget-object v8, Lzb/x;->b:Ll2/u2;

    .line 221
    .line 222
    invoke-virtual {v11, v8}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v8

    .line 226
    check-cast v8, Lzb/j;

    .line 227
    .line 228
    invoke-interface {v8, v11}, Lzb/j;->u(Ll2/o;)J

    .line 229
    .line 230
    .line 231
    move-result-wide v8

    .line 232
    move/from16 v19, v0

    .line 233
    .line 234
    xor-int/lit8 v0, v4, 0x6

    .line 235
    .line 236
    move-object/from16 v20, v2

    .line 237
    .line 238
    const/4 v2, 0x4

    .line 239
    if-le v0, v2, :cond_8

    .line 240
    .line 241
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result v0

    .line 245
    if-nez v0, :cond_9

    .line 246
    .line 247
    :cond_8
    and-int/lit8 v0, v19, 0x6

    .line 248
    .line 249
    if-ne v0, v2, :cond_a

    .line 250
    .line 251
    :cond_9
    const/4 v0, 0x1

    .line 252
    goto :goto_2

    .line 253
    :cond_a
    const/4 v0, 0x0

    .line 254
    :goto_2
    invoke-virtual {v11, v8, v9}, Ll2/t;->f(J)Z

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    or-int/2addr v0, v2

    .line 259
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    move-result v2

    .line 263
    or-int/2addr v0, v2

    .line 264
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    move-result v2

    .line 268
    or-int/2addr v0, v2

    .line 269
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    move-result v2

    .line 273
    or-int/2addr v0, v2

    .line 274
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    if-nez v0, :cond_c

    .line 279
    .line 280
    if-ne v2, v13, :cond_b

    .line 281
    .line 282
    goto :goto_3

    .line 283
    :cond_b
    move-object v8, v3

    .line 284
    move v9, v4

    .line 285
    move-object/from16 v7, v20

    .line 286
    .line 287
    goto :goto_4

    .line 288
    :cond_c
    :goto_3
    new-instance v0, Lmg/l;

    .line 289
    .line 290
    move-wide/from16 v24, v8

    .line 291
    .line 292
    move-object v8, v3

    .line 293
    move-wide/from16 v2, v24

    .line 294
    .line 295
    move v9, v4

    .line 296
    move-object v4, v5

    .line 297
    move-object v5, v6

    .line 298
    move-object v6, v7

    .line 299
    move-object/from16 v7, v20

    .line 300
    .line 301
    invoke-direct/range {v0 .. v6}, Lmg/l;-><init>(Ljava/lang/String;JLl2/b1;Ll2/b1;Ll2/b1;)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 305
    .line 306
    .line 307
    move-object v2, v0

    .line 308
    :goto_4
    move-object v1, v2

    .line 309
    check-cast v1, Lay0/n;

    .line 310
    .line 311
    invoke-virtual {v12}, Lzb/v0;->b()Lz9/y;

    .line 312
    .line 313
    .line 314
    move-result-object v19

    .line 315
    const/4 v2, 0x4

    .line 316
    if-ne v9, v2, :cond_d

    .line 317
    .line 318
    const/16 v18, 0x1

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_d
    const/16 v18, 0x0

    .line 322
    .line 323
    :goto_5
    invoke-virtual {v11, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    move-result v0

    .line 327
    or-int v0, v18, v0

    .line 328
    .line 329
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 330
    .line 331
    .line 332
    move-result v2

    .line 333
    or-int/2addr v0, v2

    .line 334
    invoke-virtual {v11, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 335
    .line 336
    .line 337
    move-result v2

    .line 338
    or-int/2addr v0, v2

    .line 339
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    move-result v2

    .line 343
    or-int/2addr v0, v2

    .line 344
    invoke-virtual {v11, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    move-result v2

    .line 348
    or-int/2addr v0, v2

    .line 349
    invoke-virtual {v11, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    move-result v2

    .line 353
    or-int/2addr v0, v2

    .line 354
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    if-nez v0, :cond_f

    .line 359
    .line 360
    if-ne v2, v13, :cond_e

    .line 361
    .line 362
    goto :goto_6

    .line 363
    :cond_e
    move-object/from16 v1, p0

    .line 364
    .line 365
    goto :goto_7

    .line 366
    :cond_f
    :goto_6
    new-instance v0, Lh2/d1;

    .line 367
    .line 368
    const/4 v9, 0x2

    .line 369
    move-object/from16 v5, p0

    .line 370
    .line 371
    move-object v4, v8

    .line 372
    move-object v2, v12

    .line 373
    move-object v6, v14

    .line 374
    move-object v8, v15

    .line 375
    move-object/from16 v3, v16

    .line 376
    .line 377
    invoke-direct/range {v0 .. v9}, Lh2/d1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 378
    .line 379
    .line 380
    move-object v1, v5

    .line 381
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 382
    .line 383
    .line 384
    move-object v2, v0

    .line 385
    :goto_7
    check-cast v2, Lay0/k;

    .line 386
    .line 387
    const/16 v22, 0x0

    .line 388
    .line 389
    const/16 v23, 0x3fc

    .line 390
    .line 391
    const-string v12, "/overview"

    .line 392
    .line 393
    const/4 v13, 0x0

    .line 394
    const/4 v14, 0x0

    .line 395
    const/4 v15, 0x0

    .line 396
    const/16 v16, 0x0

    .line 397
    .line 398
    const/16 v17, 0x0

    .line 399
    .line 400
    const/16 v18, 0x0

    .line 401
    .line 402
    const/16 v21, 0x30

    .line 403
    .line 404
    move-object/from16 v20, v11

    .line 405
    .line 406
    move-object/from16 v11, v19

    .line 407
    .line 408
    move-object/from16 v19, v2

    .line 409
    .line 410
    invoke-static/range {v11 .. v23}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 411
    .line 412
    .line 413
    goto :goto_8

    .line 414
    :cond_10
    move-object/from16 v20, v11

    .line 415
    .line 416
    invoke-virtual/range {v20 .. v20}, Ll2/t;->R()V

    .line 417
    .line 418
    .line 419
    :goto_8
    invoke-virtual/range {v20 .. v20}, Ll2/t;->s()Ll2/u1;

    .line 420
    .line 421
    .line 422
    move-result-object v0

    .line 423
    if-eqz v0, :cond_11

    .line 424
    .line 425
    new-instance v2, Ll20/d;

    .line 426
    .line 427
    const/4 v3, 0x5

    .line 428
    invoke-direct {v2, v1, v10, v3}, Ll20/d;-><init>(Ljava/lang/String;II)V

    .line 429
    .line 430
    .line 431
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 432
    .line 433
    :cond_11
    return-void
.end method

.method public static final c(Ll2/o;)Lmg/k;
    .locals 1

    .line 1
    sget-object v0, Lzb/x;->b:Ll2/u2;

    .line 2
    .line 3
    check-cast p0, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "null cannot be cast to non-null type cariad.charging.multicharge.kitten.subscription.presentation.SubscriptionUi"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    check-cast p0, Lmg/k;

    .line 15
    .line 16
    return-object p0
.end method
