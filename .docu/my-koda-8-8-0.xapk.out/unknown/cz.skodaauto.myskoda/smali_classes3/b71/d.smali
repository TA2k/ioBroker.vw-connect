.class public abstract Lb71/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move/from16 v9, p3

    .line 6
    .line 7
    const-string v1, "modifier"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "viewModel"

    .line 13
    .line 14
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object/from16 v10, p2

    .line 18
    .line 19
    check-cast v10, Ll2/t;

    .line 20
    .line 21
    const v1, -0x2c9aa9d8

    .line 22
    .line 23
    .line 24
    invoke-virtual {v10, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v10, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x4

    .line 33
    if-eqz v1, :cond_0

    .line 34
    .line 35
    move v1, v4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v1, v3

    .line 38
    :goto_0
    or-int/2addr v1, v9

    .line 39
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    if-eqz v5, :cond_1

    .line 44
    .line 45
    const/16 v5, 0x20

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_1
    const/16 v5, 0x10

    .line 49
    .line 50
    :goto_1
    or-int v11, v1, v5

    .line 51
    .line 52
    and-int/lit8 v1, v11, 0x13

    .line 53
    .line 54
    const/16 v5, 0x12

    .line 55
    .line 56
    const/4 v6, 0x1

    .line 57
    const/4 v12, 0x0

    .line 58
    if-eq v1, v5, :cond_2

    .line 59
    .line 60
    move v1, v6

    .line 61
    goto :goto_2

    .line 62
    :cond_2
    move v1, v12

    .line 63
    :goto_2
    and-int/lit8 v5, v11, 0x1

    .line 64
    .line 65
    invoke-virtual {v10, v5, v1}, Ll2/t;->O(IZ)Z

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    if-eqz v1, :cond_13

    .line 70
    .line 71
    invoke-interface {v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->isClosable()Lyy0/a2;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    invoke-static {v1, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-interface {v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->getActiveParkingManeuver()Lyy0/a2;

    .line 80
    .line 81
    .line 82
    move-result-object v5

    .line 83
    invoke-static {v5, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    invoke-interface {v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->isAwaitingFinished()Lyy0/a2;

    .line 88
    .line 89
    .line 90
    move-result-object v7

    .line 91
    invoke-static {v7, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    invoke-interface {v2}, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;->getError()Lyy0/a2;

    .line 96
    .line 97
    .line 98
    move-result-object v8

    .line 99
    invoke-static {v8, v10}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    invoke-interface {v7}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v7

    .line 107
    check-cast v7, Ljava/lang/Boolean;

    .line 108
    .line 109
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 110
    .line 111
    .line 112
    move-result v7

    .line 113
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 114
    .line 115
    if-eqz v7, :cond_5

    .line 116
    .line 117
    const v3, 0x5dac1ff1

    .line 118
    .line 119
    .line 120
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 121
    .line 122
    .line 123
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object v1

    .line 127
    check-cast v1, Ljava/lang/Boolean;

    .line 128
    .line 129
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 130
    .line 131
    .line 132
    move-result v14

    .line 133
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    if-nez v1, :cond_3

    .line 142
    .line 143
    if-ne v3, v13, :cond_4

    .line 144
    .line 145
    :cond_3
    new-instance v1, La71/z;

    .line 146
    .line 147
    const/4 v7, 0x0

    .line 148
    const/16 v8, 0x15

    .line 149
    .line 150
    const/4 v2, 0x0

    .line 151
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 152
    .line 153
    const-string v5, "closeRPAModule"

    .line 154
    .line 155
    const-string v6, "closeRPAModule()V"

    .line 156
    .line 157
    move-object/from16 v3, p1

    .line 158
    .line 159
    invoke-direct/range {v1 .. v8}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 160
    .line 161
    .line 162
    move-object v2, v3

    .line 163
    invoke-virtual {v10, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    move-object v3, v1

    .line 167
    :cond_4
    check-cast v3, Lhy0/g;

    .line 168
    .line 169
    check-cast v3, Lay0/a;

    .line 170
    .line 171
    and-int/lit8 v1, v11, 0xe

    .line 172
    .line 173
    invoke-static {v1, v3, v10, v0, v14}, Lb71/a;->k(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 177
    .line 178
    .line 179
    move-object v8, v0

    .line 180
    goto/16 :goto_a

    .line 181
    .line 182
    :cond_5
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v7

    .line 186
    check-cast v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError;

    .line 187
    .line 188
    sget-object v8, Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;->INSTANCE:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/error/ParkingFinishedError$Timeout;

    .line 189
    .line 190
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v7

    .line 194
    const/4 v8, 0x3

    .line 195
    if-eqz v7, :cond_b

    .line 196
    .line 197
    const v7, 0x5daffa02

    .line 198
    .line 199
    .line 200
    invoke-virtual {v10, v7}, Ll2/t;->Y(I)V

    .line 201
    .line 202
    .line 203
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v5

    .line 207
    check-cast v5, Ls71/h;

    .line 208
    .line 209
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 210
    .line 211
    .line 212
    move-result v5

    .line 213
    if-eqz v5, :cond_8

    .line 214
    .line 215
    if-eq v5, v6, :cond_7

    .line 216
    .line 217
    if-eq v5, v3, :cond_8

    .line 218
    .line 219
    if-eq v5, v8, :cond_7

    .line 220
    .line 221
    if-ne v5, v4, :cond_6

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_6
    const v0, -0x30704f5e

    .line 225
    .line 226
    .line 227
    invoke-static {v0, v10, v12}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 228
    .line 229
    .line 230
    move-result-object v0

    .line 231
    throw v0

    .line 232
    :cond_7
    const v3, -0x30704309

    .line 233
    .line 234
    .line 235
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 236
    .line 237
    .line 238
    const-string v3, "parking_finished_title"

    .line 239
    .line 240
    invoke-static {v3, v10}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    :goto_3
    move-object v14, v3

    .line 248
    goto :goto_5

    .line 249
    :cond_8
    :goto_4
    const v3, -0x30702be9

    .line 250
    .line 251
    .line 252
    invoke-virtual {v10, v3}, Ll2/t;->Y(I)V

    .line 253
    .line 254
    .line 255
    const-string v3, "pullout_finished_title"

    .line 256
    .line 257
    invoke-static {v3, v10}, Ly61/a;->a(Ljava/lang/String;Ll2/o;)Ljava/lang/String;

    .line 258
    .line 259
    .line 260
    move-result-object v3

    .line 261
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 262
    .line 263
    .line 264
    goto :goto_3

    .line 265
    :goto_5
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v1

    .line 269
    check-cast v1, Ljava/lang/Boolean;

    .line 270
    .line 271
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 272
    .line 273
    .line 274
    move-result v15

    .line 275
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    move-result v1

    .line 279
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v3

    .line 283
    if-nez v1, :cond_a

    .line 284
    .line 285
    if-ne v3, v13, :cond_9

    .line 286
    .line 287
    goto :goto_6

    .line 288
    :cond_9
    move-object v7, v2

    .line 289
    goto :goto_7

    .line 290
    :cond_a
    :goto_6
    new-instance v1, La71/z;

    .line 291
    .line 292
    const/4 v7, 0x0

    .line 293
    const/16 v8, 0x16

    .line 294
    .line 295
    const/4 v2, 0x0

    .line 296
    const-class v4, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 297
    .line 298
    const-string v5, "closeRPAModule"

    .line 299
    .line 300
    const-string v6, "closeRPAModule()V"

    .line 301
    .line 302
    move-object/from16 v3, p1

    .line 303
    .line 304
    invoke-direct/range {v1 .. v8}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 305
    .line 306
    .line 307
    move-object v7, v3

    .line 308
    invoke-virtual {v10, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 309
    .line 310
    .line 311
    move-object v3, v1

    .line 312
    :goto_7
    check-cast v3, Lhy0/g;

    .line 313
    .line 314
    move-object v1, v3

    .line 315
    check-cast v1, Lay0/a;

    .line 316
    .line 317
    and-int/lit8 v0, v11, 0xe

    .line 318
    .line 319
    move-object/from16 v4, p0

    .line 320
    .line 321
    move-object v3, v10

    .line 322
    move-object v2, v14

    .line 323
    move v5, v15

    .line 324
    invoke-static/range {v0 .. v5}, Lb71/a;->j(ILay0/a;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 325
    .line 326
    .line 327
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 328
    .line 329
    .line 330
    move-object/from16 v8, p0

    .line 331
    .line 332
    move-object v2, v7

    .line 333
    goto/16 :goto_a

    .line 334
    .line 335
    :cond_b
    move-object v7, v2

    .line 336
    const v0, 0x5db4faf0

    .line 337
    .line 338
    .line 339
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 340
    .line 341
    .line 342
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    check-cast v0, Ls71/h;

    .line 347
    .line 348
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 349
    .line 350
    .line 351
    move-result v0

    .line 352
    if-eqz v0, :cond_c

    .line 353
    .line 354
    if-eq v0, v6, :cond_e

    .line 355
    .line 356
    if-eq v0, v3, :cond_c

    .line 357
    .line 358
    if-eq v0, v8, :cond_e

    .line 359
    .line 360
    if-ne v0, v4, :cond_d

    .line 361
    .line 362
    :cond_c
    move-object/from16 v8, p0

    .line 363
    .line 364
    move-object v2, v7

    .line 365
    goto :goto_8

    .line 366
    :cond_d
    const v0, -0x709710ae

    .line 367
    .line 368
    .line 369
    invoke-static {v0, v10, v12}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 370
    .line 371
    .line 372
    move-result-object v0

    .line 373
    throw v0

    .line 374
    :cond_e
    const v0, 0x5db6d84a

    .line 375
    .line 376
    .line 377
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 378
    .line 379
    .line 380
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object v0

    .line 384
    check-cast v0, Ljava/lang/Boolean;

    .line 385
    .line 386
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 387
    .line 388
    .line 389
    move-result v8

    .line 390
    invoke-virtual {v10, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 391
    .line 392
    .line 393
    move-result v0

    .line 394
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 395
    .line 396
    .line 397
    move-result-object v1

    .line 398
    if-nez v0, :cond_f

    .line 399
    .line 400
    if-ne v1, v13, :cond_10

    .line 401
    .line 402
    :cond_f
    new-instance v0, La71/z;

    .line 403
    .line 404
    const/4 v6, 0x0

    .line 405
    const/16 v7, 0x17

    .line 406
    .line 407
    const/4 v1, 0x0

    .line 408
    const-class v3, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 409
    .line 410
    const-string v4, "closeRPAModule"

    .line 411
    .line 412
    const-string v5, "closeRPAModule()V"

    .line 413
    .line 414
    move-object/from16 v2, p1

    .line 415
    .line 416
    invoke-direct/range {v0 .. v7}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 420
    .line 421
    .line 422
    move-object v1, v0

    .line 423
    :cond_10
    check-cast v1, Lhy0/g;

    .line 424
    .line 425
    move-object v3, v1

    .line 426
    check-cast v3, Lay0/a;

    .line 427
    .line 428
    and-int/lit8 v5, v11, 0x7e

    .line 429
    .line 430
    move-object/from16 v0, p0

    .line 431
    .line 432
    move-object/from16 v1, p1

    .line 433
    .line 434
    move v2, v8

    .line 435
    move-object v4, v10

    .line 436
    invoke-static/range {v0 .. v5}, Lb71/a;->h(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;ZLay0/a;Ll2/o;I)V

    .line 437
    .line 438
    .line 439
    move-object v8, v0

    .line 440
    move-object v2, v1

    .line 441
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 442
    .line 443
    .line 444
    goto :goto_9

    .line 445
    :goto_8
    const v0, 0x5dbdd0d9

    .line 446
    .line 447
    .line 448
    invoke-virtual {v10, v0}, Ll2/t;->Y(I)V

    .line 449
    .line 450
    .line 451
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v0

    .line 455
    check-cast v0, Ljava/lang/Boolean;

    .line 456
    .line 457
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 458
    .line 459
    .line 460
    move-result v14

    .line 461
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 462
    .line 463
    .line 464
    move-result v0

    .line 465
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    move-result-object v1

    .line 469
    if-nez v0, :cond_11

    .line 470
    .line 471
    if-ne v1, v13, :cond_12

    .line 472
    .line 473
    :cond_11
    new-instance v0, La71/z;

    .line 474
    .line 475
    const/4 v6, 0x0

    .line 476
    const/16 v7, 0x18

    .line 477
    .line 478
    const/4 v1, 0x0

    .line 479
    const-class v3, Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;

    .line 480
    .line 481
    const-string v4, "closeRPAModule"

    .line 482
    .line 483
    const-string v5, "closeRPAModule()V"

    .line 484
    .line 485
    invoke-direct/range {v0 .. v7}, La71/z;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 489
    .line 490
    .line 491
    move-object v1, v0

    .line 492
    :cond_12
    check-cast v1, Lhy0/g;

    .line 493
    .line 494
    check-cast v1, Lay0/a;

    .line 495
    .line 496
    and-int/lit8 v0, v11, 0xe

    .line 497
    .line 498
    invoke-static {v0, v1, v10, v8, v14}, Lb71/a;->i(ILay0/a;Ll2/o;Lx2/s;Z)V

    .line 499
    .line 500
    .line 501
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 502
    .line 503
    .line 504
    :goto_9
    invoke-virtual {v10, v12}, Ll2/t;->q(Z)V

    .line 505
    .line 506
    .line 507
    goto :goto_a

    .line 508
    :cond_13
    move-object v8, v0

    .line 509
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 510
    .line 511
    .line 512
    :goto_a
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    if-eqz v0, :cond_14

    .line 517
    .line 518
    new-instance v1, Lb71/c;

    .line 519
    .line 520
    invoke-direct {v1, v8, v2, v9}, Lb71/c;-><init>(Lx2/s;Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ParkingFinishedViewModel;I)V

    .line 521
    .line 522
    .line 523
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 524
    .line 525
    :cond_14
    return-void
.end method
