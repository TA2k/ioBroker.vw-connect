.class public final synthetic Len0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Len0/g;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Len0/g;I)V
    .locals 0

    .line 1
    iput p3, p0, Len0/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Len0/e;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Len0/e;->f:Len0/g;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 46

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Len0/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Len0/e;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Len0/e;->f:Len0/g;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Lua/a;

    .line 15
    .line 16
    const-string v3, "_connection"

    .line 17
    .line 18
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v3, "SELECT * FROM ordered_vehicle where ? is commissionId"

    .line 22
    .line 23
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/4 v4, 0x1

    .line 28
    :try_start_0
    invoke-interface {v3, v4, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v1, "commissionId"

    .line 32
    .line 33
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const-string v4, "name"

    .line 38
    .line 39
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    const-string v5, "vin"

    .line 44
    .line 45
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    const-string v6, "dealerId"

    .line 50
    .line 51
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    const-string v7, "priority"

    .line 56
    .line 57
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    const-string v8, "activationStatus"

    .line 62
    .line 63
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v8

    .line 67
    const-string v9, "orderStatus"

    .line 68
    .line 69
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    const-string v10, "startDeliveryDate"

    .line 74
    .line 75
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    const-string v11, "endDeliveryDate"

    .line 80
    .line 81
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    const-string v12, "spec_model"

    .line 86
    .line 87
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    const-string v13, "spec_trimLevel"

    .line 92
    .line 93
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v13

    .line 97
    const-string v14, "spec_engine"

    .line 98
    .line 99
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v14

    .line 103
    const-string v15, "spec_exteriorColor"

    .line 104
    .line 105
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 106
    .line 107
    .line 108
    move-result v15

    .line 109
    move/from16 p0, v15

    .line 110
    .line 111
    const-string v15, "spec_interiorColor"

    .line 112
    .line 113
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 114
    .line 115
    .line 116
    move-result v15

    .line 117
    move/from16 p1, v15

    .line 118
    .line 119
    const-string v15, "spec_batteryCapacity"

    .line 120
    .line 121
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 122
    .line 123
    .line 124
    move-result v15

    .line 125
    move/from16 v16, v15

    .line 126
    .line 127
    const-string v15, "spec_maxPerformanceInKW"

    .line 128
    .line 129
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 130
    .line 131
    .line 132
    move-result v15

    .line 133
    move/from16 v17, v15

    .line 134
    .line 135
    const-string v15, "spec_wltpRangeInM"

    .line 136
    .line 137
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 138
    .line 139
    .line 140
    move-result v15

    .line 141
    move/from16 v18, v15

    .line 142
    .line 143
    const-string v15, "spec_consumptionInLitPer100km"

    .line 144
    .line 145
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 146
    .line 147
    .line 148
    move-result v15

    .line 149
    move/from16 v19, v15

    .line 150
    .line 151
    const-string v15, "spec_consumptionInkWhPer100km"

    .line 152
    .line 153
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 154
    .line 155
    .line 156
    move-result v15

    .line 157
    move/from16 v20, v15

    .line 158
    .line 159
    const-string v15, "spec_consumptionInKgPer100km"

    .line 160
    .line 161
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 162
    .line 163
    .line 164
    move-result v15

    .line 165
    move/from16 v21, v15

    .line 166
    .line 167
    new-instance v15, Landroidx/collection/f;

    .line 168
    .line 169
    move/from16 v22, v14

    .line 170
    .line 171
    const/4 v14, 0x0

    .line 172
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 173
    .line 174
    .line 175
    :cond_0
    :goto_0
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 176
    .line 177
    .line 178
    move-result v14

    .line 179
    if-eqz v14, :cond_1

    .line 180
    .line 181
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v14

    .line 185
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v23

    .line 189
    if-nez v23, :cond_0

    .line 190
    .line 191
    move/from16 v23, v13

    .line 192
    .line 193
    new-instance v13, Ljava/util/ArrayList;

    .line 194
    .line 195
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move/from16 v13, v23

    .line 202
    .line 203
    goto :goto_0

    .line 204
    :catchall_0
    move-exception v0

    .line 205
    goto/16 :goto_1a

    .line 206
    .line 207
    :cond_1
    move/from16 v23, v13

    .line 208
    .line 209
    invoke-interface {v3}, Lua/c;->reset()V

    .line 210
    .line 211
    .line 212
    invoke-virtual {v0, v2, v15}, Len0/g;->c(Lua/a;Landroidx/collection/f;)V

    .line 213
    .line 214
    .line 215
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 216
    .line 217
    .line 218
    move-result v0

    .line 219
    const/4 v2, 0x0

    .line 220
    if-eqz v0, :cond_1c

    .line 221
    .line 222
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v25

    .line 226
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v26

    .line 230
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 231
    .line 232
    .line 233
    move-result v0

    .line 234
    if-eqz v0, :cond_2

    .line 235
    .line 236
    move-object/from16 v27, v2

    .line 237
    .line 238
    goto :goto_1

    .line 239
    :cond_2
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 240
    .line 241
    .line 242
    move-result-object v0

    .line 243
    move-object/from16 v27, v0

    .line 244
    .line 245
    :goto_1
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    if-eqz v0, :cond_3

    .line 250
    .line 251
    move-object/from16 v28, v2

    .line 252
    .line 253
    goto :goto_2

    .line 254
    :cond_3
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    move-object/from16 v28, v0

    .line 259
    .line 260
    :goto_2
    invoke-interface {v3, v7}, Lua/c;->getLong(I)J

    .line 261
    .line 262
    .line 263
    move-result-wide v4

    .line 264
    long-to-int v0, v4

    .line 265
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v4

    .line 269
    invoke-static {v4}, Len0/g;->a(Ljava/lang/String;)Lss0/a;

    .line 270
    .line 271
    .line 272
    move-result-object v30

    .line 273
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v4

    .line 277
    invoke-static {v4}, Len0/g;->b(Ljava/lang/String;)Lss0/t;

    .line 278
    .line 279
    .line 280
    move-result-object v31

    .line 281
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 282
    .line 283
    .line 284
    move-result v4

    .line 285
    if-eqz v4, :cond_4

    .line 286
    .line 287
    move-object v4, v2

    .line 288
    goto :goto_3

    .line 289
    :cond_4
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object v4

    .line 293
    :goto_3
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 294
    .line 295
    .line 296
    move-result-object v32

    .line 297
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 298
    .line 299
    .line 300
    move-result v4

    .line 301
    if-eqz v4, :cond_5

    .line 302
    .line 303
    move-object v4, v2

    .line 304
    goto :goto_4

    .line 305
    :cond_5
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object v4

    .line 309
    :goto_4
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 310
    .line 311
    .line 312
    move-result-object v33

    .line 313
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 314
    .line 315
    .line 316
    move-result v4

    .line 317
    if-eqz v4, :cond_10

    .line 318
    .line 319
    move/from16 v4, v23

    .line 320
    .line 321
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 322
    .line 323
    .line 324
    move-result v5

    .line 325
    if-eqz v5, :cond_f

    .line 326
    .line 327
    move/from16 v5, v22

    .line 328
    .line 329
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 330
    .line 331
    .line 332
    move-result v6

    .line 333
    if-eqz v6, :cond_e

    .line 334
    .line 335
    move/from16 v6, p0

    .line 336
    .line 337
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 338
    .line 339
    .line 340
    move-result v7

    .line 341
    if-eqz v7, :cond_d

    .line 342
    .line 343
    move/from16 v7, p1

    .line 344
    .line 345
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 346
    .line 347
    .line 348
    move-result v8

    .line 349
    if-eqz v8, :cond_c

    .line 350
    .line 351
    move/from16 v8, v16

    .line 352
    .line 353
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 354
    .line 355
    .line 356
    move-result v9

    .line 357
    if-eqz v9, :cond_b

    .line 358
    .line 359
    move/from16 v9, v17

    .line 360
    .line 361
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 362
    .line 363
    .line 364
    move-result v10

    .line 365
    if-eqz v10, :cond_a

    .line 366
    .line 367
    move/from16 v10, v18

    .line 368
    .line 369
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 370
    .line 371
    .line 372
    move-result v11

    .line 373
    if-eqz v11, :cond_9

    .line 374
    .line 375
    move/from16 v11, v19

    .line 376
    .line 377
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 378
    .line 379
    .line 380
    move-result v13

    .line 381
    if-eqz v13, :cond_8

    .line 382
    .line 383
    move/from16 v13, v20

    .line 384
    .line 385
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 386
    .line 387
    .line 388
    move-result v14

    .line 389
    if-eqz v14, :cond_7

    .line 390
    .line 391
    move/from16 v14, v21

    .line 392
    .line 393
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 394
    .line 395
    .line 396
    move-result v16

    .line 397
    if-nez v16, :cond_6

    .line 398
    .line 399
    goto :goto_c

    .line 400
    :cond_6
    move-object/from16 v34, v2

    .line 401
    .line 402
    goto/16 :goto_19

    .line 403
    .line 404
    :cond_7
    :goto_5
    move/from16 v14, v21

    .line 405
    .line 406
    goto :goto_c

    .line 407
    :cond_8
    :goto_6
    move/from16 v13, v20

    .line 408
    .line 409
    goto :goto_5

    .line 410
    :cond_9
    :goto_7
    move/from16 v11, v19

    .line 411
    .line 412
    goto :goto_6

    .line 413
    :cond_a
    :goto_8
    move/from16 v10, v18

    .line 414
    .line 415
    goto :goto_7

    .line 416
    :cond_b
    :goto_9
    move/from16 v9, v17

    .line 417
    .line 418
    goto :goto_8

    .line 419
    :cond_c
    :goto_a
    move/from16 v8, v16

    .line 420
    .line 421
    goto :goto_9

    .line 422
    :cond_d
    :goto_b
    move/from16 v7, p1

    .line 423
    .line 424
    goto :goto_a

    .line 425
    :cond_e
    move/from16 v6, p0

    .line 426
    .line 427
    goto :goto_b

    .line 428
    :cond_f
    move/from16 v6, p0

    .line 429
    .line 430
    move/from16 v7, p1

    .line 431
    .line 432
    move/from16 v8, v16

    .line 433
    .line 434
    move/from16 v9, v17

    .line 435
    .line 436
    move/from16 v10, v18

    .line 437
    .line 438
    move/from16 v11, v19

    .line 439
    .line 440
    move/from16 v13, v20

    .line 441
    .line 442
    move/from16 v14, v21

    .line 443
    .line 444
    move/from16 v5, v22

    .line 445
    .line 446
    goto :goto_c

    .line 447
    :cond_10
    move/from16 v6, p0

    .line 448
    .line 449
    move/from16 v7, p1

    .line 450
    .line 451
    move/from16 v8, v16

    .line 452
    .line 453
    move/from16 v9, v17

    .line 454
    .line 455
    move/from16 v10, v18

    .line 456
    .line 457
    move/from16 v11, v19

    .line 458
    .line 459
    move/from16 v13, v20

    .line 460
    .line 461
    move/from16 v14, v21

    .line 462
    .line 463
    move/from16 v5, v22

    .line 464
    .line 465
    move/from16 v4, v23

    .line 466
    .line 467
    :goto_c
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 468
    .line 469
    .line 470
    move-result v16

    .line 471
    if-eqz v16, :cond_11

    .line 472
    .line 473
    move-object/from16 v35, v2

    .line 474
    .line 475
    goto :goto_d

    .line 476
    :cond_11
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 477
    .line 478
    .line 479
    move-result-object v12

    .line 480
    move-object/from16 v35, v12

    .line 481
    .line 482
    :goto_d
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 483
    .line 484
    .line 485
    move-result v12

    .line 486
    if-eqz v12, :cond_12

    .line 487
    .line 488
    move-object/from16 v36, v2

    .line 489
    .line 490
    goto :goto_e

    .line 491
    :cond_12
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 492
    .line 493
    .line 494
    move-result-object v4

    .line 495
    move-object/from16 v36, v4

    .line 496
    .line 497
    :goto_e
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 498
    .line 499
    .line 500
    move-result v4

    .line 501
    if-eqz v4, :cond_13

    .line 502
    .line 503
    move-object/from16 v37, v2

    .line 504
    .line 505
    goto :goto_f

    .line 506
    :cond_13
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 507
    .line 508
    .line 509
    move-result-object v4

    .line 510
    move-object/from16 v37, v4

    .line 511
    .line 512
    :goto_f
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 513
    .line 514
    .line 515
    move-result v4

    .line 516
    if-eqz v4, :cond_14

    .line 517
    .line 518
    move-object/from16 v38, v2

    .line 519
    .line 520
    goto :goto_10

    .line 521
    :cond_14
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 522
    .line 523
    .line 524
    move-result-object v4

    .line 525
    move-object/from16 v38, v4

    .line 526
    .line 527
    :goto_10
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 528
    .line 529
    .line 530
    move-result v4

    .line 531
    if-eqz v4, :cond_15

    .line 532
    .line 533
    move-object/from16 v39, v2

    .line 534
    .line 535
    goto :goto_11

    .line 536
    :cond_15
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object v4

    .line 540
    move-object/from16 v39, v4

    .line 541
    .line 542
    :goto_11
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 543
    .line 544
    .line 545
    move-result v4

    .line 546
    if-eqz v4, :cond_16

    .line 547
    .line 548
    move-object/from16 v40, v2

    .line 549
    .line 550
    goto :goto_12

    .line 551
    :cond_16
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 552
    .line 553
    .line 554
    move-result-wide v4

    .line 555
    long-to-int v4, v4

    .line 556
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 557
    .line 558
    .line 559
    move-result-object v4

    .line 560
    move-object/from16 v40, v4

    .line 561
    .line 562
    :goto_12
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 563
    .line 564
    .line 565
    move-result v4

    .line 566
    if-eqz v4, :cond_17

    .line 567
    .line 568
    move-object/from16 v41, v2

    .line 569
    .line 570
    goto :goto_13

    .line 571
    :cond_17
    invoke-interface {v3, v9}, Lua/c;->getLong(I)J

    .line 572
    .line 573
    .line 574
    move-result-wide v4

    .line 575
    long-to-int v4, v4

    .line 576
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 577
    .line 578
    .line 579
    move-result-object v4

    .line 580
    move-object/from16 v41, v4

    .line 581
    .line 582
    :goto_13
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 583
    .line 584
    .line 585
    move-result v4

    .line 586
    if-eqz v4, :cond_18

    .line 587
    .line 588
    move-object/from16 v42, v2

    .line 589
    .line 590
    goto :goto_14

    .line 591
    :cond_18
    invoke-interface {v3, v10}, Lua/c;->getLong(I)J

    .line 592
    .line 593
    .line 594
    move-result-wide v4

    .line 595
    long-to-int v4, v4

    .line 596
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 597
    .line 598
    .line 599
    move-result-object v4

    .line 600
    move-object/from16 v42, v4

    .line 601
    .line 602
    :goto_14
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 603
    .line 604
    .line 605
    move-result v4

    .line 606
    if-eqz v4, :cond_19

    .line 607
    .line 608
    move-object/from16 v43, v2

    .line 609
    .line 610
    goto :goto_15

    .line 611
    :cond_19
    invoke-interface {v3, v11}, Lua/c;->getDouble(I)D

    .line 612
    .line 613
    .line 614
    move-result-wide v4

    .line 615
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 616
    .line 617
    .line 618
    move-result-object v4

    .line 619
    move-object/from16 v43, v4

    .line 620
    .line 621
    :goto_15
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 622
    .line 623
    .line 624
    move-result v4

    .line 625
    if-eqz v4, :cond_1a

    .line 626
    .line 627
    move-object/from16 v44, v2

    .line 628
    .line 629
    goto :goto_16

    .line 630
    :cond_1a
    invoke-interface {v3, v13}, Lua/c;->getDouble(I)D

    .line 631
    .line 632
    .line 633
    move-result-wide v4

    .line 634
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 635
    .line 636
    .line 637
    move-result-object v4

    .line 638
    move-object/from16 v44, v4

    .line 639
    .line 640
    :goto_16
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 641
    .line 642
    .line 643
    move-result v4

    .line 644
    if-eqz v4, :cond_1b

    .line 645
    .line 646
    :goto_17
    move-object/from16 v45, v2

    .line 647
    .line 648
    goto :goto_18

    .line 649
    :cond_1b
    invoke-interface {v3, v14}, Lua/c;->getDouble(I)D

    .line 650
    .line 651
    .line 652
    move-result-wide v4

    .line 653
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 654
    .line 655
    .line 656
    move-result-object v2

    .line 657
    goto :goto_17

    .line 658
    :goto_18
    new-instance v34, Len0/j;

    .line 659
    .line 660
    invoke-direct/range {v34 .. v45}, Len0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V

    .line 661
    .line 662
    .line 663
    :goto_19
    new-instance v24, Len0/i;

    .line 664
    .line 665
    move/from16 v29, v0

    .line 666
    .line 667
    invoke-direct/range {v24 .. v34}, Len0/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILss0/a;Lss0/t;Ljava/time/LocalDate;Ljava/time/LocalDate;Len0/j;)V

    .line 668
    .line 669
    .line 670
    move-object/from16 v0, v24

    .line 671
    .line 672
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 673
    .line 674
    .line 675
    move-result-object v1

    .line 676
    invoke-static {v15, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 677
    .line 678
    .line 679
    move-result-object v1

    .line 680
    const-string v2, "getValue(...)"

    .line 681
    .line 682
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 683
    .line 684
    .line 685
    check-cast v1, Ljava/util/List;

    .line 686
    .line 687
    new-instance v2, Len0/h;

    .line 688
    .line 689
    invoke-direct {v2, v0, v1}, Len0/h;-><init>(Len0/i;Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 690
    .line 691
    .line 692
    :cond_1c
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 693
    .line 694
    .line 695
    return-object v2

    .line 696
    :goto_1a
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 697
    .line 698
    .line 699
    throw v0

    .line 700
    :pswitch_0
    iget-object v1, v0, Len0/e;->e:Ljava/lang/String;

    .line 701
    .line 702
    iget-object v0, v0, Len0/e;->f:Len0/g;

    .line 703
    .line 704
    move-object/from16 v2, p1

    .line 705
    .line 706
    check-cast v2, Lua/a;

    .line 707
    .line 708
    const-string v3, "_connection"

    .line 709
    .line 710
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 711
    .line 712
    .line 713
    const-string v3, "SELECT * FROM ordered_vehicle where ? is commissionId"

    .line 714
    .line 715
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 716
    .line 717
    .line 718
    move-result-object v3

    .line 719
    const/4 v4, 0x1

    .line 720
    :try_start_1
    invoke-interface {v3, v4, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 721
    .line 722
    .line 723
    const-string v1, "commissionId"

    .line 724
    .line 725
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 726
    .line 727
    .line 728
    move-result v1

    .line 729
    const-string v4, "name"

    .line 730
    .line 731
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 732
    .line 733
    .line 734
    move-result v4

    .line 735
    const-string v5, "vin"

    .line 736
    .line 737
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 738
    .line 739
    .line 740
    move-result v5

    .line 741
    const-string v6, "dealerId"

    .line 742
    .line 743
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 744
    .line 745
    .line 746
    move-result v6

    .line 747
    const-string v7, "priority"

    .line 748
    .line 749
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 750
    .line 751
    .line 752
    move-result v7

    .line 753
    const-string v8, "activationStatus"

    .line 754
    .line 755
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 756
    .line 757
    .line 758
    move-result v8

    .line 759
    const-string v9, "orderStatus"

    .line 760
    .line 761
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 762
    .line 763
    .line 764
    move-result v9

    .line 765
    const-string v10, "startDeliveryDate"

    .line 766
    .line 767
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 768
    .line 769
    .line 770
    move-result v10

    .line 771
    const-string v11, "endDeliveryDate"

    .line 772
    .line 773
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 774
    .line 775
    .line 776
    move-result v11

    .line 777
    const-string v12, "spec_model"

    .line 778
    .line 779
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 780
    .line 781
    .line 782
    move-result v12

    .line 783
    const-string v13, "spec_trimLevel"

    .line 784
    .line 785
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 786
    .line 787
    .line 788
    move-result v13

    .line 789
    const-string v14, "spec_engine"

    .line 790
    .line 791
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 792
    .line 793
    .line 794
    move-result v14

    .line 795
    const-string v15, "spec_exteriorColor"

    .line 796
    .line 797
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 798
    .line 799
    .line 800
    move-result v15

    .line 801
    move/from16 p0, v15

    .line 802
    .line 803
    const-string v15, "spec_interiorColor"

    .line 804
    .line 805
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 806
    .line 807
    .line 808
    move-result v15

    .line 809
    move/from16 p1, v15

    .line 810
    .line 811
    const-string v15, "spec_batteryCapacity"

    .line 812
    .line 813
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 814
    .line 815
    .line 816
    move-result v15

    .line 817
    move/from16 v16, v15

    .line 818
    .line 819
    const-string v15, "spec_maxPerformanceInKW"

    .line 820
    .line 821
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 822
    .line 823
    .line 824
    move-result v15

    .line 825
    move/from16 v17, v15

    .line 826
    .line 827
    const-string v15, "spec_wltpRangeInM"

    .line 828
    .line 829
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 830
    .line 831
    .line 832
    move-result v15

    .line 833
    move/from16 v18, v15

    .line 834
    .line 835
    const-string v15, "spec_consumptionInLitPer100km"

    .line 836
    .line 837
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 838
    .line 839
    .line 840
    move-result v15

    .line 841
    move/from16 v19, v15

    .line 842
    .line 843
    const-string v15, "spec_consumptionInkWhPer100km"

    .line 844
    .line 845
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 846
    .line 847
    .line 848
    move-result v15

    .line 849
    move/from16 v20, v15

    .line 850
    .line 851
    const-string v15, "spec_consumptionInKgPer100km"

    .line 852
    .line 853
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 854
    .line 855
    .line 856
    move-result v15

    .line 857
    move/from16 v21, v15

    .line 858
    .line 859
    new-instance v15, Landroidx/collection/f;

    .line 860
    .line 861
    move/from16 v22, v14

    .line 862
    .line 863
    const/4 v14, 0x0

    .line 864
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 865
    .line 866
    .line 867
    :cond_1d
    :goto_1b
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 868
    .line 869
    .line 870
    move-result v14

    .line 871
    if-eqz v14, :cond_1e

    .line 872
    .line 873
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 874
    .line 875
    .line 876
    move-result-object v14

    .line 877
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 878
    .line 879
    .line 880
    move-result v23

    .line 881
    if-nez v23, :cond_1d

    .line 882
    .line 883
    move/from16 v23, v13

    .line 884
    .line 885
    new-instance v13, Ljava/util/ArrayList;

    .line 886
    .line 887
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 888
    .line 889
    .line 890
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 891
    .line 892
    .line 893
    move/from16 v13, v23

    .line 894
    .line 895
    goto :goto_1b

    .line 896
    :catchall_1
    move-exception v0

    .line 897
    goto/16 :goto_35

    .line 898
    .line 899
    :cond_1e
    move/from16 v23, v13

    .line 900
    .line 901
    invoke-interface {v3}, Lua/c;->reset()V

    .line 902
    .line 903
    .line 904
    invoke-virtual {v0, v2, v15}, Len0/g;->c(Lua/a;Landroidx/collection/f;)V

    .line 905
    .line 906
    .line 907
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 908
    .line 909
    .line 910
    move-result v0

    .line 911
    const/4 v2, 0x0

    .line 912
    if-eqz v0, :cond_39

    .line 913
    .line 914
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 915
    .line 916
    .line 917
    move-result-object v25

    .line 918
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 919
    .line 920
    .line 921
    move-result-object v26

    .line 922
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 923
    .line 924
    .line 925
    move-result v0

    .line 926
    if-eqz v0, :cond_1f

    .line 927
    .line 928
    move-object/from16 v27, v2

    .line 929
    .line 930
    goto :goto_1c

    .line 931
    :cond_1f
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 932
    .line 933
    .line 934
    move-result-object v0

    .line 935
    move-object/from16 v27, v0

    .line 936
    .line 937
    :goto_1c
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 938
    .line 939
    .line 940
    move-result v0

    .line 941
    if-eqz v0, :cond_20

    .line 942
    .line 943
    move-object/from16 v28, v2

    .line 944
    .line 945
    goto :goto_1d

    .line 946
    :cond_20
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 947
    .line 948
    .line 949
    move-result-object v0

    .line 950
    move-object/from16 v28, v0

    .line 951
    .line 952
    :goto_1d
    invoke-interface {v3, v7}, Lua/c;->getLong(I)J

    .line 953
    .line 954
    .line 955
    move-result-wide v4

    .line 956
    long-to-int v0, v4

    .line 957
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 958
    .line 959
    .line 960
    move-result-object v4

    .line 961
    invoke-static {v4}, Len0/g;->a(Ljava/lang/String;)Lss0/a;

    .line 962
    .line 963
    .line 964
    move-result-object v30

    .line 965
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 966
    .line 967
    .line 968
    move-result-object v4

    .line 969
    invoke-static {v4}, Len0/g;->b(Ljava/lang/String;)Lss0/t;

    .line 970
    .line 971
    .line 972
    move-result-object v31

    .line 973
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 974
    .line 975
    .line 976
    move-result v4

    .line 977
    if-eqz v4, :cond_21

    .line 978
    .line 979
    move-object v4, v2

    .line 980
    goto :goto_1e

    .line 981
    :cond_21
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 982
    .line 983
    .line 984
    move-result-object v4

    .line 985
    :goto_1e
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 986
    .line 987
    .line 988
    move-result-object v32

    .line 989
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 990
    .line 991
    .line 992
    move-result v4

    .line 993
    if-eqz v4, :cond_22

    .line 994
    .line 995
    move-object v4, v2

    .line 996
    goto :goto_1f

    .line 997
    :cond_22
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 998
    .line 999
    .line 1000
    move-result-object v4

    .line 1001
    :goto_1f
    invoke-static {v4}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v33

    .line 1005
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 1006
    .line 1007
    .line 1008
    move-result v4

    .line 1009
    if-eqz v4, :cond_2d

    .line 1010
    .line 1011
    move/from16 v4, v23

    .line 1012
    .line 1013
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1014
    .line 1015
    .line 1016
    move-result v5

    .line 1017
    if-eqz v5, :cond_2c

    .line 1018
    .line 1019
    move/from16 v5, v22

    .line 1020
    .line 1021
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1022
    .line 1023
    .line 1024
    move-result v6

    .line 1025
    if-eqz v6, :cond_2b

    .line 1026
    .line 1027
    move/from16 v6, p0

    .line 1028
    .line 1029
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 1030
    .line 1031
    .line 1032
    move-result v7

    .line 1033
    if-eqz v7, :cond_2a

    .line 1034
    .line 1035
    move/from16 v7, p1

    .line 1036
    .line 1037
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1038
    .line 1039
    .line 1040
    move-result v8

    .line 1041
    if-eqz v8, :cond_29

    .line 1042
    .line 1043
    move/from16 v8, v16

    .line 1044
    .line 1045
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1046
    .line 1047
    .line 1048
    move-result v9

    .line 1049
    if-eqz v9, :cond_28

    .line 1050
    .line 1051
    move/from16 v9, v17

    .line 1052
    .line 1053
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 1054
    .line 1055
    .line 1056
    move-result v10

    .line 1057
    if-eqz v10, :cond_27

    .line 1058
    .line 1059
    move/from16 v10, v18

    .line 1060
    .line 1061
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 1062
    .line 1063
    .line 1064
    move-result v11

    .line 1065
    if-eqz v11, :cond_26

    .line 1066
    .line 1067
    move/from16 v11, v19

    .line 1068
    .line 1069
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 1070
    .line 1071
    .line 1072
    move-result v13

    .line 1073
    if-eqz v13, :cond_25

    .line 1074
    .line 1075
    move/from16 v13, v20

    .line 1076
    .line 1077
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 1078
    .line 1079
    .line 1080
    move-result v14

    .line 1081
    if-eqz v14, :cond_24

    .line 1082
    .line 1083
    move/from16 v14, v21

    .line 1084
    .line 1085
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 1086
    .line 1087
    .line 1088
    move-result v16

    .line 1089
    if-nez v16, :cond_23

    .line 1090
    .line 1091
    goto :goto_27

    .line 1092
    :cond_23
    move-object/from16 v34, v2

    .line 1093
    .line 1094
    goto/16 :goto_34

    .line 1095
    .line 1096
    :cond_24
    :goto_20
    move/from16 v14, v21

    .line 1097
    .line 1098
    goto :goto_27

    .line 1099
    :cond_25
    :goto_21
    move/from16 v13, v20

    .line 1100
    .line 1101
    goto :goto_20

    .line 1102
    :cond_26
    :goto_22
    move/from16 v11, v19

    .line 1103
    .line 1104
    goto :goto_21

    .line 1105
    :cond_27
    :goto_23
    move/from16 v10, v18

    .line 1106
    .line 1107
    goto :goto_22

    .line 1108
    :cond_28
    :goto_24
    move/from16 v9, v17

    .line 1109
    .line 1110
    goto :goto_23

    .line 1111
    :cond_29
    :goto_25
    move/from16 v8, v16

    .line 1112
    .line 1113
    goto :goto_24

    .line 1114
    :cond_2a
    :goto_26
    move/from16 v7, p1

    .line 1115
    .line 1116
    goto :goto_25

    .line 1117
    :cond_2b
    move/from16 v6, p0

    .line 1118
    .line 1119
    goto :goto_26

    .line 1120
    :cond_2c
    move/from16 v6, p0

    .line 1121
    .line 1122
    move/from16 v7, p1

    .line 1123
    .line 1124
    move/from16 v8, v16

    .line 1125
    .line 1126
    move/from16 v9, v17

    .line 1127
    .line 1128
    move/from16 v10, v18

    .line 1129
    .line 1130
    move/from16 v11, v19

    .line 1131
    .line 1132
    move/from16 v13, v20

    .line 1133
    .line 1134
    move/from16 v14, v21

    .line 1135
    .line 1136
    move/from16 v5, v22

    .line 1137
    .line 1138
    goto :goto_27

    .line 1139
    :cond_2d
    move/from16 v6, p0

    .line 1140
    .line 1141
    move/from16 v7, p1

    .line 1142
    .line 1143
    move/from16 v8, v16

    .line 1144
    .line 1145
    move/from16 v9, v17

    .line 1146
    .line 1147
    move/from16 v10, v18

    .line 1148
    .line 1149
    move/from16 v11, v19

    .line 1150
    .line 1151
    move/from16 v13, v20

    .line 1152
    .line 1153
    move/from16 v14, v21

    .line 1154
    .line 1155
    move/from16 v5, v22

    .line 1156
    .line 1157
    move/from16 v4, v23

    .line 1158
    .line 1159
    :goto_27
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 1160
    .line 1161
    .line 1162
    move-result v16

    .line 1163
    if-eqz v16, :cond_2e

    .line 1164
    .line 1165
    move-object/from16 v35, v2

    .line 1166
    .line 1167
    goto :goto_28

    .line 1168
    :cond_2e
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v12

    .line 1172
    move-object/from16 v35, v12

    .line 1173
    .line 1174
    :goto_28
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1175
    .line 1176
    .line 1177
    move-result v12

    .line 1178
    if-eqz v12, :cond_2f

    .line 1179
    .line 1180
    move-object/from16 v36, v2

    .line 1181
    .line 1182
    goto :goto_29

    .line 1183
    :cond_2f
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v4

    .line 1187
    move-object/from16 v36, v4

    .line 1188
    .line 1189
    :goto_29
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1190
    .line 1191
    .line 1192
    move-result v4

    .line 1193
    if-eqz v4, :cond_30

    .line 1194
    .line 1195
    move-object/from16 v37, v2

    .line 1196
    .line 1197
    goto :goto_2a

    .line 1198
    :cond_30
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1199
    .line 1200
    .line 1201
    move-result-object v4

    .line 1202
    move-object/from16 v37, v4

    .line 1203
    .line 1204
    :goto_2a
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 1205
    .line 1206
    .line 1207
    move-result v4

    .line 1208
    if-eqz v4, :cond_31

    .line 1209
    .line 1210
    move-object/from16 v38, v2

    .line 1211
    .line 1212
    goto :goto_2b

    .line 1213
    :cond_31
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1214
    .line 1215
    .line 1216
    move-result-object v4

    .line 1217
    move-object/from16 v38, v4

    .line 1218
    .line 1219
    :goto_2b
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1220
    .line 1221
    .line 1222
    move-result v4

    .line 1223
    if-eqz v4, :cond_32

    .line 1224
    .line 1225
    move-object/from16 v39, v2

    .line 1226
    .line 1227
    goto :goto_2c

    .line 1228
    :cond_32
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1229
    .line 1230
    .line 1231
    move-result-object v4

    .line 1232
    move-object/from16 v39, v4

    .line 1233
    .line 1234
    :goto_2c
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1235
    .line 1236
    .line 1237
    move-result v4

    .line 1238
    if-eqz v4, :cond_33

    .line 1239
    .line 1240
    move-object/from16 v40, v2

    .line 1241
    .line 1242
    goto :goto_2d

    .line 1243
    :cond_33
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 1244
    .line 1245
    .line 1246
    move-result-wide v4

    .line 1247
    long-to-int v4, v4

    .line 1248
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v4

    .line 1252
    move-object/from16 v40, v4

    .line 1253
    .line 1254
    :goto_2d
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 1255
    .line 1256
    .line 1257
    move-result v4

    .line 1258
    if-eqz v4, :cond_34

    .line 1259
    .line 1260
    move-object/from16 v41, v2

    .line 1261
    .line 1262
    goto :goto_2e

    .line 1263
    :cond_34
    invoke-interface {v3, v9}, Lua/c;->getLong(I)J

    .line 1264
    .line 1265
    .line 1266
    move-result-wide v4

    .line 1267
    long-to-int v4, v4

    .line 1268
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1269
    .line 1270
    .line 1271
    move-result-object v4

    .line 1272
    move-object/from16 v41, v4

    .line 1273
    .line 1274
    :goto_2e
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 1275
    .line 1276
    .line 1277
    move-result v4

    .line 1278
    if-eqz v4, :cond_35

    .line 1279
    .line 1280
    move-object/from16 v42, v2

    .line 1281
    .line 1282
    goto :goto_2f

    .line 1283
    :cond_35
    invoke-interface {v3, v10}, Lua/c;->getLong(I)J

    .line 1284
    .line 1285
    .line 1286
    move-result-wide v4

    .line 1287
    long-to-int v4, v4

    .line 1288
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v4

    .line 1292
    move-object/from16 v42, v4

    .line 1293
    .line 1294
    :goto_2f
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 1295
    .line 1296
    .line 1297
    move-result v4

    .line 1298
    if-eqz v4, :cond_36

    .line 1299
    .line 1300
    move-object/from16 v43, v2

    .line 1301
    .line 1302
    goto :goto_30

    .line 1303
    :cond_36
    invoke-interface {v3, v11}, Lua/c;->getDouble(I)D

    .line 1304
    .line 1305
    .line 1306
    move-result-wide v4

    .line 1307
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1308
    .line 1309
    .line 1310
    move-result-object v4

    .line 1311
    move-object/from16 v43, v4

    .line 1312
    .line 1313
    :goto_30
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 1314
    .line 1315
    .line 1316
    move-result v4

    .line 1317
    if-eqz v4, :cond_37

    .line 1318
    .line 1319
    move-object/from16 v44, v2

    .line 1320
    .line 1321
    goto :goto_31

    .line 1322
    :cond_37
    invoke-interface {v3, v13}, Lua/c;->getDouble(I)D

    .line 1323
    .line 1324
    .line 1325
    move-result-wide v4

    .line 1326
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v4

    .line 1330
    move-object/from16 v44, v4

    .line 1331
    .line 1332
    :goto_31
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 1333
    .line 1334
    .line 1335
    move-result v4

    .line 1336
    if-eqz v4, :cond_38

    .line 1337
    .line 1338
    :goto_32
    move-object/from16 v45, v2

    .line 1339
    .line 1340
    goto :goto_33

    .line 1341
    :cond_38
    invoke-interface {v3, v14}, Lua/c;->getDouble(I)D

    .line 1342
    .line 1343
    .line 1344
    move-result-wide v4

    .line 1345
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1346
    .line 1347
    .line 1348
    move-result-object v2

    .line 1349
    goto :goto_32

    .line 1350
    :goto_33
    new-instance v34, Len0/j;

    .line 1351
    .line 1352
    invoke-direct/range {v34 .. v45}, Len0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V

    .line 1353
    .line 1354
    .line 1355
    :goto_34
    new-instance v24, Len0/i;

    .line 1356
    .line 1357
    move/from16 v29, v0

    .line 1358
    .line 1359
    invoke-direct/range {v24 .. v34}, Len0/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILss0/a;Lss0/t;Ljava/time/LocalDate;Ljava/time/LocalDate;Len0/j;)V

    .line 1360
    .line 1361
    .line 1362
    move-object/from16 v0, v24

    .line 1363
    .line 1364
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1365
    .line 1366
    .line 1367
    move-result-object v1

    .line 1368
    invoke-static {v15, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v1

    .line 1372
    const-string v2, "getValue(...)"

    .line 1373
    .line 1374
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1375
    .line 1376
    .line 1377
    check-cast v1, Ljava/util/List;

    .line 1378
    .line 1379
    new-instance v2, Len0/h;

    .line 1380
    .line 1381
    invoke-direct {v2, v0, v1}, Len0/h;-><init>(Len0/i;Ljava/util/List;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1382
    .line 1383
    .line 1384
    :cond_39
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 1385
    .line 1386
    .line 1387
    return-object v2

    .line 1388
    :goto_35
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 1389
    .line 1390
    .line 1391
    throw v0

    .line 1392
    nop

    .line 1393
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
