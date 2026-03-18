.class public final synthetic Len0/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Len0/g;


# direct methods
.method public synthetic constructor <init>(Len0/g;I)V
    .locals 0

    .line 1
    iput p2, p0, Len0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Len0/f;->e:Len0/g;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 47

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Len0/f;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Len0/f;->e:Len0/g;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object/from16 v1, p1

    .line 11
    .line 12
    check-cast v1, Lua/a;

    .line 13
    .line 14
    const-string v2, "_connection"

    .line 15
    .line 16
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v2, "SELECT * FROM ordered_vehicle"

    .line 20
    .line 21
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    :try_start_0
    const-string v3, "commissionId"

    .line 26
    .line 27
    invoke-static {v2, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    const-string v4, "name"

    .line 32
    .line 33
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    const-string v5, "vin"

    .line 38
    .line 39
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    const-string v6, "dealerId"

    .line 44
    .line 45
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    const-string v7, "priority"

    .line 50
    .line 51
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    const-string v8, "activationStatus"

    .line 56
    .line 57
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    const-string v9, "orderStatus"

    .line 62
    .line 63
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v9

    .line 67
    const-string v10, "startDeliveryDate"

    .line 68
    .line 69
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    const-string v11, "endDeliveryDate"

    .line 74
    .line 75
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v11

    .line 79
    const-string v12, "spec_model"

    .line 80
    .line 81
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v12

    .line 85
    const-string v13, "spec_trimLevel"

    .line 86
    .line 87
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v13

    .line 91
    const-string v14, "spec_engine"

    .line 92
    .line 93
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v14

    .line 97
    const-string v15, "spec_exteriorColor"

    .line 98
    .line 99
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v15

    .line 103
    move/from16 p0, v15

    .line 104
    .line 105
    const-string v15, "spec_interiorColor"

    .line 106
    .line 107
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 108
    .line 109
    .line 110
    move-result v15

    .line 111
    move/from16 p1, v15

    .line 112
    .line 113
    const-string v15, "spec_batteryCapacity"

    .line 114
    .line 115
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 116
    .line 117
    .line 118
    move-result v15

    .line 119
    move/from16 v16, v15

    .line 120
    .line 121
    const-string v15, "spec_maxPerformanceInKW"

    .line 122
    .line 123
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 124
    .line 125
    .line 126
    move-result v15

    .line 127
    move/from16 v17, v15

    .line 128
    .line 129
    const-string v15, "spec_wltpRangeInM"

    .line 130
    .line 131
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 132
    .line 133
    .line 134
    move-result v15

    .line 135
    move/from16 v18, v15

    .line 136
    .line 137
    const-string v15, "spec_consumptionInLitPer100km"

    .line 138
    .line 139
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 140
    .line 141
    .line 142
    move-result v15

    .line 143
    move/from16 v19, v15

    .line 144
    .line 145
    const-string v15, "spec_consumptionInkWhPer100km"

    .line 146
    .line 147
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    move-result v15

    .line 151
    move/from16 v20, v15

    .line 152
    .line 153
    const-string v15, "spec_consumptionInKgPer100km"

    .line 154
    .line 155
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 156
    .line 157
    .line 158
    move-result v15

    .line 159
    move/from16 v21, v15

    .line 160
    .line 161
    new-instance v15, Landroidx/collection/f;

    .line 162
    .line 163
    move/from16 v22, v14

    .line 164
    .line 165
    const/4 v14, 0x0

    .line 166
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 167
    .line 168
    .line 169
    :cond_0
    :goto_0
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 170
    .line 171
    .line 172
    move-result v14

    .line 173
    if-eqz v14, :cond_1

    .line 174
    .line 175
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 176
    .line 177
    .line 178
    move-result-object v14

    .line 179
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 180
    .line 181
    .line 182
    move-result v23

    .line 183
    if-nez v23, :cond_0

    .line 184
    .line 185
    move/from16 v23, v13

    .line 186
    .line 187
    new-instance v13, Ljava/util/ArrayList;

    .line 188
    .line 189
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 190
    .line 191
    .line 192
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move/from16 v13, v23

    .line 196
    .line 197
    goto :goto_0

    .line 198
    :catchall_0
    move-exception v0

    .line 199
    goto/16 :goto_1b

    .line 200
    .line 201
    :cond_1
    move/from16 v23, v13

    .line 202
    .line 203
    invoke-interface {v2}, Lua/c;->reset()V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v0, v1, v15}, Len0/g;->c(Lua/a;Landroidx/collection/f;)V

    .line 207
    .line 208
    .line 209
    new-instance v0, Ljava/util/ArrayList;

    .line 210
    .line 211
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 212
    .line 213
    .line 214
    :goto_1
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 215
    .line 216
    .line 217
    move-result v1

    .line 218
    if-eqz v1, :cond_1c

    .line 219
    .line 220
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v25

    .line 224
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v26

    .line 228
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 229
    .line 230
    .line 231
    move-result v1

    .line 232
    if-eqz v1, :cond_2

    .line 233
    .line 234
    const/16 v27, 0x0

    .line 235
    .line 236
    goto :goto_2

    .line 237
    :cond_2
    invoke-interface {v2, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object v1

    .line 241
    move-object/from16 v27, v1

    .line 242
    .line 243
    :goto_2
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 244
    .line 245
    .line 246
    move-result v1

    .line 247
    if-eqz v1, :cond_3

    .line 248
    .line 249
    const/16 v28, 0x0

    .line 250
    .line 251
    goto :goto_3

    .line 252
    :cond_3
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    move-object/from16 v28, v1

    .line 257
    .line 258
    :goto_3
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 259
    .line 260
    .line 261
    move-result-wide v13

    .line 262
    long-to-int v13, v13

    .line 263
    invoke-interface {v2, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v14

    .line 267
    invoke-static {v14}, Len0/g;->a(Ljava/lang/String;)Lss0/a;

    .line 268
    .line 269
    .line 270
    move-result-object v30

    .line 271
    invoke-interface {v2, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v14

    .line 275
    invoke-static {v14}, Len0/g;->b(Ljava/lang/String;)Lss0/t;

    .line 276
    .line 277
    .line 278
    move-result-object v31

    .line 279
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 280
    .line 281
    .line 282
    move-result v14

    .line 283
    if-eqz v14, :cond_4

    .line 284
    .line 285
    const/4 v14, 0x0

    .line 286
    goto :goto_4

    .line 287
    :cond_4
    invoke-interface {v2, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v14

    .line 291
    :goto_4
    invoke-static {v14}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 292
    .line 293
    .line 294
    move-result-object v32

    .line 295
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 296
    .line 297
    .line 298
    move-result v14

    .line 299
    if-eqz v14, :cond_5

    .line 300
    .line 301
    const/4 v14, 0x0

    .line 302
    goto :goto_5

    .line 303
    :cond_5
    invoke-interface {v2, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 304
    .line 305
    .line 306
    move-result-object v14

    .line 307
    :goto_5
    invoke-static {v14}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 308
    .line 309
    .line 310
    move-result-object v33

    .line 311
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 312
    .line 313
    .line 314
    move-result v14

    .line 315
    if-eqz v14, :cond_10

    .line 316
    .line 317
    move/from16 v14, v23

    .line 318
    .line 319
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 320
    .line 321
    .line 322
    move-result v23

    .line 323
    if-eqz v23, :cond_f

    .line 324
    .line 325
    move/from16 v1, v22

    .line 326
    .line 327
    invoke-interface {v2, v1}, Lua/c;->isNull(I)Z

    .line 328
    .line 329
    .line 330
    move-result v22

    .line 331
    if-eqz v22, :cond_e

    .line 332
    .line 333
    move/from16 v22, v4

    .line 334
    .line 335
    move/from16 v4, p0

    .line 336
    .line 337
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 338
    .line 339
    .line 340
    move-result v24

    .line 341
    if-eqz v24, :cond_d

    .line 342
    .line 343
    move/from16 p0, v5

    .line 344
    .line 345
    move/from16 v5, p1

    .line 346
    .line 347
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 348
    .line 349
    .line 350
    move-result v24

    .line 351
    if-eqz v24, :cond_c

    .line 352
    .line 353
    move/from16 p1, v6

    .line 354
    .line 355
    move/from16 v6, v16

    .line 356
    .line 357
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 358
    .line 359
    .line 360
    move-result v16

    .line 361
    if-eqz v16, :cond_b

    .line 362
    .line 363
    move/from16 v16, v7

    .line 364
    .line 365
    move/from16 v7, v17

    .line 366
    .line 367
    invoke-interface {v2, v7}, Lua/c;->isNull(I)Z

    .line 368
    .line 369
    .line 370
    move-result v17

    .line 371
    if-eqz v17, :cond_a

    .line 372
    .line 373
    move/from16 v17, v8

    .line 374
    .line 375
    move/from16 v8, v18

    .line 376
    .line 377
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 378
    .line 379
    .line 380
    move-result v18

    .line 381
    if-eqz v18, :cond_9

    .line 382
    .line 383
    move/from16 v18, v9

    .line 384
    .line 385
    move/from16 v9, v19

    .line 386
    .line 387
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 388
    .line 389
    .line 390
    move-result v19

    .line 391
    if-eqz v19, :cond_8

    .line 392
    .line 393
    move/from16 v19, v10

    .line 394
    .line 395
    move/from16 v10, v20

    .line 396
    .line 397
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 398
    .line 399
    .line 400
    move-result v20

    .line 401
    if-eqz v20, :cond_7

    .line 402
    .line 403
    move/from16 v20, v11

    .line 404
    .line 405
    move/from16 v11, v21

    .line 406
    .line 407
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 408
    .line 409
    .line 410
    move-result v21

    .line 411
    if-nez v21, :cond_6

    .line 412
    .line 413
    goto :goto_e

    .line 414
    :cond_6
    move/from16 v21, v4

    .line 415
    .line 416
    move/from16 v46, v5

    .line 417
    .line 418
    const/16 v34, 0x0

    .line 419
    .line 420
    goto/16 :goto_1a

    .line 421
    .line 422
    :cond_7
    :goto_6
    move/from16 v20, v11

    .line 423
    .line 424
    move/from16 v11, v21

    .line 425
    .line 426
    goto :goto_e

    .line 427
    :cond_8
    :goto_7
    move/from16 v19, v10

    .line 428
    .line 429
    move/from16 v10, v20

    .line 430
    .line 431
    goto :goto_6

    .line 432
    :cond_9
    :goto_8
    move/from16 v18, v9

    .line 433
    .line 434
    move/from16 v9, v19

    .line 435
    .line 436
    goto :goto_7

    .line 437
    :cond_a
    :goto_9
    move/from16 v17, v8

    .line 438
    .line 439
    move/from16 v8, v18

    .line 440
    .line 441
    goto :goto_8

    .line 442
    :cond_b
    :goto_a
    move/from16 v16, v7

    .line 443
    .line 444
    move/from16 v7, v17

    .line 445
    .line 446
    goto :goto_9

    .line 447
    :cond_c
    :goto_b
    move/from16 p1, v6

    .line 448
    .line 449
    move/from16 v6, v16

    .line 450
    .line 451
    goto :goto_a

    .line 452
    :cond_d
    :goto_c
    move/from16 p0, v5

    .line 453
    .line 454
    move/from16 v5, p1

    .line 455
    .line 456
    goto :goto_b

    .line 457
    :cond_e
    :goto_d
    move/from16 v22, v4

    .line 458
    .line 459
    move/from16 v4, p0

    .line 460
    .line 461
    goto :goto_c

    .line 462
    :cond_f
    move/from16 v1, v22

    .line 463
    .line 464
    goto :goto_d

    .line 465
    :cond_10
    move/from16 v1, v22

    .line 466
    .line 467
    move/from16 v14, v23

    .line 468
    .line 469
    goto :goto_d

    .line 470
    :goto_e
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 471
    .line 472
    .line 473
    move-result v21

    .line 474
    if-eqz v21, :cond_11

    .line 475
    .line 476
    const/16 v35, 0x0

    .line 477
    .line 478
    goto :goto_f

    .line 479
    :cond_11
    invoke-interface {v2, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 480
    .line 481
    .line 482
    move-result-object v21

    .line 483
    move-object/from16 v35, v21

    .line 484
    .line 485
    :goto_f
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 486
    .line 487
    .line 488
    move-result v21

    .line 489
    if-eqz v21, :cond_12

    .line 490
    .line 491
    const/16 v36, 0x0

    .line 492
    .line 493
    goto :goto_10

    .line 494
    :cond_12
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 495
    .line 496
    .line 497
    move-result-object v21

    .line 498
    move-object/from16 v36, v21

    .line 499
    .line 500
    :goto_10
    invoke-interface {v2, v1}, Lua/c;->isNull(I)Z

    .line 501
    .line 502
    .line 503
    move-result v21

    .line 504
    if-eqz v21, :cond_13

    .line 505
    .line 506
    const/16 v37, 0x0

    .line 507
    .line 508
    goto :goto_11

    .line 509
    :cond_13
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 510
    .line 511
    .line 512
    move-result-object v21

    .line 513
    move-object/from16 v37, v21

    .line 514
    .line 515
    :goto_11
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 516
    .line 517
    .line 518
    move-result v21

    .line 519
    if-eqz v21, :cond_14

    .line 520
    .line 521
    const/16 v38, 0x0

    .line 522
    .line 523
    goto :goto_12

    .line 524
    :cond_14
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 525
    .line 526
    .line 527
    move-result-object v21

    .line 528
    move-object/from16 v38, v21

    .line 529
    .line 530
    :goto_12
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 531
    .line 532
    .line 533
    move-result v21

    .line 534
    if-eqz v21, :cond_15

    .line 535
    .line 536
    const/16 v39, 0x0

    .line 537
    .line 538
    goto :goto_13

    .line 539
    :cond_15
    invoke-interface {v2, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 540
    .line 541
    .line 542
    move-result-object v21

    .line 543
    move-object/from16 v39, v21

    .line 544
    .line 545
    :goto_13
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 546
    .line 547
    .line 548
    move-result v21

    .line 549
    if-eqz v21, :cond_16

    .line 550
    .line 551
    move/from16 v21, v4

    .line 552
    .line 553
    move/from16 v46, v5

    .line 554
    .line 555
    const/16 v40, 0x0

    .line 556
    .line 557
    goto :goto_14

    .line 558
    :cond_16
    move/from16 v21, v4

    .line 559
    .line 560
    move/from16 v46, v5

    .line 561
    .line 562
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 563
    .line 564
    .line 565
    move-result-wide v4

    .line 566
    long-to-int v4, v4

    .line 567
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 568
    .line 569
    .line 570
    move-result-object v4

    .line 571
    move-object/from16 v40, v4

    .line 572
    .line 573
    :goto_14
    invoke-interface {v2, v7}, Lua/c;->isNull(I)Z

    .line 574
    .line 575
    .line 576
    move-result v4

    .line 577
    if-eqz v4, :cond_17

    .line 578
    .line 579
    const/16 v41, 0x0

    .line 580
    .line 581
    goto :goto_15

    .line 582
    :cond_17
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 583
    .line 584
    .line 585
    move-result-wide v4

    .line 586
    long-to-int v4, v4

    .line 587
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 588
    .line 589
    .line 590
    move-result-object v4

    .line 591
    move-object/from16 v41, v4

    .line 592
    .line 593
    :goto_15
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 594
    .line 595
    .line 596
    move-result v4

    .line 597
    if-eqz v4, :cond_18

    .line 598
    .line 599
    const/16 v42, 0x0

    .line 600
    .line 601
    goto :goto_16

    .line 602
    :cond_18
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 603
    .line 604
    .line 605
    move-result-wide v4

    .line 606
    long-to-int v4, v4

    .line 607
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 608
    .line 609
    .line 610
    move-result-object v4

    .line 611
    move-object/from16 v42, v4

    .line 612
    .line 613
    :goto_16
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 614
    .line 615
    .line 616
    move-result v4

    .line 617
    if-eqz v4, :cond_19

    .line 618
    .line 619
    const/16 v43, 0x0

    .line 620
    .line 621
    goto :goto_17

    .line 622
    :cond_19
    invoke-interface {v2, v9}, Lua/c;->getDouble(I)D

    .line 623
    .line 624
    .line 625
    move-result-wide v4

    .line 626
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 627
    .line 628
    .line 629
    move-result-object v4

    .line 630
    move-object/from16 v43, v4

    .line 631
    .line 632
    :goto_17
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 633
    .line 634
    .line 635
    move-result v4

    .line 636
    if-eqz v4, :cond_1a

    .line 637
    .line 638
    const/16 v44, 0x0

    .line 639
    .line 640
    goto :goto_18

    .line 641
    :cond_1a
    invoke-interface {v2, v10}, Lua/c;->getDouble(I)D

    .line 642
    .line 643
    .line 644
    move-result-wide v4

    .line 645
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 646
    .line 647
    .line 648
    move-result-object v4

    .line 649
    move-object/from16 v44, v4

    .line 650
    .line 651
    :goto_18
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 652
    .line 653
    .line 654
    move-result v4

    .line 655
    if-eqz v4, :cond_1b

    .line 656
    .line 657
    const/16 v45, 0x0

    .line 658
    .line 659
    goto :goto_19

    .line 660
    :cond_1b
    invoke-interface {v2, v11}, Lua/c;->getDouble(I)D

    .line 661
    .line 662
    .line 663
    move-result-wide v4

    .line 664
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 665
    .line 666
    .line 667
    move-result-object v4

    .line 668
    move-object/from16 v45, v4

    .line 669
    .line 670
    :goto_19
    new-instance v34, Len0/j;

    .line 671
    .line 672
    invoke-direct/range {v34 .. v45}, Len0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V

    .line 673
    .line 674
    .line 675
    :goto_1a
    new-instance v24, Len0/i;

    .line 676
    .line 677
    move/from16 v29, v13

    .line 678
    .line 679
    invoke-direct/range {v24 .. v34}, Len0/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILss0/a;Lss0/t;Ljava/time/LocalDate;Ljava/time/LocalDate;Len0/j;)V

    .line 680
    .line 681
    .line 682
    move-object/from16 v4, v24

    .line 683
    .line 684
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 685
    .line 686
    .line 687
    move-result-object v5

    .line 688
    invoke-static {v15, v5}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 689
    .line 690
    .line 691
    move-result-object v5

    .line 692
    const-string v13, "getValue(...)"

    .line 693
    .line 694
    invoke-static {v5, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 695
    .line 696
    .line 697
    check-cast v5, Ljava/util/List;

    .line 698
    .line 699
    new-instance v13, Len0/h;

    .line 700
    .line 701
    invoke-direct {v13, v4, v5}, Len0/h;-><init>(Len0/i;Ljava/util/List;)V

    .line 702
    .line 703
    .line 704
    invoke-virtual {v0, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 705
    .line 706
    .line 707
    move/from16 v5, p0

    .line 708
    .line 709
    move/from16 v23, v14

    .line 710
    .line 711
    move/from16 p0, v21

    .line 712
    .line 713
    move/from16 v4, v22

    .line 714
    .line 715
    move/from16 v22, v1

    .line 716
    .line 717
    move/from16 v21, v11

    .line 718
    .line 719
    move/from16 v11, v20

    .line 720
    .line 721
    move/from16 v20, v10

    .line 722
    .line 723
    move/from16 v10, v19

    .line 724
    .line 725
    move/from16 v19, v9

    .line 726
    .line 727
    move/from16 v9, v18

    .line 728
    .line 729
    move/from16 v18, v8

    .line 730
    .line 731
    move/from16 v8, v17

    .line 732
    .line 733
    move/from16 v17, v7

    .line 734
    .line 735
    move/from16 v7, v16

    .line 736
    .line 737
    move/from16 v16, v6

    .line 738
    .line 739
    move/from16 v6, p1

    .line 740
    .line 741
    move/from16 p1, v46

    .line 742
    .line 743
    goto/16 :goto_1

    .line 744
    .line 745
    :cond_1c
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 746
    .line 747
    .line 748
    return-object v0

    .line 749
    :goto_1b
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 750
    .line 751
    .line 752
    throw v0

    .line 753
    :pswitch_0
    move-object/from16 v1, p1

    .line 754
    .line 755
    check-cast v1, Lua/a;

    .line 756
    .line 757
    const-string v2, "_connection"

    .line 758
    .line 759
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    const-string v2, "SELECT * FROM ordered_vehicle order by priority"

    .line 763
    .line 764
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 765
    .line 766
    .line 767
    move-result-object v2

    .line 768
    :try_start_1
    const-string v3, "commissionId"

    .line 769
    .line 770
    invoke-static {v2, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 771
    .line 772
    .line 773
    move-result v3

    .line 774
    const-string v4, "name"

    .line 775
    .line 776
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 777
    .line 778
    .line 779
    move-result v4

    .line 780
    const-string v5, "vin"

    .line 781
    .line 782
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 783
    .line 784
    .line 785
    move-result v5

    .line 786
    const-string v6, "dealerId"

    .line 787
    .line 788
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 789
    .line 790
    .line 791
    move-result v6

    .line 792
    const-string v7, "priority"

    .line 793
    .line 794
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 795
    .line 796
    .line 797
    move-result v7

    .line 798
    const-string v8, "activationStatus"

    .line 799
    .line 800
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 801
    .line 802
    .line 803
    move-result v8

    .line 804
    const-string v9, "orderStatus"

    .line 805
    .line 806
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 807
    .line 808
    .line 809
    move-result v9

    .line 810
    const-string v10, "startDeliveryDate"

    .line 811
    .line 812
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 813
    .line 814
    .line 815
    move-result v10

    .line 816
    const-string v11, "endDeliveryDate"

    .line 817
    .line 818
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 819
    .line 820
    .line 821
    move-result v11

    .line 822
    const-string v12, "spec_model"

    .line 823
    .line 824
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 825
    .line 826
    .line 827
    move-result v12

    .line 828
    const-string v13, "spec_trimLevel"

    .line 829
    .line 830
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 831
    .line 832
    .line 833
    move-result v13

    .line 834
    const-string v14, "spec_engine"

    .line 835
    .line 836
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 837
    .line 838
    .line 839
    move-result v14

    .line 840
    const-string v15, "spec_exteriorColor"

    .line 841
    .line 842
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 843
    .line 844
    .line 845
    move-result v15

    .line 846
    move/from16 p0, v15

    .line 847
    .line 848
    const-string v15, "spec_interiorColor"

    .line 849
    .line 850
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 851
    .line 852
    .line 853
    move-result v15

    .line 854
    move/from16 p1, v15

    .line 855
    .line 856
    const-string v15, "spec_batteryCapacity"

    .line 857
    .line 858
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 859
    .line 860
    .line 861
    move-result v15

    .line 862
    move/from16 v16, v15

    .line 863
    .line 864
    const-string v15, "spec_maxPerformanceInKW"

    .line 865
    .line 866
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 867
    .line 868
    .line 869
    move-result v15

    .line 870
    move/from16 v17, v15

    .line 871
    .line 872
    const-string v15, "spec_wltpRangeInM"

    .line 873
    .line 874
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 875
    .line 876
    .line 877
    move-result v15

    .line 878
    move/from16 v18, v15

    .line 879
    .line 880
    const-string v15, "spec_consumptionInLitPer100km"

    .line 881
    .line 882
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 883
    .line 884
    .line 885
    move-result v15

    .line 886
    move/from16 v19, v15

    .line 887
    .line 888
    const-string v15, "spec_consumptionInkWhPer100km"

    .line 889
    .line 890
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 891
    .line 892
    .line 893
    move-result v15

    .line 894
    move/from16 v20, v15

    .line 895
    .line 896
    const-string v15, "spec_consumptionInKgPer100km"

    .line 897
    .line 898
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 899
    .line 900
    .line 901
    move-result v15

    .line 902
    move/from16 v21, v15

    .line 903
    .line 904
    new-instance v15, Landroidx/collection/f;

    .line 905
    .line 906
    move/from16 v22, v14

    .line 907
    .line 908
    const/4 v14, 0x0

    .line 909
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 910
    .line 911
    .line 912
    :cond_1d
    :goto_1c
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 913
    .line 914
    .line 915
    move-result v14

    .line 916
    if-eqz v14, :cond_1e

    .line 917
    .line 918
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 919
    .line 920
    .line 921
    move-result-object v14

    .line 922
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 923
    .line 924
    .line 925
    move-result v23

    .line 926
    if-nez v23, :cond_1d

    .line 927
    .line 928
    move/from16 v23, v13

    .line 929
    .line 930
    new-instance v13, Ljava/util/ArrayList;

    .line 931
    .line 932
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 933
    .line 934
    .line 935
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 936
    .line 937
    .line 938
    move/from16 v13, v23

    .line 939
    .line 940
    goto :goto_1c

    .line 941
    :catchall_1
    move-exception v0

    .line 942
    goto/16 :goto_37

    .line 943
    .line 944
    :cond_1e
    move/from16 v23, v13

    .line 945
    .line 946
    invoke-interface {v2}, Lua/c;->reset()V

    .line 947
    .line 948
    .line 949
    invoke-virtual {v0, v1, v15}, Len0/g;->c(Lua/a;Landroidx/collection/f;)V

    .line 950
    .line 951
    .line 952
    new-instance v0, Ljava/util/ArrayList;

    .line 953
    .line 954
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 955
    .line 956
    .line 957
    :goto_1d
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 958
    .line 959
    .line 960
    move-result v1

    .line 961
    if-eqz v1, :cond_39

    .line 962
    .line 963
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 964
    .line 965
    .line 966
    move-result-object v25

    .line 967
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 968
    .line 969
    .line 970
    move-result-object v26

    .line 971
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 972
    .line 973
    .line 974
    move-result v1

    .line 975
    if-eqz v1, :cond_1f

    .line 976
    .line 977
    const/16 v27, 0x0

    .line 978
    .line 979
    goto :goto_1e

    .line 980
    :cond_1f
    invoke-interface {v2, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 981
    .line 982
    .line 983
    move-result-object v1

    .line 984
    move-object/from16 v27, v1

    .line 985
    .line 986
    :goto_1e
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 987
    .line 988
    .line 989
    move-result v1

    .line 990
    if-eqz v1, :cond_20

    .line 991
    .line 992
    const/16 v28, 0x0

    .line 993
    .line 994
    goto :goto_1f

    .line 995
    :cond_20
    invoke-interface {v2, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 996
    .line 997
    .line 998
    move-result-object v1

    .line 999
    move-object/from16 v28, v1

    .line 1000
    .line 1001
    :goto_1f
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 1002
    .line 1003
    .line 1004
    move-result-wide v13

    .line 1005
    long-to-int v13, v13

    .line 1006
    invoke-interface {v2, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v14

    .line 1010
    invoke-static {v14}, Len0/g;->a(Ljava/lang/String;)Lss0/a;

    .line 1011
    .line 1012
    .line 1013
    move-result-object v30

    .line 1014
    invoke-interface {v2, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1015
    .line 1016
    .line 1017
    move-result-object v14

    .line 1018
    invoke-static {v14}, Len0/g;->b(Ljava/lang/String;)Lss0/t;

    .line 1019
    .line 1020
    .line 1021
    move-result-object v31

    .line 1022
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 1023
    .line 1024
    .line 1025
    move-result v14

    .line 1026
    if-eqz v14, :cond_21

    .line 1027
    .line 1028
    const/4 v14, 0x0

    .line 1029
    goto :goto_20

    .line 1030
    :cond_21
    invoke-interface {v2, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v14

    .line 1034
    :goto_20
    invoke-static {v14}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 1035
    .line 1036
    .line 1037
    move-result-object v32

    .line 1038
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 1039
    .line 1040
    .line 1041
    move-result v14

    .line 1042
    if-eqz v14, :cond_22

    .line 1043
    .line 1044
    const/4 v14, 0x0

    .line 1045
    goto :goto_21

    .line 1046
    :cond_22
    invoke-interface {v2, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v14

    .line 1050
    :goto_21
    invoke-static {v14}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 1051
    .line 1052
    .line 1053
    move-result-object v33

    .line 1054
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1055
    .line 1056
    .line 1057
    move-result v14

    .line 1058
    if-eqz v14, :cond_2d

    .line 1059
    .line 1060
    move/from16 v14, v23

    .line 1061
    .line 1062
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1063
    .line 1064
    .line 1065
    move-result v23

    .line 1066
    if-eqz v23, :cond_2c

    .line 1067
    .line 1068
    move/from16 v1, v22

    .line 1069
    .line 1070
    invoke-interface {v2, v1}, Lua/c;->isNull(I)Z

    .line 1071
    .line 1072
    .line 1073
    move-result v22

    .line 1074
    if-eqz v22, :cond_2b

    .line 1075
    .line 1076
    move/from16 v22, v4

    .line 1077
    .line 1078
    move/from16 v4, p0

    .line 1079
    .line 1080
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 1081
    .line 1082
    .line 1083
    move-result v24

    .line 1084
    if-eqz v24, :cond_2a

    .line 1085
    .line 1086
    move/from16 p0, v5

    .line 1087
    .line 1088
    move/from16 v5, p1

    .line 1089
    .line 1090
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 1091
    .line 1092
    .line 1093
    move-result v24

    .line 1094
    if-eqz v24, :cond_29

    .line 1095
    .line 1096
    move/from16 p1, v6

    .line 1097
    .line 1098
    move/from16 v6, v16

    .line 1099
    .line 1100
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 1101
    .line 1102
    .line 1103
    move-result v16

    .line 1104
    if-eqz v16, :cond_28

    .line 1105
    .line 1106
    move/from16 v16, v7

    .line 1107
    .line 1108
    move/from16 v7, v17

    .line 1109
    .line 1110
    invoke-interface {v2, v7}, Lua/c;->isNull(I)Z

    .line 1111
    .line 1112
    .line 1113
    move-result v17

    .line 1114
    if-eqz v17, :cond_27

    .line 1115
    .line 1116
    move/from16 v17, v8

    .line 1117
    .line 1118
    move/from16 v8, v18

    .line 1119
    .line 1120
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 1121
    .line 1122
    .line 1123
    move-result v18

    .line 1124
    if-eqz v18, :cond_26

    .line 1125
    .line 1126
    move/from16 v18, v9

    .line 1127
    .line 1128
    move/from16 v9, v19

    .line 1129
    .line 1130
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 1131
    .line 1132
    .line 1133
    move-result v19

    .line 1134
    if-eqz v19, :cond_25

    .line 1135
    .line 1136
    move/from16 v19, v10

    .line 1137
    .line 1138
    move/from16 v10, v20

    .line 1139
    .line 1140
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 1141
    .line 1142
    .line 1143
    move-result v20

    .line 1144
    if-eqz v20, :cond_24

    .line 1145
    .line 1146
    move/from16 v20, v11

    .line 1147
    .line 1148
    move/from16 v11, v21

    .line 1149
    .line 1150
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 1151
    .line 1152
    .line 1153
    move-result v21

    .line 1154
    if-nez v21, :cond_23

    .line 1155
    .line 1156
    goto :goto_2a

    .line 1157
    :cond_23
    move/from16 v21, v4

    .line 1158
    .line 1159
    move/from16 v46, v5

    .line 1160
    .line 1161
    const/16 v34, 0x0

    .line 1162
    .line 1163
    goto/16 :goto_36

    .line 1164
    .line 1165
    :cond_24
    :goto_22
    move/from16 v20, v11

    .line 1166
    .line 1167
    move/from16 v11, v21

    .line 1168
    .line 1169
    goto :goto_2a

    .line 1170
    :cond_25
    :goto_23
    move/from16 v19, v10

    .line 1171
    .line 1172
    move/from16 v10, v20

    .line 1173
    .line 1174
    goto :goto_22

    .line 1175
    :cond_26
    :goto_24
    move/from16 v18, v9

    .line 1176
    .line 1177
    move/from16 v9, v19

    .line 1178
    .line 1179
    goto :goto_23

    .line 1180
    :cond_27
    :goto_25
    move/from16 v17, v8

    .line 1181
    .line 1182
    move/from16 v8, v18

    .line 1183
    .line 1184
    goto :goto_24

    .line 1185
    :cond_28
    :goto_26
    move/from16 v16, v7

    .line 1186
    .line 1187
    move/from16 v7, v17

    .line 1188
    .line 1189
    goto :goto_25

    .line 1190
    :cond_29
    :goto_27
    move/from16 p1, v6

    .line 1191
    .line 1192
    move/from16 v6, v16

    .line 1193
    .line 1194
    goto :goto_26

    .line 1195
    :cond_2a
    :goto_28
    move/from16 p0, v5

    .line 1196
    .line 1197
    move/from16 v5, p1

    .line 1198
    .line 1199
    goto :goto_27

    .line 1200
    :cond_2b
    :goto_29
    move/from16 v22, v4

    .line 1201
    .line 1202
    move/from16 v4, p0

    .line 1203
    .line 1204
    goto :goto_28

    .line 1205
    :cond_2c
    move/from16 v1, v22

    .line 1206
    .line 1207
    goto :goto_29

    .line 1208
    :cond_2d
    move/from16 v1, v22

    .line 1209
    .line 1210
    move/from16 v14, v23

    .line 1211
    .line 1212
    goto :goto_29

    .line 1213
    :goto_2a
    invoke-interface {v2, v12}, Lua/c;->isNull(I)Z

    .line 1214
    .line 1215
    .line 1216
    move-result v21

    .line 1217
    if-eqz v21, :cond_2e

    .line 1218
    .line 1219
    const/16 v35, 0x0

    .line 1220
    .line 1221
    goto :goto_2b

    .line 1222
    :cond_2e
    invoke-interface {v2, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1223
    .line 1224
    .line 1225
    move-result-object v21

    .line 1226
    move-object/from16 v35, v21

    .line 1227
    .line 1228
    :goto_2b
    invoke-interface {v2, v14}, Lua/c;->isNull(I)Z

    .line 1229
    .line 1230
    .line 1231
    move-result v21

    .line 1232
    if-eqz v21, :cond_2f

    .line 1233
    .line 1234
    const/16 v36, 0x0

    .line 1235
    .line 1236
    goto :goto_2c

    .line 1237
    :cond_2f
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1238
    .line 1239
    .line 1240
    move-result-object v21

    .line 1241
    move-object/from16 v36, v21

    .line 1242
    .line 1243
    :goto_2c
    invoke-interface {v2, v1}, Lua/c;->isNull(I)Z

    .line 1244
    .line 1245
    .line 1246
    move-result v21

    .line 1247
    if-eqz v21, :cond_30

    .line 1248
    .line 1249
    const/16 v37, 0x0

    .line 1250
    .line 1251
    goto :goto_2d

    .line 1252
    :cond_30
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1253
    .line 1254
    .line 1255
    move-result-object v21

    .line 1256
    move-object/from16 v37, v21

    .line 1257
    .line 1258
    :goto_2d
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 1259
    .line 1260
    .line 1261
    move-result v21

    .line 1262
    if-eqz v21, :cond_31

    .line 1263
    .line 1264
    const/16 v38, 0x0

    .line 1265
    .line 1266
    goto :goto_2e

    .line 1267
    :cond_31
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1268
    .line 1269
    .line 1270
    move-result-object v21

    .line 1271
    move-object/from16 v38, v21

    .line 1272
    .line 1273
    :goto_2e
    invoke-interface {v2, v5}, Lua/c;->isNull(I)Z

    .line 1274
    .line 1275
    .line 1276
    move-result v21

    .line 1277
    if-eqz v21, :cond_32

    .line 1278
    .line 1279
    const/16 v39, 0x0

    .line 1280
    .line 1281
    goto :goto_2f

    .line 1282
    :cond_32
    invoke-interface {v2, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1283
    .line 1284
    .line 1285
    move-result-object v21

    .line 1286
    move-object/from16 v39, v21

    .line 1287
    .line 1288
    :goto_2f
    invoke-interface {v2, v6}, Lua/c;->isNull(I)Z

    .line 1289
    .line 1290
    .line 1291
    move-result v21

    .line 1292
    if-eqz v21, :cond_33

    .line 1293
    .line 1294
    move/from16 v21, v4

    .line 1295
    .line 1296
    move/from16 v46, v5

    .line 1297
    .line 1298
    const/16 v40, 0x0

    .line 1299
    .line 1300
    goto :goto_30

    .line 1301
    :cond_33
    move/from16 v21, v4

    .line 1302
    .line 1303
    move/from16 v46, v5

    .line 1304
    .line 1305
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 1306
    .line 1307
    .line 1308
    move-result-wide v4

    .line 1309
    long-to-int v4, v4

    .line 1310
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v4

    .line 1314
    move-object/from16 v40, v4

    .line 1315
    .line 1316
    :goto_30
    invoke-interface {v2, v7}, Lua/c;->isNull(I)Z

    .line 1317
    .line 1318
    .line 1319
    move-result v4

    .line 1320
    if-eqz v4, :cond_34

    .line 1321
    .line 1322
    const/16 v41, 0x0

    .line 1323
    .line 1324
    goto :goto_31

    .line 1325
    :cond_34
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 1326
    .line 1327
    .line 1328
    move-result-wide v4

    .line 1329
    long-to-int v4, v4

    .line 1330
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v4

    .line 1334
    move-object/from16 v41, v4

    .line 1335
    .line 1336
    :goto_31
    invoke-interface {v2, v8}, Lua/c;->isNull(I)Z

    .line 1337
    .line 1338
    .line 1339
    move-result v4

    .line 1340
    if-eqz v4, :cond_35

    .line 1341
    .line 1342
    const/16 v42, 0x0

    .line 1343
    .line 1344
    goto :goto_32

    .line 1345
    :cond_35
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 1346
    .line 1347
    .line 1348
    move-result-wide v4

    .line 1349
    long-to-int v4, v4

    .line 1350
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1351
    .line 1352
    .line 1353
    move-result-object v4

    .line 1354
    move-object/from16 v42, v4

    .line 1355
    .line 1356
    :goto_32
    invoke-interface {v2, v9}, Lua/c;->isNull(I)Z

    .line 1357
    .line 1358
    .line 1359
    move-result v4

    .line 1360
    if-eqz v4, :cond_36

    .line 1361
    .line 1362
    const/16 v43, 0x0

    .line 1363
    .line 1364
    goto :goto_33

    .line 1365
    :cond_36
    invoke-interface {v2, v9}, Lua/c;->getDouble(I)D

    .line 1366
    .line 1367
    .line 1368
    move-result-wide v4

    .line 1369
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1370
    .line 1371
    .line 1372
    move-result-object v4

    .line 1373
    move-object/from16 v43, v4

    .line 1374
    .line 1375
    :goto_33
    invoke-interface {v2, v10}, Lua/c;->isNull(I)Z

    .line 1376
    .line 1377
    .line 1378
    move-result v4

    .line 1379
    if-eqz v4, :cond_37

    .line 1380
    .line 1381
    const/16 v44, 0x0

    .line 1382
    .line 1383
    goto :goto_34

    .line 1384
    :cond_37
    invoke-interface {v2, v10}, Lua/c;->getDouble(I)D

    .line 1385
    .line 1386
    .line 1387
    move-result-wide v4

    .line 1388
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1389
    .line 1390
    .line 1391
    move-result-object v4

    .line 1392
    move-object/from16 v44, v4

    .line 1393
    .line 1394
    :goto_34
    invoke-interface {v2, v11}, Lua/c;->isNull(I)Z

    .line 1395
    .line 1396
    .line 1397
    move-result v4

    .line 1398
    if-eqz v4, :cond_38

    .line 1399
    .line 1400
    const/16 v45, 0x0

    .line 1401
    .line 1402
    goto :goto_35

    .line 1403
    :cond_38
    invoke-interface {v2, v11}, Lua/c;->getDouble(I)D

    .line 1404
    .line 1405
    .line 1406
    move-result-wide v4

    .line 1407
    invoke-static {v4, v5}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v4

    .line 1411
    move-object/from16 v45, v4

    .line 1412
    .line 1413
    :goto_35
    new-instance v34, Len0/j;

    .line 1414
    .line 1415
    invoke-direct/range {v34 .. v45}, Len0/j;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Double;Ljava/lang/Double;Ljava/lang/Double;)V

    .line 1416
    .line 1417
    .line 1418
    :goto_36
    new-instance v24, Len0/i;

    .line 1419
    .line 1420
    move/from16 v29, v13

    .line 1421
    .line 1422
    invoke-direct/range {v24 .. v34}, Len0/i;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILss0/a;Lss0/t;Ljava/time/LocalDate;Ljava/time/LocalDate;Len0/j;)V

    .line 1423
    .line 1424
    .line 1425
    move-object/from16 v4, v24

    .line 1426
    .line 1427
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v5

    .line 1431
    invoke-static {v15, v5}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1432
    .line 1433
    .line 1434
    move-result-object v5

    .line 1435
    const-string v13, "getValue(...)"

    .line 1436
    .line 1437
    invoke-static {v5, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1438
    .line 1439
    .line 1440
    check-cast v5, Ljava/util/List;

    .line 1441
    .line 1442
    new-instance v13, Len0/h;

    .line 1443
    .line 1444
    invoke-direct {v13, v4, v5}, Len0/h;-><init>(Len0/i;Ljava/util/List;)V

    .line 1445
    .line 1446
    .line 1447
    invoke-virtual {v0, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1448
    .line 1449
    .line 1450
    move/from16 v5, p0

    .line 1451
    .line 1452
    move/from16 v23, v14

    .line 1453
    .line 1454
    move/from16 p0, v21

    .line 1455
    .line 1456
    move/from16 v4, v22

    .line 1457
    .line 1458
    move/from16 v22, v1

    .line 1459
    .line 1460
    move/from16 v21, v11

    .line 1461
    .line 1462
    move/from16 v11, v20

    .line 1463
    .line 1464
    move/from16 v20, v10

    .line 1465
    .line 1466
    move/from16 v10, v19

    .line 1467
    .line 1468
    move/from16 v19, v9

    .line 1469
    .line 1470
    move/from16 v9, v18

    .line 1471
    .line 1472
    move/from16 v18, v8

    .line 1473
    .line 1474
    move/from16 v8, v17

    .line 1475
    .line 1476
    move/from16 v17, v7

    .line 1477
    .line 1478
    move/from16 v7, v16

    .line 1479
    .line 1480
    move/from16 v16, v6

    .line 1481
    .line 1482
    move/from16 v6, p1

    .line 1483
    .line 1484
    move/from16 p1, v46

    .line 1485
    .line 1486
    goto/16 :goto_1d

    .line 1487
    .line 1488
    :cond_39
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1489
    .line 1490
    .line 1491
    return-object v0

    .line 1492
    :goto_37
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1493
    .line 1494
    .line 1495
    throw v0

    .line 1496
    nop

    .line 1497
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
