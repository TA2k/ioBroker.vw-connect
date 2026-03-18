.class public final synthetic Lif0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lif0/m;


# direct methods
.method public synthetic constructor <init>(Lif0/m;I)V
    .locals 0

    .line 1
    iput p2, p0, Lif0/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lif0/k;->e:Lif0/m;

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
    .locals 68

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lif0/k;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Lif0/k;->e:Lif0/m;

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
    const-string v2, "getValue(...)"

    .line 15
    .line 16
    const-string v3, "_connection"

    .line 17
    .line 18
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v3, "SELECT * FROM vehicle ORDER BY priority"

    .line 22
    .line 23
    invoke-interface {v1, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    :try_start_0
    const-string v4, "vin"

    .line 28
    .line 29
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v4

    .line 33
    const-string v5, "systemModelId"

    .line 34
    .line 35
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    const-string v6, "name"

    .line 40
    .line 41
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    const-string v7, "title"

    .line 46
    .line 47
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    const-string v8, "licensePlate"

    .line 52
    .line 53
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    const-string v9, "state"

    .line 58
    .line 59
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    const-string v10, "devicePlatform"

    .line 64
    .line 65
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    const-string v11, "softwareVersion"

    .line 70
    .line 71
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    move-result v11

    .line 75
    const-string v12, "connectivity_sunset_impact"

    .line 76
    .line 77
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 78
    .line 79
    .line 80
    move-result v12

    .line 81
    const-string v13, "isWorkshopMode"

    .line 82
    .line 83
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 84
    .line 85
    .line 86
    move-result v13

    .line 87
    const-string v14, "priority"

    .line 88
    .line 89
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 90
    .line 91
    .line 92
    move-result v14

    .line 93
    const-string v15, "spec_title"

    .line 94
    .line 95
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    move-result v15

    .line 99
    move-object/from16 p0, v2

    .line 100
    .line 101
    const-string v2, "spec_systemCode"

    .line 102
    .line 103
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    move/from16 p1, v2

    .line 108
    .line 109
    const-string v2, "spec_systemModelId"

    .line 110
    .line 111
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 112
    .line 113
    .line 114
    move-result v2

    .line 115
    move/from16 v16, v2

    .line 116
    .line 117
    const-string v2, "spec_model"

    .line 118
    .line 119
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    move/from16 v17, v2

    .line 124
    .line 125
    const-string v2, "spec_manufacturingDate"

    .line 126
    .line 127
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 128
    .line 129
    .line 130
    move-result v2

    .line 131
    move/from16 v18, v2

    .line 132
    .line 133
    const-string v2, "spec_gearboxType"

    .line 134
    .line 135
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    move/from16 v19, v2

    .line 140
    .line 141
    const-string v2, "spec_modelYear"

    .line 142
    .line 143
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 144
    .line 145
    .line 146
    move-result v2

    .line 147
    move/from16 v20, v2

    .line 148
    .line 149
    const-string v2, "spec_body"

    .line 150
    .line 151
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    move/from16 v21, v2

    .line 156
    .line 157
    const-string v2, "spec_batteryCapacity"

    .line 158
    .line 159
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    move/from16 v22, v2

    .line 164
    .line 165
    const-string v2, "spec_trimLevel"

    .line 166
    .line 167
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    move/from16 v23, v2

    .line 172
    .line 173
    const-string v2, "spec_maxChargingPowerInKW"

    .line 174
    .line 175
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 176
    .line 177
    .line 178
    move-result v2

    .line 179
    move/from16 v24, v2

    .line 180
    .line 181
    const-string v2, "spec_colour"

    .line 182
    .line 183
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 184
    .line 185
    .line 186
    move-result v2

    .line 187
    move/from16 v25, v2

    .line 188
    .line 189
    const-string v2, "spec_length"

    .line 190
    .line 191
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 192
    .line 193
    .line 194
    move-result v2

    .line 195
    move/from16 v26, v2

    .line 196
    .line 197
    const-string v2, "spec_width"

    .line 198
    .line 199
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    move/from16 v27, v2

    .line 204
    .line 205
    const-string v2, "spec_height"

    .line 206
    .line 207
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 208
    .line 209
    .line 210
    move-result v2

    .line 211
    move/from16 v28, v2

    .line 212
    .line 213
    const-string v2, "spec_enginepowerInKW"

    .line 214
    .line 215
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 216
    .line 217
    .line 218
    move-result v2

    .line 219
    move/from16 v29, v2

    .line 220
    .line 221
    const-string v2, "spec_enginetype"

    .line 222
    .line 223
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 224
    .line 225
    .line 226
    move-result v2

    .line 227
    move/from16 v30, v2

    .line 228
    .line 229
    const-string v2, "spec_enginecapacityInLiters"

    .line 230
    .line 231
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 232
    .line 233
    .line 234
    move-result v2

    .line 235
    move/from16 v31, v2

    .line 236
    .line 237
    const-string v2, "servicePartner_id"

    .line 238
    .line 239
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 240
    .line 241
    .line 242
    move-result v2

    .line 243
    move/from16 v32, v2

    .line 244
    .line 245
    new-instance v2, Landroidx/collection/f;

    .line 246
    .line 247
    move/from16 v33, v15

    .line 248
    .line 249
    const/4 v15, 0x0

    .line 250
    invoke-direct {v2, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 251
    .line 252
    .line 253
    move/from16 v34, v14

    .line 254
    .line 255
    new-instance v14, Landroidx/collection/f;

    .line 256
    .line 257
    invoke-direct {v14, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 258
    .line 259
    .line 260
    :goto_0
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 261
    .line 262
    .line 263
    move-result v35

    .line 264
    if-eqz v35, :cond_2

    .line 265
    .line 266
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v15

    .line 270
    invoke-virtual {v2, v15}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result v36

    .line 274
    if-nez v36, :cond_0

    .line 275
    .line 276
    move/from16 v36, v13

    .line 277
    .line 278
    new-instance v13, Ljava/util/ArrayList;

    .line 279
    .line 280
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 281
    .line 282
    .line 283
    invoke-virtual {v2, v15, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    goto :goto_1

    .line 287
    :catchall_0
    move-exception v0

    .line 288
    move-object/from16 p0, v3

    .line 289
    .line 290
    goto/16 :goto_29

    .line 291
    .line 292
    :cond_0
    move/from16 v36, v13

    .line 293
    .line 294
    :goto_1
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v13

    .line 298
    invoke-virtual {v14, v13}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    move-result v15

    .line 302
    if-nez v15, :cond_1

    .line 303
    .line 304
    new-instance v15, Ljava/util/ArrayList;

    .line 305
    .line 306
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v14, v13, v15}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    :cond_1
    move/from16 v13, v36

    .line 313
    .line 314
    const/4 v15, 0x0

    .line 315
    goto :goto_0

    .line 316
    :cond_2
    move/from16 v36, v13

    .line 317
    .line 318
    invoke-interface {v3}, Lua/c;->reset()V

    .line 319
    .line 320
    .line 321
    invoke-virtual {v0, v1, v2}, Lif0/m;->e(Lua/a;Landroidx/collection/f;)V

    .line 322
    .line 323
    .line 324
    invoke-virtual {v0, v1, v14}, Lif0/m;->f(Lua/a;Landroidx/collection/f;)V

    .line 325
    .line 326
    .line 327
    new-instance v0, Ljava/util/ArrayList;

    .line 328
    .line 329
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 330
    .line 331
    .line 332
    :goto_2
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 333
    .line 334
    .line 335
    move-result v1

    .line 336
    if-eqz v1, :cond_28

    .line 337
    .line 338
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v38

    .line 342
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v39

    .line 346
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 347
    .line 348
    .line 349
    move-result v1

    .line 350
    if-eqz v1, :cond_3

    .line 351
    .line 352
    const/16 v40, 0x0

    .line 353
    .line 354
    goto :goto_3

    .line 355
    :cond_3
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v1

    .line 359
    move-object/from16 v40, v1

    .line 360
    .line 361
    :goto_3
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object v41

    .line 365
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 366
    .line 367
    .line 368
    move-result v1

    .line 369
    if-eqz v1, :cond_4

    .line 370
    .line 371
    const/16 v42, 0x0

    .line 372
    .line 373
    goto :goto_4

    .line 374
    :cond_4
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    move-object/from16 v42, v1

    .line 379
    .line 380
    :goto_4
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    invoke-static {v1}, Lif0/m;->b(Ljava/lang/String;)Lss0/m;

    .line 385
    .line 386
    .line 387
    move-result-object v43

    .line 388
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    invoke-static {v1}, Lif0/m;->c(Ljava/lang/String;)Lss0/n;

    .line 393
    .line 394
    .line 395
    move-result-object v44

    .line 396
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 397
    .line 398
    .line 399
    move-result v1

    .line 400
    if-eqz v1, :cond_5

    .line 401
    .line 402
    const/16 v45, 0x0

    .line 403
    .line 404
    goto :goto_5

    .line 405
    :cond_5
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 406
    .line 407
    .line 408
    move-result-object v1

    .line 409
    move-object/from16 v45, v1

    .line 410
    .line 411
    :goto_5
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 412
    .line 413
    .line 414
    move-result v1

    .line 415
    if-eqz v1, :cond_6

    .line 416
    .line 417
    const/16 v46, 0x0

    .line 418
    .line 419
    :goto_6
    move-object v15, v14

    .line 420
    move/from16 v1, v36

    .line 421
    .line 422
    goto :goto_7

    .line 423
    :cond_6
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    move-object/from16 v46, v1

    .line 428
    .line 429
    goto :goto_6

    .line 430
    :goto_7
    invoke-interface {v3, v1}, Lua/c;->getLong(I)J

    .line 431
    .line 432
    .line 433
    move-result-wide v13

    .line 434
    long-to-int v13, v13

    .line 435
    if-eqz v13, :cond_7

    .line 436
    .line 437
    const/4 v13, 0x1

    .line 438
    move/from16 v47, v13

    .line 439
    .line 440
    :goto_8
    move v14, v5

    .line 441
    move/from16 v13, v34

    .line 442
    .line 443
    move/from16 v34, v6

    .line 444
    .line 445
    goto :goto_9

    .line 446
    :cond_7
    const/16 v47, 0x0

    .line 447
    .line 448
    goto :goto_8

    .line 449
    :goto_9
    invoke-interface {v3, v13}, Lua/c;->getLong(I)J

    .line 450
    .line 451
    .line 452
    move-result-wide v5

    .line 453
    long-to-int v5, v5

    .line 454
    move/from16 v6, v33

    .line 455
    .line 456
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 457
    .line 458
    .line 459
    move-result v33

    .line 460
    if-eqz v33, :cond_19

    .line 461
    .line 462
    move/from16 v33, v1

    .line 463
    .line 464
    move/from16 v1, p1

    .line 465
    .line 466
    invoke-interface {v3, v1}, Lua/c;->isNull(I)Z

    .line 467
    .line 468
    .line 469
    move-result v37

    .line 470
    if-eqz v37, :cond_18

    .line 471
    .line 472
    move/from16 v48, v5

    .line 473
    .line 474
    move/from16 v5, v16

    .line 475
    .line 476
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 477
    .line 478
    .line 479
    move-result v16

    .line 480
    if-eqz v16, :cond_17

    .line 481
    .line 482
    move/from16 p1, v7

    .line 483
    .line 484
    move/from16 v7, v17

    .line 485
    .line 486
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 487
    .line 488
    .line 489
    move-result v16

    .line 490
    if-eqz v16, :cond_16

    .line 491
    .line 492
    move/from16 v16, v8

    .line 493
    .line 494
    move/from16 v8, v18

    .line 495
    .line 496
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 497
    .line 498
    .line 499
    move-result v17

    .line 500
    if-eqz v17, :cond_15

    .line 501
    .line 502
    move/from16 v17, v9

    .line 503
    .line 504
    move/from16 v9, v19

    .line 505
    .line 506
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 507
    .line 508
    .line 509
    move-result v18

    .line 510
    if-eqz v18, :cond_14

    .line 511
    .line 512
    move/from16 v18, v10

    .line 513
    .line 514
    move/from16 v10, v20

    .line 515
    .line 516
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 517
    .line 518
    .line 519
    move-result v19

    .line 520
    if-eqz v19, :cond_13

    .line 521
    .line 522
    move/from16 v19, v11

    .line 523
    .line 524
    move/from16 v11, v21

    .line 525
    .line 526
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 527
    .line 528
    .line 529
    move-result v20

    .line 530
    if-eqz v20, :cond_12

    .line 531
    .line 532
    move/from16 v20, v12

    .line 533
    .line 534
    move/from16 v12, v22

    .line 535
    .line 536
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 537
    .line 538
    .line 539
    move-result v21

    .line 540
    if-eqz v21, :cond_11

    .line 541
    .line 542
    move/from16 v21, v13

    .line 543
    .line 544
    move/from16 v13, v23

    .line 545
    .line 546
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 547
    .line 548
    .line 549
    move-result v22

    .line 550
    if-eqz v22, :cond_10

    .line 551
    .line 552
    move/from16 v22, v14

    .line 553
    .line 554
    move/from16 v14, v24

    .line 555
    .line 556
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 557
    .line 558
    .line 559
    move-result v23

    .line 560
    if-eqz v23, :cond_f

    .line 561
    .line 562
    move-object/from16 v23, v15

    .line 563
    .line 564
    move/from16 v15, v25

    .line 565
    .line 566
    invoke-interface {v3, v15}, Lua/c;->isNull(I)Z

    .line 567
    .line 568
    .line 569
    move-result v24

    .line 570
    if-eqz v24, :cond_e

    .line 571
    .line 572
    move-object/from16 v24, v0

    .line 573
    .line 574
    move/from16 v0, v26

    .line 575
    .line 576
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 577
    .line 578
    .line 579
    move-result v25

    .line 580
    if-eqz v25, :cond_d

    .line 581
    .line 582
    move-object/from16 v25, v2

    .line 583
    .line 584
    move/from16 v2, v27

    .line 585
    .line 586
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 587
    .line 588
    .line 589
    move-result v26

    .line 590
    if-eqz v26, :cond_c

    .line 591
    .line 592
    move/from16 v26, v4

    .line 593
    .line 594
    move/from16 v4, v28

    .line 595
    .line 596
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 597
    .line 598
    .line 599
    move-result v27

    .line 600
    if-eqz v27, :cond_b

    .line 601
    .line 602
    move/from16 v28, v4

    .line 603
    .line 604
    move/from16 v4, v29

    .line 605
    .line 606
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 607
    .line 608
    .line 609
    move-result v27

    .line 610
    if-eqz v27, :cond_a

    .line 611
    .line 612
    move/from16 v29, v4

    .line 613
    .line 614
    move/from16 v4, v30

    .line 615
    .line 616
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 617
    .line 618
    .line 619
    move-result v27

    .line 620
    if-eqz v27, :cond_9

    .line 621
    .line 622
    move/from16 v30, v4

    .line 623
    .line 624
    move/from16 v4, v31

    .line 625
    .line 626
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 627
    .line 628
    .line 629
    move-result v27

    .line 630
    if-nez v27, :cond_8

    .line 631
    .line 632
    goto/16 :goto_18

    .line 633
    .line 634
    :cond_8
    move/from16 v67, v1

    .line 635
    .line 636
    move/from16 v31, v5

    .line 637
    .line 638
    move/from16 v27, v6

    .line 639
    .line 640
    move/from16 v66, v29

    .line 641
    .line 642
    const/16 v49, 0x0

    .line 643
    .line 644
    move/from16 v29, v2

    .line 645
    .line 646
    move/from16 v2, v30

    .line 647
    .line 648
    move/from16 v30, v28

    .line 649
    .line 650
    move/from16 v28, v0

    .line 651
    .line 652
    :goto_a
    move/from16 v0, v32

    .line 653
    .line 654
    goto/16 :goto_27

    .line 655
    .line 656
    :cond_9
    move/from16 v30, v4

    .line 657
    .line 658
    :goto_b
    move/from16 v4, v31

    .line 659
    .line 660
    goto/16 :goto_18

    .line 661
    .line 662
    :cond_a
    move/from16 v29, v4

    .line 663
    .line 664
    goto :goto_b

    .line 665
    :cond_b
    move/from16 v28, v4

    .line 666
    .line 667
    goto :goto_b

    .line 668
    :cond_c
    :goto_c
    move/from16 v26, v4

    .line 669
    .line 670
    goto :goto_b

    .line 671
    :cond_d
    :goto_d
    move-object/from16 v25, v2

    .line 672
    .line 673
    move/from16 v26, v4

    .line 674
    .line 675
    move/from16 v2, v27

    .line 676
    .line 677
    goto :goto_b

    .line 678
    :cond_e
    :goto_e
    move-object/from16 v24, v0

    .line 679
    .line 680
    move-object/from16 v25, v2

    .line 681
    .line 682
    move/from16 v0, v26

    .line 683
    .line 684
    move/from16 v2, v27

    .line 685
    .line 686
    goto :goto_c

    .line 687
    :cond_f
    :goto_f
    move-object/from16 v24, v0

    .line 688
    .line 689
    move-object/from16 v23, v15

    .line 690
    .line 691
    move/from16 v15, v25

    .line 692
    .line 693
    move/from16 v0, v26

    .line 694
    .line 695
    goto :goto_d

    .line 696
    :cond_10
    :goto_10
    move/from16 v22, v14

    .line 697
    .line 698
    move-object/from16 v23, v15

    .line 699
    .line 700
    move/from16 v14, v24

    .line 701
    .line 702
    move/from16 v15, v25

    .line 703
    .line 704
    goto :goto_e

    .line 705
    :cond_11
    :goto_11
    move/from16 v21, v13

    .line 706
    .line 707
    move/from16 v22, v14

    .line 708
    .line 709
    move/from16 v13, v23

    .line 710
    .line 711
    move/from16 v14, v24

    .line 712
    .line 713
    goto :goto_f

    .line 714
    :cond_12
    :goto_12
    move/from16 v20, v12

    .line 715
    .line 716
    move/from16 v21, v13

    .line 717
    .line 718
    move/from16 v12, v22

    .line 719
    .line 720
    move/from16 v13, v23

    .line 721
    .line 722
    goto :goto_10

    .line 723
    :cond_13
    :goto_13
    move/from16 v19, v11

    .line 724
    .line 725
    move/from16 v20, v12

    .line 726
    .line 727
    move/from16 v11, v21

    .line 728
    .line 729
    move/from16 v12, v22

    .line 730
    .line 731
    goto :goto_11

    .line 732
    :cond_14
    :goto_14
    move/from16 v18, v10

    .line 733
    .line 734
    move/from16 v19, v11

    .line 735
    .line 736
    move/from16 v10, v20

    .line 737
    .line 738
    move/from16 v11, v21

    .line 739
    .line 740
    goto :goto_12

    .line 741
    :cond_15
    :goto_15
    move/from16 v17, v9

    .line 742
    .line 743
    move/from16 v18, v10

    .line 744
    .line 745
    move/from16 v9, v19

    .line 746
    .line 747
    move/from16 v10, v20

    .line 748
    .line 749
    goto :goto_13

    .line 750
    :cond_16
    :goto_16
    move/from16 v16, v8

    .line 751
    .line 752
    move/from16 v17, v9

    .line 753
    .line 754
    move/from16 v8, v18

    .line 755
    .line 756
    move/from16 v9, v19

    .line 757
    .line 758
    goto :goto_14

    .line 759
    :cond_17
    :goto_17
    move/from16 p1, v7

    .line 760
    .line 761
    move/from16 v16, v8

    .line 762
    .line 763
    move/from16 v7, v17

    .line 764
    .line 765
    move/from16 v8, v18

    .line 766
    .line 767
    goto :goto_15

    .line 768
    :cond_18
    move/from16 v48, v5

    .line 769
    .line 770
    move/from16 p1, v7

    .line 771
    .line 772
    move/from16 v5, v16

    .line 773
    .line 774
    move/from16 v7, v17

    .line 775
    .line 776
    goto :goto_16

    .line 777
    :cond_19
    move/from16 v33, v1

    .line 778
    .line 779
    move/from16 v48, v5

    .line 780
    .line 781
    move/from16 v5, v16

    .line 782
    .line 783
    move/from16 v1, p1

    .line 784
    .line 785
    goto :goto_17

    .line 786
    :goto_18
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 787
    .line 788
    .line 789
    move-result-object v50

    .line 790
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 791
    .line 792
    .line 793
    move-result-object v51

    .line 794
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 795
    .line 796
    .line 797
    move-result-object v52

    .line 798
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 799
    .line 800
    .line 801
    move-result-object v53

    .line 802
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 803
    .line 804
    .line 805
    move-result v27

    .line 806
    if-eqz v27, :cond_1a

    .line 807
    .line 808
    const/16 v27, 0x0

    .line 809
    .line 810
    goto :goto_19

    .line 811
    :cond_1a
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 812
    .line 813
    .line 814
    move-result-object v27

    .line 815
    :goto_19
    invoke-static/range {v27 .. v27}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 816
    .line 817
    .line 818
    move-result-object v54

    .line 819
    if-eqz v54, :cond_27

    .line 820
    .line 821
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object v27

    .line 825
    invoke-static/range {v27 .. v27}, Lif0/m;->d(Ljava/lang/String;)Lss0/p;

    .line 826
    .line 827
    .line 828
    move-result-object v55

    .line 829
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 830
    .line 831
    .line 832
    move-result v27

    .line 833
    if-eqz v27, :cond_1b

    .line 834
    .line 835
    const/16 v57, 0x0

    .line 836
    .line 837
    goto :goto_1a

    .line 838
    :cond_1b
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 839
    .line 840
    .line 841
    move-result-object v27

    .line 842
    move-object/from16 v57, v27

    .line 843
    .line 844
    :goto_1a
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 845
    .line 846
    .line 847
    move-result v27

    .line 848
    if-eqz v27, :cond_1c

    .line 849
    .line 850
    const/16 v58, 0x0

    .line 851
    .line 852
    goto :goto_1b

    .line 853
    :cond_1c
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 854
    .line 855
    .line 856
    move-result-object v27

    .line 857
    move-object/from16 v58, v27

    .line 858
    .line 859
    :goto_1b
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 860
    .line 861
    .line 862
    move-result v27

    .line 863
    if-eqz v27, :cond_1d

    .line 864
    .line 865
    move/from16 v31, v5

    .line 866
    .line 867
    move/from16 v27, v6

    .line 868
    .line 869
    const/16 v59, 0x0

    .line 870
    .line 871
    goto :goto_1c

    .line 872
    :cond_1d
    move/from16 v31, v5

    .line 873
    .line 874
    move/from16 v27, v6

    .line 875
    .line 876
    invoke-interface {v3, v12}, Lua/c;->getLong(I)J

    .line 877
    .line 878
    .line 879
    move-result-wide v5

    .line 880
    long-to-int v5, v5

    .line 881
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 882
    .line 883
    .line 884
    move-result-object v5

    .line 885
    move-object/from16 v59, v5

    .line 886
    .line 887
    :goto_1c
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 888
    .line 889
    .line 890
    move-result v5

    .line 891
    if-eqz v5, :cond_1e

    .line 892
    .line 893
    const/16 v60, 0x0

    .line 894
    .line 895
    goto :goto_1d

    .line 896
    :cond_1e
    invoke-interface {v3, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 897
    .line 898
    .line 899
    move-result-object v5

    .line 900
    move-object/from16 v60, v5

    .line 901
    .line 902
    :goto_1d
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 903
    .line 904
    .line 905
    move-result v5

    .line 906
    if-eqz v5, :cond_1f

    .line 907
    .line 908
    const/16 v61, 0x0

    .line 909
    .line 910
    goto :goto_1e

    .line 911
    :cond_1f
    invoke-interface {v3, v14}, Lua/c;->getLong(I)J

    .line 912
    .line 913
    .line 914
    move-result-wide v5

    .line 915
    long-to-int v5, v5

    .line 916
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 917
    .line 918
    .line 919
    move-result-object v5

    .line 920
    move-object/from16 v61, v5

    .line 921
    .line 922
    :goto_1e
    invoke-interface {v3, v15}, Lua/c;->isNull(I)Z

    .line 923
    .line 924
    .line 925
    move-result v5

    .line 926
    if-eqz v5, :cond_20

    .line 927
    .line 928
    const/16 v62, 0x0

    .line 929
    .line 930
    goto :goto_1f

    .line 931
    :cond_20
    invoke-interface {v3, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 932
    .line 933
    .line 934
    move-result-object v5

    .line 935
    move-object/from16 v62, v5

    .line 936
    .line 937
    :goto_1f
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 938
    .line 939
    .line 940
    move-result v5

    .line 941
    if-eqz v5, :cond_21

    .line 942
    .line 943
    const/16 v63, 0x0

    .line 944
    .line 945
    goto :goto_20

    .line 946
    :cond_21
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 947
    .line 948
    .line 949
    move-result-wide v5

    .line 950
    long-to-int v5, v5

    .line 951
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 952
    .line 953
    .line 954
    move-result-object v5

    .line 955
    move-object/from16 v63, v5

    .line 956
    .line 957
    :goto_20
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 958
    .line 959
    .line 960
    move-result v5

    .line 961
    if-eqz v5, :cond_22

    .line 962
    .line 963
    const/16 v64, 0x0

    .line 964
    .line 965
    :goto_21
    move/from16 v5, v28

    .line 966
    .line 967
    goto :goto_22

    .line 968
    :cond_22
    invoke-interface {v3, v2}, Lua/c;->getLong(I)J

    .line 969
    .line 970
    .line 971
    move-result-wide v5

    .line 972
    long-to-int v5, v5

    .line 973
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 974
    .line 975
    .line 976
    move-result-object v5

    .line 977
    move-object/from16 v64, v5

    .line 978
    .line 979
    goto :goto_21

    .line 980
    :goto_22
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 981
    .line 982
    .line 983
    move-result v6

    .line 984
    if-eqz v6, :cond_23

    .line 985
    .line 986
    move/from16 v28, v0

    .line 987
    .line 988
    move v6, v1

    .line 989
    const/16 v65, 0x0

    .line 990
    .line 991
    :goto_23
    move/from16 v0, v29

    .line 992
    .line 993
    move/from16 v29, v2

    .line 994
    .line 995
    goto :goto_24

    .line 996
    :cond_23
    move/from16 v28, v0

    .line 997
    .line 998
    move v6, v1

    .line 999
    invoke-interface {v3, v5}, Lua/c;->getLong(I)J

    .line 1000
    .line 1001
    .line 1002
    move-result-wide v0

    .line 1003
    long-to-int v0, v0

    .line 1004
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v0

    .line 1008
    move-object/from16 v65, v0

    .line 1009
    .line 1010
    goto :goto_23

    .line 1011
    :goto_24
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 1012
    .line 1013
    .line 1014
    move-result-wide v1

    .line 1015
    long-to-int v1, v1

    .line 1016
    move/from16 v2, v30

    .line 1017
    .line 1018
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 1019
    .line 1020
    .line 1021
    move-result v30

    .line 1022
    if-eqz v30, :cond_24

    .line 1023
    .line 1024
    move/from16 v66, v0

    .line 1025
    .line 1026
    const/4 v0, 0x0

    .line 1027
    goto :goto_25

    .line 1028
    :cond_24
    invoke-interface {v3, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1029
    .line 1030
    .line 1031
    move-result-object v30

    .line 1032
    move/from16 v66, v0

    .line 1033
    .line 1034
    move-object/from16 v0, v30

    .line 1035
    .line 1036
    :goto_25
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1037
    .line 1038
    .line 1039
    move-result v30

    .line 1040
    if-eqz v30, :cond_25

    .line 1041
    .line 1042
    move/from16 v30, v5

    .line 1043
    .line 1044
    move/from16 v67, v6

    .line 1045
    .line 1046
    const/4 v5, 0x0

    .line 1047
    goto :goto_26

    .line 1048
    :cond_25
    move/from16 v30, v5

    .line 1049
    .line 1050
    move/from16 v67, v6

    .line 1051
    .line 1052
    invoke-interface {v3, v4}, Lua/c;->getDouble(I)D

    .line 1053
    .line 1054
    .line 1055
    move-result-wide v5

    .line 1056
    double-to-float v5, v5

    .line 1057
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1058
    .line 1059
    .line 1060
    move-result-object v5

    .line 1061
    :goto_26
    new-instance v6, Lif0/q;

    .line 1062
    .line 1063
    invoke-direct {v6, v1, v0, v5}, Lif0/q;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

    .line 1064
    .line 1065
    .line 1066
    new-instance v49, Lif0/p;

    .line 1067
    .line 1068
    move-object/from16 v56, v6

    .line 1069
    .line 1070
    invoke-direct/range {v49 .. v65}, Lif0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/p;Lif0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1071
    .line 1072
    .line 1073
    goto/16 :goto_a

    .line 1074
    .line 1075
    :goto_27
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1076
    .line 1077
    .line 1078
    move-result v1

    .line 1079
    if-nez v1, :cond_26

    .line 1080
    .line 1081
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v1

    .line 1085
    new-instance v5, Lif0/g0;

    .line 1086
    .line 1087
    invoke-direct {v5, v1}, Lif0/g0;-><init>(Ljava/lang/String;)V

    .line 1088
    .line 1089
    .line 1090
    move-object/from16 v50, v5

    .line 1091
    .line 1092
    goto :goto_28

    .line 1093
    :cond_26
    const/16 v50, 0x0

    .line 1094
    .line 1095
    :goto_28
    new-instance v37, Lif0/o;

    .line 1096
    .line 1097
    invoke-direct/range {v37 .. v50}, Lif0/o;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lss0/m;Lss0/n;Ljava/lang/String;Ljava/lang/String;ZILif0/p;Lif0/g0;)V

    .line 1098
    .line 1099
    .line 1100
    move-object/from16 v1, v37

    .line 1101
    .line 1102
    move/from16 v5, v26

    .line 1103
    .line 1104
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v6

    .line 1108
    move/from16 v32, v0

    .line 1109
    .line 1110
    move-object/from16 v0, v25

    .line 1111
    .line 1112
    invoke-static {v0, v6}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v6

    .line 1116
    move-object/from16 v25, v0

    .line 1117
    .line 1118
    move-object/from16 v0, p0

    .line 1119
    .line 1120
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1121
    .line 1122
    .line 1123
    check-cast v6, Ljava/util/List;

    .line 1124
    .line 1125
    move/from16 v26, v2

    .line 1126
    .line 1127
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1131
    move-object/from16 p0, v3

    .line 1132
    .line 1133
    move-object/from16 v3, v23

    .line 1134
    .line 1135
    :try_start_1
    invoke-static {v3, v2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1136
    .line 1137
    .line 1138
    move-result-object v2

    .line 1139
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1140
    .line 1141
    .line 1142
    check-cast v2, Ljava/util/List;

    .line 1143
    .line 1144
    move-object/from16 v23, v0

    .line 1145
    .line 1146
    new-instance v0, Lif0/n;

    .line 1147
    .line 1148
    invoke-direct {v0, v1, v6, v2}, Lif0/n;-><init>(Lif0/o;Ljava/util/List;Ljava/util/List;)V

    .line 1149
    .line 1150
    .line 1151
    move-object/from16 v1, v24

    .line 1152
    .line 1153
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1154
    .line 1155
    .line 1156
    move/from16 v0, v31

    .line 1157
    .line 1158
    move/from16 v31, v4

    .line 1159
    .line 1160
    move v4, v5

    .line 1161
    move/from16 v5, v22

    .line 1162
    .line 1163
    move/from16 v22, v12

    .line 1164
    .line 1165
    move/from16 v12, v20

    .line 1166
    .line 1167
    move/from16 v20, v10

    .line 1168
    .line 1169
    move/from16 v10, v18

    .line 1170
    .line 1171
    move/from16 v18, v8

    .line 1172
    .line 1173
    move/from16 v8, v16

    .line 1174
    .line 1175
    move/from16 v16, v0

    .line 1176
    .line 1177
    move/from16 v0, v30

    .line 1178
    .line 1179
    move/from16 v30, v26

    .line 1180
    .line 1181
    move/from16 v26, v28

    .line 1182
    .line 1183
    move/from16 v28, v0

    .line 1184
    .line 1185
    move-object v0, v1

    .line 1186
    move/from16 v24, v14

    .line 1187
    .line 1188
    move-object/from16 v2, v25

    .line 1189
    .line 1190
    move/from16 v36, v33

    .line 1191
    .line 1192
    move/from16 v6, v34

    .line 1193
    .line 1194
    move-object v14, v3

    .line 1195
    move/from16 v25, v15

    .line 1196
    .line 1197
    move/from16 v34, v21

    .line 1198
    .line 1199
    move/from16 v33, v27

    .line 1200
    .line 1201
    move/from16 v27, v29

    .line 1202
    .line 1203
    move/from16 v29, v66

    .line 1204
    .line 1205
    move-object/from16 v3, p0

    .line 1206
    .line 1207
    move/from16 v21, v11

    .line 1208
    .line 1209
    move/from16 v11, v19

    .line 1210
    .line 1211
    move-object/from16 p0, v23

    .line 1212
    .line 1213
    move/from16 v19, v9

    .line 1214
    .line 1215
    move/from16 v23, v13

    .line 1216
    .line 1217
    move/from16 v9, v17

    .line 1218
    .line 1219
    move/from16 v17, v7

    .line 1220
    .line 1221
    move/from16 v7, p1

    .line 1222
    .line 1223
    move/from16 p1, v67

    .line 1224
    .line 1225
    goto/16 :goto_2

    .line 1226
    .line 1227
    :catchall_1
    move-exception v0

    .line 1228
    goto :goto_29

    .line 1229
    :cond_27
    move-object/from16 p0, v3

    .line 1230
    .line 1231
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1232
    .line 1233
    const-string v1, "Expected NON-NULL \'java.time.LocalDate\', but it was NULL."

    .line 1234
    .line 1235
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1236
    .line 1237
    .line 1238
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1239
    :cond_28
    move-object v1, v0

    .line 1240
    move-object/from16 p0, v3

    .line 1241
    .line 1242
    invoke-interface/range {p0 .. p0}, Ljava/lang/AutoCloseable;->close()V

    .line 1243
    .line 1244
    .line 1245
    return-object v1

    .line 1246
    :goto_29
    invoke-interface/range {p0 .. p0}, Ljava/lang/AutoCloseable;->close()V

    .line 1247
    .line 1248
    .line 1249
    throw v0

    .line 1250
    :pswitch_0
    move-object/from16 v1, p1

    .line 1251
    .line 1252
    check-cast v1, Lua/a;

    .line 1253
    .line 1254
    const-string v2, "getValue(...)"

    .line 1255
    .line 1256
    const-string v3, "_connection"

    .line 1257
    .line 1258
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1259
    .line 1260
    .line 1261
    const-string v3, "SELECT * FROM vehicle"

    .line 1262
    .line 1263
    invoke-interface {v1, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1264
    .line 1265
    .line 1266
    move-result-object v3

    .line 1267
    :try_start_2
    const-string v4, "vin"

    .line 1268
    .line 1269
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1270
    .line 1271
    .line 1272
    move-result v4

    .line 1273
    const-string v5, "systemModelId"

    .line 1274
    .line 1275
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1276
    .line 1277
    .line 1278
    move-result v5

    .line 1279
    const-string v6, "name"

    .line 1280
    .line 1281
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1282
    .line 1283
    .line 1284
    move-result v6

    .line 1285
    const-string v7, "title"

    .line 1286
    .line 1287
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1288
    .line 1289
    .line 1290
    move-result v7

    .line 1291
    const-string v8, "licensePlate"

    .line 1292
    .line 1293
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1294
    .line 1295
    .line 1296
    move-result v8

    .line 1297
    const-string v9, "state"

    .line 1298
    .line 1299
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1300
    .line 1301
    .line 1302
    move-result v9

    .line 1303
    const-string v10, "devicePlatform"

    .line 1304
    .line 1305
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1306
    .line 1307
    .line 1308
    move-result v10

    .line 1309
    const-string v11, "softwareVersion"

    .line 1310
    .line 1311
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1312
    .line 1313
    .line 1314
    move-result v11

    .line 1315
    const-string v12, "connectivity_sunset_impact"

    .line 1316
    .line 1317
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1318
    .line 1319
    .line 1320
    move-result v12

    .line 1321
    const-string v13, "isWorkshopMode"

    .line 1322
    .line 1323
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1324
    .line 1325
    .line 1326
    move-result v13

    .line 1327
    const-string v14, "priority"

    .line 1328
    .line 1329
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1330
    .line 1331
    .line 1332
    move-result v14

    .line 1333
    const-string v15, "spec_title"

    .line 1334
    .line 1335
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1336
    .line 1337
    .line 1338
    move-result v15

    .line 1339
    move-object/from16 p0, v2

    .line 1340
    .line 1341
    const-string v2, "spec_systemCode"

    .line 1342
    .line 1343
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1344
    .line 1345
    .line 1346
    move-result v2

    .line 1347
    move/from16 p1, v2

    .line 1348
    .line 1349
    const-string v2, "spec_systemModelId"

    .line 1350
    .line 1351
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1352
    .line 1353
    .line 1354
    move-result v2

    .line 1355
    move/from16 v16, v2

    .line 1356
    .line 1357
    const-string v2, "spec_model"

    .line 1358
    .line 1359
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1360
    .line 1361
    .line 1362
    move-result v2

    .line 1363
    move/from16 v17, v2

    .line 1364
    .line 1365
    const-string v2, "spec_manufacturingDate"

    .line 1366
    .line 1367
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1368
    .line 1369
    .line 1370
    move-result v2

    .line 1371
    move/from16 v18, v2

    .line 1372
    .line 1373
    const-string v2, "spec_gearboxType"

    .line 1374
    .line 1375
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1376
    .line 1377
    .line 1378
    move-result v2

    .line 1379
    move/from16 v19, v2

    .line 1380
    .line 1381
    const-string v2, "spec_modelYear"

    .line 1382
    .line 1383
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1384
    .line 1385
    .line 1386
    move-result v2

    .line 1387
    move/from16 v20, v2

    .line 1388
    .line 1389
    const-string v2, "spec_body"

    .line 1390
    .line 1391
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1392
    .line 1393
    .line 1394
    move-result v2

    .line 1395
    move/from16 v21, v2

    .line 1396
    .line 1397
    const-string v2, "spec_batteryCapacity"

    .line 1398
    .line 1399
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1400
    .line 1401
    .line 1402
    move-result v2

    .line 1403
    move/from16 v22, v2

    .line 1404
    .line 1405
    const-string v2, "spec_trimLevel"

    .line 1406
    .line 1407
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1408
    .line 1409
    .line 1410
    move-result v2

    .line 1411
    move/from16 v23, v2

    .line 1412
    .line 1413
    const-string v2, "spec_maxChargingPowerInKW"

    .line 1414
    .line 1415
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1416
    .line 1417
    .line 1418
    move-result v2

    .line 1419
    move/from16 v24, v2

    .line 1420
    .line 1421
    const-string v2, "spec_colour"

    .line 1422
    .line 1423
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1424
    .line 1425
    .line 1426
    move-result v2

    .line 1427
    move/from16 v25, v2

    .line 1428
    .line 1429
    const-string v2, "spec_length"

    .line 1430
    .line 1431
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1432
    .line 1433
    .line 1434
    move-result v2

    .line 1435
    move/from16 v26, v2

    .line 1436
    .line 1437
    const-string v2, "spec_width"

    .line 1438
    .line 1439
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1440
    .line 1441
    .line 1442
    move-result v2

    .line 1443
    move/from16 v27, v2

    .line 1444
    .line 1445
    const-string v2, "spec_height"

    .line 1446
    .line 1447
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1448
    .line 1449
    .line 1450
    move-result v2

    .line 1451
    move/from16 v28, v2

    .line 1452
    .line 1453
    const-string v2, "spec_enginepowerInKW"

    .line 1454
    .line 1455
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1456
    .line 1457
    .line 1458
    move-result v2

    .line 1459
    move/from16 v29, v2

    .line 1460
    .line 1461
    const-string v2, "spec_enginetype"

    .line 1462
    .line 1463
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1464
    .line 1465
    .line 1466
    move-result v2

    .line 1467
    move/from16 v30, v2

    .line 1468
    .line 1469
    const-string v2, "spec_enginecapacityInLiters"

    .line 1470
    .line 1471
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1472
    .line 1473
    .line 1474
    move-result v2

    .line 1475
    move/from16 v31, v2

    .line 1476
    .line 1477
    const-string v2, "servicePartner_id"

    .line 1478
    .line 1479
    invoke-static {v3, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1480
    .line 1481
    .line 1482
    move-result v2

    .line 1483
    move/from16 v32, v2

    .line 1484
    .line 1485
    new-instance v2, Landroidx/collection/f;

    .line 1486
    .line 1487
    move/from16 v33, v15

    .line 1488
    .line 1489
    const/4 v15, 0x0

    .line 1490
    invoke-direct {v2, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 1491
    .line 1492
    .line 1493
    move/from16 v34, v14

    .line 1494
    .line 1495
    new-instance v14, Landroidx/collection/f;

    .line 1496
    .line 1497
    invoke-direct {v14, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 1498
    .line 1499
    .line 1500
    :goto_2a
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 1501
    .line 1502
    .line 1503
    move-result v35

    .line 1504
    if-eqz v35, :cond_2b

    .line 1505
    .line 1506
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v15

    .line 1510
    invoke-virtual {v2, v15}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 1511
    .line 1512
    .line 1513
    move-result v36

    .line 1514
    if-nez v36, :cond_29

    .line 1515
    .line 1516
    move/from16 v36, v13

    .line 1517
    .line 1518
    new-instance v13, Ljava/util/ArrayList;

    .line 1519
    .line 1520
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 1521
    .line 1522
    .line 1523
    invoke-virtual {v2, v15, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1524
    .line 1525
    .line 1526
    goto :goto_2b

    .line 1527
    :catchall_2
    move-exception v0

    .line 1528
    move-object/from16 p0, v3

    .line 1529
    .line 1530
    goto/16 :goto_53

    .line 1531
    .line 1532
    :cond_29
    move/from16 v36, v13

    .line 1533
    .line 1534
    :goto_2b
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v13

    .line 1538
    invoke-virtual {v14, v13}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 1539
    .line 1540
    .line 1541
    move-result v15

    .line 1542
    if-nez v15, :cond_2a

    .line 1543
    .line 1544
    new-instance v15, Ljava/util/ArrayList;

    .line 1545
    .line 1546
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 1547
    .line 1548
    .line 1549
    invoke-virtual {v14, v13, v15}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1550
    .line 1551
    .line 1552
    :cond_2a
    move/from16 v13, v36

    .line 1553
    .line 1554
    const/4 v15, 0x0

    .line 1555
    goto :goto_2a

    .line 1556
    :cond_2b
    move/from16 v36, v13

    .line 1557
    .line 1558
    invoke-interface {v3}, Lua/c;->reset()V

    .line 1559
    .line 1560
    .line 1561
    invoke-virtual {v0, v1, v2}, Lif0/m;->e(Lua/a;Landroidx/collection/f;)V

    .line 1562
    .line 1563
    .line 1564
    invoke-virtual {v0, v1, v14}, Lif0/m;->f(Lua/a;Landroidx/collection/f;)V

    .line 1565
    .line 1566
    .line 1567
    new-instance v0, Ljava/util/ArrayList;

    .line 1568
    .line 1569
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 1570
    .line 1571
    .line 1572
    :goto_2c
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 1573
    .line 1574
    .line 1575
    move-result v1

    .line 1576
    if-eqz v1, :cond_51

    .line 1577
    .line 1578
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1579
    .line 1580
    .line 1581
    move-result-object v38

    .line 1582
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1583
    .line 1584
    .line 1585
    move-result-object v39

    .line 1586
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 1587
    .line 1588
    .line 1589
    move-result v1

    .line 1590
    if-eqz v1, :cond_2c

    .line 1591
    .line 1592
    const/16 v40, 0x0

    .line 1593
    .line 1594
    goto :goto_2d

    .line 1595
    :cond_2c
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1596
    .line 1597
    .line 1598
    move-result-object v1

    .line 1599
    move-object/from16 v40, v1

    .line 1600
    .line 1601
    :goto_2d
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v41

    .line 1605
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1606
    .line 1607
    .line 1608
    move-result v1

    .line 1609
    if-eqz v1, :cond_2d

    .line 1610
    .line 1611
    const/16 v42, 0x0

    .line 1612
    .line 1613
    goto :goto_2e

    .line 1614
    :cond_2d
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1615
    .line 1616
    .line 1617
    move-result-object v1

    .line 1618
    move-object/from16 v42, v1

    .line 1619
    .line 1620
    :goto_2e
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1621
    .line 1622
    .line 1623
    move-result-object v1

    .line 1624
    invoke-static {v1}, Lif0/m;->b(Ljava/lang/String;)Lss0/m;

    .line 1625
    .line 1626
    .line 1627
    move-result-object v43

    .line 1628
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1629
    .line 1630
    .line 1631
    move-result-object v1

    .line 1632
    invoke-static {v1}, Lif0/m;->c(Ljava/lang/String;)Lss0/n;

    .line 1633
    .line 1634
    .line 1635
    move-result-object v44

    .line 1636
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 1637
    .line 1638
    .line 1639
    move-result v1

    .line 1640
    if-eqz v1, :cond_2e

    .line 1641
    .line 1642
    const/16 v45, 0x0

    .line 1643
    .line 1644
    goto :goto_2f

    .line 1645
    :cond_2e
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1646
    .line 1647
    .line 1648
    move-result-object v1

    .line 1649
    move-object/from16 v45, v1

    .line 1650
    .line 1651
    :goto_2f
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 1652
    .line 1653
    .line 1654
    move-result v1

    .line 1655
    if-eqz v1, :cond_2f

    .line 1656
    .line 1657
    const/16 v46, 0x0

    .line 1658
    .line 1659
    :goto_30
    move-object v15, v14

    .line 1660
    move/from16 v1, v36

    .line 1661
    .line 1662
    goto :goto_31

    .line 1663
    :cond_2f
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1664
    .line 1665
    .line 1666
    move-result-object v1

    .line 1667
    move-object/from16 v46, v1

    .line 1668
    .line 1669
    goto :goto_30

    .line 1670
    :goto_31
    invoke-interface {v3, v1}, Lua/c;->getLong(I)J

    .line 1671
    .line 1672
    .line 1673
    move-result-wide v13

    .line 1674
    long-to-int v13, v13

    .line 1675
    if-eqz v13, :cond_30

    .line 1676
    .line 1677
    const/4 v13, 0x1

    .line 1678
    move/from16 v47, v13

    .line 1679
    .line 1680
    :goto_32
    move v14, v5

    .line 1681
    move/from16 v13, v34

    .line 1682
    .line 1683
    move/from16 v34, v6

    .line 1684
    .line 1685
    goto :goto_33

    .line 1686
    :cond_30
    const/16 v47, 0x0

    .line 1687
    .line 1688
    goto :goto_32

    .line 1689
    :goto_33
    invoke-interface {v3, v13}, Lua/c;->getLong(I)J

    .line 1690
    .line 1691
    .line 1692
    move-result-wide v5

    .line 1693
    long-to-int v5, v5

    .line 1694
    move/from16 v6, v33

    .line 1695
    .line 1696
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 1697
    .line 1698
    .line 1699
    move-result v33

    .line 1700
    if-eqz v33, :cond_42

    .line 1701
    .line 1702
    move/from16 v33, v1

    .line 1703
    .line 1704
    move/from16 v1, p1

    .line 1705
    .line 1706
    invoke-interface {v3, v1}, Lua/c;->isNull(I)Z

    .line 1707
    .line 1708
    .line 1709
    move-result v37

    .line 1710
    if-eqz v37, :cond_41

    .line 1711
    .line 1712
    move/from16 v48, v5

    .line 1713
    .line 1714
    move/from16 v5, v16

    .line 1715
    .line 1716
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1717
    .line 1718
    .line 1719
    move-result v16

    .line 1720
    if-eqz v16, :cond_40

    .line 1721
    .line 1722
    move/from16 p1, v7

    .line 1723
    .line 1724
    move/from16 v7, v17

    .line 1725
    .line 1726
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1727
    .line 1728
    .line 1729
    move-result v16

    .line 1730
    if-eqz v16, :cond_3f

    .line 1731
    .line 1732
    move/from16 v16, v8

    .line 1733
    .line 1734
    move/from16 v8, v18

    .line 1735
    .line 1736
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1737
    .line 1738
    .line 1739
    move-result v17

    .line 1740
    if-eqz v17, :cond_3e

    .line 1741
    .line 1742
    move/from16 v17, v9

    .line 1743
    .line 1744
    move/from16 v9, v19

    .line 1745
    .line 1746
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 1747
    .line 1748
    .line 1749
    move-result v18

    .line 1750
    if-eqz v18, :cond_3d

    .line 1751
    .line 1752
    move/from16 v18, v10

    .line 1753
    .line 1754
    move/from16 v10, v20

    .line 1755
    .line 1756
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 1757
    .line 1758
    .line 1759
    move-result v19

    .line 1760
    if-eqz v19, :cond_3c

    .line 1761
    .line 1762
    move/from16 v19, v11

    .line 1763
    .line 1764
    move/from16 v11, v21

    .line 1765
    .line 1766
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 1767
    .line 1768
    .line 1769
    move-result v20

    .line 1770
    if-eqz v20, :cond_3b

    .line 1771
    .line 1772
    move/from16 v20, v12

    .line 1773
    .line 1774
    move/from16 v12, v22

    .line 1775
    .line 1776
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 1777
    .line 1778
    .line 1779
    move-result v21

    .line 1780
    if-eqz v21, :cond_3a

    .line 1781
    .line 1782
    move/from16 v21, v13

    .line 1783
    .line 1784
    move/from16 v13, v23

    .line 1785
    .line 1786
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 1787
    .line 1788
    .line 1789
    move-result v22

    .line 1790
    if-eqz v22, :cond_39

    .line 1791
    .line 1792
    move/from16 v22, v14

    .line 1793
    .line 1794
    move/from16 v14, v24

    .line 1795
    .line 1796
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 1797
    .line 1798
    .line 1799
    move-result v23

    .line 1800
    if-eqz v23, :cond_38

    .line 1801
    .line 1802
    move-object/from16 v23, v15

    .line 1803
    .line 1804
    move/from16 v15, v25

    .line 1805
    .line 1806
    invoke-interface {v3, v15}, Lua/c;->isNull(I)Z

    .line 1807
    .line 1808
    .line 1809
    move-result v24

    .line 1810
    if-eqz v24, :cond_37

    .line 1811
    .line 1812
    move-object/from16 v24, v0

    .line 1813
    .line 1814
    move/from16 v0, v26

    .line 1815
    .line 1816
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1817
    .line 1818
    .line 1819
    move-result v25

    .line 1820
    if-eqz v25, :cond_36

    .line 1821
    .line 1822
    move-object/from16 v25, v2

    .line 1823
    .line 1824
    move/from16 v2, v27

    .line 1825
    .line 1826
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 1827
    .line 1828
    .line 1829
    move-result v26

    .line 1830
    if-eqz v26, :cond_35

    .line 1831
    .line 1832
    move/from16 v26, v4

    .line 1833
    .line 1834
    move/from16 v4, v28

    .line 1835
    .line 1836
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1837
    .line 1838
    .line 1839
    move-result v27

    .line 1840
    if-eqz v27, :cond_34

    .line 1841
    .line 1842
    move/from16 v28, v4

    .line 1843
    .line 1844
    move/from16 v4, v29

    .line 1845
    .line 1846
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1847
    .line 1848
    .line 1849
    move-result v27

    .line 1850
    if-eqz v27, :cond_33

    .line 1851
    .line 1852
    move/from16 v29, v4

    .line 1853
    .line 1854
    move/from16 v4, v30

    .line 1855
    .line 1856
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1857
    .line 1858
    .line 1859
    move-result v27

    .line 1860
    if-eqz v27, :cond_32

    .line 1861
    .line 1862
    move/from16 v30, v4

    .line 1863
    .line 1864
    move/from16 v4, v31

    .line 1865
    .line 1866
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 1867
    .line 1868
    .line 1869
    move-result v27

    .line 1870
    if-nez v27, :cond_31

    .line 1871
    .line 1872
    goto/16 :goto_42

    .line 1873
    .line 1874
    :cond_31
    move/from16 v67, v1

    .line 1875
    .line 1876
    move/from16 v31, v5

    .line 1877
    .line 1878
    move/from16 v27, v6

    .line 1879
    .line 1880
    move/from16 v66, v29

    .line 1881
    .line 1882
    const/16 v49, 0x0

    .line 1883
    .line 1884
    move/from16 v29, v2

    .line 1885
    .line 1886
    move/from16 v2, v30

    .line 1887
    .line 1888
    move/from16 v30, v28

    .line 1889
    .line 1890
    move/from16 v28, v0

    .line 1891
    .line 1892
    :goto_34
    move/from16 v0, v32

    .line 1893
    .line 1894
    goto/16 :goto_51

    .line 1895
    .line 1896
    :cond_32
    move/from16 v30, v4

    .line 1897
    .line 1898
    :goto_35
    move/from16 v4, v31

    .line 1899
    .line 1900
    goto/16 :goto_42

    .line 1901
    .line 1902
    :cond_33
    move/from16 v29, v4

    .line 1903
    .line 1904
    goto :goto_35

    .line 1905
    :cond_34
    move/from16 v28, v4

    .line 1906
    .line 1907
    goto :goto_35

    .line 1908
    :cond_35
    :goto_36
    move/from16 v26, v4

    .line 1909
    .line 1910
    goto :goto_35

    .line 1911
    :cond_36
    :goto_37
    move-object/from16 v25, v2

    .line 1912
    .line 1913
    move/from16 v26, v4

    .line 1914
    .line 1915
    move/from16 v2, v27

    .line 1916
    .line 1917
    goto :goto_35

    .line 1918
    :cond_37
    :goto_38
    move-object/from16 v24, v0

    .line 1919
    .line 1920
    move-object/from16 v25, v2

    .line 1921
    .line 1922
    move/from16 v0, v26

    .line 1923
    .line 1924
    move/from16 v2, v27

    .line 1925
    .line 1926
    goto :goto_36

    .line 1927
    :cond_38
    :goto_39
    move-object/from16 v24, v0

    .line 1928
    .line 1929
    move-object/from16 v23, v15

    .line 1930
    .line 1931
    move/from16 v15, v25

    .line 1932
    .line 1933
    move/from16 v0, v26

    .line 1934
    .line 1935
    goto :goto_37

    .line 1936
    :cond_39
    :goto_3a
    move/from16 v22, v14

    .line 1937
    .line 1938
    move-object/from16 v23, v15

    .line 1939
    .line 1940
    move/from16 v14, v24

    .line 1941
    .line 1942
    move/from16 v15, v25

    .line 1943
    .line 1944
    goto :goto_38

    .line 1945
    :cond_3a
    :goto_3b
    move/from16 v21, v13

    .line 1946
    .line 1947
    move/from16 v22, v14

    .line 1948
    .line 1949
    move/from16 v13, v23

    .line 1950
    .line 1951
    move/from16 v14, v24

    .line 1952
    .line 1953
    goto :goto_39

    .line 1954
    :cond_3b
    :goto_3c
    move/from16 v20, v12

    .line 1955
    .line 1956
    move/from16 v21, v13

    .line 1957
    .line 1958
    move/from16 v12, v22

    .line 1959
    .line 1960
    move/from16 v13, v23

    .line 1961
    .line 1962
    goto :goto_3a

    .line 1963
    :cond_3c
    :goto_3d
    move/from16 v19, v11

    .line 1964
    .line 1965
    move/from16 v20, v12

    .line 1966
    .line 1967
    move/from16 v11, v21

    .line 1968
    .line 1969
    move/from16 v12, v22

    .line 1970
    .line 1971
    goto :goto_3b

    .line 1972
    :cond_3d
    :goto_3e
    move/from16 v18, v10

    .line 1973
    .line 1974
    move/from16 v19, v11

    .line 1975
    .line 1976
    move/from16 v10, v20

    .line 1977
    .line 1978
    move/from16 v11, v21

    .line 1979
    .line 1980
    goto :goto_3c

    .line 1981
    :cond_3e
    :goto_3f
    move/from16 v17, v9

    .line 1982
    .line 1983
    move/from16 v18, v10

    .line 1984
    .line 1985
    move/from16 v9, v19

    .line 1986
    .line 1987
    move/from16 v10, v20

    .line 1988
    .line 1989
    goto :goto_3d

    .line 1990
    :cond_3f
    :goto_40
    move/from16 v16, v8

    .line 1991
    .line 1992
    move/from16 v17, v9

    .line 1993
    .line 1994
    move/from16 v8, v18

    .line 1995
    .line 1996
    move/from16 v9, v19

    .line 1997
    .line 1998
    goto :goto_3e

    .line 1999
    :cond_40
    :goto_41
    move/from16 p1, v7

    .line 2000
    .line 2001
    move/from16 v16, v8

    .line 2002
    .line 2003
    move/from16 v7, v17

    .line 2004
    .line 2005
    move/from16 v8, v18

    .line 2006
    .line 2007
    goto :goto_3f

    .line 2008
    :cond_41
    move/from16 v48, v5

    .line 2009
    .line 2010
    move/from16 p1, v7

    .line 2011
    .line 2012
    move/from16 v5, v16

    .line 2013
    .line 2014
    move/from16 v7, v17

    .line 2015
    .line 2016
    goto :goto_40

    .line 2017
    :cond_42
    move/from16 v33, v1

    .line 2018
    .line 2019
    move/from16 v48, v5

    .line 2020
    .line 2021
    move/from16 v5, v16

    .line 2022
    .line 2023
    move/from16 v1, p1

    .line 2024
    .line 2025
    goto :goto_41

    .line 2026
    :goto_42
    invoke-interface {v3, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2027
    .line 2028
    .line 2029
    move-result-object v50

    .line 2030
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2031
    .line 2032
    .line 2033
    move-result-object v51

    .line 2034
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2035
    .line 2036
    .line 2037
    move-result-object v52

    .line 2038
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2039
    .line 2040
    .line 2041
    move-result-object v53

    .line 2042
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 2043
    .line 2044
    .line 2045
    move-result v27

    .line 2046
    if-eqz v27, :cond_43

    .line 2047
    .line 2048
    const/16 v27, 0x0

    .line 2049
    .line 2050
    goto :goto_43

    .line 2051
    :cond_43
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2052
    .line 2053
    .line 2054
    move-result-object v27

    .line 2055
    :goto_43
    invoke-static/range {v27 .. v27}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 2056
    .line 2057
    .line 2058
    move-result-object v54

    .line 2059
    if-eqz v54, :cond_50

    .line 2060
    .line 2061
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2062
    .line 2063
    .line 2064
    move-result-object v27

    .line 2065
    invoke-static/range {v27 .. v27}, Lif0/m;->d(Ljava/lang/String;)Lss0/p;

    .line 2066
    .line 2067
    .line 2068
    move-result-object v55

    .line 2069
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 2070
    .line 2071
    .line 2072
    move-result v27

    .line 2073
    if-eqz v27, :cond_44

    .line 2074
    .line 2075
    const/16 v57, 0x0

    .line 2076
    .line 2077
    goto :goto_44

    .line 2078
    :cond_44
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2079
    .line 2080
    .line 2081
    move-result-object v27

    .line 2082
    move-object/from16 v57, v27

    .line 2083
    .line 2084
    :goto_44
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 2085
    .line 2086
    .line 2087
    move-result v27

    .line 2088
    if-eqz v27, :cond_45

    .line 2089
    .line 2090
    const/16 v58, 0x0

    .line 2091
    .line 2092
    goto :goto_45

    .line 2093
    :cond_45
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2094
    .line 2095
    .line 2096
    move-result-object v27

    .line 2097
    move-object/from16 v58, v27

    .line 2098
    .line 2099
    :goto_45
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 2100
    .line 2101
    .line 2102
    move-result v27

    .line 2103
    if-eqz v27, :cond_46

    .line 2104
    .line 2105
    move/from16 v31, v5

    .line 2106
    .line 2107
    move/from16 v27, v6

    .line 2108
    .line 2109
    const/16 v59, 0x0

    .line 2110
    .line 2111
    goto :goto_46

    .line 2112
    :cond_46
    move/from16 v31, v5

    .line 2113
    .line 2114
    move/from16 v27, v6

    .line 2115
    .line 2116
    invoke-interface {v3, v12}, Lua/c;->getLong(I)J

    .line 2117
    .line 2118
    .line 2119
    move-result-wide v5

    .line 2120
    long-to-int v5, v5

    .line 2121
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2122
    .line 2123
    .line 2124
    move-result-object v5

    .line 2125
    move-object/from16 v59, v5

    .line 2126
    .line 2127
    :goto_46
    invoke-interface {v3, v13}, Lua/c;->isNull(I)Z

    .line 2128
    .line 2129
    .line 2130
    move-result v5

    .line 2131
    if-eqz v5, :cond_47

    .line 2132
    .line 2133
    const/16 v60, 0x0

    .line 2134
    .line 2135
    goto :goto_47

    .line 2136
    :cond_47
    invoke-interface {v3, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2137
    .line 2138
    .line 2139
    move-result-object v5

    .line 2140
    move-object/from16 v60, v5

    .line 2141
    .line 2142
    :goto_47
    invoke-interface {v3, v14}, Lua/c;->isNull(I)Z

    .line 2143
    .line 2144
    .line 2145
    move-result v5

    .line 2146
    if-eqz v5, :cond_48

    .line 2147
    .line 2148
    const/16 v61, 0x0

    .line 2149
    .line 2150
    goto :goto_48

    .line 2151
    :cond_48
    invoke-interface {v3, v14}, Lua/c;->getLong(I)J

    .line 2152
    .line 2153
    .line 2154
    move-result-wide v5

    .line 2155
    long-to-int v5, v5

    .line 2156
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2157
    .line 2158
    .line 2159
    move-result-object v5

    .line 2160
    move-object/from16 v61, v5

    .line 2161
    .line 2162
    :goto_48
    invoke-interface {v3, v15}, Lua/c;->isNull(I)Z

    .line 2163
    .line 2164
    .line 2165
    move-result v5

    .line 2166
    if-eqz v5, :cond_49

    .line 2167
    .line 2168
    const/16 v62, 0x0

    .line 2169
    .line 2170
    goto :goto_49

    .line 2171
    :cond_49
    invoke-interface {v3, v15}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2172
    .line 2173
    .line 2174
    move-result-object v5

    .line 2175
    move-object/from16 v62, v5

    .line 2176
    .line 2177
    :goto_49
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 2178
    .line 2179
    .line 2180
    move-result v5

    .line 2181
    if-eqz v5, :cond_4a

    .line 2182
    .line 2183
    const/16 v63, 0x0

    .line 2184
    .line 2185
    goto :goto_4a

    .line 2186
    :cond_4a
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 2187
    .line 2188
    .line 2189
    move-result-wide v5

    .line 2190
    long-to-int v5, v5

    .line 2191
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2192
    .line 2193
    .line 2194
    move-result-object v5

    .line 2195
    move-object/from16 v63, v5

    .line 2196
    .line 2197
    :goto_4a
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 2198
    .line 2199
    .line 2200
    move-result v5

    .line 2201
    if-eqz v5, :cond_4b

    .line 2202
    .line 2203
    const/16 v64, 0x0

    .line 2204
    .line 2205
    :goto_4b
    move/from16 v5, v28

    .line 2206
    .line 2207
    goto :goto_4c

    .line 2208
    :cond_4b
    invoke-interface {v3, v2}, Lua/c;->getLong(I)J

    .line 2209
    .line 2210
    .line 2211
    move-result-wide v5

    .line 2212
    long-to-int v5, v5

    .line 2213
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2214
    .line 2215
    .line 2216
    move-result-object v5

    .line 2217
    move-object/from16 v64, v5

    .line 2218
    .line 2219
    goto :goto_4b

    .line 2220
    :goto_4c
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 2221
    .line 2222
    .line 2223
    move-result v6

    .line 2224
    if-eqz v6, :cond_4c

    .line 2225
    .line 2226
    move/from16 v28, v0

    .line 2227
    .line 2228
    move v6, v1

    .line 2229
    const/16 v65, 0x0

    .line 2230
    .line 2231
    :goto_4d
    move/from16 v0, v29

    .line 2232
    .line 2233
    move/from16 v29, v2

    .line 2234
    .line 2235
    goto :goto_4e

    .line 2236
    :cond_4c
    move/from16 v28, v0

    .line 2237
    .line 2238
    move v6, v1

    .line 2239
    invoke-interface {v3, v5}, Lua/c;->getLong(I)J

    .line 2240
    .line 2241
    .line 2242
    move-result-wide v0

    .line 2243
    long-to-int v0, v0

    .line 2244
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2245
    .line 2246
    .line 2247
    move-result-object v0

    .line 2248
    move-object/from16 v65, v0

    .line 2249
    .line 2250
    goto :goto_4d

    .line 2251
    :goto_4e
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 2252
    .line 2253
    .line 2254
    move-result-wide v1

    .line 2255
    long-to-int v1, v1

    .line 2256
    move/from16 v2, v30

    .line 2257
    .line 2258
    invoke-interface {v3, v2}, Lua/c;->isNull(I)Z

    .line 2259
    .line 2260
    .line 2261
    move-result v30

    .line 2262
    if-eqz v30, :cond_4d

    .line 2263
    .line 2264
    move/from16 v66, v0

    .line 2265
    .line 2266
    const/4 v0, 0x0

    .line 2267
    goto :goto_4f

    .line 2268
    :cond_4d
    invoke-interface {v3, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2269
    .line 2270
    .line 2271
    move-result-object v30

    .line 2272
    move/from16 v66, v0

    .line 2273
    .line 2274
    move-object/from16 v0, v30

    .line 2275
    .line 2276
    :goto_4f
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 2277
    .line 2278
    .line 2279
    move-result v30

    .line 2280
    if-eqz v30, :cond_4e

    .line 2281
    .line 2282
    move/from16 v30, v5

    .line 2283
    .line 2284
    move/from16 v67, v6

    .line 2285
    .line 2286
    const/4 v5, 0x0

    .line 2287
    goto :goto_50

    .line 2288
    :cond_4e
    move/from16 v30, v5

    .line 2289
    .line 2290
    move/from16 v67, v6

    .line 2291
    .line 2292
    invoke-interface {v3, v4}, Lua/c;->getDouble(I)D

    .line 2293
    .line 2294
    .line 2295
    move-result-wide v5

    .line 2296
    double-to-float v5, v5

    .line 2297
    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2298
    .line 2299
    .line 2300
    move-result-object v5

    .line 2301
    :goto_50
    new-instance v6, Lif0/q;

    .line 2302
    .line 2303
    invoke-direct {v6, v1, v0, v5}, Lif0/q;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

    .line 2304
    .line 2305
    .line 2306
    new-instance v49, Lif0/p;

    .line 2307
    .line 2308
    move-object/from16 v56, v6

    .line 2309
    .line 2310
    invoke-direct/range {v49 .. v65}, Lif0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/p;Lif0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 2311
    .line 2312
    .line 2313
    goto/16 :goto_34

    .line 2314
    .line 2315
    :goto_51
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 2316
    .line 2317
    .line 2318
    move-result v1

    .line 2319
    if-nez v1, :cond_4f

    .line 2320
    .line 2321
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2322
    .line 2323
    .line 2324
    move-result-object v1

    .line 2325
    new-instance v5, Lif0/g0;

    .line 2326
    .line 2327
    invoke-direct {v5, v1}, Lif0/g0;-><init>(Ljava/lang/String;)V

    .line 2328
    .line 2329
    .line 2330
    move-object/from16 v50, v5

    .line 2331
    .line 2332
    goto :goto_52

    .line 2333
    :cond_4f
    const/16 v50, 0x0

    .line 2334
    .line 2335
    :goto_52
    new-instance v37, Lif0/o;

    .line 2336
    .line 2337
    invoke-direct/range {v37 .. v50}, Lif0/o;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lss0/m;Lss0/n;Ljava/lang/String;Ljava/lang/String;ZILif0/p;Lif0/g0;)V

    .line 2338
    .line 2339
    .line 2340
    move-object/from16 v1, v37

    .line 2341
    .line 2342
    move/from16 v5, v26

    .line 2343
    .line 2344
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2345
    .line 2346
    .line 2347
    move-result-object v6

    .line 2348
    move/from16 v32, v0

    .line 2349
    .line 2350
    move-object/from16 v0, v25

    .line 2351
    .line 2352
    invoke-static {v0, v6}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2353
    .line 2354
    .line 2355
    move-result-object v6

    .line 2356
    move-object/from16 v25, v0

    .line 2357
    .line 2358
    move-object/from16 v0, p0

    .line 2359
    .line 2360
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2361
    .line 2362
    .line 2363
    check-cast v6, Ljava/util/List;

    .line 2364
    .line 2365
    move/from16 v26, v2

    .line 2366
    .line 2367
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2368
    .line 2369
    .line 2370
    move-result-object v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 2371
    move-object/from16 p0, v3

    .line 2372
    .line 2373
    move-object/from16 v3, v23

    .line 2374
    .line 2375
    :try_start_3
    invoke-static {v3, v2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2376
    .line 2377
    .line 2378
    move-result-object v2

    .line 2379
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2380
    .line 2381
    .line 2382
    check-cast v2, Ljava/util/List;

    .line 2383
    .line 2384
    move-object/from16 v23, v0

    .line 2385
    .line 2386
    new-instance v0, Lif0/n;

    .line 2387
    .line 2388
    invoke-direct {v0, v1, v6, v2}, Lif0/n;-><init>(Lif0/o;Ljava/util/List;Ljava/util/List;)V

    .line 2389
    .line 2390
    .line 2391
    move-object/from16 v1, v24

    .line 2392
    .line 2393
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2394
    .line 2395
    .line 2396
    move/from16 v0, v31

    .line 2397
    .line 2398
    move/from16 v31, v4

    .line 2399
    .line 2400
    move v4, v5

    .line 2401
    move/from16 v5, v22

    .line 2402
    .line 2403
    move/from16 v22, v12

    .line 2404
    .line 2405
    move/from16 v12, v20

    .line 2406
    .line 2407
    move/from16 v20, v10

    .line 2408
    .line 2409
    move/from16 v10, v18

    .line 2410
    .line 2411
    move/from16 v18, v8

    .line 2412
    .line 2413
    move/from16 v8, v16

    .line 2414
    .line 2415
    move/from16 v16, v0

    .line 2416
    .line 2417
    move/from16 v0, v30

    .line 2418
    .line 2419
    move/from16 v30, v26

    .line 2420
    .line 2421
    move/from16 v26, v28

    .line 2422
    .line 2423
    move/from16 v28, v0

    .line 2424
    .line 2425
    move-object v0, v1

    .line 2426
    move/from16 v24, v14

    .line 2427
    .line 2428
    move-object/from16 v2, v25

    .line 2429
    .line 2430
    move/from16 v36, v33

    .line 2431
    .line 2432
    move/from16 v6, v34

    .line 2433
    .line 2434
    move-object v14, v3

    .line 2435
    move/from16 v25, v15

    .line 2436
    .line 2437
    move/from16 v34, v21

    .line 2438
    .line 2439
    move/from16 v33, v27

    .line 2440
    .line 2441
    move/from16 v27, v29

    .line 2442
    .line 2443
    move/from16 v29, v66

    .line 2444
    .line 2445
    move-object/from16 v3, p0

    .line 2446
    .line 2447
    move/from16 v21, v11

    .line 2448
    .line 2449
    move/from16 v11, v19

    .line 2450
    .line 2451
    move-object/from16 p0, v23

    .line 2452
    .line 2453
    move/from16 v19, v9

    .line 2454
    .line 2455
    move/from16 v23, v13

    .line 2456
    .line 2457
    move/from16 v9, v17

    .line 2458
    .line 2459
    move/from16 v17, v7

    .line 2460
    .line 2461
    move/from16 v7, p1

    .line 2462
    .line 2463
    move/from16 p1, v67

    .line 2464
    .line 2465
    goto/16 :goto_2c

    .line 2466
    .line 2467
    :catchall_3
    move-exception v0

    .line 2468
    goto :goto_53

    .line 2469
    :cond_50
    move-object/from16 p0, v3

    .line 2470
    .line 2471
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2472
    .line 2473
    const-string v1, "Expected NON-NULL \'java.time.LocalDate\', but it was NULL."

    .line 2474
    .line 2475
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2476
    .line 2477
    .line 2478
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 2479
    :cond_51
    move-object v1, v0

    .line 2480
    move-object/from16 p0, v3

    .line 2481
    .line 2482
    invoke-interface/range {p0 .. p0}, Ljava/lang/AutoCloseable;->close()V

    .line 2483
    .line 2484
    .line 2485
    return-object v1

    .line 2486
    :goto_53
    invoke-interface/range {p0 .. p0}, Ljava/lang/AutoCloseable;->close()V

    .line 2487
    .line 2488
    .line 2489
    throw v0

    .line 2490
    nop

    .line 2491
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
