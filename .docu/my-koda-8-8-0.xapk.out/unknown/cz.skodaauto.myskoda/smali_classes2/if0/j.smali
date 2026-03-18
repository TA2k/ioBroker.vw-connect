.class public final synthetic Lif0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lif0/m;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lif0/m;I)V
    .locals 0

    .line 1
    iput p3, p0, Lif0/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lif0/j;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lif0/j;->f:Lif0/m;

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
    .locals 67

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lif0/j;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lif0/j;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Lif0/j;->f:Lif0/m;

    .line 11
    .line 12
    move-object/from16 v2, p1

    .line 13
    .line 14
    check-cast v2, Lua/a;

    .line 15
    .line 16
    const-string v3, "getValue(...)"

    .line 17
    .line 18
    const-string v4, "_connection"

    .line 19
    .line 20
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v4, "SELECT * FROM vehicle where ? is vin"

    .line 24
    .line 25
    invoke-interface {v2, v4}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    const/4 v5, 0x1

    .line 30
    :try_start_0
    invoke-interface {v4, v5, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v1, "vin"

    .line 34
    .line 35
    invoke-static {v4, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    const-string v6, "systemModelId"

    .line 40
    .line 41
    invoke-static {v4, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    const-string v7, "name"

    .line 46
    .line 47
    invoke-static {v4, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    const-string v8, "title"

    .line 52
    .line 53
    invoke-static {v4, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    move-result v8

    .line 57
    const-string v9, "licensePlate"

    .line 58
    .line 59
    invoke-static {v4, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    const-string v10, "state"

    .line 64
    .line 65
    invoke-static {v4, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    move-result v10

    .line 69
    const-string v11, "devicePlatform"

    .line 70
    .line 71
    invoke-static {v4, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 72
    .line 73
    .line 74
    move-result v11

    .line 75
    const-string v12, "softwareVersion"

    .line 76
    .line 77
    invoke-static {v4, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 78
    .line 79
    .line 80
    move-result v12

    .line 81
    const-string v13, "connectivity_sunset_impact"

    .line 82
    .line 83
    invoke-static {v4, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 84
    .line 85
    .line 86
    move-result v13

    .line 87
    const-string v14, "isWorkshopMode"

    .line 88
    .line 89
    invoke-static {v4, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 90
    .line 91
    .line 92
    move-result v14

    .line 93
    const-string v15, "priority"

    .line 94
    .line 95
    invoke-static {v4, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 96
    .line 97
    .line 98
    move-result v15

    .line 99
    const-string v5, "spec_title"

    .line 100
    .line 101
    invoke-static {v4, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    move-object/from16 p1, v3

    .line 106
    .line 107
    const-string v3, "spec_systemCode"

    .line 108
    .line 109
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    move/from16 v16, v3

    .line 114
    .line 115
    const-string v3, "spec_systemModelId"

    .line 116
    .line 117
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    move/from16 v17, v3

    .line 122
    .line 123
    const-string v3, "spec_model"

    .line 124
    .line 125
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    move/from16 v18, v3

    .line 130
    .line 131
    const-string v3, "spec_manufacturingDate"

    .line 132
    .line 133
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    move/from16 v19, v3

    .line 138
    .line 139
    const-string v3, "spec_gearboxType"

    .line 140
    .line 141
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    move/from16 v20, v3

    .line 146
    .line 147
    const-string v3, "spec_modelYear"

    .line 148
    .line 149
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    move/from16 v21, v3

    .line 154
    .line 155
    const-string v3, "spec_body"

    .line 156
    .line 157
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    move/from16 v22, v3

    .line 162
    .line 163
    const-string v3, "spec_batteryCapacity"

    .line 164
    .line 165
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    move/from16 v23, v3

    .line 170
    .line 171
    const-string v3, "spec_trimLevel"

    .line 172
    .line 173
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 174
    .line 175
    .line 176
    move-result v3

    .line 177
    move/from16 v24, v3

    .line 178
    .line 179
    const-string v3, "spec_maxChargingPowerInKW"

    .line 180
    .line 181
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    move/from16 v25, v3

    .line 186
    .line 187
    const-string v3, "spec_colour"

    .line 188
    .line 189
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 190
    .line 191
    .line 192
    move-result v3

    .line 193
    move/from16 v26, v3

    .line 194
    .line 195
    const-string v3, "spec_length"

    .line 196
    .line 197
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 198
    .line 199
    .line 200
    move-result v3

    .line 201
    move/from16 v27, v3

    .line 202
    .line 203
    const-string v3, "spec_width"

    .line 204
    .line 205
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 206
    .line 207
    .line 208
    move-result v3

    .line 209
    move/from16 v28, v3

    .line 210
    .line 211
    const-string v3, "spec_height"

    .line 212
    .line 213
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 214
    .line 215
    .line 216
    move-result v3

    .line 217
    move/from16 v29, v3

    .line 218
    .line 219
    const-string v3, "spec_enginepowerInKW"

    .line 220
    .line 221
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    move/from16 v30, v3

    .line 226
    .line 227
    const-string v3, "spec_enginetype"

    .line 228
    .line 229
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    move/from16 v31, v3

    .line 234
    .line 235
    const-string v3, "spec_enginecapacityInLiters"

    .line 236
    .line 237
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 238
    .line 239
    .line 240
    move-result v3

    .line 241
    move/from16 v32, v3

    .line 242
    .line 243
    const-string v3, "servicePartner_id"

    .line 244
    .line 245
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 246
    .line 247
    .line 248
    move-result v3

    .line 249
    move/from16 v33, v3

    .line 250
    .line 251
    new-instance v3, Landroidx/collection/f;

    .line 252
    .line 253
    move/from16 v34, v5

    .line 254
    .line 255
    const/4 v5, 0x0

    .line 256
    invoke-direct {v3, v5}, Landroidx/collection/a1;-><init>(I)V

    .line 257
    .line 258
    .line 259
    move/from16 v35, v15

    .line 260
    .line 261
    new-instance v15, Landroidx/collection/f;

    .line 262
    .line 263
    invoke-direct {v15, v5}, Landroidx/collection/a1;-><init>(I)V

    .line 264
    .line 265
    .line 266
    :goto_0
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 267
    .line 268
    .line 269
    move-result v36

    .line 270
    if-eqz v36, :cond_2

    .line 271
    .line 272
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 273
    .line 274
    .line 275
    move-result-object v5

    .line 276
    invoke-virtual {v3, v5}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 277
    .line 278
    .line 279
    move-result v37

    .line 280
    if-nez v37, :cond_0

    .line 281
    .line 282
    move/from16 v37, v14

    .line 283
    .line 284
    new-instance v14, Ljava/util/ArrayList;

    .line 285
    .line 286
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 287
    .line 288
    .line 289
    invoke-virtual {v3, v5, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    goto :goto_1

    .line 293
    :catchall_0
    move-exception v0

    .line 294
    goto/16 :goto_29

    .line 295
    .line 296
    :cond_0
    move/from16 v37, v14

    .line 297
    .line 298
    :goto_1
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object v5

    .line 302
    invoke-virtual {v15, v5}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    move-result v14

    .line 306
    if-nez v14, :cond_1

    .line 307
    .line 308
    new-instance v14, Ljava/util/ArrayList;

    .line 309
    .line 310
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 311
    .line 312
    .line 313
    invoke-virtual {v15, v5, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 314
    .line 315
    .line 316
    :cond_1
    move/from16 v14, v37

    .line 317
    .line 318
    const/4 v5, 0x0

    .line 319
    goto :goto_0

    .line 320
    :cond_2
    move/from16 v37, v14

    .line 321
    .line 322
    invoke-interface {v4}, Lua/c;->reset()V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v0, v2, v3}, Lif0/m;->e(Lua/a;Landroidx/collection/f;)V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v0, v2, v15}, Lif0/m;->f(Lua/a;Landroidx/collection/f;)V

    .line 329
    .line 330
    .line 331
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 332
    .line 333
    .line 334
    move-result v0

    .line 335
    if-eqz v0, :cond_28

    .line 336
    .line 337
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v39

    .line 341
    invoke-interface {v4, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v40

    .line 345
    invoke-interface {v4, v7}, Lua/c;->isNull(I)Z

    .line 346
    .line 347
    .line 348
    move-result v0

    .line 349
    if-eqz v0, :cond_3

    .line 350
    .line 351
    const/16 v41, 0x0

    .line 352
    .line 353
    goto :goto_2

    .line 354
    :cond_3
    invoke-interface {v4, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v0

    .line 358
    move-object/from16 v41, v0

    .line 359
    .line 360
    :goto_2
    invoke-interface {v4, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 361
    .line 362
    .line 363
    move-result-object v42

    .line 364
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 365
    .line 366
    .line 367
    move-result v0

    .line 368
    if-eqz v0, :cond_4

    .line 369
    .line 370
    const/16 v43, 0x0

    .line 371
    .line 372
    goto :goto_3

    .line 373
    :cond_4
    invoke-interface {v4, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    move-object/from16 v43, v0

    .line 378
    .line 379
    :goto_3
    invoke-interface {v4, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    invoke-static {v0}, Lif0/m;->b(Ljava/lang/String;)Lss0/m;

    .line 384
    .line 385
    .line 386
    move-result-object v44

    .line 387
    invoke-interface {v4, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    invoke-static {v0}, Lif0/m;->c(Ljava/lang/String;)Lss0/n;

    .line 392
    .line 393
    .line 394
    move-result-object v45

    .line 395
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 396
    .line 397
    .line 398
    move-result v0

    .line 399
    if-eqz v0, :cond_5

    .line 400
    .line 401
    const/16 v46, 0x0

    .line 402
    .line 403
    goto :goto_4

    .line 404
    :cond_5
    invoke-interface {v4, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v0

    .line 408
    move-object/from16 v46, v0

    .line 409
    .line 410
    :goto_4
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 411
    .line 412
    .line 413
    move-result v0

    .line 414
    if-eqz v0, :cond_6

    .line 415
    .line 416
    const/16 v47, 0x0

    .line 417
    .line 418
    :goto_5
    move/from16 v0, v37

    .line 419
    .line 420
    goto :goto_6

    .line 421
    :cond_6
    invoke-interface {v4, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v0

    .line 425
    move-object/from16 v47, v0

    .line 426
    .line 427
    goto :goto_5

    .line 428
    :goto_6
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 429
    .line 430
    .line 431
    move-result-wide v5

    .line 432
    long-to-int v0, v5

    .line 433
    if-eqz v0, :cond_7

    .line 434
    .line 435
    const/16 v48, 0x1

    .line 436
    .line 437
    :goto_7
    move/from16 v0, v35

    .line 438
    .line 439
    goto :goto_8

    .line 440
    :cond_7
    const/16 v48, 0x0

    .line 441
    .line 442
    goto :goto_7

    .line 443
    :goto_8
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 444
    .line 445
    .line 446
    move-result-wide v5

    .line 447
    long-to-int v0, v5

    .line 448
    move/from16 v5, v34

    .line 449
    .line 450
    invoke-interface {v4, v5}, Lua/c;->isNull(I)Z

    .line 451
    .line 452
    .line 453
    move-result v6

    .line 454
    if-eqz v6, :cond_19

    .line 455
    .line 456
    move/from16 v6, v16

    .line 457
    .line 458
    invoke-interface {v4, v6}, Lua/c;->isNull(I)Z

    .line 459
    .line 460
    .line 461
    move-result v7

    .line 462
    if-eqz v7, :cond_18

    .line 463
    .line 464
    move/from16 v7, v17

    .line 465
    .line 466
    invoke-interface {v4, v7}, Lua/c;->isNull(I)Z

    .line 467
    .line 468
    .line 469
    move-result v8

    .line 470
    if-eqz v8, :cond_17

    .line 471
    .line 472
    move/from16 v8, v18

    .line 473
    .line 474
    invoke-interface {v4, v8}, Lua/c;->isNull(I)Z

    .line 475
    .line 476
    .line 477
    move-result v9

    .line 478
    if-eqz v9, :cond_16

    .line 479
    .line 480
    move/from16 v9, v19

    .line 481
    .line 482
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 483
    .line 484
    .line 485
    move-result v10

    .line 486
    if-eqz v10, :cond_15

    .line 487
    .line 488
    move/from16 v10, v20

    .line 489
    .line 490
    invoke-interface {v4, v10}, Lua/c;->isNull(I)Z

    .line 491
    .line 492
    .line 493
    move-result v11

    .line 494
    if-eqz v11, :cond_14

    .line 495
    .line 496
    move/from16 v11, v21

    .line 497
    .line 498
    invoke-interface {v4, v11}, Lua/c;->isNull(I)Z

    .line 499
    .line 500
    .line 501
    move-result v12

    .line 502
    if-eqz v12, :cond_13

    .line 503
    .line 504
    move/from16 v12, v22

    .line 505
    .line 506
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 507
    .line 508
    .line 509
    move-result v13

    .line 510
    if-eqz v13, :cond_12

    .line 511
    .line 512
    move/from16 v13, v23

    .line 513
    .line 514
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 515
    .line 516
    .line 517
    move-result v14

    .line 518
    if-eqz v14, :cond_11

    .line 519
    .line 520
    move/from16 v14, v24

    .line 521
    .line 522
    invoke-interface {v4, v14}, Lua/c;->isNull(I)Z

    .line 523
    .line 524
    .line 525
    move-result v16

    .line 526
    if-eqz v16, :cond_10

    .line 527
    .line 528
    move/from16 v2, v25

    .line 529
    .line 530
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 531
    .line 532
    .line 533
    move-result v16

    .line 534
    if-eqz v16, :cond_f

    .line 535
    .line 536
    move/from16 v49, v0

    .line 537
    .line 538
    move/from16 v0, v26

    .line 539
    .line 540
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 541
    .line 542
    .line 543
    move-result v16

    .line 544
    if-eqz v16, :cond_e

    .line 545
    .line 546
    move-object/from16 v16, v15

    .line 547
    .line 548
    move/from16 v15, v27

    .line 549
    .line 550
    invoke-interface {v4, v15}, Lua/c;->isNull(I)Z

    .line 551
    .line 552
    .line 553
    move-result v17

    .line 554
    if-eqz v17, :cond_d

    .line 555
    .line 556
    move-object/from16 v17, v3

    .line 557
    .line 558
    move/from16 v3, v28

    .line 559
    .line 560
    invoke-interface {v4, v3}, Lua/c;->isNull(I)Z

    .line 561
    .line 562
    .line 563
    move-result v18

    .line 564
    if-eqz v18, :cond_c

    .line 565
    .line 566
    move/from16 v18, v1

    .line 567
    .line 568
    move/from16 v1, v29

    .line 569
    .line 570
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 571
    .line 572
    .line 573
    move-result v19

    .line 574
    if-eqz v19, :cond_b

    .line 575
    .line 576
    move/from16 v29, v1

    .line 577
    .line 578
    move/from16 v1, v30

    .line 579
    .line 580
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 581
    .line 582
    .line 583
    move-result v19

    .line 584
    if-eqz v19, :cond_a

    .line 585
    .line 586
    move/from16 v30, v1

    .line 587
    .line 588
    move/from16 v1, v31

    .line 589
    .line 590
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 591
    .line 592
    .line 593
    move-result v19

    .line 594
    if-eqz v19, :cond_9

    .line 595
    .line 596
    move/from16 v31, v1

    .line 597
    .line 598
    move/from16 v1, v32

    .line 599
    .line 600
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 601
    .line 602
    .line 603
    move-result v19

    .line 604
    if-nez v19, :cond_8

    .line 605
    .line 606
    goto/16 :goto_17

    .line 607
    .line 608
    :cond_8
    const/16 v50, 0x0

    .line 609
    .line 610
    :goto_9
    move/from16 v0, v33

    .line 611
    .line 612
    goto/16 :goto_26

    .line 613
    .line 614
    :cond_9
    move/from16 v31, v1

    .line 615
    .line 616
    :goto_a
    move/from16 v1, v32

    .line 617
    .line 618
    goto/16 :goto_17

    .line 619
    .line 620
    :cond_a
    move/from16 v30, v1

    .line 621
    .line 622
    goto :goto_a

    .line 623
    :cond_b
    move/from16 v29, v1

    .line 624
    .line 625
    goto :goto_a

    .line 626
    :cond_c
    :goto_b
    move/from16 v18, v1

    .line 627
    .line 628
    goto :goto_a

    .line 629
    :cond_d
    :goto_c
    move/from16 v18, v1

    .line 630
    .line 631
    move-object/from16 v17, v3

    .line 632
    .line 633
    :goto_d
    move/from16 v3, v28

    .line 634
    .line 635
    goto :goto_a

    .line 636
    :cond_e
    :goto_e
    move/from16 v18, v1

    .line 637
    .line 638
    move-object/from16 v17, v3

    .line 639
    .line 640
    move-object/from16 v16, v15

    .line 641
    .line 642
    :goto_f
    move/from16 v15, v27

    .line 643
    .line 644
    goto :goto_d

    .line 645
    :cond_f
    move/from16 v49, v0

    .line 646
    .line 647
    move/from16 v18, v1

    .line 648
    .line 649
    move-object/from16 v17, v3

    .line 650
    .line 651
    move-object/from16 v16, v15

    .line 652
    .line 653
    :goto_10
    move/from16 v0, v26

    .line 654
    .line 655
    goto :goto_f

    .line 656
    :cond_10
    move/from16 v49, v0

    .line 657
    .line 658
    move/from16 v18, v1

    .line 659
    .line 660
    move-object/from16 v17, v3

    .line 661
    .line 662
    move-object/from16 v16, v15

    .line 663
    .line 664
    :goto_11
    move/from16 v2, v25

    .line 665
    .line 666
    goto :goto_10

    .line 667
    :cond_11
    move/from16 v49, v0

    .line 668
    .line 669
    move/from16 v18, v1

    .line 670
    .line 671
    move-object/from16 v17, v3

    .line 672
    .line 673
    move-object/from16 v16, v15

    .line 674
    .line 675
    :goto_12
    move/from16 v14, v24

    .line 676
    .line 677
    goto :goto_11

    .line 678
    :cond_12
    move/from16 v49, v0

    .line 679
    .line 680
    move/from16 v18, v1

    .line 681
    .line 682
    move-object/from16 v17, v3

    .line 683
    .line 684
    move-object/from16 v16, v15

    .line 685
    .line 686
    :goto_13
    move/from16 v13, v23

    .line 687
    .line 688
    goto :goto_12

    .line 689
    :cond_13
    move/from16 v49, v0

    .line 690
    .line 691
    move/from16 v18, v1

    .line 692
    .line 693
    move-object/from16 v17, v3

    .line 694
    .line 695
    move-object/from16 v16, v15

    .line 696
    .line 697
    :goto_14
    move/from16 v12, v22

    .line 698
    .line 699
    goto :goto_13

    .line 700
    :cond_14
    move/from16 v49, v0

    .line 701
    .line 702
    move/from16 v18, v1

    .line 703
    .line 704
    move-object/from16 v17, v3

    .line 705
    .line 706
    move-object/from16 v16, v15

    .line 707
    .line 708
    :goto_15
    move/from16 v11, v21

    .line 709
    .line 710
    goto :goto_14

    .line 711
    :cond_15
    move/from16 v49, v0

    .line 712
    .line 713
    move/from16 v18, v1

    .line 714
    .line 715
    move-object/from16 v17, v3

    .line 716
    .line 717
    move-object/from16 v16, v15

    .line 718
    .line 719
    :goto_16
    move/from16 v10, v20

    .line 720
    .line 721
    goto :goto_15

    .line 722
    :cond_16
    move/from16 v49, v0

    .line 723
    .line 724
    move/from16 v18, v1

    .line 725
    .line 726
    move-object/from16 v17, v3

    .line 727
    .line 728
    move-object/from16 v16, v15

    .line 729
    .line 730
    move/from16 v9, v19

    .line 731
    .line 732
    goto :goto_16

    .line 733
    :cond_17
    move/from16 v49, v0

    .line 734
    .line 735
    move-object/from16 v17, v3

    .line 736
    .line 737
    move-object/from16 v16, v15

    .line 738
    .line 739
    move/from16 v8, v18

    .line 740
    .line 741
    move/from16 v9, v19

    .line 742
    .line 743
    move/from16 v10, v20

    .line 744
    .line 745
    move/from16 v11, v21

    .line 746
    .line 747
    move/from16 v12, v22

    .line 748
    .line 749
    move/from16 v13, v23

    .line 750
    .line 751
    move/from16 v14, v24

    .line 752
    .line 753
    move/from16 v2, v25

    .line 754
    .line 755
    move/from16 v0, v26

    .line 756
    .line 757
    move/from16 v15, v27

    .line 758
    .line 759
    move/from16 v3, v28

    .line 760
    .line 761
    goto/16 :goto_b

    .line 762
    .line 763
    :cond_18
    move/from16 v49, v0

    .line 764
    .line 765
    move-object/from16 v16, v15

    .line 766
    .line 767
    move/from16 v7, v17

    .line 768
    .line 769
    move/from16 v8, v18

    .line 770
    .line 771
    move/from16 v9, v19

    .line 772
    .line 773
    move/from16 v10, v20

    .line 774
    .line 775
    move/from16 v11, v21

    .line 776
    .line 777
    move/from16 v12, v22

    .line 778
    .line 779
    move/from16 v13, v23

    .line 780
    .line 781
    move/from16 v14, v24

    .line 782
    .line 783
    move/from16 v2, v25

    .line 784
    .line 785
    move/from16 v0, v26

    .line 786
    .line 787
    move/from16 v15, v27

    .line 788
    .line 789
    goto/16 :goto_c

    .line 790
    .line 791
    :cond_19
    move/from16 v49, v0

    .line 792
    .line 793
    move/from16 v6, v16

    .line 794
    .line 795
    move/from16 v7, v17

    .line 796
    .line 797
    move/from16 v8, v18

    .line 798
    .line 799
    move/from16 v9, v19

    .line 800
    .line 801
    move/from16 v10, v20

    .line 802
    .line 803
    move/from16 v11, v21

    .line 804
    .line 805
    move/from16 v12, v22

    .line 806
    .line 807
    move/from16 v13, v23

    .line 808
    .line 809
    move/from16 v14, v24

    .line 810
    .line 811
    move/from16 v2, v25

    .line 812
    .line 813
    move/from16 v0, v26

    .line 814
    .line 815
    goto/16 :goto_e

    .line 816
    .line 817
    :goto_17
    invoke-interface {v4, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 818
    .line 819
    .line 820
    move-result-object v51

    .line 821
    invoke-interface {v4, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object v52

    .line 825
    invoke-interface {v4, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 826
    .line 827
    .line 828
    move-result-object v53

    .line 829
    invoke-interface {v4, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 830
    .line 831
    .line 832
    move-result-object v54

    .line 833
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 834
    .line 835
    .line 836
    move-result v5

    .line 837
    if-eqz v5, :cond_1a

    .line 838
    .line 839
    const/4 v5, 0x0

    .line 840
    goto :goto_18

    .line 841
    :cond_1a
    invoke-interface {v4, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 842
    .line 843
    .line 844
    move-result-object v5

    .line 845
    :goto_18
    invoke-static {v5}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 846
    .line 847
    .line 848
    move-result-object v55

    .line 849
    if-eqz v55, :cond_27

    .line 850
    .line 851
    invoke-interface {v4, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 852
    .line 853
    .line 854
    move-result-object v5

    .line 855
    invoke-static {v5}, Lif0/m;->d(Ljava/lang/String;)Lss0/p;

    .line 856
    .line 857
    .line 858
    move-result-object v56

    .line 859
    invoke-interface {v4, v11}, Lua/c;->isNull(I)Z

    .line 860
    .line 861
    .line 862
    move-result v5

    .line 863
    if-eqz v5, :cond_1b

    .line 864
    .line 865
    const/16 v58, 0x0

    .line 866
    .line 867
    goto :goto_19

    .line 868
    :cond_1b
    invoke-interface {v4, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 869
    .line 870
    .line 871
    move-result-object v5

    .line 872
    move-object/from16 v58, v5

    .line 873
    .line 874
    :goto_19
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 875
    .line 876
    .line 877
    move-result v5

    .line 878
    if-eqz v5, :cond_1c

    .line 879
    .line 880
    const/16 v59, 0x0

    .line 881
    .line 882
    goto :goto_1a

    .line 883
    :cond_1c
    invoke-interface {v4, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 884
    .line 885
    .line 886
    move-result-object v5

    .line 887
    move-object/from16 v59, v5

    .line 888
    .line 889
    :goto_1a
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 890
    .line 891
    .line 892
    move-result v5

    .line 893
    if-eqz v5, :cond_1d

    .line 894
    .line 895
    const/16 v60, 0x0

    .line 896
    .line 897
    goto :goto_1b

    .line 898
    :cond_1d
    invoke-interface {v4, v13}, Lua/c;->getLong(I)J

    .line 899
    .line 900
    .line 901
    move-result-wide v5

    .line 902
    long-to-int v5, v5

    .line 903
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 904
    .line 905
    .line 906
    move-result-object v5

    .line 907
    move-object/from16 v60, v5

    .line 908
    .line 909
    :goto_1b
    invoke-interface {v4, v14}, Lua/c;->isNull(I)Z

    .line 910
    .line 911
    .line 912
    move-result v5

    .line 913
    if-eqz v5, :cond_1e

    .line 914
    .line 915
    const/16 v61, 0x0

    .line 916
    .line 917
    goto :goto_1c

    .line 918
    :cond_1e
    invoke-interface {v4, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 919
    .line 920
    .line 921
    move-result-object v5

    .line 922
    move-object/from16 v61, v5

    .line 923
    .line 924
    :goto_1c
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 925
    .line 926
    .line 927
    move-result v5

    .line 928
    if-eqz v5, :cond_1f

    .line 929
    .line 930
    const/16 v62, 0x0

    .line 931
    .line 932
    goto :goto_1d

    .line 933
    :cond_1f
    invoke-interface {v4, v2}, Lua/c;->getLong(I)J

    .line 934
    .line 935
    .line 936
    move-result-wide v5

    .line 937
    long-to-int v2, v5

    .line 938
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 939
    .line 940
    .line 941
    move-result-object v2

    .line 942
    move-object/from16 v62, v2

    .line 943
    .line 944
    :goto_1d
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 945
    .line 946
    .line 947
    move-result v2

    .line 948
    if-eqz v2, :cond_20

    .line 949
    .line 950
    const/16 v63, 0x0

    .line 951
    .line 952
    goto :goto_1e

    .line 953
    :cond_20
    invoke-interface {v4, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 954
    .line 955
    .line 956
    move-result-object v0

    .line 957
    move-object/from16 v63, v0

    .line 958
    .line 959
    :goto_1e
    invoke-interface {v4, v15}, Lua/c;->isNull(I)Z

    .line 960
    .line 961
    .line 962
    move-result v0

    .line 963
    if-eqz v0, :cond_21

    .line 964
    .line 965
    const/16 v64, 0x0

    .line 966
    .line 967
    goto :goto_1f

    .line 968
    :cond_21
    invoke-interface {v4, v15}, Lua/c;->getLong(I)J

    .line 969
    .line 970
    .line 971
    move-result-wide v5

    .line 972
    long-to-int v0, v5

    .line 973
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 974
    .line 975
    .line 976
    move-result-object v0

    .line 977
    move-object/from16 v64, v0

    .line 978
    .line 979
    :goto_1f
    invoke-interface {v4, v3}, Lua/c;->isNull(I)Z

    .line 980
    .line 981
    .line 982
    move-result v0

    .line 983
    if-eqz v0, :cond_22

    .line 984
    .line 985
    const/16 v65, 0x0

    .line 986
    .line 987
    :goto_20
    move/from16 v0, v29

    .line 988
    .line 989
    goto :goto_21

    .line 990
    :cond_22
    invoke-interface {v4, v3}, Lua/c;->getLong(I)J

    .line 991
    .line 992
    .line 993
    move-result-wide v2

    .line 994
    long-to-int v0, v2

    .line 995
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 996
    .line 997
    .line 998
    move-result-object v0

    .line 999
    move-object/from16 v65, v0

    .line 1000
    .line 1001
    goto :goto_20

    .line 1002
    :goto_21
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 1003
    .line 1004
    .line 1005
    move-result v2

    .line 1006
    if-eqz v2, :cond_23

    .line 1007
    .line 1008
    const/16 v66, 0x0

    .line 1009
    .line 1010
    :goto_22
    move/from16 v0, v30

    .line 1011
    .line 1012
    goto :goto_23

    .line 1013
    :cond_23
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 1014
    .line 1015
    .line 1016
    move-result-wide v2

    .line 1017
    long-to-int v0, v2

    .line 1018
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1019
    .line 1020
    .line 1021
    move-result-object v0

    .line 1022
    move-object/from16 v66, v0

    .line 1023
    .line 1024
    goto :goto_22

    .line 1025
    :goto_23
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 1026
    .line 1027
    .line 1028
    move-result-wide v2

    .line 1029
    long-to-int v0, v2

    .line 1030
    move/from16 v2, v31

    .line 1031
    .line 1032
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 1033
    .line 1034
    .line 1035
    move-result v3

    .line 1036
    if-eqz v3, :cond_24

    .line 1037
    .line 1038
    const/4 v2, 0x0

    .line 1039
    goto :goto_24

    .line 1040
    :cond_24
    invoke-interface {v4, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1041
    .line 1042
    .line 1043
    move-result-object v2

    .line 1044
    :goto_24
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 1045
    .line 1046
    .line 1047
    move-result v3

    .line 1048
    if-eqz v3, :cond_25

    .line 1049
    .line 1050
    const/4 v1, 0x0

    .line 1051
    goto :goto_25

    .line 1052
    :cond_25
    invoke-interface {v4, v1}, Lua/c;->getDouble(I)D

    .line 1053
    .line 1054
    .line 1055
    move-result-wide v5

    .line 1056
    double-to-float v1, v5

    .line 1057
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1058
    .line 1059
    .line 1060
    move-result-object v1

    .line 1061
    :goto_25
    new-instance v3, Lif0/q;

    .line 1062
    .line 1063
    invoke-direct {v3, v0, v2, v1}, Lif0/q;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

    .line 1064
    .line 1065
    .line 1066
    new-instance v50, Lif0/p;

    .line 1067
    .line 1068
    move-object/from16 v57, v3

    .line 1069
    .line 1070
    invoke-direct/range {v50 .. v66}, Lif0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/p;Lif0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 1071
    .line 1072
    .line 1073
    goto/16 :goto_9

    .line 1074
    .line 1075
    :goto_26
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 1076
    .line 1077
    .line 1078
    move-result v1

    .line 1079
    if-nez v1, :cond_26

    .line 1080
    .line 1081
    invoke-interface {v4, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v0

    .line 1085
    new-instance v2, Lif0/g0;

    .line 1086
    .line 1087
    invoke-direct {v2, v0}, Lif0/g0;-><init>(Ljava/lang/String;)V

    .line 1088
    .line 1089
    .line 1090
    move-object/from16 v51, v2

    .line 1091
    .line 1092
    goto :goto_27

    .line 1093
    :cond_26
    const/16 v51, 0x0

    .line 1094
    .line 1095
    :goto_27
    new-instance v38, Lif0/o;

    .line 1096
    .line 1097
    invoke-direct/range {v38 .. v51}, Lif0/o;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lss0/m;Lss0/n;Ljava/lang/String;Ljava/lang/String;ZILif0/p;Lif0/g0;)V

    .line 1098
    .line 1099
    .line 1100
    move-object/from16 v0, v38

    .line 1101
    .line 1102
    move/from16 v1, v18

    .line 1103
    .line 1104
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1105
    .line 1106
    .line 1107
    move-result-object v2

    .line 1108
    move-object/from16 v3, v17

    .line 1109
    .line 1110
    invoke-static {v3, v2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1111
    .line 1112
    .line 1113
    move-result-object v2

    .line 1114
    move-object/from16 v3, p1

    .line 1115
    .line 1116
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1117
    .line 1118
    .line 1119
    check-cast v2, Ljava/util/List;

    .line 1120
    .line 1121
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v1

    .line 1125
    move-object/from16 v5, v16

    .line 1126
    .line 1127
    invoke-static {v5, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v1

    .line 1131
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1132
    .line 1133
    .line 1134
    check-cast v1, Ljava/util/List;

    .line 1135
    .line 1136
    new-instance v3, Lif0/n;

    .line 1137
    .line 1138
    invoke-direct {v3, v0, v2, v1}, Lif0/n;-><init>(Lif0/o;Ljava/util/List;Ljava/util/List;)V

    .line 1139
    .line 1140
    .line 1141
    move-object v2, v3

    .line 1142
    goto :goto_28

    .line 1143
    :cond_27
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1144
    .line 1145
    const-string v1, "Expected NON-NULL \'java.time.LocalDate\', but it was NULL."

    .line 1146
    .line 1147
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1148
    .line 1149
    .line 1150
    throw v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1151
    :cond_28
    const/4 v2, 0x0

    .line 1152
    :goto_28
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 1153
    .line 1154
    .line 1155
    return-object v2

    .line 1156
    :goto_29
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 1157
    .line 1158
    .line 1159
    throw v0

    .line 1160
    :pswitch_0
    iget-object v1, v0, Lif0/j;->e:Ljava/lang/String;

    .line 1161
    .line 1162
    iget-object v0, v0, Lif0/j;->f:Lif0/m;

    .line 1163
    .line 1164
    move-object/from16 v2, p1

    .line 1165
    .line 1166
    check-cast v2, Lua/a;

    .line 1167
    .line 1168
    const-string v3, "getValue(...)"

    .line 1169
    .line 1170
    const-string v4, "_connection"

    .line 1171
    .line 1172
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1173
    .line 1174
    .line 1175
    const-string v4, "SELECT * FROM vehicle where ? is vin"

    .line 1176
    .line 1177
    invoke-interface {v2, v4}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1178
    .line 1179
    .line 1180
    move-result-object v4

    .line 1181
    const/4 v5, 0x1

    .line 1182
    :try_start_1
    invoke-interface {v4, v5, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 1183
    .line 1184
    .line 1185
    const-string v1, "vin"

    .line 1186
    .line 1187
    invoke-static {v4, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1188
    .line 1189
    .line 1190
    move-result v1

    .line 1191
    const-string v6, "systemModelId"

    .line 1192
    .line 1193
    invoke-static {v4, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1194
    .line 1195
    .line 1196
    move-result v6

    .line 1197
    const-string v7, "name"

    .line 1198
    .line 1199
    invoke-static {v4, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1200
    .line 1201
    .line 1202
    move-result v7

    .line 1203
    const-string v8, "title"

    .line 1204
    .line 1205
    invoke-static {v4, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1206
    .line 1207
    .line 1208
    move-result v8

    .line 1209
    const-string v9, "licensePlate"

    .line 1210
    .line 1211
    invoke-static {v4, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1212
    .line 1213
    .line 1214
    move-result v9

    .line 1215
    const-string v10, "state"

    .line 1216
    .line 1217
    invoke-static {v4, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1218
    .line 1219
    .line 1220
    move-result v10

    .line 1221
    const-string v11, "devicePlatform"

    .line 1222
    .line 1223
    invoke-static {v4, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1224
    .line 1225
    .line 1226
    move-result v11

    .line 1227
    const-string v12, "softwareVersion"

    .line 1228
    .line 1229
    invoke-static {v4, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1230
    .line 1231
    .line 1232
    move-result v12

    .line 1233
    const-string v13, "connectivity_sunset_impact"

    .line 1234
    .line 1235
    invoke-static {v4, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1236
    .line 1237
    .line 1238
    move-result v13

    .line 1239
    const-string v14, "isWorkshopMode"

    .line 1240
    .line 1241
    invoke-static {v4, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1242
    .line 1243
    .line 1244
    move-result v14

    .line 1245
    const-string v15, "priority"

    .line 1246
    .line 1247
    invoke-static {v4, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1248
    .line 1249
    .line 1250
    move-result v15

    .line 1251
    const-string v5, "spec_title"

    .line 1252
    .line 1253
    invoke-static {v4, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1254
    .line 1255
    .line 1256
    move-result v5

    .line 1257
    move-object/from16 p1, v3

    .line 1258
    .line 1259
    const-string v3, "spec_systemCode"

    .line 1260
    .line 1261
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1262
    .line 1263
    .line 1264
    move-result v3

    .line 1265
    move/from16 v16, v3

    .line 1266
    .line 1267
    const-string v3, "spec_systemModelId"

    .line 1268
    .line 1269
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1270
    .line 1271
    .line 1272
    move-result v3

    .line 1273
    move/from16 v17, v3

    .line 1274
    .line 1275
    const-string v3, "spec_model"

    .line 1276
    .line 1277
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1278
    .line 1279
    .line 1280
    move-result v3

    .line 1281
    move/from16 v18, v3

    .line 1282
    .line 1283
    const-string v3, "spec_manufacturingDate"

    .line 1284
    .line 1285
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1286
    .line 1287
    .line 1288
    move-result v3

    .line 1289
    move/from16 v19, v3

    .line 1290
    .line 1291
    const-string v3, "spec_gearboxType"

    .line 1292
    .line 1293
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1294
    .line 1295
    .line 1296
    move-result v3

    .line 1297
    move/from16 v20, v3

    .line 1298
    .line 1299
    const-string v3, "spec_modelYear"

    .line 1300
    .line 1301
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1302
    .line 1303
    .line 1304
    move-result v3

    .line 1305
    move/from16 v21, v3

    .line 1306
    .line 1307
    const-string v3, "spec_body"

    .line 1308
    .line 1309
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1310
    .line 1311
    .line 1312
    move-result v3

    .line 1313
    move/from16 v22, v3

    .line 1314
    .line 1315
    const-string v3, "spec_batteryCapacity"

    .line 1316
    .line 1317
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1318
    .line 1319
    .line 1320
    move-result v3

    .line 1321
    move/from16 v23, v3

    .line 1322
    .line 1323
    const-string v3, "spec_trimLevel"

    .line 1324
    .line 1325
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1326
    .line 1327
    .line 1328
    move-result v3

    .line 1329
    move/from16 v24, v3

    .line 1330
    .line 1331
    const-string v3, "spec_maxChargingPowerInKW"

    .line 1332
    .line 1333
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1334
    .line 1335
    .line 1336
    move-result v3

    .line 1337
    move/from16 v25, v3

    .line 1338
    .line 1339
    const-string v3, "spec_colour"

    .line 1340
    .line 1341
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1342
    .line 1343
    .line 1344
    move-result v3

    .line 1345
    move/from16 v26, v3

    .line 1346
    .line 1347
    const-string v3, "spec_length"

    .line 1348
    .line 1349
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1350
    .line 1351
    .line 1352
    move-result v3

    .line 1353
    move/from16 v27, v3

    .line 1354
    .line 1355
    const-string v3, "spec_width"

    .line 1356
    .line 1357
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1358
    .line 1359
    .line 1360
    move-result v3

    .line 1361
    move/from16 v28, v3

    .line 1362
    .line 1363
    const-string v3, "spec_height"

    .line 1364
    .line 1365
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1366
    .line 1367
    .line 1368
    move-result v3

    .line 1369
    move/from16 v29, v3

    .line 1370
    .line 1371
    const-string v3, "spec_enginepowerInKW"

    .line 1372
    .line 1373
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1374
    .line 1375
    .line 1376
    move-result v3

    .line 1377
    move/from16 v30, v3

    .line 1378
    .line 1379
    const-string v3, "spec_enginetype"

    .line 1380
    .line 1381
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1382
    .line 1383
    .line 1384
    move-result v3

    .line 1385
    move/from16 v31, v3

    .line 1386
    .line 1387
    const-string v3, "spec_enginecapacityInLiters"

    .line 1388
    .line 1389
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1390
    .line 1391
    .line 1392
    move-result v3

    .line 1393
    move/from16 v32, v3

    .line 1394
    .line 1395
    const-string v3, "servicePartner_id"

    .line 1396
    .line 1397
    invoke-static {v4, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1398
    .line 1399
    .line 1400
    move-result v3

    .line 1401
    move/from16 v33, v3

    .line 1402
    .line 1403
    new-instance v3, Landroidx/collection/f;

    .line 1404
    .line 1405
    move/from16 v34, v5

    .line 1406
    .line 1407
    const/4 v5, 0x0

    .line 1408
    invoke-direct {v3, v5}, Landroidx/collection/a1;-><init>(I)V

    .line 1409
    .line 1410
    .line 1411
    move/from16 v35, v15

    .line 1412
    .line 1413
    new-instance v15, Landroidx/collection/f;

    .line 1414
    .line 1415
    invoke-direct {v15, v5}, Landroidx/collection/a1;-><init>(I)V

    .line 1416
    .line 1417
    .line 1418
    :goto_2a
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 1419
    .line 1420
    .line 1421
    move-result v36

    .line 1422
    if-eqz v36, :cond_2b

    .line 1423
    .line 1424
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1425
    .line 1426
    .line 1427
    move-result-object v5

    .line 1428
    invoke-virtual {v3, v5}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 1429
    .line 1430
    .line 1431
    move-result v37

    .line 1432
    if-nez v37, :cond_29

    .line 1433
    .line 1434
    move/from16 v37, v14

    .line 1435
    .line 1436
    new-instance v14, Ljava/util/ArrayList;

    .line 1437
    .line 1438
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 1439
    .line 1440
    .line 1441
    invoke-virtual {v3, v5, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1442
    .line 1443
    .line 1444
    goto :goto_2b

    .line 1445
    :catchall_1
    move-exception v0

    .line 1446
    goto/16 :goto_53

    .line 1447
    .line 1448
    :cond_29
    move/from16 v37, v14

    .line 1449
    .line 1450
    :goto_2b
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1451
    .line 1452
    .line 1453
    move-result-object v5

    .line 1454
    invoke-virtual {v15, v5}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 1455
    .line 1456
    .line 1457
    move-result v14

    .line 1458
    if-nez v14, :cond_2a

    .line 1459
    .line 1460
    new-instance v14, Ljava/util/ArrayList;

    .line 1461
    .line 1462
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 1463
    .line 1464
    .line 1465
    invoke-virtual {v15, v5, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1466
    .line 1467
    .line 1468
    :cond_2a
    move/from16 v14, v37

    .line 1469
    .line 1470
    const/4 v5, 0x0

    .line 1471
    goto :goto_2a

    .line 1472
    :cond_2b
    move/from16 v37, v14

    .line 1473
    .line 1474
    invoke-interface {v4}, Lua/c;->reset()V

    .line 1475
    .line 1476
    .line 1477
    invoke-virtual {v0, v2, v3}, Lif0/m;->e(Lua/a;Landroidx/collection/f;)V

    .line 1478
    .line 1479
    .line 1480
    invoke-virtual {v0, v2, v15}, Lif0/m;->f(Lua/a;Landroidx/collection/f;)V

    .line 1481
    .line 1482
    .line 1483
    invoke-interface {v4}, Lua/c;->s0()Z

    .line 1484
    .line 1485
    .line 1486
    move-result v0

    .line 1487
    if-eqz v0, :cond_51

    .line 1488
    .line 1489
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1490
    .line 1491
    .line 1492
    move-result-object v39

    .line 1493
    invoke-interface {v4, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1494
    .line 1495
    .line 1496
    move-result-object v40

    .line 1497
    invoke-interface {v4, v7}, Lua/c;->isNull(I)Z

    .line 1498
    .line 1499
    .line 1500
    move-result v0

    .line 1501
    if-eqz v0, :cond_2c

    .line 1502
    .line 1503
    const/16 v41, 0x0

    .line 1504
    .line 1505
    goto :goto_2c

    .line 1506
    :cond_2c
    invoke-interface {v4, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1507
    .line 1508
    .line 1509
    move-result-object v0

    .line 1510
    move-object/from16 v41, v0

    .line 1511
    .line 1512
    :goto_2c
    invoke-interface {v4, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1513
    .line 1514
    .line 1515
    move-result-object v42

    .line 1516
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 1517
    .line 1518
    .line 1519
    move-result v0

    .line 1520
    if-eqz v0, :cond_2d

    .line 1521
    .line 1522
    const/16 v43, 0x0

    .line 1523
    .line 1524
    goto :goto_2d

    .line 1525
    :cond_2d
    invoke-interface {v4, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1526
    .line 1527
    .line 1528
    move-result-object v0

    .line 1529
    move-object/from16 v43, v0

    .line 1530
    .line 1531
    :goto_2d
    invoke-interface {v4, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1532
    .line 1533
    .line 1534
    move-result-object v0

    .line 1535
    invoke-static {v0}, Lif0/m;->b(Ljava/lang/String;)Lss0/m;

    .line 1536
    .line 1537
    .line 1538
    move-result-object v44

    .line 1539
    invoke-interface {v4, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1540
    .line 1541
    .line 1542
    move-result-object v0

    .line 1543
    invoke-static {v0}, Lif0/m;->c(Ljava/lang/String;)Lss0/n;

    .line 1544
    .line 1545
    .line 1546
    move-result-object v45

    .line 1547
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 1548
    .line 1549
    .line 1550
    move-result v0

    .line 1551
    if-eqz v0, :cond_2e

    .line 1552
    .line 1553
    const/16 v46, 0x0

    .line 1554
    .line 1555
    goto :goto_2e

    .line 1556
    :cond_2e
    invoke-interface {v4, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1557
    .line 1558
    .line 1559
    move-result-object v0

    .line 1560
    move-object/from16 v46, v0

    .line 1561
    .line 1562
    :goto_2e
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 1563
    .line 1564
    .line 1565
    move-result v0

    .line 1566
    if-eqz v0, :cond_2f

    .line 1567
    .line 1568
    const/16 v47, 0x0

    .line 1569
    .line 1570
    :goto_2f
    move/from16 v0, v37

    .line 1571
    .line 1572
    goto :goto_30

    .line 1573
    :cond_2f
    invoke-interface {v4, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1574
    .line 1575
    .line 1576
    move-result-object v0

    .line 1577
    move-object/from16 v47, v0

    .line 1578
    .line 1579
    goto :goto_2f

    .line 1580
    :goto_30
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 1581
    .line 1582
    .line 1583
    move-result-wide v5

    .line 1584
    long-to-int v0, v5

    .line 1585
    if-eqz v0, :cond_30

    .line 1586
    .line 1587
    const/16 v48, 0x1

    .line 1588
    .line 1589
    :goto_31
    move/from16 v0, v35

    .line 1590
    .line 1591
    goto :goto_32

    .line 1592
    :cond_30
    const/16 v48, 0x0

    .line 1593
    .line 1594
    goto :goto_31

    .line 1595
    :goto_32
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 1596
    .line 1597
    .line 1598
    move-result-wide v5

    .line 1599
    long-to-int v0, v5

    .line 1600
    move/from16 v5, v34

    .line 1601
    .line 1602
    invoke-interface {v4, v5}, Lua/c;->isNull(I)Z

    .line 1603
    .line 1604
    .line 1605
    move-result v6

    .line 1606
    if-eqz v6, :cond_42

    .line 1607
    .line 1608
    move/from16 v6, v16

    .line 1609
    .line 1610
    invoke-interface {v4, v6}, Lua/c;->isNull(I)Z

    .line 1611
    .line 1612
    .line 1613
    move-result v7

    .line 1614
    if-eqz v7, :cond_41

    .line 1615
    .line 1616
    move/from16 v7, v17

    .line 1617
    .line 1618
    invoke-interface {v4, v7}, Lua/c;->isNull(I)Z

    .line 1619
    .line 1620
    .line 1621
    move-result v8

    .line 1622
    if-eqz v8, :cond_40

    .line 1623
    .line 1624
    move/from16 v8, v18

    .line 1625
    .line 1626
    invoke-interface {v4, v8}, Lua/c;->isNull(I)Z

    .line 1627
    .line 1628
    .line 1629
    move-result v9

    .line 1630
    if-eqz v9, :cond_3f

    .line 1631
    .line 1632
    move/from16 v9, v19

    .line 1633
    .line 1634
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 1635
    .line 1636
    .line 1637
    move-result v10

    .line 1638
    if-eqz v10, :cond_3e

    .line 1639
    .line 1640
    move/from16 v10, v20

    .line 1641
    .line 1642
    invoke-interface {v4, v10}, Lua/c;->isNull(I)Z

    .line 1643
    .line 1644
    .line 1645
    move-result v11

    .line 1646
    if-eqz v11, :cond_3d

    .line 1647
    .line 1648
    move/from16 v11, v21

    .line 1649
    .line 1650
    invoke-interface {v4, v11}, Lua/c;->isNull(I)Z

    .line 1651
    .line 1652
    .line 1653
    move-result v12

    .line 1654
    if-eqz v12, :cond_3c

    .line 1655
    .line 1656
    move/from16 v12, v22

    .line 1657
    .line 1658
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 1659
    .line 1660
    .line 1661
    move-result v13

    .line 1662
    if-eqz v13, :cond_3b

    .line 1663
    .line 1664
    move/from16 v13, v23

    .line 1665
    .line 1666
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 1667
    .line 1668
    .line 1669
    move-result v14

    .line 1670
    if-eqz v14, :cond_3a

    .line 1671
    .line 1672
    move/from16 v14, v24

    .line 1673
    .line 1674
    invoke-interface {v4, v14}, Lua/c;->isNull(I)Z

    .line 1675
    .line 1676
    .line 1677
    move-result v16

    .line 1678
    if-eqz v16, :cond_39

    .line 1679
    .line 1680
    move/from16 v2, v25

    .line 1681
    .line 1682
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 1683
    .line 1684
    .line 1685
    move-result v16

    .line 1686
    if-eqz v16, :cond_38

    .line 1687
    .line 1688
    move/from16 v49, v0

    .line 1689
    .line 1690
    move/from16 v0, v26

    .line 1691
    .line 1692
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 1693
    .line 1694
    .line 1695
    move-result v16

    .line 1696
    if-eqz v16, :cond_37

    .line 1697
    .line 1698
    move-object/from16 v16, v15

    .line 1699
    .line 1700
    move/from16 v15, v27

    .line 1701
    .line 1702
    invoke-interface {v4, v15}, Lua/c;->isNull(I)Z

    .line 1703
    .line 1704
    .line 1705
    move-result v17

    .line 1706
    if-eqz v17, :cond_36

    .line 1707
    .line 1708
    move-object/from16 v17, v3

    .line 1709
    .line 1710
    move/from16 v3, v28

    .line 1711
    .line 1712
    invoke-interface {v4, v3}, Lua/c;->isNull(I)Z

    .line 1713
    .line 1714
    .line 1715
    move-result v18

    .line 1716
    if-eqz v18, :cond_35

    .line 1717
    .line 1718
    move/from16 v18, v1

    .line 1719
    .line 1720
    move/from16 v1, v29

    .line 1721
    .line 1722
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 1723
    .line 1724
    .line 1725
    move-result v19

    .line 1726
    if-eqz v19, :cond_34

    .line 1727
    .line 1728
    move/from16 v29, v1

    .line 1729
    .line 1730
    move/from16 v1, v30

    .line 1731
    .line 1732
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 1733
    .line 1734
    .line 1735
    move-result v19

    .line 1736
    if-eqz v19, :cond_33

    .line 1737
    .line 1738
    move/from16 v30, v1

    .line 1739
    .line 1740
    move/from16 v1, v31

    .line 1741
    .line 1742
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 1743
    .line 1744
    .line 1745
    move-result v19

    .line 1746
    if-eqz v19, :cond_32

    .line 1747
    .line 1748
    move/from16 v31, v1

    .line 1749
    .line 1750
    move/from16 v1, v32

    .line 1751
    .line 1752
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 1753
    .line 1754
    .line 1755
    move-result v19

    .line 1756
    if-nez v19, :cond_31

    .line 1757
    .line 1758
    goto/16 :goto_41

    .line 1759
    .line 1760
    :cond_31
    const/16 v50, 0x0

    .line 1761
    .line 1762
    :goto_33
    move/from16 v0, v33

    .line 1763
    .line 1764
    goto/16 :goto_50

    .line 1765
    .line 1766
    :cond_32
    move/from16 v31, v1

    .line 1767
    .line 1768
    :goto_34
    move/from16 v1, v32

    .line 1769
    .line 1770
    goto/16 :goto_41

    .line 1771
    .line 1772
    :cond_33
    move/from16 v30, v1

    .line 1773
    .line 1774
    goto :goto_34

    .line 1775
    :cond_34
    move/from16 v29, v1

    .line 1776
    .line 1777
    goto :goto_34

    .line 1778
    :cond_35
    :goto_35
    move/from16 v18, v1

    .line 1779
    .line 1780
    goto :goto_34

    .line 1781
    :cond_36
    :goto_36
    move/from16 v18, v1

    .line 1782
    .line 1783
    move-object/from16 v17, v3

    .line 1784
    .line 1785
    :goto_37
    move/from16 v3, v28

    .line 1786
    .line 1787
    goto :goto_34

    .line 1788
    :cond_37
    :goto_38
    move/from16 v18, v1

    .line 1789
    .line 1790
    move-object/from16 v17, v3

    .line 1791
    .line 1792
    move-object/from16 v16, v15

    .line 1793
    .line 1794
    :goto_39
    move/from16 v15, v27

    .line 1795
    .line 1796
    goto :goto_37

    .line 1797
    :cond_38
    move/from16 v49, v0

    .line 1798
    .line 1799
    move/from16 v18, v1

    .line 1800
    .line 1801
    move-object/from16 v17, v3

    .line 1802
    .line 1803
    move-object/from16 v16, v15

    .line 1804
    .line 1805
    :goto_3a
    move/from16 v0, v26

    .line 1806
    .line 1807
    goto :goto_39

    .line 1808
    :cond_39
    move/from16 v49, v0

    .line 1809
    .line 1810
    move/from16 v18, v1

    .line 1811
    .line 1812
    move-object/from16 v17, v3

    .line 1813
    .line 1814
    move-object/from16 v16, v15

    .line 1815
    .line 1816
    :goto_3b
    move/from16 v2, v25

    .line 1817
    .line 1818
    goto :goto_3a

    .line 1819
    :cond_3a
    move/from16 v49, v0

    .line 1820
    .line 1821
    move/from16 v18, v1

    .line 1822
    .line 1823
    move-object/from16 v17, v3

    .line 1824
    .line 1825
    move-object/from16 v16, v15

    .line 1826
    .line 1827
    :goto_3c
    move/from16 v14, v24

    .line 1828
    .line 1829
    goto :goto_3b

    .line 1830
    :cond_3b
    move/from16 v49, v0

    .line 1831
    .line 1832
    move/from16 v18, v1

    .line 1833
    .line 1834
    move-object/from16 v17, v3

    .line 1835
    .line 1836
    move-object/from16 v16, v15

    .line 1837
    .line 1838
    :goto_3d
    move/from16 v13, v23

    .line 1839
    .line 1840
    goto :goto_3c

    .line 1841
    :cond_3c
    move/from16 v49, v0

    .line 1842
    .line 1843
    move/from16 v18, v1

    .line 1844
    .line 1845
    move-object/from16 v17, v3

    .line 1846
    .line 1847
    move-object/from16 v16, v15

    .line 1848
    .line 1849
    :goto_3e
    move/from16 v12, v22

    .line 1850
    .line 1851
    goto :goto_3d

    .line 1852
    :cond_3d
    move/from16 v49, v0

    .line 1853
    .line 1854
    move/from16 v18, v1

    .line 1855
    .line 1856
    move-object/from16 v17, v3

    .line 1857
    .line 1858
    move-object/from16 v16, v15

    .line 1859
    .line 1860
    :goto_3f
    move/from16 v11, v21

    .line 1861
    .line 1862
    goto :goto_3e

    .line 1863
    :cond_3e
    move/from16 v49, v0

    .line 1864
    .line 1865
    move/from16 v18, v1

    .line 1866
    .line 1867
    move-object/from16 v17, v3

    .line 1868
    .line 1869
    move-object/from16 v16, v15

    .line 1870
    .line 1871
    :goto_40
    move/from16 v10, v20

    .line 1872
    .line 1873
    goto :goto_3f

    .line 1874
    :cond_3f
    move/from16 v49, v0

    .line 1875
    .line 1876
    move/from16 v18, v1

    .line 1877
    .line 1878
    move-object/from16 v17, v3

    .line 1879
    .line 1880
    move-object/from16 v16, v15

    .line 1881
    .line 1882
    move/from16 v9, v19

    .line 1883
    .line 1884
    goto :goto_40

    .line 1885
    :cond_40
    move/from16 v49, v0

    .line 1886
    .line 1887
    move-object/from16 v17, v3

    .line 1888
    .line 1889
    move-object/from16 v16, v15

    .line 1890
    .line 1891
    move/from16 v8, v18

    .line 1892
    .line 1893
    move/from16 v9, v19

    .line 1894
    .line 1895
    move/from16 v10, v20

    .line 1896
    .line 1897
    move/from16 v11, v21

    .line 1898
    .line 1899
    move/from16 v12, v22

    .line 1900
    .line 1901
    move/from16 v13, v23

    .line 1902
    .line 1903
    move/from16 v14, v24

    .line 1904
    .line 1905
    move/from16 v2, v25

    .line 1906
    .line 1907
    move/from16 v0, v26

    .line 1908
    .line 1909
    move/from16 v15, v27

    .line 1910
    .line 1911
    move/from16 v3, v28

    .line 1912
    .line 1913
    goto/16 :goto_35

    .line 1914
    .line 1915
    :cond_41
    move/from16 v49, v0

    .line 1916
    .line 1917
    move-object/from16 v16, v15

    .line 1918
    .line 1919
    move/from16 v7, v17

    .line 1920
    .line 1921
    move/from16 v8, v18

    .line 1922
    .line 1923
    move/from16 v9, v19

    .line 1924
    .line 1925
    move/from16 v10, v20

    .line 1926
    .line 1927
    move/from16 v11, v21

    .line 1928
    .line 1929
    move/from16 v12, v22

    .line 1930
    .line 1931
    move/from16 v13, v23

    .line 1932
    .line 1933
    move/from16 v14, v24

    .line 1934
    .line 1935
    move/from16 v2, v25

    .line 1936
    .line 1937
    move/from16 v0, v26

    .line 1938
    .line 1939
    move/from16 v15, v27

    .line 1940
    .line 1941
    goto/16 :goto_36

    .line 1942
    .line 1943
    :cond_42
    move/from16 v49, v0

    .line 1944
    .line 1945
    move/from16 v6, v16

    .line 1946
    .line 1947
    move/from16 v7, v17

    .line 1948
    .line 1949
    move/from16 v8, v18

    .line 1950
    .line 1951
    move/from16 v9, v19

    .line 1952
    .line 1953
    move/from16 v10, v20

    .line 1954
    .line 1955
    move/from16 v11, v21

    .line 1956
    .line 1957
    move/from16 v12, v22

    .line 1958
    .line 1959
    move/from16 v13, v23

    .line 1960
    .line 1961
    move/from16 v14, v24

    .line 1962
    .line 1963
    move/from16 v2, v25

    .line 1964
    .line 1965
    move/from16 v0, v26

    .line 1966
    .line 1967
    goto/16 :goto_38

    .line 1968
    .line 1969
    :goto_41
    invoke-interface {v4, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1970
    .line 1971
    .line 1972
    move-result-object v51

    .line 1973
    invoke-interface {v4, v6}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1974
    .line 1975
    .line 1976
    move-result-object v52

    .line 1977
    invoke-interface {v4, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1978
    .line 1979
    .line 1980
    move-result-object v53

    .line 1981
    invoke-interface {v4, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1982
    .line 1983
    .line 1984
    move-result-object v54

    .line 1985
    invoke-interface {v4, v9}, Lua/c;->isNull(I)Z

    .line 1986
    .line 1987
    .line 1988
    move-result v5

    .line 1989
    if-eqz v5, :cond_43

    .line 1990
    .line 1991
    const/4 v5, 0x0

    .line 1992
    goto :goto_42

    .line 1993
    :cond_43
    invoke-interface {v4, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1994
    .line 1995
    .line 1996
    move-result-object v5

    .line 1997
    :goto_42
    invoke-static {v5}, Lwe0/b;->v(Ljava/lang/String;)Ljava/time/LocalDate;

    .line 1998
    .line 1999
    .line 2000
    move-result-object v55

    .line 2001
    if-eqz v55, :cond_50

    .line 2002
    .line 2003
    invoke-interface {v4, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2004
    .line 2005
    .line 2006
    move-result-object v5

    .line 2007
    invoke-static {v5}, Lif0/m;->d(Ljava/lang/String;)Lss0/p;

    .line 2008
    .line 2009
    .line 2010
    move-result-object v56

    .line 2011
    invoke-interface {v4, v11}, Lua/c;->isNull(I)Z

    .line 2012
    .line 2013
    .line 2014
    move-result v5

    .line 2015
    if-eqz v5, :cond_44

    .line 2016
    .line 2017
    const/16 v58, 0x0

    .line 2018
    .line 2019
    goto :goto_43

    .line 2020
    :cond_44
    invoke-interface {v4, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2021
    .line 2022
    .line 2023
    move-result-object v5

    .line 2024
    move-object/from16 v58, v5

    .line 2025
    .line 2026
    :goto_43
    invoke-interface {v4, v12}, Lua/c;->isNull(I)Z

    .line 2027
    .line 2028
    .line 2029
    move-result v5

    .line 2030
    if-eqz v5, :cond_45

    .line 2031
    .line 2032
    const/16 v59, 0x0

    .line 2033
    .line 2034
    goto :goto_44

    .line 2035
    :cond_45
    invoke-interface {v4, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2036
    .line 2037
    .line 2038
    move-result-object v5

    .line 2039
    move-object/from16 v59, v5

    .line 2040
    .line 2041
    :goto_44
    invoke-interface {v4, v13}, Lua/c;->isNull(I)Z

    .line 2042
    .line 2043
    .line 2044
    move-result v5

    .line 2045
    if-eqz v5, :cond_46

    .line 2046
    .line 2047
    const/16 v60, 0x0

    .line 2048
    .line 2049
    goto :goto_45

    .line 2050
    :cond_46
    invoke-interface {v4, v13}, Lua/c;->getLong(I)J

    .line 2051
    .line 2052
    .line 2053
    move-result-wide v5

    .line 2054
    long-to-int v5, v5

    .line 2055
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2056
    .line 2057
    .line 2058
    move-result-object v5

    .line 2059
    move-object/from16 v60, v5

    .line 2060
    .line 2061
    :goto_45
    invoke-interface {v4, v14}, Lua/c;->isNull(I)Z

    .line 2062
    .line 2063
    .line 2064
    move-result v5

    .line 2065
    if-eqz v5, :cond_47

    .line 2066
    .line 2067
    const/16 v61, 0x0

    .line 2068
    .line 2069
    goto :goto_46

    .line 2070
    :cond_47
    invoke-interface {v4, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2071
    .line 2072
    .line 2073
    move-result-object v5

    .line 2074
    move-object/from16 v61, v5

    .line 2075
    .line 2076
    :goto_46
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 2077
    .line 2078
    .line 2079
    move-result v5

    .line 2080
    if-eqz v5, :cond_48

    .line 2081
    .line 2082
    const/16 v62, 0x0

    .line 2083
    .line 2084
    goto :goto_47

    .line 2085
    :cond_48
    invoke-interface {v4, v2}, Lua/c;->getLong(I)J

    .line 2086
    .line 2087
    .line 2088
    move-result-wide v5

    .line 2089
    long-to-int v2, v5

    .line 2090
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2091
    .line 2092
    .line 2093
    move-result-object v2

    .line 2094
    move-object/from16 v62, v2

    .line 2095
    .line 2096
    :goto_47
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 2097
    .line 2098
    .line 2099
    move-result v2

    .line 2100
    if-eqz v2, :cond_49

    .line 2101
    .line 2102
    const/16 v63, 0x0

    .line 2103
    .line 2104
    goto :goto_48

    .line 2105
    :cond_49
    invoke-interface {v4, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2106
    .line 2107
    .line 2108
    move-result-object v0

    .line 2109
    move-object/from16 v63, v0

    .line 2110
    .line 2111
    :goto_48
    invoke-interface {v4, v15}, Lua/c;->isNull(I)Z

    .line 2112
    .line 2113
    .line 2114
    move-result v0

    .line 2115
    if-eqz v0, :cond_4a

    .line 2116
    .line 2117
    const/16 v64, 0x0

    .line 2118
    .line 2119
    goto :goto_49

    .line 2120
    :cond_4a
    invoke-interface {v4, v15}, Lua/c;->getLong(I)J

    .line 2121
    .line 2122
    .line 2123
    move-result-wide v5

    .line 2124
    long-to-int v0, v5

    .line 2125
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2126
    .line 2127
    .line 2128
    move-result-object v0

    .line 2129
    move-object/from16 v64, v0

    .line 2130
    .line 2131
    :goto_49
    invoke-interface {v4, v3}, Lua/c;->isNull(I)Z

    .line 2132
    .line 2133
    .line 2134
    move-result v0

    .line 2135
    if-eqz v0, :cond_4b

    .line 2136
    .line 2137
    const/16 v65, 0x0

    .line 2138
    .line 2139
    :goto_4a
    move/from16 v0, v29

    .line 2140
    .line 2141
    goto :goto_4b

    .line 2142
    :cond_4b
    invoke-interface {v4, v3}, Lua/c;->getLong(I)J

    .line 2143
    .line 2144
    .line 2145
    move-result-wide v2

    .line 2146
    long-to-int v0, v2

    .line 2147
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2148
    .line 2149
    .line 2150
    move-result-object v0

    .line 2151
    move-object/from16 v65, v0

    .line 2152
    .line 2153
    goto :goto_4a

    .line 2154
    :goto_4b
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 2155
    .line 2156
    .line 2157
    move-result v2

    .line 2158
    if-eqz v2, :cond_4c

    .line 2159
    .line 2160
    const/16 v66, 0x0

    .line 2161
    .line 2162
    :goto_4c
    move/from16 v0, v30

    .line 2163
    .line 2164
    goto :goto_4d

    .line 2165
    :cond_4c
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 2166
    .line 2167
    .line 2168
    move-result-wide v2

    .line 2169
    long-to-int v0, v2

    .line 2170
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2171
    .line 2172
    .line 2173
    move-result-object v0

    .line 2174
    move-object/from16 v66, v0

    .line 2175
    .line 2176
    goto :goto_4c

    .line 2177
    :goto_4d
    invoke-interface {v4, v0}, Lua/c;->getLong(I)J

    .line 2178
    .line 2179
    .line 2180
    move-result-wide v2

    .line 2181
    long-to-int v0, v2

    .line 2182
    move/from16 v2, v31

    .line 2183
    .line 2184
    invoke-interface {v4, v2}, Lua/c;->isNull(I)Z

    .line 2185
    .line 2186
    .line 2187
    move-result v3

    .line 2188
    if-eqz v3, :cond_4d

    .line 2189
    .line 2190
    const/4 v2, 0x0

    .line 2191
    goto :goto_4e

    .line 2192
    :cond_4d
    invoke-interface {v4, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2193
    .line 2194
    .line 2195
    move-result-object v2

    .line 2196
    :goto_4e
    invoke-interface {v4, v1}, Lua/c;->isNull(I)Z

    .line 2197
    .line 2198
    .line 2199
    move-result v3

    .line 2200
    if-eqz v3, :cond_4e

    .line 2201
    .line 2202
    const/4 v1, 0x0

    .line 2203
    goto :goto_4f

    .line 2204
    :cond_4e
    invoke-interface {v4, v1}, Lua/c;->getDouble(I)D

    .line 2205
    .line 2206
    .line 2207
    move-result-wide v5

    .line 2208
    double-to-float v1, v5

    .line 2209
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2210
    .line 2211
    .line 2212
    move-result-object v1

    .line 2213
    :goto_4f
    new-instance v3, Lif0/q;

    .line 2214
    .line 2215
    invoke-direct {v3, v0, v2, v1}, Lif0/q;-><init>(ILjava/lang/String;Ljava/lang/Float;)V

    .line 2216
    .line 2217
    .line 2218
    new-instance v50, Lif0/p;

    .line 2219
    .line 2220
    move-object/from16 v57, v3

    .line 2221
    .line 2222
    invoke-direct/range {v50 .. v66}, Lif0/p;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/LocalDate;Lss0/p;Lif0/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 2223
    .line 2224
    .line 2225
    goto/16 :goto_33

    .line 2226
    .line 2227
    :goto_50
    invoke-interface {v4, v0}, Lua/c;->isNull(I)Z

    .line 2228
    .line 2229
    .line 2230
    move-result v1

    .line 2231
    if-nez v1, :cond_4f

    .line 2232
    .line 2233
    invoke-interface {v4, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2234
    .line 2235
    .line 2236
    move-result-object v0

    .line 2237
    new-instance v2, Lif0/g0;

    .line 2238
    .line 2239
    invoke-direct {v2, v0}, Lif0/g0;-><init>(Ljava/lang/String;)V

    .line 2240
    .line 2241
    .line 2242
    move-object/from16 v51, v2

    .line 2243
    .line 2244
    goto :goto_51

    .line 2245
    :cond_4f
    const/16 v51, 0x0

    .line 2246
    .line 2247
    :goto_51
    new-instance v38, Lif0/o;

    .line 2248
    .line 2249
    invoke-direct/range {v38 .. v51}, Lif0/o;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lss0/m;Lss0/n;Ljava/lang/String;Ljava/lang/String;ZILif0/p;Lif0/g0;)V

    .line 2250
    .line 2251
    .line 2252
    move-object/from16 v0, v38

    .line 2253
    .line 2254
    move/from16 v1, v18

    .line 2255
    .line 2256
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2257
    .line 2258
    .line 2259
    move-result-object v2

    .line 2260
    move-object/from16 v3, v17

    .line 2261
    .line 2262
    invoke-static {v3, v2}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2263
    .line 2264
    .line 2265
    move-result-object v2

    .line 2266
    move-object/from16 v3, p1

    .line 2267
    .line 2268
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2269
    .line 2270
    .line 2271
    check-cast v2, Ljava/util/List;

    .line 2272
    .line 2273
    invoke-interface {v4, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2274
    .line 2275
    .line 2276
    move-result-object v1

    .line 2277
    move-object/from16 v5, v16

    .line 2278
    .line 2279
    invoke-static {v5, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2280
    .line 2281
    .line 2282
    move-result-object v1

    .line 2283
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2284
    .line 2285
    .line 2286
    check-cast v1, Ljava/util/List;

    .line 2287
    .line 2288
    new-instance v3, Lif0/n;

    .line 2289
    .line 2290
    invoke-direct {v3, v0, v2, v1}, Lif0/n;-><init>(Lif0/o;Ljava/util/List;Ljava/util/List;)V

    .line 2291
    .line 2292
    .line 2293
    move-object v2, v3

    .line 2294
    goto :goto_52

    .line 2295
    :cond_50
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2296
    .line 2297
    const-string v1, "Expected NON-NULL \'java.time.LocalDate\', but it was NULL."

    .line 2298
    .line 2299
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2300
    .line 2301
    .line 2302
    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 2303
    :cond_51
    const/4 v2, 0x0

    .line 2304
    :goto_52
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 2305
    .line 2306
    .line 2307
    return-object v2

    .line 2308
    :goto_53
    invoke-interface {v4}, Ljava/lang/AutoCloseable;->close()V

    .line 2309
    .line 2310
    .line 2311
    throw v0

    .line 2312
    nop

    .line 2313
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
