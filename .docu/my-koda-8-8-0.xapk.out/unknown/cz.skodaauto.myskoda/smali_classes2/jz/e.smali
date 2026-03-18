.class public final synthetic Ljz/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljz/f;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljz/f;I)V
    .locals 0

    .line 1
    iput p3, p0, Ljz/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljz/e;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Ljz/e;->f:Ljz/f;

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
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ljz/e;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ljz/e;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Ljz/e;->f:Ljz/f;

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
    const-string v3, "SELECT * FROM auxiliary_heating_status WHERE vin = ? LIMIT 1"

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
    const-string v1, "vin"

    .line 32
    .line 33
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    const-string v4, "estimated_date_time_to_reach_target_temperature"

    .line 38
    .line 39
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    const-string v5, "state"

    .line 44
    .line 45
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    const-string v6, "duration"

    .line 50
    .line 51
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v6

    .line 55
    const-string v7, "start_mode"

    .line 56
    .line 57
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    const-string v8, "heating_errors"

    .line 62
    .line 63
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v8

    .line 67
    const-string v9, "car_captured_timestamp"

    .line 68
    .line 69
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    const-string v10, "target_temperature_value"

    .line 74
    .line 75
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    const-string v11, "target_temperature_unit"

    .line 80
    .line 81
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    const-string v12, "outside_temperature_timestamp"

    .line 86
    .line 87
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v12

    .line 91
    const-string v13, "outside_temperature_outside_temperaturevalue"

    .line 92
    .line 93
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v13

    .line 97
    const-string v14, "outside_temperature_outside_temperatureunit"

    .line 98
    .line 99
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v14

    .line 103
    new-instance v15, Landroidx/collection/f;

    .line 104
    .line 105
    move/from16 p0, v14

    .line 106
    .line 107
    const/4 v14, 0x0

    .line 108
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 109
    .line 110
    .line 111
    :cond_0
    :goto_0
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 112
    .line 113
    .line 114
    move-result v14

    .line 115
    if-eqz v14, :cond_1

    .line 116
    .line 117
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v14

    .line 121
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    move-result v16

    .line 125
    if-nez v16, :cond_0

    .line 126
    .line 127
    move/from16 p1, v13

    .line 128
    .line 129
    new-instance v13, Ljava/util/ArrayList;

    .line 130
    .line 131
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move/from16 v13, p1

    .line 138
    .line 139
    goto :goto_0

    .line 140
    :catchall_0
    move-exception v0

    .line 141
    goto/16 :goto_9

    .line 142
    .line 143
    :cond_1
    move/from16 p1, v13

    .line 144
    .line 145
    invoke-interface {v3}, Lua/c;->reset()V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v0, v2, v15}, Ljz/f;->a(Lua/a;Landroidx/collection/f;)V

    .line 149
    .line 150
    .line 151
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    const/4 v2, 0x0

    .line 156
    if-eqz v0, :cond_b

    .line 157
    .line 158
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 159
    .line 160
    .line 161
    move-result-object v17

    .line 162
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    if-eqz v0, :cond_2

    .line 167
    .line 168
    move-object v0, v2

    .line 169
    goto :goto_1

    .line 170
    :cond_2
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    :goto_1
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 175
    .line 176
    .line 177
    move-result-object v18

    .line 178
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v19

    .line 182
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 183
    .line 184
    .line 185
    move-result-wide v20

    .line 186
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v22

    .line 190
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-eqz v0, :cond_3

    .line 195
    .line 196
    move-object/from16 v23, v2

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_3
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    move-object/from16 v23, v0

    .line 204
    .line 205
    :goto_2
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    if-eqz v0, :cond_4

    .line 210
    .line 211
    move-object v0, v2

    .line 212
    goto :goto_3

    .line 213
    :cond_4
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    :goto_3
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 218
    .line 219
    .line 220
    move-result-object v24

    .line 221
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 222
    .line 223
    .line 224
    move-result v0

    .line 225
    if-eqz v0, :cond_6

    .line 226
    .line 227
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 228
    .line 229
    .line 230
    move-result v0

    .line 231
    if-nez v0, :cond_5

    .line 232
    .line 233
    goto :goto_4

    .line 234
    :cond_5
    move-object/from16 v25, v2

    .line 235
    .line 236
    goto :goto_5

    .line 237
    :cond_6
    :goto_4
    invoke-interface {v3, v10}, Lua/c;->getDouble(I)D

    .line 238
    .line 239
    .line 240
    move-result-wide v4

    .line 241
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    new-instance v6, Ljz/g;

    .line 246
    .line 247
    invoke-direct {v6, v4, v5, v0}, Ljz/g;-><init>(DLjava/lang/String;)V

    .line 248
    .line 249
    .line 250
    move-object/from16 v25, v6

    .line 251
    .line 252
    :goto_5
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    if-eqz v0, :cond_9

    .line 257
    .line 258
    move/from16 v0, p1

    .line 259
    .line 260
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 261
    .line 262
    .line 263
    move-result v4

    .line 264
    if-eqz v4, :cond_8

    .line 265
    .line 266
    move/from16 v4, p0

    .line 267
    .line 268
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 269
    .line 270
    .line 271
    move-result v5

    .line 272
    if-nez v5, :cond_7

    .line 273
    .line 274
    goto :goto_6

    .line 275
    :cond_7
    move-object/from16 v26, v2

    .line 276
    .line 277
    goto :goto_8

    .line 278
    :cond_8
    move/from16 v4, p0

    .line 279
    .line 280
    goto :goto_6

    .line 281
    :cond_9
    move/from16 v4, p0

    .line 282
    .line 283
    move/from16 v0, p1

    .line 284
    .line 285
    :goto_6
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 286
    .line 287
    .line 288
    move-result v5

    .line 289
    if-eqz v5, :cond_a

    .line 290
    .line 291
    goto :goto_7

    .line 292
    :cond_a
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v2

    .line 296
    :goto_7
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    invoke-interface {v3, v0}, Lua/c;->getDouble(I)D

    .line 301
    .line 302
    .line 303
    move-result-wide v5

    .line 304
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v0

    .line 308
    new-instance v4, Ljb0/l;

    .line 309
    .line 310
    invoke-direct {v4, v5, v6, v0}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 311
    .line 312
    .line 313
    new-instance v0, Ljb0/c;

    .line 314
    .line 315
    invoke-direct {v0, v4, v2}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 316
    .line 317
    .line 318
    move-object/from16 v26, v0

    .line 319
    .line 320
    :goto_8
    new-instance v16, Ljz/d;

    .line 321
    .line 322
    invoke-direct/range {v16 .. v26}, Ljz/d;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljz/g;Ljb0/c;)V

    .line 323
    .line 324
    .line 325
    move-object/from16 v0, v16

    .line 326
    .line 327
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    invoke-static {v15, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v1

    .line 335
    const-string v2, "getValue(...)"

    .line 336
    .line 337
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    check-cast v1, Ljava/util/List;

    .line 341
    .line 342
    new-instance v2, Ljz/j;

    .line 343
    .line 344
    invoke-direct {v2, v0, v1}, Ljz/j;-><init>(Ljz/d;Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 345
    .line 346
    .line 347
    :cond_b
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 348
    .line 349
    .line 350
    return-object v2

    .line 351
    :goto_9
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 352
    .line 353
    .line 354
    throw v0

    .line 355
    :pswitch_0
    iget-object v1, v0, Ljz/e;->e:Ljava/lang/String;

    .line 356
    .line 357
    iget-object v0, v0, Ljz/e;->f:Ljz/f;

    .line 358
    .line 359
    move-object/from16 v2, p1

    .line 360
    .line 361
    check-cast v2, Lua/a;

    .line 362
    .line 363
    const-string v3, "_connection"

    .line 364
    .line 365
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    const-string v3, "SELECT * FROM auxiliary_heating_status WHERE vin = ? LIMIT 1"

    .line 369
    .line 370
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 371
    .line 372
    .line 373
    move-result-object v3

    .line 374
    const/4 v4, 0x1

    .line 375
    :try_start_1
    invoke-interface {v3, v4, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 376
    .line 377
    .line 378
    const-string v1, "vin"

    .line 379
    .line 380
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 381
    .line 382
    .line 383
    move-result v1

    .line 384
    const-string v4, "estimated_date_time_to_reach_target_temperature"

    .line 385
    .line 386
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 387
    .line 388
    .line 389
    move-result v4

    .line 390
    const-string v5, "state"

    .line 391
    .line 392
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 393
    .line 394
    .line 395
    move-result v5

    .line 396
    const-string v6, "duration"

    .line 397
    .line 398
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 399
    .line 400
    .line 401
    move-result v6

    .line 402
    const-string v7, "start_mode"

    .line 403
    .line 404
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 405
    .line 406
    .line 407
    move-result v7

    .line 408
    const-string v8, "heating_errors"

    .line 409
    .line 410
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 411
    .line 412
    .line 413
    move-result v8

    .line 414
    const-string v9, "car_captured_timestamp"

    .line 415
    .line 416
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 417
    .line 418
    .line 419
    move-result v9

    .line 420
    const-string v10, "target_temperature_value"

    .line 421
    .line 422
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 423
    .line 424
    .line 425
    move-result v10

    .line 426
    const-string v11, "target_temperature_unit"

    .line 427
    .line 428
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 429
    .line 430
    .line 431
    move-result v11

    .line 432
    const-string v12, "outside_temperature_timestamp"

    .line 433
    .line 434
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 435
    .line 436
    .line 437
    move-result v12

    .line 438
    const-string v13, "outside_temperature_outside_temperaturevalue"

    .line 439
    .line 440
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 441
    .line 442
    .line 443
    move-result v13

    .line 444
    const-string v14, "outside_temperature_outside_temperatureunit"

    .line 445
    .line 446
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 447
    .line 448
    .line 449
    move-result v14

    .line 450
    new-instance v15, Landroidx/collection/f;

    .line 451
    .line 452
    move/from16 p0, v14

    .line 453
    .line 454
    const/4 v14, 0x0

    .line 455
    invoke-direct {v15, v14}, Landroidx/collection/a1;-><init>(I)V

    .line 456
    .line 457
    .line 458
    :cond_c
    :goto_a
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 459
    .line 460
    .line 461
    move-result v14

    .line 462
    if-eqz v14, :cond_d

    .line 463
    .line 464
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 465
    .line 466
    .line 467
    move-result-object v14

    .line 468
    invoke-virtual {v15, v14}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    move-result v16

    .line 472
    if-nez v16, :cond_c

    .line 473
    .line 474
    move/from16 p1, v13

    .line 475
    .line 476
    new-instance v13, Ljava/util/ArrayList;

    .line 477
    .line 478
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 479
    .line 480
    .line 481
    invoke-virtual {v15, v14, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move/from16 v13, p1

    .line 485
    .line 486
    goto :goto_a

    .line 487
    :catchall_1
    move-exception v0

    .line 488
    goto/16 :goto_13

    .line 489
    .line 490
    :cond_d
    move/from16 p1, v13

    .line 491
    .line 492
    invoke-interface {v3}, Lua/c;->reset()V

    .line 493
    .line 494
    .line 495
    invoke-virtual {v0, v2, v15}, Ljz/f;->a(Lua/a;Landroidx/collection/f;)V

    .line 496
    .line 497
    .line 498
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 499
    .line 500
    .line 501
    move-result v0

    .line 502
    const/4 v2, 0x0

    .line 503
    if-eqz v0, :cond_17

    .line 504
    .line 505
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 506
    .line 507
    .line 508
    move-result-object v17

    .line 509
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 510
    .line 511
    .line 512
    move-result v0

    .line 513
    if-eqz v0, :cond_e

    .line 514
    .line 515
    move-object v0, v2

    .line 516
    goto :goto_b

    .line 517
    :cond_e
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 518
    .line 519
    .line 520
    move-result-object v0

    .line 521
    :goto_b
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 522
    .line 523
    .line 524
    move-result-object v18

    .line 525
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 526
    .line 527
    .line 528
    move-result-object v19

    .line 529
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 530
    .line 531
    .line 532
    move-result-wide v20

    .line 533
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 534
    .line 535
    .line 536
    move-result-object v22

    .line 537
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 538
    .line 539
    .line 540
    move-result v0

    .line 541
    if-eqz v0, :cond_f

    .line 542
    .line 543
    move-object/from16 v23, v2

    .line 544
    .line 545
    goto :goto_c

    .line 546
    :cond_f
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 547
    .line 548
    .line 549
    move-result-object v0

    .line 550
    move-object/from16 v23, v0

    .line 551
    .line 552
    :goto_c
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 553
    .line 554
    .line 555
    move-result v0

    .line 556
    if-eqz v0, :cond_10

    .line 557
    .line 558
    move-object v0, v2

    .line 559
    goto :goto_d

    .line 560
    :cond_10
    invoke-interface {v3, v9}, Lua/c;->g0(I)Ljava/lang/String;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    :goto_d
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 565
    .line 566
    .line 567
    move-result-object v24

    .line 568
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 569
    .line 570
    .line 571
    move-result v0

    .line 572
    if-eqz v0, :cond_12

    .line 573
    .line 574
    invoke-interface {v3, v11}, Lua/c;->isNull(I)Z

    .line 575
    .line 576
    .line 577
    move-result v0

    .line 578
    if-nez v0, :cond_11

    .line 579
    .line 580
    goto :goto_e

    .line 581
    :cond_11
    move-object/from16 v25, v2

    .line 582
    .line 583
    goto :goto_f

    .line 584
    :cond_12
    :goto_e
    invoke-interface {v3, v10}, Lua/c;->getDouble(I)D

    .line 585
    .line 586
    .line 587
    move-result-wide v4

    .line 588
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v0

    .line 592
    new-instance v6, Ljz/g;

    .line 593
    .line 594
    invoke-direct {v6, v4, v5, v0}, Ljz/g;-><init>(DLjava/lang/String;)V

    .line 595
    .line 596
    .line 597
    move-object/from16 v25, v6

    .line 598
    .line 599
    :goto_f
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 600
    .line 601
    .line 602
    move-result v0

    .line 603
    if-eqz v0, :cond_15

    .line 604
    .line 605
    move/from16 v0, p1

    .line 606
    .line 607
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 608
    .line 609
    .line 610
    move-result v4

    .line 611
    if-eqz v4, :cond_14

    .line 612
    .line 613
    move/from16 v4, p0

    .line 614
    .line 615
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 616
    .line 617
    .line 618
    move-result v5

    .line 619
    if-nez v5, :cond_13

    .line 620
    .line 621
    goto :goto_10

    .line 622
    :cond_13
    move-object/from16 v26, v2

    .line 623
    .line 624
    goto :goto_12

    .line 625
    :cond_14
    move/from16 v4, p0

    .line 626
    .line 627
    goto :goto_10

    .line 628
    :cond_15
    move/from16 v4, p0

    .line 629
    .line 630
    move/from16 v0, p1

    .line 631
    .line 632
    :goto_10
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 633
    .line 634
    .line 635
    move-result v5

    .line 636
    if-eqz v5, :cond_16

    .line 637
    .line 638
    goto :goto_11

    .line 639
    :cond_16
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 640
    .line 641
    .line 642
    move-result-object v2

    .line 643
    :goto_11
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 644
    .line 645
    .line 646
    move-result-object v2

    .line 647
    invoke-interface {v3, v0}, Lua/c;->getDouble(I)D

    .line 648
    .line 649
    .line 650
    move-result-wide v5

    .line 651
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v0

    .line 655
    new-instance v4, Ljb0/l;

    .line 656
    .line 657
    invoke-direct {v4, v5, v6, v0}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 658
    .line 659
    .line 660
    new-instance v0, Ljb0/c;

    .line 661
    .line 662
    invoke-direct {v0, v4, v2}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 663
    .line 664
    .line 665
    move-object/from16 v26, v0

    .line 666
    .line 667
    :goto_12
    new-instance v16, Ljz/d;

    .line 668
    .line 669
    invoke-direct/range {v16 .. v26}, Ljz/d;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljz/g;Ljb0/c;)V

    .line 670
    .line 671
    .line 672
    move-object/from16 v0, v16

    .line 673
    .line 674
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 675
    .line 676
    .line 677
    move-result-object v1

    .line 678
    invoke-static {v15, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v1

    .line 682
    const-string v2, "getValue(...)"

    .line 683
    .line 684
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 685
    .line 686
    .line 687
    check-cast v1, Ljava/util/List;

    .line 688
    .line 689
    new-instance v2, Ljz/j;

    .line 690
    .line 691
    invoke-direct {v2, v0, v1}, Ljz/j;-><init>(Ljz/d;Ljava/util/List;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 692
    .line 693
    .line 694
    :cond_17
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 695
    .line 696
    .line 697
    return-object v2

    .line 698
    :goto_13
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 699
    .line 700
    .line 701
    throw v0

    .line 702
    nop

    .line 703
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
