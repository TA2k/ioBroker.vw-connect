.class public final synthetic Ljb0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Ljb0/i;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Ljb0/i;I)V
    .locals 0

    .line 1
    iput p3, p0, Ljb0/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljb0/h;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Ljb0/h;->f:Ljb0/i;

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
    .locals 48

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ljb0/h;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Ljb0/h;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Ljb0/h;->f:Ljb0/i;

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
    const-string v3, "SELECT * FROM air_conditioning_status WHERE vin = ? LIMIT 1"

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
    const-string v5, "state"

    .line 38
    .line 39
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    const-string v6, "window_heating_enabled"

    .line 44
    .line 45
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v6

    .line 49
    const-string v7, "target_temperature_at"

    .line 50
    .line 51
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 52
    .line 53
    .line 54
    move-result v7

    .line 55
    const-string v8, "air_conditioning_without_external_power"

    .line 56
    .line 57
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v8

    .line 61
    const-string v9, "air_conditioning_at_unlock"

    .line 62
    .line 63
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v9

    .line 67
    const-string v10, "steering_wheel_position"

    .line 68
    .line 69
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    const-string v11, "heater_source"

    .line 74
    .line 75
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v11

    .line 79
    const-string v12, "charger_connection_state"

    .line 80
    .line 81
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 82
    .line 83
    .line 84
    move-result v12

    .line 85
    const-string v13, "air_conditioning_errors"

    .line 86
    .line 87
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 88
    .line 89
    .line 90
    move-result v13

    .line 91
    const-string v14, "car_captured_timestamp"

    .line 92
    .line 93
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v14

    .line 97
    const-string v15, "target_temperature_value"

    .line 98
    .line 99
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 100
    .line 101
    .line 102
    move-result v15

    .line 103
    const-string v4, "target_temperature_unit"

    .line 104
    .line 105
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 106
    .line 107
    .line 108
    move-result v4

    .line 109
    move/from16 p1, v4

    .line 110
    .line 111
    const-string v4, "window_heating_front"

    .line 112
    .line 113
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    move/from16 v16, v4

    .line 118
    .line 119
    const-string v4, "window_heating_rear"

    .line 120
    .line 121
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 122
    .line 123
    .line 124
    move-result v4

    .line 125
    move/from16 v17, v4

    .line 126
    .line 127
    const-string v4, "seat_heating_front_left"

    .line 128
    .line 129
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    move/from16 v18, v4

    .line 134
    .line 135
    const-string v4, "seat_heating_front_right"

    .line 136
    .line 137
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    move/from16 v19, v4

    .line 142
    .line 143
    const-string v4, "seat_heating_rear_left"

    .line 144
    .line 145
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 146
    .line 147
    .line 148
    move-result v4

    .line 149
    move/from16 v20, v4

    .line 150
    .line 151
    const-string v4, "seat_heating_rear_right"

    .line 152
    .line 153
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 154
    .line 155
    .line 156
    move-result v4

    .line 157
    move/from16 v21, v4

    .line 158
    .line 159
    const-string v4, "air_conditioning_running_request_value"

    .line 160
    .line 161
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    move/from16 v22, v4

    .line 166
    .line 167
    const-string v4, "air_conditioning_running_request_target_temperature_value"

    .line 168
    .line 169
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 170
    .line 171
    .line 172
    move-result v4

    .line 173
    move/from16 v23, v4

    .line 174
    .line 175
    const-string v4, "air_conditioning_running_request_target_temperature_unit"

    .line 176
    .line 177
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    move/from16 v24, v4

    .line 182
    .line 183
    const-string v4, "air_conditioning_outside_temperaturetimestamp"

    .line 184
    .line 185
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 186
    .line 187
    .line 188
    move-result v4

    .line 189
    move/from16 v25, v4

    .line 190
    .line 191
    const-string v4, "air_conditioning_outside_temperatureoutside_temperaturevalue"

    .line 192
    .line 193
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    move/from16 v26, v4

    .line 198
    .line 199
    const-string v4, "air_conditioning_outside_temperatureoutside_temperatureunit"

    .line 200
    .line 201
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    move/from16 v27, v4

    .line 206
    .line 207
    new-instance v4, Landroidx/collection/f;

    .line 208
    .line 209
    move/from16 v28, v15

    .line 210
    .line 211
    const/4 v15, 0x0

    .line 212
    invoke-direct {v4, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 213
    .line 214
    .line 215
    :goto_0
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 216
    .line 217
    .line 218
    move-result v29

    .line 219
    if-eqz v29, :cond_1

    .line 220
    .line 221
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 222
    .line 223
    .line 224
    move-result-object v15

    .line 225
    invoke-virtual {v4, v15}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 226
    .line 227
    .line 228
    move-result v30

    .line 229
    if-nez v30, :cond_0

    .line 230
    .line 231
    move/from16 v30, v14

    .line 232
    .line 233
    new-instance v14, Ljava/util/ArrayList;

    .line 234
    .line 235
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 236
    .line 237
    .line 238
    invoke-virtual {v4, v15, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move/from16 v14, v30

    .line 242
    .line 243
    :cond_0
    const/4 v15, 0x0

    .line 244
    goto :goto_0

    .line 245
    :catchall_0
    move-exception v0

    .line 246
    goto/16 :goto_2a

    .line 247
    .line 248
    :cond_1
    move/from16 v30, v14

    .line 249
    .line 250
    invoke-interface {v3}, Lua/c;->reset()V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v0, v2, v4}, Ljb0/i;->a(Lua/a;Landroidx/collection/f;)V

    .line 254
    .line 255
    .line 256
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    const/4 v2, 0x0

    .line 261
    if-eqz v0, :cond_25

    .line 262
    .line 263
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v32

    .line 267
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v33

    .line 271
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 272
    .line 273
    .line 274
    move-result v0

    .line 275
    if-eqz v0, :cond_2

    .line 276
    .line 277
    move-object v0, v2

    .line 278
    goto :goto_1

    .line 279
    :cond_2
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 280
    .line 281
    .line 282
    move-result-wide v5

    .line 283
    long-to-int v0, v5

    .line 284
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    :goto_1
    if-eqz v0, :cond_4

    .line 289
    .line 290
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 291
    .line 292
    .line 293
    move-result v0

    .line 294
    if-eqz v0, :cond_3

    .line 295
    .line 296
    const/4 v0, 0x1

    .line 297
    goto :goto_2

    .line 298
    :cond_3
    const/4 v0, 0x0

    .line 299
    :goto_2
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    move-object/from16 v34, v0

    .line 304
    .line 305
    goto :goto_3

    .line 306
    :cond_4
    move-object/from16 v34, v2

    .line 307
    .line 308
    :goto_3
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 309
    .line 310
    .line 311
    move-result v0

    .line 312
    if-eqz v0, :cond_5

    .line 313
    .line 314
    move-object v0, v2

    .line 315
    goto :goto_4

    .line 316
    :cond_5
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    :goto_4
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 321
    .line 322
    .line 323
    move-result-object v35

    .line 324
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 325
    .line 326
    .line 327
    move-result v0

    .line 328
    if-eqz v0, :cond_6

    .line 329
    .line 330
    move-object v0, v2

    .line 331
    goto :goto_5

    .line 332
    :cond_6
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 333
    .line 334
    .line 335
    move-result-wide v5

    .line 336
    long-to-int v0, v5

    .line 337
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 338
    .line 339
    .line 340
    move-result-object v0

    .line 341
    :goto_5
    if-eqz v0, :cond_8

    .line 342
    .line 343
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 344
    .line 345
    .line 346
    move-result v0

    .line 347
    if-eqz v0, :cond_7

    .line 348
    .line 349
    const/4 v0, 0x1

    .line 350
    goto :goto_6

    .line 351
    :cond_7
    const/4 v0, 0x0

    .line 352
    :goto_6
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    move-object/from16 v36, v0

    .line 357
    .line 358
    goto :goto_7

    .line 359
    :cond_8
    move-object/from16 v36, v2

    .line 360
    .line 361
    :goto_7
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 362
    .line 363
    .line 364
    move-result v0

    .line 365
    if-eqz v0, :cond_9

    .line 366
    .line 367
    move-object v0, v2

    .line 368
    goto :goto_8

    .line 369
    :cond_9
    invoke-interface {v3, v9}, Lua/c;->getLong(I)J

    .line 370
    .line 371
    .line 372
    move-result-wide v5

    .line 373
    long-to-int v0, v5

    .line 374
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 375
    .line 376
    .line 377
    move-result-object v0

    .line 378
    :goto_8
    if-eqz v0, :cond_b

    .line 379
    .line 380
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 381
    .line 382
    .line 383
    move-result v0

    .line 384
    if-eqz v0, :cond_a

    .line 385
    .line 386
    const/4 v0, 0x1

    .line 387
    goto :goto_9

    .line 388
    :cond_a
    const/4 v0, 0x0

    .line 389
    :goto_9
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    move-object/from16 v37, v0

    .line 394
    .line 395
    goto :goto_a

    .line 396
    :cond_b
    move-object/from16 v37, v2

    .line 397
    .line 398
    :goto_a
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v38

    .line 402
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 403
    .line 404
    .line 405
    move-result-object v39

    .line 406
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 407
    .line 408
    .line 409
    move-result v0

    .line 410
    if-eqz v0, :cond_c

    .line 411
    .line 412
    move-object/from16 v40, v2

    .line 413
    .line 414
    goto :goto_b

    .line 415
    :cond_c
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v0

    .line 419
    move-object/from16 v40, v0

    .line 420
    .line 421
    :goto_b
    invoke-interface {v3, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v41

    .line 425
    move/from16 v0, v30

    .line 426
    .line 427
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 428
    .line 429
    .line 430
    move-result v5

    .line 431
    if-eqz v5, :cond_d

    .line 432
    .line 433
    move-object v0, v2

    .line 434
    goto :goto_c

    .line 435
    :cond_d
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    :goto_c
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 440
    .line 441
    .line 442
    move-result-object v42

    .line 443
    move/from16 v0, v28

    .line 444
    .line 445
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 446
    .line 447
    .line 448
    move-result v5

    .line 449
    if-eqz v5, :cond_f

    .line 450
    .line 451
    move/from16 v5, p1

    .line 452
    .line 453
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 454
    .line 455
    .line 456
    move-result v6

    .line 457
    if-nez v6, :cond_e

    .line 458
    .line 459
    goto :goto_e

    .line 460
    :cond_e
    move-object/from16 v43, v2

    .line 461
    .line 462
    :goto_d
    move/from16 v0, v16

    .line 463
    .line 464
    goto :goto_f

    .line 465
    :cond_f
    move/from16 v5, p1

    .line 466
    .line 467
    :goto_e
    invoke-interface {v3, v0}, Lua/c;->getDouble(I)D

    .line 468
    .line 469
    .line 470
    move-result-wide v6

    .line 471
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 472
    .line 473
    .line 474
    move-result-object v0

    .line 475
    new-instance v5, Ljb0/l;

    .line 476
    .line 477
    invoke-direct {v5, v6, v7, v0}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 478
    .line 479
    .line 480
    move-object/from16 v43, v5

    .line 481
    .line 482
    goto :goto_d

    .line 483
    :goto_f
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 484
    .line 485
    .line 486
    move-result-object v0

    .line 487
    move/from16 v5, v17

    .line 488
    .line 489
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 490
    .line 491
    .line 492
    move-result-object v5

    .line 493
    new-instance v6, Ljb0/o;

    .line 494
    .line 495
    invoke-direct {v6, v0, v5}, Ljb0/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 496
    .line 497
    .line 498
    move/from16 v0, v18

    .line 499
    .line 500
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 501
    .line 502
    .line 503
    move-result v5

    .line 504
    if-eqz v5, :cond_10

    .line 505
    .line 506
    move-object v0, v2

    .line 507
    goto :goto_10

    .line 508
    :cond_10
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 509
    .line 510
    .line 511
    move-result-wide v7

    .line 512
    long-to-int v0, v7

    .line 513
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 514
    .line 515
    .line 516
    move-result-object v0

    .line 517
    :goto_10
    if-eqz v0, :cond_12

    .line 518
    .line 519
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 520
    .line 521
    .line 522
    move-result v0

    .line 523
    if-eqz v0, :cond_11

    .line 524
    .line 525
    const/4 v0, 0x1

    .line 526
    goto :goto_11

    .line 527
    :cond_11
    const/4 v0, 0x0

    .line 528
    :goto_11
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    :goto_12
    move/from16 v5, v19

    .line 533
    .line 534
    goto :goto_13

    .line 535
    :cond_12
    move-object v0, v2

    .line 536
    goto :goto_12

    .line 537
    :goto_13
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 538
    .line 539
    .line 540
    move-result v7

    .line 541
    if-eqz v7, :cond_13

    .line 542
    .line 543
    move-object v5, v2

    .line 544
    goto :goto_14

    .line 545
    :cond_13
    invoke-interface {v3, v5}, Lua/c;->getLong(I)J

    .line 546
    .line 547
    .line 548
    move-result-wide v7

    .line 549
    long-to-int v5, v7

    .line 550
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 551
    .line 552
    .line 553
    move-result-object v5

    .line 554
    :goto_14
    if-eqz v5, :cond_15

    .line 555
    .line 556
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 557
    .line 558
    .line 559
    move-result v5

    .line 560
    if-eqz v5, :cond_14

    .line 561
    .line 562
    const/4 v5, 0x1

    .line 563
    goto :goto_15

    .line 564
    :cond_14
    const/4 v5, 0x0

    .line 565
    :goto_15
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 566
    .line 567
    .line 568
    move-result-object v5

    .line 569
    :goto_16
    move/from16 v7, v20

    .line 570
    .line 571
    goto :goto_17

    .line 572
    :cond_15
    move-object v5, v2

    .line 573
    goto :goto_16

    .line 574
    :goto_17
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 575
    .line 576
    .line 577
    move-result v8

    .line 578
    if-eqz v8, :cond_16

    .line 579
    .line 580
    move-object v7, v2

    .line 581
    goto :goto_18

    .line 582
    :cond_16
    invoke-interface {v3, v7}, Lua/c;->getLong(I)J

    .line 583
    .line 584
    .line 585
    move-result-wide v7

    .line 586
    long-to-int v7, v7

    .line 587
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 588
    .line 589
    .line 590
    move-result-object v7

    .line 591
    :goto_18
    if-eqz v7, :cond_18

    .line 592
    .line 593
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 594
    .line 595
    .line 596
    move-result v7

    .line 597
    if-eqz v7, :cond_17

    .line 598
    .line 599
    const/4 v7, 0x1

    .line 600
    goto :goto_19

    .line 601
    :cond_17
    const/4 v7, 0x0

    .line 602
    :goto_19
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 603
    .line 604
    .line 605
    move-result-object v7

    .line 606
    :goto_1a
    move/from16 v8, v21

    .line 607
    .line 608
    goto :goto_1b

    .line 609
    :cond_18
    move-object v7, v2

    .line 610
    goto :goto_1a

    .line 611
    :goto_1b
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 612
    .line 613
    .line 614
    move-result v9

    .line 615
    if-eqz v9, :cond_19

    .line 616
    .line 617
    move-object v8, v2

    .line 618
    goto :goto_1c

    .line 619
    :cond_19
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 620
    .line 621
    .line 622
    move-result-wide v8

    .line 623
    long-to-int v8, v8

    .line 624
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 625
    .line 626
    .line 627
    move-result-object v8

    .line 628
    :goto_1c
    if-eqz v8, :cond_1b

    .line 629
    .line 630
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 631
    .line 632
    .line 633
    move-result v8

    .line 634
    if-eqz v8, :cond_1a

    .line 635
    .line 636
    const/16 v29, 0x1

    .line 637
    .line 638
    goto :goto_1d

    .line 639
    :cond_1a
    const/16 v29, 0x0

    .line 640
    .line 641
    :goto_1d
    invoke-static/range {v29 .. v29}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 642
    .line 643
    .line 644
    move-result-object v8

    .line 645
    goto :goto_1e

    .line 646
    :cond_1b
    move-object v8, v2

    .line 647
    :goto_1e
    new-instance v9, Ljb0/e;

    .line 648
    .line 649
    invoke-direct {v9, v0, v5, v7, v8}, Ljb0/e;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 650
    .line 651
    .line 652
    move/from16 v0, v22

    .line 653
    .line 654
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 655
    .line 656
    .line 657
    move-result v5

    .line 658
    if-eqz v5, :cond_1e

    .line 659
    .line 660
    move/from16 v5, v23

    .line 661
    .line 662
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 663
    .line 664
    .line 665
    move-result v7

    .line 666
    if-eqz v7, :cond_1d

    .line 667
    .line 668
    move/from16 v7, v24

    .line 669
    .line 670
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 671
    .line 672
    .line 673
    move-result v8

    .line 674
    if-nez v8, :cond_1c

    .line 675
    .line 676
    goto :goto_21

    .line 677
    :cond_1c
    move-object/from16 v46, v2

    .line 678
    .line 679
    :goto_1f
    move/from16 v0, v25

    .line 680
    .line 681
    goto :goto_24

    .line 682
    :cond_1d
    :goto_20
    move/from16 v7, v24

    .line 683
    .line 684
    goto :goto_21

    .line 685
    :cond_1e
    move/from16 v5, v23

    .line 686
    .line 687
    goto :goto_20

    .line 688
    :goto_21
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 689
    .line 690
    .line 691
    move-result-object v0

    .line 692
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 693
    .line 694
    .line 695
    move-result v8

    .line 696
    if-eqz v8, :cond_20

    .line 697
    .line 698
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 699
    .line 700
    .line 701
    move-result v8

    .line 702
    if-nez v8, :cond_1f

    .line 703
    .line 704
    goto :goto_22

    .line 705
    :cond_1f
    move-object v7, v2

    .line 706
    goto :goto_23

    .line 707
    :cond_20
    :goto_22
    invoke-interface {v3, v5}, Lua/c;->getDouble(I)D

    .line 708
    .line 709
    .line 710
    move-result-wide v10

    .line 711
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 712
    .line 713
    .line 714
    move-result-object v5

    .line 715
    new-instance v7, Ljb0/l;

    .line 716
    .line 717
    invoke-direct {v7, v10, v11, v5}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 718
    .line 719
    .line 720
    :goto_23
    new-instance v5, Ljb0/d;

    .line 721
    .line 722
    invoke-direct {v5, v0, v7}, Ljb0/d;-><init>(Ljava/lang/String;Ljb0/l;)V

    .line 723
    .line 724
    .line 725
    move-object/from16 v46, v5

    .line 726
    .line 727
    goto :goto_1f

    .line 728
    :goto_24
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 729
    .line 730
    .line 731
    move-result v5

    .line 732
    if-eqz v5, :cond_23

    .line 733
    .line 734
    move/from16 v5, v26

    .line 735
    .line 736
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 737
    .line 738
    .line 739
    move-result v7

    .line 740
    if-eqz v7, :cond_22

    .line 741
    .line 742
    move/from16 v7, v27

    .line 743
    .line 744
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 745
    .line 746
    .line 747
    move-result v8

    .line 748
    if-nez v8, :cond_21

    .line 749
    .line 750
    goto :goto_27

    .line 751
    :cond_21
    :goto_25
    move-object/from16 v47, v2

    .line 752
    .line 753
    goto :goto_29

    .line 754
    :cond_22
    :goto_26
    move/from16 v7, v27

    .line 755
    .line 756
    goto :goto_27

    .line 757
    :cond_23
    move/from16 v5, v26

    .line 758
    .line 759
    goto :goto_26

    .line 760
    :goto_27
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 761
    .line 762
    .line 763
    move-result v8

    .line 764
    if-eqz v8, :cond_24

    .line 765
    .line 766
    goto :goto_28

    .line 767
    :cond_24
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 768
    .line 769
    .line 770
    move-result-object v2

    .line 771
    :goto_28
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 772
    .line 773
    .line 774
    move-result-object v0

    .line 775
    invoke-interface {v3, v5}, Lua/c;->getDouble(I)D

    .line 776
    .line 777
    .line 778
    move-result-wide v10

    .line 779
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 780
    .line 781
    .line 782
    move-result-object v2

    .line 783
    new-instance v5, Ljb0/l;

    .line 784
    .line 785
    invoke-direct {v5, v10, v11, v2}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 786
    .line 787
    .line 788
    new-instance v2, Ljb0/c;

    .line 789
    .line 790
    invoke-direct {v2, v5, v0}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 791
    .line 792
    .line 793
    goto :goto_25

    .line 794
    :goto_29
    new-instance v31, Ljb0/g;

    .line 795
    .line 796
    move-object/from16 v44, v6

    .line 797
    .line 798
    move-object/from16 v45, v9

    .line 799
    .line 800
    invoke-direct/range {v31 .. v47}, Ljb0/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljb0/l;Ljb0/o;Ljb0/e;Ljb0/d;Ljb0/c;)V

    .line 801
    .line 802
    .line 803
    move-object/from16 v0, v31

    .line 804
    .line 805
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 806
    .line 807
    .line 808
    move-result-object v1

    .line 809
    invoke-static {v4, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 810
    .line 811
    .line 812
    move-result-object v1

    .line 813
    const-string v2, "getValue(...)"

    .line 814
    .line 815
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 816
    .line 817
    .line 818
    check-cast v1, Ljava/util/List;

    .line 819
    .line 820
    new-instance v2, Ljb0/p;

    .line 821
    .line 822
    invoke-direct {v2, v0, v1}, Ljb0/p;-><init>(Ljb0/g;Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 823
    .line 824
    .line 825
    :cond_25
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 826
    .line 827
    .line 828
    return-object v2

    .line 829
    :goto_2a
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 830
    .line 831
    .line 832
    throw v0

    .line 833
    :pswitch_0
    iget-object v1, v0, Ljb0/h;->e:Ljava/lang/String;

    .line 834
    .line 835
    iget-object v0, v0, Ljb0/h;->f:Ljb0/i;

    .line 836
    .line 837
    move-object/from16 v2, p1

    .line 838
    .line 839
    check-cast v2, Lua/a;

    .line 840
    .line 841
    const-string v3, "_connection"

    .line 842
    .line 843
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 844
    .line 845
    .line 846
    const-string v3, "SELECT * FROM air_conditioning_status WHERE vin = ? LIMIT 1"

    .line 847
    .line 848
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 849
    .line 850
    .line 851
    move-result-object v3

    .line 852
    const/4 v4, 0x1

    .line 853
    :try_start_1
    invoke-interface {v3, v4, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 854
    .line 855
    .line 856
    const-string v1, "vin"

    .line 857
    .line 858
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 859
    .line 860
    .line 861
    move-result v1

    .line 862
    const-string v5, "state"

    .line 863
    .line 864
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 865
    .line 866
    .line 867
    move-result v5

    .line 868
    const-string v6, "window_heating_enabled"

    .line 869
    .line 870
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 871
    .line 872
    .line 873
    move-result v6

    .line 874
    const-string v7, "target_temperature_at"

    .line 875
    .line 876
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 877
    .line 878
    .line 879
    move-result v7

    .line 880
    const-string v8, "air_conditioning_without_external_power"

    .line 881
    .line 882
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 883
    .line 884
    .line 885
    move-result v8

    .line 886
    const-string v9, "air_conditioning_at_unlock"

    .line 887
    .line 888
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 889
    .line 890
    .line 891
    move-result v9

    .line 892
    const-string v10, "steering_wheel_position"

    .line 893
    .line 894
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 895
    .line 896
    .line 897
    move-result v10

    .line 898
    const-string v11, "heater_source"

    .line 899
    .line 900
    invoke-static {v3, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 901
    .line 902
    .line 903
    move-result v11

    .line 904
    const-string v12, "charger_connection_state"

    .line 905
    .line 906
    invoke-static {v3, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 907
    .line 908
    .line 909
    move-result v12

    .line 910
    const-string v13, "air_conditioning_errors"

    .line 911
    .line 912
    invoke-static {v3, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 913
    .line 914
    .line 915
    move-result v13

    .line 916
    const-string v14, "car_captured_timestamp"

    .line 917
    .line 918
    invoke-static {v3, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 919
    .line 920
    .line 921
    move-result v14

    .line 922
    const-string v15, "target_temperature_value"

    .line 923
    .line 924
    invoke-static {v3, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 925
    .line 926
    .line 927
    move-result v15

    .line 928
    const-string v4, "target_temperature_unit"

    .line 929
    .line 930
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 931
    .line 932
    .line 933
    move-result v4

    .line 934
    move/from16 p1, v4

    .line 935
    .line 936
    const-string v4, "window_heating_front"

    .line 937
    .line 938
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 939
    .line 940
    .line 941
    move-result v4

    .line 942
    move/from16 v16, v4

    .line 943
    .line 944
    const-string v4, "window_heating_rear"

    .line 945
    .line 946
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 947
    .line 948
    .line 949
    move-result v4

    .line 950
    move/from16 v17, v4

    .line 951
    .line 952
    const-string v4, "seat_heating_front_left"

    .line 953
    .line 954
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 955
    .line 956
    .line 957
    move-result v4

    .line 958
    move/from16 v18, v4

    .line 959
    .line 960
    const-string v4, "seat_heating_front_right"

    .line 961
    .line 962
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 963
    .line 964
    .line 965
    move-result v4

    .line 966
    move/from16 v19, v4

    .line 967
    .line 968
    const-string v4, "seat_heating_rear_left"

    .line 969
    .line 970
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 971
    .line 972
    .line 973
    move-result v4

    .line 974
    move/from16 v20, v4

    .line 975
    .line 976
    const-string v4, "seat_heating_rear_right"

    .line 977
    .line 978
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 979
    .line 980
    .line 981
    move-result v4

    .line 982
    move/from16 v21, v4

    .line 983
    .line 984
    const-string v4, "air_conditioning_running_request_value"

    .line 985
    .line 986
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 987
    .line 988
    .line 989
    move-result v4

    .line 990
    move/from16 v22, v4

    .line 991
    .line 992
    const-string v4, "air_conditioning_running_request_target_temperature_value"

    .line 993
    .line 994
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 995
    .line 996
    .line 997
    move-result v4

    .line 998
    move/from16 v23, v4

    .line 999
    .line 1000
    const-string v4, "air_conditioning_running_request_target_temperature_unit"

    .line 1001
    .line 1002
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1003
    .line 1004
    .line 1005
    move-result v4

    .line 1006
    move/from16 v24, v4

    .line 1007
    .line 1008
    const-string v4, "air_conditioning_outside_temperaturetimestamp"

    .line 1009
    .line 1010
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1011
    .line 1012
    .line 1013
    move-result v4

    .line 1014
    move/from16 v25, v4

    .line 1015
    .line 1016
    const-string v4, "air_conditioning_outside_temperatureoutside_temperaturevalue"

    .line 1017
    .line 1018
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1019
    .line 1020
    .line 1021
    move-result v4

    .line 1022
    move/from16 v26, v4

    .line 1023
    .line 1024
    const-string v4, "air_conditioning_outside_temperatureoutside_temperatureunit"

    .line 1025
    .line 1026
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1027
    .line 1028
    .line 1029
    move-result v4

    .line 1030
    move/from16 v27, v4

    .line 1031
    .line 1032
    new-instance v4, Landroidx/collection/f;

    .line 1033
    .line 1034
    move/from16 v28, v15

    .line 1035
    .line 1036
    const/4 v15, 0x0

    .line 1037
    invoke-direct {v4, v15}, Landroidx/collection/a1;-><init>(I)V

    .line 1038
    .line 1039
    .line 1040
    :goto_2b
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 1041
    .line 1042
    .line 1043
    move-result v29

    .line 1044
    if-eqz v29, :cond_27

    .line 1045
    .line 1046
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v15

    .line 1050
    invoke-virtual {v4, v15}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 1051
    .line 1052
    .line 1053
    move-result v30

    .line 1054
    if-nez v30, :cond_26

    .line 1055
    .line 1056
    move/from16 v30, v14

    .line 1057
    .line 1058
    new-instance v14, Ljava/util/ArrayList;

    .line 1059
    .line 1060
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 1061
    .line 1062
    .line 1063
    invoke-virtual {v4, v15, v14}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1064
    .line 1065
    .line 1066
    move/from16 v14, v30

    .line 1067
    .line 1068
    :cond_26
    const/4 v15, 0x0

    .line 1069
    goto :goto_2b

    .line 1070
    :catchall_1
    move-exception v0

    .line 1071
    goto/16 :goto_55

    .line 1072
    .line 1073
    :cond_27
    move/from16 v30, v14

    .line 1074
    .line 1075
    invoke-interface {v3}, Lua/c;->reset()V

    .line 1076
    .line 1077
    .line 1078
    invoke-virtual {v0, v2, v4}, Ljb0/i;->a(Lua/a;Landroidx/collection/f;)V

    .line 1079
    .line 1080
    .line 1081
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 1082
    .line 1083
    .line 1084
    move-result v0

    .line 1085
    const/4 v2, 0x0

    .line 1086
    if-eqz v0, :cond_4b

    .line 1087
    .line 1088
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v32

    .line 1092
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v33

    .line 1096
    invoke-interface {v3, v6}, Lua/c;->isNull(I)Z

    .line 1097
    .line 1098
    .line 1099
    move-result v0

    .line 1100
    if-eqz v0, :cond_28

    .line 1101
    .line 1102
    move-object v0, v2

    .line 1103
    goto :goto_2c

    .line 1104
    :cond_28
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 1105
    .line 1106
    .line 1107
    move-result-wide v5

    .line 1108
    long-to-int v0, v5

    .line 1109
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1110
    .line 1111
    .line 1112
    move-result-object v0

    .line 1113
    :goto_2c
    if-eqz v0, :cond_2a

    .line 1114
    .line 1115
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1116
    .line 1117
    .line 1118
    move-result v0

    .line 1119
    if-eqz v0, :cond_29

    .line 1120
    .line 1121
    const/4 v0, 0x1

    .line 1122
    goto :goto_2d

    .line 1123
    :cond_29
    const/4 v0, 0x0

    .line 1124
    :goto_2d
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1125
    .line 1126
    .line 1127
    move-result-object v0

    .line 1128
    move-object/from16 v34, v0

    .line 1129
    .line 1130
    goto :goto_2e

    .line 1131
    :cond_2a
    move-object/from16 v34, v2

    .line 1132
    .line 1133
    :goto_2e
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1134
    .line 1135
    .line 1136
    move-result v0

    .line 1137
    if-eqz v0, :cond_2b

    .line 1138
    .line 1139
    move-object v0, v2

    .line 1140
    goto :goto_2f

    .line 1141
    :cond_2b
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1142
    .line 1143
    .line 1144
    move-result-object v0

    .line 1145
    :goto_2f
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1146
    .line 1147
    .line 1148
    move-result-object v35

    .line 1149
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1150
    .line 1151
    .line 1152
    move-result v0

    .line 1153
    if-eqz v0, :cond_2c

    .line 1154
    .line 1155
    move-object v0, v2

    .line 1156
    goto :goto_30

    .line 1157
    :cond_2c
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 1158
    .line 1159
    .line 1160
    move-result-wide v5

    .line 1161
    long-to-int v0, v5

    .line 1162
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v0

    .line 1166
    :goto_30
    if-eqz v0, :cond_2e

    .line 1167
    .line 1168
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1169
    .line 1170
    .line 1171
    move-result v0

    .line 1172
    if-eqz v0, :cond_2d

    .line 1173
    .line 1174
    const/4 v0, 0x1

    .line 1175
    goto :goto_31

    .line 1176
    :cond_2d
    const/4 v0, 0x0

    .line 1177
    :goto_31
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1178
    .line 1179
    .line 1180
    move-result-object v0

    .line 1181
    move-object/from16 v36, v0

    .line 1182
    .line 1183
    goto :goto_32

    .line 1184
    :cond_2e
    move-object/from16 v36, v2

    .line 1185
    .line 1186
    :goto_32
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 1187
    .line 1188
    .line 1189
    move-result v0

    .line 1190
    if-eqz v0, :cond_2f

    .line 1191
    .line 1192
    move-object v0, v2

    .line 1193
    goto :goto_33

    .line 1194
    :cond_2f
    invoke-interface {v3, v9}, Lua/c;->getLong(I)J

    .line 1195
    .line 1196
    .line 1197
    move-result-wide v5

    .line 1198
    long-to-int v0, v5

    .line 1199
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1200
    .line 1201
    .line 1202
    move-result-object v0

    .line 1203
    :goto_33
    if-eqz v0, :cond_31

    .line 1204
    .line 1205
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1206
    .line 1207
    .line 1208
    move-result v0

    .line 1209
    if-eqz v0, :cond_30

    .line 1210
    .line 1211
    const/4 v0, 0x1

    .line 1212
    goto :goto_34

    .line 1213
    :cond_30
    const/4 v0, 0x0

    .line 1214
    :goto_34
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v0

    .line 1218
    move-object/from16 v37, v0

    .line 1219
    .line 1220
    goto :goto_35

    .line 1221
    :cond_31
    move-object/from16 v37, v2

    .line 1222
    .line 1223
    :goto_35
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1224
    .line 1225
    .line 1226
    move-result-object v38

    .line 1227
    invoke-interface {v3, v11}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v39

    .line 1231
    invoke-interface {v3, v12}, Lua/c;->isNull(I)Z

    .line 1232
    .line 1233
    .line 1234
    move-result v0

    .line 1235
    if-eqz v0, :cond_32

    .line 1236
    .line 1237
    move-object/from16 v40, v2

    .line 1238
    .line 1239
    goto :goto_36

    .line 1240
    :cond_32
    invoke-interface {v3, v12}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1241
    .line 1242
    .line 1243
    move-result-object v0

    .line 1244
    move-object/from16 v40, v0

    .line 1245
    .line 1246
    :goto_36
    invoke-interface {v3, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1247
    .line 1248
    .line 1249
    move-result-object v41

    .line 1250
    move/from16 v0, v30

    .line 1251
    .line 1252
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1253
    .line 1254
    .line 1255
    move-result v5

    .line 1256
    if-eqz v5, :cond_33

    .line 1257
    .line 1258
    move-object v0, v2

    .line 1259
    goto :goto_37

    .line 1260
    :cond_33
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1261
    .line 1262
    .line 1263
    move-result-object v0

    .line 1264
    :goto_37
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1265
    .line 1266
    .line 1267
    move-result-object v42

    .line 1268
    move/from16 v0, v28

    .line 1269
    .line 1270
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1271
    .line 1272
    .line 1273
    move-result v5

    .line 1274
    if-eqz v5, :cond_35

    .line 1275
    .line 1276
    move/from16 v5, p1

    .line 1277
    .line 1278
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1279
    .line 1280
    .line 1281
    move-result v6

    .line 1282
    if-nez v6, :cond_34

    .line 1283
    .line 1284
    goto :goto_39

    .line 1285
    :cond_34
    move-object/from16 v43, v2

    .line 1286
    .line 1287
    :goto_38
    move/from16 v0, v16

    .line 1288
    .line 1289
    goto :goto_3a

    .line 1290
    :cond_35
    move/from16 v5, p1

    .line 1291
    .line 1292
    :goto_39
    invoke-interface {v3, v0}, Lua/c;->getDouble(I)D

    .line 1293
    .line 1294
    .line 1295
    move-result-wide v6

    .line 1296
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1297
    .line 1298
    .line 1299
    move-result-object v0

    .line 1300
    new-instance v5, Ljb0/l;

    .line 1301
    .line 1302
    invoke-direct {v5, v6, v7, v0}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 1303
    .line 1304
    .line 1305
    move-object/from16 v43, v5

    .line 1306
    .line 1307
    goto :goto_38

    .line 1308
    :goto_3a
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v0

    .line 1312
    move/from16 v5, v17

    .line 1313
    .line 1314
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1315
    .line 1316
    .line 1317
    move-result-object v5

    .line 1318
    new-instance v6, Ljb0/o;

    .line 1319
    .line 1320
    invoke-direct {v6, v0, v5}, Ljb0/o;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1321
    .line 1322
    .line 1323
    move/from16 v0, v18

    .line 1324
    .line 1325
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1326
    .line 1327
    .line 1328
    move-result v5

    .line 1329
    if-eqz v5, :cond_36

    .line 1330
    .line 1331
    move-object v0, v2

    .line 1332
    goto :goto_3b

    .line 1333
    :cond_36
    invoke-interface {v3, v0}, Lua/c;->getLong(I)J

    .line 1334
    .line 1335
    .line 1336
    move-result-wide v7

    .line 1337
    long-to-int v0, v7

    .line 1338
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1339
    .line 1340
    .line 1341
    move-result-object v0

    .line 1342
    :goto_3b
    if-eqz v0, :cond_38

    .line 1343
    .line 1344
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 1345
    .line 1346
    .line 1347
    move-result v0

    .line 1348
    if-eqz v0, :cond_37

    .line 1349
    .line 1350
    const/4 v0, 0x1

    .line 1351
    goto :goto_3c

    .line 1352
    :cond_37
    const/4 v0, 0x0

    .line 1353
    :goto_3c
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v0

    .line 1357
    :goto_3d
    move/from16 v5, v19

    .line 1358
    .line 1359
    goto :goto_3e

    .line 1360
    :cond_38
    move-object v0, v2

    .line 1361
    goto :goto_3d

    .line 1362
    :goto_3e
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1363
    .line 1364
    .line 1365
    move-result v7

    .line 1366
    if-eqz v7, :cond_39

    .line 1367
    .line 1368
    move-object v5, v2

    .line 1369
    goto :goto_3f

    .line 1370
    :cond_39
    invoke-interface {v3, v5}, Lua/c;->getLong(I)J

    .line 1371
    .line 1372
    .line 1373
    move-result-wide v7

    .line 1374
    long-to-int v5, v7

    .line 1375
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1376
    .line 1377
    .line 1378
    move-result-object v5

    .line 1379
    :goto_3f
    if-eqz v5, :cond_3b

    .line 1380
    .line 1381
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 1382
    .line 1383
    .line 1384
    move-result v5

    .line 1385
    if-eqz v5, :cond_3a

    .line 1386
    .line 1387
    const/4 v5, 0x1

    .line 1388
    goto :goto_40

    .line 1389
    :cond_3a
    const/4 v5, 0x0

    .line 1390
    :goto_40
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1391
    .line 1392
    .line 1393
    move-result-object v5

    .line 1394
    :goto_41
    move/from16 v7, v20

    .line 1395
    .line 1396
    goto :goto_42

    .line 1397
    :cond_3b
    move-object v5, v2

    .line 1398
    goto :goto_41

    .line 1399
    :goto_42
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1400
    .line 1401
    .line 1402
    move-result v8

    .line 1403
    if-eqz v8, :cond_3c

    .line 1404
    .line 1405
    move-object v7, v2

    .line 1406
    goto :goto_43

    .line 1407
    :cond_3c
    invoke-interface {v3, v7}, Lua/c;->getLong(I)J

    .line 1408
    .line 1409
    .line 1410
    move-result-wide v7

    .line 1411
    long-to-int v7, v7

    .line 1412
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1413
    .line 1414
    .line 1415
    move-result-object v7

    .line 1416
    :goto_43
    if-eqz v7, :cond_3e

    .line 1417
    .line 1418
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 1419
    .line 1420
    .line 1421
    move-result v7

    .line 1422
    if-eqz v7, :cond_3d

    .line 1423
    .line 1424
    const/4 v7, 0x1

    .line 1425
    goto :goto_44

    .line 1426
    :cond_3d
    const/4 v7, 0x0

    .line 1427
    :goto_44
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1428
    .line 1429
    .line 1430
    move-result-object v7

    .line 1431
    :goto_45
    move/from16 v8, v21

    .line 1432
    .line 1433
    goto :goto_46

    .line 1434
    :cond_3e
    move-object v7, v2

    .line 1435
    goto :goto_45

    .line 1436
    :goto_46
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 1437
    .line 1438
    .line 1439
    move-result v9

    .line 1440
    if-eqz v9, :cond_3f

    .line 1441
    .line 1442
    move-object v8, v2

    .line 1443
    goto :goto_47

    .line 1444
    :cond_3f
    invoke-interface {v3, v8}, Lua/c;->getLong(I)J

    .line 1445
    .line 1446
    .line 1447
    move-result-wide v8

    .line 1448
    long-to-int v8, v8

    .line 1449
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1450
    .line 1451
    .line 1452
    move-result-object v8

    .line 1453
    :goto_47
    if-eqz v8, :cond_41

    .line 1454
    .line 1455
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 1456
    .line 1457
    .line 1458
    move-result v8

    .line 1459
    if-eqz v8, :cond_40

    .line 1460
    .line 1461
    const/16 v29, 0x1

    .line 1462
    .line 1463
    goto :goto_48

    .line 1464
    :cond_40
    const/16 v29, 0x0

    .line 1465
    .line 1466
    :goto_48
    invoke-static/range {v29 .. v29}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1467
    .line 1468
    .line 1469
    move-result-object v8

    .line 1470
    goto :goto_49

    .line 1471
    :cond_41
    move-object v8, v2

    .line 1472
    :goto_49
    new-instance v9, Ljb0/e;

    .line 1473
    .line 1474
    invoke-direct {v9, v0, v5, v7, v8}, Ljb0/e;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 1475
    .line 1476
    .line 1477
    move/from16 v0, v22

    .line 1478
    .line 1479
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1480
    .line 1481
    .line 1482
    move-result v5

    .line 1483
    if-eqz v5, :cond_44

    .line 1484
    .line 1485
    move/from16 v5, v23

    .line 1486
    .line 1487
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1488
    .line 1489
    .line 1490
    move-result v7

    .line 1491
    if-eqz v7, :cond_43

    .line 1492
    .line 1493
    move/from16 v7, v24

    .line 1494
    .line 1495
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1496
    .line 1497
    .line 1498
    move-result v8

    .line 1499
    if-nez v8, :cond_42

    .line 1500
    .line 1501
    goto :goto_4c

    .line 1502
    :cond_42
    move-object/from16 v46, v2

    .line 1503
    .line 1504
    :goto_4a
    move/from16 v0, v25

    .line 1505
    .line 1506
    goto :goto_4f

    .line 1507
    :cond_43
    :goto_4b
    move/from16 v7, v24

    .line 1508
    .line 1509
    goto :goto_4c

    .line 1510
    :cond_44
    move/from16 v5, v23

    .line 1511
    .line 1512
    goto :goto_4b

    .line 1513
    :goto_4c
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1514
    .line 1515
    .line 1516
    move-result-object v0

    .line 1517
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1518
    .line 1519
    .line 1520
    move-result v8

    .line 1521
    if-eqz v8, :cond_46

    .line 1522
    .line 1523
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1524
    .line 1525
    .line 1526
    move-result v8

    .line 1527
    if-nez v8, :cond_45

    .line 1528
    .line 1529
    goto :goto_4d

    .line 1530
    :cond_45
    move-object v7, v2

    .line 1531
    goto :goto_4e

    .line 1532
    :cond_46
    :goto_4d
    invoke-interface {v3, v5}, Lua/c;->getDouble(I)D

    .line 1533
    .line 1534
    .line 1535
    move-result-wide v10

    .line 1536
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1537
    .line 1538
    .line 1539
    move-result-object v5

    .line 1540
    new-instance v7, Ljb0/l;

    .line 1541
    .line 1542
    invoke-direct {v7, v10, v11, v5}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 1543
    .line 1544
    .line 1545
    :goto_4e
    new-instance v5, Ljb0/d;

    .line 1546
    .line 1547
    invoke-direct {v5, v0, v7}, Ljb0/d;-><init>(Ljava/lang/String;Ljb0/l;)V

    .line 1548
    .line 1549
    .line 1550
    move-object/from16 v46, v5

    .line 1551
    .line 1552
    goto :goto_4a

    .line 1553
    :goto_4f
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1554
    .line 1555
    .line 1556
    move-result v5

    .line 1557
    if-eqz v5, :cond_49

    .line 1558
    .line 1559
    move/from16 v5, v26

    .line 1560
    .line 1561
    invoke-interface {v3, v5}, Lua/c;->isNull(I)Z

    .line 1562
    .line 1563
    .line 1564
    move-result v7

    .line 1565
    if-eqz v7, :cond_48

    .line 1566
    .line 1567
    move/from16 v7, v27

    .line 1568
    .line 1569
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 1570
    .line 1571
    .line 1572
    move-result v8

    .line 1573
    if-nez v8, :cond_47

    .line 1574
    .line 1575
    goto :goto_52

    .line 1576
    :cond_47
    :goto_50
    move-object/from16 v47, v2

    .line 1577
    .line 1578
    goto :goto_54

    .line 1579
    :cond_48
    :goto_51
    move/from16 v7, v27

    .line 1580
    .line 1581
    goto :goto_52

    .line 1582
    :cond_49
    move/from16 v5, v26

    .line 1583
    .line 1584
    goto :goto_51

    .line 1585
    :goto_52
    invoke-interface {v3, v0}, Lua/c;->isNull(I)Z

    .line 1586
    .line 1587
    .line 1588
    move-result v8

    .line 1589
    if-eqz v8, :cond_4a

    .line 1590
    .line 1591
    goto :goto_53

    .line 1592
    :cond_4a
    invoke-interface {v3, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1593
    .line 1594
    .line 1595
    move-result-object v2

    .line 1596
    :goto_53
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 1597
    .line 1598
    .line 1599
    move-result-object v0

    .line 1600
    invoke-interface {v3, v5}, Lua/c;->getDouble(I)D

    .line 1601
    .line 1602
    .line 1603
    move-result-wide v10

    .line 1604
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1605
    .line 1606
    .line 1607
    move-result-object v2

    .line 1608
    new-instance v5, Ljb0/l;

    .line 1609
    .line 1610
    invoke-direct {v5, v10, v11, v2}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 1611
    .line 1612
    .line 1613
    new-instance v2, Ljb0/c;

    .line 1614
    .line 1615
    invoke-direct {v2, v5, v0}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 1616
    .line 1617
    .line 1618
    goto :goto_50

    .line 1619
    :goto_54
    new-instance v31, Ljb0/g;

    .line 1620
    .line 1621
    move-object/from16 v44, v6

    .line 1622
    .line 1623
    move-object/from16 v45, v9

    .line 1624
    .line 1625
    invoke-direct/range {v31 .. v47}, Ljb0/g;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/time/OffsetDateTime;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;Ljb0/l;Ljb0/o;Ljb0/e;Ljb0/d;Ljb0/c;)V

    .line 1626
    .line 1627
    .line 1628
    move-object/from16 v0, v31

    .line 1629
    .line 1630
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v1

    .line 1634
    invoke-static {v4, v1}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1635
    .line 1636
    .line 1637
    move-result-object v1

    .line 1638
    const-string v2, "getValue(...)"

    .line 1639
    .line 1640
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1641
    .line 1642
    .line 1643
    check-cast v1, Ljava/util/List;

    .line 1644
    .line 1645
    new-instance v2, Ljb0/p;

    .line 1646
    .line 1647
    invoke-direct {v2, v0, v1}, Ljb0/p;-><init>(Ljb0/g;Ljava/util/List;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1648
    .line 1649
    .line 1650
    :cond_4b
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 1651
    .line 1652
    .line 1653
    return-object v2

    .line 1654
    :goto_55
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 1655
    .line 1656
    .line 1657
    throw v0

    .line 1658
    nop

    .line 1659
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
