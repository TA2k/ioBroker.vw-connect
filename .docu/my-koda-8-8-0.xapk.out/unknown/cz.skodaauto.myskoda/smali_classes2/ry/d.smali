.class public final synthetic Lry/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;

.field public final synthetic f:Lry/e;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;Lry/e;I)V
    .locals 0

    .line 1
    iput p3, p0, Lry/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lry/d;->e:Ljava/lang/String;

    .line 4
    .line 5
    iput-object p2, p0, Lry/d;->f:Lry/e;

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
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lry/d;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lry/d;->e:Ljava/lang/String;

    .line 9
    .line 10
    iget-object v0, v0, Lry/d;->f:Lry/e;

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
    const-string v3, "SELECT * FROM active_ventilation_status WHERE vin = ? LIMIT 1"

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
    const-string v4, "estimated_to_reach_target"

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
    const-string v7, "car_captured_timestamp"

    .line 56
    .line 57
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    const-string v8, "outside_temperature_timestamp"

    .line 62
    .line 63
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    move-result v8

    .line 67
    const-string v9, "outside_temperature_outside_temperaturevalue"

    .line 68
    .line 69
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 70
    .line 71
    .line 72
    move-result v9

    .line 73
    const-string v10, "outside_temperature_outside_temperatureunit"

    .line 74
    .line 75
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 76
    .line 77
    .line 78
    move-result v10

    .line 79
    new-instance v11, Landroidx/collection/f;

    .line 80
    .line 81
    const/4 v12, 0x0

    .line 82
    invoke-direct {v11, v12}, Landroidx/collection/a1;-><init>(I)V

    .line 83
    .line 84
    .line 85
    :cond_0
    :goto_0
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 86
    .line 87
    .line 88
    move-result v12

    .line 89
    if-eqz v12, :cond_1

    .line 90
    .line 91
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v12

    .line 95
    invoke-virtual {v11, v12}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v13

    .line 99
    if-nez v13, :cond_0

    .line 100
    .line 101
    new-instance v13, Ljava/util/ArrayList;

    .line 102
    .line 103
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v11, v12, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    goto :goto_0

    .line 110
    :catchall_0
    move-exception v0

    .line 111
    goto/16 :goto_7

    .line 112
    .line 113
    :cond_1
    invoke-interface {v3}, Lua/c;->reset()V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, v2, v11}, Lry/e;->a(Lua/a;Landroidx/collection/f;)V

    .line 117
    .line 118
    .line 119
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 120
    .line 121
    .line 122
    move-result v0

    .line 123
    const/4 v2, 0x0

    .line 124
    if-eqz v0, :cond_7

    .line 125
    .line 126
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v13

    .line 130
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_2

    .line 135
    .line 136
    move-object v0, v2

    .line 137
    goto :goto_1

    .line 138
    :cond_2
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    :goto_1
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 143
    .line 144
    .line 145
    move-result-object v14

    .line 146
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object v15

    .line 150
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 151
    .line 152
    .line 153
    move-result-wide v16

    .line 154
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-eqz v0, :cond_3

    .line 159
    .line 160
    move-object v0, v2

    .line 161
    goto :goto_2

    .line 162
    :cond_3
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    :goto_2
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 167
    .line 168
    .line 169
    move-result-object v18

    .line 170
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_5

    .line 175
    .line 176
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 177
    .line 178
    .line 179
    move-result v0

    .line 180
    if-eqz v0, :cond_5

    .line 181
    .line 182
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    if-nez v0, :cond_4

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_4
    :goto_3
    move-object/from16 v19, v2

    .line 190
    .line 191
    goto :goto_6

    .line 192
    :cond_5
    :goto_4
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    if-eqz v0, :cond_6

    .line 197
    .line 198
    goto :goto_5

    .line 199
    :cond_6
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v2

    .line 203
    :goto_5
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 204
    .line 205
    .line 206
    move-result-object v0

    .line 207
    invoke-interface {v3, v9}, Lua/c;->getDouble(I)D

    .line 208
    .line 209
    .line 210
    move-result-wide v4

    .line 211
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    new-instance v6, Ljb0/l;

    .line 216
    .line 217
    invoke-direct {v6, v4, v5, v2}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 218
    .line 219
    .line 220
    new-instance v2, Ljb0/c;

    .line 221
    .line 222
    invoke-direct {v2, v6, v0}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 223
    .line 224
    .line 225
    goto :goto_3

    .line 226
    :goto_6
    new-instance v12, Lry/c;

    .line 227
    .line 228
    invoke-direct/range {v12 .. v19}, Lry/c;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;JLjava/time/OffsetDateTime;Ljb0/c;)V

    .line 229
    .line 230
    .line 231
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v0

    .line 235
    invoke-static {v11, v0}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    const-string v1, "getValue(...)"

    .line 240
    .line 241
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    check-cast v0, Ljava/util/List;

    .line 245
    .line 246
    new-instance v2, Lry/h;

    .line 247
    .line 248
    invoke-direct {v2, v12, v0}, Lry/h;-><init>(Lry/c;Ljava/util/List;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 249
    .line 250
    .line 251
    :cond_7
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 252
    .line 253
    .line 254
    return-object v2

    .line 255
    :goto_7
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 256
    .line 257
    .line 258
    throw v0

    .line 259
    :pswitch_0
    iget-object v1, v0, Lry/d;->e:Ljava/lang/String;

    .line 260
    .line 261
    iget-object v0, v0, Lry/d;->f:Lry/e;

    .line 262
    .line 263
    move-object/from16 v2, p1

    .line 264
    .line 265
    check-cast v2, Lua/a;

    .line 266
    .line 267
    const-string v3, "_connection"

    .line 268
    .line 269
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 270
    .line 271
    .line 272
    const-string v3, "SELECT * FROM active_ventilation_status WHERE vin = ? LIMIT 1"

    .line 273
    .line 274
    invoke-interface {v2, v3}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    const/4 v4, 0x1

    .line 279
    :try_start_1
    invoke-interface {v3, v4, v1}, Lua/c;->w(ILjava/lang/String;)V

    .line 280
    .line 281
    .line 282
    const-string v1, "vin"

    .line 283
    .line 284
    invoke-static {v3, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 285
    .line 286
    .line 287
    move-result v1

    .line 288
    const-string v4, "estimated_to_reach_target"

    .line 289
    .line 290
    invoke-static {v3, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 291
    .line 292
    .line 293
    move-result v4

    .line 294
    const-string v5, "state"

    .line 295
    .line 296
    invoke-static {v3, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 297
    .line 298
    .line 299
    move-result v5

    .line 300
    const-string v6, "duration"

    .line 301
    .line 302
    invoke-static {v3, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 303
    .line 304
    .line 305
    move-result v6

    .line 306
    const-string v7, "car_captured_timestamp"

    .line 307
    .line 308
    invoke-static {v3, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 309
    .line 310
    .line 311
    move-result v7

    .line 312
    const-string v8, "outside_temperature_timestamp"

    .line 313
    .line 314
    invoke-static {v3, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 315
    .line 316
    .line 317
    move-result v8

    .line 318
    const-string v9, "outside_temperature_outside_temperaturevalue"

    .line 319
    .line 320
    invoke-static {v3, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 321
    .line 322
    .line 323
    move-result v9

    .line 324
    const-string v10, "outside_temperature_outside_temperatureunit"

    .line 325
    .line 326
    invoke-static {v3, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 327
    .line 328
    .line 329
    move-result v10

    .line 330
    new-instance v11, Landroidx/collection/f;

    .line 331
    .line 332
    const/4 v12, 0x0

    .line 333
    invoke-direct {v11, v12}, Landroidx/collection/a1;-><init>(I)V

    .line 334
    .line 335
    .line 336
    :cond_8
    :goto_8
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 337
    .line 338
    .line 339
    move-result v12

    .line 340
    if-eqz v12, :cond_9

    .line 341
    .line 342
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v12

    .line 346
    invoke-virtual {v11, v12}, Landroidx/collection/f;->containsKey(Ljava/lang/Object;)Z

    .line 347
    .line 348
    .line 349
    move-result v13

    .line 350
    if-nez v13, :cond_8

    .line 351
    .line 352
    new-instance v13, Ljava/util/ArrayList;

    .line 353
    .line 354
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 355
    .line 356
    .line 357
    invoke-virtual {v11, v12, v13}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    goto :goto_8

    .line 361
    :catchall_1
    move-exception v0

    .line 362
    goto/16 :goto_f

    .line 363
    .line 364
    :cond_9
    invoke-interface {v3}, Lua/c;->reset()V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v0, v2, v11}, Lry/e;->a(Lua/a;Landroidx/collection/f;)V

    .line 368
    .line 369
    .line 370
    invoke-interface {v3}, Lua/c;->s0()Z

    .line 371
    .line 372
    .line 373
    move-result v0

    .line 374
    const/4 v2, 0x0

    .line 375
    if-eqz v0, :cond_f

    .line 376
    .line 377
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v13

    .line 381
    invoke-interface {v3, v4}, Lua/c;->isNull(I)Z

    .line 382
    .line 383
    .line 384
    move-result v0

    .line 385
    if-eqz v0, :cond_a

    .line 386
    .line 387
    move-object v0, v2

    .line 388
    goto :goto_9

    .line 389
    :cond_a
    invoke-interface {v3, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    :goto_9
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 394
    .line 395
    .line 396
    move-result-object v14

    .line 397
    invoke-interface {v3, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v15

    .line 401
    invoke-interface {v3, v6}, Lua/c;->getLong(I)J

    .line 402
    .line 403
    .line 404
    move-result-wide v16

    .line 405
    invoke-interface {v3, v7}, Lua/c;->isNull(I)Z

    .line 406
    .line 407
    .line 408
    move-result v0

    .line 409
    if-eqz v0, :cond_b

    .line 410
    .line 411
    move-object v0, v2

    .line 412
    goto :goto_a

    .line 413
    :cond_b
    invoke-interface {v3, v7}, Lua/c;->g0(I)Ljava/lang/String;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    :goto_a
    invoke-static {v0}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 418
    .line 419
    .line 420
    move-result-object v18

    .line 421
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 422
    .line 423
    .line 424
    move-result v0

    .line 425
    if-eqz v0, :cond_d

    .line 426
    .line 427
    invoke-interface {v3, v9}, Lua/c;->isNull(I)Z

    .line 428
    .line 429
    .line 430
    move-result v0

    .line 431
    if-eqz v0, :cond_d

    .line 432
    .line 433
    invoke-interface {v3, v10}, Lua/c;->isNull(I)Z

    .line 434
    .line 435
    .line 436
    move-result v0

    .line 437
    if-nez v0, :cond_c

    .line 438
    .line 439
    goto :goto_c

    .line 440
    :cond_c
    :goto_b
    move-object/from16 v19, v2

    .line 441
    .line 442
    goto :goto_e

    .line 443
    :cond_d
    :goto_c
    invoke-interface {v3, v8}, Lua/c;->isNull(I)Z

    .line 444
    .line 445
    .line 446
    move-result v0

    .line 447
    if-eqz v0, :cond_e

    .line 448
    .line 449
    goto :goto_d

    .line 450
    :cond_e
    invoke-interface {v3, v8}, Lua/c;->g0(I)Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v2

    .line 454
    :goto_d
    invoke-static {v2}, La61/a;->p(Ljava/lang/String;)Ljava/time/OffsetDateTime;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    invoke-interface {v3, v9}, Lua/c;->getDouble(I)D

    .line 459
    .line 460
    .line 461
    move-result-wide v4

    .line 462
    invoke-interface {v3, v10}, Lua/c;->g0(I)Ljava/lang/String;

    .line 463
    .line 464
    .line 465
    move-result-object v2

    .line 466
    new-instance v6, Ljb0/l;

    .line 467
    .line 468
    invoke-direct {v6, v4, v5, v2}, Ljb0/l;-><init>(DLjava/lang/String;)V

    .line 469
    .line 470
    .line 471
    new-instance v2, Ljb0/c;

    .line 472
    .line 473
    invoke-direct {v2, v6, v0}, Ljb0/c;-><init>(Ljb0/l;Ljava/time/OffsetDateTime;)V

    .line 474
    .line 475
    .line 476
    goto :goto_b

    .line 477
    :goto_e
    new-instance v12, Lry/c;

    .line 478
    .line 479
    invoke-direct/range {v12 .. v19}, Lry/c;-><init>(Ljava/lang/String;Ljava/time/OffsetDateTime;Ljava/lang/String;JLjava/time/OffsetDateTime;Ljb0/c;)V

    .line 480
    .line 481
    .line 482
    invoke-interface {v3, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v0

    .line 486
    invoke-static {v11, v0}, Lmx0/x;->i(Ljava/util/Map;Ljava/lang/Object;)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    const-string v1, "getValue(...)"

    .line 491
    .line 492
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 493
    .line 494
    .line 495
    check-cast v0, Ljava/util/List;

    .line 496
    .line 497
    new-instance v2, Lry/h;

    .line 498
    .line 499
    invoke-direct {v2, v12, v0}, Lry/h;-><init>(Lry/c;Ljava/util/List;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 500
    .line 501
    .line 502
    :cond_f
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 503
    .line 504
    .line 505
    return-object v2

    .line 506
    :goto_f
    invoke-interface {v3}, Ljava/lang/AutoCloseable;->close()V

    .line 507
    .line 508
    .line 509
    throw v0

    .line 510
    nop

    .line 511
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
