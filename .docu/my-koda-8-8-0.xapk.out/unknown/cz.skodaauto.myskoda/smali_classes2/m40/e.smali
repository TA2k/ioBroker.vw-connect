.class public final synthetic Lm40/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lm40/e;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p1, Lua/a;

    .line 2
    .line 3
    const-string p0, "_connection"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "SELECT COUNT(*) > 0 FROM workspec WHERE state NOT IN (2, 3, 5) LIMIT 1"

    .line 9
    .line 10
    invoke-interface {p1, p0}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    :try_start_0
    invoke-interface {p0}, Lua/c;->s0()Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const/4 v0, 0x0

    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    invoke-interface {p0, v0}, Lua/c;->getLong(I)J

    .line 22
    .line 23
    .line 24
    move-result-wide v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    long-to-int p1, v1

    .line 26
    if-eqz p1, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    goto :goto_0

    .line 30
    :catchall_0
    move-exception p1

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 33
    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :goto_1
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V

    .line 41
    .line 42
    .line 43
    throw p1
.end method

.method private final b(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 84

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    check-cast v0, Lua/a;

    .line 4
    .line 5
    const-string v1, "_connection"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v1, "SELECT * FROM workspec WHERE state=0 ORDER BY last_enqueue_time LIMIT ?"

    .line 11
    .line 12
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/16 v0, 0xc8

    .line 17
    .line 18
    int-to-long v2, v0

    .line 19
    const/4 v0, 0x1

    .line 20
    :try_start_0
    invoke-interface {v1, v0, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 21
    .line 22
    .line 23
    const-string v2, "id"

    .line 24
    .line 25
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    const-string v3, "state"

    .line 30
    .line 31
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    const-string v4, "worker_class_name"

    .line 36
    .line 37
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    const-string v5, "input_merger_class_name"

    .line 42
    .line 43
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 44
    .line 45
    .line 46
    move-result v5

    .line 47
    const-string v6, "input"

    .line 48
    .line 49
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v6

    .line 53
    const-string v7, "output"

    .line 54
    .line 55
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    const-string v8, "initial_delay"

    .line 60
    .line 61
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    const-string v9, "interval_duration"

    .line 66
    .line 67
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 68
    .line 69
    .line 70
    move-result v9

    .line 71
    const-string v10, "flex_duration"

    .line 72
    .line 73
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 74
    .line 75
    .line 76
    move-result v10

    .line 77
    const-string v11, "run_attempt_count"

    .line 78
    .line 79
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 80
    .line 81
    .line 82
    move-result v11

    .line 83
    const-string v12, "backoff_policy"

    .line 84
    .line 85
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 86
    .line 87
    .line 88
    move-result v12

    .line 89
    const-string v13, "backoff_delay_duration"

    .line 90
    .line 91
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 92
    .line 93
    .line 94
    move-result v13

    .line 95
    const-string v14, "last_enqueue_time"

    .line 96
    .line 97
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 98
    .line 99
    .line 100
    move-result v14

    .line 101
    const-string v15, "minimum_retention_duration"

    .line 102
    .line 103
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 104
    .line 105
    .line 106
    move-result v15

    .line 107
    const-string v0, "schedule_requested_at"

    .line 108
    .line 109
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    move/from16 p1, v0

    .line 114
    .line 115
    const-string v0, "run_in_foreground"

    .line 116
    .line 117
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    move/from16 v16, v0

    .line 122
    .line 123
    const-string v0, "out_of_quota_policy"

    .line 124
    .line 125
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    move/from16 v17, v0

    .line 130
    .line 131
    const-string v0, "period_count"

    .line 132
    .line 133
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    move/from16 v18, v0

    .line 138
    .line 139
    const-string v0, "generation"

    .line 140
    .line 141
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 142
    .line 143
    .line 144
    move-result v0

    .line 145
    move/from16 v19, v0

    .line 146
    .line 147
    const-string v0, "next_schedule_time_override"

    .line 148
    .line 149
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 150
    .line 151
    .line 152
    move-result v0

    .line 153
    move/from16 v20, v0

    .line 154
    .line 155
    const-string v0, "next_schedule_time_override_generation"

    .line 156
    .line 157
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    move/from16 v21, v0

    .line 162
    .line 163
    const-string v0, "stop_reason"

    .line 164
    .line 165
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    move-result v0

    .line 169
    move/from16 v22, v0

    .line 170
    .line 171
    const-string v0, "trace_tag"

    .line 172
    .line 173
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 174
    .line 175
    .line 176
    move-result v0

    .line 177
    move/from16 v23, v0

    .line 178
    .line 179
    const-string v0, "backoff_on_system_interruptions"

    .line 180
    .line 181
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 182
    .line 183
    .line 184
    move-result v0

    .line 185
    move/from16 v24, v0

    .line 186
    .line 187
    const-string v0, "required_network_type"

    .line 188
    .line 189
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 190
    .line 191
    .line 192
    move-result v0

    .line 193
    move/from16 v25, v0

    .line 194
    .line 195
    const-string v0, "required_network_request"

    .line 196
    .line 197
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 198
    .line 199
    .line 200
    move-result v0

    .line 201
    move/from16 v26, v0

    .line 202
    .line 203
    const-string v0, "requires_charging"

    .line 204
    .line 205
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 206
    .line 207
    .line 208
    move-result v0

    .line 209
    move/from16 v27, v0

    .line 210
    .line 211
    const-string v0, "requires_device_idle"

    .line 212
    .line 213
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    move/from16 v28, v0

    .line 218
    .line 219
    const-string v0, "requires_battery_not_low"

    .line 220
    .line 221
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 222
    .line 223
    .line 224
    move-result v0

    .line 225
    move/from16 v29, v0

    .line 226
    .line 227
    const-string v0, "requires_storage_not_low"

    .line 228
    .line 229
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 230
    .line 231
    .line 232
    move-result v0

    .line 233
    move/from16 v30, v0

    .line 234
    .line 235
    const-string v0, "trigger_content_update_delay"

    .line 236
    .line 237
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 238
    .line 239
    .line 240
    move-result v0

    .line 241
    move/from16 v31, v0

    .line 242
    .line 243
    const-string v0, "trigger_max_content_delay"

    .line 244
    .line 245
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    move/from16 v32, v0

    .line 250
    .line 251
    const-string v0, "content_uri_triggers"

    .line 252
    .line 253
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 254
    .line 255
    .line 256
    move-result v0

    .line 257
    move/from16 v33, v0

    .line 258
    .line 259
    new-instance v0, Ljava/util/ArrayList;

    .line 260
    .line 261
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 262
    .line 263
    .line 264
    :goto_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 265
    .line 266
    .line 267
    move-result v34

    .line 268
    if-eqz v34, :cond_9

    .line 269
    .line 270
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v36

    .line 274
    move/from16 v34, v14

    .line 275
    .line 276
    move/from16 v69, v15

    .line 277
    .line 278
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 279
    .line 280
    .line 281
    move-result-wide v14

    .line 282
    long-to-int v14, v14

    .line 283
    invoke-static {v14}, Ljp/z0;->g(I)Leb/h0;

    .line 284
    .line 285
    .line 286
    move-result-object v37

    .line 287
    invoke-interface {v1, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v38

    .line 291
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v39

    .line 295
    invoke-interface {v1, v6}, Lua/c;->getBlob(I)[B

    .line 296
    .line 297
    .line 298
    move-result-object v14

    .line 299
    sget-object v15, Leb/h;->b:Leb/h;

    .line 300
    .line 301
    invoke-static {v14}, Lkp/b6;->b([B)Leb/h;

    .line 302
    .line 303
    .line 304
    move-result-object v40

    .line 305
    invoke-interface {v1, v7}, Lua/c;->getBlob(I)[B

    .line 306
    .line 307
    .line 308
    move-result-object v14

    .line 309
    invoke-static {v14}, Lkp/b6;->b([B)Leb/h;

    .line 310
    .line 311
    .line 312
    move-result-object v41

    .line 313
    invoke-interface {v1, v8}, Lua/c;->getLong(I)J

    .line 314
    .line 315
    .line 316
    move-result-wide v42

    .line 317
    invoke-interface {v1, v9}, Lua/c;->getLong(I)J

    .line 318
    .line 319
    .line 320
    move-result-wide v44

    .line 321
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 322
    .line 323
    .line 324
    move-result-wide v46

    .line 325
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 326
    .line 327
    .line 328
    move-result-wide v14

    .line 329
    long-to-int v14, v14

    .line 330
    move v15, v2

    .line 331
    move/from16 v70, v3

    .line 332
    .line 333
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 334
    .line 335
    .line 336
    move-result-wide v2

    .line 337
    long-to-int v2, v2

    .line 338
    invoke-static {v2}, Ljp/z0;->d(I)Leb/a;

    .line 339
    .line 340
    .line 341
    move-result-object v50

    .line 342
    invoke-interface {v1, v13}, Lua/c;->getLong(I)J

    .line 343
    .line 344
    .line 345
    move-result-wide v51

    .line 346
    move/from16 v2, v34

    .line 347
    .line 348
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 349
    .line 350
    .line 351
    move-result-wide v53

    .line 352
    move/from16 v3, v69

    .line 353
    .line 354
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 355
    .line 356
    .line 357
    move-result-wide v55

    .line 358
    move/from16 v34, v2

    .line 359
    .line 360
    move/from16 v2, p1

    .line 361
    .line 362
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 363
    .line 364
    .line 365
    move-result-wide v57

    .line 366
    move/from16 p1, v2

    .line 367
    .line 368
    move/from16 v69, v3

    .line 369
    .line 370
    move/from16 v2, v16

    .line 371
    .line 372
    move/from16 v16, v4

    .line 373
    .line 374
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 375
    .line 376
    .line 377
    move-result-wide v3

    .line 378
    long-to-int v3, v3

    .line 379
    if-eqz v3, :cond_0

    .line 380
    .line 381
    const/16 v59, 0x1

    .line 382
    .line 383
    :goto_1
    move/from16 v3, v17

    .line 384
    .line 385
    move/from16 v17, v5

    .line 386
    .line 387
    goto :goto_2

    .line 388
    :cond_0
    const/16 v59, 0x0

    .line 389
    .line 390
    goto :goto_1

    .line 391
    :goto_2
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 392
    .line 393
    .line 394
    move-result-wide v4

    .line 395
    long-to-int v4, v4

    .line 396
    invoke-static {v4}, Ljp/z0;->f(I)Leb/e0;

    .line 397
    .line 398
    .line 399
    move-result-object v60

    .line 400
    move v5, v2

    .line 401
    move/from16 v4, v18

    .line 402
    .line 403
    move/from16 v18, v3

    .line 404
    .line 405
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 406
    .line 407
    .line 408
    move-result-wide v2

    .line 409
    long-to-int v2, v2

    .line 410
    move/from16 v71, v5

    .line 411
    .line 412
    move/from16 v3, v19

    .line 413
    .line 414
    move/from16 v19, v4

    .line 415
    .line 416
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 417
    .line 418
    .line 419
    move-result-wide v4

    .line 420
    long-to-int v4, v4

    .line 421
    move/from16 v5, v20

    .line 422
    .line 423
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 424
    .line 425
    .line 426
    move-result-wide v63

    .line 427
    move/from16 v61, v2

    .line 428
    .line 429
    move/from16 v20, v3

    .line 430
    .line 431
    move/from16 v62, v4

    .line 432
    .line 433
    move/from16 v2, v21

    .line 434
    .line 435
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 436
    .line 437
    .line 438
    move-result-wide v3

    .line 439
    long-to-int v3, v3

    .line 440
    move/from16 v21, v2

    .line 441
    .line 442
    move/from16 v65, v3

    .line 443
    .line 444
    move/from16 v4, v22

    .line 445
    .line 446
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 447
    .line 448
    .line 449
    move-result-wide v2

    .line 450
    long-to-int v2, v2

    .line 451
    move/from16 v3, v23

    .line 452
    .line 453
    invoke-interface {v1, v3}, Lua/c;->isNull(I)Z

    .line 454
    .line 455
    .line 456
    move-result v22

    .line 457
    const/16 v23, 0x0

    .line 458
    .line 459
    if-eqz v22, :cond_1

    .line 460
    .line 461
    move-object/from16 v67, v23

    .line 462
    .line 463
    :goto_3
    move/from16 v66, v2

    .line 464
    .line 465
    move/from16 v2, v24

    .line 466
    .line 467
    goto :goto_4

    .line 468
    :cond_1
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 469
    .line 470
    .line 471
    move-result-object v22

    .line 472
    move-object/from16 v67, v22

    .line 473
    .line 474
    goto :goto_3

    .line 475
    :goto_4
    invoke-interface {v1, v2}, Lua/c;->isNull(I)Z

    .line 476
    .line 477
    .line 478
    move-result v22

    .line 479
    if-eqz v22, :cond_2

    .line 480
    .line 481
    move/from16 v24, v3

    .line 482
    .line 483
    move/from16 v22, v4

    .line 484
    .line 485
    move-object/from16 v3, v23

    .line 486
    .line 487
    goto :goto_5

    .line 488
    :cond_2
    move/from16 v24, v3

    .line 489
    .line 490
    move/from16 v22, v4

    .line 491
    .line 492
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 493
    .line 494
    .line 495
    move-result-wide v3

    .line 496
    long-to-int v3, v3

    .line 497
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 498
    .line 499
    .line 500
    move-result-object v3

    .line 501
    :goto_5
    if-eqz v3, :cond_4

    .line 502
    .line 503
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 504
    .line 505
    .line 506
    move-result v3

    .line 507
    if-eqz v3, :cond_3

    .line 508
    .line 509
    const/4 v3, 0x1

    .line 510
    goto :goto_6

    .line 511
    :cond_3
    const/4 v3, 0x0

    .line 512
    :goto_6
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 513
    .line 514
    .line 515
    move-result-object v23

    .line 516
    :cond_4
    move-object/from16 v68, v23

    .line 517
    .line 518
    move/from16 v3, v25

    .line 519
    .line 520
    move/from16 v23, v5

    .line 521
    .line 522
    goto :goto_7

    .line 523
    :catchall_0
    move-exception v0

    .line 524
    goto/16 :goto_10

    .line 525
    .line 526
    :goto_7
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 527
    .line 528
    .line 529
    move-result-wide v4

    .line 530
    long-to-int v4, v4

    .line 531
    invoke-static {v4}, Ljp/z0;->e(I)Leb/x;

    .line 532
    .line 533
    .line 534
    move-result-object v74

    .line 535
    move/from16 v4, v26

    .line 536
    .line 537
    invoke-interface {v1, v4}, Lua/c;->getBlob(I)[B

    .line 538
    .line 539
    .line 540
    move-result-object v5

    .line 541
    invoke-static {v5}, Ljp/z0;->m([B)Lnb/d;

    .line 542
    .line 543
    .line 544
    move-result-object v73

    .line 545
    move/from16 v25, v2

    .line 546
    .line 547
    move/from16 v26, v3

    .line 548
    .line 549
    move/from16 v5, v27

    .line 550
    .line 551
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 552
    .line 553
    .line 554
    move-result-wide v2

    .line 555
    long-to-int v2, v2

    .line 556
    if-eqz v2, :cond_5

    .line 557
    .line 558
    const/16 v75, 0x1

    .line 559
    .line 560
    :goto_8
    move/from16 v27, v4

    .line 561
    .line 562
    move/from16 v2, v28

    .line 563
    .line 564
    goto :goto_9

    .line 565
    :cond_5
    const/16 v75, 0x0

    .line 566
    .line 567
    goto :goto_8

    .line 568
    :goto_9
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 569
    .line 570
    .line 571
    move-result-wide v3

    .line 572
    long-to-int v3, v3

    .line 573
    if-eqz v3, :cond_6

    .line 574
    .line 575
    const/16 v76, 0x1

    .line 576
    .line 577
    :goto_a
    move/from16 v28, v5

    .line 578
    .line 579
    move/from16 v3, v29

    .line 580
    .line 581
    goto :goto_b

    .line 582
    :cond_6
    const/16 v76, 0x0

    .line 583
    .line 584
    goto :goto_a

    .line 585
    :goto_b
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 586
    .line 587
    .line 588
    move-result-wide v4

    .line 589
    long-to-int v4, v4

    .line 590
    if-eqz v4, :cond_7

    .line 591
    .line 592
    const/16 v77, 0x1

    .line 593
    .line 594
    :goto_c
    move v5, v2

    .line 595
    move/from16 v29, v3

    .line 596
    .line 597
    move/from16 v4, v30

    .line 598
    .line 599
    goto :goto_d

    .line 600
    :cond_7
    const/16 v77, 0x0

    .line 601
    .line 602
    goto :goto_c

    .line 603
    :goto_d
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 604
    .line 605
    .line 606
    move-result-wide v2

    .line 607
    long-to-int v2, v2

    .line 608
    if-eqz v2, :cond_8

    .line 609
    .line 610
    const/16 v78, 0x1

    .line 611
    .line 612
    :goto_e
    move/from16 v2, v31

    .line 613
    .line 614
    goto :goto_f

    .line 615
    :cond_8
    const/16 v78, 0x0

    .line 616
    .line 617
    goto :goto_e

    .line 618
    :goto_f
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 619
    .line 620
    .line 621
    move-result-wide v79

    .line 622
    move/from16 v3, v32

    .line 623
    .line 624
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 625
    .line 626
    .line 627
    move-result-wide v81

    .line 628
    move/from16 v31, v2

    .line 629
    .line 630
    move/from16 v2, v33

    .line 631
    .line 632
    invoke-interface {v1, v2}, Lua/c;->getBlob(I)[B

    .line 633
    .line 634
    .line 635
    move-result-object v30

    .line 636
    invoke-static/range {v30 .. v30}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 637
    .line 638
    .line 639
    move-result-object v83

    .line 640
    new-instance v48, Leb/e;

    .line 641
    .line 642
    move-object/from16 v72, v48

    .line 643
    .line 644
    invoke-direct/range {v72 .. v83}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 645
    .line 646
    .line 647
    move-object/from16 v48, v72

    .line 648
    .line 649
    new-instance v35, Lmb/o;

    .line 650
    .line 651
    move/from16 v49, v14

    .line 652
    .line 653
    invoke-direct/range {v35 .. v68}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 654
    .line 655
    .line 656
    move-object/from16 v14, v35

    .line 657
    .line 658
    invoke-virtual {v0, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 659
    .line 660
    .line 661
    move/from16 v14, v28

    .line 662
    .line 663
    move/from16 v28, v5

    .line 664
    .line 665
    move/from16 v5, v17

    .line 666
    .line 667
    move/from16 v17, v18

    .line 668
    .line 669
    move/from16 v18, v19

    .line 670
    .line 671
    move/from16 v19, v20

    .line 672
    .line 673
    move/from16 v20, v23

    .line 674
    .line 675
    move/from16 v23, v24

    .line 676
    .line 677
    move/from16 v24, v25

    .line 678
    .line 679
    move/from16 v25, v26

    .line 680
    .line 681
    move/from16 v26, v27

    .line 682
    .line 683
    move/from16 v27, v14

    .line 684
    .line 685
    move/from16 v33, v2

    .line 686
    .line 687
    move/from16 v32, v3

    .line 688
    .line 689
    move/from16 v30, v4

    .line 690
    .line 691
    move v2, v15

    .line 692
    move/from16 v4, v16

    .line 693
    .line 694
    move/from16 v14, v34

    .line 695
    .line 696
    move/from16 v15, v69

    .line 697
    .line 698
    move/from16 v3, v70

    .line 699
    .line 700
    move/from16 v16, v71

    .line 701
    .line 702
    goto/16 :goto_0

    .line 703
    .line 704
    :cond_9
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 705
    .line 706
    .line 707
    return-object v0

    .line 708
    :goto_10
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 709
    .line 710
    .line 711
    throw v0
.end method

.method private final c(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "Loading available payment providers"

    .line 9
    .line 10
    return-object p0
.end method

.method private final d(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "Init payment"

    .line 9
    .line 10
    return-object p0
.end method

.method private final e(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "onCtaClick"

    .line 9
    .line 10
    return-object p0
.end method

.method private final f(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "onCancel"

    .line 9
    .line 10
    return-object p0
.end method

.method private final g(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lhi/a;

    .line 2
    .line 3
    const-string p0, "$this$sdkViewModel"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Lme/f;

    .line 9
    .line 10
    invoke-direct {p0}, Lme/f;-><init>()V

    .line 11
    .line 12
    .line 13
    return-object p0
.end method

.method private final h(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "Failed to load payment overview screen"

    .line 9
    .line 10
    return-object p0
.end method

.method private final i(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "Loading payment data from backend"

    .line 9
    .line 10
    return-object p0
.end method

.method private final j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lgi/c;

    .line 2
    .line 3
    const-string p0, "$this$log"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string p0, "Receiving payment data from Edit screen"

    .line 9
    .line 10
    return-object p0
.end method

.method private final k(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lz9/y;

    .line 2
    .line 3
    const-string p0, "$this$navigator"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    const/4 v0, 0x6

    .line 10
    const-string v1, "/billing_address"

    .line 11
    .line 12
    invoke-static {p1, v1, p0, v0}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 86

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm40/e;->d:I

    .line 4
    .line 5
    const-string v2, "run_in_foreground"

    .line 6
    .line 7
    const-string v3, "schedule_requested_at"

    .line 8
    .line 9
    const-string v4, "minimum_retention_duration"

    .line 10
    .line 11
    const-string v5, "last_enqueue_time"

    .line 12
    .line 13
    const-string v6, "backoff_delay_duration"

    .line 14
    .line 15
    const-string v7, "backoff_policy"

    .line 16
    .line 17
    const-string v8, "run_attempt_count"

    .line 18
    .line 19
    const-string v9, "flex_duration"

    .line 20
    .line 21
    const-string v10, "interval_duration"

    .line 22
    .line 23
    const-string v11, "initial_delay"

    .line 24
    .line 25
    const-string v12, "output"

    .line 26
    .line 27
    const-string v13, "input"

    .line 28
    .line 29
    const-string v14, "input_merger_class_name"

    .line 30
    .line 31
    const-string v15, "worker_class_name"

    .line 32
    .line 33
    const-string v0, "state"

    .line 34
    .line 35
    move/from16 v16, v1

    .line 36
    .line 37
    const-string v1, "id"

    .line 38
    .line 39
    const/16 v17, 0x1

    .line 40
    .line 41
    sget-object v18, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    const/16 v19, 0x0

    .line 44
    .line 45
    move-object/from16 v20, v2

    .line 46
    .line 47
    const-string v2, "_connection"

    .line 48
    .line 49
    move-object/from16 v22, v3

    .line 50
    .line 51
    const-string v3, "$this$request"

    .line 52
    .line 53
    packed-switch v16, :pswitch_data_0

    .line 54
    .line 55
    .line 56
    move-object/from16 v0, p1

    .line 57
    .line 58
    check-cast v0, Lz9/c0;

    .line 59
    .line 60
    const-string v1, "$this$navigate"

    .line 61
    .line 62
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lmg/i;

    .line 66
    .line 67
    const/4 v2, 0x7

    .line 68
    invoke-direct {v1, v2}, Lmg/i;-><init>(I)V

    .line 69
    .line 70
    .line 71
    const-string v2, "/tariff_confirmation"

    .line 72
    .line 73
    invoke-virtual {v0, v2, v1}, Lz9/c0;->b(Ljava/lang/String;Lay0/k;)V

    .line 74
    .line 75
    .line 76
    return-object v18

    .line 77
    :pswitch_0
    invoke-direct/range {p0 .. p1}, Lm40/e;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    return-object v0

    .line 82
    :pswitch_1
    invoke-direct/range {p0 .. p1}, Lm40/e;->j(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    return-object v0

    .line 87
    :pswitch_2
    invoke-direct/range {p0 .. p1}, Lm40/e;->i(Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    return-object v0

    .line 92
    :pswitch_3
    invoke-direct/range {p0 .. p1}, Lm40/e;->h(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    return-object v0

    .line 97
    :pswitch_4
    invoke-direct/range {p0 .. p1}, Lm40/e;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    return-object v0

    .line 102
    :pswitch_5
    invoke-direct/range {p0 .. p1}, Lm40/e;->f(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    return-object v0

    .line 107
    :pswitch_6
    invoke-direct/range {p0 .. p1}, Lm40/e;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    return-object v0

    .line 112
    :pswitch_7
    invoke-direct/range {p0 .. p1}, Lm40/e;->d(Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    return-object v0

    .line 117
    :pswitch_8
    invoke-direct/range {p0 .. p1}, Lm40/e;->c(Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    return-object v0

    .line 122
    :pswitch_9
    move-object/from16 v0, p1

    .line 123
    .line 124
    check-cast v0, Lgi/c;

    .line 125
    .line 126
    const-string v1, "$this$log"

    .line 127
    .line 128
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    const-string v0, "Complete payment"

    .line 132
    .line 133
    return-object v0

    .line 134
    :pswitch_a
    move-object/from16 v0, p1

    .line 135
    .line 136
    check-cast v0, Lua/a;

    .line 137
    .line 138
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    const-string v1, "UPDATE workspec SET schedule_requested_at=-1 WHERE state NOT IN (2, 3, 5)"

    .line 142
    .line 143
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    :try_start_0
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 148
    .line 149
    .line 150
    invoke-static {v0}, Ljp/ze;->b(Lua/a;)I

    .line 151
    .line 152
    .line 153
    move-result v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 154
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 155
    .line 156
    .line 157
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    return-object v0

    .line 162
    :catchall_0
    move-exception v0

    .line 163
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 164
    .line 165
    .line 166
    throw v0

    .line 167
    :pswitch_b
    invoke-direct/range {p0 .. p1}, Lm40/e;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    return-object v0

    .line 172
    :pswitch_c
    invoke-direct/range {p0 .. p1}, Lm40/e;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v0

    .line 176
    return-object v0

    .line 177
    :pswitch_d
    move-object/from16 v0, p1

    .line 178
    .line 179
    check-cast v0, Lua/a;

    .line 180
    .line 181
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    const-string v1, "Select COUNT(*) FROM workspec WHERE LENGTH(content_uri_triggers)<>0 AND state NOT IN (2, 3, 5)"

    .line 185
    .line 186
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    :try_start_1
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 191
    .line 192
    .line 193
    move-result v0

    .line 194
    if-eqz v0, :cond_0

    .line 195
    .line 196
    const/4 v0, 0x0

    .line 197
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 198
    .line 199
    .line 200
    move-result-wide v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 201
    long-to-int v2, v2

    .line 202
    goto :goto_0

    .line 203
    :catchall_1
    move-exception v0

    .line 204
    goto :goto_1

    .line 205
    :cond_0
    const/4 v2, 0x0

    .line 206
    :goto_0
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 207
    .line 208
    .line 209
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    return-object v0

    .line 214
    :goto_1
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 215
    .line 216
    .line 217
    throw v0

    .line 218
    :pswitch_e
    move-object/from16 v3, p1

    .line 219
    .line 220
    check-cast v3, Lua/a;

    .line 221
    .line 222
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    const-string v2, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 AND LENGTH(content_uri_triggers)<>0 ORDER BY last_enqueue_time"

    .line 226
    .line 227
    invoke-interface {v3, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 228
    .line 229
    .line 230
    move-result-object v2

    .line 231
    :try_start_2
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 232
    .line 233
    .line 234
    move-result v1

    .line 235
    invoke-static {v2, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 236
    .line 237
    .line 238
    move-result v0

    .line 239
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 240
    .line 241
    .line 242
    move-result v3

    .line 243
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 244
    .line 245
    .line 246
    move-result v14

    .line 247
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 248
    .line 249
    .line 250
    move-result v13

    .line 251
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 252
    .line 253
    .line 254
    move-result v12

    .line 255
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 256
    .line 257
    .line 258
    move-result v11

    .line 259
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 260
    .line 261
    .line 262
    move-result v10

    .line 263
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 264
    .line 265
    .line 266
    move-result v9

    .line 267
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 268
    .line 269
    .line 270
    move-result v8

    .line 271
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 272
    .line 273
    .line 274
    move-result v7

    .line 275
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 276
    .line 277
    .line 278
    move-result v6

    .line 279
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 280
    .line 281
    .line 282
    move-result v5

    .line 283
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 284
    .line 285
    .line 286
    move-result v4

    .line 287
    move-object/from16 v15, v22

    .line 288
    .line 289
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 290
    .line 291
    .line 292
    move-result v15

    .line 293
    move/from16 p0, v15

    .line 294
    .line 295
    move-object/from16 v15, v20

    .line 296
    .line 297
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 298
    .line 299
    .line 300
    move-result v15

    .line 301
    move/from16 p1, v15

    .line 302
    .line 303
    const-string v15, "out_of_quota_policy"

    .line 304
    .line 305
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 306
    .line 307
    .line 308
    move-result v15

    .line 309
    move/from16 v16, v15

    .line 310
    .line 311
    const-string v15, "period_count"

    .line 312
    .line 313
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 314
    .line 315
    .line 316
    move-result v15

    .line 317
    move/from16 v18, v15

    .line 318
    .line 319
    const-string v15, "generation"

    .line 320
    .line 321
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 322
    .line 323
    .line 324
    move-result v15

    .line 325
    move/from16 v20, v15

    .line 326
    .line 327
    const-string v15, "next_schedule_time_override"

    .line 328
    .line 329
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 330
    .line 331
    .line 332
    move-result v15

    .line 333
    move/from16 v22, v15

    .line 334
    .line 335
    const-string v15, "next_schedule_time_override_generation"

    .line 336
    .line 337
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 338
    .line 339
    .line 340
    move-result v15

    .line 341
    move/from16 v23, v15

    .line 342
    .line 343
    const-string v15, "stop_reason"

    .line 344
    .line 345
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 346
    .line 347
    .line 348
    move-result v15

    .line 349
    move/from16 v24, v15

    .line 350
    .line 351
    const-string v15, "trace_tag"

    .line 352
    .line 353
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 354
    .line 355
    .line 356
    move-result v15

    .line 357
    move/from16 v25, v15

    .line 358
    .line 359
    const-string v15, "backoff_on_system_interruptions"

    .line 360
    .line 361
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 362
    .line 363
    .line 364
    move-result v15

    .line 365
    move/from16 v26, v15

    .line 366
    .line 367
    const-string v15, "required_network_type"

    .line 368
    .line 369
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 370
    .line 371
    .line 372
    move-result v15

    .line 373
    move/from16 v27, v15

    .line 374
    .line 375
    const-string v15, "required_network_request"

    .line 376
    .line 377
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 378
    .line 379
    .line 380
    move-result v15

    .line 381
    move/from16 v28, v15

    .line 382
    .line 383
    const-string v15, "requires_charging"

    .line 384
    .line 385
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 386
    .line 387
    .line 388
    move-result v15

    .line 389
    move/from16 v29, v15

    .line 390
    .line 391
    const-string v15, "requires_device_idle"

    .line 392
    .line 393
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 394
    .line 395
    .line 396
    move-result v15

    .line 397
    move/from16 v30, v15

    .line 398
    .line 399
    const-string v15, "requires_battery_not_low"

    .line 400
    .line 401
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 402
    .line 403
    .line 404
    move-result v15

    .line 405
    move/from16 v31, v15

    .line 406
    .line 407
    const-string v15, "requires_storage_not_low"

    .line 408
    .line 409
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 410
    .line 411
    .line 412
    move-result v15

    .line 413
    move/from16 v32, v15

    .line 414
    .line 415
    const-string v15, "trigger_content_update_delay"

    .line 416
    .line 417
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 418
    .line 419
    .line 420
    move-result v15

    .line 421
    move/from16 v33, v15

    .line 422
    .line 423
    const-string v15, "trigger_max_content_delay"

    .line 424
    .line 425
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 426
    .line 427
    .line 428
    move-result v15

    .line 429
    move/from16 v34, v15

    .line 430
    .line 431
    const-string v15, "content_uri_triggers"

    .line 432
    .line 433
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 434
    .line 435
    .line 436
    move-result v15

    .line 437
    move/from16 v35, v15

    .line 438
    .line 439
    new-instance v15, Ljava/util/ArrayList;

    .line 440
    .line 441
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 442
    .line 443
    .line 444
    :goto_2
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 445
    .line 446
    .line 447
    move-result v36

    .line 448
    if-eqz v36, :cond_a

    .line 449
    .line 450
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 451
    .line 452
    .line 453
    move-result-object v38

    .line 454
    move/from16 v71, v4

    .line 455
    .line 456
    move/from16 v36, v5

    .line 457
    .line 458
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 459
    .line 460
    .line 461
    move-result-wide v4

    .line 462
    long-to-int v4, v4

    .line 463
    invoke-static {v4}, Ljp/z0;->g(I)Leb/h0;

    .line 464
    .line 465
    .line 466
    move-result-object v39

    .line 467
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 468
    .line 469
    .line 470
    move-result-object v40

    .line 471
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 472
    .line 473
    .line 474
    move-result-object v41

    .line 475
    invoke-interface {v2, v13}, Lua/c;->getBlob(I)[B

    .line 476
    .line 477
    .line 478
    move-result-object v4

    .line 479
    sget-object v5, Leb/h;->b:Leb/h;

    .line 480
    .line 481
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 482
    .line 483
    .line 484
    move-result-object v42

    .line 485
    invoke-interface {v2, v12}, Lua/c;->getBlob(I)[B

    .line 486
    .line 487
    .line 488
    move-result-object v4

    .line 489
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 490
    .line 491
    .line 492
    move-result-object v43

    .line 493
    invoke-interface {v2, v11}, Lua/c;->getLong(I)J

    .line 494
    .line 495
    .line 496
    move-result-wide v44

    .line 497
    invoke-interface {v2, v10}, Lua/c;->getLong(I)J

    .line 498
    .line 499
    .line 500
    move-result-wide v46

    .line 501
    invoke-interface {v2, v9}, Lua/c;->getLong(I)J

    .line 502
    .line 503
    .line 504
    move-result-wide v48

    .line 505
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 506
    .line 507
    .line 508
    move-result-wide v4

    .line 509
    long-to-int v4, v4

    .line 510
    move/from16 v73, v0

    .line 511
    .line 512
    move/from16 v72, v1

    .line 513
    .line 514
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 515
    .line 516
    .line 517
    move-result-wide v0

    .line 518
    long-to-int v0, v0

    .line 519
    invoke-static {v0}, Ljp/z0;->d(I)Leb/a;

    .line 520
    .line 521
    .line 522
    move-result-object v52

    .line 523
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 524
    .line 525
    .line 526
    move-result-wide v53

    .line 527
    move/from16 v0, v36

    .line 528
    .line 529
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 530
    .line 531
    .line 532
    move-result-wide v55

    .line 533
    move/from16 v1, v71

    .line 534
    .line 535
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 536
    .line 537
    .line 538
    move-result-wide v57

    .line 539
    move/from16 v5, p0

    .line 540
    .line 541
    invoke-interface {v2, v5}, Lua/c;->getLong(I)J

    .line 542
    .line 543
    .line 544
    move-result-wide v59

    .line 545
    move/from16 v36, v0

    .line 546
    .line 547
    move/from16 p0, v3

    .line 548
    .line 549
    move/from16 v51, v4

    .line 550
    .line 551
    move/from16 v0, p1

    .line 552
    .line 553
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 554
    .line 555
    .line 556
    move-result-wide v3

    .line 557
    long-to-int v3, v3

    .line 558
    if-eqz v3, :cond_1

    .line 559
    .line 560
    move/from16 v61, v17

    .line 561
    .line 562
    :goto_3
    move/from16 p1, v0

    .line 563
    .line 564
    move/from16 v71, v1

    .line 565
    .line 566
    move/from16 v3, v16

    .line 567
    .line 568
    goto :goto_4

    .line 569
    :cond_1
    const/16 v61, 0x0

    .line 570
    .line 571
    goto :goto_3

    .line 572
    :goto_4
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 573
    .line 574
    .line 575
    move-result-wide v0

    .line 576
    long-to-int v0, v0

    .line 577
    invoke-static {v0}, Ljp/z0;->f(I)Leb/e0;

    .line 578
    .line 579
    .line 580
    move-result-object v62

    .line 581
    move/from16 v16, v3

    .line 582
    .line 583
    move/from16 v0, v18

    .line 584
    .line 585
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 586
    .line 587
    .line 588
    move-result-wide v3

    .line 589
    long-to-int v1, v3

    .line 590
    move/from16 v18, v0

    .line 591
    .line 592
    move/from16 v63, v1

    .line 593
    .line 594
    move/from16 v3, v20

    .line 595
    .line 596
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 597
    .line 598
    .line 599
    move-result-wide v0

    .line 600
    long-to-int v0, v0

    .line 601
    move/from16 v1, v22

    .line 602
    .line 603
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 604
    .line 605
    .line 606
    move-result-wide v65

    .line 607
    move/from16 v64, v0

    .line 608
    .line 609
    move/from16 v4, v23

    .line 610
    .line 611
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 612
    .line 613
    .line 614
    move-result-wide v0

    .line 615
    long-to-int v0, v0

    .line 616
    move/from16 v20, v3

    .line 617
    .line 618
    move/from16 v23, v4

    .line 619
    .line 620
    move/from16 v1, v24

    .line 621
    .line 622
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 623
    .line 624
    .line 625
    move-result-wide v3

    .line 626
    long-to-int v3, v3

    .line 627
    move/from16 v4, v25

    .line 628
    .line 629
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 630
    .line 631
    .line 632
    move-result v24

    .line 633
    if-eqz v24, :cond_2

    .line 634
    .line 635
    move-object/from16 v69, v19

    .line 636
    .line 637
    :goto_5
    move/from16 v67, v0

    .line 638
    .line 639
    move/from16 v0, v26

    .line 640
    .line 641
    goto :goto_6

    .line 642
    :cond_2
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 643
    .line 644
    .line 645
    move-result-object v24

    .line 646
    move-object/from16 v69, v24

    .line 647
    .line 648
    goto :goto_5

    .line 649
    :goto_6
    invoke-interface {v2, v0}, Lua/c;->isNull(I)Z

    .line 650
    .line 651
    .line 652
    move-result v24

    .line 653
    if-eqz v24, :cond_3

    .line 654
    .line 655
    move/from16 v68, v3

    .line 656
    .line 657
    move/from16 v25, v4

    .line 658
    .line 659
    move-object/from16 v3, v19

    .line 660
    .line 661
    goto :goto_7

    .line 662
    :cond_3
    move/from16 v68, v3

    .line 663
    .line 664
    move/from16 v25, v4

    .line 665
    .line 666
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 667
    .line 668
    .line 669
    move-result-wide v3

    .line 670
    long-to-int v3, v3

    .line 671
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 672
    .line 673
    .line 674
    move-result-object v3

    .line 675
    :goto_7
    if-eqz v3, :cond_5

    .line 676
    .line 677
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 678
    .line 679
    .line 680
    move-result v3

    .line 681
    if-eqz v3, :cond_4

    .line 682
    .line 683
    move/from16 v3, v17

    .line 684
    .line 685
    goto :goto_8

    .line 686
    :cond_4
    const/4 v3, 0x0

    .line 687
    :goto_8
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 688
    .line 689
    .line 690
    move-result-object v3

    .line 691
    move-object/from16 v70, v3

    .line 692
    .line 693
    :goto_9
    move/from16 v26, v0

    .line 694
    .line 695
    move/from16 v24, v1

    .line 696
    .line 697
    move/from16 v3, v27

    .line 698
    .line 699
    goto :goto_a

    .line 700
    :catchall_2
    move-exception v0

    .line 701
    goto/16 :goto_13

    .line 702
    .line 703
    :cond_5
    move-object/from16 v70, v19

    .line 704
    .line 705
    goto :goto_9

    .line 706
    :goto_a
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 707
    .line 708
    .line 709
    move-result-wide v0

    .line 710
    long-to-int v0, v0

    .line 711
    invoke-static {v0}, Ljp/z0;->e(I)Leb/x;

    .line 712
    .line 713
    .line 714
    move-result-object v76

    .line 715
    move/from16 v0, v28

    .line 716
    .line 717
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    invoke-static {v1}, Ljp/z0;->m([B)Lnb/d;

    .line 722
    .line 723
    .line 724
    move-result-object v75

    .line 725
    move/from16 v27, v3

    .line 726
    .line 727
    move/from16 v1, v29

    .line 728
    .line 729
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 730
    .line 731
    .line 732
    move-result-wide v3

    .line 733
    long-to-int v3, v3

    .line 734
    if-eqz v3, :cond_6

    .line 735
    .line 736
    move/from16 v77, v17

    .line 737
    .line 738
    :goto_b
    move/from16 v28, v0

    .line 739
    .line 740
    move/from16 v29, v1

    .line 741
    .line 742
    move/from16 v3, v30

    .line 743
    .line 744
    goto :goto_c

    .line 745
    :cond_6
    const/16 v77, 0x0

    .line 746
    .line 747
    goto :goto_b

    .line 748
    :goto_c
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 749
    .line 750
    .line 751
    move-result-wide v0

    .line 752
    long-to-int v0, v0

    .line 753
    if-eqz v0, :cond_7

    .line 754
    .line 755
    move/from16 v78, v17

    .line 756
    .line 757
    :goto_d
    move/from16 v30, v3

    .line 758
    .line 759
    move/from16 v0, v31

    .line 760
    .line 761
    goto :goto_e

    .line 762
    :cond_7
    const/16 v78, 0x0

    .line 763
    .line 764
    goto :goto_d

    .line 765
    :goto_e
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 766
    .line 767
    .line 768
    move-result-wide v3

    .line 769
    long-to-int v1, v3

    .line 770
    if-eqz v1, :cond_8

    .line 771
    .line 772
    move/from16 v79, v17

    .line 773
    .line 774
    :goto_f
    move/from16 v1, v32

    .line 775
    .line 776
    goto :goto_10

    .line 777
    :cond_8
    const/16 v79, 0x0

    .line 778
    .line 779
    goto :goto_f

    .line 780
    :goto_10
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 781
    .line 782
    .line 783
    move-result-wide v3

    .line 784
    long-to-int v3, v3

    .line 785
    if-eqz v3, :cond_9

    .line 786
    .line 787
    move/from16 v80, v17

    .line 788
    .line 789
    :goto_11
    move/from16 v3, v33

    .line 790
    .line 791
    goto :goto_12

    .line 792
    :cond_9
    const/16 v80, 0x0

    .line 793
    .line 794
    goto :goto_11

    .line 795
    :goto_12
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 796
    .line 797
    .line 798
    move-result-wide v81

    .line 799
    move/from16 v4, v34

    .line 800
    .line 801
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 802
    .line 803
    .line 804
    move-result-wide v83

    .line 805
    move/from16 v31, v0

    .line 806
    .line 807
    move/from16 v0, v35

    .line 808
    .line 809
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 810
    .line 811
    .line 812
    move-result-object v32

    .line 813
    invoke-static/range {v32 .. v32}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 814
    .line 815
    .line 816
    move-result-object v85

    .line 817
    new-instance v50, Leb/e;

    .line 818
    .line 819
    move-object/from16 v74, v50

    .line 820
    .line 821
    invoke-direct/range {v74 .. v85}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 822
    .line 823
    .line 824
    move-object/from16 v50, v74

    .line 825
    .line 826
    new-instance v37, Lmb/o;

    .line 827
    .line 828
    invoke-direct/range {v37 .. v70}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 829
    .line 830
    .line 831
    move/from16 v35, v0

    .line 832
    .line 833
    move-object/from16 v0, v37

    .line 834
    .line 835
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 836
    .line 837
    .line 838
    move/from16 v32, v1

    .line 839
    .line 840
    move/from16 v33, v3

    .line 841
    .line 842
    move/from16 v34, v4

    .line 843
    .line 844
    move/from16 v4, v71

    .line 845
    .line 846
    move/from16 v1, v72

    .line 847
    .line 848
    move/from16 v0, v73

    .line 849
    .line 850
    move/from16 v3, p0

    .line 851
    .line 852
    move/from16 p0, v5

    .line 853
    .line 854
    move/from16 v5, v36

    .line 855
    .line 856
    goto/16 :goto_2

    .line 857
    .line 858
    :cond_a
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 859
    .line 860
    .line 861
    return-object v15

    .line 862
    :goto_13
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 863
    .line 864
    .line 865
    throw v0

    .line 866
    :pswitch_f
    move-object/from16 v3, p1

    .line 867
    .line 868
    check-cast v3, Lua/a;

    .line 869
    .line 870
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 871
    .line 872
    .line 873
    const-string v2, "SELECT * FROM workspec WHERE state=1"

    .line 874
    .line 875
    invoke-interface {v3, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 876
    .line 877
    .line 878
    move-result-object v2

    .line 879
    :try_start_3
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 880
    .line 881
    .line 882
    move-result v1

    .line 883
    invoke-static {v2, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 884
    .line 885
    .line 886
    move-result v0

    .line 887
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 888
    .line 889
    .line 890
    move-result v3

    .line 891
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 892
    .line 893
    .line 894
    move-result v14

    .line 895
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 896
    .line 897
    .line 898
    move-result v13

    .line 899
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 900
    .line 901
    .line 902
    move-result v12

    .line 903
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 904
    .line 905
    .line 906
    move-result v11

    .line 907
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 908
    .line 909
    .line 910
    move-result v10

    .line 911
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 912
    .line 913
    .line 914
    move-result v9

    .line 915
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 916
    .line 917
    .line 918
    move-result v8

    .line 919
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 920
    .line 921
    .line 922
    move-result v7

    .line 923
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 924
    .line 925
    .line 926
    move-result v6

    .line 927
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 928
    .line 929
    .line 930
    move-result v5

    .line 931
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 932
    .line 933
    .line 934
    move-result v4

    .line 935
    move-object/from16 v15, v22

    .line 936
    .line 937
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 938
    .line 939
    .line 940
    move-result v15

    .line 941
    move/from16 p0, v15

    .line 942
    .line 943
    move-object/from16 v15, v20

    .line 944
    .line 945
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 946
    .line 947
    .line 948
    move-result v15

    .line 949
    move/from16 p1, v15

    .line 950
    .line 951
    const-string v15, "out_of_quota_policy"

    .line 952
    .line 953
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 954
    .line 955
    .line 956
    move-result v15

    .line 957
    move/from16 v16, v15

    .line 958
    .line 959
    const-string v15, "period_count"

    .line 960
    .line 961
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 962
    .line 963
    .line 964
    move-result v15

    .line 965
    move/from16 v18, v15

    .line 966
    .line 967
    const-string v15, "generation"

    .line 968
    .line 969
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 970
    .line 971
    .line 972
    move-result v15

    .line 973
    move/from16 v20, v15

    .line 974
    .line 975
    const-string v15, "next_schedule_time_override"

    .line 976
    .line 977
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 978
    .line 979
    .line 980
    move-result v15

    .line 981
    move/from16 v22, v15

    .line 982
    .line 983
    const-string v15, "next_schedule_time_override_generation"

    .line 984
    .line 985
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 986
    .line 987
    .line 988
    move-result v15

    .line 989
    move/from16 v23, v15

    .line 990
    .line 991
    const-string v15, "stop_reason"

    .line 992
    .line 993
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 994
    .line 995
    .line 996
    move-result v15

    .line 997
    move/from16 v24, v15

    .line 998
    .line 999
    const-string v15, "trace_tag"

    .line 1000
    .line 1001
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1002
    .line 1003
    .line 1004
    move-result v15

    .line 1005
    move/from16 v25, v15

    .line 1006
    .line 1007
    const-string v15, "backoff_on_system_interruptions"

    .line 1008
    .line 1009
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1010
    .line 1011
    .line 1012
    move-result v15

    .line 1013
    move/from16 v26, v15

    .line 1014
    .line 1015
    const-string v15, "required_network_type"

    .line 1016
    .line 1017
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1018
    .line 1019
    .line 1020
    move-result v15

    .line 1021
    move/from16 v27, v15

    .line 1022
    .line 1023
    const-string v15, "required_network_request"

    .line 1024
    .line 1025
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1026
    .line 1027
    .line 1028
    move-result v15

    .line 1029
    move/from16 v28, v15

    .line 1030
    .line 1031
    const-string v15, "requires_charging"

    .line 1032
    .line 1033
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1034
    .line 1035
    .line 1036
    move-result v15

    .line 1037
    move/from16 v29, v15

    .line 1038
    .line 1039
    const-string v15, "requires_device_idle"

    .line 1040
    .line 1041
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1042
    .line 1043
    .line 1044
    move-result v15

    .line 1045
    move/from16 v30, v15

    .line 1046
    .line 1047
    const-string v15, "requires_battery_not_low"

    .line 1048
    .line 1049
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1050
    .line 1051
    .line 1052
    move-result v15

    .line 1053
    move/from16 v31, v15

    .line 1054
    .line 1055
    const-string v15, "requires_storage_not_low"

    .line 1056
    .line 1057
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1058
    .line 1059
    .line 1060
    move-result v15

    .line 1061
    move/from16 v32, v15

    .line 1062
    .line 1063
    const-string v15, "trigger_content_update_delay"

    .line 1064
    .line 1065
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1066
    .line 1067
    .line 1068
    move-result v15

    .line 1069
    move/from16 v33, v15

    .line 1070
    .line 1071
    const-string v15, "trigger_max_content_delay"

    .line 1072
    .line 1073
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1074
    .line 1075
    .line 1076
    move-result v15

    .line 1077
    move/from16 v34, v15

    .line 1078
    .line 1079
    const-string v15, "content_uri_triggers"

    .line 1080
    .line 1081
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1082
    .line 1083
    .line 1084
    move-result v15

    .line 1085
    move/from16 v35, v15

    .line 1086
    .line 1087
    new-instance v15, Ljava/util/ArrayList;

    .line 1088
    .line 1089
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 1090
    .line 1091
    .line 1092
    :goto_14
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 1093
    .line 1094
    .line 1095
    move-result v36

    .line 1096
    if-eqz v36, :cond_14

    .line 1097
    .line 1098
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1099
    .line 1100
    .line 1101
    move-result-object v38

    .line 1102
    move/from16 v71, v4

    .line 1103
    .line 1104
    move/from16 v36, v5

    .line 1105
    .line 1106
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1107
    .line 1108
    .line 1109
    move-result-wide v4

    .line 1110
    long-to-int v4, v4

    .line 1111
    invoke-static {v4}, Ljp/z0;->g(I)Leb/h0;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v39

    .line 1115
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1116
    .line 1117
    .line 1118
    move-result-object v40

    .line 1119
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v41

    .line 1123
    invoke-interface {v2, v13}, Lua/c;->getBlob(I)[B

    .line 1124
    .line 1125
    .line 1126
    move-result-object v4

    .line 1127
    sget-object v5, Leb/h;->b:Leb/h;

    .line 1128
    .line 1129
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 1130
    .line 1131
    .line 1132
    move-result-object v42

    .line 1133
    invoke-interface {v2, v12}, Lua/c;->getBlob(I)[B

    .line 1134
    .line 1135
    .line 1136
    move-result-object v4

    .line 1137
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 1138
    .line 1139
    .line 1140
    move-result-object v43

    .line 1141
    invoke-interface {v2, v11}, Lua/c;->getLong(I)J

    .line 1142
    .line 1143
    .line 1144
    move-result-wide v44

    .line 1145
    invoke-interface {v2, v10}, Lua/c;->getLong(I)J

    .line 1146
    .line 1147
    .line 1148
    move-result-wide v46

    .line 1149
    invoke-interface {v2, v9}, Lua/c;->getLong(I)J

    .line 1150
    .line 1151
    .line 1152
    move-result-wide v48

    .line 1153
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 1154
    .line 1155
    .line 1156
    move-result-wide v4

    .line 1157
    long-to-int v4, v4

    .line 1158
    move/from16 v73, v0

    .line 1159
    .line 1160
    move/from16 v72, v1

    .line 1161
    .line 1162
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 1163
    .line 1164
    .line 1165
    move-result-wide v0

    .line 1166
    long-to-int v0, v0

    .line 1167
    invoke-static {v0}, Ljp/z0;->d(I)Leb/a;

    .line 1168
    .line 1169
    .line 1170
    move-result-object v52

    .line 1171
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 1172
    .line 1173
    .line 1174
    move-result-wide v53

    .line 1175
    move/from16 v0, v36

    .line 1176
    .line 1177
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1178
    .line 1179
    .line 1180
    move-result-wide v55

    .line 1181
    move/from16 v1, v71

    .line 1182
    .line 1183
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1184
    .line 1185
    .line 1186
    move-result-wide v57

    .line 1187
    move/from16 v5, p0

    .line 1188
    .line 1189
    invoke-interface {v2, v5}, Lua/c;->getLong(I)J

    .line 1190
    .line 1191
    .line 1192
    move-result-wide v59

    .line 1193
    move/from16 v36, v0

    .line 1194
    .line 1195
    move/from16 p0, v3

    .line 1196
    .line 1197
    move/from16 v51, v4

    .line 1198
    .line 1199
    move/from16 v0, p1

    .line 1200
    .line 1201
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1202
    .line 1203
    .line 1204
    move-result-wide v3

    .line 1205
    long-to-int v3, v3

    .line 1206
    if-eqz v3, :cond_b

    .line 1207
    .line 1208
    move/from16 v61, v17

    .line 1209
    .line 1210
    :goto_15
    move/from16 p1, v0

    .line 1211
    .line 1212
    move/from16 v71, v1

    .line 1213
    .line 1214
    move/from16 v3, v16

    .line 1215
    .line 1216
    goto :goto_16

    .line 1217
    :cond_b
    const/16 v61, 0x0

    .line 1218
    .line 1219
    goto :goto_15

    .line 1220
    :goto_16
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1221
    .line 1222
    .line 1223
    move-result-wide v0

    .line 1224
    long-to-int v0, v0

    .line 1225
    invoke-static {v0}, Ljp/z0;->f(I)Leb/e0;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v62

    .line 1229
    move/from16 v16, v3

    .line 1230
    .line 1231
    move/from16 v0, v18

    .line 1232
    .line 1233
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1234
    .line 1235
    .line 1236
    move-result-wide v3

    .line 1237
    long-to-int v1, v3

    .line 1238
    move/from16 v18, v0

    .line 1239
    .line 1240
    move/from16 v63, v1

    .line 1241
    .line 1242
    move/from16 v3, v20

    .line 1243
    .line 1244
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1245
    .line 1246
    .line 1247
    move-result-wide v0

    .line 1248
    long-to-int v0, v0

    .line 1249
    move/from16 v1, v22

    .line 1250
    .line 1251
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1252
    .line 1253
    .line 1254
    move-result-wide v65

    .line 1255
    move/from16 v64, v0

    .line 1256
    .line 1257
    move/from16 v4, v23

    .line 1258
    .line 1259
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1260
    .line 1261
    .line 1262
    move-result-wide v0

    .line 1263
    long-to-int v0, v0

    .line 1264
    move/from16 v20, v3

    .line 1265
    .line 1266
    move/from16 v23, v4

    .line 1267
    .line 1268
    move/from16 v1, v24

    .line 1269
    .line 1270
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1271
    .line 1272
    .line 1273
    move-result-wide v3

    .line 1274
    long-to-int v3, v3

    .line 1275
    move/from16 v4, v25

    .line 1276
    .line 1277
    invoke-interface {v2, v4}, Lua/c;->isNull(I)Z

    .line 1278
    .line 1279
    .line 1280
    move-result v24

    .line 1281
    if-eqz v24, :cond_c

    .line 1282
    .line 1283
    move-object/from16 v69, v19

    .line 1284
    .line 1285
    :goto_17
    move/from16 v67, v0

    .line 1286
    .line 1287
    move/from16 v0, v26

    .line 1288
    .line 1289
    goto :goto_18

    .line 1290
    :cond_c
    invoke-interface {v2, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1291
    .line 1292
    .line 1293
    move-result-object v24

    .line 1294
    move-object/from16 v69, v24

    .line 1295
    .line 1296
    goto :goto_17

    .line 1297
    :goto_18
    invoke-interface {v2, v0}, Lua/c;->isNull(I)Z

    .line 1298
    .line 1299
    .line 1300
    move-result v24

    .line 1301
    if-eqz v24, :cond_d

    .line 1302
    .line 1303
    move/from16 v68, v3

    .line 1304
    .line 1305
    move/from16 v25, v4

    .line 1306
    .line 1307
    move-object/from16 v3, v19

    .line 1308
    .line 1309
    goto :goto_19

    .line 1310
    :cond_d
    move/from16 v68, v3

    .line 1311
    .line 1312
    move/from16 v25, v4

    .line 1313
    .line 1314
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1315
    .line 1316
    .line 1317
    move-result-wide v3

    .line 1318
    long-to-int v3, v3

    .line 1319
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v3

    .line 1323
    :goto_19
    if-eqz v3, :cond_f

    .line 1324
    .line 1325
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 1326
    .line 1327
    .line 1328
    move-result v3

    .line 1329
    if-eqz v3, :cond_e

    .line 1330
    .line 1331
    move/from16 v3, v17

    .line 1332
    .line 1333
    goto :goto_1a

    .line 1334
    :cond_e
    const/4 v3, 0x0

    .line 1335
    :goto_1a
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1336
    .line 1337
    .line 1338
    move-result-object v3

    .line 1339
    move-object/from16 v70, v3

    .line 1340
    .line 1341
    :goto_1b
    move/from16 v26, v0

    .line 1342
    .line 1343
    move/from16 v24, v1

    .line 1344
    .line 1345
    move/from16 v3, v27

    .line 1346
    .line 1347
    goto :goto_1c

    .line 1348
    :catchall_3
    move-exception v0

    .line 1349
    goto/16 :goto_25

    .line 1350
    .line 1351
    :cond_f
    move-object/from16 v70, v19

    .line 1352
    .line 1353
    goto :goto_1b

    .line 1354
    :goto_1c
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1355
    .line 1356
    .line 1357
    move-result-wide v0

    .line 1358
    long-to-int v0, v0

    .line 1359
    invoke-static {v0}, Ljp/z0;->e(I)Leb/x;

    .line 1360
    .line 1361
    .line 1362
    move-result-object v76

    .line 1363
    move/from16 v0, v28

    .line 1364
    .line 1365
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 1366
    .line 1367
    .line 1368
    move-result-object v1

    .line 1369
    invoke-static {v1}, Ljp/z0;->m([B)Lnb/d;

    .line 1370
    .line 1371
    .line 1372
    move-result-object v75

    .line 1373
    move/from16 v27, v3

    .line 1374
    .line 1375
    move/from16 v1, v29

    .line 1376
    .line 1377
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1378
    .line 1379
    .line 1380
    move-result-wide v3

    .line 1381
    long-to-int v3, v3

    .line 1382
    if-eqz v3, :cond_10

    .line 1383
    .line 1384
    move/from16 v77, v17

    .line 1385
    .line 1386
    :goto_1d
    move/from16 v28, v0

    .line 1387
    .line 1388
    move/from16 v29, v1

    .line 1389
    .line 1390
    move/from16 v3, v30

    .line 1391
    .line 1392
    goto :goto_1e

    .line 1393
    :cond_10
    const/16 v77, 0x0

    .line 1394
    .line 1395
    goto :goto_1d

    .line 1396
    :goto_1e
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1397
    .line 1398
    .line 1399
    move-result-wide v0

    .line 1400
    long-to-int v0, v0

    .line 1401
    if-eqz v0, :cond_11

    .line 1402
    .line 1403
    move/from16 v78, v17

    .line 1404
    .line 1405
    :goto_1f
    move/from16 v30, v3

    .line 1406
    .line 1407
    move/from16 v0, v31

    .line 1408
    .line 1409
    goto :goto_20

    .line 1410
    :cond_11
    const/16 v78, 0x0

    .line 1411
    .line 1412
    goto :goto_1f

    .line 1413
    :goto_20
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1414
    .line 1415
    .line 1416
    move-result-wide v3

    .line 1417
    long-to-int v1, v3

    .line 1418
    if-eqz v1, :cond_12

    .line 1419
    .line 1420
    move/from16 v79, v17

    .line 1421
    .line 1422
    :goto_21
    move/from16 v1, v32

    .line 1423
    .line 1424
    goto :goto_22

    .line 1425
    :cond_12
    const/16 v79, 0x0

    .line 1426
    .line 1427
    goto :goto_21

    .line 1428
    :goto_22
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1429
    .line 1430
    .line 1431
    move-result-wide v3

    .line 1432
    long-to-int v3, v3

    .line 1433
    if-eqz v3, :cond_13

    .line 1434
    .line 1435
    move/from16 v80, v17

    .line 1436
    .line 1437
    :goto_23
    move/from16 v3, v33

    .line 1438
    .line 1439
    goto :goto_24

    .line 1440
    :cond_13
    const/16 v80, 0x0

    .line 1441
    .line 1442
    goto :goto_23

    .line 1443
    :goto_24
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1444
    .line 1445
    .line 1446
    move-result-wide v81

    .line 1447
    move/from16 v4, v34

    .line 1448
    .line 1449
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1450
    .line 1451
    .line 1452
    move-result-wide v83

    .line 1453
    move/from16 v31, v0

    .line 1454
    .line 1455
    move/from16 v0, v35

    .line 1456
    .line 1457
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 1458
    .line 1459
    .line 1460
    move-result-object v32

    .line 1461
    invoke-static/range {v32 .. v32}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v85

    .line 1465
    new-instance v50, Leb/e;

    .line 1466
    .line 1467
    move-object/from16 v74, v50

    .line 1468
    .line 1469
    invoke-direct/range {v74 .. v85}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 1470
    .line 1471
    .line 1472
    move-object/from16 v50, v74

    .line 1473
    .line 1474
    new-instance v37, Lmb/o;

    .line 1475
    .line 1476
    invoke-direct/range {v37 .. v70}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 1477
    .line 1478
    .line 1479
    move/from16 v35, v0

    .line 1480
    .line 1481
    move-object/from16 v0, v37

    .line 1482
    .line 1483
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 1484
    .line 1485
    .line 1486
    move/from16 v32, v1

    .line 1487
    .line 1488
    move/from16 v33, v3

    .line 1489
    .line 1490
    move/from16 v34, v4

    .line 1491
    .line 1492
    move/from16 v4, v71

    .line 1493
    .line 1494
    move/from16 v1, v72

    .line 1495
    .line 1496
    move/from16 v0, v73

    .line 1497
    .line 1498
    move/from16 v3, p0

    .line 1499
    .line 1500
    move/from16 p0, v5

    .line 1501
    .line 1502
    move/from16 v5, v36

    .line 1503
    .line 1504
    goto/16 :goto_14

    .line 1505
    .line 1506
    :cond_14
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1507
    .line 1508
    .line 1509
    return-object v15

    .line 1510
    :goto_25
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 1511
    .line 1512
    .line 1513
    throw v0

    .line 1514
    :pswitch_10
    move-object/from16 v3, p1

    .line 1515
    .line 1516
    check-cast v3, Lua/a;

    .line 1517
    .line 1518
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1519
    .line 1520
    .line 1521
    const-string v2, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at<>-1"

    .line 1522
    .line 1523
    invoke-interface {v3, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 1524
    .line 1525
    .line 1526
    move-result-object v2

    .line 1527
    :try_start_4
    invoke-static {v2, v1}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1528
    .line 1529
    .line 1530
    move-result v1

    .line 1531
    invoke-static {v2, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1532
    .line 1533
    .line 1534
    move-result v0

    .line 1535
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1536
    .line 1537
    .line 1538
    move-result v3

    .line 1539
    invoke-static {v2, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1540
    .line 1541
    .line 1542
    move-result v14

    .line 1543
    invoke-static {v2, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1544
    .line 1545
    .line 1546
    move-result v13

    .line 1547
    invoke-static {v2, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1548
    .line 1549
    .line 1550
    move-result v12

    .line 1551
    invoke-static {v2, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1552
    .line 1553
    .line 1554
    move-result v11

    .line 1555
    invoke-static {v2, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1556
    .line 1557
    .line 1558
    move-result v10

    .line 1559
    invoke-static {v2, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1560
    .line 1561
    .line 1562
    move-result v9

    .line 1563
    invoke-static {v2, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1564
    .line 1565
    .line 1566
    move-result v8

    .line 1567
    invoke-static {v2, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1568
    .line 1569
    .line 1570
    move-result v7

    .line 1571
    invoke-static {v2, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1572
    .line 1573
    .line 1574
    move-result v6

    .line 1575
    invoke-static {v2, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1576
    .line 1577
    .line 1578
    move-result v5

    .line 1579
    invoke-static {v2, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1580
    .line 1581
    .line 1582
    move-result v4

    .line 1583
    move-object/from16 v15, v22

    .line 1584
    .line 1585
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1586
    .line 1587
    .line 1588
    move-result v15

    .line 1589
    move/from16 p0, v15

    .line 1590
    .line 1591
    move-object/from16 v15, v20

    .line 1592
    .line 1593
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1594
    .line 1595
    .line 1596
    move-result v15

    .line 1597
    move/from16 p1, v15

    .line 1598
    .line 1599
    const-string v15, "out_of_quota_policy"

    .line 1600
    .line 1601
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1602
    .line 1603
    .line 1604
    move-result v15

    .line 1605
    move/from16 v16, v15

    .line 1606
    .line 1607
    const-string v15, "period_count"

    .line 1608
    .line 1609
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1610
    .line 1611
    .line 1612
    move-result v15

    .line 1613
    move/from16 v18, v15

    .line 1614
    .line 1615
    const-string v15, "generation"

    .line 1616
    .line 1617
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1618
    .line 1619
    .line 1620
    move-result v15

    .line 1621
    move/from16 v20, v15

    .line 1622
    .line 1623
    const-string v15, "next_schedule_time_override"

    .line 1624
    .line 1625
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1626
    .line 1627
    .line 1628
    move-result v15

    .line 1629
    move/from16 v22, v15

    .line 1630
    .line 1631
    const-string v15, "next_schedule_time_override_generation"

    .line 1632
    .line 1633
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1634
    .line 1635
    .line 1636
    move-result v15

    .line 1637
    move/from16 v23, v15

    .line 1638
    .line 1639
    const-string v15, "stop_reason"

    .line 1640
    .line 1641
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1642
    .line 1643
    .line 1644
    move-result v15

    .line 1645
    move/from16 v24, v15

    .line 1646
    .line 1647
    const-string v15, "trace_tag"

    .line 1648
    .line 1649
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1650
    .line 1651
    .line 1652
    move-result v15

    .line 1653
    move/from16 v25, v15

    .line 1654
    .line 1655
    const-string v15, "backoff_on_system_interruptions"

    .line 1656
    .line 1657
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1658
    .line 1659
    .line 1660
    move-result v15

    .line 1661
    move/from16 v26, v15

    .line 1662
    .line 1663
    const-string v15, "required_network_type"

    .line 1664
    .line 1665
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1666
    .line 1667
    .line 1668
    move-result v15

    .line 1669
    move/from16 v27, v15

    .line 1670
    .line 1671
    const-string v15, "required_network_request"

    .line 1672
    .line 1673
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1674
    .line 1675
    .line 1676
    move-result v15

    .line 1677
    move/from16 v28, v15

    .line 1678
    .line 1679
    const-string v15, "requires_charging"

    .line 1680
    .line 1681
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1682
    .line 1683
    .line 1684
    move-result v15

    .line 1685
    move/from16 v29, v15

    .line 1686
    .line 1687
    const-string v15, "requires_device_idle"

    .line 1688
    .line 1689
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1690
    .line 1691
    .line 1692
    move-result v15

    .line 1693
    move/from16 v30, v15

    .line 1694
    .line 1695
    const-string v15, "requires_battery_not_low"

    .line 1696
    .line 1697
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1698
    .line 1699
    .line 1700
    move-result v15

    .line 1701
    move/from16 v31, v15

    .line 1702
    .line 1703
    const-string v15, "requires_storage_not_low"

    .line 1704
    .line 1705
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1706
    .line 1707
    .line 1708
    move-result v15

    .line 1709
    move/from16 v32, v15

    .line 1710
    .line 1711
    const-string v15, "trigger_content_update_delay"

    .line 1712
    .line 1713
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1714
    .line 1715
    .line 1716
    move-result v15

    .line 1717
    move/from16 v33, v15

    .line 1718
    .line 1719
    const-string v15, "trigger_max_content_delay"

    .line 1720
    .line 1721
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1722
    .line 1723
    .line 1724
    move-result v15

    .line 1725
    move/from16 v34, v15

    .line 1726
    .line 1727
    const-string v15, "content_uri_triggers"

    .line 1728
    .line 1729
    invoke-static {v2, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 1730
    .line 1731
    .line 1732
    move-result v15

    .line 1733
    move/from16 v35, v15

    .line 1734
    .line 1735
    new-instance v15, Ljava/util/ArrayList;

    .line 1736
    .line 1737
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 1738
    .line 1739
    .line 1740
    :goto_26
    invoke-interface {v2}, Lua/c;->s0()Z

    .line 1741
    .line 1742
    .line 1743
    move-result v36

    .line 1744
    if-eqz v36, :cond_1e

    .line 1745
    .line 1746
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1747
    .line 1748
    .line 1749
    move-result-object v38

    .line 1750
    move/from16 v71, v4

    .line 1751
    .line 1752
    move/from16 v36, v5

    .line 1753
    .line 1754
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1755
    .line 1756
    .line 1757
    move-result-wide v4

    .line 1758
    long-to-int v4, v4

    .line 1759
    invoke-static {v4}, Ljp/z0;->g(I)Leb/h0;

    .line 1760
    .line 1761
    .line 1762
    move-result-object v39

    .line 1763
    invoke-interface {v2, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1764
    .line 1765
    .line 1766
    move-result-object v40

    .line 1767
    invoke-interface {v2, v14}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1768
    .line 1769
    .line 1770
    move-result-object v41

    .line 1771
    invoke-interface {v2, v13}, Lua/c;->getBlob(I)[B

    .line 1772
    .line 1773
    .line 1774
    move-result-object v4

    .line 1775
    sget-object v5, Leb/h;->b:Leb/h;

    .line 1776
    .line 1777
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 1778
    .line 1779
    .line 1780
    move-result-object v42

    .line 1781
    invoke-interface {v2, v12}, Lua/c;->getBlob(I)[B

    .line 1782
    .line 1783
    .line 1784
    move-result-object v4

    .line 1785
    invoke-static {v4}, Lkp/b6;->b([B)Leb/h;

    .line 1786
    .line 1787
    .line 1788
    move-result-object v43

    .line 1789
    invoke-interface {v2, v11}, Lua/c;->getLong(I)J

    .line 1790
    .line 1791
    .line 1792
    move-result-wide v44

    .line 1793
    invoke-interface {v2, v10}, Lua/c;->getLong(I)J

    .line 1794
    .line 1795
    .line 1796
    move-result-wide v46

    .line 1797
    invoke-interface {v2, v9}, Lua/c;->getLong(I)J

    .line 1798
    .line 1799
    .line 1800
    move-result-wide v48

    .line 1801
    invoke-interface {v2, v8}, Lua/c;->getLong(I)J

    .line 1802
    .line 1803
    .line 1804
    move-result-wide v4

    .line 1805
    long-to-int v4, v4

    .line 1806
    move/from16 v72, v0

    .line 1807
    .line 1808
    move v5, v1

    .line 1809
    invoke-interface {v2, v7}, Lua/c;->getLong(I)J

    .line 1810
    .line 1811
    .line 1812
    move-result-wide v0

    .line 1813
    long-to-int v0, v0

    .line 1814
    invoke-static {v0}, Ljp/z0;->d(I)Leb/a;

    .line 1815
    .line 1816
    .line 1817
    move-result-object v52

    .line 1818
    invoke-interface {v2, v6}, Lua/c;->getLong(I)J

    .line 1819
    .line 1820
    .line 1821
    move-result-wide v53

    .line 1822
    move/from16 v0, v36

    .line 1823
    .line 1824
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1825
    .line 1826
    .line 1827
    move-result-wide v55

    .line 1828
    move/from16 v1, v71

    .line 1829
    .line 1830
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1831
    .line 1832
    .line 1833
    move-result-wide v57

    .line 1834
    move/from16 v36, v0

    .line 1835
    .line 1836
    move/from16 v0, p0

    .line 1837
    .line 1838
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1839
    .line 1840
    .line 1841
    move-result-wide v59

    .line 1842
    move/from16 p0, v0

    .line 1843
    .line 1844
    move/from16 v51, v4

    .line 1845
    .line 1846
    move/from16 v0, p1

    .line 1847
    .line 1848
    move/from16 p1, v3

    .line 1849
    .line 1850
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1851
    .line 1852
    .line 1853
    move-result-wide v3

    .line 1854
    long-to-int v3, v3

    .line 1855
    if-eqz v3, :cond_15

    .line 1856
    .line 1857
    move/from16 v61, v17

    .line 1858
    .line 1859
    :goto_27
    move v4, v0

    .line 1860
    move/from16 v71, v1

    .line 1861
    .line 1862
    move/from16 v3, v16

    .line 1863
    .line 1864
    goto :goto_28

    .line 1865
    :cond_15
    const/16 v61, 0x0

    .line 1866
    .line 1867
    goto :goto_27

    .line 1868
    :goto_28
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 1869
    .line 1870
    .line 1871
    move-result-wide v0

    .line 1872
    long-to-int v0, v0

    .line 1873
    invoke-static {v0}, Ljp/z0;->f(I)Leb/e0;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v62

    .line 1877
    move/from16 v16, v3

    .line 1878
    .line 1879
    move v1, v4

    .line 1880
    move/from16 v0, v18

    .line 1881
    .line 1882
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1883
    .line 1884
    .line 1885
    move-result-wide v3

    .line 1886
    long-to-int v3, v3

    .line 1887
    move/from16 v18, v0

    .line 1888
    .line 1889
    move/from16 v4, v20

    .line 1890
    .line 1891
    move/from16 v20, v1

    .line 1892
    .line 1893
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1894
    .line 1895
    .line 1896
    move-result-wide v0

    .line 1897
    long-to-int v0, v0

    .line 1898
    move/from16 v1, v22

    .line 1899
    .line 1900
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 1901
    .line 1902
    .line 1903
    move-result-wide v65

    .line 1904
    move/from16 v64, v0

    .line 1905
    .line 1906
    move/from16 v63, v3

    .line 1907
    .line 1908
    move/from16 v22, v4

    .line 1909
    .line 1910
    move/from16 v0, v23

    .line 1911
    .line 1912
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1913
    .line 1914
    .line 1915
    move-result-wide v3

    .line 1916
    long-to-int v3, v3

    .line 1917
    move/from16 v23, v1

    .line 1918
    .line 1919
    move/from16 v4, v24

    .line 1920
    .line 1921
    move/from16 v24, v0

    .line 1922
    .line 1923
    invoke-interface {v2, v4}, Lua/c;->getLong(I)J

    .line 1924
    .line 1925
    .line 1926
    move-result-wide v0

    .line 1927
    long-to-int v0, v0

    .line 1928
    move/from16 v1, v25

    .line 1929
    .line 1930
    invoke-interface {v2, v1}, Lua/c;->isNull(I)Z

    .line 1931
    .line 1932
    .line 1933
    move-result v25

    .line 1934
    if-eqz v25, :cond_16

    .line 1935
    .line 1936
    move-object/from16 v69, v19

    .line 1937
    .line 1938
    :goto_29
    move/from16 v68, v0

    .line 1939
    .line 1940
    move/from16 v0, v26

    .line 1941
    .line 1942
    goto :goto_2a

    .line 1943
    :cond_16
    invoke-interface {v2, v1}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1944
    .line 1945
    .line 1946
    move-result-object v25

    .line 1947
    move-object/from16 v69, v25

    .line 1948
    .line 1949
    goto :goto_29

    .line 1950
    :goto_2a
    invoke-interface {v2, v0}, Lua/c;->isNull(I)Z

    .line 1951
    .line 1952
    .line 1953
    move-result v25

    .line 1954
    if-eqz v25, :cond_17

    .line 1955
    .line 1956
    move/from16 v67, v3

    .line 1957
    .line 1958
    move/from16 v25, v4

    .line 1959
    .line 1960
    move-object/from16 v3, v19

    .line 1961
    .line 1962
    goto :goto_2b

    .line 1963
    :cond_17
    move/from16 v67, v3

    .line 1964
    .line 1965
    move/from16 v25, v4

    .line 1966
    .line 1967
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 1968
    .line 1969
    .line 1970
    move-result-wide v3

    .line 1971
    long-to-int v3, v3

    .line 1972
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1973
    .line 1974
    .line 1975
    move-result-object v3

    .line 1976
    :goto_2b
    if-eqz v3, :cond_19

    .line 1977
    .line 1978
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 1979
    .line 1980
    .line 1981
    move-result v3

    .line 1982
    if-eqz v3, :cond_18

    .line 1983
    .line 1984
    move/from16 v3, v17

    .line 1985
    .line 1986
    goto :goto_2c

    .line 1987
    :cond_18
    const/4 v3, 0x0

    .line 1988
    :goto_2c
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1989
    .line 1990
    .line 1991
    move-result-object v3

    .line 1992
    move-object/from16 v70, v3

    .line 1993
    .line 1994
    :goto_2d
    move/from16 v26, v0

    .line 1995
    .line 1996
    move v4, v1

    .line 1997
    move/from16 v3, v27

    .line 1998
    .line 1999
    goto :goto_2e

    .line 2000
    :catchall_4
    move-exception v0

    .line 2001
    goto/16 :goto_37

    .line 2002
    .line 2003
    :cond_19
    move-object/from16 v70, v19

    .line 2004
    .line 2005
    goto :goto_2d

    .line 2006
    :goto_2e
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 2007
    .line 2008
    .line 2009
    move-result-wide v0

    .line 2010
    long-to-int v0, v0

    .line 2011
    invoke-static {v0}, Ljp/z0;->e(I)Leb/x;

    .line 2012
    .line 2013
    .line 2014
    move-result-object v75

    .line 2015
    move/from16 v0, v28

    .line 2016
    .line 2017
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 2018
    .line 2019
    .line 2020
    move-result-object v1

    .line 2021
    invoke-static {v1}, Ljp/z0;->m([B)Lnb/d;

    .line 2022
    .line 2023
    .line 2024
    move-result-object v74

    .line 2025
    move/from16 v27, v3

    .line 2026
    .line 2027
    move/from16 v28, v4

    .line 2028
    .line 2029
    move/from16 v1, v29

    .line 2030
    .line 2031
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 2032
    .line 2033
    .line 2034
    move-result-wide v3

    .line 2035
    long-to-int v3, v3

    .line 2036
    if-eqz v3, :cond_1a

    .line 2037
    .line 2038
    move/from16 v76, v17

    .line 2039
    .line 2040
    :goto_2f
    move v4, v0

    .line 2041
    move/from16 v29, v1

    .line 2042
    .line 2043
    move/from16 v3, v30

    .line 2044
    .line 2045
    goto :goto_30

    .line 2046
    :cond_1a
    const/16 v76, 0x0

    .line 2047
    .line 2048
    goto :goto_2f

    .line 2049
    :goto_30
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 2050
    .line 2051
    .line 2052
    move-result-wide v0

    .line 2053
    long-to-int v0, v0

    .line 2054
    if-eqz v0, :cond_1b

    .line 2055
    .line 2056
    move/from16 v77, v17

    .line 2057
    .line 2058
    :goto_31
    move/from16 v30, v3

    .line 2059
    .line 2060
    move v1, v4

    .line 2061
    move/from16 v0, v31

    .line 2062
    .line 2063
    goto :goto_32

    .line 2064
    :cond_1b
    const/16 v77, 0x0

    .line 2065
    .line 2066
    goto :goto_31

    .line 2067
    :goto_32
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 2068
    .line 2069
    .line 2070
    move-result-wide v3

    .line 2071
    long-to-int v3, v3

    .line 2072
    if-eqz v3, :cond_1c

    .line 2073
    .line 2074
    move/from16 v78, v17

    .line 2075
    .line 2076
    :goto_33
    move/from16 v31, v0

    .line 2077
    .line 2078
    move v4, v1

    .line 2079
    move/from16 v3, v32

    .line 2080
    .line 2081
    goto :goto_34

    .line 2082
    :cond_1c
    const/16 v78, 0x0

    .line 2083
    .line 2084
    goto :goto_33

    .line 2085
    :goto_34
    invoke-interface {v2, v3}, Lua/c;->getLong(I)J

    .line 2086
    .line 2087
    .line 2088
    move-result-wide v0

    .line 2089
    long-to-int v0, v0

    .line 2090
    if-eqz v0, :cond_1d

    .line 2091
    .line 2092
    move/from16 v79, v17

    .line 2093
    .line 2094
    :goto_35
    move/from16 v0, v33

    .line 2095
    .line 2096
    goto :goto_36

    .line 2097
    :cond_1d
    const/16 v79, 0x0

    .line 2098
    .line 2099
    goto :goto_35

    .line 2100
    :goto_36
    invoke-interface {v2, v0}, Lua/c;->getLong(I)J

    .line 2101
    .line 2102
    .line 2103
    move-result-wide v80

    .line 2104
    move/from16 v1, v34

    .line 2105
    .line 2106
    invoke-interface {v2, v1}, Lua/c;->getLong(I)J

    .line 2107
    .line 2108
    .line 2109
    move-result-wide v82

    .line 2110
    move/from16 v33, v0

    .line 2111
    .line 2112
    move/from16 v0, v35

    .line 2113
    .line 2114
    invoke-interface {v2, v0}, Lua/c;->getBlob(I)[B

    .line 2115
    .line 2116
    .line 2117
    move-result-object v32

    .line 2118
    invoke-static/range {v32 .. v32}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 2119
    .line 2120
    .line 2121
    move-result-object v84

    .line 2122
    new-instance v50, Leb/e;

    .line 2123
    .line 2124
    move-object/from16 v73, v50

    .line 2125
    .line 2126
    invoke-direct/range {v73 .. v84}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 2127
    .line 2128
    .line 2129
    move-object/from16 v50, v73

    .line 2130
    .line 2131
    new-instance v37, Lmb/o;

    .line 2132
    .line 2133
    invoke-direct/range {v37 .. v70}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 2134
    .line 2135
    .line 2136
    move/from16 v35, v0

    .line 2137
    .line 2138
    move-object/from16 v0, v37

    .line 2139
    .line 2140
    invoke-virtual {v15, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    .line 2141
    .line 2142
    .line 2143
    move/from16 v34, v1

    .line 2144
    .line 2145
    move/from16 v32, v3

    .line 2146
    .line 2147
    move v1, v5

    .line 2148
    move/from16 v5, v36

    .line 2149
    .line 2150
    move/from16 v0, v72

    .line 2151
    .line 2152
    move/from16 v3, p1

    .line 2153
    .line 2154
    move/from16 p1, v20

    .line 2155
    .line 2156
    move/from16 v20, v22

    .line 2157
    .line 2158
    move/from16 v22, v23

    .line 2159
    .line 2160
    move/from16 v23, v24

    .line 2161
    .line 2162
    move/from16 v24, v25

    .line 2163
    .line 2164
    move/from16 v25, v28

    .line 2165
    .line 2166
    move/from16 v28, v4

    .line 2167
    .line 2168
    move/from16 v4, v71

    .line 2169
    .line 2170
    goto/16 :goto_26

    .line 2171
    .line 2172
    :cond_1e
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 2173
    .line 2174
    .line 2175
    return-object v15

    .line 2176
    :goto_37
    invoke-interface {v2}, Ljava/lang/AutoCloseable;->close()V

    .line 2177
    .line 2178
    .line 2179
    throw v0

    .line 2180
    :pswitch_11
    move-object/from16 v0, p1

    .line 2181
    .line 2182
    check-cast v0, Lua/a;

    .line 2183
    .line 2184
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2185
    .line 2186
    .line 2187
    const-string v1, "DELETE FROM WorkProgress"

    .line 2188
    .line 2189
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2190
    .line 2191
    .line 2192
    move-result-object v1

    .line 2193
    :try_start_5
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_5

    .line 2194
    .line 2195
    .line 2196
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2197
    .line 2198
    .line 2199
    return-object v18

    .line 2200
    :catchall_5
    move-exception v0

    .line 2201
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2202
    .line 2203
    .line 2204
    throw v0

    .line 2205
    :pswitch_12
    move-object/from16 v0, p1

    .line 2206
    .line 2207
    check-cast v0, Lua/a;

    .line 2208
    .line 2209
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2210
    .line 2211
    .line 2212
    const-string v1, "SELECT DISTINCT work_spec_id FROM SystemIdInfo"

    .line 2213
    .line 2214
    invoke-interface {v0, v1}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2215
    .line 2216
    .line 2217
    move-result-object v1

    .line 2218
    :try_start_6
    new-instance v0, Ljava/util/ArrayList;

    .line 2219
    .line 2220
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 2221
    .line 2222
    .line 2223
    :goto_38
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 2224
    .line 2225
    .line 2226
    move-result v2

    .line 2227
    if-eqz v2, :cond_1f

    .line 2228
    .line 2229
    const/4 v2, 0x0

    .line 2230
    invoke-interface {v1, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 2231
    .line 2232
    .line 2233
    move-result-object v3

    .line 2234
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_6

    .line 2235
    .line 2236
    .line 2237
    goto :goto_38

    .line 2238
    :catchall_6
    move-exception v0

    .line 2239
    goto :goto_39

    .line 2240
    :cond_1f
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2241
    .line 2242
    .line 2243
    return-object v0

    .line 2244
    :goto_39
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2245
    .line 2246
    .line 2247
    throw v0

    .line 2248
    :pswitch_13
    move-object/from16 v0, p1

    .line 2249
    .line 2250
    check-cast v0, Lap0/p;

    .line 2251
    .line 2252
    const-string v1, "it"

    .line 2253
    .line 2254
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2255
    .line 2256
    .line 2257
    return-object v18

    .line 2258
    :pswitch_14
    move-object/from16 v0, p1

    .line 2259
    .line 2260
    check-cast v0, Ljava/lang/String;

    .line 2261
    .line 2262
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2263
    .line 2264
    .line 2265
    invoke-static {v0}, Lkp/x;->b(Ljava/lang/String;)Lbm0/c;

    .line 2266
    .line 2267
    .line 2268
    move-result-object v0

    .line 2269
    return-object v0

    .line 2270
    :pswitch_15
    move-object/from16 v0, p1

    .line 2271
    .line 2272
    check-cast v0, Lcz/myskoda/api/bff_fueling/v2/CreatedFuelingSessionDto;

    .line 2273
    .line 2274
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2275
    .line 2276
    .line 2277
    new-instance v1, Lp40/a;

    .line 2278
    .line 2279
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/CreatedFuelingSessionDto;->getId()Ljava/lang/String;

    .line 2280
    .line 2281
    .line 2282
    move-result-object v2

    .line 2283
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/CreatedFuelingSessionDto;->getState()Ljava/lang/String;

    .line 2284
    .line 2285
    .line 2286
    move-result-object v0

    .line 2287
    invoke-static {v0}, Llp/wf;->b(Ljava/lang/String;)Lon0/h;

    .line 2288
    .line 2289
    .line 2290
    move-result-object v0

    .line 2291
    invoke-direct {v1, v2, v0}, Lp40/a;-><init>(Ljava/lang/String;Lon0/h;)V

    .line 2292
    .line 2293
    .line 2294
    return-object v1

    .line 2295
    :pswitch_16
    move-object/from16 v0, p1

    .line 2296
    .line 2297
    check-cast v0, Ljava/lang/String;

    .line 2298
    .line 2299
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2300
    .line 2301
    .line 2302
    invoke-static {v0}, Lkp/x;->b(Ljava/lang/String;)Lbm0/c;

    .line 2303
    .line 2304
    .line 2305
    move-result-object v0

    .line 2306
    return-object v0

    .line 2307
    :pswitch_17
    move-object/from16 v0, p1

    .line 2308
    .line 2309
    check-cast v0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionStateResponseDto;

    .line 2310
    .line 2311
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2312
    .line 2313
    .line 2314
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionStateResponseDto;->getState()Ljava/lang/String;

    .line 2315
    .line 2316
    .line 2317
    move-result-object v0

    .line 2318
    invoke-static {v0}, Llp/wf;->b(Ljava/lang/String;)Lon0/h;

    .line 2319
    .line 2320
    .line 2321
    move-result-object v0

    .line 2322
    return-object v0

    .line 2323
    :pswitch_18
    move-object/from16 v0, p1

    .line 2324
    .line 2325
    check-cast v0, Ljava/lang/String;

    .line 2326
    .line 2327
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2328
    .line 2329
    .line 2330
    invoke-static {v0}, Lkp/x;->b(Ljava/lang/String;)Lbm0/c;

    .line 2331
    .line 2332
    .line 2333
    move-result-object v0

    .line 2334
    return-object v0

    .line 2335
    :pswitch_19
    move-object/from16 v0, p1

    .line 2336
    .line 2337
    check-cast v0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;

    .line 2338
    .line 2339
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2340
    .line 2341
    .line 2342
    invoke-static {v0}, Llp/wf;->c(Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;)Lon0/e;

    .line 2343
    .line 2344
    .line 2345
    move-result-object v0

    .line 2346
    return-object v0

    .line 2347
    :pswitch_1a
    move-object/from16 v0, p1

    .line 2348
    .line 2349
    check-cast v0, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;

    .line 2350
    .line 2351
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2352
    .line 2353
    .line 2354
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getId()Ljava/lang/String;

    .line 2355
    .line 2356
    .line 2357
    move-result-object v5

    .line 2358
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getCurrencyCode()Ljava/lang/String;

    .line 2359
    .line 2360
    .line 2361
    move-result-object v6

    .line 2362
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getPumps()Ljava/util/List;

    .line 2363
    .line 2364
    .line 2365
    move-result-object v1

    .line 2366
    check-cast v1, Ljava/lang/Iterable;

    .line 2367
    .line 2368
    new-instance v7, Ljava/util/ArrayList;

    .line 2369
    .line 2370
    const/16 v2, 0xa

    .line 2371
    .line 2372
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2373
    .line 2374
    .line 2375
    move-result v3

    .line 2376
    invoke-direct {v7, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 2377
    .line 2378
    .line 2379
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2380
    .line 2381
    .line 2382
    move-result-object v1

    .line 2383
    :goto_3a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 2384
    .line 2385
    .line 2386
    move-result v3

    .line 2387
    const-string v4, ""

    .line 2388
    .line 2389
    if-eqz v3, :cond_25

    .line 2390
    .line 2391
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2392
    .line 2393
    .line 2394
    move-result-object v3

    .line 2395
    check-cast v3, Lcz/myskoda/api/bff_fueling/v2/GasStationPumpDto;

    .line 2396
    .line 2397
    invoke-virtual {v0}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getCurrencyCode()Ljava/lang/String;

    .line 2398
    .line 2399
    .line 2400
    move-result-object v8

    .line 2401
    const-string v9, "<this>"

    .line 2402
    .line 2403
    invoke-static {v3, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2404
    .line 2405
    .line 2406
    invoke-virtual {v3}, Lcz/myskoda/api/bff_fueling/v2/GasStationPumpDto;->getId()Ljava/lang/String;

    .line 2407
    .line 2408
    .line 2409
    move-result-object v10

    .line 2410
    invoke-virtual {v3}, Lcz/myskoda/api/bff_fueling/v2/GasStationPumpDto;->getName()Ljava/lang/String;

    .line 2411
    .line 2412
    .line 2413
    move-result-object v11

    .line 2414
    invoke-virtual {v3}, Lcz/myskoda/api/bff_fueling/v2/GasStationPumpDto;->getPaymentType()Ljava/lang/String;

    .line 2415
    .line 2416
    .line 2417
    move-result-object v12

    .line 2418
    const-string v13, "POSTPAY"

    .line 2419
    .line 2420
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 2421
    .line 2422
    .line 2423
    move-result v12

    .line 2424
    if-eqz v12, :cond_20

    .line 2425
    .line 2426
    sget-object v12, Lon0/y;->e:Lon0/y;

    .line 2427
    .line 2428
    goto :goto_3b

    .line 2429
    :cond_20
    sget-object v12, Lon0/y;->d:Lon0/y;

    .line 2430
    .line 2431
    :goto_3b
    invoke-virtual {v3}, Lcz/myskoda/api/bff_fueling/v2/GasStationPumpDto;->getFuelTypes()Ljava/util/List;

    .line 2432
    .line 2433
    .line 2434
    move-result-object v3

    .line 2435
    check-cast v3, Ljava/lang/Iterable;

    .line 2436
    .line 2437
    new-instance v13, Ljava/util/ArrayList;

    .line 2438
    .line 2439
    invoke-static {v3, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2440
    .line 2441
    .line 2442
    move-result v14

    .line 2443
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 2444
    .line 2445
    .line 2446
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2447
    .line 2448
    .line 2449
    move-result-object v3

    .line 2450
    :goto_3c
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 2451
    .line 2452
    .line 2453
    move-result v14

    .line 2454
    if-eqz v14, :cond_24

    .line 2455
    .line 2456
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2457
    .line 2458
    .line 2459
    move-result-object v14

    .line 2460
    check-cast v14, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;

    .line 2461
    .line 2462
    invoke-static {v14, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2463
    .line 2464
    .line 2465
    new-instance v15, Lon0/w;

    .line 2466
    .line 2467
    invoke-virtual {v14}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->getId()Ljava/lang/String;

    .line 2468
    .line 2469
    .line 2470
    move-result-object v2

    .line 2471
    move-object/from16 p1, v0

    .line 2472
    .line 2473
    invoke-virtual {v14}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->getName()Ljava/lang/String;

    .line 2474
    .line 2475
    .line 2476
    move-result-object v0

    .line 2477
    invoke-virtual {v14}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->getGroup()Ljava/lang/String;

    .line 2478
    .line 2479
    .line 2480
    move-result-object v16

    .line 2481
    move-object/from16 v17, v1

    .line 2482
    .line 2483
    if-nez v16, :cond_21

    .line 2484
    .line 2485
    move-object v1, v4

    .line 2486
    goto :goto_3d

    .line 2487
    :cond_21
    move-object/from16 v1, v16

    .line 2488
    .line 2489
    :goto_3d
    if-eqz v8, :cond_23

    .line 2490
    .line 2491
    invoke-virtual {v14}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->getPricePerUnit()Ljava/lang/Double;

    .line 2492
    .line 2493
    .line 2494
    move-result-object v16

    .line 2495
    if-eqz v16, :cond_23

    .line 2496
    .line 2497
    move-object/from16 v16, v3

    .line 2498
    .line 2499
    new-instance v3, Lol0/a;

    .line 2500
    .line 2501
    invoke-virtual {v14}, Lcz/myskoda/api/bff_fueling/v2/GasStationFuelDto;->getPricePerUnit()Ljava/lang/Double;

    .line 2502
    .line 2503
    .line 2504
    move-result-object v14

    .line 2505
    if-eqz v14, :cond_22

    .line 2506
    .line 2507
    invoke-virtual {v14}, Ljava/lang/Double;->doubleValue()D

    .line 2508
    .line 2509
    .line 2510
    move-result-wide v20

    .line 2511
    goto :goto_3e

    .line 2512
    :cond_22
    const-wide/16 v20, 0x0

    .line 2513
    .line 2514
    :goto_3e
    new-instance v14, Ljava/math/BigDecimal;

    .line 2515
    .line 2516
    move-object/from16 v18, v4

    .line 2517
    .line 2518
    invoke-static/range {v20 .. v21}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 2519
    .line 2520
    .line 2521
    move-result-object v4

    .line 2522
    invoke-direct {v14, v4}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 2523
    .line 2524
    .line 2525
    invoke-direct {v3, v14, v8}, Lol0/a;-><init>(Ljava/math/BigDecimal;Ljava/lang/String;)V

    .line 2526
    .line 2527
    .line 2528
    goto :goto_3f

    .line 2529
    :cond_23
    move-object/from16 v16, v3

    .line 2530
    .line 2531
    move-object/from16 v18, v4

    .line 2532
    .line 2533
    move-object/from16 v3, v19

    .line 2534
    .line 2535
    :goto_3f
    invoke-direct {v15, v2, v0, v1, v3}, Lon0/w;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lol0/a;)V

    .line 2536
    .line 2537
    .line 2538
    invoke-virtual {v13, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2539
    .line 2540
    .line 2541
    move-object/from16 v0, p1

    .line 2542
    .line 2543
    move-object/from16 v3, v16

    .line 2544
    .line 2545
    move-object/from16 v1, v17

    .line 2546
    .line 2547
    move-object/from16 v4, v18

    .line 2548
    .line 2549
    const/16 v2, 0xa

    .line 2550
    .line 2551
    goto :goto_3c

    .line 2552
    :cond_24
    move-object/from16 p1, v0

    .line 2553
    .line 2554
    move-object/from16 v17, v1

    .line 2555
    .line 2556
    new-instance v0, Lon0/z;

    .line 2557
    .line 2558
    invoke-direct {v0, v10, v11, v12, v13}, Lon0/z;-><init>(Ljava/lang/String;Ljava/lang/String;Lon0/y;Ljava/util/List;)V

    .line 2559
    .line 2560
    .line 2561
    invoke-virtual {v7, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2562
    .line 2563
    .line 2564
    move-object/from16 v0, p1

    .line 2565
    .line 2566
    const/16 v2, 0xa

    .line 2567
    .line 2568
    goto/16 :goto_3a

    .line 2569
    .line 2570
    :cond_25
    move-object/from16 p1, v0

    .line 2571
    .line 2572
    move-object/from16 v18, v4

    .line 2573
    .line 2574
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getTermsAndConditions()Ljava/lang/String;

    .line 2575
    .line 2576
    .line 2577
    move-result-object v0

    .line 2578
    if-nez v0, :cond_26

    .line 2579
    .line 2580
    move-object/from16 v8, v18

    .line 2581
    .line 2582
    goto :goto_40

    .line 2583
    :cond_26
    move-object v8, v0

    .line 2584
    :goto_40
    invoke-virtual/range {p1 .. p1}, Lcz/myskoda/api/bff_fueling/v2/GasStationDto;->getCountryCode()Ljava/lang/String;

    .line 2585
    .line 2586
    .line 2587
    move-result-object v9

    .line 2588
    new-instance v4, Lon0/x;

    .line 2589
    .line 2590
    invoke-direct/range {v4 .. v9}, Lon0/x;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;)V

    .line 2591
    .line 2592
    .line 2593
    return-object v4

    .line 2594
    :pswitch_1b
    move-object/from16 v0, p1

    .line 2595
    .line 2596
    check-cast v0, Ljava/lang/String;

    .line 2597
    .line 2598
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2599
    .line 2600
    .line 2601
    invoke-static {v0}, Lkp/x;->b(Ljava/lang/String;)Lbm0/c;

    .line 2602
    .line 2603
    .line 2604
    move-result-object v0

    .line 2605
    return-object v0

    .line 2606
    :pswitch_1c
    move-object/from16 v0, p1

    .line 2607
    .line 2608
    check-cast v0, Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;

    .line 2609
    .line 2610
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2611
    .line 2612
    .line 2613
    invoke-static {v0}, Llp/wf;->c(Lcz/myskoda/api/bff_fueling/v2/FuelingSessionDto;)Lon0/e;

    .line 2614
    .line 2615
    .line 2616
    move-result-object v0

    .line 2617
    return-object v0

    .line 2618
    nop

    .line 2619
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
