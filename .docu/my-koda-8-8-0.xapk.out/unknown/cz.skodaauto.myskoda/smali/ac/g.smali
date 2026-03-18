.class public final synthetic Lac/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:I


# direct methods
.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lac/g;->d:I

    iput p1, p0, Lac/g;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lm1/t;I)V
    .locals 0

    .line 2
    const/4 p1, 0x5

    iput p1, p0, Lac/g;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Lac/g;->e:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 83

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lac/g;->d:I

    .line 4
    .line 5
    const-string v2, "Country selection index out of bounds: "

    .line 6
    .line 7
    const-string v3, "$this$log"

    .line 8
    .line 9
    const-string v5, "Failure, Retry after delay of "

    .line 10
    .line 11
    const/4 v7, 0x1

    .line 12
    iget v0, v0, Lac/g;->e:I

    .line 13
    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    move-object/from16 v1, p1

    .line 18
    .line 19
    check-cast v1, Llx0/l;

    .line 20
    .line 21
    const-string v2, "waypoint"

    .line 22
    .line 23
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v1, Ljava/lang/Number;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-ne v1, v0, :cond_0

    .line 35
    .line 36
    move v6, v7

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 v6, 0x0

    .line 39
    :goto_0
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    return-object v0

    .line 44
    :pswitch_0
    move-object/from16 v1, p1

    .line 45
    .line 46
    check-cast v1, Lgi/c;

    .line 47
    .line 48
    invoke-static {v0, v5}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    return-object v0

    .line 53
    :pswitch_1
    move-object/from16 v1, p1

    .line 54
    .line 55
    check-cast v1, Ljava/lang/Integer;

    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 58
    .line 59
    .line 60
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    .line 61
    .line 62
    new-instance v2, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v3, "Collection doesn\'t contain element at index "

    .line 65
    .line 66
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const/16 v0, 0x2e

    .line 73
    .line 74
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    invoke-direct {v1, v0}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw v1

    .line 85
    :pswitch_2
    move-object/from16 v1, p1

    .line 86
    .line 87
    check-cast v1, Lgi/c;

    .line 88
    .line 89
    const-string v1, "Retrying with "

    .line 90
    .line 91
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    return-object v0

    .line 96
    :pswitch_3
    move-object/from16 v1, p1

    .line 97
    .line 98
    check-cast v1, Lua/a;

    .line 99
    .line 100
    const-string v2, "_connection"

    .line 101
    .line 102
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    const-string v2, "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 ORDER BY last_enqueue_time LIMIT (SELECT MAX(?-COUNT(*), 0) FROM workspec WHERE schedule_requested_at<>-1 AND LENGTH(content_uri_triggers)=0 AND state NOT IN (2, 3, 5))"

    .line 106
    .line 107
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    int-to-long v2, v0

    .line 112
    :try_start_0
    invoke-interface {v1, v7, v2, v3}, Lua/c;->bindLong(IJ)V

    .line 113
    .line 114
    .line 115
    const-string v0, "id"

    .line 116
    .line 117
    invoke-static {v1, v0}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 118
    .line 119
    .line 120
    move-result v0

    .line 121
    const-string v2, "state"

    .line 122
    .line 123
    invoke-static {v1, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 124
    .line 125
    .line 126
    move-result v2

    .line 127
    const-string v3, "worker_class_name"

    .line 128
    .line 129
    invoke-static {v1, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 130
    .line 131
    .line 132
    move-result v3

    .line 133
    const-string v5, "input_merger_class_name"

    .line 134
    .line 135
    invoke-static {v1, v5}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    const-string v8, "input"

    .line 140
    .line 141
    invoke-static {v1, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 142
    .line 143
    .line 144
    move-result v8

    .line 145
    const-string v9, "output"

    .line 146
    .line 147
    invoke-static {v1, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 148
    .line 149
    .line 150
    move-result v9

    .line 151
    const-string v10, "initial_delay"

    .line 152
    .line 153
    invoke-static {v1, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 154
    .line 155
    .line 156
    move-result v10

    .line 157
    const-string v11, "interval_duration"

    .line 158
    .line 159
    invoke-static {v1, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 160
    .line 161
    .line 162
    move-result v11

    .line 163
    const-string v12, "flex_duration"

    .line 164
    .line 165
    invoke-static {v1, v12}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 166
    .line 167
    .line 168
    move-result v12

    .line 169
    const-string v13, "run_attempt_count"

    .line 170
    .line 171
    invoke-static {v1, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 172
    .line 173
    .line 174
    move-result v13

    .line 175
    const-string v14, "backoff_policy"

    .line 176
    .line 177
    invoke-static {v1, v14}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 178
    .line 179
    .line 180
    move-result v14

    .line 181
    const-string v15, "backoff_delay_duration"

    .line 182
    .line 183
    invoke-static {v1, v15}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 184
    .line 185
    .line 186
    move-result v15

    .line 187
    const-string v4, "last_enqueue_time"

    .line 188
    .line 189
    invoke-static {v1, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 190
    .line 191
    .line 192
    move-result v4

    .line 193
    const-string v6, "minimum_retention_duration"

    .line 194
    .line 195
    invoke-static {v1, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 196
    .line 197
    .line 198
    move-result v6

    .line 199
    const-string v7, "schedule_requested_at"

    .line 200
    .line 201
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 202
    .line 203
    .line 204
    move-result v7

    .line 205
    move/from16 p0, v7

    .line 206
    .line 207
    const-string v7, "run_in_foreground"

    .line 208
    .line 209
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 210
    .line 211
    .line 212
    move-result v7

    .line 213
    move/from16 p1, v7

    .line 214
    .line 215
    const-string v7, "out_of_quota_policy"

    .line 216
    .line 217
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 218
    .line 219
    .line 220
    move-result v7

    .line 221
    move/from16 v16, v7

    .line 222
    .line 223
    const-string v7, "period_count"

    .line 224
    .line 225
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 226
    .line 227
    .line 228
    move-result v7

    .line 229
    move/from16 v17, v7

    .line 230
    .line 231
    const-string v7, "generation"

    .line 232
    .line 233
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 234
    .line 235
    .line 236
    move-result v7

    .line 237
    move/from16 v18, v7

    .line 238
    .line 239
    const-string v7, "next_schedule_time_override"

    .line 240
    .line 241
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 242
    .line 243
    .line 244
    move-result v7

    .line 245
    move/from16 v19, v7

    .line 246
    .line 247
    const-string v7, "next_schedule_time_override_generation"

    .line 248
    .line 249
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 250
    .line 251
    .line 252
    move-result v7

    .line 253
    move/from16 v20, v7

    .line 254
    .line 255
    const-string v7, "stop_reason"

    .line 256
    .line 257
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 258
    .line 259
    .line 260
    move-result v7

    .line 261
    move/from16 v21, v7

    .line 262
    .line 263
    const-string v7, "trace_tag"

    .line 264
    .line 265
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 266
    .line 267
    .line 268
    move-result v7

    .line 269
    move/from16 v22, v7

    .line 270
    .line 271
    const-string v7, "backoff_on_system_interruptions"

    .line 272
    .line 273
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 274
    .line 275
    .line 276
    move-result v7

    .line 277
    move/from16 v23, v7

    .line 278
    .line 279
    const-string v7, "required_network_type"

    .line 280
    .line 281
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 282
    .line 283
    .line 284
    move-result v7

    .line 285
    move/from16 v24, v7

    .line 286
    .line 287
    const-string v7, "required_network_request"

    .line 288
    .line 289
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 290
    .line 291
    .line 292
    move-result v7

    .line 293
    move/from16 v25, v7

    .line 294
    .line 295
    const-string v7, "requires_charging"

    .line 296
    .line 297
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    move/from16 v26, v7

    .line 302
    .line 303
    const-string v7, "requires_device_idle"

    .line 304
    .line 305
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 306
    .line 307
    .line 308
    move-result v7

    .line 309
    move/from16 v27, v7

    .line 310
    .line 311
    const-string v7, "requires_battery_not_low"

    .line 312
    .line 313
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    move/from16 v28, v7

    .line 318
    .line 319
    const-string v7, "requires_storage_not_low"

    .line 320
    .line 321
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 322
    .line 323
    .line 324
    move-result v7

    .line 325
    move/from16 v29, v7

    .line 326
    .line 327
    const-string v7, "trigger_content_update_delay"

    .line 328
    .line 329
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 330
    .line 331
    .line 332
    move-result v7

    .line 333
    move/from16 v30, v7

    .line 334
    .line 335
    const-string v7, "trigger_max_content_delay"

    .line 336
    .line 337
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 338
    .line 339
    .line 340
    move-result v7

    .line 341
    move/from16 v31, v7

    .line 342
    .line 343
    const-string v7, "content_uri_triggers"

    .line 344
    .line 345
    invoke-static {v1, v7}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 346
    .line 347
    .line 348
    move-result v7

    .line 349
    move/from16 v32, v7

    .line 350
    .line 351
    new-instance v7, Ljava/util/ArrayList;

    .line 352
    .line 353
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 354
    .line 355
    .line 356
    :goto_1
    invoke-interface {v1}, Lua/c;->s0()Z

    .line 357
    .line 358
    .line 359
    move-result v33

    .line 360
    if-eqz v33, :cond_a

    .line 361
    .line 362
    invoke-interface {v1, v0}, Lua/c;->g0(I)Ljava/lang/String;

    .line 363
    .line 364
    .line 365
    move-result-object v35

    .line 366
    move/from16 v33, v6

    .line 367
    .line 368
    move-object/from16 v68, v7

    .line 369
    .line 370
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 371
    .line 372
    .line 373
    move-result-wide v6

    .line 374
    long-to-int v6, v6

    .line 375
    invoke-static {v6}, Ljp/z0;->g(I)Leb/h0;

    .line 376
    .line 377
    .line 378
    move-result-object v36

    .line 379
    invoke-interface {v1, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 380
    .line 381
    .line 382
    move-result-object v37

    .line 383
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v38

    .line 387
    invoke-interface {v1, v8}, Lua/c;->getBlob(I)[B

    .line 388
    .line 389
    .line 390
    move-result-object v6

    .line 391
    sget-object v7, Leb/h;->b:Leb/h;

    .line 392
    .line 393
    invoke-static {v6}, Lkp/b6;->b([B)Leb/h;

    .line 394
    .line 395
    .line 396
    move-result-object v39

    .line 397
    invoke-interface {v1, v9}, Lua/c;->getBlob(I)[B

    .line 398
    .line 399
    .line 400
    move-result-object v6

    .line 401
    invoke-static {v6}, Lkp/b6;->b([B)Leb/h;

    .line 402
    .line 403
    .line 404
    move-result-object v40

    .line 405
    invoke-interface {v1, v10}, Lua/c;->getLong(I)J

    .line 406
    .line 407
    .line 408
    move-result-wide v41

    .line 409
    invoke-interface {v1, v11}, Lua/c;->getLong(I)J

    .line 410
    .line 411
    .line 412
    move-result-wide v43

    .line 413
    invoke-interface {v1, v12}, Lua/c;->getLong(I)J

    .line 414
    .line 415
    .line 416
    move-result-wide v45

    .line 417
    invoke-interface {v1, v13}, Lua/c;->getLong(I)J

    .line 418
    .line 419
    .line 420
    move-result-wide v6

    .line 421
    long-to-int v6, v6

    .line 422
    move v7, v2

    .line 423
    move/from16 v69, v3

    .line 424
    .line 425
    invoke-interface {v1, v14}, Lua/c;->getLong(I)J

    .line 426
    .line 427
    .line 428
    move-result-wide v2

    .line 429
    long-to-int v2, v2

    .line 430
    invoke-static {v2}, Ljp/z0;->d(I)Leb/a;

    .line 431
    .line 432
    .line 433
    move-result-object v49

    .line 434
    invoke-interface {v1, v15}, Lua/c;->getLong(I)J

    .line 435
    .line 436
    .line 437
    move-result-wide v50

    .line 438
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 439
    .line 440
    .line 441
    move-result-wide v52

    .line 442
    move/from16 v2, v33

    .line 443
    .line 444
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 445
    .line 446
    .line 447
    move-result-wide v54

    .line 448
    move/from16 v3, p0

    .line 449
    .line 450
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 451
    .line 452
    .line 453
    move-result-wide v56

    .line 454
    move/from16 p0, v0

    .line 455
    .line 456
    move/from16 v33, v2

    .line 457
    .line 458
    move/from16 v0, p1

    .line 459
    .line 460
    move/from16 p1, v3

    .line 461
    .line 462
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 463
    .line 464
    .line 465
    move-result-wide v2

    .line 466
    long-to-int v2, v2

    .line 467
    if-eqz v2, :cond_1

    .line 468
    .line 469
    const/16 v58, 0x1

    .line 470
    .line 471
    :goto_2
    move/from16 v2, v16

    .line 472
    .line 473
    move/from16 v16, v4

    .line 474
    .line 475
    goto :goto_3

    .line 476
    :cond_1
    const/16 v58, 0x0

    .line 477
    .line 478
    goto :goto_2

    .line 479
    :goto_3
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 480
    .line 481
    .line 482
    move-result-wide v3

    .line 483
    long-to-int v3, v3

    .line 484
    invoke-static {v3}, Ljp/z0;->f(I)Leb/e0;

    .line 485
    .line 486
    .line 487
    move-result-object v59

    .line 488
    move/from16 v3, v17

    .line 489
    .line 490
    move/from16 v17, v5

    .line 491
    .line 492
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 493
    .line 494
    .line 495
    move-result-wide v4

    .line 496
    long-to-int v4, v4

    .line 497
    move/from16 v70, v3

    .line 498
    .line 499
    move/from16 v5, v18

    .line 500
    .line 501
    move/from16 v18, v2

    .line 502
    .line 503
    invoke-interface {v1, v5}, Lua/c;->getLong(I)J

    .line 504
    .line 505
    .line 506
    move-result-wide v2

    .line 507
    long-to-int v2, v2

    .line 508
    move/from16 v3, v19

    .line 509
    .line 510
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 511
    .line 512
    .line 513
    move-result-wide v62

    .line 514
    move/from16 v19, v0

    .line 515
    .line 516
    move/from16 v61, v2

    .line 517
    .line 518
    move/from16 v0, v20

    .line 519
    .line 520
    move/from16 v20, v3

    .line 521
    .line 522
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 523
    .line 524
    .line 525
    move-result-wide v2

    .line 526
    long-to-int v2, v2

    .line 527
    move/from16 v60, v4

    .line 528
    .line 529
    move/from16 v3, v21

    .line 530
    .line 531
    move/from16 v21, v5

    .line 532
    .line 533
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 534
    .line 535
    .line 536
    move-result-wide v4

    .line 537
    long-to-int v4, v4

    .line 538
    move/from16 v5, v22

    .line 539
    .line 540
    invoke-interface {v1, v5}, Lua/c;->isNull(I)Z

    .line 541
    .line 542
    .line 543
    move-result v22

    .line 544
    if-eqz v22, :cond_2

    .line 545
    .line 546
    const/16 v66, 0x0

    .line 547
    .line 548
    :goto_4
    move/from16 v22, v0

    .line 549
    .line 550
    move/from16 v0, v23

    .line 551
    .line 552
    goto :goto_5

    .line 553
    :cond_2
    invoke-interface {v1, v5}, Lua/c;->g0(I)Ljava/lang/String;

    .line 554
    .line 555
    .line 556
    move-result-object v22

    .line 557
    move-object/from16 v66, v22

    .line 558
    .line 559
    goto :goto_4

    .line 560
    :goto_5
    invoke-interface {v1, v0}, Lua/c;->isNull(I)Z

    .line 561
    .line 562
    .line 563
    move-result v23

    .line 564
    if-eqz v23, :cond_3

    .line 565
    .line 566
    move/from16 v64, v2

    .line 567
    .line 568
    move/from16 v23, v3

    .line 569
    .line 570
    const/4 v2, 0x0

    .line 571
    goto :goto_6

    .line 572
    :cond_3
    move/from16 v64, v2

    .line 573
    .line 574
    move/from16 v23, v3

    .line 575
    .line 576
    invoke-interface {v1, v0}, Lua/c;->getLong(I)J

    .line 577
    .line 578
    .line 579
    move-result-wide v2

    .line 580
    long-to-int v2, v2

    .line 581
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 582
    .line 583
    .line 584
    move-result-object v2

    .line 585
    :goto_6
    if-eqz v2, :cond_5

    .line 586
    .line 587
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 588
    .line 589
    .line 590
    move-result v2

    .line 591
    if-eqz v2, :cond_4

    .line 592
    .line 593
    const/4 v2, 0x1

    .line 594
    goto :goto_7

    .line 595
    :cond_4
    const/4 v2, 0x0

    .line 596
    :goto_7
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 597
    .line 598
    .line 599
    move-result-object v2

    .line 600
    move-object/from16 v67, v2

    .line 601
    .line 602
    :goto_8
    move/from16 v65, v4

    .line 603
    .line 604
    move/from16 v2, v24

    .line 605
    .line 606
    goto :goto_9

    .line 607
    :catchall_0
    move-exception v0

    .line 608
    goto/16 :goto_12

    .line 609
    .line 610
    :cond_5
    const/16 v67, 0x0

    .line 611
    .line 612
    goto :goto_8

    .line 613
    :goto_9
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 614
    .line 615
    .line 616
    move-result-wide v3

    .line 617
    long-to-int v3, v3

    .line 618
    invoke-static {v3}, Ljp/z0;->e(I)Leb/x;

    .line 619
    .line 620
    .line 621
    move-result-object v73

    .line 622
    move/from16 v3, v25

    .line 623
    .line 624
    invoke-interface {v1, v3}, Lua/c;->getBlob(I)[B

    .line 625
    .line 626
    .line 627
    move-result-object v4

    .line 628
    invoke-static {v4}, Ljp/z0;->m([B)Lnb/d;

    .line 629
    .line 630
    .line 631
    move-result-object v72

    .line 632
    move/from16 v24, v2

    .line 633
    .line 634
    move/from16 v25, v3

    .line 635
    .line 636
    move/from16 v4, v26

    .line 637
    .line 638
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 639
    .line 640
    .line 641
    move-result-wide v2

    .line 642
    long-to-int v2, v2

    .line 643
    if-eqz v2, :cond_6

    .line 644
    .line 645
    const/16 v74, 0x1

    .line 646
    .line 647
    :goto_a
    move/from16 v26, v4

    .line 648
    .line 649
    move/from16 v2, v27

    .line 650
    .line 651
    goto :goto_b

    .line 652
    :cond_6
    const/16 v74, 0x0

    .line 653
    .line 654
    goto :goto_a

    .line 655
    :goto_b
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 656
    .line 657
    .line 658
    move-result-wide v3

    .line 659
    long-to-int v3, v3

    .line 660
    if-eqz v3, :cond_7

    .line 661
    .line 662
    const/16 v75, 0x1

    .line 663
    .line 664
    :goto_c
    move/from16 v27, v5

    .line 665
    .line 666
    move/from16 v3, v28

    .line 667
    .line 668
    goto :goto_d

    .line 669
    :cond_7
    const/16 v75, 0x0

    .line 670
    .line 671
    goto :goto_c

    .line 672
    :goto_d
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 673
    .line 674
    .line 675
    move-result-wide v4

    .line 676
    long-to-int v4, v4

    .line 677
    if-eqz v4, :cond_8

    .line 678
    .line 679
    const/16 v76, 0x1

    .line 680
    .line 681
    :goto_e
    move v5, v2

    .line 682
    move/from16 v28, v3

    .line 683
    .line 684
    move/from16 v4, v29

    .line 685
    .line 686
    goto :goto_f

    .line 687
    :cond_8
    const/16 v76, 0x0

    .line 688
    .line 689
    goto :goto_e

    .line 690
    :goto_f
    invoke-interface {v1, v4}, Lua/c;->getLong(I)J

    .line 691
    .line 692
    .line 693
    move-result-wide v2

    .line 694
    long-to-int v2, v2

    .line 695
    if-eqz v2, :cond_9

    .line 696
    .line 697
    const/16 v77, 0x1

    .line 698
    .line 699
    :goto_10
    move/from16 v2, v30

    .line 700
    .line 701
    goto :goto_11

    .line 702
    :cond_9
    const/16 v77, 0x0

    .line 703
    .line 704
    goto :goto_10

    .line 705
    :goto_11
    invoke-interface {v1, v2}, Lua/c;->getLong(I)J

    .line 706
    .line 707
    .line 708
    move-result-wide v78

    .line 709
    move/from16 v3, v31

    .line 710
    .line 711
    invoke-interface {v1, v3}, Lua/c;->getLong(I)J

    .line 712
    .line 713
    .line 714
    move-result-wide v80

    .line 715
    move/from16 v29, v0

    .line 716
    .line 717
    move/from16 v0, v32

    .line 718
    .line 719
    invoke-interface {v1, v0}, Lua/c;->getBlob(I)[B

    .line 720
    .line 721
    .line 722
    move-result-object v30

    .line 723
    invoke-static/range {v30 .. v30}, Ljp/z0;->b([B)Ljava/util/LinkedHashSet;

    .line 724
    .line 725
    .line 726
    move-result-object v82

    .line 727
    new-instance v47, Leb/e;

    .line 728
    .line 729
    move-object/from16 v71, v47

    .line 730
    .line 731
    invoke-direct/range {v71 .. v82}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 732
    .line 733
    .line 734
    move-object/from16 v47, v71

    .line 735
    .line 736
    new-instance v34, Lmb/o;

    .line 737
    .line 738
    move/from16 v48, v6

    .line 739
    .line 740
    invoke-direct/range {v34 .. v67}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 741
    .line 742
    .line 743
    move-object/from16 v6, v34

    .line 744
    .line 745
    move/from16 v32, v0

    .line 746
    .line 747
    move-object/from16 v0, v68

    .line 748
    .line 749
    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 750
    .line 751
    .line 752
    move/from16 v6, v29

    .line 753
    .line 754
    move/from16 v29, v4

    .line 755
    .line 756
    move/from16 v4, v16

    .line 757
    .line 758
    move/from16 v16, v18

    .line 759
    .line 760
    move/from16 v18, v21

    .line 761
    .line 762
    move/from16 v21, v23

    .line 763
    .line 764
    move/from16 v23, v6

    .line 765
    .line 766
    move/from16 v30, v2

    .line 767
    .line 768
    move/from16 v31, v3

    .line 769
    .line 770
    move v2, v7

    .line 771
    move/from16 v6, v33

    .line 772
    .line 773
    move/from16 v3, v69

    .line 774
    .line 775
    move-object v7, v0

    .line 776
    move/from16 v0, p0

    .line 777
    .line 778
    move/from16 p0, p1

    .line 779
    .line 780
    move/from16 p1, v19

    .line 781
    .line 782
    move/from16 v19, v20

    .line 783
    .line 784
    move/from16 v20, v22

    .line 785
    .line 786
    move/from16 v22, v27

    .line 787
    .line 788
    move/from16 v27, v5

    .line 789
    .line 790
    move/from16 v5, v17

    .line 791
    .line 792
    move/from16 v17, v70

    .line 793
    .line 794
    goto/16 :goto_1

    .line 795
    .line 796
    :cond_a
    move-object v0, v7

    .line 797
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 798
    .line 799
    .line 800
    return-object v0

    .line 801
    :goto_12
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 802
    .line 803
    .line 804
    throw v0

    .line 805
    :pswitch_4
    move-object/from16 v1, p1

    .line 806
    .line 807
    check-cast v1, Lo1/j0;

    .line 808
    .line 809
    invoke-static {}, Lgv/a;->e()Lv2/f;

    .line 810
    .line 811
    .line 812
    move-result-object v2

    .line 813
    if-eqz v2, :cond_b

    .line 814
    .line 815
    invoke-virtual {v2}, Lv2/f;->e()Lay0/k;

    .line 816
    .line 817
    .line 818
    move-result-object v4

    .line 819
    goto :goto_13

    .line 820
    :cond_b
    const/4 v4, 0x0

    .line 821
    :goto_13
    invoke-static {v2}, Lgv/a;->j(Lv2/f;)Lv2/f;

    .line 822
    .line 823
    .line 824
    move-result-object v3

    .line 825
    invoke-static {v2, v3, v4}, Lgv/a;->p(Lv2/f;Lv2/f;Lay0/k;)V

    .line 826
    .line 827
    .line 828
    iget v2, v1, Lo1/j0;->a:I

    .line 829
    .line 830
    const/4 v3, -0x1

    .line 831
    if-ne v2, v3, :cond_c

    .line 832
    .line 833
    const/4 v2, 0x2

    .line 834
    :cond_c
    const/4 v6, 0x0

    .line 835
    :goto_14
    if-ge v6, v2, :cond_d

    .line 836
    .line 837
    add-int v3, v0, v6

    .line 838
    .line 839
    invoke-virtual {v1, v3}, Lo1/j0;->a(I)V

    .line 840
    .line 841
    .line 842
    add-int/lit8 v6, v6, 0x1

    .line 843
    .line 844
    goto :goto_14

    .line 845
    :cond_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 846
    .line 847
    return-object v0

    .line 848
    :pswitch_5
    move-object/from16 v1, p1

    .line 849
    .line 850
    check-cast v1, Lgi/c;

    .line 851
    .line 852
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    new-instance v1, Ljava/lang/StringBuilder;

    .line 856
    .line 857
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 858
    .line 859
    .line 860
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 861
    .line 862
    .line 863
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 864
    .line 865
    .line 866
    move-result-object v0

    .line 867
    return-object v0

    .line 868
    :pswitch_6
    move-object/from16 v1, p1

    .line 869
    .line 870
    check-cast v1, Lgi/c;

    .line 871
    .line 872
    invoke-static {v0, v5}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 873
    .line 874
    .line 875
    move-result-object v0

    .line 876
    return-object v0

    .line 877
    :pswitch_7
    move-object/from16 v1, p1

    .line 878
    .line 879
    check-cast v1, Ljava/lang/Integer;

    .line 880
    .line 881
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 882
    .line 883
    .line 884
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 885
    .line 886
    .line 887
    move-result-object v0

    .line 888
    return-object v0

    .line 889
    :pswitch_8
    move-object/from16 v1, p1

    .line 890
    .line 891
    check-cast v1, Lgi/c;

    .line 892
    .line 893
    invoke-static {v0, v5}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 894
    .line 895
    .line 896
    move-result-object v0

    .line 897
    return-object v0

    .line 898
    :pswitch_9
    move-object/from16 v1, p1

    .line 899
    .line 900
    check-cast v1, Lgi/c;

    .line 901
    .line 902
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    new-instance v1, Ljava/lang/StringBuilder;

    .line 906
    .line 907
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 911
    .line 912
    .line 913
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 914
    .line 915
    .line 916
    move-result-object v0

    .line 917
    return-object v0

    .line 918
    nop

    .line 919
    :pswitch_data_0
    .packed-switch 0x0
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
