.class public final Lhm/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lyl/r;


# direct methods
.method public constructor <init>(Lyl/r;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lhm/c;->a:Lyl/r;

    return-void
.end method

.method public constructor <init>(Lyl/r;Lhm/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lhm/c;->a:Lyl/r;

    return-void
.end method


# virtual methods
.method public a(Lmm/g;Lhm/a;Lnm/h;Lnm/g;)Lhm/b;
    .locals 17

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    iget-object v3, v0, Lmm/g;->i:Lmm/b;

    .line 8
    .line 9
    iget-object v4, v0, Lmm/g;->q:Lnm/d;

    .line 10
    .line 11
    iget-boolean v3, v3, Lmm/b;->d:Z

    .line 12
    .line 13
    if-nez v3, :cond_1

    .line 14
    .line 15
    :cond_0
    const/4 v2, 0x0

    .line 16
    goto/16 :goto_19

    .line 17
    .line 18
    :cond_1
    move-object/from16 v3, p0

    .line 19
    .line 20
    iget-object v3, v3, Lhm/c;->a:Lyl/r;

    .line 21
    .line 22
    invoke-virtual {v3}, Lyl/r;->c()Lhm/d;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    if-eqz v3, :cond_c

    .line 27
    .line 28
    iget-object v6, v3, Lhm/d;->c:Ljava/lang/Object;

    .line 29
    .line 30
    monitor-enter v6

    .line 31
    :try_start_0
    iget-object v7, v3, Lhm/d;->a:Lh6/j;

    .line 32
    .line 33
    iget-object v7, v7, Lh6/j;->f:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v7, Lc1/i2;

    .line 36
    .line 37
    iget-object v7, v7, Lc1/i2;->f:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v7, Ljava/util/LinkedHashMap;

    .line 40
    .line 41
    invoke-virtual {v7, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    check-cast v7, Lhm/e;

    .line 46
    .line 47
    const/4 v8, 0x0

    .line 48
    if-eqz v7, :cond_2

    .line 49
    .line 50
    new-instance v9, Lhm/b;

    .line 51
    .line 52
    iget-object v10, v7, Lhm/e;->a:Lyl/j;

    .line 53
    .line 54
    iget-object v7, v7, Lhm/e;->b:Ljava/util/Map;

    .line 55
    .line 56
    invoke-direct {v9, v10, v7}, Lhm/b;-><init>(Lyl/j;Ljava/util/Map;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    move-object v9, v8

    .line 61
    :goto_0
    const/4 v7, 0x0

    .line 62
    if-nez v9, :cond_7

    .line 63
    .line 64
    iget-object v9, v3, Lhm/d;->b:Lhm/g;

    .line 65
    .line 66
    iget-object v10, v9, Lhm/g;->a:Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    invoke-virtual {v10, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    check-cast v10, Ljava/util/ArrayList;

    .line 73
    .line 74
    if-nez v10, :cond_3

    .line 75
    .line 76
    move-object v9, v8

    .line 77
    goto :goto_4

    .line 78
    :cond_3
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 79
    .line 80
    .line 81
    move-result v11

    .line 82
    move v12, v7

    .line 83
    :goto_1
    if-ge v12, v11, :cond_6

    .line 84
    .line 85
    invoke-interface {v10, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v13

    .line 89
    check-cast v13, Lhm/f;

    .line 90
    .line 91
    iget-object v14, v13, Lhm/f;->a:Ljava/lang/ref/WeakReference;

    .line 92
    .line 93
    invoke-virtual {v14}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v14

    .line 97
    check-cast v14, Lyl/j;

    .line 98
    .line 99
    if-eqz v14, :cond_4

    .line 100
    .line 101
    new-instance v15, Lhm/b;

    .line 102
    .line 103
    iget-object v13, v13, Lhm/f;->b:Ljava/util/Map;

    .line 104
    .line 105
    invoke-direct {v15, v14, v13}, Lhm/b;-><init>(Lyl/j;Ljava/util/Map;)V

    .line 106
    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_4
    move-object v15, v8

    .line 110
    :goto_2
    if-eqz v15, :cond_5

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_5
    add-int/lit8 v12, v12, 0x1

    .line 114
    .line 115
    goto :goto_1

    .line 116
    :cond_6
    move-object v15, v8

    .line 117
    :goto_3
    invoke-virtual {v9}, Lhm/g;->b()V

    .line 118
    .line 119
    .line 120
    move-object v9, v15

    .line 121
    goto :goto_4

    .line 122
    :catchall_0
    move-exception v0

    .line 123
    goto :goto_7

    .line 124
    :cond_7
    :goto_4
    if-eqz v9, :cond_b

    .line 125
    .line 126
    iget-object v10, v9, Lhm/b;->a:Lyl/j;

    .line 127
    .line 128
    invoke-interface {v10}, Lyl/j;->b()Z

    .line 129
    .line 130
    .line 131
    move-result v10

    .line 132
    if-nez v10, :cond_b

    .line 133
    .line 134
    iget-object v10, v3, Lhm/d;->c:Ljava/lang/Object;

    .line 135
    .line 136
    monitor-enter v10
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 137
    :try_start_1
    iget-object v11, v3, Lhm/d;->a:Lh6/j;

    .line 138
    .line 139
    iget-object v11, v11, Lh6/j;->f:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v11, Lc1/i2;

    .line 142
    .line 143
    iget-object v12, v11, Lc1/i2;->f:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v12, Ljava/util/LinkedHashMap;

    .line 146
    .line 147
    invoke-interface {v12, v1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v12

    .line 151
    if-eqz v12, :cond_8

    .line 152
    .line 153
    invoke-virtual {v11}, Lc1/i2;->c()J

    .line 154
    .line 155
    .line 156
    move-result-wide v13

    .line 157
    invoke-virtual {v11, v1, v12}, Lc1/i2;->f(Ljava/lang/Object;Ljava/lang/Object;)J

    .line 158
    .line 159
    .line 160
    move-result-wide v15

    .line 161
    sub-long/2addr v13, v15

    .line 162
    iput-wide v13, v11, Lc1/i2;->e:J

    .line 163
    .line 164
    invoke-virtual {v11, v1, v12, v8}, Lc1/i2;->b(Ljava/lang/Object;Ljava/lang/Object;Lhm/e;)V

    .line 165
    .line 166
    .line 167
    :cond_8
    const/4 v8, 0x1

    .line 168
    if-eqz v12, :cond_9

    .line 169
    .line 170
    move v11, v8

    .line 171
    goto :goto_5

    .line 172
    :cond_9
    move v11, v7

    .line 173
    :goto_5
    iget-object v3, v3, Lhm/d;->b:Lhm/g;

    .line 174
    .line 175
    iget-object v3, v3, Lhm/g;->a:Ljava/util/LinkedHashMap;

    .line 176
    .line 177
    invoke-virtual {v3, v1}, Ljava/util/AbstractMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 181
    if-eqz v3, :cond_a

    .line 182
    .line 183
    move v7, v8

    .line 184
    :cond_a
    :try_start_2
    monitor-exit v10

    .line 185
    goto :goto_6

    .line 186
    :catchall_1
    move-exception v0

    .line 187
    monitor-exit v10

    .line 188
    throw v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 189
    :cond_b
    :goto_6
    monitor-exit v6

    .line 190
    goto :goto_8

    .line 191
    :goto_7
    monitor-exit v6

    .line 192
    throw v0

    .line 193
    :cond_c
    const/4 v9, 0x0

    .line 194
    :goto_8
    if-eqz v9, :cond_0

    .line 195
    .line 196
    iget-object v3, v9, Lhm/b;->a:Lyl/j;

    .line 197
    .line 198
    instance-of v6, v3, Lyl/a;

    .line 199
    .line 200
    if-eqz v6, :cond_d

    .line 201
    .line 202
    move-object v6, v3

    .line 203
    check-cast v6, Lyl/a;

    .line 204
    .line 205
    goto :goto_9

    .line 206
    :cond_d
    const/4 v6, 0x0

    .line 207
    :goto_9
    const/4 v7, 0x0

    .line 208
    if-nez v6, :cond_e

    .line 209
    .line 210
    goto :goto_a

    .line 211
    :cond_e
    iget-object v6, v6, Lyl/a;->a:Landroid/graphics/Bitmap;

    .line 212
    .line 213
    invoke-virtual {v6}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 214
    .line 215
    .line 216
    move-result-object v6

    .line 217
    if-nez v6, :cond_f

    .line 218
    .line 219
    sget-object v6, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 220
    .line 221
    :cond_f
    sget-object v8, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 222
    .line 223
    if-ne v6, v8, :cond_11

    .line 224
    .line 225
    sget-object v6, Lmm/i;->f:Ld8/c;

    .line 226
    .line 227
    invoke-static {v0, v6}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v6

    .line 231
    check-cast v6, Ljava/lang/Boolean;

    .line 232
    .line 233
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 234
    .line 235
    .line 236
    move-result v6

    .line 237
    if-nez v6, :cond_11

    .line 238
    .line 239
    :cond_10
    const/4 v2, 0x0

    .line 240
    goto/16 :goto_18

    .line 241
    .line 242
    :cond_11
    :goto_a
    iget-object v1, v1, Lhm/a;->b:Ljava/util/Map;

    .line 243
    .line 244
    const-string v6, "coil#size"

    .line 245
    .line 246
    invoke-interface {v1, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    check-cast v1, Ljava/lang/String;

    .line 251
    .line 252
    if-eqz v1, :cond_13

    .line 253
    .line 254
    invoke-virtual {v2}, Lnm/h;->toString()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 259
    .line 260
    .line 261
    move-result v0

    .line 262
    if-eqz v0, :cond_10

    .line 263
    .line 264
    :cond_12
    :goto_b
    const/4 v2, 0x0

    .line 265
    const/4 v6, 0x1

    .line 266
    goto/16 :goto_17

    .line 267
    .line 268
    :cond_13
    iget-object v1, v9, Lhm/b;->b:Ljava/util/Map;

    .line 269
    .line 270
    const-string v8, "coil#is_sampled"

    .line 271
    .line 272
    invoke-interface {v1, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    instance-of v8, v1, Ljava/lang/Boolean;

    .line 277
    .line 278
    if-eqz v8, :cond_14

    .line 279
    .line 280
    check-cast v1, Ljava/lang/Boolean;

    .line 281
    .line 282
    goto :goto_c

    .line 283
    :cond_14
    const/4 v1, 0x0

    .line 284
    :goto_c
    if-eqz v1, :cond_15

    .line 285
    .line 286
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 287
    .line 288
    .line 289
    move-result v1

    .line 290
    goto :goto_d

    .line 291
    :cond_15
    move v1, v7

    .line 292
    :goto_d
    if-nez v1, :cond_16

    .line 293
    .line 294
    sget-object v1, Lnm/h;->c:Lnm/h;

    .line 295
    .line 296
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 297
    .line 298
    .line 299
    move-result v1

    .line 300
    if-nez v1, :cond_12

    .line 301
    .line 302
    sget-object v1, Lnm/d;->e:Lnm/d;

    .line 303
    .line 304
    if-ne v4, v1, :cond_16

    .line 305
    .line 306
    goto :goto_b

    .line 307
    :cond_16
    invoke-interface {v3}, Lyl/j;->o()I

    .line 308
    .line 309
    .line 310
    move-result v1

    .line 311
    invoke-interface {v3}, Lyl/j;->m()I

    .line 312
    .line 313
    .line 314
    move-result v8

    .line 315
    instance-of v3, v3, Lyl/a;

    .line 316
    .line 317
    if-eqz v3, :cond_17

    .line 318
    .line 319
    sget-object v3, Lmm/h;->b:Ld8/c;

    .line 320
    .line 321
    invoke-static {v0, v3}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v0

    .line 325
    check-cast v0, Lnm/h;

    .line 326
    .line 327
    goto :goto_e

    .line 328
    :cond_17
    sget-object v0, Lnm/h;->c:Lnm/h;

    .line 329
    .line 330
    :goto_e
    iget-object v3, v2, Lnm/h;->a:Lnm/c;

    .line 331
    .line 332
    instance-of v10, v3, Lnm/a;

    .line 333
    .line 334
    const v11, 0x7fffffff

    .line 335
    .line 336
    .line 337
    if-eqz v10, :cond_18

    .line 338
    .line 339
    check-cast v3, Lnm/a;

    .line 340
    .line 341
    iget v3, v3, Lnm/a;->a:I

    .line 342
    .line 343
    goto :goto_f

    .line 344
    :cond_18
    move v3, v11

    .line 345
    :goto_f
    iget-object v10, v0, Lnm/h;->a:Lnm/c;

    .line 346
    .line 347
    instance-of v12, v10, Lnm/a;

    .line 348
    .line 349
    if-eqz v12, :cond_19

    .line 350
    .line 351
    check-cast v10, Lnm/a;

    .line 352
    .line 353
    iget v10, v10, Lnm/a;->a:I

    .line 354
    .line 355
    goto :goto_10

    .line 356
    :cond_19
    move v10, v11

    .line 357
    :goto_10
    invoke-static {v3, v10}, Ljava/lang/Math;->min(II)I

    .line 358
    .line 359
    .line 360
    move-result v3

    .line 361
    iget-object v2, v2, Lnm/h;->b:Lnm/c;

    .line 362
    .line 363
    instance-of v10, v2, Lnm/a;

    .line 364
    .line 365
    if-eqz v10, :cond_1a

    .line 366
    .line 367
    check-cast v2, Lnm/a;

    .line 368
    .line 369
    iget v2, v2, Lnm/a;->a:I

    .line 370
    .line 371
    goto :goto_11

    .line 372
    :cond_1a
    move v2, v11

    .line 373
    :goto_11
    iget-object v0, v0, Lnm/h;->b:Lnm/c;

    .line 374
    .line 375
    instance-of v10, v0, Lnm/a;

    .line 376
    .line 377
    if-eqz v10, :cond_1b

    .line 378
    .line 379
    check-cast v0, Lnm/a;

    .line 380
    .line 381
    iget v0, v0, Lnm/a;->a:I

    .line 382
    .line 383
    goto :goto_12

    .line 384
    :cond_1b
    move v0, v11

    .line 385
    :goto_12
    invoke-static {v2, v0}, Ljava/lang/Math;->min(II)I

    .line 386
    .line 387
    .line 388
    move-result v0

    .line 389
    int-to-double v12, v3

    .line 390
    int-to-double v14, v1

    .line 391
    div-double/2addr v12, v14

    .line 392
    int-to-double v14, v0

    .line 393
    const/4 v2, 0x0

    .line 394
    int-to-double v5, v8

    .line 395
    div-double/2addr v14, v5

    .line 396
    if-eq v3, v11, :cond_1c

    .line 397
    .line 398
    if-eq v0, v11, :cond_1c

    .line 399
    .line 400
    move-object/from16 v5, p4

    .line 401
    .line 402
    goto :goto_13

    .line 403
    :cond_1c
    sget-object v5, Lnm/g;->e:Lnm/g;

    .line 404
    .line 405
    :goto_13
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 406
    .line 407
    .line 408
    move-result v5

    .line 409
    if-eqz v5, :cond_1f

    .line 410
    .line 411
    const/4 v6, 0x1

    .line 412
    if-ne v5, v6, :cond_1e

    .line 413
    .line 414
    cmpg-double v5, v12, v14

    .line 415
    .line 416
    if-gez v5, :cond_1d

    .line 417
    .line 418
    sub-int/2addr v3, v1

    .line 419
    invoke-static {v3}, Ljava/lang/Math;->abs(I)I

    .line 420
    .line 421
    .line 422
    move-result v0

    .line 423
    :goto_14
    const/4 v6, 0x1

    .line 424
    goto :goto_16

    .line 425
    :cond_1d
    sub-int/2addr v0, v8

    .line 426
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    .line 427
    .line 428
    .line 429
    move-result v0

    .line 430
    :goto_15
    move-wide v12, v14

    .line 431
    goto :goto_14

    .line 432
    :cond_1e
    new-instance v0, La8/r0;

    .line 433
    .line 434
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 435
    .line 436
    .line 437
    throw v0

    .line 438
    :cond_1f
    cmpl-double v5, v12, v14

    .line 439
    .line 440
    if-lez v5, :cond_20

    .line 441
    .line 442
    sub-int/2addr v3, v1

    .line 443
    invoke-static {v3}, Ljava/lang/Math;->abs(I)I

    .line 444
    .line 445
    .line 446
    move-result v0

    .line 447
    goto :goto_14

    .line 448
    :cond_20
    sub-int/2addr v0, v8

    .line 449
    invoke-static {v0}, Ljava/lang/Math;->abs(I)I

    .line 450
    .line 451
    .line 452
    move-result v0

    .line 453
    goto :goto_15

    .line 454
    :goto_16
    if-gt v0, v6, :cond_21

    .line 455
    .line 456
    goto :goto_17

    .line 457
    :cond_21
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 458
    .line 459
    .line 460
    move-result v0

    .line 461
    const-wide/high16 v3, 0x3ff0000000000000L    # 1.0

    .line 462
    .line 463
    if-eqz v0, :cond_23

    .line 464
    .line 465
    if-ne v0, v6, :cond_22

    .line 466
    .line 467
    cmpg-double v0, v12, v3

    .line 468
    .line 469
    if-gtz v0, :cond_24

    .line 470
    .line 471
    goto :goto_17

    .line 472
    :cond_22
    new-instance v0, La8/r0;

    .line 473
    .line 474
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 475
    .line 476
    .line 477
    throw v0

    .line 478
    :cond_23
    cmpg-double v0, v12, v3

    .line 479
    .line 480
    if-nez v0, :cond_24

    .line 481
    .line 482
    :goto_17
    move v7, v6

    .line 483
    :cond_24
    :goto_18
    if-eqz v7, :cond_25

    .line 484
    .line 485
    return-object v9

    .line 486
    :cond_25
    :goto_19
    return-object v2
.end method

.method public b(Lmm/g;Ljava/lang/Object;Lmm/n;Lyl/f;)Lhm/a;
    .locals 7

    .line 1
    iget-object p4, p1, Lmm/g;->i:Lmm/b;

    .line 2
    .line 3
    iget-object v0, p1, Lmm/g;->d:Ljava/util/Map;

    .line 4
    .line 5
    sget-object v1, Lmm/b;->g:Lmm/b;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-ne p4, v1, :cond_0

    .line 9
    .line 10
    goto/16 :goto_4

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lhm/c;->a:Lyl/r;

    .line 13
    .line 14
    iget-object p0, p0, Lyl/r;->d:Lyl/d;

    .line 15
    .line 16
    iget-object p0, p0, Lyl/d;->c:Ljava/util/List;

    .line 17
    .line 18
    move-object p4, p0

    .line 19
    check-cast p4, Ljava/util/Collection;

    .line 20
    .line 21
    invoke-interface {p4}, Ljava/util/Collection;->size()I

    .line 22
    .line 23
    .line 24
    move-result p4

    .line 25
    const/4 v1, 0x0

    .line 26
    :goto_0
    if-ge v1, p4, :cond_5

    .line 27
    .line 28
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    check-cast v3, Llx0/l;

    .line 33
    .line 34
    iget-object v4, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v4, Lfm/a;

    .line 37
    .line 38
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v3, Lhy0/d;

    .line 41
    .line 42
    invoke-interface {v3, p2}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_4

    .line 47
    .line 48
    const-string v3, "null cannot be cast to non-null type coil3.key.Keyer<kotlin.Any>"

    .line 49
    .line 50
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    iget v3, v4, Lfm/a;->a:I

    .line 54
    .line 55
    packed-switch v3, :pswitch_data_0

    .line 56
    .line 57
    .line 58
    move-object v3, p2

    .line 59
    check-cast v3, Lyl/t;

    .line 60
    .line 61
    iget-object v3, v3, Lyl/t;->a:Ljava/lang/String;

    .line 62
    .line 63
    goto/16 :goto_2

    .line 64
    .line 65
    :pswitch_0
    move-object v3, p2

    .line 66
    check-cast v3, Lyl/t;

    .line 67
    .line 68
    iget-object v4, v3, Lyl/t;->c:Ljava/lang/String;

    .line 69
    .line 70
    const-string v5, "file"

    .line 71
    .line 72
    if-eqz v4, :cond_1

    .line 73
    .line 74
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    if-eqz v4, :cond_3

    .line 79
    .line 80
    :cond_1
    iget-object v4, v3, Lyl/t;->e:Ljava/lang/String;

    .line 81
    .line 82
    if-eqz v4, :cond_3

    .line 83
    .line 84
    sget-object v4, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 85
    .line 86
    iget-object v4, v3, Lyl/t;->c:Ljava/lang/String;

    .line 87
    .line 88
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    if-eqz v4, :cond_2

    .line 93
    .line 94
    invoke-static {v3}, Lyl/m;->g(Lyl/t;)Ljava/util/List;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-static {v4}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    const-string v5, "android_asset"

    .line 103
    .line 104
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v4

    .line 108
    if-eqz v4, :cond_2

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_2
    sget-object v4, Lmm/h;->c:Ld8/c;

    .line 112
    .line 113
    invoke-static {p3, v4}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    check-cast v4, Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_3

    .line 124
    .line 125
    invoke-static {v3}, Lyl/m;->f(Lyl/t;)Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    if-eqz v4, :cond_3

    .line 130
    .line 131
    iget-object v5, p3, Lmm/n;->f:Lu01/k;

    .line 132
    .line 133
    sget-object v6, Lu01/y;->e:Ljava/lang/String;

    .line 134
    .line 135
    invoke-static {v4}, Lrb0/a;->a(Ljava/lang/String;)Lu01/y;

    .line 136
    .line 137
    .line 138
    move-result-object v4

    .line 139
    invoke-virtual {v5, v4}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    iget-object v4, v4, Li5/f;->g:Ljava/io/Serializable;

    .line 144
    .line 145
    check-cast v4, Ljava/lang/Long;

    .line 146
    .line 147
    new-instance v5, Ljava/lang/StringBuilder;

    .line 148
    .line 149
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    const/16 v3, 0x2d

    .line 156
    .line 157
    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v3

    .line 167
    goto :goto_2

    .line 168
    :cond_3
    :goto_1
    move-object v3, v2

    .line 169
    goto :goto_2

    .line 170
    :pswitch_1
    move-object v3, p2

    .line 171
    check-cast v3, Lyl/t;

    .line 172
    .line 173
    iget-object v4, v3, Lyl/t;->c:Ljava/lang/String;

    .line 174
    .line 175
    const-string v5, "android.resource"

    .line 176
    .line 177
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-eqz v4, :cond_3

    .line 182
    .line 183
    new-instance v4, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 189
    .line 190
    .line 191
    const/16 v3, 0x3a

    .line 192
    .line 193
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 194
    .line 195
    .line 196
    iget-object v3, p3, Lmm/n;->a:Landroid/content/Context;

    .line 197
    .line 198
    invoke-virtual {v3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    invoke-virtual {v3}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 203
    .line 204
    .line 205
    move-result-object v3

    .line 206
    sget-object v5, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 207
    .line 208
    iget v3, v3, Landroid/content/res/Configuration;->uiMode:I

    .line 209
    .line 210
    and-int/lit8 v3, v3, 0x30

    .line 211
    .line 212
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 213
    .line 214
    .line 215
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    :goto_2
    if-eqz v3, :cond_4

    .line 220
    .line 221
    goto :goto_3

    .line 222
    :cond_4
    add-int/lit8 v1, v1, 0x1

    .line 223
    .line 224
    goto/16 :goto_0

    .line 225
    .line 226
    :cond_5
    move-object v3, v2

    .line 227
    :goto_3
    if-nez v3, :cond_6

    .line 228
    .line 229
    :goto_4
    return-object v2

    .line 230
    :cond_6
    sget-object p0, Lmm/h;->a:Ld8/c;

    .line 231
    .line 232
    invoke-static {p1, p0}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object p0

    .line 236
    check-cast p0, Ljava/util/List;

    .line 237
    .line 238
    check-cast p0, Ljava/util/Collection;

    .line 239
    .line 240
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    if-nez p0, :cond_7

    .line 245
    .line 246
    invoke-static {v0}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    iget-object p1, p3, Lmm/n;->b:Lnm/h;

    .line 251
    .line 252
    invoke-virtual {p1}, Lnm/h;->toString()Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object p1

    .line 256
    const-string p2, "coil#size"

    .line 257
    .line 258
    invoke-interface {p0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    new-instance p1, Lhm/a;

    .line 262
    .line 263
    invoke-direct {p1, v3, p0}, Lhm/a;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 264
    .line 265
    .line 266
    return-object p1

    .line 267
    :cond_7
    new-instance p0, Lhm/a;

    .line 268
    .line 269
    invoke-direct {p0, v3, v0}, Lhm/a;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    .line 270
    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(Lmm/g;Lnm/h;)Lmm/n;
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    new-instance v1, Lmm/n;

    .line 4
    .line 5
    move-object v2, v1

    .line 6
    iget-object v1, v0, Lmm/g;->a:Landroid/content/Context;

    .line 7
    .line 8
    iget-object v3, v0, Lmm/g;->p:Lnm/g;

    .line 9
    .line 10
    iget-object v4, v0, Lmm/g;->q:Lnm/d;

    .line 11
    .line 12
    iget-object v6, v0, Lmm/g;->e:Lu01/k;

    .line 13
    .line 14
    iget-object v7, v0, Lmm/g;->i:Lmm/b;

    .line 15
    .line 16
    iget-object v8, v0, Lmm/g;->j:Lmm/b;

    .line 17
    .line 18
    iget-object v9, v0, Lmm/g;->k:Lmm/b;

    .line 19
    .line 20
    sget-object v5, Lmm/i;->b:Ld8/c;

    .line 21
    .line 22
    invoke-static {v0, v5}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v10

    .line 26
    check-cast v10, Landroid/graphics/Bitmap$Config;

    .line 27
    .line 28
    sget-object v11, Lmm/i;->g:Ld8/c;

    .line 29
    .line 30
    invoke-static {v0, v11}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v12

    .line 34
    check-cast v12, Ljava/lang/Boolean;

    .line 35
    .line 36
    invoke-virtual {v12}, Ljava/lang/Boolean;->booleanValue()Z

    .line 37
    .line 38
    .line 39
    move-result v12

    .line 40
    sget-object v13, Lmm/h;->a:Ld8/c;

    .line 41
    .line 42
    invoke-static {v0, v13}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v14

    .line 46
    check-cast v14, Ljava/util/List;

    .line 47
    .line 48
    invoke-interface {v14}, Ljava/util/List;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result v14

    .line 52
    const/16 v16, 0x0

    .line 53
    .line 54
    if-nez v14, :cond_1

    .line 55
    .line 56
    sget-object v14, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 57
    .line 58
    invoke-static {v0, v5}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v17

    .line 62
    move-object/from16 v15, v17

    .line 63
    .line 64
    check-cast v15, Landroid/graphics/Bitmap$Config;

    .line 65
    .line 66
    invoke-static {v15, v14}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result v14

    .line 70
    if-eqz v14, :cond_0

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_0
    move/from16 v14, v16

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_1
    :goto_0
    const/4 v14, 0x1

    .line 77
    :goto_1
    invoke-static {v0, v5}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v15

    .line 81
    check-cast v15, Landroid/graphics/Bitmap$Config;

    .line 82
    .line 83
    move-object/from16 v17, v1

    .line 84
    .line 85
    sget-object v1, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 86
    .line 87
    if-ne v15, v1, :cond_2

    .line 88
    .line 89
    invoke-static {v0, v5}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v15

    .line 93
    check-cast v15, Landroid/graphics/Bitmap$Config;

    .line 94
    .line 95
    if-ne v15, v1, :cond_2

    .line 96
    .line 97
    sget-object v1, Lmm/i;->f:Ld8/c;

    .line 98
    .line 99
    invoke-static {v0, v1}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    check-cast v1, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_2

    .line 110
    .line 111
    move/from16 v1, v16

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_2
    const/4 v1, 0x1

    .line 115
    :goto_2
    if-eqz v14, :cond_3

    .line 116
    .line 117
    if-eqz v1, :cond_3

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_3
    sget-object v10, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 121
    .line 122
    :goto_3
    if-eqz v12, :cond_4

    .line 123
    .line 124
    invoke-static {v0, v13}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    check-cast v1, Ljava/util/List;

    .line 129
    .line 130
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_4

    .line 135
    .line 136
    sget-object v1, Landroid/graphics/Bitmap$Config;->ALPHA_8:Landroid/graphics/Bitmap$Config;

    .line 137
    .line 138
    if-eq v10, v1, :cond_4

    .line 139
    .line 140
    const/4 v15, 0x1

    .line 141
    goto :goto_4

    .line 142
    :cond_4
    move/from16 v15, v16

    .line 143
    .line 144
    :goto_4
    iget-object v1, v0, Lmm/g;->t:Lmm/e;

    .line 145
    .line 146
    iget-object v1, v1, Lmm/e;->n:Lyl/i;

    .line 147
    .line 148
    iget-object v1, v1, Lyl/i;->a:Ljava/util/Map;

    .line 149
    .line 150
    iget-object v12, v0, Lmm/g;->r:Lyl/i;

    .line 151
    .line 152
    iget-object v12, v12, Lyl/i;->a:Ljava/util/Map;

    .line 153
    .line 154
    invoke-static {v1, v12}, Lmx0/x;->p(Ljava/util/Map;Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    invoke-static {v1}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    .line 159
    .line 160
    .line 161
    move-result-object v1

    .line 162
    invoke-static {v0, v5}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v12

    .line 166
    check-cast v12, Landroid/graphics/Bitmap$Config;

    .line 167
    .line 168
    if-eq v10, v12, :cond_6

    .line 169
    .line 170
    if-eqz v10, :cond_5

    .line 171
    .line 172
    invoke-interface {v1, v5, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_5
    invoke-interface {v1, v5}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    :cond_6
    :goto_5
    invoke-static {v0, v11}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 180
    .line 181
    .line 182
    move-result-object v0

    .line 183
    check-cast v0, Ljava/lang/Boolean;

    .line 184
    .line 185
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 186
    .line 187
    .line 188
    move-result v0

    .line 189
    if-eq v15, v0, :cond_7

    .line 190
    .line 191
    invoke-static {v15}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    invoke-interface {v1, v11, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    :cond_7
    new-instance v10, Lyl/i;

    .line 199
    .line 200
    invoke-static {v1}, Lkp/g8;->d(Ljava/util/Map;)Ljava/util/Map;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    invoke-direct {v10, v0}, Lyl/i;-><init>(Ljava/util/Map;)V

    .line 205
    .line 206
    .line 207
    const/4 v5, 0x0

    .line 208
    move-object v0, v2

    .line 209
    move-object/from16 v1, v17

    .line 210
    .line 211
    move-object/from16 v2, p2

    .line 212
    .line 213
    invoke-direct/range {v0 .. v10}, Lmm/n;-><init>(Landroid/content/Context;Lnm/h;Lnm/g;Lnm/d;Ljava/lang/String;Lu01/k;Lmm/b;Lmm/b;Lmm/b;Lyl/i;)V

    .line 214
    .line 215
    .line 216
    return-object v0
.end method
