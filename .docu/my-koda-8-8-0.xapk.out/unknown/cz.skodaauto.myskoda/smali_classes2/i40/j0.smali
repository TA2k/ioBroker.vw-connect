.class public final synthetic Li40/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Li40/j0;->d:I

    iput-object p2, p0, Li40/j0;->e:Ljava/lang/Object;

    iput-object p3, p0, Li40/j0;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lh40/m3;)V
    .locals 1

    .line 2
    const/4 v0, 0x2

    iput v0, p0, Li40/j0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li40/j0;->f:Ljava/lang/Object;

    iput-object p2, p0, Li40/j0;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Li40/j0;->d:I

    .line 6
    .line 7
    const/4 v3, 0x4

    .line 8
    const v4, 0x799532c4

    .line 9
    .line 10
    .line 11
    const-wide v5, 0xffffffffL

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    const/4 v7, 0x7

    .line 17
    const/4 v10, 0x0

    .line 18
    packed-switch v2, :pswitch_data_0

    .line 19
    .line 20
    .line 21
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Ll2/a0;

    .line 24
    .line 25
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Landroidx/collection/r0;

    .line 28
    .line 29
    invoke-virtual {v2, v1}, Ll2/a0;->z(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object v0

    .line 40
    :pswitch_0
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v2, Lxh/e;

    .line 43
    .line 44
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Lay0/k;

    .line 47
    .line 48
    check-cast v1, Lhi/a;

    .line 49
    .line 50
    const-string v3, "$this$sdkViewModel"

    .line 51
    .line 52
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    const-class v3, Led/e;

    .line 56
    .line 57
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 58
    .line 59
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    check-cast v1, Lii/a;

    .line 64
    .line 65
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    move-object v5, v1

    .line 70
    check-cast v5, Led/e;

    .line 71
    .line 72
    new-instance v1, Lkd/p;

    .line 73
    .line 74
    new-instance v3, Ljd/b;

    .line 75
    .line 76
    const-class v6, Led/e;

    .line 77
    .line 78
    const-string v7, "getHomeChargingHistory"

    .line 79
    .line 80
    const-string v8, "getHomeChargingHistory-gIAlu-s(Lcariad/charging/multicharge/kitten/charginghistory/models/home/HomeChargingHistoryRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 81
    .line 82
    const/4 v9, 0x0

    .line 83
    const/4 v10, 0x1

    .line 84
    const/4 v4, 0x2

    .line 85
    invoke-direct/range {v3 .. v10}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 86
    .line 87
    .line 88
    invoke-direct {v1, v2, v0, v3}, Lkd/p;-><init>(Lxh/e;Lay0/k;Ljd/b;)V

    .line 89
    .line 90
    .line 91
    return-object v1

    .line 92
    :pswitch_1
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v2, Lvp/y1;

    .line 95
    .line 96
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lk4/f0;

    .line 99
    .line 100
    check-cast v1, Lk4/i0;

    .line 101
    .line 102
    iget-object v3, v2, Lvp/y1;->e:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast v3, Lnm0/b;

    .line 105
    .line 106
    monitor-enter v3

    .line 107
    :try_start_0
    invoke-interface {v1}, Lk4/i0;->h()Z

    .line 108
    .line 109
    .line 110
    move-result v4

    .line 111
    if-eqz v4, :cond_1

    .line 112
    .line 113
    iget-object v2, v2, Lvp/y1;->f:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v2, Landroidx/collection/w;

    .line 116
    .line 117
    invoke-virtual {v2, v0, v1}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    check-cast v0, Lk4/i0;

    .line 122
    .line 123
    goto :goto_0

    .line 124
    :catchall_0
    move-exception v0

    .line 125
    goto :goto_1

    .line 126
    :cond_1
    iget-object v1, v2, Lvp/y1;->f:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v1, Landroidx/collection/w;

    .line 129
    .line 130
    invoke-virtual {v1, v0}, Landroidx/collection/w;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    check-cast v0, Lk4/i0;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 135
    .line 136
    :goto_0
    monitor-exit v3

    .line 137
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 138
    .line 139
    return-object v0

    .line 140
    :goto_1
    monitor-exit v3

    .line 141
    throw v0

    .line 142
    :pswitch_2
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v2, Lk4/o;

    .line 145
    .line 146
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 147
    .line 148
    move-object v3, v0

    .line 149
    check-cast v3, Lk4/f0;

    .line 150
    .line 151
    move-object/from16 v19, v1

    .line 152
    .line 153
    check-cast v19, Lay0/k;

    .line 154
    .line 155
    iget-object v1, v2, Lk4/o;->d:Lk4/s;

    .line 156
    .line 157
    iget-object v4, v2, Lk4/o;->a:Lcq/r1;

    .line 158
    .line 159
    iget-object v5, v2, Lk4/o;->f:Li40/e1;

    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 162
    .line 163
    .line 164
    iget-object v0, v3, Lk4/f0;->a:Lk4/n;

    .line 165
    .line 166
    instance-of v6, v0, Lk4/q;

    .line 167
    .line 168
    if-nez v6, :cond_2

    .line 169
    .line 170
    const/4 v0, 0x0

    .line 171
    goto/16 :goto_22

    .line 172
    .line 173
    :cond_2
    check-cast v0, Lk4/q;

    .line 174
    .line 175
    iget-object v0, v0, Lk4/q;->i:Ljava/util/List;

    .line 176
    .line 177
    iget-object v6, v3, Lk4/f0;->b:Lk4/x;

    .line 178
    .line 179
    iget v7, v3, Lk4/f0;->c:I

    .line 180
    .line 181
    new-instance v10, Ljava/util/ArrayList;

    .line 182
    .line 183
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 184
    .line 185
    .line 186
    move-result v14

    .line 187
    invoke-direct {v10, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 188
    .line 189
    .line 190
    move-object v14, v0

    .line 191
    check-cast v14, Ljava/util/Collection;

    .line 192
    .line 193
    invoke-interface {v14}, Ljava/util/Collection;->size()I

    .line 194
    .line 195
    .line 196
    move-result v15

    .line 197
    const/4 v11, 0x0

    .line 198
    const/16 v16, 0x0

    .line 199
    .line 200
    :goto_2
    if-ge v11, v15, :cond_4

    .line 201
    .line 202
    invoke-interface {v0, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v8

    .line 206
    move-object/from16 v17, v8

    .line 207
    .line 208
    check-cast v17, Lk4/l;

    .line 209
    .line 210
    invoke-interface/range {v17 .. v17}, Lk4/l;->b()Lk4/x;

    .line 211
    .line 212
    .line 213
    move-result-object v12

    .line 214
    invoke-static {v12, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 215
    .line 216
    .line 217
    move-result v12

    .line 218
    if-eqz v12, :cond_3

    .line 219
    .line 220
    invoke-interface/range {v17 .. v17}, Lk4/l;->c()I

    .line 221
    .line 222
    .line 223
    move-result v12

    .line 224
    if-ne v12, v7, :cond_3

    .line 225
    .line 226
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    :cond_3
    add-int/lit8 v11, v11, 0x1

    .line 230
    .line 231
    goto :goto_2

    .line 232
    :cond_4
    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    .line 233
    .line 234
    .line 235
    move-result v8

    .line 236
    if-nez v8, :cond_5

    .line 237
    .line 238
    goto/16 :goto_14

    .line 239
    .line 240
    :cond_5
    new-instance v8, Ljava/util/ArrayList;

    .line 241
    .line 242
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 243
    .line 244
    .line 245
    move-result v10

    .line 246
    invoke-direct {v8, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 247
    .line 248
    .line 249
    invoke-interface {v14}, Ljava/util/Collection;->size()I

    .line 250
    .line 251
    .line 252
    move-result v10

    .line 253
    move/from16 v11, v16

    .line 254
    .line 255
    :goto_3
    if-ge v11, v10, :cond_7

    .line 256
    .line 257
    invoke-interface {v0, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v12

    .line 261
    move-object v14, v12

    .line 262
    check-cast v14, Lk4/l;

    .line 263
    .line 264
    invoke-interface {v14}, Lk4/l;->c()I

    .line 265
    .line 266
    .line 267
    move-result v14

    .line 268
    if-ne v14, v7, :cond_6

    .line 269
    .line 270
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    :cond_6
    add-int/lit8 v11, v11, 0x1

    .line 274
    .line 275
    goto :goto_3

    .line 276
    :cond_7
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 277
    .line 278
    .line 279
    move-result v7

    .line 280
    if-eqz v7, :cond_8

    .line 281
    .line 282
    goto :goto_4

    .line 283
    :cond_8
    move-object v0, v8

    .line 284
    :goto_4
    check-cast v0, Ljava/util/List;

    .line 285
    .line 286
    sget-object v7, Lk4/x;->f:Lk4/x;

    .line 287
    .line 288
    invoke-virtual {v6, v7}, Lk4/x;->a(Lk4/x;)I

    .line 289
    .line 290
    .line 291
    move-result v7

    .line 292
    iget v8, v6, Lk4/x;->d:I

    .line 293
    .line 294
    if-gez v7, :cond_11

    .line 295
    .line 296
    move-object v6, v0

    .line 297
    check-cast v6, Ljava/util/Collection;

    .line 298
    .line 299
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 300
    .line 301
    .line 302
    move-result v7

    .line 303
    move/from16 v10, v16

    .line 304
    .line 305
    const/4 v11, 0x0

    .line 306
    const/4 v12, 0x0

    .line 307
    :goto_5
    if-ge v10, v7, :cond_e

    .line 308
    .line 309
    invoke-interface {v0, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object v14

    .line 313
    check-cast v14, Lk4/l;

    .line 314
    .line 315
    invoke-interface {v14}, Lk4/l;->b()Lk4/x;

    .line 316
    .line 317
    .line 318
    move-result-object v14

    .line 319
    iget v15, v14, Lk4/x;->d:I

    .line 320
    .line 321
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 322
    .line 323
    .line 324
    move-result v17

    .line 325
    if-gez v17, :cond_a

    .line 326
    .line 327
    if-eqz v11, :cond_9

    .line 328
    .line 329
    iget v9, v11, Lk4/x;->d:I

    .line 330
    .line 331
    invoke-static {v15, v9}, Lkotlin/jvm/internal/m;->g(II)I

    .line 332
    .line 333
    .line 334
    move-result v9

    .line 335
    if-lez v9, :cond_c

    .line 336
    .line 337
    :cond_9
    move-object v11, v14

    .line 338
    goto :goto_6

    .line 339
    :cond_a
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 340
    .line 341
    .line 342
    move-result v9

    .line 343
    if-lez v9, :cond_d

    .line 344
    .line 345
    if-eqz v12, :cond_b

    .line 346
    .line 347
    iget v9, v12, Lk4/x;->d:I

    .line 348
    .line 349
    invoke-static {v15, v9}, Lkotlin/jvm/internal/m;->g(II)I

    .line 350
    .line 351
    .line 352
    move-result v9

    .line 353
    if-gez v9, :cond_c

    .line 354
    .line 355
    :cond_b
    move-object v12, v14

    .line 356
    :cond_c
    :goto_6
    add-int/lit8 v10, v10, 0x1

    .line 357
    .line 358
    goto :goto_5

    .line 359
    :cond_d
    move-object v11, v14

    .line 360
    move-object v12, v11

    .line 361
    :cond_e
    if-nez v11, :cond_f

    .line 362
    .line 363
    move-object v11, v12

    .line 364
    :cond_f
    new-instance v10, Ljava/util/ArrayList;

    .line 365
    .line 366
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 367
    .line 368
    .line 369
    move-result v7

    .line 370
    invoke-direct {v10, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 371
    .line 372
    .line 373
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 374
    .line 375
    .line 376
    move-result v6

    .line 377
    move/from16 v7, v16

    .line 378
    .line 379
    :goto_7
    if-ge v7, v6, :cond_2f

    .line 380
    .line 381
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 382
    .line 383
    .line 384
    move-result-object v8

    .line 385
    move-object v9, v8

    .line 386
    check-cast v9, Lk4/l;

    .line 387
    .line 388
    invoke-interface {v9}, Lk4/l;->b()Lk4/x;

    .line 389
    .line 390
    .line 391
    move-result-object v9

    .line 392
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    move-result v9

    .line 396
    if-eqz v9, :cond_10

    .line 397
    .line 398
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 399
    .line 400
    .line 401
    :cond_10
    add-int/lit8 v7, v7, 0x1

    .line 402
    .line 403
    goto :goto_7

    .line 404
    :cond_11
    sget-object v7, Lk4/x;->g:Lk4/x;

    .line 405
    .line 406
    invoke-virtual {v6, v7}, Lk4/x;->a(Lk4/x;)I

    .line 407
    .line 408
    .line 409
    move-result v6

    .line 410
    if-lez v6, :cond_1b

    .line 411
    .line 412
    move-object v6, v0

    .line 413
    check-cast v6, Ljava/util/Collection;

    .line 414
    .line 415
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 416
    .line 417
    .line 418
    move-result v7

    .line 419
    move/from16 v9, v16

    .line 420
    .line 421
    const/4 v10, 0x0

    .line 422
    const/4 v11, 0x0

    .line 423
    :goto_8
    if-ge v9, v7, :cond_17

    .line 424
    .line 425
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v12

    .line 429
    check-cast v12, Lk4/l;

    .line 430
    .line 431
    invoke-interface {v12}, Lk4/l;->b()Lk4/x;

    .line 432
    .line 433
    .line 434
    move-result-object v12

    .line 435
    iget v14, v12, Lk4/x;->d:I

    .line 436
    .line 437
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 438
    .line 439
    .line 440
    move-result v15

    .line 441
    if-gez v15, :cond_13

    .line 442
    .line 443
    if-eqz v10, :cond_12

    .line 444
    .line 445
    iget v15, v10, Lk4/x;->d:I

    .line 446
    .line 447
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 448
    .line 449
    .line 450
    move-result v14

    .line 451
    if-lez v14, :cond_15

    .line 452
    .line 453
    :cond_12
    move-object v10, v12

    .line 454
    goto :goto_9

    .line 455
    :cond_13
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 456
    .line 457
    .line 458
    move-result v15

    .line 459
    if-lez v15, :cond_16

    .line 460
    .line 461
    if-eqz v11, :cond_14

    .line 462
    .line 463
    iget v15, v11, Lk4/x;->d:I

    .line 464
    .line 465
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 466
    .line 467
    .line 468
    move-result v14

    .line 469
    if-gez v14, :cond_15

    .line 470
    .line 471
    :cond_14
    move-object v11, v12

    .line 472
    :cond_15
    :goto_9
    add-int/lit8 v9, v9, 0x1

    .line 473
    .line 474
    goto :goto_8

    .line 475
    :cond_16
    move-object v10, v12

    .line 476
    move-object v11, v10

    .line 477
    :cond_17
    if-nez v11, :cond_18

    .line 478
    .line 479
    goto :goto_a

    .line 480
    :cond_18
    move-object v10, v11

    .line 481
    :goto_a
    new-instance v7, Ljava/util/ArrayList;

    .line 482
    .line 483
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 484
    .line 485
    .line 486
    move-result v8

    .line 487
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 488
    .line 489
    .line 490
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 491
    .line 492
    .line 493
    move-result v6

    .line 494
    move/from16 v8, v16

    .line 495
    .line 496
    :goto_b
    if-ge v8, v6, :cond_1a

    .line 497
    .line 498
    invoke-interface {v0, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v9

    .line 502
    move-object v11, v9

    .line 503
    check-cast v11, Lk4/l;

    .line 504
    .line 505
    invoke-interface {v11}, Lk4/l;->b()Lk4/x;

    .line 506
    .line 507
    .line 508
    move-result-object v11

    .line 509
    invoke-static {v11, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 510
    .line 511
    .line 512
    move-result v11

    .line 513
    if-eqz v11, :cond_19

    .line 514
    .line 515
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 516
    .line 517
    .line 518
    :cond_19
    add-int/lit8 v8, v8, 0x1

    .line 519
    .line 520
    goto :goto_b

    .line 521
    :cond_1a
    move-object v10, v7

    .line 522
    goto/16 :goto_14

    .line 523
    .line 524
    :cond_1b
    move-object v6, v0

    .line 525
    check-cast v6, Ljava/util/Collection;

    .line 526
    .line 527
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 528
    .line 529
    .line 530
    move-result v9

    .line 531
    move/from16 v10, v16

    .line 532
    .line 533
    const/4 v11, 0x0

    .line 534
    const/4 v12, 0x0

    .line 535
    :goto_c
    if-ge v10, v9, :cond_22

    .line 536
    .line 537
    invoke-interface {v0, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    move-result-object v14

    .line 541
    check-cast v14, Lk4/l;

    .line 542
    .line 543
    invoke-interface {v14}, Lk4/l;->b()Lk4/x;

    .line 544
    .line 545
    .line 546
    move-result-object v14

    .line 547
    iget v15, v14, Lk4/x;->d:I

    .line 548
    .line 549
    iget v13, v7, Lk4/x;->d:I

    .line 550
    .line 551
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->g(II)I

    .line 552
    .line 553
    .line 554
    move-result v13

    .line 555
    if-lez v13, :cond_1c

    .line 556
    .line 557
    goto :goto_d

    .line 558
    :cond_1c
    iget v13, v14, Lk4/x;->d:I

    .line 559
    .line 560
    invoke-static {v13, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 561
    .line 562
    .line 563
    move-result v15

    .line 564
    if-gez v15, :cond_1e

    .line 565
    .line 566
    if-eqz v11, :cond_1d

    .line 567
    .line 568
    iget v15, v11, Lk4/x;->d:I

    .line 569
    .line 570
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 571
    .line 572
    .line 573
    move-result v13

    .line 574
    if-lez v13, :cond_20

    .line 575
    .line 576
    :cond_1d
    move-object v11, v14

    .line 577
    goto :goto_d

    .line 578
    :cond_1e
    invoke-static {v13, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 579
    .line 580
    .line 581
    move-result v15

    .line 582
    if-lez v15, :cond_21

    .line 583
    .line 584
    if-eqz v12, :cond_1f

    .line 585
    .line 586
    iget v15, v12, Lk4/x;->d:I

    .line 587
    .line 588
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 589
    .line 590
    .line 591
    move-result v13

    .line 592
    if-gez v13, :cond_20

    .line 593
    .line 594
    :cond_1f
    move-object v12, v14

    .line 595
    :cond_20
    :goto_d
    add-int/lit8 v10, v10, 0x1

    .line 596
    .line 597
    goto :goto_c

    .line 598
    :cond_21
    move-object v11, v14

    .line 599
    move-object v12, v11

    .line 600
    :cond_22
    if-nez v12, :cond_23

    .line 601
    .line 602
    goto :goto_e

    .line 603
    :cond_23
    move-object v11, v12

    .line 604
    :goto_e
    new-instance v10, Ljava/util/ArrayList;

    .line 605
    .line 606
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 607
    .line 608
    .line 609
    move-result v7

    .line 610
    invoke-direct {v10, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 611
    .line 612
    .line 613
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 614
    .line 615
    .line 616
    move-result v7

    .line 617
    move/from16 v9, v16

    .line 618
    .line 619
    :goto_f
    if-ge v9, v7, :cond_25

    .line 620
    .line 621
    invoke-interface {v0, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 622
    .line 623
    .line 624
    move-result-object v12

    .line 625
    move-object v13, v12

    .line 626
    check-cast v13, Lk4/l;

    .line 627
    .line 628
    invoke-interface {v13}, Lk4/l;->b()Lk4/x;

    .line 629
    .line 630
    .line 631
    move-result-object v13

    .line 632
    invoke-static {v13, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 633
    .line 634
    .line 635
    move-result v13

    .line 636
    if-eqz v13, :cond_24

    .line 637
    .line 638
    invoke-virtual {v10, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 639
    .line 640
    .line 641
    :cond_24
    add-int/lit8 v9, v9, 0x1

    .line 642
    .line 643
    goto :goto_f

    .line 644
    :cond_25
    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    .line 645
    .line 646
    .line 647
    move-result v7

    .line 648
    if-eqz v7, :cond_2f

    .line 649
    .line 650
    sget-object v7, Lk4/x;->g:Lk4/x;

    .line 651
    .line 652
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 653
    .line 654
    .line 655
    move-result v9

    .line 656
    move/from16 v10, v16

    .line 657
    .line 658
    const/4 v11, 0x0

    .line 659
    const/4 v12, 0x0

    .line 660
    :goto_10
    if-ge v10, v9, :cond_2c

    .line 661
    .line 662
    invoke-interface {v0, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object v13

    .line 666
    check-cast v13, Lk4/l;

    .line 667
    .line 668
    invoke-interface {v13}, Lk4/l;->b()Lk4/x;

    .line 669
    .line 670
    .line 671
    move-result-object v13

    .line 672
    if-eqz v7, :cond_26

    .line 673
    .line 674
    iget v14, v13, Lk4/x;->d:I

    .line 675
    .line 676
    iget v15, v7, Lk4/x;->d:I

    .line 677
    .line 678
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 679
    .line 680
    .line 681
    move-result v14

    .line 682
    if-gez v14, :cond_26

    .line 683
    .line 684
    goto :goto_11

    .line 685
    :cond_26
    iget v14, v13, Lk4/x;->d:I

    .line 686
    .line 687
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 688
    .line 689
    .line 690
    move-result v15

    .line 691
    if-gez v15, :cond_28

    .line 692
    .line 693
    if-eqz v11, :cond_27

    .line 694
    .line 695
    iget v15, v11, Lk4/x;->d:I

    .line 696
    .line 697
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 698
    .line 699
    .line 700
    move-result v14

    .line 701
    if-lez v14, :cond_2a

    .line 702
    .line 703
    :cond_27
    move-object v11, v13

    .line 704
    goto :goto_11

    .line 705
    :cond_28
    invoke-static {v14, v8}, Lkotlin/jvm/internal/m;->g(II)I

    .line 706
    .line 707
    .line 708
    move-result v15

    .line 709
    if-lez v15, :cond_2b

    .line 710
    .line 711
    if-eqz v12, :cond_29

    .line 712
    .line 713
    iget v15, v12, Lk4/x;->d:I

    .line 714
    .line 715
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 716
    .line 717
    .line 718
    move-result v14

    .line 719
    if-gez v14, :cond_2a

    .line 720
    .line 721
    :cond_29
    move-object v12, v13

    .line 722
    :cond_2a
    :goto_11
    add-int/lit8 v10, v10, 0x1

    .line 723
    .line 724
    goto :goto_10

    .line 725
    :cond_2b
    move-object v11, v13

    .line 726
    move-object v12, v11

    .line 727
    :cond_2c
    if-nez v12, :cond_2d

    .line 728
    .line 729
    goto :goto_12

    .line 730
    :cond_2d
    move-object v11, v12

    .line 731
    :goto_12
    new-instance v10, Ljava/util/ArrayList;

    .line 732
    .line 733
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 734
    .line 735
    .line 736
    move-result v7

    .line 737
    invoke-direct {v10, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 738
    .line 739
    .line 740
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 741
    .line 742
    .line 743
    move-result v6

    .line 744
    move/from16 v7, v16

    .line 745
    .line 746
    :goto_13
    if-ge v7, v6, :cond_2f

    .line 747
    .line 748
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 749
    .line 750
    .line 751
    move-result-object v8

    .line 752
    move-object v9, v8

    .line 753
    check-cast v9, Lk4/l;

    .line 754
    .line 755
    invoke-interface {v9}, Lk4/l;->b()Lk4/x;

    .line 756
    .line 757
    .line 758
    move-result-object v9

    .line 759
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 760
    .line 761
    .line 762
    move-result v9

    .line 763
    if-eqz v9, :cond_2e

    .line 764
    .line 765
    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 766
    .line 767
    .line 768
    :cond_2e
    add-int/lit8 v7, v7, 0x1

    .line 769
    .line 770
    goto :goto_13

    .line 771
    :cond_2f
    :goto_14
    iget-object v6, v1, Lk4/s;->a:Lil/g;

    .line 772
    .line 773
    invoke-interface {v10}, Ljava/util/Collection;->size()I

    .line 774
    .line 775
    .line 776
    move-result v7

    .line 777
    move/from16 v8, v16

    .line 778
    .line 779
    const/4 v9, 0x0

    .line 780
    :goto_15
    if-ge v8, v7, :cond_3e

    .line 781
    .line 782
    invoke-interface {v10, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 783
    .line 784
    .line 785
    move-result-object v0

    .line 786
    move-object v11, v0

    .line 787
    check-cast v11, Lk4/l;

    .line 788
    .line 789
    invoke-interface {v11}, Lk4/l;->a()I

    .line 790
    .line 791
    .line 792
    move-result v0

    .line 793
    if-nez v0, :cond_33

    .line 794
    .line 795
    iget-object v0, v6, Lil/g;->g:Ljava/lang/Object;

    .line 796
    .line 797
    move-object v7, v0

    .line 798
    check-cast v7, Lnm0/b;

    .line 799
    .line 800
    monitor-enter v7

    .line 801
    :try_start_1
    new-instance v0, Lk4/h;

    .line 802
    .line 803
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 804
    .line 805
    .line 806
    invoke-direct {v0, v11}, Lk4/h;-><init>(Lk4/l;)V

    .line 807
    .line 808
    .line 809
    iget-object v8, v6, Lil/g;->e:Ljava/lang/Object;

    .line 810
    .line 811
    check-cast v8, Landroidx/collection/w;

    .line 812
    .line 813
    invoke-virtual {v8, v0}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 814
    .line 815
    .line 816
    move-result-object v8

    .line 817
    check-cast v8, Lk4/g;

    .line 818
    .line 819
    if-nez v8, :cond_30

    .line 820
    .line 821
    iget-object v8, v6, Lil/g;->f:Ljava/lang/Object;

    .line 822
    .line 823
    check-cast v8, Landroidx/collection/q0;

    .line 824
    .line 825
    invoke-virtual {v8, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 826
    .line 827
    .line 828
    move-result-object v0

    .line 829
    move-object v8, v0

    .line 830
    check-cast v8, Lk4/g;

    .line 831
    .line 832
    goto :goto_16

    .line 833
    :catchall_1
    move-exception v0

    .line 834
    goto :goto_19

    .line 835
    :cond_30
    :goto_16
    if-eqz v8, :cond_31

    .line 836
    .line 837
    iget-object v0, v8, Lk4/g;->a:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 838
    .line 839
    monitor-exit v7

    .line 840
    goto :goto_18

    .line 841
    :cond_31
    monitor-exit v7

    .line 842
    :try_start_2
    invoke-virtual {v4, v11}, Lcq/r1;->e(Lk4/l;)Landroid/graphics/Typeface;

    .line 843
    .line 844
    .line 845
    move-result-object v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 846
    goto :goto_17

    .line 847
    :catch_0
    invoke-virtual {v5, v3}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    move-result-object v0

    .line 851
    :goto_17
    invoke-static {v6, v11, v4, v0}, Lil/g;->T(Lil/g;Lk4/l;Lcq/r1;Ljava/lang/Object;)V

    .line 852
    .line 853
    .line 854
    :goto_18
    if-nez v0, :cond_32

    .line 855
    .line 856
    invoke-virtual {v5, v3}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 857
    .line 858
    .line 859
    move-result-object v0

    .line 860
    :cond_32
    iget v5, v3, Lk4/f0;->d:I

    .line 861
    .line 862
    iget-object v6, v3, Lk4/f0;->b:Lk4/x;

    .line 863
    .line 864
    iget v7, v3, Lk4/f0;->c:I

    .line 865
    .line 866
    invoke-static {v5, v0, v11, v6, v7}, Llp/yc;->b(ILjava/lang/Object;Lk4/l;Lk4/x;I)Ljava/lang/Object;

    .line 867
    .line 868
    .line 869
    move-result-object v0

    .line 870
    new-instance v5, Llx0/l;

    .line 871
    .line 872
    invoke-direct {v5, v9, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 873
    .line 874
    .line 875
    goto/16 :goto_21

    .line 876
    .line 877
    :goto_19
    monitor-exit v7

    .line 878
    throw v0

    .line 879
    :cond_33
    const/4 v12, 0x1

    .line 880
    if-ne v0, v12, :cond_37

    .line 881
    .line 882
    iget-object v0, v6, Lil/g;->g:Ljava/lang/Object;

    .line 883
    .line 884
    move-object v12, v0

    .line 885
    check-cast v12, Lnm0/b;

    .line 886
    .line 887
    monitor-enter v12

    .line 888
    :try_start_3
    new-instance v0, Lk4/h;

    .line 889
    .line 890
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 891
    .line 892
    .line 893
    invoke-direct {v0, v11}, Lk4/h;-><init>(Lk4/l;)V

    .line 894
    .line 895
    .line 896
    iget-object v13, v6, Lil/g;->e:Ljava/lang/Object;

    .line 897
    .line 898
    check-cast v13, Landroidx/collection/w;

    .line 899
    .line 900
    invoke-virtual {v13, v0}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 901
    .line 902
    .line 903
    move-result-object v13

    .line 904
    check-cast v13, Lk4/g;

    .line 905
    .line 906
    if-nez v13, :cond_34

    .line 907
    .line 908
    iget-object v13, v6, Lil/g;->f:Ljava/lang/Object;

    .line 909
    .line 910
    check-cast v13, Landroidx/collection/q0;

    .line 911
    .line 912
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 913
    .line 914
    .line 915
    move-result-object v0

    .line 916
    move-object v13, v0

    .line 917
    check-cast v13, Lk4/g;

    .line 918
    .line 919
    goto :goto_1a

    .line 920
    :catchall_2
    move-exception v0

    .line 921
    goto :goto_1d

    .line 922
    :cond_34
    :goto_1a
    if-eqz v13, :cond_35

    .line 923
    .line 924
    iget-object v0, v13, Lk4/g;->a:Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 925
    .line 926
    monitor-exit v12

    .line 927
    goto :goto_1c

    .line 928
    :cond_35
    monitor-exit v12

    .line 929
    :try_start_4
    invoke-virtual {v4, v11}, Lcq/r1;->e(Lk4/l;)Landroid/graphics/Typeface;

    .line 930
    .line 931
    .line 932
    move-result-object v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 933
    goto :goto_1b

    .line 934
    :catchall_3
    move-exception v0

    .line 935
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 936
    .line 937
    .line 938
    move-result-object v0

    .line 939
    :goto_1b
    instance-of v12, v0, Llx0/n;

    .line 940
    .line 941
    if-eqz v12, :cond_36

    .line 942
    .line 943
    const/4 v0, 0x0

    .line 944
    :cond_36
    invoke-static {v6, v11, v4, v0}, Lil/g;->T(Lil/g;Lk4/l;Lcq/r1;Ljava/lang/Object;)V

    .line 945
    .line 946
    .line 947
    :goto_1c
    if-eqz v0, :cond_3b

    .line 948
    .line 949
    iget v5, v3, Lk4/f0;->d:I

    .line 950
    .line 951
    iget-object v6, v3, Lk4/f0;->b:Lk4/x;

    .line 952
    .line 953
    iget v7, v3, Lk4/f0;->c:I

    .line 954
    .line 955
    invoke-static {v5, v0, v11, v6, v7}, Llp/yc;->b(ILjava/lang/Object;Lk4/l;Lk4/x;I)Ljava/lang/Object;

    .line 956
    .line 957
    .line 958
    move-result-object v0

    .line 959
    new-instance v5, Llx0/l;

    .line 960
    .line 961
    invoke-direct {v5, v9, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 962
    .line 963
    .line 964
    goto/16 :goto_21

    .line 965
    .line 966
    :goto_1d
    monitor-exit v12

    .line 967
    throw v0

    .line 968
    :cond_37
    const/4 v12, 0x2

    .line 969
    if-ne v0, v12, :cond_3d

    .line 970
    .line 971
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 972
    .line 973
    .line 974
    new-instance v0, Lk4/h;

    .line 975
    .line 976
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 977
    .line 978
    .line 979
    invoke-direct {v0, v11}, Lk4/h;-><init>(Lk4/l;)V

    .line 980
    .line 981
    .line 982
    iget-object v12, v6, Lil/g;->g:Ljava/lang/Object;

    .line 983
    .line 984
    check-cast v12, Lnm0/b;

    .line 985
    .line 986
    monitor-enter v12

    .line 987
    :try_start_5
    iget-object v13, v6, Lil/g;->e:Ljava/lang/Object;

    .line 988
    .line 989
    check-cast v13, Landroidx/collection/w;

    .line 990
    .line 991
    invoke-virtual {v13, v0}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 992
    .line 993
    .line 994
    move-result-object v13

    .line 995
    check-cast v13, Lk4/g;

    .line 996
    .line 997
    if-nez v13, :cond_38

    .line 998
    .line 999
    iget-object v13, v6, Lil/g;->f:Ljava/lang/Object;

    .line 1000
    .line 1001
    check-cast v13, Landroidx/collection/q0;

    .line 1002
    .line 1003
    invoke-virtual {v13, v0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1004
    .line 1005
    .line 1006
    move-result-object v0

    .line 1007
    move-object v13, v0

    .line 1008
    check-cast v13, Lk4/g;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 1009
    .line 1010
    goto :goto_1e

    .line 1011
    :catchall_4
    move-exception v0

    .line 1012
    goto :goto_20

    .line 1013
    :cond_38
    :goto_1e
    monitor-exit v12

    .line 1014
    if-nez v13, :cond_3a

    .line 1015
    .line 1016
    if-nez v9, :cond_39

    .line 1017
    .line 1018
    const/4 v12, 0x1

    .line 1019
    new-array v0, v12, [Lk4/l;

    .line 1020
    .line 1021
    aput-object v11, v0, v16

    .line 1022
    .line 1023
    invoke-static {v0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v0

    .line 1027
    move-object v9, v0

    .line 1028
    goto :goto_1f

    .line 1029
    :cond_39
    invoke-interface {v9, v11}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 1030
    .line 1031
    .line 1032
    goto :goto_1f

    .line 1033
    :cond_3a
    iget-object v0, v13, Lk4/g;->a:Ljava/lang/Object;

    .line 1034
    .line 1035
    if-nez v0, :cond_3c

    .line 1036
    .line 1037
    :cond_3b
    :goto_1f
    add-int/lit8 v8, v8, 0x1

    .line 1038
    .line 1039
    goto/16 :goto_15

    .line 1040
    .line 1041
    :cond_3c
    iget v5, v3, Lk4/f0;->d:I

    .line 1042
    .line 1043
    iget-object v6, v3, Lk4/f0;->b:Lk4/x;

    .line 1044
    .line 1045
    iget v7, v3, Lk4/f0;->c:I

    .line 1046
    .line 1047
    invoke-static {v5, v0, v11, v6, v7}, Llp/yc;->b(ILjava/lang/Object;Lk4/l;Lk4/x;I)Ljava/lang/Object;

    .line 1048
    .line 1049
    .line 1050
    move-result-object v0

    .line 1051
    new-instance v5, Llx0/l;

    .line 1052
    .line 1053
    invoke-direct {v5, v9, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1054
    .line 1055
    .line 1056
    goto :goto_21

    .line 1057
    :goto_20
    monitor-exit v12

    .line 1058
    throw v0

    .line 1059
    :cond_3d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1060
    .line 1061
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1062
    .line 1063
    const-string v2, "Unknown font type "

    .line 1064
    .line 1065
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1066
    .line 1067
    .line 1068
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1069
    .line 1070
    .line 1071
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1072
    .line 1073
    .line 1074
    move-result-object v1

    .line 1075
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1076
    .line 1077
    .line 1078
    throw v0

    .line 1079
    :cond_3e
    invoke-virtual {v5, v3}, Li40/e1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1080
    .line 1081
    .line 1082
    move-result-object v0

    .line 1083
    new-instance v5, Llx0/l;

    .line 1084
    .line 1085
    invoke-direct {v5, v9, v0}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 1086
    .line 1087
    .line 1088
    :goto_21
    iget-object v0, v5, Llx0/l;->d:Ljava/lang/Object;

    .line 1089
    .line 1090
    move-object v15, v0

    .line 1091
    check-cast v15, Ljava/util/List;

    .line 1092
    .line 1093
    iget-object v0, v5, Llx0/l;->e:Ljava/lang/Object;

    .line 1094
    .line 1095
    if-nez v15, :cond_3f

    .line 1096
    .line 1097
    new-instance v1, Lk4/h0;

    .line 1098
    .line 1099
    const/4 v12, 0x1

    .line 1100
    invoke-direct {v1, v0, v12}, Lk4/h0;-><init>(Ljava/lang/Object;Z)V

    .line 1101
    .line 1102
    .line 1103
    move-object v0, v1

    .line 1104
    goto :goto_22

    .line 1105
    :cond_3f
    const/4 v12, 0x1

    .line 1106
    new-instance v14, Lk4/f;

    .line 1107
    .line 1108
    iget-object v5, v1, Lk4/s;->a:Lil/g;

    .line 1109
    .line 1110
    move-object/from16 v16, v0

    .line 1111
    .line 1112
    move-object/from16 v17, v3

    .line 1113
    .line 1114
    move-object/from16 v20, v4

    .line 1115
    .line 1116
    move-object/from16 v18, v5

    .line 1117
    .line 1118
    invoke-direct/range {v14 .. v20}, Lk4/f;-><init>(Ljava/util/List;Ljava/lang/Object;Lk4/f0;Lil/g;Lay0/k;Lcq/r1;)V

    .line 1119
    .line 1120
    .line 1121
    iget-object v0, v1, Lk4/s;->b:Lpw0/a;

    .line 1122
    .line 1123
    sget-object v1, Lvy0/c0;->g:Lvy0/c0;

    .line 1124
    .line 1125
    new-instance v4, Lk20/a;

    .line 1126
    .line 1127
    const/4 v5, 0x3

    .line 1128
    const/4 v6, 0x0

    .line 1129
    invoke-direct {v4, v14, v6, v5}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 1130
    .line 1131
    .line 1132
    invoke-static {v0, v6, v1, v4, v12}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1133
    .line 1134
    .line 1135
    new-instance v0, Lk4/g0;

    .line 1136
    .line 1137
    invoke-direct {v0, v14}, Lk4/g0;-><init>(Lk4/f;)V

    .line 1138
    .line 1139
    .line 1140
    :goto_22
    if-nez v0, :cond_44

    .line 1141
    .line 1142
    iget-object v0, v2, Lk4/o;->e:Lj1/a;

    .line 1143
    .line 1144
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 1145
    .line 1146
    iget-object v0, v3, Lk4/f0;->a:Lk4/n;

    .line 1147
    .line 1148
    iget v1, v3, Lk4/f0;->c:I

    .line 1149
    .line 1150
    iget-object v2, v3, Lk4/f0;->b:Lk4/x;

    .line 1151
    .line 1152
    if-eqz v0, :cond_40

    .line 1153
    .line 1154
    instance-of v3, v0, Lk4/j;

    .line 1155
    .line 1156
    if-eqz v3, :cond_41

    .line 1157
    .line 1158
    :cond_40
    const/4 v6, 0x0

    .line 1159
    goto :goto_23

    .line 1160
    :cond_41
    instance-of v3, v0, Lk4/z;

    .line 1161
    .line 1162
    if-eqz v3, :cond_42

    .line 1163
    .line 1164
    check-cast v0, Lk4/z;

    .line 1165
    .line 1166
    iget-object v0, v0, Lk4/z;->i:Ljava/lang/String;

    .line 1167
    .line 1168
    invoke-static {v0, v2, v1}, Let/d;->b(Ljava/lang/String;Lk4/x;I)Landroid/graphics/Typeface;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v0

    .line 1172
    goto :goto_24

    .line 1173
    :cond_42
    const/4 v12, 0x0

    .line 1174
    goto :goto_25

    .line 1175
    :goto_23
    invoke-static {v6, v2, v1}, Let/d;->b(Ljava/lang/String;Lk4/x;I)Landroid/graphics/Typeface;

    .line 1176
    .line 1177
    .line 1178
    move-result-object v0

    .line 1179
    :goto_24
    new-instance v12, Lk4/h0;

    .line 1180
    .line 1181
    const/4 v1, 0x1

    .line 1182
    invoke-direct {v12, v0, v1}, Lk4/h0;-><init>(Ljava/lang/Object;Z)V

    .line 1183
    .line 1184
    .line 1185
    :goto_25
    if-eqz v12, :cond_43

    .line 1186
    .line 1187
    move-object v0, v12

    .line 1188
    goto :goto_26

    .line 1189
    :cond_43
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1190
    .line 1191
    const-string v1, "Could not load font"

    .line 1192
    .line 1193
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1194
    .line 1195
    .line 1196
    throw v0

    .line 1197
    :cond_44
    :goto_26
    return-object v0

    .line 1198
    :pswitch_3
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1199
    .line 1200
    check-cast v2, Lk1/r1;

    .line 1201
    .line 1202
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1203
    .line 1204
    check-cast v0, Landroid/view/View;

    .line 1205
    .line 1206
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 1207
    .line 1208
    iget-object v1, v2, Lk1/r1;->u:Lk1/m0;

    .line 1209
    .line 1210
    iget v3, v2, Lk1/r1;->t:I

    .line 1211
    .line 1212
    if-nez v3, :cond_46

    .line 1213
    .line 1214
    sget-object v3, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 1215
    .line 1216
    invoke-static {v0, v1}, Ld6/k0;->j(Landroid/view/View;Ld6/s;)V

    .line 1217
    .line 1218
    .line 1219
    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 1220
    .line 1221
    .line 1222
    move-result v3

    .line 1223
    if-eqz v3, :cond_45

    .line 1224
    .line 1225
    invoke-virtual {v0}, Landroid/view/View;->requestApplyInsets()V

    .line 1226
    .line 1227
    .line 1228
    :cond_45
    invoke-virtual {v0, v1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 1229
    .line 1230
    .line 1231
    invoke-static {v0, v1}, Ld6/r0;->k(Landroid/view/View;Landroidx/datastore/preferences/protobuf/k;)V

    .line 1232
    .line 1233
    .line 1234
    :cond_46
    iget v1, v2, Lk1/r1;->t:I

    .line 1235
    .line 1236
    const/16 v21, 0x1

    .line 1237
    .line 1238
    add-int/lit8 v1, v1, 0x1

    .line 1239
    .line 1240
    iput v1, v2, Lk1/r1;->t:I

    .line 1241
    .line 1242
    new-instance v1, Laa/t;

    .line 1243
    .line 1244
    invoke-direct {v1, v7, v2, v0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1245
    .line 1246
    .line 1247
    return-object v1

    .line 1248
    :pswitch_4
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1249
    .line 1250
    check-cast v2, Lk1/y0;

    .line 1251
    .line 1252
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1253
    .line 1254
    check-cast v0, Lt3/e1;

    .line 1255
    .line 1256
    check-cast v1, Lt3/d1;

    .line 1257
    .line 1258
    iget-boolean v3, v2, Lk1/y0;->v:Z

    .line 1259
    .line 1260
    if-eqz v3, :cond_47

    .line 1261
    .line 1262
    iget v3, v2, Lk1/y0;->r:F

    .line 1263
    .line 1264
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 1265
    .line 1266
    .line 1267
    move-result v3

    .line 1268
    iget v2, v2, Lk1/y0;->s:F

    .line 1269
    .line 1270
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 1271
    .line 1272
    .line 1273
    move-result v2

    .line 1274
    invoke-static {v1, v0, v3, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 1275
    .line 1276
    .line 1277
    goto :goto_27

    .line 1278
    :cond_47
    iget v3, v2, Lk1/y0;->r:F

    .line 1279
    .line 1280
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 1281
    .line 1282
    .line 1283
    move-result v3

    .line 1284
    iget v2, v2, Lk1/y0;->s:F

    .line 1285
    .line 1286
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 1287
    .line 1288
    .line 1289
    move-result v2

    .line 1290
    invoke-virtual {v1, v0, v3, v2, v10}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 1291
    .line 1292
    .line 1293
    :goto_27
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1294
    .line 1295
    return-object v0

    .line 1296
    :pswitch_5
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1297
    .line 1298
    check-cast v2, Lk1/x0;

    .line 1299
    .line 1300
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1301
    .line 1302
    move-object v8, v0

    .line 1303
    check-cast v8, Lt3/e1;

    .line 1304
    .line 1305
    move-object v7, v1

    .line 1306
    check-cast v7, Lt3/d1;

    .line 1307
    .line 1308
    iget-object v0, v2, Lk1/x0;->r:Lay0/k;

    .line 1309
    .line 1310
    invoke-interface {v0, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1311
    .line 1312
    .line 1313
    move-result-object v0

    .line 1314
    check-cast v0, Lt4/j;

    .line 1315
    .line 1316
    iget-wide v0, v0, Lt4/j;->a:J

    .line 1317
    .line 1318
    iget-boolean v2, v2, Lk1/x0;->s:Z

    .line 1319
    .line 1320
    const/16 v3, 0x20

    .line 1321
    .line 1322
    if-eqz v2, :cond_48

    .line 1323
    .line 1324
    shr-long v2, v0, v3

    .line 1325
    .line 1326
    long-to-int v2, v2

    .line 1327
    and-long/2addr v0, v5

    .line 1328
    long-to-int v0, v0

    .line 1329
    invoke-static {v7, v8, v2, v0}, Lt3/d1;->p(Lt3/d1;Lt3/e1;II)V

    .line 1330
    .line 1331
    .line 1332
    goto :goto_28

    .line 1333
    :cond_48
    shr-long v2, v0, v3

    .line 1334
    .line 1335
    long-to-int v9, v2

    .line 1336
    and-long/2addr v0, v5

    .line 1337
    long-to-int v10, v0

    .line 1338
    const/4 v11, 0x0

    .line 1339
    const/16 v12, 0xc

    .line 1340
    .line 1341
    invoke-static/range {v7 .. v12}, Lt3/d1;->z(Lt3/d1;Lt3/e1;IILay0/k;I)V

    .line 1342
    .line 1343
    .line 1344
    :goto_28
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1345
    .line 1346
    return-object v0

    .line 1347
    :pswitch_6
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1348
    .line 1349
    check-cast v2, Lk1/w0;

    .line 1350
    .line 1351
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1352
    .line 1353
    check-cast v0, Lt3/e1;

    .line 1354
    .line 1355
    check-cast v1, Lt3/d1;

    .line 1356
    .line 1357
    iget-boolean v3, v2, Lk1/w0;->t:Z

    .line 1358
    .line 1359
    if-eqz v3, :cond_49

    .line 1360
    .line 1361
    iget v3, v2, Lk1/w0;->r:F

    .line 1362
    .line 1363
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 1364
    .line 1365
    .line 1366
    move-result v3

    .line 1367
    iget v2, v2, Lk1/w0;->s:F

    .line 1368
    .line 1369
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 1370
    .line 1371
    .line 1372
    move-result v2

    .line 1373
    invoke-static {v1, v0, v3, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 1374
    .line 1375
    .line 1376
    goto :goto_29

    .line 1377
    :cond_49
    iget v3, v2, Lk1/w0;->r:F

    .line 1378
    .line 1379
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 1380
    .line 1381
    .line 1382
    move-result v3

    .line 1383
    iget v2, v2, Lk1/w0;->s:F

    .line 1384
    .line 1385
    invoke-interface {v1, v2}, Lt4/c;->Q(F)I

    .line 1386
    .line 1387
    .line 1388
    move-result v2

    .line 1389
    invoke-virtual {v1, v0, v3, v2, v10}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 1390
    .line 1391
    .line 1392
    :goto_29
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1393
    .line 1394
    return-object v0

    .line 1395
    :pswitch_7
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1396
    .line 1397
    check-cast v2, Ljz/h;

    .line 1398
    .line 1399
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1400
    .line 1401
    check-cast v0, Ljz/i;

    .line 1402
    .line 1403
    check-cast v1, Lua/a;

    .line 1404
    .line 1405
    const-string v3, "_connection"

    .line 1406
    .line 1407
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1408
    .line 1409
    .line 1410
    iget-object v2, v2, Ljz/h;->b:Las0/h;

    .line 1411
    .line 1412
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1413
    .line 1414
    .line 1415
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1416
    .line 1417
    return-object v0

    .line 1418
    :pswitch_8
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1419
    .line 1420
    check-cast v2, Ljz/f;

    .line 1421
    .line 1422
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1423
    .line 1424
    check-cast v0, Lua/a;

    .line 1425
    .line 1426
    check-cast v1, Landroidx/collection/f;

    .line 1427
    .line 1428
    const-string v3, "_tmpMap"

    .line 1429
    .line 1430
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1431
    .line 1432
    .line 1433
    invoke-virtual {v2, v0, v1}, Ljz/f;->a(Lua/a;Landroidx/collection/f;)V

    .line 1434
    .line 1435
    .line 1436
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1437
    .line 1438
    return-object v0

    .line 1439
    :pswitch_9
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1440
    .line 1441
    check-cast v2, Ljz/c;

    .line 1442
    .line 1443
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1444
    .line 1445
    check-cast v0, Ljz/d;

    .line 1446
    .line 1447
    check-cast v1, Lua/a;

    .line 1448
    .line 1449
    const-string v3, "_connection"

    .line 1450
    .line 1451
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1452
    .line 1453
    .line 1454
    iget-object v2, v2, Ljz/c;->b:Las0/h;

    .line 1455
    .line 1456
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1457
    .line 1458
    .line 1459
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1460
    .line 1461
    return-object v0

    .line 1462
    :pswitch_a
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1463
    .line 1464
    check-cast v2, Lhe/h;

    .line 1465
    .line 1466
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1467
    .line 1468
    check-cast v0, Lay0/k;

    .line 1469
    .line 1470
    check-cast v1, Lm1/f;

    .line 1471
    .line 1472
    const-string v5, "$this$LazyColumn"

    .line 1473
    .line 1474
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1475
    .line 1476
    .line 1477
    iget-object v2, v2, Lhe/h;->a:Lnx0/c;

    .line 1478
    .line 1479
    invoke-virtual {v2}, Lnx0/c;->c()I

    .line 1480
    .line 1481
    .line 1482
    move-result v5

    .line 1483
    new-instance v6, Lag/t;

    .line 1484
    .line 1485
    const/4 v7, 0x6

    .line 1486
    invoke-direct {v6, v2, v7}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 1487
    .line 1488
    .line 1489
    new-instance v7, Ldl/i;

    .line 1490
    .line 1491
    invoke-direct {v7, v2, v0, v3}, Ldl/i;-><init>(Ljava/util/List;Ljava/lang/Object;I)V

    .line 1492
    .line 1493
    .line 1494
    new-instance v0, Lt2/b;

    .line 1495
    .line 1496
    const/4 v12, 0x1

    .line 1497
    invoke-direct {v0, v7, v12, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1498
    .line 1499
    .line 1500
    const/4 v2, 0x0

    .line 1501
    invoke-virtual {v1, v5, v2, v6, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1502
    .line 1503
    .line 1504
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1505
    .line 1506
    return-object v0

    .line 1507
    :pswitch_b
    const/16 v16, 0x0

    .line 1508
    .line 1509
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1510
    .line 1511
    check-cast v2, Ljava/lang/String;

    .line 1512
    .line 1513
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1514
    .line 1515
    check-cast v0, Lh2/d6;

    .line 1516
    .line 1517
    check-cast v1, Lhi/a;

    .line 1518
    .line 1519
    const-string v3, "$this$sdkViewModel"

    .line 1520
    .line 1521
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1522
    .line 1523
    .line 1524
    const-class v3, Ldh/u;

    .line 1525
    .line 1526
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1527
    .line 1528
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1529
    .line 1530
    .line 1531
    move-result-object v3

    .line 1532
    check-cast v1, Lii/a;

    .line 1533
    .line 1534
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1535
    .line 1536
    .line 1537
    move-result-object v1

    .line 1538
    check-cast v1, Ldh/u;

    .line 1539
    .line 1540
    new-instance v3, Ljh/l;

    .line 1541
    .line 1542
    new-instance v4, Lai/e;

    .line 1543
    .line 1544
    const/16 v5, 0x9

    .line 1545
    .line 1546
    const/4 v6, 0x0

    .line 1547
    invoke-direct {v4, v1, v2, v6, v5}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1548
    .line 1549
    .line 1550
    new-instance v5, Ljh/b;

    .line 1551
    .line 1552
    move/from16 v7, v16

    .line 1553
    .line 1554
    invoke-direct {v5, v1, v2, v6, v7}, Ljh/b;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1555
    .line 1556
    .line 1557
    new-instance v7, Ljh/b;

    .line 1558
    .line 1559
    const/4 v12, 0x1

    .line 1560
    invoke-direct {v7, v1, v2, v6, v12}, Ljh/b;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 1561
    .line 1562
    .line 1563
    invoke-direct {v3, v4, v5, v7, v0}, Ljh/l;-><init>(Lai/e;Ljh/b;Ljh/b;Lh2/d6;)V

    .line 1564
    .line 1565
    .line 1566
    return-object v3

    .line 1567
    :pswitch_c
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1568
    .line 1569
    check-cast v2, Ljb0/m;

    .line 1570
    .line 1571
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1572
    .line 1573
    check-cast v0, Ljb0/n;

    .line 1574
    .line 1575
    check-cast v1, Lua/a;

    .line 1576
    .line 1577
    const-string v3, "_connection"

    .line 1578
    .line 1579
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1580
    .line 1581
    .line 1582
    iget-object v2, v2, Ljb0/m;->b:Las0/h;

    .line 1583
    .line 1584
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1585
    .line 1586
    .line 1587
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1588
    .line 1589
    return-object v0

    .line 1590
    :pswitch_d
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1591
    .line 1592
    check-cast v2, Ljb0/i;

    .line 1593
    .line 1594
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1595
    .line 1596
    check-cast v0, Lua/a;

    .line 1597
    .line 1598
    check-cast v1, Landroidx/collection/f;

    .line 1599
    .line 1600
    const-string v3, "_tmpMap"

    .line 1601
    .line 1602
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1603
    .line 1604
    .line 1605
    invoke-virtual {v2, v0, v1}, Ljb0/i;->a(Lua/a;Landroidx/collection/f;)V

    .line 1606
    .line 1607
    .line 1608
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1609
    .line 1610
    return-object v0

    .line 1611
    :pswitch_e
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1612
    .line 1613
    check-cast v2, Ljb0/f;

    .line 1614
    .line 1615
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1616
    .line 1617
    check-cast v0, Ljb0/g;

    .line 1618
    .line 1619
    check-cast v1, Lua/a;

    .line 1620
    .line 1621
    const-string v3, "_connection"

    .line 1622
    .line 1623
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1624
    .line 1625
    .line 1626
    iget-object v2, v2, Ljb0/f;->b:Las0/h;

    .line 1627
    .line 1628
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1629
    .line 1630
    .line 1631
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1632
    .line 1633
    return-object v0

    .line 1634
    :pswitch_f
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1635
    .line 1636
    check-cast v2, Lj50/a;

    .line 1637
    .line 1638
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1639
    .line 1640
    check-cast v0, Lj50/d;

    .line 1641
    .line 1642
    check-cast v1, Lua/a;

    .line 1643
    .line 1644
    const-string v3, "_connection"

    .line 1645
    .line 1646
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1647
    .line 1648
    .line 1649
    iget-object v2, v2, Lj50/a;->b:Las0/h;

    .line 1650
    .line 1651
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1652
    .line 1653
    .line 1654
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1655
    .line 1656
    return-object v0

    .line 1657
    :pswitch_10
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1658
    .line 1659
    move-object v3, v2

    .line 1660
    check-cast v3, Ljava/util/LinkedHashSet;

    .line 1661
    .line 1662
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1663
    .line 1664
    check-cast v0, Lhy0/d;

    .line 1665
    .line 1666
    check-cast v1, Lgi/c;

    .line 1667
    .line 1668
    const-string v2, "$this$log"

    .line 1669
    .line 1670
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1671
    .line 1672
    .line 1673
    new-instance v7, Li70/q;

    .line 1674
    .line 1675
    const/16 v1, 0x1c

    .line 1676
    .line 1677
    invoke-direct {v7, v1}, Li70/q;-><init>(I)V

    .line 1678
    .line 1679
    .line 1680
    const/16 v8, 0x1f

    .line 1681
    .line 1682
    const/4 v4, 0x0

    .line 1683
    const/4 v5, 0x0

    .line 1684
    const/4 v6, 0x0

    .line 1685
    invoke-static/range {v3 .. v8}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 1686
    .line 1687
    .line 1688
    move-result-object v1

    .line 1689
    invoke-interface {v0}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 1690
    .line 1691
    .line 1692
    move-result-object v0

    .line 1693
    invoke-interface {v3}, Ljava/util/Set;->size()I

    .line 1694
    .line 1695
    .line 1696
    move-result v2

    .line 1697
    const-string v3, "Duplicated creator for "

    .line 1698
    .line 1699
    const-string v4, ". Set("

    .line 1700
    .line 1701
    const-string v5, "): "

    .line 1702
    .line 1703
    invoke-static {v3, v2, v0, v4, v5}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1704
    .line 1705
    .line 1706
    move-result-object v0

    .line 1707
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1708
    .line 1709
    .line 1710
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1711
    .line 1712
    .line 1713
    move-result-object v0

    .line 1714
    return-object v0

    .line 1715
    :pswitch_11
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1716
    .line 1717
    check-cast v2, Lif0/m;

    .line 1718
    .line 1719
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1720
    .line 1721
    check-cast v0, [Lif0/o;

    .line 1722
    .line 1723
    check-cast v1, Lua/a;

    .line 1724
    .line 1725
    const-string v3, "_connection"

    .line 1726
    .line 1727
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1728
    .line 1729
    .line 1730
    iget-object v2, v2, Lif0/m;->b:Las0/h;

    .line 1731
    .line 1732
    invoke-virtual {v2, v1, v0}, Llp/ef;->f(Lua/a;[Ljava/lang/Object;)V

    .line 1733
    .line 1734
    .line 1735
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1736
    .line 1737
    return-object v0

    .line 1738
    :pswitch_12
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1739
    .line 1740
    check-cast v2, Lif0/h;

    .line 1741
    .line 1742
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1743
    .line 1744
    check-cast v0, Ljava/util/List;

    .line 1745
    .line 1746
    check-cast v1, Lua/a;

    .line 1747
    .line 1748
    const-string v3, "_connection"

    .line 1749
    .line 1750
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1751
    .line 1752
    .line 1753
    iget-object v2, v2, Lif0/h;->b:Las0/h;

    .line 1754
    .line 1755
    check-cast v0, Ljava/lang/Iterable;

    .line 1756
    .line 1757
    invoke-virtual {v2, v1, v0}, Llp/ef;->d(Lua/a;Ljava/lang/Iterable;)V

    .line 1758
    .line 1759
    .line 1760
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1761
    .line 1762
    return-object v0

    .line 1763
    :pswitch_13
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1764
    .line 1765
    check-cast v2, Lif0/e;

    .line 1766
    .line 1767
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1768
    .line 1769
    check-cast v0, Ljava/util/List;

    .line 1770
    .line 1771
    check-cast v1, Lua/a;

    .line 1772
    .line 1773
    const-string v3, "_connection"

    .line 1774
    .line 1775
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1776
    .line 1777
    .line 1778
    iget-object v2, v2, Lif0/e;->b:Las0/h;

    .line 1779
    .line 1780
    check-cast v0, Ljava/lang/Iterable;

    .line 1781
    .line 1782
    invoke-virtual {v2, v1, v0}, Llp/ef;->d(Lua/a;Ljava/lang/Iterable;)V

    .line 1783
    .line 1784
    .line 1785
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1786
    .line 1787
    return-object v0

    .line 1788
    :pswitch_14
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1789
    .line 1790
    check-cast v2, Ljava/lang/String;

    .line 1791
    .line 1792
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1793
    .line 1794
    check-cast v0, Lzb/s0;

    .line 1795
    .line 1796
    check-cast v1, Lhi/a;

    .line 1797
    .line 1798
    const-string v3, "$this$sdkViewModel"

    .line 1799
    .line 1800
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1801
    .line 1802
    .line 1803
    const-class v3, Led/e;

    .line 1804
    .line 1805
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1806
    .line 1807
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v3

    .line 1811
    check-cast v1, Lii/a;

    .line 1812
    .line 1813
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1814
    .line 1815
    .line 1816
    move-result-object v3

    .line 1817
    move-object v7, v3

    .line 1818
    check-cast v7, Led/e;

    .line 1819
    .line 1820
    const-class v3, Lxb/a;

    .line 1821
    .line 1822
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1823
    .line 1824
    .line 1825
    move-result-object v3

    .line 1826
    invoke-virtual {v1, v3}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 1827
    .line 1828
    .line 1829
    move-result-object v1

    .line 1830
    check-cast v1, Lxb/a;

    .line 1831
    .line 1832
    new-instance v3, Lid/f;

    .line 1833
    .line 1834
    new-instance v5, Lag/c;

    .line 1835
    .line 1836
    const-class v8, Led/e;

    .line 1837
    .line 1838
    const-string v9, "getHomeChargingHistoryDetail"

    .line 1839
    .line 1840
    const-string v10, "getHomeChargingHistoryDetail-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 1841
    .line 1842
    const/4 v11, 0x0

    .line 1843
    const/16 v12, 0x1b

    .line 1844
    .line 1845
    const/4 v6, 0x2

    .line 1846
    invoke-direct/range {v5 .. v12}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 1847
    .line 1848
    .line 1849
    new-instance v4, Lid/a;

    .line 1850
    .line 1851
    const/4 v7, 0x0

    .line 1852
    invoke-direct {v4, v1, v7}, Lid/a;-><init>(Lxb/a;I)V

    .line 1853
    .line 1854
    .line 1855
    invoke-direct {v3, v2, v5, v0, v4}, Lid/f;-><init>(Ljava/lang/String;Lag/c;Lzb/s0;Lid/a;)V

    .line 1856
    .line 1857
    .line 1858
    return-object v3

    .line 1859
    :pswitch_15
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1860
    .line 1861
    check-cast v2, Lic0/e;

    .line 1862
    .line 1863
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1864
    .line 1865
    check-cast v0, Lic0/f;

    .line 1866
    .line 1867
    check-cast v1, Lua/a;

    .line 1868
    .line 1869
    const-string v3, "_connection"

    .line 1870
    .line 1871
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1872
    .line 1873
    .line 1874
    iget-object v2, v2, Lic0/e;->b:Las0/h;

    .line 1875
    .line 1876
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1877
    .line 1878
    .line 1879
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1880
    .line 1881
    return-object v0

    .line 1882
    :pswitch_16
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1883
    .line 1884
    check-cast v2, Lvy0/x1;

    .line 1885
    .line 1886
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1887
    .line 1888
    check-cast v0, Lxy0/x;

    .line 1889
    .line 1890
    check-cast v1, Lib/c;

    .line 1891
    .line 1892
    const/4 v6, 0x0

    .line 1893
    invoke-virtual {v2, v6}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 1894
    .line 1895
    .line 1896
    check-cast v0, Lxy0/w;

    .line 1897
    .line 1898
    invoke-virtual {v0, v1}, Lxy0/w;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1899
    .line 1900
    .line 1901
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1902
    .line 1903
    return-object v0

    .line 1904
    :pswitch_17
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1905
    .line 1906
    check-cast v2, Li91/v3;

    .line 1907
    .line 1908
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1909
    .line 1910
    check-cast v0, Lay0/k;

    .line 1911
    .line 1912
    check-cast v1, Ljava/lang/Float;

    .line 1913
    .line 1914
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1915
    .line 1916
    .line 1917
    if-eqz v2, :cond_4a

    .line 1918
    .line 1919
    invoke-virtual {v2}, Li91/v3;->a()V

    .line 1920
    .line 1921
    .line 1922
    :cond_4a
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1923
    .line 1924
    .line 1925
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1926
    .line 1927
    return-object v0

    .line 1928
    :pswitch_18
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1929
    .line 1930
    check-cast v2, Li70/f0;

    .line 1931
    .line 1932
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1933
    .line 1934
    check-cast v0, Li70/g0;

    .line 1935
    .line 1936
    check-cast v1, Lua/a;

    .line 1937
    .line 1938
    const-string v3, "_connection"

    .line 1939
    .line 1940
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1941
    .line 1942
    .line 1943
    iget-object v2, v2, Li70/f0;->b:Las0/h;

    .line 1944
    .line 1945
    invoke-virtual {v2, v1, v0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 1946
    .line 1947
    .line 1948
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1949
    .line 1950
    return-object v0

    .line 1951
    :pswitch_19
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 1952
    .line 1953
    check-cast v2, Ll2/b1;

    .line 1954
    .line 1955
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 1956
    .line 1957
    check-cast v0, Lt4/m;

    .line 1958
    .line 1959
    check-cast v1, Lt3/y;

    .line 1960
    .line 1961
    const-string v3, "coordinates"

    .line 1962
    .line 1963
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1964
    .line 1965
    .line 1966
    invoke-interface {v1}, Lt3/y;->h()J

    .line 1967
    .line 1968
    .line 1969
    move-result-wide v3

    .line 1970
    and-long/2addr v3, v5

    .line 1971
    long-to-int v1, v3

    .line 1972
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1973
    .line 1974
    .line 1975
    move-result-object v1

    .line 1976
    invoke-static {v1}, Lxf0/i0;->N(Ljava/lang/Number;)F

    .line 1977
    .line 1978
    .line 1979
    move-result v1

    .line 1980
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1981
    .line 1982
    .line 1983
    move-result-object v3

    .line 1984
    check-cast v3, Lk1/z0;

    .line 1985
    .line 1986
    sget v4, Li50/s;->c:F

    .line 1987
    .line 1988
    add-float/2addr v1, v4

    .line 1989
    const/16 v4, 0x1a

    .line 1990
    .line 1991
    invoke-static {v3, v0, v1, v10, v4}, Lxf0/y1;->z(Lk1/z0;Lt4/m;FFI)Lk1/a1;

    .line 1992
    .line 1993
    .line 1994
    move-result-object v0

    .line 1995
    invoke-interface {v2, v0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 1996
    .line 1997
    .line 1998
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1999
    .line 2000
    return-object v0

    .line 2001
    :pswitch_1a
    iget-object v2, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 2002
    .line 2003
    check-cast v2, Lay0/k;

    .line 2004
    .line 2005
    iget-object v0, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 2006
    .line 2007
    check-cast v0, Lh40/m3;

    .line 2008
    .line 2009
    check-cast v1, Lh40/m3;

    .line 2010
    .line 2011
    const-string v3, "it"

    .line 2012
    .line 2013
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2014
    .line 2015
    .line 2016
    invoke-interface {v2, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2017
    .line 2018
    .line 2019
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2020
    .line 2021
    return-object v0

    .line 2022
    :pswitch_1b
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 2023
    .line 2024
    check-cast v2, Lh40/i3;

    .line 2025
    .line 2026
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 2027
    .line 2028
    check-cast v0, Ll2/g1;

    .line 2029
    .line 2030
    check-cast v1, Lm1/f;

    .line 2031
    .line 2032
    const-string v3, "$this$LazyColumn"

    .line 2033
    .line 2034
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2035
    .line 2036
    .line 2037
    iget-object v2, v2, Lh40/i3;->a:Ljava/util/List;

    .line 2038
    .line 2039
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 2040
    .line 2041
    .line 2042
    move-result v3

    .line 2043
    new-instance v5, Lak/p;

    .line 2044
    .line 2045
    const/16 v6, 0x13

    .line 2046
    .line 2047
    invoke-direct {v5, v2, v6}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 2048
    .line 2049
    .line 2050
    new-instance v6, Ldl/i;

    .line 2051
    .line 2052
    const/4 v12, 0x2

    .line 2053
    invoke-direct {v6, v2, v0, v12}, Ldl/i;-><init>(Ljava/util/List;Ljava/lang/Object;I)V

    .line 2054
    .line 2055
    .line 2056
    new-instance v0, Lt2/b;

    .line 2057
    .line 2058
    const/4 v12, 0x1

    .line 2059
    invoke-direct {v0, v6, v12, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 2060
    .line 2061
    .line 2062
    const/4 v6, 0x0

    .line 2063
    invoke-virtual {v1, v3, v6, v5, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 2064
    .line 2065
    .line 2066
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2067
    .line 2068
    return-object v0

    .line 2069
    :pswitch_1c
    iget-object v2, v0, Li40/j0;->e:Ljava/lang/Object;

    .line 2070
    .line 2071
    check-cast v2, Lh40/r0;

    .line 2072
    .line 2073
    iget-object v0, v0, Li40/j0;->f:Ljava/lang/Object;

    .line 2074
    .line 2075
    check-cast v0, Lay0/k;

    .line 2076
    .line 2077
    check-cast v1, Lm1/f;

    .line 2078
    .line 2079
    const-string v4, "$this$LazyColumn"

    .line 2080
    .line 2081
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2082
    .line 2083
    .line 2084
    iget-boolean v4, v2, Lh40/r0;->g:Z

    .line 2085
    .line 2086
    const/16 v5, 0x12

    .line 2087
    .line 2088
    if-eqz v4, :cond_4b

    .line 2089
    .line 2090
    new-instance v0, Lb50/c;

    .line 2091
    .line 2092
    invoke-direct {v0, v2, v5}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 2093
    .line 2094
    .line 2095
    new-instance v2, Lt2/b;

    .line 2096
    .line 2097
    const v3, -0x2d4312b7

    .line 2098
    .line 2099
    .line 2100
    const/4 v12, 0x1

    .line 2101
    invoke-direct {v2, v0, v12, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 2102
    .line 2103
    .line 2104
    const/4 v5, 0x3

    .line 2105
    invoke-static {v1, v2, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 2106
    .line 2107
    .line 2108
    goto :goto_2a

    .line 2109
    :cond_4b
    invoke-virtual {v2}, Lh40/r0;->b()Ljava/util/List;

    .line 2110
    .line 2111
    .line 2112
    move-result-object v2

    .line 2113
    new-instance v4, Lhz0/t1;

    .line 2114
    .line 2115
    invoke-direct {v4, v5}, Lhz0/t1;-><init>(I)V

    .line 2116
    .line 2117
    .line 2118
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 2119
    .line 2120
    .line 2121
    move-result v6

    .line 2122
    new-instance v8, Lc41/g;

    .line 2123
    .line 2124
    invoke-direct {v8, v7, v4, v2}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 2125
    .line 2126
    .line 2127
    new-instance v4, Lak/p;

    .line 2128
    .line 2129
    invoke-direct {v4, v2, v5}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 2130
    .line 2131
    .line 2132
    new-instance v5, Lak/q;

    .line 2133
    .line 2134
    invoke-direct {v5, v2, v0, v3}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 2135
    .line 2136
    .line 2137
    new-instance v0, Lt2/b;

    .line 2138
    .line 2139
    const v2, 0x2fd4df92

    .line 2140
    .line 2141
    .line 2142
    const/4 v12, 0x1

    .line 2143
    invoke-direct {v0, v5, v12, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 2144
    .line 2145
    .line 2146
    invoke-virtual {v1, v6, v8, v4, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 2147
    .line 2148
    .line 2149
    :goto_2a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2150
    .line 2151
    return-object v0

    .line 2152
    nop

    .line 2153
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
