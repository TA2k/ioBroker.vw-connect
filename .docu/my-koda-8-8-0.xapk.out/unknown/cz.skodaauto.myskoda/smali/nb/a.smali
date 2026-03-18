.class public abstract Lnb/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "EnqueueRunnable"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lnb/a;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public static a(Lfb/o;)Z
    .locals 63

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static {v0}, Lfb/o;->e(Lfb/o;)Ljava/util/HashSet;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object v2, v0, Lfb/o;->a:Lfb/u;

    .line 8
    .line 9
    iget-object v3, v0, Lfb/o;->d:Ljava/util/List;

    .line 10
    .line 11
    const/4 v4, 0x0

    .line 12
    new-array v5, v4, [Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v1, v5}, Ljava/util/HashSet;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    check-cast v1, [Ljava/lang/String;

    .line 19
    .line 20
    iget-object v5, v0, Lfb/o;->b:Ljava/lang/String;

    .line 21
    .line 22
    iget-object v6, v0, Lfb/o;->c:Leb/m;

    .line 23
    .line 24
    iget-object v7, v2, Lfb/u;->b:Leb/b;

    .line 25
    .line 26
    iget-object v7, v7, Leb/b;->d:Leb/j;

    .line 27
    .line 28
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 32
    .line 33
    .line 34
    move-result-wide v7

    .line 35
    iget-object v9, v2, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 36
    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    array-length v11, v1

    .line 40
    if-lez v11, :cond_0

    .line 41
    .line 42
    const/4 v11, 0x1

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    move v11, v4

    .line 45
    :goto_0
    if-eqz v11, :cond_6

    .line 46
    .line 47
    array-length v12, v1

    .line 48
    move v13, v4

    .line 49
    move v15, v13

    .line 50
    move/from16 v16, v15

    .line 51
    .line 52
    const/4 v14, 0x1

    .line 53
    :goto_1
    if-ge v13, v12, :cond_7

    .line 54
    .line 55
    aget-object v4, v1, v13

    .line 56
    .line 57
    invoke-virtual {v9}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 58
    .line 59
    .line 60
    move-result-object v10

    .line 61
    invoke-virtual {v10, v4}, Lmb/s;->e(Ljava/lang/String;)Lmb/o;

    .line 62
    .line 63
    .line 64
    move-result-object v10

    .line 65
    if-nez v10, :cond_2

    .line 66
    .line 67
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    new-instance v2, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v3, "Prerequisite "

    .line 74
    .line 75
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v3, " doesn\'t exist; not enqueuing"

    .line 82
    .line 83
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    sget-object v3, Lnb/a;->a:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {v1, v3, v2}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_1
    :goto_2
    const/4 v2, 0x1

    .line 96
    const/4 v4, 0x0

    .line 97
    goto/16 :goto_22

    .line 98
    .line 99
    :cond_2
    iget-object v4, v10, Lmb/o;->b:Leb/h0;

    .line 100
    .line 101
    sget-object v10, Leb/h0;->f:Leb/h0;

    .line 102
    .line 103
    if-ne v4, v10, :cond_3

    .line 104
    .line 105
    const/4 v10, 0x1

    .line 106
    goto :goto_3

    .line 107
    :cond_3
    const/4 v10, 0x0

    .line 108
    :goto_3
    and-int/2addr v14, v10

    .line 109
    sget-object v10, Leb/h0;->g:Leb/h0;

    .line 110
    .line 111
    if-ne v4, v10, :cond_4

    .line 112
    .line 113
    const/16 v16, 0x1

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_4
    sget-object v10, Leb/h0;->i:Leb/h0;

    .line 117
    .line 118
    if-ne v4, v10, :cond_5

    .line 119
    .line 120
    const/4 v15, 0x1

    .line 121
    :cond_5
    :goto_4
    add-int/lit8 v13, v13, 0x1

    .line 122
    .line 123
    const/4 v4, 0x0

    .line 124
    goto :goto_1

    .line 125
    :cond_6
    const/4 v14, 0x1

    .line 126
    const/4 v15, 0x0

    .line 127
    const/16 v16, 0x0

    .line 128
    .line 129
    :cond_7
    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    if-nez v4, :cond_16

    .line 134
    .line 135
    if-nez v11, :cond_16

    .line 136
    .line 137
    invoke-virtual {v9}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 138
    .line 139
    .line 140
    move-result-object v10

    .line 141
    invoke-virtual {v10, v5}, Lmb/s;->f(Ljava/lang/String;)Ljava/util/List;

    .line 142
    .line 143
    .line 144
    move-result-object v10

    .line 145
    invoke-interface {v10}, Ljava/util/List;->isEmpty()Z

    .line 146
    .line 147
    .line 148
    move-result v12

    .line 149
    if-nez v12, :cond_16

    .line 150
    .line 151
    sget-object v12, Leb/m;->f:Leb/m;

    .line 152
    .line 153
    if-eq v6, v12, :cond_c

    .line 154
    .line 155
    sget-object v12, Leb/m;->g:Leb/m;

    .line 156
    .line 157
    if-ne v6, v12, :cond_8

    .line 158
    .line 159
    goto :goto_6

    .line 160
    :cond_8
    sget-object v12, Leb/m;->e:Leb/m;

    .line 161
    .line 162
    if-ne v6, v12, :cond_a

    .line 163
    .line 164
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 165
    .line 166
    .line 167
    move-result-object v6

    .line 168
    :cond_9
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 169
    .line 170
    .line 171
    move-result v12

    .line 172
    if-eqz v12, :cond_a

    .line 173
    .line 174
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v12

    .line 178
    check-cast v12, Lmb/m;

    .line 179
    .line 180
    iget-object v12, v12, Lmb/m;->b:Leb/h0;

    .line 181
    .line 182
    sget-object v13, Leb/h0;->d:Leb/h0;

    .line 183
    .line 184
    if-eq v12, v13, :cond_1

    .line 185
    .line 186
    sget-object v13, Leb/h0;->e:Leb/h0;

    .line 187
    .line 188
    if-ne v12, v13, :cond_9

    .line 189
    .line 190
    goto :goto_2

    .line 191
    :cond_a
    const-string v6, "getWorkDatabase(...)"

    .line 192
    .line 193
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    new-instance v6, La8/y0;

    .line 197
    .line 198
    const/16 v12, 0xc

    .line 199
    .line 200
    invoke-direct {v6, v9, v5, v2, v12}, La8/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 201
    .line 202
    .line 203
    new-instance v12, Lh91/a;

    .line 204
    .line 205
    const/4 v13, 0x2

    .line 206
    invoke-direct {v12, v6, v13}, Lh91/a;-><init>(Ljava/lang/Runnable;I)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v9, v12}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    invoke-virtual {v9}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 213
    .line 214
    .line 215
    move-result-object v6

    .line 216
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 217
    .line 218
    .line 219
    move-result-object v10

    .line 220
    :goto_5
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 221
    .line 222
    .line 223
    move-result v12

    .line 224
    if-eqz v12, :cond_b

    .line 225
    .line 226
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v12

    .line 230
    check-cast v12, Lmb/m;

    .line 231
    .line 232
    iget-object v12, v12, Lmb/m;->a:Ljava/lang/String;

    .line 233
    .line 234
    invoke-virtual {v6, v12}, Lmb/s;->c(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_b
    move-object/from16 v17, v3

    .line 239
    .line 240
    move/from16 v18, v4

    .line 241
    .line 242
    move-object/from16 v19, v9

    .line 243
    .line 244
    const/4 v3, 0x1

    .line 245
    goto/16 :goto_c

    .line 246
    .line 247
    :cond_c
    :goto_6
    invoke-virtual {v9}, Landroidx/work/impl/WorkDatabase;->s()Lmb/b;

    .line 248
    .line 249
    .line 250
    move-result-object v11

    .line 251
    new-instance v12, Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 254
    .line 255
    .line 256
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 257
    .line 258
    .line 259
    move-result-object v10

    .line 260
    :goto_7
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 261
    .line 262
    .line 263
    move-result v13

    .line 264
    if-eqz v13, :cond_11

    .line 265
    .line 266
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v13

    .line 270
    check-cast v13, Lmb/m;

    .line 271
    .line 272
    move-object/from16 v17, v3

    .line 273
    .line 274
    iget-object v3, v13, Lmb/m;->a:Ljava/lang/String;

    .line 275
    .line 276
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 277
    .line 278
    .line 279
    move/from16 v18, v4

    .line 280
    .line 281
    const-string v4, "id"

    .line 282
    .line 283
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    iget-object v4, v11, Lmb/b;->a:Lla/u;

    .line 287
    .line 288
    move-object/from16 v19, v9

    .line 289
    .line 290
    new-instance v9, Lif0/d;

    .line 291
    .line 292
    move-object/from16 v20, v10

    .line 293
    .line 294
    const/16 v10, 0xa

    .line 295
    .line 296
    invoke-direct {v9, v3, v10}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 297
    .line 298
    .line 299
    const/4 v3, 0x0

    .line 300
    const/4 v10, 0x1

    .line 301
    invoke-static {v4, v10, v3, v9}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 302
    .line 303
    .line 304
    move-result-object v4

    .line 305
    check-cast v4, Ljava/lang/Boolean;

    .line 306
    .line 307
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 308
    .line 309
    .line 310
    move-result v3

    .line 311
    if-nez v3, :cond_10

    .line 312
    .line 313
    iget-object v3, v13, Lmb/m;->b:Leb/h0;

    .line 314
    .line 315
    sget-object v4, Leb/h0;->f:Leb/h0;

    .line 316
    .line 317
    if-ne v3, v4, :cond_d

    .line 318
    .line 319
    const/4 v4, 0x1

    .line 320
    goto :goto_8

    .line 321
    :cond_d
    const/4 v4, 0x0

    .line 322
    :goto_8
    and-int/2addr v4, v14

    .line 323
    sget-object v9, Leb/h0;->g:Leb/h0;

    .line 324
    .line 325
    if-ne v3, v9, :cond_e

    .line 326
    .line 327
    const/16 v16, 0x1

    .line 328
    .line 329
    goto :goto_9

    .line 330
    :cond_e
    sget-object v9, Leb/h0;->i:Leb/h0;

    .line 331
    .line 332
    if-ne v3, v9, :cond_f

    .line 333
    .line 334
    const/4 v15, 0x1

    .line 335
    :cond_f
    :goto_9
    iget-object v3, v13, Lmb/m;->a:Ljava/lang/String;

    .line 336
    .line 337
    invoke-virtual {v12, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move v14, v4

    .line 341
    :cond_10
    move-object/from16 v3, v17

    .line 342
    .line 343
    move/from16 v4, v18

    .line 344
    .line 345
    move-object/from16 v9, v19

    .line 346
    .line 347
    move-object/from16 v10, v20

    .line 348
    .line 349
    goto :goto_7

    .line 350
    :cond_11
    move-object/from16 v17, v3

    .line 351
    .line 352
    move/from16 v18, v4

    .line 353
    .line 354
    move-object/from16 v19, v9

    .line 355
    .line 356
    sget-object v3, Leb/m;->g:Leb/m;

    .line 357
    .line 358
    if-ne v6, v3, :cond_14

    .line 359
    .line 360
    if-nez v15, :cond_12

    .line 361
    .line 362
    if-eqz v16, :cond_14

    .line 363
    .line 364
    :cond_12
    invoke-virtual/range {v19 .. v19}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 365
    .line 366
    .line 367
    move-result-object v3

    .line 368
    invoke-virtual {v3, v5}, Lmb/s;->f(Ljava/lang/String;)Ljava/util/List;

    .line 369
    .line 370
    .line 371
    move-result-object v4

    .line 372
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 373
    .line 374
    .line 375
    move-result-object v4

    .line 376
    :goto_a
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 377
    .line 378
    .line 379
    move-result v6

    .line 380
    if-eqz v6, :cond_13

    .line 381
    .line 382
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v6

    .line 386
    check-cast v6, Lmb/m;

    .line 387
    .line 388
    iget-object v6, v6, Lmb/m;->a:Ljava/lang/String;

    .line 389
    .line 390
    invoke-virtual {v3, v6}, Lmb/s;->c(Ljava/lang/String;)V

    .line 391
    .line 392
    .line 393
    goto :goto_a

    .line 394
    :cond_13
    sget-object v12, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 395
    .line 396
    const/4 v15, 0x0

    .line 397
    const/16 v16, 0x0

    .line 398
    .line 399
    :cond_14
    invoke-interface {v12, v1}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    check-cast v1, [Ljava/lang/String;

    .line 404
    .line 405
    array-length v3, v1

    .line 406
    if-lez v3, :cond_15

    .line 407
    .line 408
    const/4 v11, 0x1

    .line 409
    goto :goto_b

    .line 410
    :cond_15
    const/4 v11, 0x0

    .line 411
    :goto_b
    const/4 v3, 0x0

    .line 412
    goto :goto_c

    .line 413
    :cond_16
    move-object/from16 v17, v3

    .line 414
    .line 415
    move/from16 v18, v4

    .line 416
    .line 417
    move-object/from16 v19, v9

    .line 418
    .line 419
    goto :goto_b

    .line 420
    :goto_c
    invoke-interface/range {v17 .. v17}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 421
    .line 422
    .line 423
    move-result-object v4

    .line 424
    move v10, v3

    .line 425
    :goto_d
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 426
    .line 427
    .line 428
    move-result v3

    .line 429
    if-eqz v3, :cond_29

    .line 430
    .line 431
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object v3

    .line 435
    check-cast v3, Leb/k0;

    .line 436
    .line 437
    iget-object v6, v3, Leb/k0;->b:Lmb/o;

    .line 438
    .line 439
    iget-object v9, v3, Leb/k0;->a:Ljava/util/UUID;

    .line 440
    .line 441
    if-eqz v11, :cond_19

    .line 442
    .line 443
    if-nez v14, :cond_19

    .line 444
    .line 445
    if-eqz v16, :cond_17

    .line 446
    .line 447
    sget-object v12, Leb/h0;->g:Leb/h0;

    .line 448
    .line 449
    iput-object v12, v6, Lmb/o;->b:Leb/h0;

    .line 450
    .line 451
    goto :goto_e

    .line 452
    :cond_17
    if-eqz v15, :cond_18

    .line 453
    .line 454
    sget-object v12, Leb/h0;->i:Leb/h0;

    .line 455
    .line 456
    iput-object v12, v6, Lmb/o;->b:Leb/h0;

    .line 457
    .line 458
    goto :goto_e

    .line 459
    :cond_18
    sget-object v12, Leb/h0;->h:Leb/h0;

    .line 460
    .line 461
    iput-object v12, v6, Lmb/o;->b:Leb/h0;

    .line 462
    .line 463
    goto :goto_e

    .line 464
    :cond_19
    iput-wide v7, v6, Lmb/o;->n:J

    .line 465
    .line 466
    :goto_e
    iget-object v12, v6, Lmb/o;->b:Leb/h0;

    .line 467
    .line 468
    sget-object v13, Leb/h0;->d:Leb/h0;

    .line 469
    .line 470
    if-ne v12, v13, :cond_1a

    .line 471
    .line 472
    const/4 v10, 0x1

    .line 473
    :cond_1a
    invoke-virtual/range {v19 .. v19}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 474
    .line 475
    .line 476
    move-result-object v12

    .line 477
    iget-object v13, v2, Lfb/u;->e:Ljava/util/List;

    .line 478
    .line 479
    move-object/from16 v17, v2

    .line 480
    .line 481
    const-string v2, "schedulers"

    .line 482
    .line 483
    invoke-static {v13, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    const-string v2, "workSpec"

    .line 487
    .line 488
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    iget-object v2, v6, Lmb/o;->e:Leb/h;

    .line 492
    .line 493
    const-string v13, "androidx.work.multiprocess.RemoteListenableDelegatingWorker.ARGUMENT_REMOTE_LISTENABLE_WORKER_NAME"

    .line 494
    .line 495
    invoke-virtual {v2, v13}, Leb/h;->a(Ljava/lang/String;)Z

    .line 496
    .line 497
    .line 498
    move-result v2

    .line 499
    move/from16 v20, v2

    .line 500
    .line 501
    iget-object v2, v6, Lmb/o;->e:Leb/h;

    .line 502
    .line 503
    move-object/from16 v21, v4

    .line 504
    .line 505
    const-string v4, "androidx.work.impl.workers.RemoteListenableWorker.ARGUMENT_PACKAGE_NAME"

    .line 506
    .line 507
    invoke-virtual {v2, v4}, Leb/h;->a(Ljava/lang/String;)Z

    .line 508
    .line 509
    .line 510
    move-result v2

    .line 511
    iget-object v4, v6, Lmb/o;->e:Leb/h;

    .line 512
    .line 513
    move/from16 v22, v2

    .line 514
    .line 515
    const-string v2, "androidx.work.impl.workers.RemoteListenableWorker.ARGUMENT_CLASS_NAME"

    .line 516
    .line 517
    invoke-virtual {v4, v2}, Leb/h;->a(Ljava/lang/String;)Z

    .line 518
    .line 519
    .line 520
    move-result v2

    .line 521
    if-nez v20, :cond_25

    .line 522
    .line 523
    if-eqz v22, :cond_25

    .line 524
    .line 525
    if-eqz v2, :cond_25

    .line 526
    .line 527
    iget-object v2, v6, Lmb/o;->c:Ljava/lang/String;

    .line 528
    .line 529
    new-instance v4, Leb/c0;

    .line 530
    .line 531
    invoke-direct {v4}, Leb/c0;-><init>()V

    .line 532
    .line 533
    .line 534
    move-wide/from16 v22, v7

    .line 535
    .line 536
    iget-object v7, v4, Leb/c0;->a:Ljava/lang/Object;

    .line 537
    .line 538
    check-cast v7, Ljava/util/LinkedHashMap;

    .line 539
    .line 540
    iget-object v8, v6, Lmb/o;->e:Leb/h;

    .line 541
    .line 542
    move-object/from16 v20, v9

    .line 543
    .line 544
    const-string v9, "data"

    .line 545
    .line 546
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    iget-object v8, v8, Leb/h;->a:Ljava/util/HashMap;

    .line 550
    .line 551
    invoke-virtual {v4, v8}, Leb/c0;->b(Ljava/util/HashMap;)V

    .line 552
    .line 553
    .line 554
    invoke-interface {v7, v13, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    new-instance v2, Leb/h;

    .line 558
    .line 559
    invoke-direct {v2, v7}, Leb/h;-><init>(Ljava/util/LinkedHashMap;)V

    .line 560
    .line 561
    .line 562
    invoke-static {v2}, Lkp/b6;->d(Leb/h;)[B

    .line 563
    .line 564
    .line 565
    const v4, 0x1ffffeb

    .line 566
    .line 567
    .line 568
    and-int/lit8 v7, v4, 0x1

    .line 569
    .line 570
    if-eqz v7, :cond_1b

    .line 571
    .line 572
    iget-object v7, v6, Lmb/o;->a:Ljava/lang/String;

    .line 573
    .line 574
    goto :goto_f

    .line 575
    :cond_1b
    const/4 v7, 0x0

    .line 576
    :goto_f
    and-int/lit8 v8, v4, 0x2

    .line 577
    .line 578
    if-eqz v8, :cond_1c

    .line 579
    .line 580
    iget-object v8, v6, Lmb/o;->b:Leb/h0;

    .line 581
    .line 582
    goto :goto_10

    .line 583
    :cond_1c
    const/4 v8, 0x0

    .line 584
    :goto_10
    and-int/lit8 v9, v4, 0x4

    .line 585
    .line 586
    if-eqz v9, :cond_1d

    .line 587
    .line 588
    iget-object v9, v6, Lmb/o;->c:Ljava/lang/String;

    .line 589
    .line 590
    goto :goto_11

    .line 591
    :cond_1d
    const-string v9, "androidx.work.multiprocess.RemoteListenableDelegatingWorker"

    .line 592
    .line 593
    :goto_11
    iget-object v13, v6, Lmb/o;->d:Ljava/lang/String;

    .line 594
    .line 595
    and-int/lit8 v24, v4, 0x10

    .line 596
    .line 597
    if-eqz v24, :cond_1e

    .line 598
    .line 599
    iget-object v2, v6, Lmb/o;->e:Leb/h;

    .line 600
    .line 601
    :cond_1e
    iget-object v4, v6, Lmb/o;->f:Leb/h;

    .line 602
    .line 603
    move/from16 v59, v10

    .line 604
    .line 605
    move/from16 v58, v11

    .line 606
    .line 607
    iget-wide v10, v6, Lmb/o;->g:J

    .line 608
    .line 609
    move-wide/from16 v31, v10

    .line 610
    .line 611
    iget-wide v10, v6, Lmb/o;->h:J

    .line 612
    .line 613
    move-wide/from16 v33, v10

    .line 614
    .line 615
    iget-wide v10, v6, Lmb/o;->i:J

    .line 616
    .line 617
    move-wide/from16 v35, v10

    .line 618
    .line 619
    iget-object v10, v6, Lmb/o;->j:Leb/e;

    .line 620
    .line 621
    move/from16 v60, v14

    .line 622
    .line 623
    const v11, 0x1ffffeb

    .line 624
    .line 625
    .line 626
    and-int/lit16 v14, v11, 0x400

    .line 627
    .line 628
    if-eqz v14, :cond_1f

    .line 629
    .line 630
    iget v14, v6, Lmb/o;->k:I

    .line 631
    .line 632
    :goto_12
    move/from16 v38, v14

    .line 633
    .line 634
    goto :goto_13

    .line 635
    :cond_1f
    const/4 v14, 0x0

    .line 636
    goto :goto_12

    .line 637
    :goto_13
    iget-object v14, v6, Lmb/o;->l:Leb/a;

    .line 638
    .line 639
    move-object/from16 v61, v1

    .line 640
    .line 641
    iget-wide v0, v6, Lmb/o;->m:J

    .line 642
    .line 643
    move-wide/from16 v40, v0

    .line 644
    .line 645
    and-int/lit16 v0, v11, 0x2000

    .line 646
    .line 647
    if-eqz v0, :cond_20

    .line 648
    .line 649
    iget-wide v0, v6, Lmb/o;->n:J

    .line 650
    .line 651
    :goto_14
    move-wide/from16 v42, v0

    .line 652
    .line 653
    goto :goto_15

    .line 654
    :cond_20
    const-wide/16 v0, 0x0

    .line 655
    .line 656
    goto :goto_14

    .line 657
    :goto_15
    iget-wide v0, v6, Lmb/o;->o:J

    .line 658
    .line 659
    move/from16 v24, v11

    .line 660
    .line 661
    move-object/from16 v62, v12

    .line 662
    .line 663
    iget-wide v11, v6, Lmb/o;->p:J

    .line 664
    .line 665
    move-wide/from16 v44, v0

    .line 666
    .line 667
    iget-boolean v0, v6, Lmb/o;->q:Z

    .line 668
    .line 669
    iget-object v1, v6, Lmb/o;->r:Leb/e0;

    .line 670
    .line 671
    const/high16 v25, 0x40000

    .line 672
    .line 673
    and-int v25, v24, v25

    .line 674
    .line 675
    move/from16 v48, v0

    .line 676
    .line 677
    if-eqz v25, :cond_21

    .line 678
    .line 679
    iget v0, v6, Lmb/o;->s:I

    .line 680
    .line 681
    :goto_16
    move/from16 v50, v0

    .line 682
    .line 683
    goto :goto_17

    .line 684
    :cond_21
    const/4 v0, 0x0

    .line 685
    goto :goto_16

    .line 686
    :goto_17
    const/high16 v0, 0x80000

    .line 687
    .line 688
    and-int v0, v24, v0

    .line 689
    .line 690
    if-eqz v0, :cond_22

    .line 691
    .line 692
    iget v0, v6, Lmb/o;->t:I

    .line 693
    .line 694
    :goto_18
    move/from16 v51, v0

    .line 695
    .line 696
    goto :goto_19

    .line 697
    :cond_22
    const/4 v0, 0x0

    .line 698
    goto :goto_18

    .line 699
    :goto_19
    const/high16 v0, 0x100000

    .line 700
    .line 701
    and-int v0, v24, v0

    .line 702
    .line 703
    move-wide/from16 v46, v11

    .line 704
    .line 705
    if-eqz v0, :cond_23

    .line 706
    .line 707
    iget-wide v11, v6, Lmb/o;->u:J

    .line 708
    .line 709
    :goto_1a
    move-wide/from16 v52, v11

    .line 710
    .line 711
    goto :goto_1b

    .line 712
    :cond_23
    const-wide/16 v11, 0x0

    .line 713
    .line 714
    goto :goto_1a

    .line 715
    :goto_1b
    const/high16 v0, 0x200000

    .line 716
    .line 717
    and-int v0, v24, v0

    .line 718
    .line 719
    if-eqz v0, :cond_24

    .line 720
    .line 721
    iget v0, v6, Lmb/o;->v:I

    .line 722
    .line 723
    :goto_1c
    move/from16 v54, v0

    .line 724
    .line 725
    goto :goto_1d

    .line 726
    :cond_24
    const/4 v0, 0x0

    .line 727
    goto :goto_1c

    .line 728
    :goto_1d
    iget v0, v6, Lmb/o;->w:I

    .line 729
    .line 730
    iget-object v11, v6, Lmb/o;->x:Ljava/lang/String;

    .line 731
    .line 732
    iget-object v12, v6, Lmb/o;->y:Ljava/lang/Boolean;

    .line 733
    .line 734
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 735
    .line 736
    .line 737
    const-string v6, "id"

    .line 738
    .line 739
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 740
    .line 741
    .line 742
    const-string v6, "state"

    .line 743
    .line 744
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 745
    .line 746
    .line 747
    const-string v6, "workerClassName"

    .line 748
    .line 749
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 750
    .line 751
    .line 752
    const-string v6, "inputMergerClassName"

    .line 753
    .line 754
    invoke-static {v13, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 755
    .line 756
    .line 757
    const-string v6, "input"

    .line 758
    .line 759
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 760
    .line 761
    .line 762
    const-string v6, "output"

    .line 763
    .line 764
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 765
    .line 766
    .line 767
    const-string v6, "constraints"

    .line 768
    .line 769
    invoke-static {v10, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 770
    .line 771
    .line 772
    const-string v6, "backoffPolicy"

    .line 773
    .line 774
    invoke-static {v14, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 775
    .line 776
    .line 777
    const-string v6, "outOfQuotaPolicy"

    .line 778
    .line 779
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 780
    .line 781
    .line 782
    new-instance v24, Lmb/o;

    .line 783
    .line 784
    move/from16 v55, v0

    .line 785
    .line 786
    move-object/from16 v49, v1

    .line 787
    .line 788
    move-object/from16 v29, v2

    .line 789
    .line 790
    move-object/from16 v30, v4

    .line 791
    .line 792
    move-object/from16 v25, v7

    .line 793
    .line 794
    move-object/from16 v26, v8

    .line 795
    .line 796
    move-object/from16 v27, v9

    .line 797
    .line 798
    move-object/from16 v37, v10

    .line 799
    .line 800
    move-object/from16 v56, v11

    .line 801
    .line 802
    move-object/from16 v57, v12

    .line 803
    .line 804
    move-object/from16 v28, v13

    .line 805
    .line 806
    move-object/from16 v39, v14

    .line 807
    .line 808
    invoke-direct/range {v24 .. v57}, Lmb/o;-><init>(Ljava/lang/String;Leb/h0;Ljava/lang/String;Ljava/lang/String;Leb/h;Leb/h;JJJLeb/e;ILeb/a;JJJJZLeb/e0;IIJIILjava/lang/String;Ljava/lang/Boolean;)V

    .line 809
    .line 810
    .line 811
    move-object/from16 v6, v24

    .line 812
    .line 813
    goto :goto_1e

    .line 814
    :cond_25
    move-object/from16 v61, v1

    .line 815
    .line 816
    move-wide/from16 v22, v7

    .line 817
    .line 818
    move-object/from16 v20, v9

    .line 819
    .line 820
    move/from16 v59, v10

    .line 821
    .line 822
    move/from16 v58, v11

    .line 823
    .line 824
    move-object/from16 v62, v12

    .line 825
    .line 826
    move/from16 v60, v14

    .line 827
    .line 828
    :goto_1e
    invoke-virtual/range {v62 .. v62}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 829
    .line 830
    .line 831
    move-object/from16 v0, v62

    .line 832
    .line 833
    iget-object v1, v0, Lmb/s;->a:Lla/u;

    .line 834
    .line 835
    new-instance v2, Ll2/v1;

    .line 836
    .line 837
    const/16 v4, 0xb

    .line 838
    .line 839
    invoke-direct {v2, v4, v0, v6}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 840
    .line 841
    .line 842
    const/4 v0, 0x0

    .line 843
    const/4 v10, 0x1

    .line 844
    invoke-static {v1, v0, v10, v2}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 845
    .line 846
    .line 847
    const-string v0, "toString(...)"

    .line 848
    .line 849
    move-object/from16 v1, v61

    .line 850
    .line 851
    if-eqz v58, :cond_26

    .line 852
    .line 853
    array-length v2, v1

    .line 854
    const/4 v4, 0x0

    .line 855
    :goto_1f
    if-ge v4, v2, :cond_26

    .line 856
    .line 857
    aget-object v6, v1, v4

    .line 858
    .line 859
    new-instance v7, Lmb/a;

    .line 860
    .line 861
    invoke-virtual/range {v20 .. v20}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 862
    .line 863
    .line 864
    move-result-object v8

    .line 865
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 866
    .line 867
    .line 868
    invoke-direct {v7, v8, v6}, Lmb/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 869
    .line 870
    .line 871
    invoke-virtual/range {v19 .. v19}, Landroidx/work/impl/WorkDatabase;->s()Lmb/b;

    .line 872
    .line 873
    .line 874
    move-result-object v6

    .line 875
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 876
    .line 877
    .line 878
    iget-object v8, v6, Lmb/b;->a:Lla/u;

    .line 879
    .line 880
    new-instance v9, Ll2/v1;

    .line 881
    .line 882
    const/4 v10, 0x5

    .line 883
    invoke-direct {v9, v10, v6, v7}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 884
    .line 885
    .line 886
    const/4 v6, 0x0

    .line 887
    const/4 v10, 0x1

    .line 888
    invoke-static {v8, v6, v10, v9}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    add-int/lit8 v4, v4, 0x1

    .line 892
    .line 893
    goto :goto_1f

    .line 894
    :cond_26
    invoke-virtual/range {v19 .. v19}, Landroidx/work/impl/WorkDatabase;->y()Lmb/u;

    .line 895
    .line 896
    .line 897
    move-result-object v2

    .line 898
    invoke-virtual/range {v20 .. v20}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 899
    .line 900
    .line 901
    move-result-object v4

    .line 902
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 903
    .line 904
    .line 905
    iget-object v3, v3, Leb/k0;->c:Ljava/util/Set;

    .line 906
    .line 907
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 908
    .line 909
    .line 910
    const-string v6, "id"

    .line 911
    .line 912
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 913
    .line 914
    .line 915
    const-string v6, "tags"

    .line 916
    .line 917
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 918
    .line 919
    .line 920
    check-cast v3, Ljava/lang/Iterable;

    .line 921
    .line 922
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 923
    .line 924
    .line 925
    move-result-object v3

    .line 926
    :goto_20
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 927
    .line 928
    .line 929
    move-result v6

    .line 930
    if-eqz v6, :cond_27

    .line 931
    .line 932
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 933
    .line 934
    .line 935
    move-result-object v6

    .line 936
    check-cast v6, Ljava/lang/String;

    .line 937
    .line 938
    new-instance v7, Lmb/t;

    .line 939
    .line 940
    invoke-direct {v7, v6, v4}, Lmb/t;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 941
    .line 942
    .line 943
    iget-object v6, v2, Lmb/u;->a:Lla/u;

    .line 944
    .line 945
    new-instance v8, Ll2/v1;

    .line 946
    .line 947
    const/16 v9, 0xd

    .line 948
    .line 949
    invoke-direct {v8, v9, v2, v7}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 950
    .line 951
    .line 952
    const/4 v7, 0x0

    .line 953
    const/4 v9, 0x1

    .line 954
    invoke-static {v6, v7, v9, v8}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 955
    .line 956
    .line 957
    goto :goto_20

    .line 958
    :cond_27
    if-nez v18, :cond_28

    .line 959
    .line 960
    invoke-virtual/range {v19 .. v19}, Landroidx/work/impl/WorkDatabase;->v()Lmb/k;

    .line 961
    .line 962
    .line 963
    move-result-object v2

    .line 964
    new-instance v3, Lmb/j;

    .line 965
    .line 966
    invoke-virtual/range {v20 .. v20}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 967
    .line 968
    .line 969
    move-result-object v4

    .line 970
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 971
    .line 972
    .line 973
    invoke-direct {v3, v5, v4}, Lmb/j;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 974
    .line 975
    .line 976
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 977
    .line 978
    .line 979
    iget-object v0, v2, Lmb/k;->a:Lla/u;

    .line 980
    .line 981
    new-instance v4, Ll2/v1;

    .line 982
    .line 983
    const/16 v6, 0x8

    .line 984
    .line 985
    invoke-direct {v4, v6, v2, v3}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 986
    .line 987
    .line 988
    const/4 v2, 0x1

    .line 989
    const/4 v3, 0x0

    .line 990
    invoke-static {v0, v3, v2, v4}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 991
    .line 992
    .line 993
    goto :goto_21

    .line 994
    :cond_28
    const/4 v2, 0x1

    .line 995
    const/4 v3, 0x0

    .line 996
    :goto_21
    move-object/from16 v0, p0

    .line 997
    .line 998
    move-object/from16 v2, v17

    .line 999
    .line 1000
    move-object/from16 v4, v21

    .line 1001
    .line 1002
    move-wide/from16 v7, v22

    .line 1003
    .line 1004
    move/from16 v11, v58

    .line 1005
    .line 1006
    move/from16 v10, v59

    .line 1007
    .line 1008
    move/from16 v14, v60

    .line 1009
    .line 1010
    goto/16 :goto_d

    .line 1011
    .line 1012
    :cond_29
    const/4 v2, 0x1

    .line 1013
    move-object/from16 v0, p0

    .line 1014
    .line 1015
    move v4, v10

    .line 1016
    :goto_22
    iput-boolean v2, v0, Lfb/o;->g:Z

    .line 1017
    .line 1018
    return v4
.end method
