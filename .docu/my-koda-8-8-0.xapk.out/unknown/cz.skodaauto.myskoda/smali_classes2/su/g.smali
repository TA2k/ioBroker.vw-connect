.class public final Lsu/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final d:Ljava/util/Set;

.field public e:Lm8/o;

.field public f:Lj1/a;

.field public g:Lyu/b;

.field public h:F

.field public final synthetic i:Lsu/i;


# direct methods
.method public constructor <init>(Lsu/i;Ljava/util/Set;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsu/g;->i:Lsu/i;

    .line 5
    .line 6
    iput-object p2, p0, Lsu/g;->d:Ljava/util/Set;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 28

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v2, v1, Lsu/g;->i:Lsu/i;

    .line 4
    .line 5
    iget v3, v2, Lsu/i;->k:I

    .line 6
    .line 7
    iget-object v0, v2, Lsu/i;->l:Ljava/util/Set;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    sget-object v0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 17
    .line 18
    :goto_0
    iget-object v4, v1, Lsu/g;->d:Ljava/util/Set;

    .line 19
    .line 20
    if-eqz v4, :cond_1

    .line 21
    .line 22
    invoke-static {v4}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    goto :goto_1

    .line 27
    :cond_1
    sget-object v5, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 28
    .line 29
    :goto_1
    invoke-interface {v5, v0}, Ljava/util/Set;->equals(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_2

    .line 34
    .line 35
    iget-object v0, v1, Lsu/g;->e:Lm8/o;

    .line 36
    .line 37
    invoke-virtual {v0}, Lm8/o;->run()V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_2
    new-instance v5, Lsu/e;

    .line 42
    .line 43
    invoke-direct {v5, v2}, Lsu/e;-><init>(Lsu/i;)V

    .line 44
    .line 45
    .line 46
    iget v6, v1, Lsu/g;->h:F

    .line 47
    .line 48
    iget v0, v2, Lsu/i;->n:F

    .line 49
    .line 50
    cmpl-float v7, v6, v0

    .line 51
    .line 52
    if-lez v7, :cond_3

    .line 53
    .line 54
    const/4 v7, 0x1

    .line 55
    goto :goto_2

    .line 56
    :cond_3
    const/4 v7, 0x0

    .line 57
    :goto_2
    sub-float v9, v6, v0

    .line 58
    .line 59
    iget-object v10, v2, Lsu/i;->h:Ljava/util/Set;

    .line 60
    .line 61
    :try_start_0
    iget-object v0, v1, Lsu/g;->f:Lj1/a;

    .line 62
    .line 63
    invoke-virtual {v0}, Lj1/a;->q()Lsp/v;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    iget-object v0, v0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 68
    .line 69
    move/from16 v17, v6

    .line 70
    .line 71
    move/from16 v18, v7

    .line 72
    .line 73
    move/from16 v16, v9

    .line 74
    .line 75
    goto/16 :goto_6

    .line 76
    .line 77
    :catch_0
    move-exception v0

    .line 78
    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    .line 79
    .line 80
    .line 81
    new-instance v0, Lcom/google/android/gms/maps/model/LatLng;

    .line 82
    .line 83
    const-wide/16 v11, 0x0

    .line 84
    .line 85
    invoke-direct {v0, v11, v12, v11, v12}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 86
    .line 87
    .line 88
    const-wide/high16 v11, 0x7ff0000000000000L    # Double.POSITIVE_INFINITY

    .line 89
    .line 90
    iget-wide v13, v0, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 91
    .line 92
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->min(DD)D

    .line 93
    .line 94
    .line 95
    move-result-wide v11

    .line 96
    move/from16 v16, v9

    .line 97
    .line 98
    const/4 v15, 0x1

    .line 99
    const-wide/high16 v8, -0x10000000000000L    # Double.NEGATIVE_INFINITY

    .line 100
    .line 101
    invoke-static {v8, v9, v13, v14}, Ljava/lang/Math;->max(DD)D

    .line 102
    .line 103
    .line 104
    move-result-wide v8

    .line 105
    const-wide/high16 v13, 0x7ff8000000000000L    # Double.NaN

    .line 106
    .line 107
    invoke-static {v13, v14}, Ljava/lang/Double;->isNaN(D)Z

    .line 108
    .line 109
    .line 110
    move-result v17

    .line 111
    move-wide/from16 v18, v13

    .line 112
    .line 113
    iget-wide v13, v0, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 114
    .line 115
    if-eqz v17, :cond_4

    .line 116
    .line 117
    move/from16 v17, v6

    .line 118
    .line 119
    :goto_3
    move/from16 v18, v7

    .line 120
    .line 121
    move-wide v6, v13

    .line 122
    goto :goto_5

    .line 123
    :cond_4
    cmpg-double v0, v18, v13

    .line 124
    .line 125
    if-lez v0, :cond_7

    .line 126
    .line 127
    cmpg-double v0, v13, v18

    .line 128
    .line 129
    if-gtz v0, :cond_5

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_5
    sub-double v20, v18, v13

    .line 133
    .line 134
    sub-double v22, v13, v18

    .line 135
    .line 136
    const-wide v24, 0x4076800000000000L    # 360.0

    .line 137
    .line 138
    .line 139
    .line 140
    .line 141
    add-double v22, v22, v24

    .line 142
    .line 143
    add-double v20, v20, v24

    .line 144
    .line 145
    rem-double v20, v20, v24

    .line 146
    .line 147
    rem-double v22, v22, v24

    .line 148
    .line 149
    cmpg-double v0, v20, v22

    .line 150
    .line 151
    if-gez v0, :cond_6

    .line 152
    .line 153
    move/from16 v17, v6

    .line 154
    .line 155
    move-wide/from16 v26, v18

    .line 156
    .line 157
    move/from16 v18, v7

    .line 158
    .line 159
    move-wide/from16 v6, v26

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_6
    move/from16 v17, v6

    .line 163
    .line 164
    move-wide/from16 v26, v18

    .line 165
    .line 166
    move/from16 v18, v7

    .line 167
    .line 168
    move-wide v6, v13

    .line 169
    move-wide/from16 v13, v26

    .line 170
    .line 171
    goto :goto_5

    .line 172
    :cond_7
    :goto_4
    move/from16 v17, v6

    .line 173
    .line 174
    move-wide/from16 v13, v18

    .line 175
    .line 176
    goto :goto_3

    .line 177
    :goto_5
    invoke-static {v13, v14}, Ljava/lang/Double;->isNaN(D)Z

    .line 178
    .line 179
    .line 180
    move-result v0

    .line 181
    xor-int/2addr v0, v15

    .line 182
    const-string v15, "no included points"

    .line 183
    .line 184
    invoke-static {v15, v0}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 185
    .line 186
    .line 187
    new-instance v0, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 188
    .line 189
    new-instance v15, Lcom/google/android/gms/maps/model/LatLng;

    .line 190
    .line 191
    invoke-direct {v15, v11, v12, v13, v14}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 192
    .line 193
    .line 194
    new-instance v11, Lcom/google/android/gms/maps/model/LatLng;

    .line 195
    .line 196
    invoke-direct {v11, v8, v9, v6, v7}, Lcom/google/android/gms/maps/model/LatLng;-><init>(DD)V

    .line 197
    .line 198
    .line 199
    invoke-direct {v0, v15, v11}, Lcom/google/android/gms/maps/model/LatLngBounds;-><init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 200
    .line 201
    .line 202
    :goto_6
    iget-object v6, v2, Lsu/i;->l:Ljava/util/Set;

    .line 203
    .line 204
    const/4 v7, 0x0

    .line 205
    if-eqz v6, :cond_9

    .line 206
    .line 207
    iget-boolean v6, v2, Lsu/i;->d:Z

    .line 208
    .line 209
    if-eqz v6, :cond_9

    .line 210
    .line 211
    new-instance v6, Ljava/util/ArrayList;

    .line 212
    .line 213
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 214
    .line 215
    .line 216
    iget-object v8, v2, Lsu/i;->l:Ljava/util/Set;

    .line 217
    .line 218
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 219
    .line 220
    .line 221
    move-result-object v8

    .line 222
    :cond_8
    :goto_7
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 223
    .line 224
    .line 225
    move-result v9

    .line 226
    if-eqz v9, :cond_a

    .line 227
    .line 228
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 229
    .line 230
    .line 231
    move-result-object v9

    .line 232
    check-cast v9, Lqu/a;

    .line 233
    .line 234
    invoke-interface {v9}, Lqu/a;->a()I

    .line 235
    .line 236
    .line 237
    move-result v11

    .line 238
    if-lt v11, v3, :cond_8

    .line 239
    .line 240
    invoke-interface {v9}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 241
    .line 242
    .line 243
    move-result-object v11

    .line 244
    invoke-virtual {v0, v11}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    if-eqz v11, :cond_8

    .line 249
    .line 250
    iget-object v11, v1, Lsu/g;->g:Lyu/b;

    .line 251
    .line 252
    invoke-interface {v9}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 253
    .line 254
    .line 255
    move-result-object v9

    .line 256
    invoke-virtual {v11, v9}, Lyu/b;->b(Lcom/google/android/gms/maps/model/LatLng;)Lyu/a;

    .line 257
    .line 258
    .line 259
    move-result-object v9

    .line 260
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    goto :goto_7

    .line 264
    :cond_9
    move-object v6, v7

    .line 265
    :cond_a
    new-instance v8, Ljava/util/concurrent/ConcurrentHashMap;

    .line 266
    .line 267
    invoke-direct {v8}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 268
    .line 269
    .line 270
    invoke-static {v8}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 271
    .line 272
    .line 273
    move-result-object v8

    .line 274
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 275
    .line 276
    .line 277
    move-result-object v9

    .line 278
    :goto_8
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 279
    .line 280
    .line 281
    move-result v11

    .line 282
    if-eqz v11, :cond_d

    .line 283
    .line 284
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v11

    .line 288
    check-cast v11, Lqu/a;

    .line 289
    .line 290
    invoke-interface {v11}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 291
    .line 292
    .line 293
    move-result-object v12

    .line 294
    invoke-virtual {v0, v12}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 295
    .line 296
    .line 297
    move-result v12

    .line 298
    if-eqz v18, :cond_c

    .line 299
    .line 300
    if-eqz v12, :cond_c

    .line 301
    .line 302
    iget-boolean v13, v2, Lsu/i;->d:Z

    .line 303
    .line 304
    if-eqz v13, :cond_c

    .line 305
    .line 306
    iget-object v12, v1, Lsu/g;->g:Lyu/b;

    .line 307
    .line 308
    invoke-interface {v11}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 309
    .line 310
    .line 311
    move-result-object v13

    .line 312
    invoke-virtual {v12, v13}, Lyu/b;->b(Lcom/google/android/gms/maps/model/LatLng;)Lyu/a;

    .line 313
    .line 314
    .line 315
    move-result-object v12

    .line 316
    invoke-static {v2, v6, v12}, Lsu/i;->b(Lsu/i;Ljava/util/ArrayList;Lyu/a;)Lyu/a;

    .line 317
    .line 318
    .line 319
    move-result-object v12

    .line 320
    if-eqz v12, :cond_b

    .line 321
    .line 322
    iget-object v13, v1, Lsu/g;->g:Lyu/b;

    .line 323
    .line 324
    invoke-virtual {v13, v12}, Lyu/b;->a(Lyu/a;)Lcom/google/android/gms/maps/model/LatLng;

    .line 325
    .line 326
    .line 327
    move-result-object v12

    .line 328
    new-instance v13, Lsu/d;

    .line 329
    .line 330
    invoke-direct {v13, v2, v11, v8, v12}, Lsu/d;-><init>(Lsu/i;Lqu/a;Ljava/util/Set;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 331
    .line 332
    .line 333
    const/4 v15, 0x1

    .line 334
    invoke-virtual {v5, v15, v13}, Lsu/e;->a(ZLsu/d;)V

    .line 335
    .line 336
    .line 337
    goto :goto_8

    .line 338
    :cond_b
    const/4 v15, 0x1

    .line 339
    new-instance v12, Lsu/d;

    .line 340
    .line 341
    invoke-direct {v12, v2, v11, v8, v7}, Lsu/d;-><init>(Lsu/i;Lqu/a;Ljava/util/Set;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 342
    .line 343
    .line 344
    invoke-virtual {v5, v15, v12}, Lsu/e;->a(ZLsu/d;)V

    .line 345
    .line 346
    .line 347
    goto :goto_8

    .line 348
    :cond_c
    new-instance v13, Lsu/d;

    .line 349
    .line 350
    invoke-direct {v13, v2, v11, v8, v7}, Lsu/d;-><init>(Lsu/i;Lqu/a;Ljava/util/Set;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v5, v12, v13}, Lsu/e;->a(ZLsu/d;)V

    .line 354
    .line 355
    .line 356
    goto :goto_8

    .line 357
    :cond_d
    invoke-virtual {v5}, Lsu/e;->e()V

    .line 358
    .line 359
    .line 360
    invoke-interface {v10, v8}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 361
    .line 362
    .line 363
    iget-boolean v6, v2, Lsu/i;->d:Z

    .line 364
    .line 365
    if-eqz v6, :cond_f

    .line 366
    .line 367
    new-instance v7, Ljava/util/ArrayList;

    .line 368
    .line 369
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 370
    .line 371
    .line 372
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 373
    .line 374
    .line 375
    move-result-object v6

    .line 376
    :cond_e
    :goto_9
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 377
    .line 378
    .line 379
    move-result v9

    .line 380
    if-eqz v9, :cond_f

    .line 381
    .line 382
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v9

    .line 386
    check-cast v9, Lqu/a;

    .line 387
    .line 388
    invoke-interface {v9}, Lqu/a;->a()I

    .line 389
    .line 390
    .line 391
    move-result v11

    .line 392
    if-lt v11, v3, :cond_e

    .line 393
    .line 394
    invoke-interface {v9}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 395
    .line 396
    .line 397
    move-result-object v11

    .line 398
    invoke-virtual {v0, v11}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 399
    .line 400
    .line 401
    move-result v11

    .line 402
    if-eqz v11, :cond_e

    .line 403
    .line 404
    iget-object v11, v1, Lsu/g;->g:Lyu/b;

    .line 405
    .line 406
    invoke-interface {v9}, Lqu/a;->getPosition()Lcom/google/android/gms/maps/model/LatLng;

    .line 407
    .line 408
    .line 409
    move-result-object v9

    .line 410
    invoke-virtual {v11, v9}, Lyu/b;->b(Lcom/google/android/gms/maps/model/LatLng;)Lyu/a;

    .line 411
    .line 412
    .line 413
    move-result-object v9

    .line 414
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 415
    .line 416
    .line 417
    goto :goto_9

    .line 418
    :cond_f
    invoke-interface {v10}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 419
    .line 420
    .line 421
    move-result-object v3

    .line 422
    :goto_a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 423
    .line 424
    .line 425
    move-result v6

    .line 426
    if-eqz v6, :cond_12

    .line 427
    .line 428
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v6

    .line 432
    check-cast v6, Lsu/f;

    .line 433
    .line 434
    iget-object v9, v6, Lsu/f;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 435
    .line 436
    iget-object v10, v6, Lsu/f;->a:Lsp/k;

    .line 437
    .line 438
    invoke-virtual {v0, v9}, Lcom/google/android/gms/maps/model/LatLngBounds;->x0(Lcom/google/android/gms/maps/model/LatLng;)Z

    .line 439
    .line 440
    .line 441
    move-result v9

    .line 442
    if-nez v18, :cond_11

    .line 443
    .line 444
    const/high16 v11, -0x3fc00000    # -3.0f

    .line 445
    .line 446
    cmpl-float v11, v16, v11

    .line 447
    .line 448
    if-lez v11, :cond_11

    .line 449
    .line 450
    if-eqz v9, :cond_11

    .line 451
    .line 452
    iget-boolean v11, v2, Lsu/i;->d:Z

    .line 453
    .line 454
    if-eqz v11, :cond_11

    .line 455
    .line 456
    iget-object v9, v1, Lsu/g;->g:Lyu/b;

    .line 457
    .line 458
    iget-object v11, v6, Lsu/f;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 459
    .line 460
    invoke-virtual {v9, v11}, Lyu/b;->b(Lcom/google/android/gms/maps/model/LatLng;)Lyu/a;

    .line 461
    .line 462
    .line 463
    move-result-object v9

    .line 464
    invoke-static {v2, v7, v9}, Lsu/i;->b(Lsu/i;Ljava/util/ArrayList;Lyu/a;)Lyu/a;

    .line 465
    .line 466
    .line 467
    move-result-object v9

    .line 468
    if-eqz v9, :cond_10

    .line 469
    .line 470
    iget-object v10, v1, Lsu/g;->g:Lyu/b;

    .line 471
    .line 472
    invoke-virtual {v10, v9}, Lyu/b;->a(Lyu/a;)Lcom/google/android/gms/maps/model/LatLng;

    .line 473
    .line 474
    .line 475
    move-result-object v9

    .line 476
    iget-object v10, v6, Lsu/f;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 477
    .line 478
    iget-object v11, v5, Lsu/e;->d:Ljava/util/concurrent/locks/ReentrantLock;

    .line 479
    .line 480
    invoke-virtual {v11}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    .line 481
    .line 482
    .line 483
    new-instance v12, Lsu/c;

    .line 484
    .line 485
    iget-object v13, v5, Lsu/e;->l:Lsu/i;

    .line 486
    .line 487
    invoke-direct {v12, v13, v6, v10, v9}, Lsu/c;-><init>(Lsu/i;Lsu/f;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V

    .line 488
    .line 489
    .line 490
    iget-object v6, v13, Lsu/i;->c:Lqu/c;

    .line 491
    .line 492
    iget-object v6, v6, Lqu/c;->d:Ltu/b;

    .line 493
    .line 494
    iput-object v6, v12, Lsu/c;->f:Ltu/b;

    .line 495
    .line 496
    const/4 v15, 0x1

    .line 497
    iput-boolean v15, v12, Lsu/c;->e:Z

    .line 498
    .line 499
    iget-object v6, v5, Lsu/e;->j:Ljava/util/LinkedList;

    .line 500
    .line 501
    invoke-virtual {v6, v12}, Ljava/util/LinkedList;->add(Ljava/lang/Object;)Z

    .line 502
    .line 503
    .line 504
    invoke-virtual {v11}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    .line 505
    .line 506
    .line 507
    goto :goto_a

    .line 508
    :cond_10
    const/4 v15, 0x1

    .line 509
    invoke-virtual {v5, v15, v10}, Lsu/e;->d(ZLsp/k;)V

    .line 510
    .line 511
    .line 512
    goto :goto_a

    .line 513
    :cond_11
    const/4 v15, 0x1

    .line 514
    invoke-virtual {v5, v9, v10}, Lsu/e;->d(ZLsp/k;)V

    .line 515
    .line 516
    .line 517
    goto :goto_a

    .line 518
    :cond_12
    invoke-virtual {v5}, Lsu/e;->e()V

    .line 519
    .line 520
    .line 521
    iput-object v8, v2, Lsu/i;->h:Ljava/util/Set;

    .line 522
    .line 523
    iput-object v4, v2, Lsu/i;->l:Ljava/util/Set;

    .line 524
    .line 525
    move/from16 v3, v17

    .line 526
    .line 527
    iput v3, v2, Lsu/i;->n:F

    .line 528
    .line 529
    iget-object v0, v1, Lsu/g;->e:Lm8/o;

    .line 530
    .line 531
    invoke-virtual {v0}, Lm8/o;->run()V

    .line 532
    .line 533
    .line 534
    return-void
.end method
