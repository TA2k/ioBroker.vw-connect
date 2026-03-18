.class public final Lxm/l;
.super Lxm/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcn/k;

.field public final i:Landroid/graphics/Path;

.field public j:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lxm/e;-><init>(Ljava/util/List;)V

    .line 2
    .line 3
    .line 4
    new-instance p1, Lcn/k;

    .line 5
    .line 6
    invoke-direct {p1}, Lcn/k;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lxm/l;->h:Lcn/k;

    .line 10
    .line 11
    new-instance p1, Landroid/graphics/Path;

    .line 12
    .line 13
    invoke-direct {p1}, Landroid/graphics/Path;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lxm/l;->i:Landroid/graphics/Path;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final e(Lhn/a;F)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p2

    .line 6
    .line 7
    iget-object v3, v1, Lhn/a;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lcn/k;

    .line 10
    .line 11
    iget-object v1, v1, Lhn/a;->c:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v1, Lcn/k;

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    move-object v1, v3

    .line 18
    :cond_0
    iget-object v4, v0, Lxm/l;->h:Lcn/k;

    .line 19
    .line 20
    iget-object v5, v4, Lcn/k;->a:Ljava/util/ArrayList;

    .line 21
    .line 22
    iget-object v6, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 23
    .line 24
    if-nez v6, :cond_1

    .line 25
    .line 26
    new-instance v6, Landroid/graphics/PointF;

    .line 27
    .line 28
    invoke-direct {v6}, Landroid/graphics/PointF;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v6, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 32
    .line 33
    :cond_1
    iget-boolean v6, v3, Lcn/k;->c:Z

    .line 34
    .line 35
    iget-object v7, v3, Lcn/k;->a:Ljava/util/ArrayList;

    .line 36
    .line 37
    const/4 v9, 0x1

    .line 38
    if-nez v6, :cond_3

    .line 39
    .line 40
    iget-boolean v6, v1, Lcn/k;->c:Z

    .line 41
    .line 42
    if-eqz v6, :cond_2

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_2
    const/4 v6, 0x0

    .line 46
    goto :goto_1

    .line 47
    :cond_3
    :goto_0
    move v6, v9

    .line 48
    :goto_1
    iput-boolean v6, v4, Lcn/k;->c:Z

    .line 49
    .line 50
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 51
    .line 52
    .line 53
    move-result v6

    .line 54
    iget-object v10, v1, Lcn/k;->a:Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 57
    .line 58
    .line 59
    move-result v11

    .line 60
    if-eq v6, v11, :cond_4

    .line 61
    .line 62
    new-instance v6, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v11, "Curves must have the same number of control points. Shape 1: "

    .line 65
    .line 66
    invoke-direct {v6, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 70
    .line 71
    .line 72
    move-result v11

    .line 73
    invoke-virtual {v6, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v11, "\tShape 2: "

    .line 77
    .line 78
    invoke-virtual {v6, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 82
    .line 83
    .line 84
    move-result v11

    .line 85
    invoke-virtual {v6, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    invoke-static {v6}, Lgn/c;->a(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    :cond_4
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 96
    .line 97
    .line 98
    move-result v6

    .line 99
    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    .line 100
    .line 101
    .line 102
    move-result v11

    .line 103
    invoke-static {v6, v11}, Ljava/lang/Math;->min(II)I

    .line 104
    .line 105
    .line 106
    move-result v6

    .line 107
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 108
    .line 109
    .line 110
    move-result v11

    .line 111
    if-ge v11, v6, :cond_5

    .line 112
    .line 113
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 114
    .line 115
    .line 116
    move-result v11

    .line 117
    :goto_2
    if-ge v11, v6, :cond_6

    .line 118
    .line 119
    new-instance v12, Lan/a;

    .line 120
    .line 121
    invoke-direct {v12}, Lan/a;-><init>()V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    add-int/lit8 v11, v11, 0x1

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_5
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 131
    .line 132
    .line 133
    move-result v11

    .line 134
    if-le v11, v6, :cond_6

    .line 135
    .line 136
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 137
    .line 138
    .line 139
    move-result v11

    .line 140
    sub-int/2addr v11, v9

    .line 141
    :goto_3
    if-lt v11, v6, :cond_6

    .line 142
    .line 143
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 144
    .line 145
    .line 146
    move-result v12

    .line 147
    sub-int/2addr v12, v9

    .line 148
    invoke-virtual {v5, v12}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    add-int/lit8 v11, v11, -0x1

    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_6
    iget-object v3, v3, Lcn/k;->b:Landroid/graphics/PointF;

    .line 155
    .line 156
    iget-object v1, v1, Lcn/k;->b:Landroid/graphics/PointF;

    .line 157
    .line 158
    iget v6, v3, Landroid/graphics/PointF;->x:F

    .line 159
    .line 160
    iget v11, v1, Landroid/graphics/PointF;->x:F

    .line 161
    .line 162
    invoke-static {v6, v11, v2}, Lgn/f;->e(FFF)F

    .line 163
    .line 164
    .line 165
    move-result v6

    .line 166
    iget v3, v3, Landroid/graphics/PointF;->y:F

    .line 167
    .line 168
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 169
    .line 170
    invoke-static {v3, v1, v2}, Lgn/f;->e(FFF)F

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    invoke-virtual {v4, v6, v1}, Lcn/k;->a(FF)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    sub-int/2addr v1, v9

    .line 182
    :goto_4
    if-ltz v1, :cond_7

    .line 183
    .line 184
    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v3

    .line 188
    check-cast v3, Lan/a;

    .line 189
    .line 190
    invoke-virtual {v10, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    check-cast v6, Lan/a;

    .line 195
    .line 196
    iget-object v11, v3, Lan/a;->a:Landroid/graphics/PointF;

    .line 197
    .line 198
    iget-object v12, v3, Lan/a;->b:Landroid/graphics/PointF;

    .line 199
    .line 200
    iget-object v3, v3, Lan/a;->c:Landroid/graphics/PointF;

    .line 201
    .line 202
    iget-object v13, v6, Lan/a;->a:Landroid/graphics/PointF;

    .line 203
    .line 204
    iget-object v14, v6, Lan/a;->b:Landroid/graphics/PointF;

    .line 205
    .line 206
    iget-object v6, v6, Lan/a;->c:Landroid/graphics/PointF;

    .line 207
    .line 208
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object v15

    .line 212
    check-cast v15, Lan/a;

    .line 213
    .line 214
    move/from16 p1, v9

    .line 215
    .line 216
    iget v9, v11, Landroid/graphics/PointF;->x:F

    .line 217
    .line 218
    iget v8, v13, Landroid/graphics/PointF;->x:F

    .line 219
    .line 220
    invoke-static {v9, v8, v2}, Lgn/f;->e(FFF)F

    .line 221
    .line 222
    .line 223
    move-result v8

    .line 224
    iget v9, v11, Landroid/graphics/PointF;->y:F

    .line 225
    .line 226
    iget v11, v13, Landroid/graphics/PointF;->y:F

    .line 227
    .line 228
    invoke-static {v9, v11, v2}, Lgn/f;->e(FFF)F

    .line 229
    .line 230
    .line 231
    move-result v9

    .line 232
    iget-object v11, v15, Lan/a;->a:Landroid/graphics/PointF;

    .line 233
    .line 234
    invoke-virtual {v11, v8, v9}, Landroid/graphics/PointF;->set(FF)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object v8

    .line 241
    check-cast v8, Lan/a;

    .line 242
    .line 243
    iget v9, v12, Landroid/graphics/PointF;->x:F

    .line 244
    .line 245
    iget v11, v14, Landroid/graphics/PointF;->x:F

    .line 246
    .line 247
    invoke-static {v9, v11, v2}, Lgn/f;->e(FFF)F

    .line 248
    .line 249
    .line 250
    move-result v9

    .line 251
    iget v11, v12, Landroid/graphics/PointF;->y:F

    .line 252
    .line 253
    iget v12, v14, Landroid/graphics/PointF;->y:F

    .line 254
    .line 255
    invoke-static {v11, v12, v2}, Lgn/f;->e(FFF)F

    .line 256
    .line 257
    .line 258
    move-result v11

    .line 259
    iget-object v8, v8, Lan/a;->b:Landroid/graphics/PointF;

    .line 260
    .line 261
    invoke-virtual {v8, v9, v11}, Landroid/graphics/PointF;->set(FF)V

    .line 262
    .line 263
    .line 264
    invoke-virtual {v5, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v8

    .line 268
    check-cast v8, Lan/a;

    .line 269
    .line 270
    iget v9, v3, Landroid/graphics/PointF;->x:F

    .line 271
    .line 272
    iget v11, v6, Landroid/graphics/PointF;->x:F

    .line 273
    .line 274
    invoke-static {v9, v11, v2}, Lgn/f;->e(FFF)F

    .line 275
    .line 276
    .line 277
    move-result v9

    .line 278
    iget v3, v3, Landroid/graphics/PointF;->y:F

    .line 279
    .line 280
    iget v6, v6, Landroid/graphics/PointF;->y:F

    .line 281
    .line 282
    invoke-static {v3, v6, v2}, Lgn/f;->e(FFF)F

    .line 283
    .line 284
    .line 285
    move-result v3

    .line 286
    iget-object v6, v8, Lan/a;->c:Landroid/graphics/PointF;

    .line 287
    .line 288
    invoke-virtual {v6, v9, v3}, Landroid/graphics/PointF;->set(FF)V

    .line 289
    .line 290
    .line 291
    add-int/lit8 v1, v1, -0x1

    .line 292
    .line 293
    move/from16 v9, p1

    .line 294
    .line 295
    goto :goto_4

    .line 296
    :cond_7
    move/from16 p1, v9

    .line 297
    .line 298
    iget-object v1, v0, Lxm/l;->j:Ljava/util/ArrayList;

    .line 299
    .line 300
    if-eqz v1, :cond_1b

    .line 301
    .line 302
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 303
    .line 304
    .line 305
    move-result v1

    .line 306
    add-int/lit8 v1, v1, -0x1

    .line 307
    .line 308
    :goto_5
    iget-object v2, v4, Lcn/k;->a:Ljava/util/ArrayList;

    .line 309
    .line 310
    if-ltz v1, :cond_1a

    .line 311
    .line 312
    iget-object v3, v0, Lxm/l;->j:Ljava/util/ArrayList;

    .line 313
    .line 314
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 315
    .line 316
    .line 317
    move-result-object v3

    .line 318
    check-cast v3, Lwm/p;

    .line 319
    .line 320
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 321
    .line 322
    .line 323
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 324
    .line 325
    .line 326
    move-result v5

    .line 327
    const/4 v6, 0x2

    .line 328
    if-gt v5, v6, :cond_8

    .line 329
    .line 330
    goto :goto_6

    .line 331
    :cond_8
    iget-object v5, v3, Lwm/p;->b:Lxm/e;

    .line 332
    .line 333
    invoke-virtual {v5}, Lxm/e;->d()Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v5

    .line 337
    check-cast v5, Ljava/lang/Float;

    .line 338
    .line 339
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    const/4 v6, 0x0

    .line 344
    cmpl-float v7, v5, v6

    .line 345
    .line 346
    if-nez v7, :cond_9

    .line 347
    .line 348
    :goto_6
    move/from16 p2, v1

    .line 349
    .line 350
    goto/16 :goto_14

    .line 351
    .line 352
    :cond_9
    iget-boolean v7, v4, Lcn/k;->c:Z

    .line 353
    .line 354
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 355
    .line 356
    .line 357
    move-result v8

    .line 358
    add-int/lit8 v8, v8, -0x1

    .line 359
    .line 360
    const/4 v9, 0x0

    .line 361
    :goto_7
    if-ltz v8, :cond_f

    .line 362
    .line 363
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v10

    .line 367
    check-cast v10, Lan/a;

    .line 368
    .line 369
    add-int/lit8 v11, v8, -0x1

    .line 370
    .line 371
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 372
    .line 373
    .line 374
    move-result v12

    .line 375
    invoke-static {v11, v12}, Lwm/p;->f(II)I

    .line 376
    .line 377
    .line 378
    move-result v11

    .line 379
    invoke-interface {v2, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v11

    .line 383
    check-cast v11, Lan/a;

    .line 384
    .line 385
    if-nez v8, :cond_a

    .line 386
    .line 387
    if-nez v7, :cond_a

    .line 388
    .line 389
    iget-object v12, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 390
    .line 391
    goto :goto_8

    .line 392
    :cond_a
    iget-object v12, v11, Lan/a;->c:Landroid/graphics/PointF;

    .line 393
    .line 394
    :goto_8
    if-nez v8, :cond_b

    .line 395
    .line 396
    if-nez v7, :cond_b

    .line 397
    .line 398
    move-object v11, v12

    .line 399
    goto :goto_9

    .line 400
    :cond_b
    iget-object v11, v11, Lan/a;->b:Landroid/graphics/PointF;

    .line 401
    .line 402
    :goto_9
    iget-object v10, v10, Lan/a;->a:Landroid/graphics/PointF;

    .line 403
    .line 404
    iget-boolean v13, v4, Lcn/k;->c:Z

    .line 405
    .line 406
    if-nez v13, :cond_d

    .line 407
    .line 408
    if-eqz v8, :cond_c

    .line 409
    .line 410
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 411
    .line 412
    .line 413
    move-result v13

    .line 414
    add-int/lit8 v13, v13, -0x1

    .line 415
    .line 416
    if-ne v8, v13, :cond_d

    .line 417
    .line 418
    :cond_c
    move/from16 v13, p1

    .line 419
    .line 420
    goto :goto_a

    .line 421
    :cond_d
    const/4 v13, 0x0

    .line 422
    :goto_a
    invoke-virtual {v11, v12}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 423
    .line 424
    .line 425
    move-result v11

    .line 426
    if-eqz v11, :cond_e

    .line 427
    .line 428
    invoke-virtual {v10, v12}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 429
    .line 430
    .line 431
    move-result v10

    .line 432
    if-eqz v10, :cond_e

    .line 433
    .line 434
    if-nez v13, :cond_e

    .line 435
    .line 436
    add-int/lit8 v9, v9, 0x2

    .line 437
    .line 438
    goto :goto_b

    .line 439
    :cond_e
    add-int/lit8 v9, v9, 0x1

    .line 440
    .line 441
    :goto_b
    add-int/lit8 v8, v8, -0x1

    .line 442
    .line 443
    goto :goto_7

    .line 444
    :cond_f
    iget-object v8, v3, Lwm/p;->c:Lcn/k;

    .line 445
    .line 446
    if-eqz v8, :cond_11

    .line 447
    .line 448
    iget-object v8, v8, Lcn/k;->a:Ljava/util/ArrayList;

    .line 449
    .line 450
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 451
    .line 452
    .line 453
    move-result v8

    .line 454
    if-eq v8, v9, :cond_10

    .line 455
    .line 456
    goto :goto_c

    .line 457
    :cond_10
    const/4 v6, 0x0

    .line 458
    goto :goto_e

    .line 459
    :cond_11
    :goto_c
    new-instance v8, Ljava/util/ArrayList;

    .line 460
    .line 461
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 462
    .line 463
    .line 464
    const/4 v10, 0x0

    .line 465
    :goto_d
    if-ge v10, v9, :cond_12

    .line 466
    .line 467
    new-instance v11, Lan/a;

    .line 468
    .line 469
    invoke-direct {v11}, Lan/a;-><init>()V

    .line 470
    .line 471
    .line 472
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 473
    .line 474
    .line 475
    add-int/lit8 v10, v10, 0x1

    .line 476
    .line 477
    goto :goto_d

    .line 478
    :cond_12
    new-instance v9, Lcn/k;

    .line 479
    .line 480
    new-instance v10, Landroid/graphics/PointF;

    .line 481
    .line 482
    invoke-direct {v10, v6, v6}, Landroid/graphics/PointF;-><init>(FF)V

    .line 483
    .line 484
    .line 485
    const/4 v6, 0x0

    .line 486
    invoke-direct {v9, v10, v6, v8}, Lcn/k;-><init>(Landroid/graphics/PointF;ZLjava/util/List;)V

    .line 487
    .line 488
    .line 489
    iput-object v9, v3, Lwm/p;->c:Lcn/k;

    .line 490
    .line 491
    :goto_e
    iget-object v3, v3, Lwm/p;->c:Lcn/k;

    .line 492
    .line 493
    iput-boolean v7, v3, Lcn/k;->c:Z

    .line 494
    .line 495
    iget-object v7, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 496
    .line 497
    iget v8, v7, Landroid/graphics/PointF;->x:F

    .line 498
    .line 499
    iget v7, v7, Landroid/graphics/PointF;->y:F

    .line 500
    .line 501
    invoke-virtual {v3, v8, v7}, Lcn/k;->a(FF)V

    .line 502
    .line 503
    .line 504
    iget-object v7, v3, Lcn/k;->a:Ljava/util/ArrayList;

    .line 505
    .line 506
    iget-boolean v8, v4, Lcn/k;->c:Z

    .line 507
    .line 508
    move v9, v6

    .line 509
    move v10, v9

    .line 510
    :goto_f
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 511
    .line 512
    .line 513
    move-result v11

    .line 514
    if-ge v9, v11, :cond_19

    .line 515
    .line 516
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v11

    .line 520
    check-cast v11, Lan/a;

    .line 521
    .line 522
    add-int/lit8 v12, v9, -0x1

    .line 523
    .line 524
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 525
    .line 526
    .line 527
    move-result v13

    .line 528
    invoke-static {v12, v13}, Lwm/p;->f(II)I

    .line 529
    .line 530
    .line 531
    move-result v12

    .line 532
    invoke-interface {v2, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 533
    .line 534
    .line 535
    move-result-object v12

    .line 536
    check-cast v12, Lan/a;

    .line 537
    .line 538
    add-int/lit8 v13, v9, -0x2

    .line 539
    .line 540
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 541
    .line 542
    .line 543
    move-result v14

    .line 544
    invoke-static {v13, v14}, Lwm/p;->f(II)I

    .line 545
    .line 546
    .line 547
    move-result v13

    .line 548
    invoke-interface {v2, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 549
    .line 550
    .line 551
    move-result-object v13

    .line 552
    check-cast v13, Lan/a;

    .line 553
    .line 554
    if-nez v9, :cond_13

    .line 555
    .line 556
    if-nez v8, :cond_13

    .line 557
    .line 558
    iget-object v14, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 559
    .line 560
    goto :goto_10

    .line 561
    :cond_13
    iget-object v14, v12, Lan/a;->c:Landroid/graphics/PointF;

    .line 562
    .line 563
    :goto_10
    if-nez v9, :cond_14

    .line 564
    .line 565
    if-nez v8, :cond_14

    .line 566
    .line 567
    move-object v15, v14

    .line 568
    goto :goto_11

    .line 569
    :cond_14
    iget-object v15, v12, Lan/a;->b:Landroid/graphics/PointF;

    .line 570
    .line 571
    :goto_11
    iget-object v6, v11, Lan/a;->a:Landroid/graphics/PointF;

    .line 572
    .line 573
    iget-object v13, v13, Lan/a;->c:Landroid/graphics/PointF;

    .line 574
    .line 575
    move/from16 p2, v1

    .line 576
    .line 577
    iget-object v1, v11, Lan/a;->c:Landroid/graphics/PointF;

    .line 578
    .line 579
    move-object/from16 v16, v2

    .line 580
    .line 581
    iget-boolean v2, v4, Lcn/k;->c:Z

    .line 582
    .line 583
    if-nez v2, :cond_16

    .line 584
    .line 585
    if-eqz v9, :cond_15

    .line 586
    .line 587
    invoke-interface/range {v16 .. v16}, Ljava/util/List;->size()I

    .line 588
    .line 589
    .line 590
    move-result v2

    .line 591
    add-int/lit8 v2, v2, -0x1

    .line 592
    .line 593
    if-ne v9, v2, :cond_16

    .line 594
    .line 595
    :cond_15
    move/from16 v2, p1

    .line 596
    .line 597
    goto :goto_12

    .line 598
    :cond_16
    const/4 v2, 0x0

    .line 599
    :goto_12
    invoke-virtual {v15, v14}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 600
    .line 601
    .line 602
    move-result v15

    .line 603
    if-eqz v15, :cond_18

    .line 604
    .line 605
    invoke-virtual {v6, v14}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 606
    .line 607
    .line 608
    move-result v6

    .line 609
    if-eqz v6, :cond_18

    .line 610
    .line 611
    if-nez v2, :cond_18

    .line 612
    .line 613
    iget v2, v14, Landroid/graphics/PointF;->x:F

    .line 614
    .line 615
    iget v6, v13, Landroid/graphics/PointF;->x:F

    .line 616
    .line 617
    sub-float v6, v2, v6

    .line 618
    .line 619
    iget v11, v14, Landroid/graphics/PointF;->y:F

    .line 620
    .line 621
    iget v12, v13, Landroid/graphics/PointF;->y:F

    .line 622
    .line 623
    sub-float v12, v11, v12

    .line 624
    .line 625
    iget v15, v1, Landroid/graphics/PointF;->x:F

    .line 626
    .line 627
    sub-float/2addr v15, v2

    .line 628
    iget v2, v1, Landroid/graphics/PointF;->y:F

    .line 629
    .line 630
    sub-float/2addr v2, v11

    .line 631
    move-object/from16 v17, v4

    .line 632
    .line 633
    move/from16 v18, v5

    .line 634
    .line 635
    float-to-double v4, v6

    .line 636
    float-to-double v11, v12

    .line 637
    invoke-static {v4, v5, v11, v12}, Ljava/lang/Math;->hypot(DD)D

    .line 638
    .line 639
    .line 640
    move-result-wide v4

    .line 641
    double-to-float v4, v4

    .line 642
    float-to-double v5, v15

    .line 643
    float-to-double v11, v2

    .line 644
    invoke-static {v5, v6, v11, v12}, Ljava/lang/Math;->hypot(DD)D

    .line 645
    .line 646
    .line 647
    move-result-wide v5

    .line 648
    double-to-float v2, v5

    .line 649
    div-float v5, v18, v4

    .line 650
    .line 651
    const/high16 v4, 0x3f000000    # 0.5f

    .line 652
    .line 653
    invoke-static {v5, v4}, Ljava/lang/Math;->min(FF)F

    .line 654
    .line 655
    .line 656
    move-result v5

    .line 657
    div-float v2, v18, v2

    .line 658
    .line 659
    invoke-static {v2, v4}, Ljava/lang/Math;->min(FF)F

    .line 660
    .line 661
    .line 662
    move-result v2

    .line 663
    iget v4, v14, Landroid/graphics/PointF;->x:F

    .line 664
    .line 665
    iget v6, v13, Landroid/graphics/PointF;->x:F

    .line 666
    .line 667
    invoke-static {v6, v4, v5, v4}, La7/g0;->b(FFFF)F

    .line 668
    .line 669
    .line 670
    move-result v6

    .line 671
    iget v11, v14, Landroid/graphics/PointF;->y:F

    .line 672
    .line 673
    iget v12, v13, Landroid/graphics/PointF;->y:F

    .line 674
    .line 675
    invoke-static {v12, v11, v5, v11}, La7/g0;->b(FFFF)F

    .line 676
    .line 677
    .line 678
    move-result v5

    .line 679
    iget v12, v1, Landroid/graphics/PointF;->x:F

    .line 680
    .line 681
    invoke-static {v12, v4, v2, v4}, La7/g0;->b(FFFF)F

    .line 682
    .line 683
    .line 684
    move-result v12

    .line 685
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 686
    .line 687
    invoke-static {v1, v11, v2, v11}, La7/g0;->b(FFFF)F

    .line 688
    .line 689
    .line 690
    move-result v1

    .line 691
    sub-float v2, v6, v4

    .line 692
    .line 693
    const v13, 0x3f0d4952    # 0.5519f

    .line 694
    .line 695
    .line 696
    mul-float/2addr v2, v13

    .line 697
    sub-float v2, v6, v2

    .line 698
    .line 699
    sub-float v14, v5, v11

    .line 700
    .line 701
    mul-float/2addr v14, v13

    .line 702
    sub-float v14, v5, v14

    .line 703
    .line 704
    sub-float v4, v12, v4

    .line 705
    .line 706
    mul-float/2addr v4, v13

    .line 707
    sub-float v4, v12, v4

    .line 708
    .line 709
    sub-float v11, v1, v11

    .line 710
    .line 711
    mul-float/2addr v11, v13

    .line 712
    sub-float v11, v1, v11

    .line 713
    .line 714
    add-int/lit8 v13, v10, -0x1

    .line 715
    .line 716
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 717
    .line 718
    .line 719
    move-result v15

    .line 720
    invoke-static {v13, v15}, Lwm/p;->f(II)I

    .line 721
    .line 722
    .line 723
    move-result v13

    .line 724
    invoke-interface {v7, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 725
    .line 726
    .line 727
    move-result-object v13

    .line 728
    check-cast v13, Lan/a;

    .line 729
    .line 730
    invoke-interface {v7, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    move-result-object v15

    .line 734
    check-cast v15, Lan/a;

    .line 735
    .line 736
    move/from16 v19, v8

    .line 737
    .line 738
    iget-object v8, v13, Lan/a;->b:Landroid/graphics/PointF;

    .line 739
    .line 740
    invoke-virtual {v8, v6, v5}, Landroid/graphics/PointF;->set(FF)V

    .line 741
    .line 742
    .line 743
    iget-object v8, v13, Lan/a;->c:Landroid/graphics/PointF;

    .line 744
    .line 745
    invoke-virtual {v8, v6, v5}, Landroid/graphics/PointF;->set(FF)V

    .line 746
    .line 747
    .line 748
    if-nez v9, :cond_17

    .line 749
    .line 750
    invoke-virtual {v3, v6, v5}, Lcn/k;->a(FF)V

    .line 751
    .line 752
    .line 753
    :cond_17
    iget-object v5, v15, Lan/a;->a:Landroid/graphics/PointF;

    .line 754
    .line 755
    invoke-virtual {v5, v2, v14}, Landroid/graphics/PointF;->set(FF)V

    .line 756
    .line 757
    .line 758
    add-int/lit8 v2, v10, 0x1

    .line 759
    .line 760
    invoke-interface {v7, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 761
    .line 762
    .line 763
    move-result-object v2

    .line 764
    check-cast v2, Lan/a;

    .line 765
    .line 766
    iget-object v5, v15, Lan/a;->b:Landroid/graphics/PointF;

    .line 767
    .line 768
    invoke-virtual {v5, v4, v11}, Landroid/graphics/PointF;->set(FF)V

    .line 769
    .line 770
    .line 771
    iget-object v4, v15, Lan/a;->c:Landroid/graphics/PointF;

    .line 772
    .line 773
    invoke-virtual {v4, v12, v1}, Landroid/graphics/PointF;->set(FF)V

    .line 774
    .line 775
    .line 776
    iget-object v2, v2, Lan/a;->a:Landroid/graphics/PointF;

    .line 777
    .line 778
    invoke-virtual {v2, v12, v1}, Landroid/graphics/PointF;->set(FF)V

    .line 779
    .line 780
    .line 781
    add-int/lit8 v10, v10, 0x2

    .line 782
    .line 783
    goto :goto_13

    .line 784
    :cond_18
    move-object/from16 v17, v4

    .line 785
    .line 786
    move/from16 v18, v5

    .line 787
    .line 788
    move/from16 v19, v8

    .line 789
    .line 790
    add-int/lit8 v1, v10, -0x1

    .line 791
    .line 792
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 793
    .line 794
    .line 795
    move-result v2

    .line 796
    invoke-static {v1, v2}, Lwm/p;->f(II)I

    .line 797
    .line 798
    .line 799
    move-result v1

    .line 800
    invoke-interface {v7, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 801
    .line 802
    .line 803
    move-result-object v1

    .line 804
    check-cast v1, Lan/a;

    .line 805
    .line 806
    invoke-interface {v7, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 807
    .line 808
    .line 809
    move-result-object v2

    .line 810
    check-cast v2, Lan/a;

    .line 811
    .line 812
    iget-object v4, v12, Lan/a;->b:Landroid/graphics/PointF;

    .line 813
    .line 814
    iget v5, v4, Landroid/graphics/PointF;->x:F

    .line 815
    .line 816
    iget v4, v4, Landroid/graphics/PointF;->y:F

    .line 817
    .line 818
    iget-object v6, v1, Lan/a;->b:Landroid/graphics/PointF;

    .line 819
    .line 820
    invoke-virtual {v6, v5, v4}, Landroid/graphics/PointF;->set(FF)V

    .line 821
    .line 822
    .line 823
    iget-object v4, v12, Lan/a;->c:Landroid/graphics/PointF;

    .line 824
    .line 825
    iget v5, v4, Landroid/graphics/PointF;->x:F

    .line 826
    .line 827
    iget v4, v4, Landroid/graphics/PointF;->y:F

    .line 828
    .line 829
    iget-object v1, v1, Lan/a;->c:Landroid/graphics/PointF;

    .line 830
    .line 831
    invoke-virtual {v1, v5, v4}, Landroid/graphics/PointF;->set(FF)V

    .line 832
    .line 833
    .line 834
    iget-object v1, v11, Lan/a;->a:Landroid/graphics/PointF;

    .line 835
    .line 836
    iget v4, v1, Landroid/graphics/PointF;->x:F

    .line 837
    .line 838
    iget v1, v1, Landroid/graphics/PointF;->y:F

    .line 839
    .line 840
    iget-object v2, v2, Lan/a;->a:Landroid/graphics/PointF;

    .line 841
    .line 842
    invoke-virtual {v2, v4, v1}, Landroid/graphics/PointF;->set(FF)V

    .line 843
    .line 844
    .line 845
    add-int/lit8 v10, v10, 0x1

    .line 846
    .line 847
    :goto_13
    add-int/lit8 v9, v9, 0x1

    .line 848
    .line 849
    move/from16 v1, p2

    .line 850
    .line 851
    move-object/from16 v2, v16

    .line 852
    .line 853
    move-object/from16 v4, v17

    .line 854
    .line 855
    move/from16 v5, v18

    .line 856
    .line 857
    move/from16 v8, v19

    .line 858
    .line 859
    const/4 v6, 0x0

    .line 860
    goto/16 :goto_f

    .line 861
    .line 862
    :cond_19
    move-object v4, v3

    .line 863
    goto/16 :goto_6

    .line 864
    .line 865
    :goto_14
    add-int/lit8 v1, p2, -0x1

    .line 866
    .line 867
    goto/16 :goto_5

    .line 868
    .line 869
    :cond_1a
    move-object/from16 v17, v4

    .line 870
    .line 871
    :cond_1b
    iget-object v5, v0, Lxm/l;->i:Landroid/graphics/Path;

    .line 872
    .line 873
    invoke-virtual {v5}, Landroid/graphics/Path;->reset()V

    .line 874
    .line 875
    .line 876
    iget-object v0, v4, Lcn/k;->b:Landroid/graphics/PointF;

    .line 877
    .line 878
    iget-object v1, v4, Lcn/k;->a:Ljava/util/ArrayList;

    .line 879
    .line 880
    iget v2, v0, Landroid/graphics/PointF;->x:F

    .line 881
    .line 882
    iget v3, v0, Landroid/graphics/PointF;->y:F

    .line 883
    .line 884
    invoke-virtual {v5, v2, v3}, Landroid/graphics/Path;->moveTo(FF)V

    .line 885
    .line 886
    .line 887
    sget-object v2, Lgn/f;->a:Landroid/graphics/PointF;

    .line 888
    .line 889
    iget v3, v0, Landroid/graphics/PointF;->x:F

    .line 890
    .line 891
    iget v0, v0, Landroid/graphics/PointF;->y:F

    .line 892
    .line 893
    invoke-virtual {v2, v3, v0}, Landroid/graphics/PointF;->set(FF)V

    .line 894
    .line 895
    .line 896
    const/4 v0, 0x0

    .line 897
    :goto_15
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 898
    .line 899
    .line 900
    move-result v3

    .line 901
    if-ge v0, v3, :cond_1d

    .line 902
    .line 903
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 904
    .line 905
    .line 906
    move-result-object v3

    .line 907
    check-cast v3, Lan/a;

    .line 908
    .line 909
    iget-object v6, v3, Lan/a;->a:Landroid/graphics/PointF;

    .line 910
    .line 911
    iget-object v7, v3, Lan/a;->b:Landroid/graphics/PointF;

    .line 912
    .line 913
    iget-object v3, v3, Lan/a;->c:Landroid/graphics/PointF;

    .line 914
    .line 915
    invoke-virtual {v6, v2}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 916
    .line 917
    .line 918
    move-result v8

    .line 919
    if-eqz v8, :cond_1c

    .line 920
    .line 921
    invoke-virtual {v7, v3}, Landroid/graphics/PointF;->equals(Ljava/lang/Object;)Z

    .line 922
    .line 923
    .line 924
    move-result v8

    .line 925
    if-eqz v8, :cond_1c

    .line 926
    .line 927
    iget v6, v3, Landroid/graphics/PointF;->x:F

    .line 928
    .line 929
    iget v7, v3, Landroid/graphics/PointF;->y:F

    .line 930
    .line 931
    invoke-virtual {v5, v6, v7}, Landroid/graphics/Path;->lineTo(FF)V

    .line 932
    .line 933
    .line 934
    goto :goto_16

    .line 935
    :cond_1c
    iget v8, v6, Landroid/graphics/PointF;->x:F

    .line 936
    .line 937
    iget v6, v6, Landroid/graphics/PointF;->y:F

    .line 938
    .line 939
    move v9, v6

    .line 940
    move v6, v8

    .line 941
    iget v8, v7, Landroid/graphics/PointF;->x:F

    .line 942
    .line 943
    iget v7, v7, Landroid/graphics/PointF;->y:F

    .line 944
    .line 945
    iget v10, v3, Landroid/graphics/PointF;->x:F

    .line 946
    .line 947
    iget v11, v3, Landroid/graphics/PointF;->y:F

    .line 948
    .line 949
    move/from16 v20, v9

    .line 950
    .line 951
    move v9, v7

    .line 952
    move/from16 v7, v20

    .line 953
    .line 954
    invoke-virtual/range {v5 .. v11}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    .line 955
    .line 956
    .line 957
    :goto_16
    iget v6, v3, Landroid/graphics/PointF;->x:F

    .line 958
    .line 959
    iget v3, v3, Landroid/graphics/PointF;->y:F

    .line 960
    .line 961
    invoke-virtual {v2, v6, v3}, Landroid/graphics/PointF;->set(FF)V

    .line 962
    .line 963
    .line 964
    add-int/lit8 v0, v0, 0x1

    .line 965
    .line 966
    goto :goto_15

    .line 967
    :cond_1d
    iget-boolean v0, v4, Lcn/k;->c:Z

    .line 968
    .line 969
    if-eqz v0, :cond_1e

    .line 970
    .line 971
    invoke-virtual {v5}, Landroid/graphics/Path;->close()V

    .line 972
    .line 973
    .line 974
    :cond_1e
    return-object v5
.end method

.method public final h()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/l;->j:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-nez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method
