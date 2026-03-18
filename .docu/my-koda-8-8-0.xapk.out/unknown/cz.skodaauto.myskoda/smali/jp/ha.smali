.class public abstract Ljp/ha;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Landroid/content/res/Resources$Theme;Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;I)Lb4/a;
    .locals 55

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    invoke-static {v2}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    new-instance v4, Lk3/a;

    .line 12
    .line 13
    invoke-direct {v4, v2}, Lk3/a;-><init>(Landroid/content/res/XmlResourceParser;)V

    .line 14
    .line 15
    .line 16
    sget-object v5, Lk3/b;->a:[I

    .line 17
    .line 18
    invoke-static {v1, v0, v3, v5}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 19
    .line 20
    .line 21
    move-result-object v5

    .line 22
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 23
    .line 24
    .line 25
    move-result v6

    .line 26
    invoke-virtual {v4, v6}, Lk3/a;->b(I)V

    .line 27
    .line 28
    .line 29
    const-string v6, "autoMirrored"

    .line 30
    .line 31
    invoke-static {v2, v6}, Lp5/b;->d(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 32
    .line 33
    .line 34
    move-result v6

    .line 35
    const/4 v7, 0x0

    .line 36
    const/4 v8, 0x5

    .line 37
    if-nez v6, :cond_0

    .line 38
    .line 39
    move/from16 v18, v7

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {v5, v8, v7}, Landroid/content/res/TypedArray;->getBoolean(IZ)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    move/from16 v18, v6

    .line 47
    .line 48
    :goto_0
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    invoke-virtual {v4, v6}, Lk3/a;->b(I)V

    .line 53
    .line 54
    .line 55
    const-string v6, "viewportWidth"

    .line 56
    .line 57
    const/4 v9, 0x7

    .line 58
    const/4 v10, 0x0

    .line 59
    invoke-virtual {v4, v5, v6, v9, v10}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 60
    .line 61
    .line 62
    move-result v13

    .line 63
    const-string v6, "viewportHeight"

    .line 64
    .line 65
    const/16 v11, 0x8

    .line 66
    .line 67
    invoke-virtual {v4, v5, v6, v11, v10}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 68
    .line 69
    .line 70
    move-result v14

    .line 71
    cmpg-float v6, v13, v10

    .line 72
    .line 73
    if-lez v6, :cond_2e

    .line 74
    .line 75
    cmpg-float v6, v14, v10

    .line 76
    .line 77
    if-lez v6, :cond_2d

    .line 78
    .line 79
    const/4 v6, 0x3

    .line 80
    invoke-virtual {v5, v6, v10}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 81
    .line 82
    .line 83
    move-result v12

    .line 84
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 85
    .line 86
    .line 87
    move-result v15

    .line 88
    invoke-virtual {v4, v15}, Lk3/a;->b(I)V

    .line 89
    .line 90
    .line 91
    const/4 v15, 0x2

    .line 92
    invoke-virtual {v5, v15, v10}, Landroid/content/res/TypedArray;->getDimension(IF)F

    .line 93
    .line 94
    .line 95
    move-result v16

    .line 96
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 97
    .line 98
    .line 99
    move-result v9

    .line 100
    invoke-virtual {v4, v9}, Lk3/a;->b(I)V

    .line 101
    .line 102
    .line 103
    const/4 v9, 0x1

    .line 104
    invoke-virtual {v5, v9}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 105
    .line 106
    .line 107
    move-result v19

    .line 108
    if-eqz v19, :cond_3

    .line 109
    .line 110
    new-instance v10, Landroid/util/TypedValue;

    .line 111
    .line 112
    invoke-direct {v10}, Landroid/util/TypedValue;-><init>()V

    .line 113
    .line 114
    .line 115
    invoke-virtual {v5, v9, v10}, Landroid/content/res/TypedArray;->getValue(ILandroid/util/TypedValue;)Z

    .line 116
    .line 117
    .line 118
    iget v10, v10, Landroid/util/TypedValue;->type:I

    .line 119
    .line 120
    if-ne v10, v15, :cond_1

    .line 121
    .line 122
    sget-wide v20, Le3/s;->i:J

    .line 123
    .line 124
    move-wide/from16 v9, v20

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_1
    invoke-static {v5, v2, v0}, Lp5/b;->b(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    .line 128
    .line 129
    .line 130
    move-result-object v10

    .line 131
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 132
    .line 133
    .line 134
    move-result v9

    .line 135
    invoke-virtual {v4, v9}, Lk3/a;->b(I)V

    .line 136
    .line 137
    .line 138
    if-eqz v10, :cond_2

    .line 139
    .line 140
    invoke-virtual {v10}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    .line 141
    .line 142
    .line 143
    move-result v9

    .line 144
    invoke-static {v9}, Le3/j0;->c(I)J

    .line 145
    .line 146
    .line 147
    move-result-wide v9

    .line 148
    goto :goto_1

    .line 149
    :cond_2
    sget-wide v9, Le3/s;->i:J

    .line 150
    .line 151
    goto :goto_1

    .line 152
    :cond_3
    sget-wide v9, Le3/s;->i:J

    .line 153
    .line 154
    :goto_1
    const/4 v7, 0x6

    .line 155
    move-wide/from16 v22, v9

    .line 156
    .line 157
    const/4 v10, -0x1

    .line 158
    invoke-virtual {v5, v7, v10}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 159
    .line 160
    .line 161
    move-result v9

    .line 162
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 163
    .line 164
    .line 165
    move-result v11

    .line 166
    invoke-virtual {v4, v11}, Lk3/a;->b(I)V

    .line 167
    .line 168
    .line 169
    const/16 v11, 0xd

    .line 170
    .line 171
    const/16 v7, 0x9

    .line 172
    .line 173
    if-eq v9, v10, :cond_4

    .line 174
    .line 175
    if-eq v9, v6, :cond_6

    .line 176
    .line 177
    if-eq v9, v8, :cond_4

    .line 178
    .line 179
    if-eq v9, v7, :cond_5

    .line 180
    .line 181
    packed-switch v9, :pswitch_data_0

    .line 182
    .line 183
    .line 184
    :cond_4
    move v9, v8

    .line 185
    goto :goto_2

    .line 186
    :pswitch_0
    const/16 v9, 0xc

    .line 187
    .line 188
    goto :goto_2

    .line 189
    :pswitch_1
    const/16 v9, 0xe

    .line 190
    .line 191
    goto :goto_2

    .line 192
    :pswitch_2
    move v9, v11

    .line 193
    goto :goto_2

    .line 194
    :cond_5
    move v9, v7

    .line 195
    goto :goto_2

    .line 196
    :cond_6
    move v9, v6

    .line 197
    :goto_2
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 198
    .line 199
    .line 200
    move-result-object v10

    .line 201
    iget v10, v10, Landroid/util/DisplayMetrics;->density:F

    .line 202
    .line 203
    div-float/2addr v12, v10

    .line 204
    invoke-virtual {v1}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    .line 205
    .line 206
    .line 207
    move-result-object v10

    .line 208
    iget v10, v10, Landroid/util/DisplayMetrics;->density:F

    .line 209
    .line 210
    div-float v16, v16, v10

    .line 211
    .line 212
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->recycle()V

    .line 213
    .line 214
    .line 215
    move/from16 v17, v9

    .line 216
    .line 217
    const/4 v5, 0x7

    .line 218
    new-instance v9, Lj3/e;

    .line 219
    .line 220
    const/4 v10, 0x0

    .line 221
    const/16 v27, 0x0

    .line 222
    .line 223
    const/16 v19, 0x1

    .line 224
    .line 225
    move v11, v12

    .line 226
    move v7, v15

    .line 227
    move/from16 v12, v16

    .line 228
    .line 229
    move-wide/from16 v15, v22

    .line 230
    .line 231
    const/4 v5, 0x1

    .line 232
    invoke-direct/range {v9 .. v19}, Lj3/e;-><init>(Ljava/lang/String;FFFFJIZI)V

    .line 233
    .line 234
    .line 235
    const/4 v10, 0x0

    .line 236
    :goto_3
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 237
    .line 238
    .line 239
    move-result v11

    .line 240
    if-eq v11, v5, :cond_2c

    .line 241
    .line 242
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 243
    .line 244
    .line 245
    move-result v11

    .line 246
    if-ge v11, v5, :cond_7

    .line 247
    .line 248
    invoke-interface {v2}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 249
    .line 250
    .line 251
    move-result v11

    .line 252
    if-ne v11, v6, :cond_7

    .line 253
    .line 254
    goto/16 :goto_21

    .line 255
    .line 256
    :cond_7
    iget-object v11, v4, Lk3/a;->a:Lorg/xmlpull/v1/XmlPullParser;

    .line 257
    .line 258
    invoke-interface {v11}, Lorg/xmlpull/v1/XmlPullParser;->getEventType()I

    .line 259
    .line 260
    .line 261
    move-result v12

    .line 262
    const-string v13, "ImageVector.Builder is single use, create a new instance to create a new ImageVector"

    .line 263
    .line 264
    iget-object v14, v9, Lj3/e;->i:Ljava/util/ArrayList;

    .line 265
    .line 266
    const-string v15, "group"

    .line 267
    .line 268
    if-eq v12, v7, :cond_c

    .line 269
    .line 270
    if-eq v12, v6, :cond_9

    .line 271
    .line 272
    :cond_8
    move/from16 v17, v7

    .line 273
    .line 274
    goto :goto_5

    .line 275
    :cond_9
    invoke-interface {v11}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v11

    .line 279
    invoke-virtual {v15, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    move-result v11

    .line 283
    if-eqz v11, :cond_8

    .line 284
    .line 285
    add-int/lit8 v10, v10, 0x1

    .line 286
    .line 287
    const/4 v11, 0x0

    .line 288
    :goto_4
    if-ge v11, v10, :cond_b

    .line 289
    .line 290
    iget-boolean v12, v9, Lj3/e;->k:Z

    .line 291
    .line 292
    if-eqz v12, :cond_a

    .line 293
    .line 294
    invoke-static {v13}, Ls3/a;->b(Ljava/lang/String;)V

    .line 295
    .line 296
    .line 297
    :cond_a
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 298
    .line 299
    .line 300
    move-result v12

    .line 301
    sub-int/2addr v12, v5

    .line 302
    invoke-virtual {v14, v12}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v12

    .line 306
    check-cast v12, Lj3/d;

    .line 307
    .line 308
    invoke-static {v14, v5}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object v15

    .line 312
    check-cast v15, Lj3/d;

    .line 313
    .line 314
    iget-object v15, v15, Lj3/d;->j:Ljava/util/ArrayList;

    .line 315
    .line 316
    new-instance v30, Lj3/g0;

    .line 317
    .line 318
    iget-object v6, v12, Lj3/d;->a:Ljava/lang/String;

    .line 319
    .line 320
    iget v7, v12, Lj3/d;->b:F

    .line 321
    .line 322
    iget v5, v12, Lj3/d;->c:F

    .line 323
    .line 324
    iget v8, v12, Lj3/d;->d:F

    .line 325
    .line 326
    iget v2, v12, Lj3/d;->e:F

    .line 327
    .line 328
    move/from16 v35, v2

    .line 329
    .line 330
    iget v2, v12, Lj3/d;->f:F

    .line 331
    .line 332
    move/from16 v36, v2

    .line 333
    .line 334
    iget v2, v12, Lj3/d;->g:F

    .line 335
    .line 336
    move/from16 v37, v2

    .line 337
    .line 338
    iget v2, v12, Lj3/d;->h:F

    .line 339
    .line 340
    move/from16 v38, v2

    .line 341
    .line 342
    iget-object v2, v12, Lj3/d;->i:Ljava/util/List;

    .line 343
    .line 344
    iget-object v12, v12, Lj3/d;->j:Ljava/util/ArrayList;

    .line 345
    .line 346
    move-object/from16 v39, v2

    .line 347
    .line 348
    move/from16 v33, v5

    .line 349
    .line 350
    move-object/from16 v31, v6

    .line 351
    .line 352
    move/from16 v32, v7

    .line 353
    .line 354
    move/from16 v34, v8

    .line 355
    .line 356
    move-object/from16 v40, v12

    .line 357
    .line 358
    invoke-direct/range {v30 .. v40}, Lj3/g0;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;Ljava/util/ArrayList;)V

    .line 359
    .line 360
    .line 361
    move-object/from16 v2, v30

    .line 362
    .line 363
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 364
    .line 365
    .line 366
    add-int/lit8 v11, v11, 0x1

    .line 367
    .line 368
    move-object/from16 v2, p2

    .line 369
    .line 370
    const/4 v5, 0x1

    .line 371
    const/4 v6, 0x3

    .line 372
    const/4 v7, 0x2

    .line 373
    const/4 v8, 0x5

    .line 374
    goto :goto_4

    .line 375
    :cond_b
    move/from16 v17, v7

    .line 376
    .line 377
    const/4 v10, 0x0

    .line 378
    :goto_5
    const/4 v11, 0x0

    .line 379
    const/4 v15, 0x0

    .line 380
    :goto_6
    const/16 v24, 0x8

    .line 381
    .line 382
    const/16 v25, 0x6

    .line 383
    .line 384
    :goto_7
    const/16 v26, 0xc

    .line 385
    .line 386
    goto/16 :goto_20

    .line 387
    .line 388
    :cond_c
    invoke-interface {v11}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v2

    .line 392
    if-eqz v2, :cond_d

    .line 393
    .line 394
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 395
    .line 396
    .line 397
    move-result v5

    .line 398
    const v6, -0x624e8b7e

    .line 399
    .line 400
    .line 401
    sget-object v39, Lmx0/s;->d:Lmx0/s;

    .line 402
    .line 403
    const-string v7, ""

    .line 404
    .line 405
    iget-object v8, v4, Lk3/a;->c:Lj1/a;

    .line 406
    .line 407
    if-eq v5, v6, :cond_27

    .line 408
    .line 409
    const v6, 0x346425

    .line 410
    .line 411
    .line 412
    const/high16 v12, 0x3f800000    # 1.0f

    .line 413
    .line 414
    if-eq v5, v6, :cond_12

    .line 415
    .line 416
    const v6, 0x5e0f67f

    .line 417
    .line 418
    .line 419
    if-eq v5, v6, :cond_e

    .line 420
    .line 421
    :cond_d
    :goto_8
    const/4 v5, 0x1

    .line 422
    const/4 v11, 0x0

    .line 423
    const/4 v15, 0x0

    .line 424
    goto/16 :goto_b

    .line 425
    .line 426
    :cond_e
    invoke-virtual {v2, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 427
    .line 428
    .line 429
    move-result v2

    .line 430
    if-nez v2, :cond_f

    .line 431
    .line 432
    goto :goto_8

    .line 433
    :cond_f
    sget-object v2, Lk3/b;->b:[I

    .line 434
    .line 435
    invoke-static {v1, v0, v3, v2}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 436
    .line 437
    .line 438
    move-result-object v2

    .line 439
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 440
    .line 441
    .line 442
    move-result v5

    .line 443
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 444
    .line 445
    .line 446
    const-string v5, "rotation"

    .line 447
    .line 448
    const/4 v6, 0x5

    .line 449
    const/4 v15, 0x0

    .line 450
    invoke-virtual {v4, v2, v5, v6, v15}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 451
    .line 452
    .line 453
    move-result v32

    .line 454
    const/4 v5, 0x1

    .line 455
    invoke-virtual {v2, v5, v15}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 456
    .line 457
    .line 458
    move-result v33

    .line 459
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 460
    .line 461
    .line 462
    move-result v5

    .line 463
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 464
    .line 465
    .line 466
    const/4 v5, 0x2

    .line 467
    invoke-virtual {v2, v5, v15}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 468
    .line 469
    .line 470
    move-result v34

    .line 471
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 472
    .line 473
    .line 474
    move-result v5

    .line 475
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 476
    .line 477
    .line 478
    const-string v5, "scaleX"

    .line 479
    .line 480
    const/4 v6, 0x3

    .line 481
    invoke-virtual {v4, v2, v5, v6, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 482
    .line 483
    .line 484
    move-result v35

    .line 485
    const-string v5, "scaleY"

    .line 486
    .line 487
    const/4 v6, 0x4

    .line 488
    invoke-virtual {v4, v2, v5, v6, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 489
    .line 490
    .line 491
    move-result v36

    .line 492
    const-string v5, "translateX"

    .line 493
    .line 494
    const/4 v6, 0x6

    .line 495
    invoke-virtual {v4, v2, v5, v6, v15}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 496
    .line 497
    .line 498
    move-result v37

    .line 499
    const-string v5, "translateY"

    .line 500
    .line 501
    const/4 v6, 0x7

    .line 502
    invoke-virtual {v4, v2, v5, v6, v15}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 503
    .line 504
    .line 505
    move-result v38

    .line 506
    const/4 v5, 0x0

    .line 507
    invoke-virtual {v2, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 508
    .line 509
    .line 510
    move-result-object v8

    .line 511
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 512
    .line 513
    .line 514
    move-result v5

    .line 515
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 516
    .line 517
    .line 518
    if-nez v8, :cond_10

    .line 519
    .line 520
    move-object/from16 v31, v7

    .line 521
    .line 522
    goto :goto_9

    .line 523
    :cond_10
    move-object/from16 v31, v8

    .line 524
    .line 525
    :goto_9
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 526
    .line 527
    .line 528
    sget v2, Lj3/h0;->a:I

    .line 529
    .line 530
    iget-boolean v2, v9, Lj3/e;->k:Z

    .line 531
    .line 532
    if-eqz v2, :cond_11

    .line 533
    .line 534
    invoke-static {v13}, Ls3/a;->b(Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    :cond_11
    new-instance v30, Lj3/d;

    .line 538
    .line 539
    const/16 v40, 0x200

    .line 540
    .line 541
    invoke-direct/range {v30 .. v40}, Lj3/d;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;I)V

    .line 542
    .line 543
    .line 544
    move-object/from16 v2, v30

    .line 545
    .line 546
    invoke-virtual {v14, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 547
    .line 548
    .line 549
    :goto_a
    const/4 v5, 0x1

    .line 550
    const/4 v11, 0x0

    .line 551
    :goto_b
    const/16 v17, 0x2

    .line 552
    .line 553
    goto/16 :goto_6

    .line 554
    .line 555
    :cond_12
    const/4 v6, 0x7

    .line 556
    const/4 v15, 0x0

    .line 557
    const-string v5, "path"

    .line 558
    .line 559
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 560
    .line 561
    .line 562
    move-result v2

    .line 563
    if-nez v2, :cond_13

    .line 564
    .line 565
    goto :goto_a

    .line 566
    :cond_13
    sget-object v2, Lk3/b;->c:[I

    .line 567
    .line 568
    invoke-static {v1, v0, v3, v2}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 569
    .line 570
    .line 571
    move-result-object v2

    .line 572
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 573
    .line 574
    .line 575
    move-result v5

    .line 576
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 577
    .line 578
    .line 579
    const-string v5, "pathData"

    .line 580
    .line 581
    const-string v6, "http://schemas.android.com/apk/res/android"

    .line 582
    .line 583
    invoke-interface {v11, v6, v5}, Lorg/xmlpull/v1/XmlPullParser;->getAttributeValue(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 584
    .line 585
    .line 586
    move-result-object v5

    .line 587
    if-eqz v5, :cond_26

    .line 588
    .line 589
    const/4 v5, 0x0

    .line 590
    invoke-virtual {v2, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 591
    .line 592
    .line 593
    move-result-object v6

    .line 594
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 595
    .line 596
    .line 597
    move-result v5

    .line 598
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 599
    .line 600
    .line 601
    if-nez v6, :cond_14

    .line 602
    .line 603
    move-object/from16 v41, v7

    .line 604
    .line 605
    :goto_c
    const/4 v5, 0x2

    .line 606
    goto :goto_d

    .line 607
    :cond_14
    move-object/from16 v41, v6

    .line 608
    .line 609
    goto :goto_c

    .line 610
    :goto_d
    invoke-virtual {v2, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 611
    .line 612
    .line 613
    move-result-object v6

    .line 614
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 615
    .line 616
    .line 617
    move-result v5

    .line 618
    invoke-virtual {v4, v5}, Lk3/a;->b(I)V

    .line 619
    .line 620
    .line 621
    if-nez v6, :cond_15

    .line 622
    .line 623
    sget v5, Lj3/h0;->a:I

    .line 624
    .line 625
    :goto_e
    move-object/from16 v42, v39

    .line 626
    .line 627
    goto :goto_f

    .line 628
    :cond_15
    invoke-static {v8, v6}, Lj1/a;->v(Lj1/a;Ljava/lang/String;)Ljava/util/ArrayList;

    .line 629
    .line 630
    .line 631
    move-result-object v39

    .line 632
    goto :goto_e

    .line 633
    :goto_f
    const-string v5, "fillColor"

    .line 634
    .line 635
    const/4 v6, 0x1

    .line 636
    invoke-static {v2, v11, v0, v5, v6}, Lp5/b;->c(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;Ljava/lang/String;I)Lbb/g0;

    .line 637
    .line 638
    .line 639
    move-result-object v5

    .line 640
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 641
    .line 642
    .line 643
    move-result v6

    .line 644
    invoke-virtual {v4, v6}, Lk3/a;->b(I)V

    .line 645
    .line 646
    .line 647
    const-string v6, "fillAlpha"

    .line 648
    .line 649
    const/16 v7, 0xc

    .line 650
    .line 651
    invoke-virtual {v4, v2, v6, v7, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 652
    .line 653
    .line 654
    move-result v45

    .line 655
    const-string v6, "strokeLineCap"

    .line 656
    .line 657
    invoke-static {v11, v6}, Lp5/b;->d(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 658
    .line 659
    .line 660
    move-result v6

    .line 661
    if-nez v6, :cond_16

    .line 662
    .line 663
    const/4 v6, -0x1

    .line 664
    const/16 v8, 0x8

    .line 665
    .line 666
    goto :goto_10

    .line 667
    :cond_16
    const/4 v6, -0x1

    .line 668
    const/16 v8, 0x8

    .line 669
    .line 670
    invoke-virtual {v2, v8, v6}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 671
    .line 672
    .line 673
    move-result v23

    .line 674
    move/from16 v6, v23

    .line 675
    .line 676
    :goto_10
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 677
    .line 678
    .line 679
    move-result v7

    .line 680
    invoke-virtual {v4, v7}, Lk3/a;->b(I)V

    .line 681
    .line 682
    .line 683
    if-eqz v6, :cond_19

    .line 684
    .line 685
    const/4 v7, 0x1

    .line 686
    if-eq v6, v7, :cond_18

    .line 687
    .line 688
    const/4 v7, 0x2

    .line 689
    if-eq v6, v7, :cond_17

    .line 690
    .line 691
    :goto_11
    const/16 v49, 0x0

    .line 692
    .line 693
    goto :goto_12

    .line 694
    :cond_17
    move/from16 v49, v7

    .line 695
    .line 696
    goto :goto_12

    .line 697
    :cond_18
    const/4 v7, 0x2

    .line 698
    const/16 v49, 0x1

    .line 699
    .line 700
    goto :goto_12

    .line 701
    :cond_19
    const/4 v7, 0x2

    .line 702
    goto :goto_11

    .line 703
    :goto_12
    const-string v6, "strokeLineJoin"

    .line 704
    .line 705
    invoke-static {v11, v6}, Lp5/b;->d(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 706
    .line 707
    .line 708
    move-result v6

    .line 709
    if-nez v6, :cond_1a

    .line 710
    .line 711
    const/4 v6, -0x1

    .line 712
    goto :goto_13

    .line 713
    :cond_1a
    const/16 v6, 0x9

    .line 714
    .line 715
    const/4 v7, -0x1

    .line 716
    invoke-virtual {v2, v6, v7}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 717
    .line 718
    .line 719
    move-result v20

    .line 720
    move/from16 v6, v20

    .line 721
    .line 722
    :goto_13
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 723
    .line 724
    .line 725
    move-result v7

    .line 726
    invoke-virtual {v4, v7}, Lk3/a;->b(I)V

    .line 727
    .line 728
    .line 729
    if-eqz v6, :cond_1c

    .line 730
    .line 731
    const/4 v7, 0x1

    .line 732
    if-eq v6, v7, :cond_1b

    .line 733
    .line 734
    const/16 v50, 0x2

    .line 735
    .line 736
    goto :goto_14

    .line 737
    :cond_1b
    const/16 v50, 0x1

    .line 738
    .line 739
    goto :goto_14

    .line 740
    :cond_1c
    const/16 v50, 0x0

    .line 741
    .line 742
    :goto_14
    const-string v6, "strokeMiterLimit"

    .line 743
    .line 744
    const/16 v7, 0xa

    .line 745
    .line 746
    invoke-virtual {v4, v2, v6, v7, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 747
    .line 748
    .line 749
    move-result v51

    .line 750
    const-string v6, "strokeColor"

    .line 751
    .line 752
    const/4 v7, 0x3

    .line 753
    invoke-static {v2, v11, v0, v6, v7}, Lp5/b;->c(Landroid/content/res/TypedArray;Lorg/xmlpull/v1/XmlPullParser;Landroid/content/res/Resources$Theme;Ljava/lang/String;I)Lbb/g0;

    .line 754
    .line 755
    .line 756
    move-result-object v6

    .line 757
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 758
    .line 759
    .line 760
    move-result v7

    .line 761
    invoke-virtual {v4, v7}, Lk3/a;->b(I)V

    .line 762
    .line 763
    .line 764
    const-string v7, "strokeAlpha"

    .line 765
    .line 766
    const/16 v8, 0xb

    .line 767
    .line 768
    invoke-virtual {v4, v2, v7, v8, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 769
    .line 770
    .line 771
    move-result v47

    .line 772
    const-string v7, "strokeWidth"

    .line 773
    .line 774
    const/4 v8, 0x4

    .line 775
    invoke-virtual {v4, v2, v7, v8, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 776
    .line 777
    .line 778
    move-result v48

    .line 779
    const-string v7, "trimPathEnd"

    .line 780
    .line 781
    const/4 v8, 0x6

    .line 782
    invoke-virtual {v4, v2, v7, v8, v12}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 783
    .line 784
    .line 785
    move-result v53

    .line 786
    const-string v7, "trimPathOffset"

    .line 787
    .line 788
    const/4 v12, 0x7

    .line 789
    invoke-virtual {v4, v2, v7, v12, v15}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 790
    .line 791
    .line 792
    move-result v54

    .line 793
    const-string v7, "trimPathStart"

    .line 794
    .line 795
    const/4 v12, 0x5

    .line 796
    invoke-virtual {v4, v2, v7, v12, v15}, Lk3/a;->a(Landroid/content/res/TypedArray;Ljava/lang/String;IF)F

    .line 797
    .line 798
    .line 799
    move-result v52

    .line 800
    const-string v7, "fillType"

    .line 801
    .line 802
    invoke-static {v11, v7}, Lp5/b;->d(Lorg/xmlpull/v1/XmlPullParser;Ljava/lang/String;)Z

    .line 803
    .line 804
    .line 805
    move-result v7

    .line 806
    if-nez v7, :cond_1d

    .line 807
    .line 808
    const/16 v7, 0xd

    .line 809
    .line 810
    const/16 v19, 0x0

    .line 811
    .line 812
    goto :goto_15

    .line 813
    :cond_1d
    const/16 v7, 0xd

    .line 814
    .line 815
    const/4 v11, 0x0

    .line 816
    invoke-virtual {v2, v7, v11}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 817
    .line 818
    .line 819
    move-result v19

    .line 820
    :goto_15
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 821
    .line 822
    .line 823
    move-result v11

    .line 824
    invoke-virtual {v4, v11}, Lk3/a;->b(I)V

    .line 825
    .line 826
    .line 827
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 828
    .line 829
    .line 830
    iget-object v2, v5, Lbb/g0;->f:Ljava/lang/Object;

    .line 831
    .line 832
    check-cast v2, Landroid/graphics/Shader;

    .line 833
    .line 834
    if-eqz v2, :cond_1e

    .line 835
    .line 836
    goto :goto_16

    .line 837
    :cond_1e
    iget v7, v5, Lbb/g0;->e:I

    .line 838
    .line 839
    if-eqz v7, :cond_20

    .line 840
    .line 841
    :goto_16
    if-eqz v2, :cond_1f

    .line 842
    .line 843
    new-instance v5, Le3/q;

    .line 844
    .line 845
    invoke-direct {v5, v2}, Le3/q;-><init>(Landroid/graphics/Shader;)V

    .line 846
    .line 847
    .line 848
    move-object/from16 v44, v5

    .line 849
    .line 850
    goto :goto_17

    .line 851
    :cond_1f
    new-instance v2, Le3/p0;

    .line 852
    .line 853
    iget v5, v5, Lbb/g0;->e:I

    .line 854
    .line 855
    invoke-static {v5}, Le3/j0;->c(I)J

    .line 856
    .line 857
    .line 858
    move-result-wide v11

    .line 859
    invoke-direct {v2, v11, v12}, Le3/p0;-><init>(J)V

    .line 860
    .line 861
    .line 862
    move-object/from16 v44, v2

    .line 863
    .line 864
    goto :goto_17

    .line 865
    :cond_20
    const/16 v44, 0x0

    .line 866
    .line 867
    :goto_17
    iget-object v2, v6, Lbb/g0;->f:Ljava/lang/Object;

    .line 868
    .line 869
    check-cast v2, Landroid/graphics/Shader;

    .line 870
    .line 871
    if-eqz v2, :cond_21

    .line 872
    .line 873
    goto :goto_18

    .line 874
    :cond_21
    iget v5, v6, Lbb/g0;->e:I

    .line 875
    .line 876
    if-eqz v5, :cond_23

    .line 877
    .line 878
    :goto_18
    if-eqz v2, :cond_22

    .line 879
    .line 880
    new-instance v11, Le3/q;

    .line 881
    .line 882
    invoke-direct {v11, v2}, Le3/q;-><init>(Landroid/graphics/Shader;)V

    .line 883
    .line 884
    .line 885
    :goto_19
    move-object/from16 v46, v11

    .line 886
    .line 887
    goto :goto_1a

    .line 888
    :cond_22
    new-instance v11, Le3/p0;

    .line 889
    .line 890
    iget v2, v6, Lbb/g0;->e:I

    .line 891
    .line 892
    invoke-static {v2}, Le3/j0;->c(I)J

    .line 893
    .line 894
    .line 895
    move-result-wide v5

    .line 896
    invoke-direct {v11, v5, v6}, Le3/p0;-><init>(J)V

    .line 897
    .line 898
    .line 899
    goto :goto_19

    .line 900
    :cond_23
    const/16 v46, 0x0

    .line 901
    .line 902
    :goto_1a
    if-nez v19, :cond_24

    .line 903
    .line 904
    const/16 v43, 0x0

    .line 905
    .line 906
    goto :goto_1b

    .line 907
    :cond_24
    const/16 v43, 0x1

    .line 908
    .line 909
    :goto_1b
    iget-boolean v2, v9, Lj3/e;->k:Z

    .line 910
    .line 911
    if-eqz v2, :cond_25

    .line 912
    .line 913
    invoke-static {v13}, Ls3/a;->b(Ljava/lang/String;)V

    .line 914
    .line 915
    .line 916
    :cond_25
    const/4 v5, 0x1

    .line 917
    invoke-static {v14, v5}, Lkx/a;->f(Ljava/util/ArrayList;I)Ljava/lang/Object;

    .line 918
    .line 919
    .line 920
    move-result-object v2

    .line 921
    check-cast v2, Lj3/d;

    .line 922
    .line 923
    iget-object v2, v2, Lj3/d;->j:Ljava/util/ArrayList;

    .line 924
    .line 925
    new-instance v40, Lj3/k0;

    .line 926
    .line 927
    invoke-direct/range {v40 .. v54}, Lj3/k0;-><init>(Ljava/lang/String;Ljava/util/List;ILe3/p;FLe3/p;FFIIFFFF)V

    .line 928
    .line 929
    .line 930
    move-object/from16 v5, v40

    .line 931
    .line 932
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 933
    .line 934
    .line 935
    move/from16 v25, v8

    .line 936
    .line 937
    const/4 v5, 0x1

    .line 938
    const/4 v11, 0x0

    .line 939
    const/16 v17, 0x2

    .line 940
    .line 941
    const/16 v24, 0x8

    .line 942
    .line 943
    goto/16 :goto_7

    .line 944
    .line 945
    :cond_26
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 946
    .line 947
    const-string v1, "No path data available"

    .line 948
    .line 949
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 950
    .line 951
    .line 952
    throw v0

    .line 953
    :cond_27
    move-object v5, v7

    .line 954
    const/4 v15, 0x0

    .line 955
    const/16 v17, 0x2

    .line 956
    .line 957
    const/16 v24, 0x8

    .line 958
    .line 959
    const/16 v25, 0x6

    .line 960
    .line 961
    const/16 v26, 0xc

    .line 962
    .line 963
    const-string v6, "clip-path"

    .line 964
    .line 965
    invoke-virtual {v2, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 966
    .line 967
    .line 968
    move-result v2

    .line 969
    if-nez v2, :cond_28

    .line 970
    .line 971
    const/4 v5, 0x1

    .line 972
    const/4 v11, 0x0

    .line 973
    goto :goto_20

    .line 974
    :cond_28
    sget-object v2, Lk3/b;->d:[I

    .line 975
    .line 976
    invoke-static {v1, v0, v3, v2}, Lp5/b;->g(Landroid/content/res/Resources;Landroid/content/res/Resources$Theme;Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 977
    .line 978
    .line 979
    move-result-object v2

    .line 980
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 981
    .line 982
    .line 983
    move-result v6

    .line 984
    invoke-virtual {v4, v6}, Lk3/a;->b(I)V

    .line 985
    .line 986
    .line 987
    const/4 v11, 0x0

    .line 988
    invoke-virtual {v2, v11}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 989
    .line 990
    .line 991
    move-result-object v6

    .line 992
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 993
    .line 994
    .line 995
    move-result v12

    .line 996
    invoke-virtual {v4, v12}, Lk3/a;->b(I)V

    .line 997
    .line 998
    .line 999
    if-nez v6, :cond_29

    .line 1000
    .line 1001
    move-object/from16 v29, v5

    .line 1002
    .line 1003
    :goto_1c
    const/4 v5, 0x1

    .line 1004
    goto :goto_1d

    .line 1005
    :cond_29
    move-object/from16 v29, v6

    .line 1006
    .line 1007
    goto :goto_1c

    .line 1008
    :goto_1d
    invoke-virtual {v2, v5}, Landroid/content/res/TypedArray;->getString(I)Ljava/lang/String;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v6

    .line 1012
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->getChangingConfigurations()I

    .line 1013
    .line 1014
    .line 1015
    move-result v12

    .line 1016
    invoke-virtual {v4, v12}, Lk3/a;->b(I)V

    .line 1017
    .line 1018
    .line 1019
    if-nez v6, :cond_2a

    .line 1020
    .line 1021
    sget v6, Lj3/h0;->a:I

    .line 1022
    .line 1023
    :goto_1e
    move-object/from16 v37, v39

    .line 1024
    .line 1025
    goto :goto_1f

    .line 1026
    :cond_2a
    invoke-static {v8, v6}, Lj1/a;->v(Lj1/a;Ljava/lang/String;)Ljava/util/ArrayList;

    .line 1027
    .line 1028
    .line 1029
    move-result-object v39

    .line 1030
    goto :goto_1e

    .line 1031
    :goto_1f
    invoke-virtual {v2}, Landroid/content/res/TypedArray;->recycle()V

    .line 1032
    .line 1033
    .line 1034
    iget-boolean v2, v9, Lj3/e;->k:Z

    .line 1035
    .line 1036
    if-eqz v2, :cond_2b

    .line 1037
    .line 1038
    invoke-static {v13}, Ls3/a;->b(Ljava/lang/String;)V

    .line 1039
    .line 1040
    .line 1041
    :cond_2b
    new-instance v28, Lj3/d;

    .line 1042
    .line 1043
    const/16 v38, 0x200

    .line 1044
    .line 1045
    const/16 v30, 0x0

    .line 1046
    .line 1047
    const/16 v31, 0x0

    .line 1048
    .line 1049
    const/16 v32, 0x0

    .line 1050
    .line 1051
    const/high16 v33, 0x3f800000    # 1.0f

    .line 1052
    .line 1053
    const/high16 v34, 0x3f800000    # 1.0f

    .line 1054
    .line 1055
    const/16 v35, 0x0

    .line 1056
    .line 1057
    const/16 v36, 0x0

    .line 1058
    .line 1059
    invoke-direct/range {v28 .. v38}, Lj3/d;-><init>(Ljava/lang/String;FFFFFFFLjava/util/List;I)V

    .line 1060
    .line 1061
    .line 1062
    move-object/from16 v2, v28

    .line 1063
    .line 1064
    invoke-virtual {v14, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1065
    .line 1066
    .line 1067
    add-int/lit8 v10, v10, 0x1

    .line 1068
    .line 1069
    :goto_20
    invoke-interface/range {p2 .. p2}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 1070
    .line 1071
    .line 1072
    move-object/from16 v2, p2

    .line 1073
    .line 1074
    move/from16 v7, v17

    .line 1075
    .line 1076
    const/4 v6, 0x3

    .line 1077
    const/4 v8, 0x5

    .line 1078
    goto/16 :goto_3

    .line 1079
    .line 1080
    :cond_2c
    :goto_21
    iget v0, v4, Lk3/a;->b:I

    .line 1081
    .line 1082
    or-int v0, p3, v0

    .line 1083
    .line 1084
    new-instance v1, Lb4/a;

    .line 1085
    .line 1086
    invoke-virtual {v9}, Lj3/e;->b()Lj3/f;

    .line 1087
    .line 1088
    .line 1089
    move-result-object v2

    .line 1090
    invoke-direct {v1, v2, v0}, Lb4/a;-><init>(Lj3/f;I)V

    .line 1091
    .line 1092
    .line 1093
    return-object v1

    .line 1094
    :cond_2d
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 1095
    .line 1096
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1097
    .line 1098
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 1099
    .line 1100
    .line 1101
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getPositionDescription()Ljava/lang/String;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v2

    .line 1105
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1106
    .line 1107
    .line 1108
    const-string v2, "<VectorGraphic> tag requires viewportHeight > 0"

    .line 1109
    .line 1110
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1111
    .line 1112
    .line 1113
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1114
    .line 1115
    .line 1116
    move-result-object v1

    .line 1117
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 1118
    .line 1119
    .line 1120
    throw v0

    .line 1121
    :cond_2e
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 1122
    .line 1123
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1124
    .line 1125
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 1126
    .line 1127
    .line 1128
    invoke-virtual {v5}, Landroid/content/res/TypedArray;->getPositionDescription()Ljava/lang/String;

    .line 1129
    .line 1130
    .line 1131
    move-result-object v2

    .line 1132
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1133
    .line 1134
    .line 1135
    const-string v2, "<VectorGraphic> tag requires viewportWidth > 0"

    .line 1136
    .line 1137
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1138
    .line 1139
    .line 1140
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v1

    .line 1144
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 1145
    .line 1146
    .line 1147
    throw v0

    .line 1148
    nop

    .line 1149
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public static final b(Lay0/n;)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-static {}, Ljava/lang/Thread;->interrupted()Z

    .line 2
    .line 3
    .line 4
    new-instance v0, Llb0/q0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, p0, v1}, Llb0/q0;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 11
    .line 12
    invoke-static {p0, v0}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static final c(IILl2/o;)Lj3/f;
    .locals 6

    .line 1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 2
    .line 3
    check-cast p2, Ll2/t;

    .line 4
    .line 5
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Landroid/content/Context;

    .line 10
    .line 11
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->c:Ll2/e0;

    .line 12
    .line 13
    invoke-virtual {p2, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    check-cast v1, Landroid/content/res/Resources;

    .line 18
    .line 19
    invoke-virtual {v0}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    and-int/lit8 v3, p1, 0x70

    .line 28
    .line 29
    xor-int/lit8 v3, v3, 0x30

    .line 30
    .line 31
    const/4 v4, 0x1

    .line 32
    const/16 v5, 0x20

    .line 33
    .line 34
    if-le v3, v5, :cond_0

    .line 35
    .line 36
    invoke-virtual {p2, p0}, Ll2/t;->e(I)Z

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-nez v3, :cond_1

    .line 41
    .line 42
    :cond_0
    and-int/lit8 p1, p1, 0x30

    .line 43
    .line 44
    if-ne p1, v5, :cond_2

    .line 45
    .line 46
    :cond_1
    move p1, v4

    .line 47
    goto :goto_0

    .line 48
    :cond_2
    const/4 p1, 0x0

    .line 49
    :goto_0
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    or-int/2addr p1, v3

    .line 54
    invoke-virtual {p2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    or-int/2addr p1, v3

    .line 59
    invoke-virtual {p2, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    or-int/2addr p1, v2

    .line 64
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    if-nez p1, :cond_3

    .line 69
    .line 70
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 71
    .line 72
    if-ne v2, p1, :cond_5

    .line 73
    .line 74
    :cond_3
    new-instance p1, Landroid/util/TypedValue;

    .line 75
    .line 76
    invoke-direct {p1}, Landroid/util/TypedValue;-><init>()V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v1, p0, p1, v4}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1, p0}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    :goto_1
    const/4 v3, 0x2

    .line 91
    if-eq v2, v3, :cond_4

    .line 92
    .line 93
    if-eq v2, v4, :cond_4

    .line 94
    .line 95
    invoke-interface {p0}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    goto :goto_1

    .line 100
    :cond_4
    if-ne v2, v3, :cond_6

    .line 101
    .line 102
    iget p1, p1, Landroid/util/TypedValue;->changingConfigurations:I

    .line 103
    .line 104
    invoke-static {v0, v1, p0, p1}, Ljp/ha;->a(Landroid/content/res/Resources$Theme;Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;I)Lb4/a;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    iget-object v2, p0, Lb4/a;->a:Lj3/f;

    .line 109
    .line 110
    invoke-virtual {p2, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 111
    .line 112
    .line 113
    :cond_5
    check-cast v2, Lj3/f;

    .line 114
    .line 115
    return-object v2

    .line 116
    :cond_6
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 117
    .line 118
    const-string p1, "No start tag found"

    .line 119
    .line 120
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method
