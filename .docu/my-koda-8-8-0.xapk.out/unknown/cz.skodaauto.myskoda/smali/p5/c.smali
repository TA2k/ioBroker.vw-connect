.class public abstract Lp5/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/lang/ThreadLocal;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lp5/c;->a:Ljava/lang/ThreadLocal;

    .line 7
    .line 8
    return-void
.end method

.method public static a(Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;
    .locals 4

    .line 1
    invoke-static {p1}, Landroid/util/Xml;->asAttributeSet(Lorg/xmlpull/v1/XmlPullParser;)Landroid/util/AttributeSet;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    :goto_0
    invoke-interface {p1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x2

    .line 10
    if-eq v1, v2, :cond_0

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eq v1, v3, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    if-ne v1, v2, :cond_1

    .line 17
    .line 18
    invoke-static {p0, p1, v0, p2}, Lp5/c;->b(Landroid/content/res/Resources;Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :cond_1
    new-instance p0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 24
    .line 25
    const-string p1, "No start tag found"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public static b(Landroid/content/res/Resources;Lorg/xmlpull/v1/XmlPullParser;Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p3

    .line 6
    .line 7
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    const-string v4, "selector"

    .line 12
    .line 13
    invoke-virtual {v3, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    if-eqz v4, :cond_23

    .line 18
    .line 19
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v4, 0x1

    .line 24
    add-int/2addr v3, v4

    .line 25
    const/16 v5, 0x14

    .line 26
    .line 27
    new-array v6, v5, [[I

    .line 28
    .line 29
    new-array v5, v5, [I

    .line 30
    .line 31
    const/4 v7, 0x0

    .line 32
    move v8, v7

    .line 33
    :goto_0
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->next()I

    .line 34
    .line 35
    .line 36
    move-result v9

    .line 37
    if-eq v9, v4, :cond_22

    .line 38
    .line 39
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getDepth()I

    .line 40
    .line 41
    .line 42
    move-result v10

    .line 43
    const/4 v11, 0x3

    .line 44
    if-ge v10, v3, :cond_0

    .line 45
    .line 46
    if-eq v9, v11, :cond_22

    .line 47
    .line 48
    :cond_0
    const/4 v12, 0x2

    .line 49
    if-ne v9, v12, :cond_1

    .line 50
    .line 51
    if-gt v10, v3, :cond_1

    .line 52
    .line 53
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getName()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object v9

    .line 57
    const-string v10, "item"

    .line 58
    .line 59
    invoke-virtual {v9, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v9

    .line 63
    if-nez v9, :cond_2

    .line 64
    .line 65
    :cond_1
    move/from16 v34, v3

    .line 66
    .line 67
    move/from16 v16, v4

    .line 68
    .line 69
    goto/16 :goto_19

    .line 70
    .line 71
    :cond_2
    sget-object v9, Lm5/a;->a:[I

    .line 72
    .line 73
    if-nez v2, :cond_3

    .line 74
    .line 75
    invoke-virtual {v0, v1, v9}, Landroid/content/res/Resources;->obtainAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    goto :goto_1

    .line 80
    :cond_3
    invoke-virtual {v2, v1, v9, v7, v7}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes(Landroid/util/AttributeSet;[III)Landroid/content/res/TypedArray;

    .line 81
    .line 82
    .line 83
    move-result-object v9

    .line 84
    :goto_1
    const/4 v10, -0x1

    .line 85
    invoke-virtual {v9, v7, v10}, Landroid/content/res/TypedArray;->getResourceId(II)I

    .line 86
    .line 87
    .line 88
    move-result v13

    .line 89
    const v14, -0xff01

    .line 90
    .line 91
    .line 92
    const/16 v15, 0x1f

    .line 93
    .line 94
    if-eq v13, v10, :cond_6

    .line 95
    .line 96
    sget-object v10, Lp5/c;->a:Ljava/lang/ThreadLocal;

    .line 97
    .line 98
    invoke-virtual {v10}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v16

    .line 102
    check-cast v16, Landroid/util/TypedValue;

    .line 103
    .line 104
    if-nez v16, :cond_4

    .line 105
    .line 106
    new-instance v12, Landroid/util/TypedValue;

    .line 107
    .line 108
    invoke-direct {v12}, Landroid/util/TypedValue;-><init>()V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v10, v12}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_4
    move-object/from16 v12, v16

    .line 116
    .line 117
    :goto_2
    invoke-virtual {v0, v13, v12, v4}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 118
    .line 119
    .line 120
    iget v10, v12, Landroid/util/TypedValue;->type:I

    .line 121
    .line 122
    const/16 v12, 0x1c

    .line 123
    .line 124
    if-lt v10, v12, :cond_5

    .line 125
    .line 126
    if-gt v10, v15, :cond_5

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_5
    :try_start_0
    invoke-virtual {v0, v13}, Landroid/content/res/Resources;->getXml(I)Landroid/content/res/XmlResourceParser;

    .line 130
    .line 131
    .line 132
    move-result-object v10

    .line 133
    invoke-static {v0, v10, v2}, Lp5/c;->a(Landroid/content/res/Resources;Landroid/content/res/XmlResourceParser;Landroid/content/res/Resources$Theme;)Landroid/content/res/ColorStateList;

    .line 134
    .line 135
    .line 136
    move-result-object v10

    .line 137
    invoke-virtual {v10}, Landroid/content/res/ColorStateList;->getDefaultColor()I

    .line 138
    .line 139
    .line 140
    move-result v10
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 141
    goto :goto_4

    .line 142
    :catch_0
    invoke-virtual {v9, v7, v14}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 143
    .line 144
    .line 145
    move-result v10

    .line 146
    goto :goto_4

    .line 147
    :cond_6
    :goto_3
    invoke-virtual {v9, v7, v14}, Landroid/content/res/TypedArray;->getColor(II)I

    .line 148
    .line 149
    .line 150
    move-result v10

    .line 151
    :goto_4
    invoke-virtual {v9, v4}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 152
    .line 153
    .line 154
    move-result v12

    .line 155
    const/high16 v13, 0x3f800000    # 1.0f

    .line 156
    .line 157
    if-eqz v12, :cond_7

    .line 158
    .line 159
    invoke-virtual {v9, v4, v13}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 160
    .line 161
    .line 162
    move-result v11

    .line 163
    goto :goto_5

    .line 164
    :cond_7
    invoke-virtual {v9, v11}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 165
    .line 166
    .line 167
    move-result v12

    .line 168
    if-eqz v12, :cond_8

    .line 169
    .line 170
    invoke-virtual {v9, v11, v13}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 171
    .line 172
    .line 173
    move-result v11

    .line 174
    goto :goto_5

    .line 175
    :cond_8
    move v11, v13

    .line 176
    :goto_5
    sget v12, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 177
    .line 178
    const/4 v14, 0x4

    .line 179
    move/from16 v16, v4

    .line 180
    .line 181
    const/high16 v4, -0x40800000    # -1.0f

    .line 182
    .line 183
    if-lt v12, v15, :cond_9

    .line 184
    .line 185
    const/4 v12, 0x2

    .line 186
    invoke-virtual {v9, v12}, Landroid/content/res/TypedArray;->hasValue(I)Z

    .line 187
    .line 188
    .line 189
    move-result v15

    .line 190
    if-eqz v15, :cond_9

    .line 191
    .line 192
    invoke-virtual {v9, v12, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 193
    .line 194
    .line 195
    move-result v4

    .line 196
    goto :goto_6

    .line 197
    :cond_9
    invoke-virtual {v9, v14, v4}, Landroid/content/res/TypedArray;->getFloat(IF)F

    .line 198
    .line 199
    .line 200
    move-result v4

    .line 201
    :goto_6
    invoke-virtual {v9}, Landroid/content/res/TypedArray;->recycle()V

    .line 202
    .line 203
    .line 204
    invoke-interface {v1}, Landroid/util/AttributeSet;->getAttributeCount()I

    .line 205
    .line 206
    .line 207
    move-result v9

    .line 208
    new-array v12, v9, [I

    .line 209
    .line 210
    move v15, v7

    .line 211
    move/from16 v18, v13

    .line 212
    .line 213
    move v13, v15

    .line 214
    :goto_7
    if-ge v15, v9, :cond_c

    .line 215
    .line 216
    invoke-interface {v1, v15}, Landroid/util/AttributeSet;->getAttributeNameResource(I)I

    .line 217
    .line 218
    .line 219
    move-result v14

    .line 220
    const v7, 0x10101a5

    .line 221
    .line 222
    .line 223
    if-eq v14, v7, :cond_b

    .line 224
    .line 225
    const v7, 0x101031f

    .line 226
    .line 227
    .line 228
    if-eq v14, v7, :cond_b

    .line 229
    .line 230
    const v7, 0x7f040031

    .line 231
    .line 232
    .line 233
    if-eq v14, v7, :cond_b

    .line 234
    .line 235
    const v7, 0x7f0402d7

    .line 236
    .line 237
    .line 238
    if-eq v14, v7, :cond_b

    .line 239
    .line 240
    add-int/lit8 v7, v13, 0x1

    .line 241
    .line 242
    const/4 v0, 0x0

    .line 243
    invoke-interface {v1, v15, v0}, Landroid/util/AttributeSet;->getAttributeBooleanValue(IZ)Z

    .line 244
    .line 245
    .line 246
    move-result v20

    .line 247
    if-eqz v20, :cond_a

    .line 248
    .line 249
    goto :goto_8

    .line 250
    :cond_a
    neg-int v14, v14

    .line 251
    :goto_8
    aput v14, v12, v13

    .line 252
    .line 253
    move v13, v7

    .line 254
    :cond_b
    add-int/lit8 v15, v15, 0x1

    .line 255
    .line 256
    move-object/from16 v0, p0

    .line 257
    .line 258
    const/4 v7, 0x0

    .line 259
    const/4 v14, 0x4

    .line 260
    goto :goto_7

    .line 261
    :cond_c
    invoke-static {v12, v13}, Landroid/util/StateSet;->trimStateSet([II)[I

    .line 262
    .line 263
    .line 264
    move-result-object v0

    .line 265
    const/4 v7, 0x0

    .line 266
    cmpl-float v9, v4, v7

    .line 267
    .line 268
    const/high16 v12, 0x42c80000    # 100.0f

    .line 269
    .line 270
    if-ltz v9, :cond_d

    .line 271
    .line 272
    cmpg-float v9, v4, v12

    .line 273
    .line 274
    if-gtz v9, :cond_d

    .line 275
    .line 276
    move/from16 v9, v16

    .line 277
    .line 278
    goto :goto_9

    .line 279
    :cond_d
    const/4 v9, 0x0

    .line 280
    :goto_9
    cmpl-float v13, v11, v18

    .line 281
    .line 282
    if-nez v13, :cond_e

    .line 283
    .line 284
    if-nez v9, :cond_e

    .line 285
    .line 286
    move-object/from16 v31, v0

    .line 287
    .line 288
    move/from16 v34, v3

    .line 289
    .line 290
    goto/16 :goto_16

    .line 291
    .line 292
    :cond_e
    invoke-static {v10}, Landroid/graphics/Color;->alpha(I)I

    .line 293
    .line 294
    .line 295
    move-result v13

    .line 296
    int-to-float v13, v13

    .line 297
    mul-float/2addr v13, v11

    .line 298
    const/high16 v11, 0x3f000000    # 0.5f

    .line 299
    .line 300
    add-float/2addr v13, v11

    .line 301
    float-to-int v11, v13

    .line 302
    const/16 v13, 0xff

    .line 303
    .line 304
    const/4 v14, 0x0

    .line 305
    invoke-static {v11, v14, v13}, Llp/he;->e(III)I

    .line 306
    .line 307
    .line 308
    move-result v11

    .line 309
    if-eqz v9, :cond_1d

    .line 310
    .line 311
    invoke-static {v10}, Lp5/a;->a(I)Lp5/a;

    .line 312
    .line 313
    .line 314
    move-result-object v9

    .line 315
    iget v10, v9, Lp5/a;->a:F

    .line 316
    .line 317
    iget v9, v9, Lp5/a;->b:F

    .line 318
    .line 319
    sget-object v13, Lp5/k;->k:Lp5/k;

    .line 320
    .line 321
    float-to-double v14, v9

    .line 322
    const-wide/high16 v20, 0x3ff0000000000000L    # 1.0

    .line 323
    .line 324
    cmpg-double v14, v14, v20

    .line 325
    .line 326
    if-ltz v14, :cond_f

    .line 327
    .line 328
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 329
    .line 330
    .line 331
    move-result v14

    .line 332
    int-to-double v14, v14

    .line 333
    const-wide/16 v20, 0x0

    .line 334
    .line 335
    cmpg-double v14, v14, v20

    .line 336
    .line 337
    if-lez v14, :cond_f

    .line 338
    .line 339
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 340
    .line 341
    .line 342
    move-result v14

    .line 343
    int-to-double v14, v14

    .line 344
    const-wide/high16 v20, 0x4059000000000000L    # 100.0

    .line 345
    .line 346
    cmpl-double v14, v14, v20

    .line 347
    .line 348
    if-ltz v14, :cond_10

    .line 349
    .line 350
    :cond_f
    move-object/from16 v31, v0

    .line 351
    .line 352
    move/from16 v34, v3

    .line 353
    .line 354
    goto/16 :goto_14

    .line 355
    .line 356
    :cond_10
    cmpg-float v14, v10, v7

    .line 357
    .line 358
    if-gez v14, :cond_11

    .line 359
    .line 360
    move v10, v7

    .line 361
    goto :goto_a

    .line 362
    :cond_11
    const/high16 v14, 0x43b40000    # 360.0f

    .line 363
    .line 364
    invoke-static {v14, v10}, Ljava/lang/Math;->min(FF)F

    .line 365
    .line 366
    .line 367
    move-result v10

    .line 368
    :goto_a
    move/from16 v21, v7

    .line 369
    .line 370
    move/from16 v22, v21

    .line 371
    .line 372
    move v15, v9

    .line 373
    move/from16 v20, v16

    .line 374
    .line 375
    const/4 v7, 0x0

    .line 376
    :goto_b
    sub-float v23, v21, v9

    .line 377
    .line 378
    invoke-static/range {v23 .. v23}, Ljava/lang/Math;->abs(F)F

    .line 379
    .line 380
    .line 381
    move-result v23

    .line 382
    const v24, 0x3ecccccd    # 0.4f

    .line 383
    .line 384
    .line 385
    cmpl-float v23, v23, v24

    .line 386
    .line 387
    if-ltz v23, :cond_1b

    .line 388
    .line 389
    const/high16 v23, 0x447a0000    # 1000.0f

    .line 390
    .line 391
    move/from16 v26, v12

    .line 392
    .line 393
    move/from16 v25, v22

    .line 394
    .line 395
    move/from16 v24, v23

    .line 396
    .line 397
    const/16 v27, 0x0

    .line 398
    .line 399
    :goto_c
    sub-float v28, v25, v26

    .line 400
    .line 401
    invoke-static/range {v28 .. v28}, Ljava/lang/Math;->abs(F)F

    .line 402
    .line 403
    .line 404
    move-result v28

    .line 405
    const v29, 0x3c23d70a    # 0.01f

    .line 406
    .line 407
    .line 408
    cmpl-float v28, v28, v29

    .line 409
    .line 410
    const/high16 v29, 0x40000000    # 2.0f

    .line 411
    .line 412
    if-lez v28, :cond_17

    .line 413
    .line 414
    sub-float v28, v26, v25

    .line 415
    .line 416
    div-float v28, v28, v29

    .line 417
    .line 418
    move/from16 v30, v12

    .line 419
    .line 420
    add-float v12, v28, v25

    .line 421
    .line 422
    invoke-static {v12, v15, v10}, Lp5/a;->b(FFF)Lp5/a;

    .line 423
    .line 424
    .line 425
    move-result-object v14

    .line 426
    move-object/from16 v31, v0

    .line 427
    .line 428
    sget-object v0, Lp5/k;->k:Lp5/k;

    .line 429
    .line 430
    invoke-virtual {v14, v0}, Lp5/a;->c(Lp5/k;)I

    .line 431
    .line 432
    .line 433
    move-result v0

    .line 434
    invoke-static {v0}, Landroid/graphics/Color;->red(I)I

    .line 435
    .line 436
    .line 437
    move-result v14

    .line 438
    invoke-static {v14}, Lp5/b;->f(I)F

    .line 439
    .line 440
    .line 441
    move-result v14

    .line 442
    invoke-static {v0}, Landroid/graphics/Color;->green(I)I

    .line 443
    .line 444
    .line 445
    move-result v32

    .line 446
    invoke-static/range {v32 .. v32}, Lp5/b;->f(I)F

    .line 447
    .line 448
    .line 449
    move-result v32

    .line 450
    invoke-static {v0}, Landroid/graphics/Color;->blue(I)I

    .line 451
    .line 452
    .line 453
    move-result v33

    .line 454
    invoke-static/range {v33 .. v33}, Lp5/b;->f(I)F

    .line 455
    .line 456
    .line 457
    move-result v33

    .line 458
    sget-object v34, Lp5/b;->d:[[F

    .line 459
    .line 460
    aget-object v34, v34, v16

    .line 461
    .line 462
    const/16 v19, 0x0

    .line 463
    .line 464
    aget v35, v34, v19

    .line 465
    .line 466
    mul-float v14, v14, v35

    .line 467
    .line 468
    aget v35, v34, v16

    .line 469
    .line 470
    mul-float v32, v32, v35

    .line 471
    .line 472
    add-float v32, v32, v14

    .line 473
    .line 474
    const/16 v17, 0x2

    .line 475
    .line 476
    aget v14, v34, v17

    .line 477
    .line 478
    mul-float v33, v33, v14

    .line 479
    .line 480
    add-float v33, v33, v32

    .line 481
    .line 482
    div-float v14, v33, v30

    .line 483
    .line 484
    const v32, 0x3c111aa7

    .line 485
    .line 486
    .line 487
    cmpg-float v32, v14, v32

    .line 488
    .line 489
    if-gtz v32, :cond_12

    .line 490
    .line 491
    const v32, 0x4461d2f7

    .line 492
    .line 493
    .line 494
    mul-float v14, v14, v32

    .line 495
    .line 496
    move/from16 v32, v0

    .line 497
    .line 498
    goto :goto_d

    .line 499
    :cond_12
    move/from16 v32, v0

    .line 500
    .line 501
    float-to-double v0, v14

    .line 502
    invoke-static {v0, v1}, Ljava/lang/Math;->cbrt(D)D

    .line 503
    .line 504
    .line 505
    move-result-wide v0

    .line 506
    double-to-float v0, v0

    .line 507
    const/high16 v1, 0x42e80000    # 116.0f

    .line 508
    .line 509
    mul-float/2addr v0, v1

    .line 510
    const/high16 v1, 0x41800000    # 16.0f

    .line 511
    .line 512
    sub-float v14, v0, v1

    .line 513
    .line 514
    :goto_d
    sub-float v0, v4, v14

    .line 515
    .line 516
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 517
    .line 518
    .line 519
    move-result v0

    .line 520
    const v1, 0x3e4ccccd    # 0.2f

    .line 521
    .line 522
    .line 523
    cmpg-float v1, v0, v1

    .line 524
    .line 525
    if-gez v1, :cond_13

    .line 526
    .line 527
    invoke-static/range {v32 .. v32}, Lp5/a;->a(I)Lp5/a;

    .line 528
    .line 529
    .line 530
    move-result-object v1

    .line 531
    move/from16 v32, v0

    .line 532
    .line 533
    iget v0, v1, Lp5/a;->c:F

    .line 534
    .line 535
    iget v2, v1, Lp5/a;->b:F

    .line 536
    .line 537
    invoke-static {v0, v2, v10}, Lp5/a;->b(FFF)Lp5/a;

    .line 538
    .line 539
    .line 540
    move-result-object v0

    .line 541
    iget v2, v1, Lp5/a;->d:F

    .line 542
    .line 543
    move/from16 v33, v2

    .line 544
    .line 545
    iget v2, v0, Lp5/a;->d:F

    .line 546
    .line 547
    sub-float v2, v33, v2

    .line 548
    .line 549
    move/from16 v33, v2

    .line 550
    .line 551
    iget v2, v1, Lp5/a;->e:F

    .line 552
    .line 553
    move/from16 v34, v2

    .line 554
    .line 555
    iget v2, v0, Lp5/a;->e:F

    .line 556
    .line 557
    sub-float v2, v34, v2

    .line 558
    .line 559
    move/from16 v34, v2

    .line 560
    .line 561
    iget v2, v1, Lp5/a;->f:F

    .line 562
    .line 563
    iget v0, v0, Lp5/a;->f:F

    .line 564
    .line 565
    sub-float/2addr v2, v0

    .line 566
    mul-float v0, v33, v33

    .line 567
    .line 568
    mul-float v33, v34, v34

    .line 569
    .line 570
    add-float v33, v33, v0

    .line 571
    .line 572
    mul-float/2addr v2, v2

    .line 573
    add-float v2, v2, v33

    .line 574
    .line 575
    move-object/from16 v33, v1

    .line 576
    .line 577
    float-to-double v0, v2

    .line 578
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 579
    .line 580
    .line 581
    move-result-wide v0

    .line 582
    move/from16 v34, v3

    .line 583
    .line 584
    const-wide v2, 0x3fe428f5c28f5c29L    # 0.63

    .line 585
    .line 586
    .line 587
    .line 588
    .line 589
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 590
    .line 591
    .line 592
    move-result-wide v0

    .line 593
    const-wide v2, 0x3ff68f5c28f5c28fL    # 1.41

    .line 594
    .line 595
    .line 596
    .line 597
    .line 598
    mul-double/2addr v0, v2

    .line 599
    double-to-float v0, v0

    .line 600
    cmpg-float v1, v0, v18

    .line 601
    .line 602
    if-gtz v1, :cond_14

    .line 603
    .line 604
    move/from16 v24, v0

    .line 605
    .line 606
    move/from16 v23, v32

    .line 607
    .line 608
    move-object/from16 v27, v33

    .line 609
    .line 610
    goto :goto_e

    .line 611
    :cond_13
    move/from16 v34, v3

    .line 612
    .line 613
    :cond_14
    :goto_e
    cmpl-float v0, v23, v22

    .line 614
    .line 615
    if-nez v0, :cond_15

    .line 616
    .line 617
    cmpl-float v0, v24, v22

    .line 618
    .line 619
    if-nez v0, :cond_15

    .line 620
    .line 621
    :goto_f
    move-object/from16 v0, v27

    .line 622
    .line 623
    goto :goto_11

    .line 624
    :cond_15
    cmpg-float v0, v14, v4

    .line 625
    .line 626
    if-gez v0, :cond_16

    .line 627
    .line 628
    move/from16 v25, v12

    .line 629
    .line 630
    goto :goto_10

    .line 631
    :cond_16
    move/from16 v26, v12

    .line 632
    .line 633
    :goto_10
    move-object/from16 v1, p2

    .line 634
    .line 635
    move-object/from16 v2, p3

    .line 636
    .line 637
    move/from16 v12, v30

    .line 638
    .line 639
    move-object/from16 v0, v31

    .line 640
    .line 641
    move/from16 v3, v34

    .line 642
    .line 643
    goto/16 :goto_c

    .line 644
    .line 645
    :cond_17
    move-object/from16 v31, v0

    .line 646
    .line 647
    move/from16 v34, v3

    .line 648
    .line 649
    move/from16 v30, v12

    .line 650
    .line 651
    const/16 v17, 0x2

    .line 652
    .line 653
    goto :goto_f

    .line 654
    :goto_11
    if-eqz v20, :cond_19

    .line 655
    .line 656
    if-eqz v0, :cond_18

    .line 657
    .line 658
    invoke-virtual {v0, v13}, Lp5/a;->c(Lp5/k;)I

    .line 659
    .line 660
    .line 661
    move-result v0

    .line 662
    :goto_12
    move v10, v0

    .line 663
    goto :goto_15

    .line 664
    :cond_18
    sub-float v0, v9, v21

    .line 665
    .line 666
    div-float v0, v0, v29

    .line 667
    .line 668
    add-float v15, v0, v21

    .line 669
    .line 670
    move-object/from16 v1, p2

    .line 671
    .line 672
    move-object/from16 v2, p3

    .line 673
    .line 674
    move/from16 v12, v30

    .line 675
    .line 676
    move-object/from16 v0, v31

    .line 677
    .line 678
    move/from16 v3, v34

    .line 679
    .line 680
    const/16 v20, 0x0

    .line 681
    .line 682
    goto/16 :goto_b

    .line 683
    .line 684
    :cond_19
    if-nez v0, :cond_1a

    .line 685
    .line 686
    move v9, v15

    .line 687
    goto :goto_13

    .line 688
    :cond_1a
    move-object v7, v0

    .line 689
    move/from16 v21, v15

    .line 690
    .line 691
    :goto_13
    sub-float v0, v9, v21

    .line 692
    .line 693
    div-float v0, v0, v29

    .line 694
    .line 695
    add-float v15, v0, v21

    .line 696
    .line 697
    move-object/from16 v1, p2

    .line 698
    .line 699
    move-object/from16 v2, p3

    .line 700
    .line 701
    move/from16 v12, v30

    .line 702
    .line 703
    move-object/from16 v0, v31

    .line 704
    .line 705
    move/from16 v3, v34

    .line 706
    .line 707
    goto/16 :goto_b

    .line 708
    .line 709
    :cond_1b
    move-object/from16 v31, v0

    .line 710
    .line 711
    move/from16 v34, v3

    .line 712
    .line 713
    if-nez v7, :cond_1c

    .line 714
    .line 715
    invoke-static {v4}, Lp5/b;->e(F)I

    .line 716
    .line 717
    .line 718
    move-result v0

    .line 719
    goto :goto_12

    .line 720
    :cond_1c
    invoke-virtual {v7, v13}, Lp5/a;->c(Lp5/k;)I

    .line 721
    .line 722
    .line 723
    move-result v0

    .line 724
    goto :goto_12

    .line 725
    :goto_14
    invoke-static {v4}, Lp5/b;->e(F)I

    .line 726
    .line 727
    .line 728
    move-result v0

    .line 729
    goto :goto_12

    .line 730
    :cond_1d
    move-object/from16 v31, v0

    .line 731
    .line 732
    move/from16 v34, v3

    .line 733
    .line 734
    :goto_15
    const v0, 0xffffff

    .line 735
    .line 736
    .line 737
    and-int/2addr v0, v10

    .line 738
    shl-int/lit8 v1, v11, 0x18

    .line 739
    .line 740
    or-int v10, v0, v1

    .line 741
    .line 742
    :goto_16
    add-int/lit8 v0, v8, 0x1

    .line 743
    .line 744
    array-length v1, v5

    .line 745
    const/16 v2, 0x8

    .line 746
    .line 747
    if-le v0, v1, :cond_1f

    .line 748
    .line 749
    const/4 v1, 0x4

    .line 750
    if-gt v8, v1, :cond_1e

    .line 751
    .line 752
    move v1, v2

    .line 753
    goto :goto_17

    .line 754
    :cond_1e
    mul-int/lit8 v1, v8, 0x2

    .line 755
    .line 756
    :goto_17
    new-array v1, v1, [I

    .line 757
    .line 758
    const/4 v14, 0x0

    .line 759
    invoke-static {v5, v14, v1, v14, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 760
    .line 761
    .line 762
    move-object v5, v1

    .line 763
    :cond_1f
    aput v10, v5, v8

    .line 764
    .line 765
    array-length v1, v6

    .line 766
    if-le v0, v1, :cond_21

    .line 767
    .line 768
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    invoke-virtual {v1}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 773
    .line 774
    .line 775
    move-result-object v1

    .line 776
    const/4 v3, 0x4

    .line 777
    if-gt v8, v3, :cond_20

    .line 778
    .line 779
    goto :goto_18

    .line 780
    :cond_20
    mul-int/lit8 v2, v8, 0x2

    .line 781
    .line 782
    :goto_18
    invoke-static {v1, v2}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    .line 783
    .line 784
    .line 785
    move-result-object v1

    .line 786
    check-cast v1, [Ljava/lang/Object;

    .line 787
    .line 788
    const/4 v14, 0x0

    .line 789
    invoke-static {v6, v14, v1, v14, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 790
    .line 791
    .line 792
    move-object v6, v1

    .line 793
    :cond_21
    aput-object v31, v6, v8

    .line 794
    .line 795
    check-cast v6, [[I

    .line 796
    .line 797
    move-object/from16 v1, p2

    .line 798
    .line 799
    move-object/from16 v2, p3

    .line 800
    .line 801
    move v8, v0

    .line 802
    move/from16 v4, v16

    .line 803
    .line 804
    move/from16 v3, v34

    .line 805
    .line 806
    const/4 v7, 0x0

    .line 807
    move-object/from16 v0, p0

    .line 808
    .line 809
    goto/16 :goto_0

    .line 810
    .line 811
    :goto_19
    move-object/from16 v0, p0

    .line 812
    .line 813
    move-object/from16 v1, p2

    .line 814
    .line 815
    move-object/from16 v2, p3

    .line 816
    .line 817
    move/from16 v4, v16

    .line 818
    .line 819
    move/from16 v3, v34

    .line 820
    .line 821
    const/4 v7, 0x0

    .line 822
    goto/16 :goto_0

    .line 823
    .line 824
    :cond_22
    new-array v0, v8, [I

    .line 825
    .line 826
    new-array v1, v8, [[I

    .line 827
    .line 828
    const/4 v14, 0x0

    .line 829
    invoke-static {v5, v14, v0, v14, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 830
    .line 831
    .line 832
    invoke-static {v6, v14, v1, v14, v8}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 833
    .line 834
    .line 835
    new-instance v2, Landroid/content/res/ColorStateList;

    .line 836
    .line 837
    invoke-direct {v2, v1, v0}, Landroid/content/res/ColorStateList;-><init>([[I[I)V

    .line 838
    .line 839
    .line 840
    return-object v2

    .line 841
    :cond_23
    new-instance v0, Lorg/xmlpull/v1/XmlPullParserException;

    .line 842
    .line 843
    new-instance v1, Ljava/lang/StringBuilder;

    .line 844
    .line 845
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 846
    .line 847
    .line 848
    invoke-interface/range {p1 .. p1}, Lorg/xmlpull/v1/XmlPullParser;->getPositionDescription()Ljava/lang/String;

    .line 849
    .line 850
    .line 851
    move-result-object v2

    .line 852
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 853
    .line 854
    .line 855
    const-string v2, ": invalid color state list tag "

    .line 856
    .line 857
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 858
    .line 859
    .line 860
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 861
    .line 862
    .line 863
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 864
    .line 865
    .line 866
    move-result-object v1

    .line 867
    invoke-direct {v0, v1}, Lorg/xmlpull/v1/XmlPullParserException;-><init>(Ljava/lang/String;)V

    .line 868
    .line 869
    .line 870
    throw v0
.end method
