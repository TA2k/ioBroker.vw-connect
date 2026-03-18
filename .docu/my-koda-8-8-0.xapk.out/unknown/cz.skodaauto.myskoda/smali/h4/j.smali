.class public final Lh4/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/text/TextPaint;

.field public final b:Landroid/text/TextUtils$TruncateAt;

.field public final c:Z

.field public final d:Z

.field public e:Li4/c;

.field public final f:Landroid/text/Layout;

.field public final g:I

.field public final h:I

.field public final i:I

.field public final j:F

.field public final k:F

.field public final l:Z

.field public final m:Landroid/graphics/Paint$FontMetricsInt;

.field public final n:I

.field public final o:[Lj4/h;

.field public final p:Landroid/graphics/Rect;

.field public q:Landroidx/lifecycle/c1;


# direct methods
.method public constructor <init>(Ljava/lang/CharSequence;FLandroid/text/TextPaint;ILandroid/text/TextUtils$TruncateAt;IZIIIIIILh4/f;)V
    .locals 23

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
    move/from16 v3, p4

    .line 8
    .line 9
    move/from16 v6, p7

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    move-object/from16 v4, p3

    .line 15
    .line 16
    iput-object v4, v0, Lh4/j;->a:Landroid/text/TextPaint;

    .line 17
    .line 18
    move-object/from16 v7, p5

    .line 19
    .line 20
    iput-object v7, v0, Lh4/j;->b:Landroid/text/TextUtils$TruncateAt;

    .line 21
    .line 22
    iput-boolean v6, v0, Lh4/j;->c:Z

    .line 23
    .line 24
    new-instance v5, Landroid/graphics/Rect;

    .line 25
    .line 26
    invoke-direct {v5}, Landroid/graphics/Rect;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object v5, v0, Lh4/j;->p:Landroid/graphics/Rect;

    .line 30
    .line 31
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    invoke-static/range {p6 .. p6}, Lh4/k;->a(I)Landroid/text/TextDirectionHeuristic;

    .line 36
    .line 37
    .line 38
    move-result-object v12

    .line 39
    sget-object v8, Lh4/h;->a:Landroid/text/Layout$Alignment;

    .line 40
    .line 41
    const/4 v13, 0x1

    .line 42
    if-eqz v3, :cond_4

    .line 43
    .line 44
    if-eq v3, v13, :cond_3

    .line 45
    .line 46
    const/4 v8, 0x2

    .line 47
    if-eq v3, v8, :cond_2

    .line 48
    .line 49
    const/4 v8, 0x3

    .line 50
    if-eq v3, v8, :cond_1

    .line 51
    .line 52
    const/4 v8, 0x4

    .line 53
    if-eq v3, v8, :cond_0

    .line 54
    .line 55
    sget-object v3, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    sget-object v3, Lh4/h;->b:Landroid/text/Layout$Alignment;

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_1
    sget-object v3, Lh4/h;->a:Landroid/text/Layout$Alignment;

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    sget-object v3, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    sget-object v3, Landroid/text/Layout$Alignment;->ALIGN_OPPOSITE:Landroid/text/Layout$Alignment;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_4
    sget-object v3, Landroid/text/Layout$Alignment;->ALIGN_NORMAL:Landroid/text/Layout$Alignment;

    .line 71
    .line 72
    :goto_0
    instance-of v8, v1, Landroid/text/Spanned;

    .line 73
    .line 74
    if-eqz v8, :cond_5

    .line 75
    .line 76
    move-object v8, v1

    .line 77
    check-cast v8, Landroid/text/Spanned;

    .line 78
    .line 79
    const/4 v9, -0x1

    .line 80
    const-class v10, Lj4/a;

    .line 81
    .line 82
    invoke-interface {v8, v9, v5, v10}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 83
    .line 84
    .line 85
    move-result v8

    .line 86
    if-ge v8, v5, :cond_5

    .line 87
    .line 88
    move v5, v13

    .line 89
    goto :goto_1

    .line 90
    :cond_5
    const/4 v5, 0x0

    .line 91
    :goto_1
    const-string v8, "TextLayout:initLayout"

    .line 92
    .line 93
    invoke-static {v8}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    :try_start_0
    invoke-virtual/range {p14 .. p14}, Lh4/f;->a()Landroid/text/BoringLayout$Metrics;

    .line 97
    .line 98
    .line 99
    move-result-object v8

    .line 100
    float-to-double v9, v2

    .line 101
    invoke-static {v9, v10}, Ljava/lang/Math;->ceil(D)D

    .line 102
    .line 103
    .line 104
    move-result-wide v14

    .line 105
    double-to-float v11, v14

    .line 106
    float-to-int v11, v11

    .line 107
    const/16 v14, 0x21

    .line 108
    .line 109
    if-eqz v8, :cond_9

    .line 110
    .line 111
    invoke-virtual/range {p14 .. p14}, Lh4/f;->c()F

    .line 112
    .line 113
    .line 114
    move-result v15

    .line 115
    cmpg-float v2, v15, v2

    .line 116
    .line 117
    if-gtz v2, :cond_9

    .line 118
    .line 119
    if-nez v5, :cond_9

    .line 120
    .line 121
    iput-boolean v13, v0, Lh4/j;->l:Z

    .line 122
    .line 123
    if-ltz v11, :cond_6

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_6
    const-string v2, "negative width"

    .line 127
    .line 128
    invoke-static {v2}, Lm4/a;->a(Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    :goto_2
    if-ltz v11, :cond_7

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_7
    const-string v2, "negative ellipsized width"

    .line 135
    .line 136
    invoke-static {v2}, Lm4/a;->a(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    :goto_3
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 140
    .line 141
    if-lt v2, v14, :cond_8

    .line 142
    .line 143
    move-object v5, v8

    .line 144
    move v8, v11

    .line 145
    move-object v2, v4

    .line 146
    move-object v4, v3

    .line 147
    move v3, v11

    .line 148
    invoke-static/range {v1 .. v8}, Lb/s;->i(Ljava/lang/CharSequence;Landroid/text/TextPaint;ILandroid/text/Layout$Alignment;Landroid/text/BoringLayout$Metrics;ZLandroid/text/TextUtils$TruncateAt;I)Landroid/text/BoringLayout;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    goto :goto_4

    .line 153
    :cond_8
    move-object v4, v3

    .line 154
    move-object v5, v8

    .line 155
    move v3, v11

    .line 156
    new-instance v1, Landroid/text/BoringLayout;

    .line 157
    .line 158
    const/high16 v6, 0x3f800000    # 1.0f

    .line 159
    .line 160
    const/4 v7, 0x0

    .line 161
    move v11, v3

    .line 162
    move-object/from16 v2, p1

    .line 163
    .line 164
    move-object/from16 v10, p5

    .line 165
    .line 166
    move/from16 v9, p7

    .line 167
    .line 168
    move-object v8, v5

    .line 169
    move-object v5, v4

    .line 170
    move v4, v3

    .line 171
    move-object/from16 v3, p3

    .line 172
    .line 173
    invoke-direct/range {v1 .. v11}, Landroid/text/BoringLayout;-><init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;ILandroid/text/Layout$Alignment;FFLandroid/text/BoringLayout$Metrics;ZLandroid/text/TextUtils$TruncateAt;I)V

    .line 174
    .line 175
    .line 176
    move-object v2, v1

    .line 177
    :goto_4
    move/from16 v7, p8

    .line 178
    .line 179
    move-object v5, v12

    .line 180
    goto :goto_5

    .line 181
    :cond_9
    move-object v4, v3

    .line 182
    move v3, v11

    .line 183
    const/4 v1, 0x0

    .line 184
    iput-boolean v1, v0, Lh4/j;->l:Z

    .line 185
    .line 186
    move-object v5, v4

    .line 187
    invoke-interface/range {p1 .. p1}, Ljava/lang/CharSequence;->length()I

    .line 188
    .line 189
    .line 190
    move-result v4

    .line 191
    invoke-static {v9, v10}, Ljava/lang/Math;->ceil(D)D

    .line 192
    .line 193
    .line 194
    move-result-wide v6

    .line 195
    double-to-float v2, v6

    .line 196
    float-to-int v9, v2

    .line 197
    move-object/from16 v1, p1

    .line 198
    .line 199
    move-object/from16 v2, p3

    .line 200
    .line 201
    move-object/from16 v8, p5

    .line 202
    .line 203
    move/from16 v11, p7

    .line 204
    .line 205
    move/from16 v7, p8

    .line 206
    .line 207
    move/from16 v13, p10

    .line 208
    .line 209
    move/from16 v14, p11

    .line 210
    .line 211
    move/from16 v15, p12

    .line 212
    .line 213
    move/from16 v10, p13

    .line 214
    .line 215
    move-object v6, v5

    .line 216
    move-object v5, v12

    .line 217
    move/from16 v12, p9

    .line 218
    .line 219
    invoke-static/range {v1 .. v15}, Lh4/g;->a(Ljava/lang/CharSequence;Landroid/text/TextPaint;IILandroid/text/TextDirectionHeuristic;Landroid/text/Layout$Alignment;ILandroid/text/TextUtils$TruncateAt;IIZIIII)Landroid/text/StaticLayout;

    .line 220
    .line 221
    .line 222
    move-result-object v2

    .line 223
    :goto_5
    iput-object v2, v0, Lh4/j;->f:Landroid/text/Layout;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 224
    .line 225
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v2}, Landroid/text/Layout;->getLineCount()I

    .line 229
    .line 230
    .line 231
    move-result v1

    .line 232
    invoke-static {v1, v7}, Ljava/lang/Math;->min(II)I

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    iput v1, v0, Lh4/j;->g:I

    .line 237
    .line 238
    add-int/lit8 v3, v1, -0x1

    .line 239
    .line 240
    if-ge v1, v7, :cond_b

    .line 241
    .line 242
    :cond_a
    const/4 v13, 0x0

    .line 243
    goto :goto_6

    .line 244
    :cond_b
    invoke-virtual {v2, v3}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 245
    .line 246
    .line 247
    move-result v4

    .line 248
    if-gtz v4, :cond_c

    .line 249
    .line 250
    invoke-virtual {v2, v3}, Landroid/text/Layout;->getLineEnd(I)I

    .line 251
    .line 252
    .line 253
    move-result v4

    .line 254
    invoke-interface/range {p1 .. p1}, Ljava/lang/CharSequence;->length()I

    .line 255
    .line 256
    .line 257
    move-result v6

    .line 258
    if-eq v4, v6, :cond_a

    .line 259
    .line 260
    :cond_c
    const/4 v13, 0x1

    .line 261
    :goto_6
    iput-boolean v13, v0, Lh4/j;->d:Z

    .line 262
    .line 263
    sget-wide v6, Lh4/k;->b:J

    .line 264
    .line 265
    const-wide v8, 0xffffffffL

    .line 266
    .line 267
    .line 268
    .line 269
    .line 270
    if-nez p7, :cond_15

    .line 271
    .line 272
    iget-boolean v10, v0, Lh4/j;->l:Z

    .line 273
    .line 274
    if-eqz v10, :cond_e

    .line 275
    .line 276
    move-object v10, v2

    .line 277
    check-cast v10, Landroid/text/BoringLayout;

    .line 278
    .line 279
    sget v11, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 280
    .line 281
    const/16 v12, 0x21

    .line 282
    .line 283
    if-lt v11, v12, :cond_d

    .line 284
    .line 285
    invoke-static {v10}, Lb/s;->z(Landroid/text/BoringLayout;)Z

    .line 286
    .line 287
    .line 288
    move-result v13

    .line 289
    goto :goto_7

    .line 290
    :cond_d
    const/4 v13, 0x0

    .line 291
    goto :goto_7

    .line 292
    :cond_e
    const/16 v12, 0x21

    .line 293
    .line 294
    move-object v10, v2

    .line 295
    check-cast v10, Landroid/text/StaticLayout;

    .line 296
    .line 297
    sget v11, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 298
    .line 299
    if-lt v11, v12, :cond_f

    .line 300
    .line 301
    invoke-static {v10}, Lb/s;->A(Landroid/text/StaticLayout;)Z

    .line 302
    .line 303
    .line 304
    move-result v13

    .line 305
    goto :goto_7

    .line 306
    :cond_f
    const/4 v13, 0x1

    .line 307
    :goto_7
    if-eqz v13, :cond_10

    .line 308
    .line 309
    const/16 p1, 0x20

    .line 310
    .line 311
    const/4 v4, 0x1

    .line 312
    :goto_8
    const/4 v13, 0x0

    .line 313
    goto :goto_d

    .line 314
    :cond_10
    invoke-virtual {v2}, Landroid/text/Layout;->getPaint()Landroid/text/TextPaint;

    .line 315
    .line 316
    .line 317
    move-result-object v10

    .line 318
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 319
    .line 320
    .line 321
    move-result-object v11

    .line 322
    const/4 v13, 0x0

    .line 323
    invoke-virtual {v2, v13}, Landroid/text/Layout;->getLineStart(I)I

    .line 324
    .line 325
    .line 326
    move-result v14

    .line 327
    invoke-virtual {v2, v13}, Landroid/text/Layout;->getLineEnd(I)I

    .line 328
    .line 329
    .line 330
    move-result v15

    .line 331
    invoke-static {v10, v11, v14, v15}, Lh4/g;->b(Landroid/text/TextPaint;Ljava/lang/CharSequence;II)Landroid/graphics/Rect;

    .line 332
    .line 333
    .line 334
    move-result-object v14

    .line 335
    invoke-virtual {v2, v13}, Landroid/text/Layout;->getLineAscent(I)I

    .line 336
    .line 337
    .line 338
    move-result v15

    .line 339
    const/16 p1, 0x20

    .line 340
    .line 341
    iget v4, v14, Landroid/graphics/Rect;->top:I

    .line 342
    .line 343
    if-ge v4, v15, :cond_11

    .line 344
    .line 345
    sub-int/2addr v15, v4

    .line 346
    :goto_9
    const/4 v4, 0x1

    .line 347
    goto :goto_a

    .line 348
    :cond_11
    invoke-virtual {v2}, Landroid/text/Layout;->getTopPadding()I

    .line 349
    .line 350
    .line 351
    move-result v15

    .line 352
    goto :goto_9

    .line 353
    :goto_a
    if-ne v1, v4, :cond_12

    .line 354
    .line 355
    goto :goto_b

    .line 356
    :cond_12
    invoke-virtual {v2, v3}, Landroid/text/Layout;->getLineStart(I)I

    .line 357
    .line 358
    .line 359
    move-result v1

    .line 360
    invoke-virtual {v2, v3}, Landroid/text/Layout;->getLineEnd(I)I

    .line 361
    .line 362
    .line 363
    move-result v14

    .line 364
    invoke-static {v10, v11, v1, v14}, Lh4/g;->b(Landroid/text/TextPaint;Ljava/lang/CharSequence;II)Landroid/graphics/Rect;

    .line 365
    .line 366
    .line 367
    move-result-object v14

    .line 368
    :goto_b
    invoke-virtual {v2, v3}, Landroid/text/Layout;->getLineDescent(I)I

    .line 369
    .line 370
    .line 371
    move-result v1

    .line 372
    iget v10, v14, Landroid/graphics/Rect;->bottom:I

    .line 373
    .line 374
    if-le v10, v1, :cond_13

    .line 375
    .line 376
    sub-int/2addr v10, v1

    .line 377
    goto :goto_c

    .line 378
    :cond_13
    invoke-virtual {v2}, Landroid/text/Layout;->getBottomPadding()I

    .line 379
    .line 380
    .line 381
    move-result v10

    .line 382
    :goto_c
    if-nez v15, :cond_14

    .line 383
    .line 384
    if-nez v10, :cond_14

    .line 385
    .line 386
    goto :goto_d

    .line 387
    :cond_14
    int-to-long v14, v15

    .line 388
    shl-long v14, v14, p1

    .line 389
    .line 390
    int-to-long v10, v10

    .line 391
    and-long/2addr v10, v8

    .line 392
    or-long/2addr v10, v14

    .line 393
    goto :goto_e

    .line 394
    :cond_15
    const/16 p1, 0x20

    .line 395
    .line 396
    const/4 v4, 0x1

    .line 397
    const/16 v12, 0x21

    .line 398
    .line 399
    goto :goto_8

    .line 400
    :goto_d
    move-wide v10, v6

    .line 401
    :goto_e
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 402
    .line 403
    .line 404
    move-result-object v1

    .line 405
    instance-of v1, v1, Landroid/text/Spanned;

    .line 406
    .line 407
    const/4 v14, 0x0

    .line 408
    if-nez v1, :cond_16

    .line 409
    .line 410
    move/from16 v21, v4

    .line 411
    .line 412
    goto :goto_f

    .line 413
    :cond_16
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 414
    .line 415
    .line 416
    move-result-object v1

    .line 417
    const-string v15, "null cannot be cast to non-null type android.text.Spanned"

    .line 418
    .line 419
    invoke-static {v1, v15}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    check-cast v1, Landroid/text/Spanned;

    .line 423
    .line 424
    move/from16 v21, v4

    .line 425
    .line 426
    const-class v4, Lj4/h;

    .line 427
    .line 428
    invoke-static {v1, v4}, Lh4/g;->f(Landroid/text/Spanned;Ljava/lang/Class;)Z

    .line 429
    .line 430
    .line 431
    move-result v1

    .line 432
    if-nez v1, :cond_17

    .line 433
    .line 434
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 435
    .line 436
    .line 437
    move-result-object v1

    .line 438
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 439
    .line 440
    .line 441
    move-result v1

    .line 442
    if-lez v1, :cond_17

    .line 443
    .line 444
    :goto_f
    move-object v1, v14

    .line 445
    goto :goto_10

    .line 446
    :cond_17
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 447
    .line 448
    .line 449
    move-result-object v1

    .line 450
    invoke-static {v1, v15}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 451
    .line 452
    .line 453
    check-cast v1, Landroid/text/Spanned;

    .line 454
    .line 455
    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 460
    .line 461
    .line 462
    move-result v2

    .line 463
    invoke-interface {v1, v13, v2, v4}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v1

    .line 467
    check-cast v1, [Lj4/h;

    .line 468
    .line 469
    :goto_10
    iput-object v1, v0, Lh4/j;->o:[Lj4/h;

    .line 470
    .line 471
    if-eqz v1, :cond_1c

    .line 472
    .line 473
    array-length v2, v1

    .line 474
    move v4, v13

    .line 475
    move v6, v4

    .line 476
    move v7, v6

    .line 477
    :goto_11
    if-ge v4, v2, :cond_1a

    .line 478
    .line 479
    aget-object v15, v1, v4

    .line 480
    .line 481
    move-wide/from16 p2, v8

    .line 482
    .line 483
    iget v8, v15, Lj4/h;->n:I

    .line 484
    .line 485
    if-gez v8, :cond_18

    .line 486
    .line 487
    invoke-static {v8}, Ljava/lang/Math;->abs(I)I

    .line 488
    .line 489
    .line 490
    move-result v8

    .line 491
    invoke-static {v6, v8}, Ljava/lang/Math;->max(II)I

    .line 492
    .line 493
    .line 494
    move-result v6

    .line 495
    :cond_18
    iget v8, v15, Lj4/h;->o:I

    .line 496
    .line 497
    if-gez v8, :cond_19

    .line 498
    .line 499
    invoke-static {v8}, Ljava/lang/Math;->abs(I)I

    .line 500
    .line 501
    .line 502
    move-result v7

    .line 503
    invoke-static {v6, v7}, Ljava/lang/Math;->max(II)I

    .line 504
    .line 505
    .line 506
    move-result v7

    .line 507
    :cond_19
    add-int/lit8 v4, v4, 0x1

    .line 508
    .line 509
    move-wide/from16 v8, p2

    .line 510
    .line 511
    goto :goto_11

    .line 512
    :cond_1a
    move-wide/from16 p2, v8

    .line 513
    .line 514
    if-nez v6, :cond_1b

    .line 515
    .line 516
    if-nez v7, :cond_1b

    .line 517
    .line 518
    sget-wide v1, Lh4/k;->b:J

    .line 519
    .line 520
    :goto_12
    move-wide v6, v1

    .line 521
    goto :goto_13

    .line 522
    :cond_1b
    int-to-long v1, v6

    .line 523
    shl-long v1, v1, p1

    .line 524
    .line 525
    int-to-long v6, v7

    .line 526
    and-long v6, v6, p2

    .line 527
    .line 528
    or-long/2addr v1, v6

    .line 529
    goto :goto_12

    .line 530
    :cond_1c
    move-wide/from16 p2, v8

    .line 531
    .line 532
    :goto_13
    shr-long v1, v10, p1

    .line 533
    .line 534
    long-to-int v1, v1

    .line 535
    shr-long v8, v6, p1

    .line 536
    .line 537
    long-to-int v2, v8

    .line 538
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 539
    .line 540
    .line 541
    move-result v1

    .line 542
    iput v1, v0, Lh4/j;->h:I

    .line 543
    .line 544
    and-long v1, v10, p2

    .line 545
    .line 546
    long-to-int v1, v1

    .line 547
    and-long v6, v6, p2

    .line 548
    .line 549
    long-to-int v2, v6

    .line 550
    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    .line 551
    .line 552
    .line 553
    move-result v1

    .line 554
    iput v1, v0, Lh4/j;->i:I

    .line 555
    .line 556
    iget-object v7, v0, Lh4/j;->a:Landroid/text/TextPaint;

    .line 557
    .line 558
    iget-object v1, v0, Lh4/j;->o:[Lj4/h;

    .line 559
    .line 560
    iget v2, v0, Lh4/j;->g:I

    .line 561
    .line 562
    add-int/lit8 v2, v2, -0x1

    .line 563
    .line 564
    iget-object v4, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 565
    .line 566
    invoke-virtual {v4, v2}, Landroid/text/Layout;->getLineStart(I)I

    .line 567
    .line 568
    .line 569
    move-result v6

    .line 570
    invoke-virtual {v4, v2}, Landroid/text/Layout;->getLineEnd(I)I

    .line 571
    .line 572
    .line 573
    move-result v4

    .line 574
    if-ne v6, v4, :cond_1d

    .line 575
    .line 576
    if-eqz v1, :cond_1d

    .line 577
    .line 578
    array-length v4, v1

    .line 579
    if-nez v4, :cond_1e

    .line 580
    .line 581
    :cond_1d
    move v1, v13

    .line 582
    goto/16 :goto_15

    .line 583
    .line 584
    :cond_1e
    new-instance v6, Landroid/text/SpannableString;

    .line 585
    .line 586
    const-string v4, "\u200b"

    .line 587
    .line 588
    invoke-direct {v6, v4}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 589
    .line 590
    .line 591
    invoke-static {v1}, Lmx0/n;->u([Ljava/lang/Object;)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    move-result-object v1

    .line 595
    check-cast v1, Lj4/h;

    .line 596
    .line 597
    invoke-virtual {v6}, Landroid/text/SpannableString;->length()I

    .line 598
    .line 599
    .line 600
    move-result v4

    .line 601
    if-eqz v2, :cond_1f

    .line 602
    .line 603
    iget-boolean v2, v1, Lj4/h;->g:Z

    .line 604
    .line 605
    if-eqz v2, :cond_1f

    .line 606
    .line 607
    move v14, v13

    .line 608
    goto :goto_14

    .line 609
    :cond_1f
    iget-boolean v14, v1, Lj4/h;->g:Z

    .line 610
    .line 611
    :goto_14
    new-instance v2, Lj4/h;

    .line 612
    .line 613
    iget v8, v1, Lj4/h;->d:F

    .line 614
    .line 615
    iget-boolean v9, v1, Lj4/h;->g:Z

    .line 616
    .line 617
    iget v10, v1, Lj4/h;->h:F

    .line 618
    .line 619
    iget-boolean v1, v1, Lj4/h;->i:Z

    .line 620
    .line 621
    move/from16 p7, v1

    .line 622
    .line 623
    move-object/from16 p1, v2

    .line 624
    .line 625
    move/from16 p3, v4

    .line 626
    .line 627
    move/from16 p2, v8

    .line 628
    .line 629
    move/from16 p5, v9

    .line 630
    .line 631
    move/from16 p6, v10

    .line 632
    .line 633
    move/from16 p4, v14

    .line 634
    .line 635
    invoke-direct/range {p1 .. p7}, Lj4/h;-><init>(FIZZFZ)V

    .line 636
    .line 637
    .line 638
    move-object/from16 v1, p1

    .line 639
    .line 640
    invoke-virtual {v6}, Landroid/text/SpannableString;->length()I

    .line 641
    .line 642
    .line 643
    move-result v2

    .line 644
    invoke-virtual {v6, v1, v13, v2, v12}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 645
    .line 646
    .line 647
    invoke-virtual {v6}, Landroid/text/SpannableString;->length()I

    .line 648
    .line 649
    .line 650
    move-result v9

    .line 651
    iget-boolean v1, v0, Lh4/j;->c:Z

    .line 652
    .line 653
    sget-object v11, Lh4/d;->a:Landroid/text/Layout$Alignment;

    .line 654
    .line 655
    const/16 v19, 0x0

    .line 656
    .line 657
    const/16 v20, 0x0

    .line 658
    .line 659
    const v8, 0x7fffffff

    .line 660
    .line 661
    .line 662
    const v12, 0x7fffffff

    .line 663
    .line 664
    .line 665
    move/from16 v22, v13

    .line 666
    .line 667
    const/4 v13, 0x0

    .line 668
    const v14, 0x7fffffff

    .line 669
    .line 670
    .line 671
    const/4 v15, 0x0

    .line 672
    const/16 v17, 0x0

    .line 673
    .line 674
    const/16 v18, 0x0

    .line 675
    .line 676
    move/from16 v16, v1

    .line 677
    .line 678
    move-object v10, v5

    .line 679
    move/from16 v1, v22

    .line 680
    .line 681
    invoke-static/range {v6 .. v20}, Lh4/g;->a(Ljava/lang/CharSequence;Landroid/text/TextPaint;IILandroid/text/TextDirectionHeuristic;Landroid/text/Layout$Alignment;ILandroid/text/TextUtils$TruncateAt;IIZIIII)Landroid/text/StaticLayout;

    .line 682
    .line 683
    .line 684
    move-result-object v2

    .line 685
    new-instance v14, Landroid/graphics/Paint$FontMetricsInt;

    .line 686
    .line 687
    invoke-direct {v14}, Landroid/graphics/Paint$FontMetricsInt;-><init>()V

    .line 688
    .line 689
    .line 690
    invoke-virtual {v2, v1}, Landroid/text/Layout;->getLineAscent(I)I

    .line 691
    .line 692
    .line 693
    move-result v4

    .line 694
    iput v4, v14, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 695
    .line 696
    invoke-virtual {v2, v1}, Landroid/text/StaticLayout;->getLineDescent(I)I

    .line 697
    .line 698
    .line 699
    move-result v4

    .line 700
    iput v4, v14, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 701
    .line 702
    invoke-virtual {v2, v1}, Landroid/text/StaticLayout;->getLineTop(I)I

    .line 703
    .line 704
    .line 705
    move-result v4

    .line 706
    iput v4, v14, Landroid/graphics/Paint$FontMetricsInt;->top:I

    .line 707
    .line 708
    invoke-virtual {v2, v1}, Landroid/text/Layout;->getLineBottom(I)I

    .line 709
    .line 710
    .line 711
    move-result v2

    .line 712
    iput v2, v14, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 713
    .line 714
    :goto_15
    if-eqz v14, :cond_20

    .line 715
    .line 716
    iget v1, v14, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 717
    .line 718
    invoke-virtual {v0, v3}, Lh4/j;->e(I)F

    .line 719
    .line 720
    .line 721
    move-result v2

    .line 722
    invoke-virtual {v0, v3}, Lh4/j;->g(I)F

    .line 723
    .line 724
    .line 725
    move-result v4

    .line 726
    sub-float/2addr v2, v4

    .line 727
    float-to-int v2, v2

    .line 728
    sub-int/2addr v1, v2

    .line 729
    :cond_20
    iput v1, v0, Lh4/j;->n:I

    .line 730
    .line 731
    iput-object v14, v0, Lh4/j;->m:Landroid/graphics/Paint$FontMetricsInt;

    .line 732
    .line 733
    iget-object v1, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 734
    .line 735
    invoke-virtual {v1}, Landroid/text/Layout;->getPaint()Landroid/text/TextPaint;

    .line 736
    .line 737
    .line 738
    move-result-object v2

    .line 739
    invoke-static {v1, v3, v2}, Llp/kb;->a(Landroid/text/Layout;ILandroid/graphics/Paint;)F

    .line 740
    .line 741
    .line 742
    move-result v1

    .line 743
    iput v1, v0, Lh4/j;->j:F

    .line 744
    .line 745
    iget-object v1, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 746
    .line 747
    invoke-virtual {v1}, Landroid/text/Layout;->getPaint()Landroid/text/TextPaint;

    .line 748
    .line 749
    .line 750
    move-result-object v2

    .line 751
    invoke-static {v1, v3, v2}, Llp/kb;->b(Landroid/text/Layout;ILandroid/graphics/Paint;)F

    .line 752
    .line 753
    .line 754
    move-result v1

    .line 755
    iput v1, v0, Lh4/j;->k:F

    .line 756
    .line 757
    return-void

    .line 758
    :catchall_0
    move-exception v0

    .line 759
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 760
    .line 761
    .line 762
    throw v0
.end method


# virtual methods
.method public final a()I
    .locals 2

    .line 1
    iget-boolean v0, p0, Lh4/j;->d:Z

    .line 2
    .line 3
    iget-object v1, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget v0, p0, Lh4/j;->g:I

    .line 8
    .line 9
    add-int/lit8 v0, v0, -0x1

    .line 10
    .line 11
    invoke-virtual {v1, v0}, Landroid/text/Layout;->getLineBottom(I)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v1}, Landroid/text/Layout;->getHeight()I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    :goto_0
    iget v1, p0, Lh4/j;->h:I

    .line 21
    .line 22
    add-int/2addr v0, v1

    .line 23
    iget v1, p0, Lh4/j;->i:I

    .line 24
    .line 25
    add-int/2addr v0, v1

    .line 26
    iget p0, p0, Lh4/j;->n:I

    .line 27
    .line 28
    add-int/2addr v0, p0

    .line 29
    return v0
.end method

.method public final b(I)F
    .locals 1

    .line 1
    iget v0, p0, Lh4/j;->g:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, -0x1

    .line 4
    .line 5
    if-ne p1, v0, :cond_0

    .line 6
    .line 7
    iget p1, p0, Lh4/j;->j:F

    .line 8
    .line 9
    iget p0, p0, Lh4/j;->k:F

    .line 10
    .line 11
    add-float/2addr p1, p0

    .line 12
    return p1

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public final c()Landroidx/lifecycle/c1;
    .locals 2

    .line 1
    iget-object v0, p0, Lh4/j;->q:Landroidx/lifecycle/c1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroidx/lifecycle/c1;

    .line 6
    .line 7
    iget-object v1, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 8
    .line 9
    invoke-direct {v0, v1}, Landroidx/lifecycle/c1;-><init>(Landroid/text/Layout;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lh4/j;->q:Landroidx/lifecycle/c1;

    .line 13
    .line 14
    :cond_0
    return-object v0
.end method

.method public final d(I)F
    .locals 2

    .line 1
    iget v0, p0, Lh4/j;->h:I

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    iget v1, p0, Lh4/j;->g:I

    .line 5
    .line 6
    add-int/lit8 v1, v1, -0x1

    .line 7
    .line 8
    if-ne p1, v1, :cond_0

    .line 9
    .line 10
    iget-object v1, p0, Lh4/j;->m:Landroid/graphics/Paint$FontMetricsInt;

    .line 11
    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lh4/j;->g(I)F

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    iget p1, v1, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 19
    .line 20
    int-to-float p1, p1

    .line 21
    sub-float/2addr p0, p1

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object p0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 24
    .line 25
    invoke-virtual {p0, p1}, Landroid/text/Layout;->getLineBaseline(I)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    int-to-float p0, p0

    .line 30
    :goto_0
    add-float/2addr v0, p0

    .line 31
    return v0
.end method

.method public final e(I)F
    .locals 3

    .line 1
    iget v0, p0, Lh4/j;->g:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, -0x1

    .line 4
    .line 5
    iget-object v2, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 6
    .line 7
    if-ne p1, v1, :cond_0

    .line 8
    .line 9
    iget-object v1, p0, Lh4/j;->m:Landroid/graphics/Paint$FontMetricsInt;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    add-int/lit8 p1, p1, -0x1

    .line 14
    .line 15
    invoke-virtual {v2, p1}, Landroid/text/Layout;->getLineBottom(I)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    int-to-float p0, p0

    .line 20
    iget p1, v1, Landroid/graphics/Paint$FontMetricsInt;->bottom:I

    .line 21
    .line 22
    int-to-float p1, p1

    .line 23
    add-float/2addr p0, p1

    .line 24
    return p0

    .line 25
    :cond_0
    iget v1, p0, Lh4/j;->h:I

    .line 26
    .line 27
    int-to-float v1, v1

    .line 28
    invoke-virtual {v2, p1}, Landroid/text/Layout;->getLineBottom(I)I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    int-to-float v2, v2

    .line 33
    add-float/2addr v1, v2

    .line 34
    add-int/lit8 v0, v0, -0x1

    .line 35
    .line 36
    if-ne p1, v0, :cond_1

    .line 37
    .line 38
    iget p0, p0, Lh4/j;->i:I

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    const/4 p0, 0x0

    .line 42
    :goto_0
    int-to-float p0, p0

    .line 43
    add-float/2addr v1, p0

    .line 44
    return v1
.end method

.method public final f(I)I
    .locals 2

    .line 1
    sget-object v0, Lh4/k;->a:Lh4/i;

    .line 2
    .line 3
    iget-object v0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-lez v1, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lh4/j;->b:Landroid/text/TextUtils$TruncateAt;

    .line 12
    .line 13
    sget-object v1, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    .line 14
    .line 15
    if-ne p0, v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineEnd(I)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    return p0
.end method

.method public final g(I)F
    .locals 1

    .line 1
    iget-object v0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineTop(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    int-to-float v0, v0

    .line 8
    if-nez p1, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget p0, p0, Lh4/j;->h:I

    .line 13
    .line 14
    :goto_0
    int-to-float p0, p0

    .line 15
    add-float/2addr v0, p0

    .line 16
    return v0
.end method

.method public final h(IZ)F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh4/j;->c()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-virtual {v0, p1, v1, p2}, Landroidx/lifecycle/c1;->x(IZZ)F

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    iget-object v0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    invoke-virtual {p0, p1}, Lh4/j;->b(I)F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-float/2addr p0, p2

    .line 21
    return p0
.end method

.method public final i(IZ)F
    .locals 2

    .line 1
    invoke-virtual {p0}, Lh4/j;->c()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {v0, p1, v1, p2}, Landroidx/lifecycle/c1;->x(IZZ)F

    .line 7
    .line 8
    .line 9
    move-result p2

    .line 10
    iget-object v0, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 11
    .line 12
    invoke-virtual {v0, p1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    invoke-virtual {p0, p1}, Lh4/j;->b(I)F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    add-float/2addr p0, p2

    .line 21
    return p0
.end method

.method public final j()Li4/c;
    .locals 4

    .line 1
    iget-object v0, p0, Lh4/j;->e:Li4/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    new-instance v0, Li4/c;

    .line 7
    .line 8
    iget-object v1, p0, Lh4/j;->f:Landroid/text/Layout;

    .line 9
    .line 10
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget-object v3, p0, Lh4/j;->a:Landroid/text/TextPaint;

    .line 23
    .line 24
    invoke-virtual {v3}, Landroid/graphics/Paint;->getTextLocale()Ljava/util/Locale;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-direct {v0, v2, v1, v3}, Li4/c;-><init>(Ljava/lang/CharSequence;ILjava/util/Locale;)V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Lh4/j;->e:Li4/c;

    .line 32
    .line 33
    return-object v0
.end method
