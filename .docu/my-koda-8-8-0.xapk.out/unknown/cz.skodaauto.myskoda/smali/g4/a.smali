.class public final Lg4/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lo4/c;

.field public final b:I

.field public final c:J

.field public final d:Lh4/j;

.field public final e:Ljava/lang/CharSequence;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lo4/c;IIJ)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v10, p1

    .line 4
    .line 5
    move/from16 v4, p2

    .line 6
    .line 7
    move/from16 v11, p3

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v10, v0, Lg4/a;->a:Lo4/c;

    .line 13
    .line 14
    iput v4, v0, Lg4/a;->b:I

    .line 15
    .line 16
    move-wide/from16 v12, p4

    .line 17
    .line 18
    iput-wide v12, v0, Lg4/a;->c:J

    .line 19
    .line 20
    invoke-static {v12, v13}, Lt4/a;->i(J)I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-nez v1, :cond_0

    .line 25
    .line 26
    invoke-static {v12, v13}, Lt4/a;->j(J)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const-string v1, "Setting Constraints.minWidth and Constraints.minHeight is not supported, these should be the default zero values instead."

    .line 34
    .line 35
    invoke-static {v1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :goto_0
    const/4 v14, 0x1

    .line 39
    if-lt v4, v14, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const-string v1, "maxLines should be greater than 0"

    .line 43
    .line 44
    invoke-static {v1}, Lm4/a;->a(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :goto_1
    iget-object v1, v10, Lo4/c;->e:Lg4/p0;

    .line 48
    .line 49
    iget-object v2, v10, Lo4/c;->k:Ljava/lang/CharSequence;

    .line 50
    .line 51
    const/4 v3, 0x5

    .line 52
    const/4 v5, 0x4

    .line 53
    const/4 v6, 0x2

    .line 54
    if-ne v11, v6, :cond_9

    .line 55
    .line 56
    iget-object v8, v1, Lg4/p0;->a:Lg4/g0;

    .line 57
    .line 58
    iget-wide v8, v8, Lg4/g0;->h:J

    .line 59
    .line 60
    const/16 v17, 0x0

    .line 61
    .line 62
    invoke-static/range {v17 .. v17}, Lgq/b;->c(I)J

    .line 63
    .line 64
    .line 65
    move-result-wide v6

    .line 66
    invoke-static {v8, v9, v6, v7}, Lt4/o;->a(JJ)Z

    .line 67
    .line 68
    .line 69
    move-result v6

    .line 70
    if-nez v6, :cond_8

    .line 71
    .line 72
    iget-object v6, v1, Lg4/p0;->a:Lg4/g0;

    .line 73
    .line 74
    iget-wide v6, v6, Lg4/g0;->h:J

    .line 75
    .line 76
    sget-wide v8, Lt4/o;->c:J

    .line 77
    .line 78
    invoke-static {v6, v7, v8, v9}, Lt4/o;->a(JJ)Z

    .line 79
    .line 80
    .line 81
    move-result v6

    .line 82
    if-nez v6, :cond_8

    .line 83
    .line 84
    iget-object v6, v1, Lg4/p0;->b:Lg4/t;

    .line 85
    .line 86
    iget v6, v6, Lg4/t;->a:I

    .line 87
    .line 88
    const/high16 v7, -0x80000000

    .line 89
    .line 90
    if-ne v6, v7, :cond_2

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_2
    if-ne v6, v3, :cond_3

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_3
    if-ne v6, v5, :cond_4

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_4
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    if-nez v6, :cond_5

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_5
    instance-of v6, v2, Landroid/text/Spannable;

    .line 107
    .line 108
    if-eqz v6, :cond_6

    .line 109
    .line 110
    move-object v6, v2

    .line 111
    check-cast v6, Landroid/text/Spannable;

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_6
    const/4 v6, 0x0

    .line 115
    :goto_2
    if-nez v6, :cond_7

    .line 116
    .line 117
    new-instance v6, Landroid/text/SpannableString;

    .line 118
    .line 119
    invoke-direct {v6, v2}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 120
    .line 121
    .line 122
    :cond_7
    move-object v2, v6

    .line 123
    const-class v6, Lj4/c;

    .line 124
    .line 125
    invoke-static {v2, v6}, Lh4/g;->f(Landroid/text/Spanned;Ljava/lang/Class;)Z

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-nez v6, :cond_8

    .line 130
    .line 131
    new-instance v6, Lj4/c;

    .line 132
    .line 133
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 134
    .line 135
    .line 136
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    sub-int/2addr v7, v14

    .line 141
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 142
    .line 143
    .line 144
    move-result v8

    .line 145
    sub-int/2addr v8, v14

    .line 146
    const/16 v9, 0x21

    .line 147
    .line 148
    invoke-interface {v2, v6, v7, v8, v9}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 149
    .line 150
    .line 151
    :cond_8
    :goto_3
    move-object v9, v2

    .line 152
    goto :goto_4

    .line 153
    :cond_9
    const/16 v17, 0x0

    .line 154
    .line 155
    goto :goto_3

    .line 156
    :goto_4
    iput-object v9, v0, Lg4/a;->e:Ljava/lang/CharSequence;

    .line 157
    .line 158
    iget-object v2, v1, Lg4/p0;->b:Lg4/t;

    .line 159
    .line 160
    iget-object v1, v1, Lg4/p0;->a:Lg4/g0;

    .line 161
    .line 162
    iget v6, v2, Lg4/t;->a:I

    .line 163
    .line 164
    const/4 v7, 0x3

    .line 165
    if-ne v6, v14, :cond_a

    .line 166
    .line 167
    move v8, v7

    .line 168
    goto :goto_6

    .line 169
    :cond_a
    const/4 v8, 0x2

    .line 170
    if-ne v6, v8, :cond_b

    .line 171
    .line 172
    move v8, v5

    .line 173
    goto :goto_6

    .line 174
    :cond_b
    if-ne v6, v7, :cond_c

    .line 175
    .line 176
    const/4 v8, 0x2

    .line 177
    goto :goto_6

    .line 178
    :cond_c
    if-ne v6, v3, :cond_d

    .line 179
    .line 180
    goto :goto_5

    .line 181
    :cond_d
    const/4 v8, 0x6

    .line 182
    if-ne v6, v8, :cond_e

    .line 183
    .line 184
    move v8, v14

    .line 185
    goto :goto_6

    .line 186
    :cond_e
    :goto_5
    move/from16 v8, v17

    .line 187
    .line 188
    :goto_6
    if-ne v6, v5, :cond_f

    .line 189
    .line 190
    move v6, v14

    .line 191
    goto :goto_7

    .line 192
    :cond_f
    move/from16 v6, v17

    .line 193
    .line 194
    :goto_7
    iget v15, v2, Lg4/t;->h:I

    .line 195
    .line 196
    const/16 v3, 0x20

    .line 197
    .line 198
    const/4 v5, 0x2

    .line 199
    if-ne v15, v5, :cond_11

    .line 200
    .line 201
    sget v15, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 202
    .line 203
    if-gt v15, v3, :cond_10

    .line 204
    .line 205
    move v15, v5

    .line 206
    goto :goto_8

    .line 207
    :cond_10
    const/4 v15, 0x4

    .line 208
    goto :goto_8

    .line 209
    :cond_11
    move/from16 v15, v17

    .line 210
    .line 211
    :goto_8
    iget v2, v2, Lg4/t;->g:I

    .line 212
    .line 213
    and-int/lit16 v3, v2, 0xff

    .line 214
    .line 215
    if-ne v3, v14, :cond_12

    .line 216
    .line 217
    goto :goto_9

    .line 218
    :cond_12
    if-ne v3, v5, :cond_13

    .line 219
    .line 220
    move v3, v2

    .line 221
    move v2, v6

    .line 222
    move v6, v14

    .line 223
    goto :goto_a

    .line 224
    :cond_13
    if-ne v3, v7, :cond_14

    .line 225
    .line 226
    move v3, v2

    .line 227
    move v2, v6

    .line 228
    const/4 v6, 0x2

    .line 229
    goto :goto_a

    .line 230
    :cond_14
    :goto_9
    move v3, v2

    .line 231
    move v2, v6

    .line 232
    move/from16 v6, v17

    .line 233
    .line 234
    :goto_a
    shr-int/lit8 v5, v3, 0x8

    .line 235
    .line 236
    and-int/lit16 v5, v5, 0xff

    .line 237
    .line 238
    if-ne v5, v14, :cond_15

    .line 239
    .line 240
    goto :goto_b

    .line 241
    :cond_15
    const/4 v14, 0x2

    .line 242
    if-ne v5, v14, :cond_16

    .line 243
    .line 244
    move v5, v7

    .line 245
    const/4 v7, 0x1

    .line 246
    goto :goto_c

    .line 247
    :cond_16
    if-ne v5, v7, :cond_17

    .line 248
    .line 249
    move v5, v7

    .line 250
    const/4 v7, 0x2

    .line 251
    goto :goto_c

    .line 252
    :cond_17
    const/4 v14, 0x4

    .line 253
    if-ne v5, v14, :cond_18

    .line 254
    .line 255
    move v5, v7

    .line 256
    goto :goto_c

    .line 257
    :cond_18
    :goto_b
    move v5, v7

    .line 258
    move/from16 v7, v17

    .line 259
    .line 260
    :goto_c
    shr-int/lit8 v3, v3, 0x10

    .line 261
    .line 262
    and-int/lit16 v3, v3, 0xff

    .line 263
    .line 264
    const/4 v14, 0x1

    .line 265
    if-ne v3, v14, :cond_19

    .line 266
    .line 267
    const/4 v14, 0x2

    .line 268
    goto :goto_d

    .line 269
    :cond_19
    const/4 v14, 0x2

    .line 270
    if-ne v3, v14, :cond_1a

    .line 271
    .line 272
    move-object v3, v1

    .line 273
    move v1, v8

    .line 274
    const/4 v8, 0x1

    .line 275
    goto :goto_e

    .line 276
    :cond_1a
    :goto_d
    move-object v3, v1

    .line 277
    move v1, v8

    .line 278
    move/from16 v8, v17

    .line 279
    .line 280
    :goto_e
    if-ne v11, v14, :cond_1b

    .line 281
    .line 282
    sget-object v16, Landroid/text/TextUtils$TruncateAt;->END:Landroid/text/TextUtils$TruncateAt;

    .line 283
    .line 284
    :goto_f
    move v5, v15

    .line 285
    const/16 v18, 0x20

    .line 286
    .line 287
    move-object v15, v3

    .line 288
    move-object/from16 v3, v16

    .line 289
    .line 290
    goto :goto_10

    .line 291
    :cond_1b
    const/4 v5, 0x5

    .line 292
    if-ne v11, v5, :cond_1c

    .line 293
    .line 294
    sget-object v16, Landroid/text/TextUtils$TruncateAt;->MIDDLE:Landroid/text/TextUtils$TruncateAt;

    .line 295
    .line 296
    goto :goto_f

    .line 297
    :cond_1c
    const/4 v5, 0x4

    .line 298
    if-ne v11, v5, :cond_1d

    .line 299
    .line 300
    sget-object v16, Landroid/text/TextUtils$TruncateAt;->START:Landroid/text/TextUtils$TruncateAt;

    .line 301
    .line 302
    goto :goto_f

    .line 303
    :cond_1d
    move v5, v15

    .line 304
    const/16 v18, 0x20

    .line 305
    .line 306
    move-object v15, v3

    .line 307
    const/4 v3, 0x0

    .line 308
    :goto_10
    invoke-virtual/range {v0 .. v9}, Lg4/a;->a(IILandroid/text/TextUtils$TruncateAt;IIIIILjava/lang/CharSequence;)Lh4/j;

    .line 309
    .line 310
    .line 311
    move-result-object v14

    .line 312
    iget-object v0, v14, Lh4/j;->f:Landroid/text/Layout;

    .line 313
    .line 314
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 315
    .line 316
    move/from16 v16, v1

    .line 317
    .line 318
    const/16 v1, 0x23

    .line 319
    .line 320
    if-ge v4, v1, :cond_1e

    .line 321
    .line 322
    iget-object v1, v10, Lo4/c;->j:Lo4/d;

    .line 323
    .line 324
    invoke-virtual {v1}, Landroid/graphics/Paint;->getLetterSpacing()F

    .line 325
    .line 326
    .line 327
    move-result v1

    .line 328
    const/4 v4, 0x0

    .line 329
    cmpg-float v1, v1, v4

    .line 330
    .line 331
    if-nez v1, :cond_1f

    .line 332
    .line 333
    :cond_1e
    const/4 v10, 0x2

    .line 334
    move-object/from16 v0, p0

    .line 335
    .line 336
    move/from16 v4, p2

    .line 337
    .line 338
    move/from16 v1, v16

    .line 339
    .line 340
    goto :goto_13

    .line 341
    :cond_1f
    const/4 v1, 0x4

    .line 342
    if-ne v11, v1, :cond_20

    .line 343
    .line 344
    :goto_11
    const/4 v1, 0x0

    .line 345
    goto :goto_12

    .line 346
    :cond_20
    const/4 v1, 0x5

    .line 347
    if-ne v11, v1, :cond_1e

    .line 348
    .line 349
    goto :goto_11

    .line 350
    :goto_12
    invoke-virtual {v0, v1}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 351
    .line 352
    .line 353
    move-result v4

    .line 354
    if-lez v4, :cond_1e

    .line 355
    .line 356
    invoke-virtual {v0, v1}, Landroid/text/Layout;->getEllipsisStart(I)I

    .line 357
    .line 358
    .line 359
    move-result v4

    .line 360
    invoke-virtual {v0, v1}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 361
    .line 362
    .line 363
    move-result v0

    .line 364
    add-int/2addr v0, v4

    .line 365
    invoke-interface {v9, v1, v4}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 366
    .line 367
    .line 368
    move-result-object v4

    .line 369
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 370
    .line 371
    .line 372
    move-result v10

    .line 373
    invoke-interface {v9, v0, v10}, Ljava/lang/CharSequence;->subSequence(II)Ljava/lang/CharSequence;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    const/4 v9, 0x3

    .line 378
    new-array v9, v9, [Ljava/lang/CharSequence;

    .line 379
    .line 380
    aput-object v4, v9, v1

    .line 381
    .line 382
    const-string v1, "\u2026"

    .line 383
    .line 384
    const/16 v19, 0x1

    .line 385
    .line 386
    aput-object v1, v9, v19

    .line 387
    .line 388
    const/4 v10, 0x2

    .line 389
    aput-object v0, v9, v10

    .line 390
    .line 391
    invoke-static {v9}, Landroid/text/TextUtils;->concat([Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 392
    .line 393
    .line 394
    move-result-object v9

    .line 395
    move-object/from16 v0, p0

    .line 396
    .line 397
    move/from16 v4, p2

    .line 398
    .line 399
    move/from16 v1, v16

    .line 400
    .line 401
    invoke-virtual/range {v0 .. v9}, Lg4/a;->a(IILandroid/text/TextUtils$TruncateAt;IIIIILjava/lang/CharSequence;)Lh4/j;

    .line 402
    .line 403
    .line 404
    move-result-object v14

    .line 405
    :goto_13
    iget v9, v14, Lh4/j;->g:I

    .line 406
    .line 407
    if-ne v11, v10, :cond_25

    .line 408
    .line 409
    invoke-virtual {v14}, Lh4/j;->a()I

    .line 410
    .line 411
    .line 412
    move-result v11

    .line 413
    move/from16 v16, v10

    .line 414
    .line 415
    invoke-static {v12, v13}, Lt4/a;->g(J)I

    .line 416
    .line 417
    .line 418
    move-result v10

    .line 419
    if-le v11, v10, :cond_26

    .line 420
    .line 421
    const/4 v10, 0x1

    .line 422
    if-le v4, v10, :cond_26

    .line 423
    .line 424
    invoke-static {v12, v13}, Lt4/a;->g(J)I

    .line 425
    .line 426
    .line 427
    move-result v4

    .line 428
    const/4 v10, 0x0

    .line 429
    :goto_14
    if-ge v10, v9, :cond_22

    .line 430
    .line 431
    invoke-virtual {v14, v10}, Lh4/j;->e(I)F

    .line 432
    .line 433
    .line 434
    move-result v11

    .line 435
    int-to-float v12, v4

    .line 436
    cmpl-float v11, v11, v12

    .line 437
    .line 438
    if-lez v11, :cond_21

    .line 439
    .line 440
    goto :goto_15

    .line 441
    :cond_21
    add-int/lit8 v10, v10, 0x1

    .line 442
    .line 443
    goto :goto_14

    .line 444
    :cond_22
    move v10, v9

    .line 445
    :goto_15
    if-ltz v10, :cond_24

    .line 446
    .line 447
    iget v4, v0, Lg4/a;->b:I

    .line 448
    .line 449
    if-eq v10, v4, :cond_24

    .line 450
    .line 451
    const/4 v4, 0x1

    .line 452
    if-ge v10, v4, :cond_23

    .line 453
    .line 454
    const/4 v4, 0x1

    .line 455
    goto :goto_16

    .line 456
    :cond_23
    move v4, v10

    .line 457
    :goto_16
    iget-object v9, v0, Lg4/a;->e:Ljava/lang/CharSequence;

    .line 458
    .line 459
    invoke-virtual/range {v0 .. v9}, Lg4/a;->a(IILandroid/text/TextUtils$TruncateAt;IIIIILjava/lang/CharSequence;)Lh4/j;

    .line 460
    .line 461
    .line 462
    move-result-object v14

    .line 463
    :cond_24
    iput-object v14, v0, Lg4/a;->d:Lh4/j;

    .line 464
    .line 465
    goto :goto_17

    .line 466
    :cond_25
    move/from16 v16, v10

    .line 467
    .line 468
    :cond_26
    iput-object v14, v0, Lg4/a;->d:Lh4/j;

    .line 469
    .line 470
    :goto_17
    iget-object v1, v0, Lg4/a;->a:Lo4/c;

    .line 471
    .line 472
    iget-object v1, v1, Lo4/c;->j:Lo4/d;

    .line 473
    .line 474
    iget-object v2, v15, Lg4/g0;->a:Lr4/o;

    .line 475
    .line 476
    invoke-interface {v2}, Lr4/o;->c()Le3/p;

    .line 477
    .line 478
    .line 479
    move-result-object v2

    .line 480
    invoke-virtual {v0}, Lg4/a;->d()F

    .line 481
    .line 482
    .line 483
    move-result v3

    .line 484
    invoke-virtual {v0}, Lg4/a;->b()F

    .line 485
    .line 486
    .line 487
    move-result v4

    .line 488
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 489
    .line 490
    .line 491
    move-result v3

    .line 492
    int-to-long v5, v3

    .line 493
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 494
    .line 495
    .line 496
    move-result v3

    .line 497
    int-to-long v3, v3

    .line 498
    shl-long v5, v5, v18

    .line 499
    .line 500
    const-wide v7, 0xffffffffL

    .line 501
    .line 502
    .line 503
    .line 504
    .line 505
    and-long/2addr v3, v7

    .line 506
    or-long/2addr v3, v5

    .line 507
    iget-object v5, v15, Lg4/g0;->a:Lr4/o;

    .line 508
    .line 509
    invoke-interface {v5}, Lr4/o;->b()F

    .line 510
    .line 511
    .line 512
    move-result v5

    .line 513
    invoke-virtual {v1, v2, v3, v4, v5}, Lo4/d;->c(Le3/p;JF)V

    .line 514
    .line 515
    .line 516
    iget-object v1, v0, Lg4/a;->d:Lh4/j;

    .line 517
    .line 518
    iget-object v1, v1, Lh4/j;->f:Landroid/text/Layout;

    .line 519
    .line 520
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 521
    .line 522
    .line 523
    move-result-object v2

    .line 524
    instance-of v2, v2, Landroid/text/Spanned;

    .line 525
    .line 526
    if-nez v2, :cond_28

    .line 527
    .line 528
    :cond_27
    const/4 v1, 0x0

    .line 529
    goto :goto_18

    .line 530
    :cond_28
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 531
    .line 532
    .line 533
    move-result-object v2

    .line 534
    const-string v3, "null cannot be cast to non-null type android.text.Spanned"

    .line 535
    .line 536
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 537
    .line 538
    .line 539
    check-cast v2, Landroid/text/Spanned;

    .line 540
    .line 541
    const/4 v4, -0x1

    .line 542
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 543
    .line 544
    .line 545
    move-result v5

    .line 546
    const-class v6, Lq4/b;

    .line 547
    .line 548
    invoke-interface {v2, v4, v5, v6}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 549
    .line 550
    .line 551
    move-result v4

    .line 552
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 553
    .line 554
    .line 555
    move-result v2

    .line 556
    if-eq v4, v2, :cond_27

    .line 557
    .line 558
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 559
    .line 560
    .line 561
    move-result-object v2

    .line 562
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 563
    .line 564
    .line 565
    check-cast v2, Landroid/text/Spanned;

    .line 566
    .line 567
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 568
    .line 569
    .line 570
    move-result-object v1

    .line 571
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 572
    .line 573
    .line 574
    move-result v1

    .line 575
    const/4 v3, 0x0

    .line 576
    invoke-interface {v2, v3, v1, v6}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 577
    .line 578
    .line 579
    move-result-object v1

    .line 580
    check-cast v1, [Lq4/b;

    .line 581
    .line 582
    :goto_18
    if-eqz v1, :cond_29

    .line 583
    .line 584
    invoke-static {v1}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 585
    .line 586
    .line 587
    move-result-object v1

    .line 588
    :goto_19
    invoke-virtual {v1}, Landroidx/collection/d1;->hasNext()Z

    .line 589
    .line 590
    .line 591
    move-result v2

    .line 592
    if-eqz v2, :cond_29

    .line 593
    .line 594
    invoke-virtual {v1}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 595
    .line 596
    .line 597
    move-result-object v2

    .line 598
    check-cast v2, Lq4/b;

    .line 599
    .line 600
    invoke-virtual {v0}, Lg4/a;->d()F

    .line 601
    .line 602
    .line 603
    move-result v3

    .line 604
    invoke-virtual {v0}, Lg4/a;->b()F

    .line 605
    .line 606
    .line 607
    move-result v4

    .line 608
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 609
    .line 610
    .line 611
    move-result v3

    .line 612
    int-to-long v5, v3

    .line 613
    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 614
    .line 615
    .line 616
    move-result v3

    .line 617
    int-to-long v3, v3

    .line 618
    shl-long v5, v5, v18

    .line 619
    .line 620
    and-long/2addr v3, v7

    .line 621
    or-long/2addr v3, v5

    .line 622
    iget-object v2, v2, Lq4/b;->f:Ll2/j1;

    .line 623
    .line 624
    new-instance v5, Ld3/e;

    .line 625
    .line 626
    invoke-direct {v5, v3, v4}, Ld3/e;-><init>(J)V

    .line 627
    .line 628
    .line 629
    invoke-virtual {v2, v5}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 630
    .line 631
    .line 632
    goto :goto_19

    .line 633
    :cond_29
    iget-object v1, v0, Lg4/a;->e:Ljava/lang/CharSequence;

    .line 634
    .line 635
    instance-of v2, v1, Landroid/text/Spanned;

    .line 636
    .line 637
    if-nez v2, :cond_2a

    .line 638
    .line 639
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 640
    .line 641
    goto/16 :goto_26

    .line 642
    .line 643
    :cond_2a
    move-object v2, v1

    .line 644
    check-cast v2, Landroid/text/Spanned;

    .line 645
    .line 646
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 647
    .line 648
    .line 649
    move-result v1

    .line 650
    const-class v3, Lj4/i;

    .line 651
    .line 652
    const/4 v4, 0x0

    .line 653
    invoke-interface {v2, v4, v1, v3}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v1

    .line 657
    new-instance v3, Ljava/util/ArrayList;

    .line 658
    .line 659
    array-length v4, v1

    .line 660
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 661
    .line 662
    .line 663
    array-length v4, v1

    .line 664
    const/4 v7, 0x0

    .line 665
    :goto_1a
    if-ge v7, v4, :cond_35

    .line 666
    .line 667
    aget-object v5, v1, v7

    .line 668
    .line 669
    check-cast v5, Lj4/i;

    .line 670
    .line 671
    invoke-interface {v2, v5}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 672
    .line 673
    .line 674
    move-result v6

    .line 675
    invoke-interface {v2, v5}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 676
    .line 677
    .line 678
    move-result v8

    .line 679
    iget-object v9, v0, Lg4/a;->d:Lh4/j;

    .line 680
    .line 681
    iget-object v9, v9, Lh4/j;->f:Landroid/text/Layout;

    .line 682
    .line 683
    invoke-virtual {v9, v6}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 684
    .line 685
    .line 686
    move-result v9

    .line 687
    iget v10, v0, Lg4/a;->b:I

    .line 688
    .line 689
    if-lt v9, v10, :cond_2b

    .line 690
    .line 691
    const/4 v10, 0x1

    .line 692
    goto :goto_1b

    .line 693
    :cond_2b
    const/4 v10, 0x0

    .line 694
    :goto_1b
    iget-object v11, v0, Lg4/a;->d:Lh4/j;

    .line 695
    .line 696
    iget-object v11, v11, Lh4/j;->f:Landroid/text/Layout;

    .line 697
    .line 698
    invoke-virtual {v11, v9}, Landroid/text/Layout;->getEllipsisCount(I)I

    .line 699
    .line 700
    .line 701
    move-result v11

    .line 702
    if-lez v11, :cond_2c

    .line 703
    .line 704
    iget-object v11, v0, Lg4/a;->d:Lh4/j;

    .line 705
    .line 706
    iget-object v11, v11, Lh4/j;->f:Landroid/text/Layout;

    .line 707
    .line 708
    invoke-virtual {v11, v9}, Landroid/text/Layout;->getLineStart(I)I

    .line 709
    .line 710
    .line 711
    move-result v11

    .line 712
    iget-object v12, v0, Lg4/a;->d:Lh4/j;

    .line 713
    .line 714
    iget-object v12, v12, Lh4/j;->f:Landroid/text/Layout;

    .line 715
    .line 716
    invoke-virtual {v12, v9}, Landroid/text/Layout;->getEllipsisStart(I)I

    .line 717
    .line 718
    .line 719
    move-result v12

    .line 720
    add-int/2addr v12, v11

    .line 721
    if-le v8, v12, :cond_2c

    .line 722
    .line 723
    const/4 v11, 0x1

    .line 724
    goto :goto_1c

    .line 725
    :cond_2c
    const/4 v11, 0x0

    .line 726
    :goto_1c
    iget-object v12, v0, Lg4/a;->d:Lh4/j;

    .line 727
    .line 728
    invoke-virtual {v12, v9}, Lh4/j;->f(I)I

    .line 729
    .line 730
    .line 731
    move-result v12

    .line 732
    if-le v8, v12, :cond_2d

    .line 733
    .line 734
    const/4 v8, 0x1

    .line 735
    goto :goto_1d

    .line 736
    :cond_2d
    const/4 v8, 0x0

    .line 737
    :goto_1d
    if-nez v11, :cond_2e

    .line 738
    .line 739
    if-nez v8, :cond_2e

    .line 740
    .line 741
    if-eqz v10, :cond_2f

    .line 742
    .line 743
    :cond_2e
    move/from16 v12, v16

    .line 744
    .line 745
    const/4 v11, 0x0

    .line 746
    const/4 v14, 0x1

    .line 747
    goto/16 :goto_24

    .line 748
    .line 749
    :cond_2f
    iget-object v8, v0, Lg4/a;->d:Lh4/j;

    .line 750
    .line 751
    iget-object v8, v8, Lh4/j;->f:Landroid/text/Layout;

    .line 752
    .line 753
    invoke-virtual {v8, v6}, Landroid/text/Layout;->isRtlCharAt(I)Z

    .line 754
    .line 755
    .line 756
    move-result v8

    .line 757
    if-eqz v8, :cond_30

    .line 758
    .line 759
    sget-object v8, Lr4/j;->e:Lr4/j;

    .line 760
    .line 761
    goto :goto_1e

    .line 762
    :cond_30
    sget-object v8, Lr4/j;->d:Lr4/j;

    .line 763
    .line 764
    :goto_1e
    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    .line 765
    .line 766
    .line 767
    move-result v8

    .line 768
    const-string v10, "PlaceholderSpan is not laid out yet."

    .line 769
    .line 770
    if-eqz v8, :cond_33

    .line 771
    .line 772
    const/4 v14, 0x1

    .line 773
    if-ne v8, v14, :cond_32

    .line 774
    .line 775
    iget-object v8, v0, Lg4/a;->d:Lh4/j;

    .line 776
    .line 777
    const/4 v11, 0x0

    .line 778
    invoke-virtual {v8, v6, v11}, Lh4/j;->h(IZ)F

    .line 779
    .line 780
    .line 781
    move-result v6

    .line 782
    iget-boolean v8, v5, Lj4/i;->m:Z

    .line 783
    .line 784
    if-nez v8, :cond_31

    .line 785
    .line 786
    invoke-static {v10}, Lm4/a;->c(Ljava/lang/String;)V

    .line 787
    .line 788
    .line 789
    :cond_31
    iget v8, v5, Lj4/i;->k:I

    .line 790
    .line 791
    int-to-float v8, v8

    .line 792
    sub-float/2addr v6, v8

    .line 793
    const/4 v11, 0x0

    .line 794
    goto :goto_1f

    .line 795
    :cond_32
    new-instance v0, La8/r0;

    .line 796
    .line 797
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 798
    .line 799
    .line 800
    throw v0

    .line 801
    :cond_33
    const/4 v14, 0x1

    .line 802
    iget-object v8, v0, Lg4/a;->d:Lh4/j;

    .line 803
    .line 804
    const/4 v11, 0x0

    .line 805
    invoke-virtual {v8, v6, v11}, Lh4/j;->h(IZ)F

    .line 806
    .line 807
    .line 808
    move-result v6

    .line 809
    :goto_1f
    iget-boolean v8, v5, Lj4/i;->m:Z

    .line 810
    .line 811
    if-nez v8, :cond_34

    .line 812
    .line 813
    invoke-static {v10}, Lm4/a;->c(Ljava/lang/String;)V

    .line 814
    .line 815
    .line 816
    :cond_34
    iget v8, v5, Lj4/i;->k:I

    .line 817
    .line 818
    int-to-float v8, v8

    .line 819
    add-float/2addr v8, v6

    .line 820
    iget-object v10, v0, Lg4/a;->d:Lh4/j;

    .line 821
    .line 822
    iget v12, v5, Lj4/i;->i:I

    .line 823
    .line 824
    packed-switch v12, :pswitch_data_0

    .line 825
    .line 826
    .line 827
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 828
    .line 829
    const-string v1, "unexpected verticalAlignment"

    .line 830
    .line 831
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 832
    .line 833
    .line 834
    throw v0

    .line 835
    :pswitch_0
    invoke-virtual {v5}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 836
    .line 837
    .line 838
    move-result-object v12

    .line 839
    iget v13, v12, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 840
    .line 841
    iget v12, v12, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 842
    .line 843
    add-int/2addr v13, v12

    .line 844
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 845
    .line 846
    .line 847
    move-result v12

    .line 848
    sub-int/2addr v13, v12

    .line 849
    div-int/lit8 v13, v13, 0x2

    .line 850
    .line 851
    int-to-float v12, v13

    .line 852
    invoke-virtual {v10, v9}, Lh4/j;->d(I)F

    .line 853
    .line 854
    .line 855
    move-result v9

    .line 856
    :goto_20
    add-float/2addr v9, v12

    .line 857
    :goto_21
    move/from16 v12, v16

    .line 858
    .line 859
    goto :goto_23

    .line 860
    :pswitch_1
    invoke-virtual {v5}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 861
    .line 862
    .line 863
    move-result-object v12

    .line 864
    iget v12, v12, Landroid/graphics/Paint$FontMetricsInt;->descent:I

    .line 865
    .line 866
    int-to-float v12, v12

    .line 867
    invoke-virtual {v10, v9}, Lh4/j;->d(I)F

    .line 868
    .line 869
    .line 870
    move-result v9

    .line 871
    add-float/2addr v9, v12

    .line 872
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 873
    .line 874
    .line 875
    move-result v10

    .line 876
    int-to-float v10, v10

    .line 877
    sub-float/2addr v9, v10

    .line 878
    goto :goto_21

    .line 879
    :pswitch_2
    invoke-virtual {v5}, Lj4/i;->a()Landroid/graphics/Paint$FontMetricsInt;

    .line 880
    .line 881
    .line 882
    move-result-object v12

    .line 883
    iget v12, v12, Landroid/graphics/Paint$FontMetricsInt;->ascent:I

    .line 884
    .line 885
    int-to-float v12, v12

    .line 886
    invoke-virtual {v10, v9}, Lh4/j;->d(I)F

    .line 887
    .line 888
    .line 889
    move-result v9

    .line 890
    goto :goto_20

    .line 891
    :pswitch_3
    invoke-virtual {v10, v9}, Lh4/j;->g(I)F

    .line 892
    .line 893
    .line 894
    move-result v12

    .line 895
    invoke-virtual {v10, v9}, Lh4/j;->e(I)F

    .line 896
    .line 897
    .line 898
    move-result v9

    .line 899
    add-float/2addr v9, v12

    .line 900
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 901
    .line 902
    .line 903
    move-result v10

    .line 904
    int-to-float v10, v10

    .line 905
    sub-float/2addr v9, v10

    .line 906
    move/from16 v12, v16

    .line 907
    .line 908
    int-to-float v10, v12

    .line 909
    div-float/2addr v9, v10

    .line 910
    goto :goto_23

    .line 911
    :pswitch_4
    move/from16 v12, v16

    .line 912
    .line 913
    invoke-virtual {v10, v9}, Lh4/j;->e(I)F

    .line 914
    .line 915
    .line 916
    move-result v9

    .line 917
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 918
    .line 919
    .line 920
    move-result v10

    .line 921
    :goto_22
    int-to-float v10, v10

    .line 922
    sub-float/2addr v9, v10

    .line 923
    goto :goto_23

    .line 924
    :pswitch_5
    move/from16 v12, v16

    .line 925
    .line 926
    invoke-virtual {v10, v9}, Lh4/j;->g(I)F

    .line 927
    .line 928
    .line 929
    move-result v9

    .line 930
    goto :goto_23

    .line 931
    :pswitch_6
    move/from16 v12, v16

    .line 932
    .line 933
    invoke-virtual {v10, v9}, Lh4/j;->d(I)F

    .line 934
    .line 935
    .line 936
    move-result v9

    .line 937
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 938
    .line 939
    .line 940
    move-result v10

    .line 941
    goto :goto_22

    .line 942
    :goto_23
    invoke-virtual {v5}, Lj4/i;->b()I

    .line 943
    .line 944
    .line 945
    move-result v5

    .line 946
    int-to-float v5, v5

    .line 947
    add-float/2addr v5, v9

    .line 948
    new-instance v10, Ld3/c;

    .line 949
    .line 950
    invoke-direct {v10, v6, v9, v8, v5}, Ld3/c;-><init>(FFFF)V

    .line 951
    .line 952
    .line 953
    goto :goto_25

    .line 954
    :goto_24
    const/4 v10, 0x0

    .line 955
    :goto_25
    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 956
    .line 957
    .line 958
    add-int/lit8 v7, v7, 0x1

    .line 959
    .line 960
    move/from16 v16, v12

    .line 961
    .line 962
    goto/16 :goto_1a

    .line 963
    .line 964
    :cond_35
    move-object v1, v3

    .line 965
    :goto_26
    iput-object v1, v0, Lg4/a;->f:Ljava/lang/Object;

    .line 966
    .line 967
    return-void

    .line 968
    nop

    .line 969
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(IILandroid/text/TextUtils$TruncateAt;IIIIILjava/lang/CharSequence;)Lh4/j;
    .locals 15

    .line 1
    invoke-virtual {p0}, Lg4/a;->d()F

    .line 2
    .line 3
    .line 4
    move-result v2

    .line 5
    iget-object p0, p0, Lg4/a;->a:Lo4/c;

    .line 6
    .line 7
    iget-object v3, p0, Lo4/c;->j:Lo4/d;

    .line 8
    .line 9
    iget v6, p0, Lo4/c;->o:I

    .line 10
    .line 11
    iget-object v14, p0, Lo4/c;->l:Lh4/f;

    .line 12
    .line 13
    iget-object p0, p0, Lo4/c;->e:Lg4/p0;

    .line 14
    .line 15
    sget-object v0, Lo4/b;->a:Lo4/a;

    .line 16
    .line 17
    iget-object p0, p0, Lg4/p0;->c:Lg4/y;

    .line 18
    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    iget-object p0, p0, Lg4/y;->b:Lg4/w;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    iget-boolean p0, p0, Lg4/w;->a:Z

    .line 26
    .line 27
    :goto_0
    move v7, p0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    goto :goto_0

    .line 31
    :goto_1
    new-instance v0, Lh4/j;

    .line 32
    .line 33
    move/from16 v4, p1

    .line 34
    .line 35
    move/from16 v13, p2

    .line 36
    .line 37
    move-object/from16 v5, p3

    .line 38
    .line 39
    move/from16 v8, p4

    .line 40
    .line 41
    move/from16 v12, p5

    .line 42
    .line 43
    move/from16 v9, p6

    .line 44
    .line 45
    move/from16 v10, p7

    .line 46
    .line 47
    move/from16 v11, p8

    .line 48
    .line 49
    move-object/from16 v1, p9

    .line 50
    .line 51
    invoke-direct/range {v0 .. v14}, Lh4/j;-><init>(Ljava/lang/CharSequence;FLandroid/text/TextPaint;ILandroid/text/TextUtils$TruncateAt;IZIIIIIILh4/f;)V

    .line 52
    .line 53
    .line 54
    return-object v0
.end method

.method public final b()F
    .locals 0

    .line 1
    iget-object p0, p0, Lg4/a;->d:Lh4/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh4/j;->a()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    int-to-float p0, p0

    .line 8
    return p0
.end method

.method public final c(Ld3/c;ILf3/d;)J
    .locals 10

    .line 1
    invoke-static {p1}, Le3/j0;->x(Ld3/c;)Landroid/graphics/RectF;

    .line 2
    .line 3
    .line 4
    move-result-object v4

    .line 5
    const/4 p1, 0x1

    .line 6
    const/4 v8, 0x0

    .line 7
    if-nez p2, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    if-ne p2, p1, :cond_1

    .line 11
    .line 12
    move p2, p1

    .line 13
    goto :goto_1

    .line 14
    :cond_1
    :goto_0
    move p2, v8

    .line 15
    :goto_1
    new-instance v6, La71/a0;

    .line 16
    .line 17
    const/16 v0, 0x19

    .line 18
    .line 19
    invoke-direct {v6, p3, v0}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lg4/a;->d:Lh4/j;

    .line 23
    .line 24
    iget-object p0, v0, Lh4/j;->a:Landroid/text/TextPaint;

    .line 25
    .line 26
    iget-object v1, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 27
    .line 28
    sget p3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 29
    .line 30
    const/16 v2, 0x22

    .line 31
    .line 32
    if-lt p3, v2, :cond_3

    .line 33
    .line 34
    if-ne p2, p1, :cond_2

    .line 35
    .line 36
    new-instance p0, Lb81/b;

    .line 37
    .line 38
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 39
    .line 40
    .line 41
    move-result-object p2

    .line 42
    invoke-virtual {v0}, Lh4/j;->j()Li4/c;

    .line 43
    .line 44
    .line 45
    move-result-object p3

    .line 46
    const/16 v0, 0xa

    .line 47
    .line 48
    invoke-direct {p0, v0, p2, p3}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p2, Li4/a;

    .line 52
    .line 53
    invoke-direct {p2, p0}, Li4/a;-><init>(Lb81/b;)V

    .line 54
    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_2
    invoke-static {}, Lc2/h;->s()V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    invoke-static {p2, p0}, Lc2/h;->k(Ljava/lang/CharSequence;Landroid/text/TextPaint;)Landroid/text/GraphemeClusterSegmentFinder;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-static {p0}, Lc2/h;->l(Ljava/lang/Object;)Landroid/text/SegmentFinder;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    :goto_2
    new-instance p0, Lh4/a;

    .line 73
    .line 74
    invoke-direct {p0, v6}, Lh4/a;-><init>(La71/a0;)V

    .line 75
    .line 76
    .line 77
    invoke-static {v1, v4, p2, p0}, Lc2/h;->z(Landroid/text/Layout;Landroid/graphics/RectF;Landroid/text/SegmentFinder;Lh4/a;)[I

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    goto/16 :goto_7

    .line 82
    .line 83
    :cond_3
    invoke-virtual {v0}, Lh4/j;->c()Landroidx/lifecycle/c1;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    if-ne p2, p1, :cond_4

    .line 88
    .line 89
    new-instance p0, Lb81/b;

    .line 90
    .line 91
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 92
    .line 93
    .line 94
    move-result-object p2

    .line 95
    invoke-virtual {v0}, Lh4/j;->j()Li4/c;

    .line 96
    .line 97
    .line 98
    move-result-object p3

    .line 99
    const/16 v3, 0xa

    .line 100
    .line 101
    invoke-direct {p0, v3, p2, p3}, Lb81/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    move-object v5, p0

    .line 105
    goto :goto_3

    .line 106
    :cond_4
    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    new-instance p3, Lb81/a;

    .line 111
    .line 112
    const/16 v3, 0xa

    .line 113
    .line 114
    invoke-direct {p3, v3, p2, p0}, Lb81/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    move-object v5, p3

    .line 118
    :goto_3
    iget p0, v4, Landroid/graphics/RectF;->top:F

    .line 119
    .line 120
    float-to-int p0, p0

    .line 121
    invoke-virtual {v1, p0}, Landroid/text/Layout;->getLineForVertical(I)I

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    iget p2, v4, Landroid/graphics/RectF;->top:F

    .line 126
    .line 127
    invoke-virtual {v0, p0}, Lh4/j;->e(I)F

    .line 128
    .line 129
    .line 130
    move-result p3

    .line 131
    cmpl-float p2, p2, p3

    .line 132
    .line 133
    if-lez p2, :cond_5

    .line 134
    .line 135
    add-int/lit8 p0, p0, 0x1

    .line 136
    .line 137
    iget p2, v0, Lh4/j;->g:I

    .line 138
    .line 139
    if-lt p0, p2, :cond_5

    .line 140
    .line 141
    goto :goto_6

    .line 142
    :cond_5
    move v3, p0

    .line 143
    iget p0, v4, Landroid/graphics/RectF;->bottom:F

    .line 144
    .line 145
    float-to-int p0, p0

    .line 146
    invoke-virtual {v1, p0}, Landroid/text/Layout;->getLineForVertical(I)I

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    if-nez p0, :cond_6

    .line 151
    .line 152
    iget p2, v4, Landroid/graphics/RectF;->bottom:F

    .line 153
    .line 154
    invoke-virtual {v0, v8}, Lh4/j;->g(I)F

    .line 155
    .line 156
    .line 157
    move-result p3

    .line 158
    cmpg-float p2, p2, p3

    .line 159
    .line 160
    if-gez p2, :cond_6

    .line 161
    .line 162
    goto :goto_6

    .line 163
    :cond_6
    const/4 v7, 0x1

    .line 164
    invoke-static/range {v0 .. v7}, Lh4/g;->e(Lh4/j;Landroid/text/Layout;Landroidx/lifecycle/c1;ILandroid/graphics/RectF;Li4/b;La71/a0;Z)I

    .line 165
    .line 166
    .line 167
    move-result p2

    .line 168
    :goto_4
    move p3, v3

    .line 169
    const/4 v9, -0x1

    .line 170
    if-ne p2, v9, :cond_7

    .line 171
    .line 172
    if-ge p3, p0, :cond_7

    .line 173
    .line 174
    add-int/lit8 v3, p3, 0x1

    .line 175
    .line 176
    const/4 v7, 0x1

    .line 177
    invoke-static/range {v0 .. v7}, Lh4/g;->e(Lh4/j;Landroid/text/Layout;Landroidx/lifecycle/c1;ILandroid/graphics/RectF;Li4/b;La71/a0;Z)I

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    goto :goto_4

    .line 182
    :cond_7
    if-ne p2, v9, :cond_8

    .line 183
    .line 184
    goto :goto_6

    .line 185
    :cond_8
    const/4 v7, 0x0

    .line 186
    move v3, p0

    .line 187
    invoke-static/range {v0 .. v7}, Lh4/g;->e(Lh4/j;Landroid/text/Layout;Landroidx/lifecycle/c1;ILandroid/graphics/RectF;Li4/b;La71/a0;Z)I

    .line 188
    .line 189
    .line 190
    move-result p0

    .line 191
    :goto_5
    if-ne p0, v9, :cond_9

    .line 192
    .line 193
    if-ge p3, v3, :cond_9

    .line 194
    .line 195
    add-int/lit8 v3, v3, -0x1

    .line 196
    .line 197
    const/4 v7, 0x0

    .line 198
    invoke-static/range {v0 .. v7}, Lh4/g;->e(Lh4/j;Landroid/text/Layout;Landroidx/lifecycle/c1;ILandroid/graphics/RectF;Li4/b;La71/a0;Z)I

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    goto :goto_5

    .line 203
    :cond_9
    if-ne p0, v9, :cond_a

    .line 204
    .line 205
    :goto_6
    const/4 p0, 0x0

    .line 206
    goto :goto_7

    .line 207
    :cond_a
    add-int/2addr p2, p1

    .line 208
    invoke-interface {v5, p2}, Li4/b;->e(I)I

    .line 209
    .line 210
    .line 211
    move-result p2

    .line 212
    sub-int/2addr p0, p1

    .line 213
    invoke-interface {v5, p0}, Li4/b;->f(I)I

    .line 214
    .line 215
    .line 216
    move-result p0

    .line 217
    filled-new-array {p2, p0}, [I

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    :goto_7
    if-nez p0, :cond_b

    .line 222
    .line 223
    sget-wide p0, Lg4/o0;->b:J

    .line 224
    .line 225
    return-wide p0

    .line 226
    :cond_b
    aget p2, p0, v8

    .line 227
    .line 228
    aget p0, p0, p1

    .line 229
    .line 230
    invoke-static {p2, p0}, Lg4/f0;->b(II)J

    .line 231
    .line 232
    .line 233
    move-result-wide p0

    .line 234
    return-wide p0
.end method

.method public final d()F
    .locals 2

    .line 1
    iget-wide v0, p0, Lg4/a;->c:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lt4/a;->h(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    int-to-float p0, p0

    .line 8
    return p0
.end method

.method public final e(Le3/r;)V
    .locals 4

    .line 1
    invoke-static {p1}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    iget-object v0, p0, Lg4/a;->d:Lh4/j;

    .line 6
    .line 7
    iget-boolean v1, v0, Lh4/j;->d:Z

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    if-eqz v1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lg4/a;->d()F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {p0}, Lg4/a;->b()F

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-virtual {p1, v2, v2, v1, p0}, Landroid/graphics/Canvas;->clipRect(FFFF)Z

    .line 24
    .line 25
    .line 26
    :cond_0
    iget p0, v0, Lh4/j;->h:I

    .line 27
    .line 28
    iget-object v1, v0, Lh4/j;->p:Landroid/graphics/Rect;

    .line 29
    .line 30
    invoke-virtual {p1, v1}, Landroid/graphics/Canvas;->getClipBounds(Landroid/graphics/Rect;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-nez v1, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    if-eqz p0, :cond_2

    .line 38
    .line 39
    int-to-float v1, p0

    .line 40
    invoke-virtual {p1, v2, v1}, Landroid/graphics/Canvas;->translate(FF)V

    .line 41
    .line 42
    .line 43
    :cond_2
    sget-object v1, Lh4/k;->a:Lh4/i;

    .line 44
    .line 45
    iput-object p1, v1, Lh4/i;->a:Landroid/graphics/Canvas;

    .line 46
    .line 47
    iget-object v3, v0, Lh4/j;->f:Landroid/text/Layout;

    .line 48
    .line 49
    invoke-virtual {v3, v1}, Landroid/text/Layout;->draw(Landroid/graphics/Canvas;)V

    .line 50
    .line 51
    .line 52
    if-eqz p0, :cond_3

    .line 53
    .line 54
    const/4 v1, -0x1

    .line 55
    int-to-float v1, v1

    .line 56
    int-to-float p0, p0

    .line 57
    mul-float/2addr v1, p0

    .line 58
    invoke-virtual {p1, v2, v1}, Landroid/graphics/Canvas;->translate(FF)V

    .line 59
    .line 60
    .line 61
    :cond_3
    :goto_0
    iget-boolean p0, v0, Lh4/j;->d:Z

    .line 62
    .line 63
    if-eqz p0, :cond_4

    .line 64
    .line 65
    invoke-virtual {p1}, Landroid/graphics/Canvas;->restore()V

    .line 66
    .line 67
    .line 68
    :cond_4
    return-void
.end method

.method public final f(Le3/r;JLe3/m0;Lr4/l;Lg3/e;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lg4/a;->a:Lo4/c;

    .line 2
    .line 3
    iget-object v0, v0, Lo4/c;->j:Lo4/d;

    .line 4
    .line 5
    iget v1, v0, Lo4/d;->c:I

    .line 6
    .line 7
    invoke-virtual {v0, p2, p3}, Lo4/d;->d(J)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0, p4}, Lo4/d;->f(Le3/m0;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p5}, Lo4/d;->g(Lr4/l;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0, p6}, Lo4/d;->e(Lg3/e;)V

    .line 17
    .line 18
    .line 19
    const/4 p2, 0x3

    .line 20
    invoke-virtual {v0, p2}, Lo4/d;->b(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lg4/a;->e(Le3/r;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, v1}, Lo4/d;->b(I)V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public final g(Le3/r;Le3/p;FLe3/m0;Lr4/l;Lg3/e;)V
    .locals 8

    .line 1
    iget-object v0, p0, Lg4/a;->a:Lo4/c;

    .line 2
    .line 3
    iget-object v0, v0, Lo4/c;->j:Lo4/d;

    .line 4
    .line 5
    iget v1, v0, Lo4/d;->c:I

    .line 6
    .line 7
    invoke-virtual {p0}, Lg4/a;->d()F

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    invoke-virtual {p0}, Lg4/a;->b()F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    int-to-long v4, v2

    .line 20
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    int-to-long v2, v2

    .line 25
    const/16 v6, 0x20

    .line 26
    .line 27
    shl-long/2addr v4, v6

    .line 28
    const-wide v6, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v2, v6

    .line 34
    or-long/2addr v2, v4

    .line 35
    invoke-virtual {v0, p2, v2, v3, p3}, Lo4/d;->c(Le3/p;JF)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0, p4}, Lo4/d;->f(Le3/m0;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, p5}, Lo4/d;->g(Lr4/l;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, p6}, Lo4/d;->e(Lg3/e;)V

    .line 45
    .line 46
    .line 47
    const/4 p2, 0x3

    .line 48
    invoke-virtual {v0, p2}, Lo4/d;->b(I)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p1}, Lg4/a;->e(Le3/r;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v1}, Lo4/d;->b(I)V

    .line 55
    .line 56
    .line 57
    return-void
.end method
