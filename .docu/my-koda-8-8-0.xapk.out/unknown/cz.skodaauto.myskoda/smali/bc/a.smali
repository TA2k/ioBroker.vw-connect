.class public final Lbc/a;
.super Low/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Lqw/a;


# direct methods
.method public constructor <init>(Lqw/e;Low/c;La2/e;FLqw/a;)V
    .locals 1

    .line 1
    sget-object v0, Low/a;->d:Low/a;

    .line 2
    .line 3
    const-string v0, "valueFormatter"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Low/b;-><init>(Lqw/e;Low/c;La2/e;F)V

    .line 9
    .line 10
    .line 11
    iput-object p5, p0, Lbc/a;->g:Lqw/a;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final c(Lc1/h2;Ljava/util/List;)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lc1/h2;->c:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v9, v2

    .line 8
    check-cast v9, Landroid/graphics/RectF;

    .line 9
    .line 10
    iget-object v2, v1, Lc1/h2;->b:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v10, v2

    .line 13
    check-cast v10, Lkw/g;

    .line 14
    .line 15
    invoke-static/range {p2 .. p2}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Low/e;

    .line 20
    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 25
    .line 26
    .line 27
    move-result-object v7

    .line 28
    iget-object v3, v0, Lbc/a;->g:Lqw/a;

    .line 29
    .line 30
    if-eqz v3, :cond_3

    .line 31
    .line 32
    move-object v4, v7

    .line 33
    check-cast v4, Ljava/lang/Iterable;

    .line 34
    .line 35
    new-instance v5, Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    :cond_1
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v6

    .line 48
    if-eqz v6, :cond_2

    .line 49
    .line 50
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v6

    .line 54
    instance-of v8, v6, Low/e;

    .line 55
    .line 56
    if-eqz v8, :cond_1

    .line 57
    .line 58
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_2
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v4

    .line 66
    check-cast v4, Low/e;

    .line 67
    .line 68
    if-eqz v4, :cond_3

    .line 69
    .line 70
    iget-object v5, v4, Low/e;->c:Ljava/util/List;

    .line 71
    .line 72
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    check-cast v5, Low/d;

    .line 77
    .line 78
    if-eqz v5, :cond_3

    .line 79
    .line 80
    iget v5, v5, Low/d;->b:F

    .line 81
    .line 82
    iget v6, v9, Landroid/graphics/RectF;->bottom:F

    .line 83
    .line 84
    iget v4, v4, Low/e;->b:F

    .line 85
    .line 86
    invoke-static {v3, v1, v5, v6, v4}, Lqw/a;->c(Lqw/a;Lc1/h2;FFF)V

    .line 87
    .line 88
    .line 89
    :cond_3
    iget v3, v0, Low/b;->d:F

    .line 90
    .line 91
    const/high16 v4, 0x40000000    # 2.0f

    .line 92
    .line 93
    div-float/2addr v3, v4

    .line 94
    invoke-interface {v10}, Lpw/f;->a()F

    .line 95
    .line 96
    .line 97
    move-result v4

    .line 98
    mul-float/2addr v4, v3

    .line 99
    instance-of v3, v2, Low/e;

    .line 100
    .line 101
    if-eqz v3, :cond_5

    .line 102
    .line 103
    iget-object v3, v2, Low/e;->c:Ljava/util/List;

    .line 104
    .line 105
    invoke-static {v3}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    check-cast v3, Low/d;

    .line 110
    .line 111
    if-eqz v3, :cond_5

    .line 112
    .line 113
    iget v2, v2, Low/e;->b:F

    .line 114
    .line 115
    iget v5, v3, Low/d;->b:F

    .line 116
    .line 117
    iget v3, v3, Low/d;->c:I

    .line 118
    .line 119
    invoke-interface {v10}, Lpw/f;->i()Lc2/k;

    .line 120
    .line 121
    .line 122
    move-result-object v6

    .line 123
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 124
    .line 125
    .line 126
    move-result-object v3

    .line 127
    iget-object v8, v0, Low/b;->c:La2/e;

    .line 128
    .line 129
    filled-new-array {v8, v3}, [Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v3

    .line 133
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 134
    .line 135
    .line 136
    array-length v11, v3

    .line 137
    invoke-static {v3, v11}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v11

    .line 141
    sget-object v12, Low/b;->f:Lfv/b;

    .line 142
    .line 143
    invoke-virtual {v6, v12, v11}, Lc2/k;->w(Lfv/b;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v11

    .line 147
    if-nez v11, :cond_4

    .line 148
    .line 149
    iget-object v8, v8, La2/e;->e:Ljava/lang/Object;

    .line 150
    .line 151
    move-object v11, v8

    .line 152
    check-cast v11, Lqw/b;

    .line 153
    .line 154
    array-length v8, v3

    .line 155
    invoke-static {v3, v8}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    invoke-virtual {v6, v12, v3, v11}, Lc2/k;->A(Lfv/b;[Ljava/lang/Object;Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    :cond_4
    check-cast v11, Lqw/b;

    .line 163
    .line 164
    sub-float v3, v2, v4

    .line 165
    .line 166
    move v6, v4

    .line 167
    sub-float v4, v5, v6

    .line 168
    .line 169
    add-float/2addr v2, v6

    .line 170
    add-float/2addr v6, v5

    .line 171
    move v5, v2

    .line 172
    move-object v2, v1

    .line 173
    move-object v1, v11

    .line 174
    invoke-virtual/range {v1 .. v6}, Lqw/b;->a(Lc1/h2;FFFF)V

    .line 175
    .line 176
    .line 177
    :cond_5
    sget-object v1, Low/a;->d:Low/a;

    .line 178
    .line 179
    iget-object v1, v0, Low/b;->b:Low/c;

    .line 180
    .line 181
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 182
    .line 183
    .line 184
    new-instance v2, Landroid/text/SpannableStringBuilder;

    .line 185
    .line 186
    invoke-direct {v2}, Landroid/text/SpannableStringBuilder;-><init>()V

    .line 187
    .line 188
    .line 189
    move-object v11, v7

    .line 190
    check-cast v11, Ljava/lang/Iterable;

    .line 191
    .line 192
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    const/4 v4, 0x0

    .line 197
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 198
    .line 199
    .line 200
    move-result v5

    .line 201
    const-string v13, "Unexpected `CartesianMarker.Target` implementation."

    .line 202
    .line 203
    if-eqz v5, :cond_d

    .line 204
    .line 205
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v5

    .line 209
    add-int/lit8 v6, v4, 0x1

    .line 210
    .line 211
    if-ltz v4, :cond_c

    .line 212
    .line 213
    check-cast v5, Low/e;

    .line 214
    .line 215
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 216
    .line 217
    .line 218
    const-string v14, "target"

    .line 219
    .line 220
    invoke-static {v5, v14}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    instance-of v14, v5, Low/e;

    .line 224
    .line 225
    if-eqz v14, :cond_b

    .line 226
    .line 227
    iget-object v5, v5, Low/e;->c:Ljava/util/List;

    .line 228
    .line 229
    move-object v13, v5

    .line 230
    check-cast v13, Ljava/lang/Iterable;

    .line 231
    .line 232
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 233
    .line 234
    .line 235
    move-result-object v13

    .line 236
    const/4 v14, 0x0

    .line 237
    :goto_2
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 238
    .line 239
    .line 240
    move-result v15

    .line 241
    const/16 p2, 0x0

    .line 242
    .line 243
    const-string v8, ", "

    .line 244
    .line 245
    if-eqz v15, :cond_9

    .line 246
    .line 247
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v15

    .line 251
    add-int/lit8 v16, v14, 0x1

    .line 252
    .line 253
    if-ltz v14, :cond_8

    .line 254
    .line 255
    check-cast v15, Low/d;

    .line 256
    .line 257
    iget-object v12, v15, Low/d;->a:Lmw/i;

    .line 258
    .line 259
    move-object/from16 v19, v5

    .line 260
    .line 261
    move/from16 v18, v6

    .line 262
    .line 263
    iget-wide v5, v12, Lmw/i;->b:D

    .line 264
    .line 265
    iget v12, v15, Low/d;->c:I

    .line 266
    .line 267
    iget-object v15, v1, Low/c;->a:Ljava/text/DecimalFormat;

    .line 268
    .line 269
    move-object/from16 v20, v3

    .line 270
    .line 271
    iget-boolean v3, v1, Low/c;->b:Z

    .line 272
    .line 273
    if-eqz v3, :cond_6

    .line 274
    .line 275
    invoke-virtual {v15, v5, v6}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v3

    .line 279
    const-string v5, "format(...)"

    .line 280
    .line 281
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    new-instance v5, Landroid/text/style/ForegroundColorSpan;

    .line 285
    .line 286
    invoke-direct {v5, v12}, Landroid/text/style/ForegroundColorSpan;-><init>(I)V

    .line 287
    .line 288
    .line 289
    const/16 v6, 0x21

    .line 290
    .line 291
    invoke-virtual {v2, v3, v5, v6}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;Ljava/lang/Object;I)Landroid/text/SpannableStringBuilder;

    .line 292
    .line 293
    .line 294
    move-result-object v3

    .line 295
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto :goto_3

    .line 299
    :cond_6
    invoke-virtual {v15, v5, v6}, Ljava/text/NumberFormat;->format(D)Ljava/lang/String;

    .line 300
    .line 301
    .line 302
    move-result-object v3

    .line 303
    invoke-virtual {v2, v3}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 304
    .line 305
    .line 306
    :goto_3
    invoke-static/range {v19 .. v19}, Ljp/k1;->h(Ljava/util/List;)I

    .line 307
    .line 308
    .line 309
    move-result v3

    .line 310
    if-eq v14, v3, :cond_7

    .line 311
    .line 312
    invoke-virtual {v2, v8}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 313
    .line 314
    .line 315
    :cond_7
    move/from16 v14, v16

    .line 316
    .line 317
    move/from16 v6, v18

    .line 318
    .line 319
    move-object/from16 v5, v19

    .line 320
    .line 321
    move-object/from16 v3, v20

    .line 322
    .line 323
    goto :goto_2

    .line 324
    :cond_8
    invoke-static {}, Ljp/k1;->r()V

    .line 325
    .line 326
    .line 327
    throw p2

    .line 328
    :cond_9
    move-object/from16 v20, v3

    .line 329
    .line 330
    move/from16 v18, v6

    .line 331
    .line 332
    invoke-static {v7}, Ljp/k1;->h(Ljava/util/List;)I

    .line 333
    .line 334
    .line 335
    move-result v3

    .line 336
    if-eq v4, v3, :cond_a

    .line 337
    .line 338
    invoke-virtual {v2, v8}, Landroid/text/SpannableStringBuilder;->append(Ljava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 339
    .line 340
    .line 341
    :cond_a
    move/from16 v4, v18

    .line 342
    .line 343
    move-object/from16 v3, v20

    .line 344
    .line 345
    goto/16 :goto_1

    .line 346
    .line 347
    :cond_b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 348
    .line 349
    invoke-direct {v0, v13}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 350
    .line 351
    .line 352
    throw v0

    .line 353
    :cond_c
    const/16 p2, 0x0

    .line 354
    .line 355
    invoke-static {}, Ljp/k1;->r()V

    .line 356
    .line 357
    .line 358
    throw p2

    .line 359
    :cond_d
    check-cast v7, Ljava/util/Collection;

    .line 360
    .line 361
    move-object v1, v7

    .line 362
    check-cast v1, Ljava/lang/Iterable;

    .line 363
    .line 364
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 365
    .line 366
    .line 367
    move-result-object v1

    .line 368
    const/4 v12, 0x0

    .line 369
    move v3, v12

    .line 370
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 371
    .line 372
    .line 373
    move-result v4

    .line 374
    if-eqz v4, :cond_e

    .line 375
    .line 376
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v4

    .line 380
    check-cast v4, Low/e;

    .line 381
    .line 382
    const-string v5, "it"

    .line 383
    .line 384
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 385
    .line 386
    .line 387
    iget v4, v4, Low/e;->b:F

    .line 388
    .line 389
    add-float/2addr v3, v4

    .line 390
    goto :goto_4

    .line 391
    :cond_e
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 392
    .line 393
    .line 394
    move-result v1

    .line 395
    int-to-float v1, v1

    .line 396
    div-float v14, v3, v1

    .line 397
    .line 398
    invoke-virtual {v9}, Landroid/graphics/RectF;->width()F

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    float-to-int v3, v1

    .line 403
    const/4 v7, 0x0

    .line 404
    const/16 v8, 0xe8

    .line 405
    .line 406
    iget-object v1, v0, Low/b;->a:Lqw/e;

    .line 407
    .line 408
    const/4 v4, 0x0

    .line 409
    iget-object v5, v0, Low/b;->e:Landroid/graphics/RectF;

    .line 410
    .line 411
    const/4 v6, 0x0

    .line 412
    move-object v0, v1

    .line 413
    move-object/from16 v1, p1

    .line 414
    .line 415
    invoke-static/range {v0 .. v8}, Lqw/e;->b(Lqw/e;Lpw/f;Ljava/lang/CharSequence;IILandroid/graphics/RectF;FZI)Landroid/graphics/RectF;

    .line 416
    .line 417
    .line 418
    move-result-object v3

    .line 419
    invoke-virtual {v3}, Landroid/graphics/RectF;->width()F

    .line 420
    .line 421
    .line 422
    move-result v1

    .line 423
    const/4 v4, 0x2

    .line 424
    int-to-float v4, v4

    .line 425
    div-float/2addr v1, v4

    .line 426
    sub-float v5, v14, v1

    .line 427
    .line 428
    iget v6, v9, Landroid/graphics/RectF;->left:F

    .line 429
    .line 430
    cmpg-float v5, v5, v6

    .line 431
    .line 432
    if-gez v5, :cond_f

    .line 433
    .line 434
    add-float v14, v6, v1

    .line 435
    .line 436
    goto :goto_5

    .line 437
    :cond_f
    add-float v5, v14, v1

    .line 438
    .line 439
    iget v6, v9, Landroid/graphics/RectF;->right:F

    .line 440
    .line 441
    cmpl-float v5, v5, v6

    .line 442
    .line 443
    if-lez v5, :cond_10

    .line 444
    .line 445
    sub-float v14, v6, v1

    .line 446
    .line 447
    :cond_10
    :goto_5
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 448
    .line 449
    .line 450
    move-result-object v1

    .line 451
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 452
    .line 453
    .line 454
    move-result v5

    .line 455
    if-eqz v5, :cond_1c

    .line 456
    .line 457
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 458
    .line 459
    .line 460
    move-result-object v5

    .line 461
    check-cast v5, Low/e;

    .line 462
    .line 463
    instance-of v6, v5, Low/e;

    .line 464
    .line 465
    if-eqz v6, :cond_1b

    .line 466
    .line 467
    iget-object v5, v5, Low/e;->c:Ljava/util/List;

    .line 468
    .line 469
    check-cast v5, Ljava/lang/Iterable;

    .line 470
    .line 471
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 472
    .line 473
    .line 474
    move-result-object v5

    .line 475
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 476
    .line 477
    .line 478
    move-result v6

    .line 479
    if-eqz v6, :cond_1a

    .line 480
    .line 481
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 482
    .line 483
    .line 484
    move-result-object v6

    .line 485
    check-cast v6, Low/d;

    .line 486
    .line 487
    iget v6, v6, Low/d;->b:F

    .line 488
    .line 489
    :goto_6
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 490
    .line 491
    .line 492
    move-result v7

    .line 493
    if-eqz v7, :cond_11

    .line 494
    .line 495
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object v7

    .line 499
    check-cast v7, Low/d;

    .line 500
    .line 501
    iget v7, v7, Low/d;->b:F

    .line 502
    .line 503
    invoke-static {v6, v7}, Ljava/lang/Math;->min(FF)F

    .line 504
    .line 505
    .line 506
    move-result v6

    .line 507
    goto :goto_6

    .line 508
    :cond_11
    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 509
    .line 510
    .line 511
    move-result v5

    .line 512
    if-eqz v5, :cond_15

    .line 513
    .line 514
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    move-result-object v5

    .line 518
    check-cast v5, Low/e;

    .line 519
    .line 520
    instance-of v7, v5, Low/e;

    .line 521
    .line 522
    if-eqz v7, :cond_14

    .line 523
    .line 524
    iget-object v5, v5, Low/e;->c:Ljava/util/List;

    .line 525
    .line 526
    check-cast v5, Ljava/lang/Iterable;

    .line 527
    .line 528
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 529
    .line 530
    .line 531
    move-result-object v5

    .line 532
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 533
    .line 534
    .line 535
    move-result v7

    .line 536
    if-eqz v7, :cond_13

    .line 537
    .line 538
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 539
    .line 540
    .line 541
    move-result-object v7

    .line 542
    check-cast v7, Low/d;

    .line 543
    .line 544
    iget v7, v7, Low/d;->b:F

    .line 545
    .line 546
    :goto_8
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 547
    .line 548
    .line 549
    move-result v8

    .line 550
    if-eqz v8, :cond_12

    .line 551
    .line 552
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    move-result-object v8

    .line 556
    check-cast v8, Low/d;

    .line 557
    .line 558
    iget v8, v8, Low/d;->b:F

    .line 559
    .line 560
    invoke-static {v7, v8}, Ljava/lang/Math;->min(FF)F

    .line 561
    .line 562
    .line 563
    move-result v7

    .line 564
    goto :goto_8

    .line 565
    :cond_12
    invoke-static {v6, v7}, Ljava/lang/Math;->min(FF)F

    .line 566
    .line 567
    .line 568
    move-result v6

    .line 569
    goto :goto_7

    .line 570
    :cond_13
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 571
    .line 572
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 573
    .line 574
    .line 575
    throw v0

    .line 576
    :cond_14
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 577
    .line 578
    invoke-direct {v0, v13}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    throw v0

    .line 582
    :cond_15
    sget-object v1, Low/a;->d:Low/a;

    .line 583
    .line 584
    invoke-virtual {v3}, Landroid/graphics/RectF;->height()F

    .line 585
    .line 586
    .line 587
    move-result v1

    .line 588
    sub-float v1, v6, v1

    .line 589
    .line 590
    invoke-interface {v10, v12}, Lpw/f;->c(F)F

    .line 591
    .line 592
    .line 593
    move-result v3

    .line 594
    sub-float/2addr v1, v3

    .line 595
    iget v3, v9, Landroid/graphics/RectF;->top:F

    .line 596
    .line 597
    cmpg-float v1, v1, v3

    .line 598
    .line 599
    const/4 v3, 0x1

    .line 600
    if-gez v1, :cond_16

    .line 601
    .line 602
    move/from16 v17, v3

    .line 603
    .line 604
    goto :goto_9

    .line 605
    :cond_16
    const/16 v17, 0x0

    .line 606
    .line 607
    :goto_9
    if-eqz v17, :cond_17

    .line 608
    .line 609
    sget-object v1, Ltw/i;->d:[Ltw/i;

    .line 610
    .line 611
    goto :goto_a

    .line 612
    :cond_17
    sget-object v1, Ltw/i;->d:[Ltw/i;

    .line 613
    .line 614
    :goto_a
    if-eqz v17, :cond_18

    .line 615
    .line 616
    goto :goto_b

    .line 617
    :cond_18
    const/4 v3, -0x1

    .line 618
    :goto_b
    int-to-float v1, v3

    .line 619
    invoke-interface {v10, v12}, Lpw/f;->c(F)F

    .line 620
    .line 621
    .line 622
    move-result v3

    .line 623
    mul-float/2addr v3, v1

    .line 624
    add-float/2addr v3, v6

    .line 625
    if-eqz v17, :cond_19

    .line 626
    .line 627
    sget-object v1, Lpw/i;->f:Lpw/i;

    .line 628
    .line 629
    :goto_c
    move-object v6, v1

    .line 630
    goto :goto_d

    .line 631
    :cond_19
    sget-object v1, Lpw/i;->d:Lpw/i;

    .line 632
    .line 633
    goto :goto_c

    .line 634
    :goto_d
    iget v1, v9, Landroid/graphics/RectF;->right:F

    .line 635
    .line 636
    sub-float/2addr v1, v14

    .line 637
    iget v5, v9, Landroid/graphics/RectF;->left:F

    .line 638
    .line 639
    sub-float v5, v14, v5

    .line 640
    .line 641
    invoke-static {v1, v5}, Ljava/lang/Math;->min(FF)F

    .line 642
    .line 643
    .line 644
    move-result v1

    .line 645
    mul-float/2addr v1, v4

    .line 646
    float-to-double v4, v1

    .line 647
    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    .line 648
    .line 649
    .line 650
    move-result-wide v4

    .line 651
    double-to-float v1, v4

    .line 652
    float-to-int v7, v1

    .line 653
    const/4 v9, 0x0

    .line 654
    const/16 v10, 0x190

    .line 655
    .line 656
    const/4 v5, 0x0

    .line 657
    const/4 v8, 0x0

    .line 658
    move-object/from16 v1, p1

    .line 659
    .line 660
    move v4, v3

    .line 661
    move v3, v14

    .line 662
    invoke-static/range {v0 .. v10}, Lqw/e;->a(Lqw/e;Lc1/h2;Ljava/lang/CharSequence;FFLpw/e;Lpw/i;IIFI)V

    .line 663
    .line 664
    .line 665
    return-void

    .line 666
    :cond_1a
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 667
    .line 668
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 669
    .line 670
    .line 671
    throw v0

    .line 672
    :cond_1b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 673
    .line 674
    invoke-direct {v0, v13}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 675
    .line 676
    .line 677
    throw v0

    .line 678
    :cond_1c
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 679
    .line 680
    invoke-direct {v0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 681
    .line 682
    .line 683
    throw v0
.end method
