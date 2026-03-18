.class public abstract Lkp/k6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ID)Ljava/lang/String;
    .locals 2

    .line 1
    invoke-static {}, Ljava/text/NumberFormat;->getInstance()Ljava/text/NumberFormat;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/math/BigDecimal;

    .line 6
    .line 7
    invoke-direct {v1, p1, p2}, Ljava/math/BigDecimal;-><init>(D)V

    .line 8
    .line 9
    .line 10
    sget-object p1, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 11
    .line 12
    invoke-virtual {v1, p0, p1}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    invoke-virtual {v0, p0}, Ljava/text/Format;->format(Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const-string p1, "format(...)"

    .line 21
    .line 22
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-object p0
.end method

.method public static b(D)D
    .locals 1

    .line 1
    new-instance v0, Ljava/math/BigDecimal;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Ljava/math/BigDecimal;-><init>(D)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Ljava/math/RoundingMode;->HALF_UP:Ljava/math/RoundingMode;

    .line 7
    .line 8
    const/4 p1, 0x0

    .line 9
    invoke-virtual {v0, p1, p0}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Ljava/math/BigDecimal;->doubleValue()D

    .line 14
    .line 15
    .line 16
    move-result-wide p0

    .line 17
    return-wide p0
.end method

.method public static final c(Lem/a;Lmm/g;Lmm/n;Lyl/f;Lrx0/c;)Ljava/lang/Object;
    .locals 17

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
    move-object/from16 v3, p4

    .line 8
    .line 9
    instance-of v4, v3, Lem/g;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lem/g;

    .line 15
    .line 16
    iget v5, v4, Lem/g;->m:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lem/g;->m:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lem/g;

    .line 29
    .line 30
    invoke-direct {v4, v3}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lem/g;->l:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lem/g;->m:I

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    if-eqz v6, :cond_2

    .line 41
    .line 42
    if-ne v6, v7, :cond_1

    .line 43
    .line 44
    iget v0, v4, Lem/g;->k:I

    .line 45
    .line 46
    iget v1, v4, Lem/g;->j:I

    .line 47
    .line 48
    iget v2, v4, Lem/g;->i:I

    .line 49
    .line 50
    iget-object v6, v4, Lem/g;->h:Ljava/util/List;

    .line 51
    .line 52
    check-cast v6, Ljava/util/List;

    .line 53
    .line 54
    iget-object v9, v4, Lem/g;->g:Lyl/f;

    .line 55
    .line 56
    iget-object v10, v4, Lem/g;->f:Lmm/n;

    .line 57
    .line 58
    iget-object v11, v4, Lem/g;->e:Lmm/g;

    .line 59
    .line 60
    iget-object v12, v4, Lem/g;->d:Lem/a;

    .line 61
    .line 62
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object/from16 p4, v4

    .line 66
    .line 67
    move v4, v2

    .line 68
    move-object v2, v10

    .line 69
    move-object/from16 v10, p4

    .line 70
    .line 71
    move/from16 p4, v7

    .line 72
    .line 73
    move-object v7, v6

    .line 74
    move v6, v0

    .line 75
    move-object v0, v12

    .line 76
    goto/16 :goto_9

    .line 77
    .line 78
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 79
    .line 80
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 81
    .line 82
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    throw v0

    .line 86
    :cond_2
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    sget-object v3, Lmm/h;->a:Ld8/c;

    .line 90
    .line 91
    invoke-static {v1, v3}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    check-cast v3, Ljava/util/List;

    .line 96
    .line 97
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 98
    .line 99
    .line 100
    move-result v6

    .line 101
    if-eqz v6, :cond_3

    .line 102
    .line 103
    return-object v0

    .line 104
    :cond_3
    iget-object v6, v0, Lem/a;->a:Lyl/j;

    .line 105
    .line 106
    instance-of v9, v6, Lyl/a;

    .line 107
    .line 108
    if-nez v9, :cond_4

    .line 109
    .line 110
    sget-object v10, Lmm/h;->d:Ld8/c;

    .line 111
    .line 112
    invoke-static {v1, v10}, Lyl/m;->d(Lmm/g;Ld8/c;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v10

    .line 116
    check-cast v10, Ljava/lang/Boolean;

    .line 117
    .line 118
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 119
    .line 120
    .line 121
    move-result v10

    .line 122
    if-nez v10, :cond_4

    .line 123
    .line 124
    return-object v0

    .line 125
    :cond_4
    if-eqz v9, :cond_6

    .line 126
    .line 127
    move-object v9, v6

    .line 128
    check-cast v9, Lyl/a;

    .line 129
    .line 130
    iget-object v9, v9, Lyl/a;->a:Landroid/graphics/Bitmap;

    .line 131
    .line 132
    invoke-virtual {v9}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    if-nez v10, :cond_5

    .line 137
    .line 138
    sget-object v10, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 139
    .line 140
    :cond_5
    sget-object v11, Lsm/i;->a:[Landroid/graphics/Bitmap$Config;

    .line 141
    .line 142
    invoke-static {v10, v11}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 143
    .line 144
    .line 145
    move-result v10

    .line 146
    if-eqz v10, :cond_6

    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_6
    iget-object v9, v2, Lmm/n;->a:Landroid/content/Context;

    .line 150
    .line 151
    invoke-virtual {v9}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 152
    .line 153
    .line 154
    move-result-object v9

    .line 155
    invoke-static {v6, v9}, Lyl/m;->b(Lyl/j;Landroid/content/res/Resources;)Landroid/graphics/drawable/Drawable;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    sget-object v9, Lmm/i;->b:Ld8/c;

    .line 160
    .line 161
    invoke-static {v2, v9}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v9

    .line 165
    check-cast v9, Landroid/graphics/Bitmap$Config;

    .line 166
    .line 167
    iget-object v10, v2, Lmm/n;->b:Lnm/h;

    .line 168
    .line 169
    iget-object v11, v2, Lmm/n;->c:Lnm/g;

    .line 170
    .line 171
    iget-object v12, v2, Lmm/n;->d:Lnm/d;

    .line 172
    .line 173
    sget-object v13, Lnm/d;->e:Lnm/d;

    .line 174
    .line 175
    if-ne v12, v13, :cond_7

    .line 176
    .line 177
    move v12, v7

    .line 178
    goto :goto_1

    .line 179
    :cond_7
    const/4 v12, 0x0

    .line 180
    :goto_1
    invoke-static {v6, v9, v10, v11, v12}, Lsm/b;->a(Landroid/graphics/drawable/Drawable;Landroid/graphics/Bitmap$Config;Lnm/h;Lnm/g;Z)Landroid/graphics/Bitmap;

    .line 181
    .line 182
    .line 183
    move-result-object v9

    .line 184
    :goto_2
    invoke-virtual/range {p3 .. p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 185
    .line 186
    .line 187
    move-object v6, v3

    .line 188
    check-cast v6, Ljava/util/Collection;

    .line 189
    .line 190
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 191
    .line 192
    .line 193
    move-result v6

    .line 194
    move-object v11, v3

    .line 195
    move-object v10, v4

    .line 196
    move-object v12, v9

    .line 197
    const/4 v4, 0x0

    .line 198
    const/4 v9, 0x0

    .line 199
    move-object/from16 v3, p3

    .line 200
    .line 201
    :goto_3
    if-ge v4, v6, :cond_e

    .line 202
    .line 203
    invoke-interface {v11, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    move-result-object v13

    .line 207
    check-cast v13, Lip0/c;

    .line 208
    .line 209
    iget-object v14, v2, Lmm/n;->b:Lnm/h;

    .line 210
    .line 211
    iput-object v0, v10, Lem/g;->d:Lem/a;

    .line 212
    .line 213
    iput-object v1, v10, Lem/g;->e:Lmm/g;

    .line 214
    .line 215
    iput-object v2, v10, Lem/g;->f:Lmm/n;

    .line 216
    .line 217
    iput-object v3, v10, Lem/g;->g:Lyl/f;

    .line 218
    .line 219
    move-object v14, v11

    .line 220
    check-cast v14, Ljava/util/List;

    .line 221
    .line 222
    iput-object v14, v10, Lem/g;->h:Ljava/util/List;

    .line 223
    .line 224
    iput v9, v10, Lem/g;->i:I

    .line 225
    .line 226
    iput v4, v10, Lem/g;->j:I

    .line 227
    .line 228
    iput v6, v10, Lem/g;->k:I

    .line 229
    .line 230
    iput v7, v10, Lem/g;->m:I

    .line 231
    .line 232
    iget-object v13, v13, Lip0/c;->b:Lhp0/c;

    .line 233
    .line 234
    iget-object v14, v13, Lhp0/c;->a:Ljava/lang/Integer;

    .line 235
    .line 236
    if-eqz v14, :cond_8

    .line 237
    .line 238
    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    .line 239
    .line 240
    .line 241
    move-result v14

    .line 242
    goto :goto_4

    .line 243
    :cond_8
    const/4 v14, 0x0

    .line 244
    :goto_4
    iget-object v15, v13, Lhp0/c;->b:Ljava/lang/Integer;

    .line 245
    .line 246
    if-eqz v15, :cond_9

    .line 247
    .line 248
    invoke-virtual {v15}, Ljava/lang/Integer;->intValue()I

    .line 249
    .line 250
    .line 251
    move-result v15

    .line 252
    :goto_5
    move/from16 p4, v7

    .line 253
    .line 254
    goto :goto_6

    .line 255
    :cond_9
    const/4 v15, 0x0

    .line 256
    goto :goto_5

    .line 257
    :goto_6
    iget-object v7, v13, Lhp0/c;->c:Ljava/lang/Integer;

    .line 258
    .line 259
    if-eqz v7, :cond_a

    .line 260
    .line 261
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 262
    .line 263
    .line 264
    move-result v7

    .line 265
    goto :goto_7

    .line 266
    :cond_a
    const/4 v7, 0x0

    .line 267
    :goto_7
    iget-object v8, v13, Lhp0/c;->d:Ljava/lang/Integer;

    .line 268
    .line 269
    if-eqz v8, :cond_b

    .line 270
    .line 271
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 272
    .line 273
    .line 274
    move-result v8

    .line 275
    goto :goto_8

    .line 276
    :cond_b
    const/4 v8, 0x0

    .line 277
    :goto_8
    invoke-virtual {v12}, Landroid/graphics/Bitmap;->getWidth()I

    .line 278
    .line 279
    .line 280
    move-result v16

    .line 281
    add-int v16, v16, v14

    .line 282
    .line 283
    add-int v15, v16, v15

    .line 284
    .line 285
    invoke-virtual {v12}, Landroid/graphics/Bitmap;->getHeight()I

    .line 286
    .line 287
    .line 288
    move-result v16

    .line 289
    add-int v16, v16, v7

    .line 290
    .line 291
    add-int v8, v16, v8

    .line 292
    .line 293
    move-object/from16 v16, v1

    .line 294
    .line 295
    sget-object v1, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 296
    .line 297
    invoke-static {v15, v8, v1}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    move-object/from16 p0, v2

    .line 302
    .line 303
    new-instance v2, Landroid/graphics/Canvas;

    .line 304
    .line 305
    invoke-direct {v2, v1}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 306
    .line 307
    .line 308
    move-object/from16 p1, v3

    .line 309
    .line 310
    new-instance v3, Landroid/graphics/Matrix;

    .line 311
    .line 312
    invoke-direct {v3}, Landroid/graphics/Matrix;-><init>()V

    .line 313
    .line 314
    .line 315
    int-to-float v14, v14

    .line 316
    int-to-float v7, v7

    .line 317
    invoke-virtual {v3, v14, v7}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    .line 318
    .line 319
    .line 320
    iget-boolean v7, v13, Lhp0/c;->f:Z

    .line 321
    .line 322
    if-eqz v7, :cond_c

    .line 323
    .line 324
    int-to-float v7, v15

    .line 325
    const/high16 v13, 0x40000000    # 2.0f

    .line 326
    .line 327
    div-float/2addr v7, v13

    .line 328
    int-to-float v8, v8

    .line 329
    div-float/2addr v8, v13

    .line 330
    const/high16 v13, -0x40800000    # -1.0f

    .line 331
    .line 332
    const/high16 v14, 0x3f800000    # 1.0f

    .line 333
    .line 334
    invoke-virtual {v3, v13, v14, v7, v8}, Landroid/graphics/Matrix;->postScale(FFFF)Z

    .line 335
    .line 336
    .line 337
    :cond_c
    const/4 v7, 0x0

    .line 338
    invoke-virtual {v2, v12, v3, v7}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Matrix;Landroid/graphics/Paint;)V

    .line 339
    .line 340
    .line 341
    if-ne v1, v5, :cond_d

    .line 342
    .line 343
    return-object v5

    .line 344
    :cond_d
    move-object/from16 v2, p0

    .line 345
    .line 346
    move-object v3, v1

    .line 347
    move v1, v4

    .line 348
    move v4, v9

    .line 349
    move-object v7, v11

    .line 350
    move-object/from16 v11, v16

    .line 351
    .line 352
    move-object/from16 v9, p1

    .line 353
    .line 354
    :goto_9
    move-object v12, v3

    .line 355
    check-cast v12, Landroid/graphics/Bitmap;

    .line 356
    .line 357
    invoke-interface {v10}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 358
    .line 359
    .line 360
    move-result-object v3

    .line 361
    invoke-static {v3}, Lvy0/e0;->r(Lpx0/g;)V

    .line 362
    .line 363
    .line 364
    add-int/lit8 v1, v1, 0x1

    .line 365
    .line 366
    move-object v3, v9

    .line 367
    move v9, v4

    .line 368
    move v4, v1

    .line 369
    move-object v1, v11

    .line 370
    move-object v11, v7

    .line 371
    move/from16 v7, p4

    .line 372
    .line 373
    goto/16 :goto_3

    .line 374
    .line 375
    :cond_e
    move-object/from16 p1, v3

    .line 376
    .line 377
    invoke-virtual/range {p1 .. p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 378
    .line 379
    .line 380
    new-instance v1, Lyl/a;

    .line 381
    .line 382
    invoke-direct {v1, v12}, Lyl/a;-><init>(Landroid/graphics/Bitmap;)V

    .line 383
    .line 384
    .line 385
    iget-boolean v2, v0, Lem/a;->b:Z

    .line 386
    .line 387
    iget-object v3, v0, Lem/a;->c:Lbm/h;

    .line 388
    .line 389
    iget-object v0, v0, Lem/a;->d:Ljava/lang/String;

    .line 390
    .line 391
    new-instance v4, Lem/a;

    .line 392
    .line 393
    invoke-direct {v4, v1, v2, v3, v0}, Lem/a;-><init>(Lyl/j;ZLbm/h;Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    return-object v4
.end method
