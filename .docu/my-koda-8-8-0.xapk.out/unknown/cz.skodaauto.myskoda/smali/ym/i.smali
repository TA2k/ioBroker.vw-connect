.class public final Lym/i;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Landroid/graphics/Rect;

.field public final synthetic g:Lt3/k;

.field public final synthetic h:Landroid/graphics/Matrix;

.field public final synthetic i:Lum/j;

.field public final synthetic j:Lum/a;

.field public final synthetic k:Landroid/content/Context;

.field public final synthetic l:Lay0/a;

.field public final synthetic m:Ll2/b1;


# direct methods
.method public constructor <init>(Landroid/graphics/Rect;Lt3/k;Landroid/graphics/Matrix;Lum/j;Lum/a;Landroid/content/Context;Lay0/a;Ll2/b1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lym/i;->f:Landroid/graphics/Rect;

    .line 2
    .line 3
    iput-object p2, p0, Lym/i;->g:Lt3/k;

    .line 4
    .line 5
    iput-object p3, p0, Lym/i;->h:Landroid/graphics/Matrix;

    .line 6
    .line 7
    iput-object p4, p0, Lym/i;->i:Lum/j;

    .line 8
    .line 9
    iput-object p5, p0, Lym/i;->j:Lum/a;

    .line 10
    .line 11
    iput-object p6, p0, Lym/i;->k:Landroid/content/Context;

    .line 12
    .line 13
    iput-object p7, p0, Lym/i;->l:Lay0/a;

    .line 14
    .line 15
    iput-object p8, p0, Lym/i;->m:Ll2/b1;

    .line 16
    .line 17
    const/4 p1, 0x1

    .line 18
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 19
    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 15

    .line 1
    move-object/from16 v1, p1

    .line 2
    .line 3
    check-cast v1, Lg3/d;

    .line 4
    .line 5
    const-string v2, "$this$Canvas"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-interface {v1}, Lg3/d;->x0()Lgw0/c;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    iget-object v3, p0, Lym/i;->f:Landroid/graphics/Rect;

    .line 19
    .line 20
    invoke-virtual {v3}, Landroid/graphics/Rect;->width()I

    .line 21
    .line 22
    .line 23
    move-result v4

    .line 24
    int-to-float v4, v4

    .line 25
    invoke-virtual {v3}, Landroid/graphics/Rect;->height()I

    .line 26
    .line 27
    .line 28
    move-result v5

    .line 29
    int-to-float v5, v5

    .line 30
    invoke-static {v4, v5}, Ljp/ef;->a(FF)J

    .line 31
    .line 32
    .line 33
    move-result-wide v4

    .line 34
    invoke-interface {v1}, Lg3/d;->e()J

    .line 35
    .line 36
    .line 37
    move-result-wide v6

    .line 38
    invoke-static {v6, v7}, Ld3/e;->d(J)F

    .line 39
    .line 40
    .line 41
    move-result v6

    .line 42
    invoke-static {v6}, Lcy0/a;->i(F)I

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    invoke-interface {v1}, Lg3/d;->e()J

    .line 47
    .line 48
    .line 49
    move-result-wide v7

    .line 50
    invoke-static {v7, v8}, Ld3/e;->b(J)F

    .line 51
    .line 52
    .line 53
    move-result v7

    .line 54
    invoke-static {v7}, Lcy0/a;->i(F)I

    .line 55
    .line 56
    .line 57
    move-result v7

    .line 58
    invoke-static {v6, v7}, Lkp/f9;->a(II)J

    .line 59
    .line 60
    .line 61
    move-result-wide v6

    .line 62
    invoke-interface {v1}, Lg3/d;->e()J

    .line 63
    .line 64
    .line 65
    move-result-wide v8

    .line 66
    iget-object v10, p0, Lym/i;->g:Lt3/k;

    .line 67
    .line 68
    invoke-interface {v10, v4, v5, v8, v9}, Lt3/k;->a(JJ)J

    .line 69
    .line 70
    .line 71
    move-result-wide v8

    .line 72
    invoke-static {v4, v5}, Ld3/e;->d(J)F

    .line 73
    .line 74
    .line 75
    move-result v10

    .line 76
    sget v11, Lt3/j1;->a:I

    .line 77
    .line 78
    const/16 v11, 0x20

    .line 79
    .line 80
    shr-long v12, v8, v11

    .line 81
    .line 82
    long-to-int v12, v12

    .line 83
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 84
    .line 85
    .line 86
    move-result v13

    .line 87
    mul-float/2addr v13, v10

    .line 88
    float-to-int v10, v13

    .line 89
    invoke-static {v4, v5}, Ld3/e;->b(J)F

    .line 90
    .line 91
    .line 92
    move-result v4

    .line 93
    const-wide v13, 0xffffffffL

    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    and-long/2addr v8, v13

    .line 99
    long-to-int v5, v8

    .line 100
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    mul-float/2addr v8, v4

    .line 105
    float-to-int v4, v8

    .line 106
    invoke-static {v10, v4}, Lkp/f9;->a(II)J

    .line 107
    .line 108
    .line 109
    move-result-wide v8

    .line 110
    invoke-interface {v1}, Lg3/d;->getLayoutDirection()Lt4/m;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    move/from16 p1, v11

    .line 115
    .line 116
    move v4, v12

    .line 117
    shr-long v11, v6, p1

    .line 118
    .line 119
    long-to-int v10, v11

    .line 120
    shr-long v11, v8, p1

    .line 121
    .line 122
    long-to-int v11, v11

    .line 123
    sub-int/2addr v10, v11

    .line 124
    int-to-float v10, v10

    .line 125
    const/high16 v11, 0x40000000    # 2.0f

    .line 126
    .line 127
    div-float/2addr v10, v11

    .line 128
    and-long/2addr v6, v13

    .line 129
    long-to-int v6, v6

    .line 130
    and-long v7, v8, v13

    .line 131
    .line 132
    long-to-int v7, v7

    .line 133
    sub-int/2addr v6, v7

    .line 134
    int-to-float v6, v6

    .line 135
    div-float/2addr v6, v11

    .line 136
    sget-object v7, Lt4/m;->d:Lt4/m;

    .line 137
    .line 138
    const/4 v8, 0x0

    .line 139
    if-ne v1, v7, :cond_0

    .line 140
    .line 141
    move v1, v8

    .line 142
    goto :goto_0

    .line 143
    :cond_0
    const/4 v1, -0x1

    .line 144
    int-to-float v1, v1

    .line 145
    mul-float/2addr v1, v8

    .line 146
    :goto_0
    const/4 v7, 0x1

    .line 147
    int-to-float v9, v7

    .line 148
    add-float/2addr v1, v9

    .line 149
    mul-float/2addr v1, v10

    .line 150
    add-float/2addr v9, v8

    .line 151
    mul-float/2addr v9, v6

    .line 152
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 153
    .line 154
    .line 155
    move-result v1

    .line 156
    invoke-static {v9}, Ljava/lang/Math;->round(F)I

    .line 157
    .line 158
    .line 159
    move-result v6

    .line 160
    int-to-long v9, v1

    .line 161
    shl-long v9, v9, p1

    .line 162
    .line 163
    int-to-long v11, v6

    .line 164
    and-long/2addr v11, v13

    .line 165
    or-long/2addr v9, v11

    .line 166
    iget-object v1, p0, Lym/i;->h:Landroid/graphics/Matrix;

    .line 167
    .line 168
    invoke-virtual {v1}, Landroid/graphics/Matrix;->reset()V

    .line 169
    .line 170
    .line 171
    shr-long v11, v9, p1

    .line 172
    .line 173
    long-to-int v6, v11

    .line 174
    int-to-float v6, v6

    .line 175
    and-long/2addr v9, v13

    .line 176
    long-to-int v9, v9

    .line 177
    int-to-float v9, v9

    .line 178
    invoke-virtual {v1, v6, v9}, Landroid/graphics/Matrix;->preTranslate(FF)Z

    .line 179
    .line 180
    .line 181
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    invoke-virtual {v1, v4, v5}, Landroid/graphics/Matrix;->preScale(FF)Z

    .line 190
    .line 191
    .line 192
    iget-object v4, p0, Lym/i;->i:Lum/j;

    .line 193
    .line 194
    iget-object v5, v4, Lum/j;->j:Lpv/g;

    .line 195
    .line 196
    iget-object v6, v4, Lum/j;->e:Lgn/e;

    .line 197
    .line 198
    iget-object v5, v5, Lpv/g;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v5, Ljava/util/HashSet;

    .line 201
    .line 202
    sget-object v9, Lum/k;->d:Lum/k;

    .line 203
    .line 204
    invoke-virtual {v5, v9}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 205
    .line 206
    .line 207
    move-result v5

    .line 208
    iget-object v9, v4, Lum/j;->d:Lum/a;

    .line 209
    .line 210
    if-eqz v9, :cond_1

    .line 211
    .line 212
    if-eqz v5, :cond_1

    .line 213
    .line 214
    invoke-virtual {v4}, Lum/j;->b()V

    .line 215
    .line 216
    .line 217
    :cond_1
    iput v7, v4, Lum/j;->H:I

    .line 218
    .line 219
    invoke-virtual {v4}, Lum/j;->c()V

    .line 220
    .line 221
    .line 222
    iput v7, v4, Lum/j;->I:I

    .line 223
    .line 224
    iget-object v5, v4, Lum/j;->g:Ljava/util/ArrayList;

    .line 225
    .line 226
    iget-object v9, v4, Lum/j;->d:Lum/a;

    .line 227
    .line 228
    const/4 v10, 0x0

    .line 229
    const/4 v11, 0x0

    .line 230
    iget-object v12, p0, Lym/i;->j:Lum/a;

    .line 231
    .line 232
    if-ne v9, v12, :cond_2

    .line 233
    .line 234
    goto/16 :goto_4

    .line 235
    .line 236
    :cond_2
    iput-boolean v7, v4, Lum/j;->C:Z

    .line 237
    .line 238
    iget-boolean v9, v6, Lgn/e;->p:Z

    .line 239
    .line 240
    if-eqz v9, :cond_3

    .line 241
    .line 242
    invoke-virtual {v6}, Lgn/e;->cancel()V

    .line 243
    .line 244
    .line 245
    invoke-virtual {v4}, Landroid/graphics/drawable/Drawable;->isVisible()Z

    .line 246
    .line 247
    .line 248
    move-result v9

    .line 249
    if-nez v9, :cond_3

    .line 250
    .line 251
    iput v7, v4, Lum/j;->G:I

    .line 252
    .line 253
    :cond_3
    iput-object v10, v4, Lum/j;->d:Lum/a;

    .line 254
    .line 255
    iput-object v10, v4, Lum/j;->l:Ldn/c;

    .line 256
    .line 257
    iput-object v10, v4, Lum/j;->h:Lzm/a;

    .line 258
    .line 259
    const v9, -0x800001

    .line 260
    .line 261
    .line 262
    iput v9, v4, Lum/j;->F:F

    .line 263
    .line 264
    iput-object v10, v6, Lgn/e;->o:Lum/a;

    .line 265
    .line 266
    const/high16 v9, -0x31000000

    .line 267
    .line 268
    iput v9, v6, Lgn/e;->m:F

    .line 269
    .line 270
    const/high16 v9, 0x4f000000

    .line 271
    .line 272
    iput v9, v6, Lgn/e;->n:F

    .line 273
    .line 274
    invoke-virtual {v4}, Lum/j;->invalidateSelf()V

    .line 275
    .line 276
    .line 277
    iput-object v12, v4, Lum/j;->d:Lum/a;

    .line 278
    .line 279
    invoke-virtual {v4}, Lum/j;->b()V

    .line 280
    .line 281
    .line 282
    iget-object v9, v6, Lgn/e;->o:Lum/a;

    .line 283
    .line 284
    if-nez v9, :cond_4

    .line 285
    .line 286
    move v9, v7

    .line 287
    goto :goto_1

    .line 288
    :cond_4
    move v9, v11

    .line 289
    :goto_1
    iput-object v12, v6, Lgn/e;->o:Lum/a;

    .line 290
    .line 291
    if-eqz v9, :cond_5

    .line 292
    .line 293
    iget v9, v6, Lgn/e;->m:F

    .line 294
    .line 295
    iget v13, v12, Lum/a;->l:F

    .line 296
    .line 297
    invoke-static {v9, v13}, Ljava/lang/Math;->max(FF)F

    .line 298
    .line 299
    .line 300
    move-result v9

    .line 301
    iget v13, v6, Lgn/e;->n:F

    .line 302
    .line 303
    iget v14, v12, Lum/a;->m:F

    .line 304
    .line 305
    invoke-static {v13, v14}, Ljava/lang/Math;->min(FF)F

    .line 306
    .line 307
    .line 308
    move-result v13

    .line 309
    invoke-virtual {v6, v9, v13}, Lgn/e;->j(FF)V

    .line 310
    .line 311
    .line 312
    goto :goto_2

    .line 313
    :cond_5
    iget v9, v12, Lum/a;->l:F

    .line 314
    .line 315
    float-to-int v9, v9

    .line 316
    int-to-float v9, v9

    .line 317
    iget v13, v12, Lum/a;->m:F

    .line 318
    .line 319
    float-to-int v13, v13

    .line 320
    int-to-float v13, v13

    .line 321
    invoke-virtual {v6, v9, v13}, Lgn/e;->j(FF)V

    .line 322
    .line 323
    .line 324
    :goto_2
    iget v9, v6, Lgn/e;->k:F

    .line 325
    .line 326
    iput v8, v6, Lgn/e;->k:F

    .line 327
    .line 328
    iput v8, v6, Lgn/e;->j:F

    .line 329
    .line 330
    float-to-int v8, v9

    .line 331
    int-to-float v8, v8

    .line 332
    invoke-virtual {v6, v8}, Lgn/e;->i(F)V

    .line 333
    .line 334
    .line 335
    invoke-virtual {v6}, Lgn/e;->f()V

    .line 336
    .line 337
    .line 338
    invoke-virtual {v6}, Lgn/e;->getAnimatedFraction()F

    .line 339
    .line 340
    .line 341
    move-result v8

    .line 342
    invoke-virtual {v4, v8}, Lum/j;->l(F)V

    .line 343
    .line 344
    .line 345
    new-instance v8, Ljava/util/ArrayList;

    .line 346
    .line 347
    invoke-direct {v8, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 351
    .line 352
    .line 353
    move-result-object v8

    .line 354
    :goto_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 355
    .line 356
    .line 357
    move-result v9

    .line 358
    if-eqz v9, :cond_7

    .line 359
    .line 360
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 361
    .line 362
    .line 363
    move-result-object v9

    .line 364
    check-cast v9, Lum/i;

    .line 365
    .line 366
    if-eqz v9, :cond_6

    .line 367
    .line 368
    invoke-interface {v9}, Lum/i;->run()V

    .line 369
    .line 370
    .line 371
    :cond_6
    invoke-interface {v8}, Ljava/util/Iterator;->remove()V

    .line 372
    .line 373
    .line 374
    goto :goto_3

    .line 375
    :cond_7
    invoke-virtual {v5}, Ljava/util/ArrayList;->clear()V

    .line 376
    .line 377
    .line 378
    iget-object v5, v12, Lum/a;->a:Li21/a;

    .line 379
    .line 380
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 381
    .line 382
    .line 383
    invoke-virtual {v4}, Lum/j;->c()V

    .line 384
    .line 385
    .line 386
    invoke-virtual {v4}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 387
    .line 388
    .line 389
    move-result-object v5

    .line 390
    instance-of v8, v5, Landroid/widget/ImageView;

    .line 391
    .line 392
    if-eqz v8, :cond_8

    .line 393
    .line 394
    check-cast v5, Landroid/widget/ImageView;

    .line 395
    .line 396
    invoke-virtual {v5, v10}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v5, v4}, Landroid/widget/ImageView;->setImageDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 400
    .line 401
    .line 402
    :cond_8
    :goto_4
    iget-object v5, p0, Lym/i;->m:Ll2/b1;

    .line 403
    .line 404
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v5

    .line 408
    if-nez v5, :cond_13

    .line 409
    .line 410
    iput-boolean v7, v4, Lum/j;->n:Z

    .line 411
    .line 412
    iget-boolean v5, v4, Lum/j;->k:Z

    .line 413
    .line 414
    if-eq v7, v5, :cond_a

    .line 415
    .line 416
    iput-boolean v7, v4, Lum/j;->k:Z

    .line 417
    .line 418
    iget-object v5, v4, Lum/j;->l:Ldn/c;

    .line 419
    .line 420
    if-eqz v5, :cond_9

    .line 421
    .line 422
    iput-boolean v7, v5, Ldn/c;->I:Z

    .line 423
    .line 424
    :cond_9
    invoke-virtual {v4}, Lum/j;->invalidateSelf()V

    .line 425
    .line 426
    .line 427
    :cond_a
    invoke-virtual {v4}, Lum/j;->g()Lan/f;

    .line 428
    .line 429
    .line 430
    move-result-object v5

    .line 431
    iget-object v8, p0, Lym/i;->k:Landroid/content/Context;

    .line 432
    .line 433
    invoke-virtual {v4, v8}, Lum/j;->a(Landroid/content/Context;)Z

    .line 434
    .line 435
    .line 436
    move-result v8

    .line 437
    if-nez v8, :cond_b

    .line 438
    .line 439
    if-eqz v5, :cond_b

    .line 440
    .line 441
    iget v0, v5, Lan/f;->b:F

    .line 442
    .line 443
    invoke-virtual {v4, v0}, Lum/j;->l(F)V

    .line 444
    .line 445
    .line 446
    goto :goto_5

    .line 447
    :cond_b
    iget-object v0, p0, Lym/i;->l:Lay0/a;

    .line 448
    .line 449
    invoke-interface {v0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    check-cast v0, Ljava/lang/Number;

    .line 454
    .line 455
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 456
    .line 457
    .line 458
    move-result v0

    .line 459
    invoke-virtual {v4, v0}, Lum/j;->l(F)V

    .line 460
    .line 461
    .line 462
    :goto_5
    invoke-virtual {v3}, Landroid/graphics/Rect;->width()I

    .line 463
    .line 464
    .line 465
    move-result v0

    .line 466
    invoke-virtual {v3}, Landroid/graphics/Rect;->height()I

    .line 467
    .line 468
    .line 469
    move-result v3

    .line 470
    invoke-virtual {v4, v11, v11, v0, v3}, Landroid/graphics/drawable/Drawable;->setBounds(IIII)V

    .line 471
    .line 472
    .line 473
    invoke-static {v2}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 474
    .line 475
    .line 476
    move-result-object v0

    .line 477
    iget-object v2, v4, Lum/j;->E:Lm8/o;

    .line 478
    .line 479
    sget-object v3, Lum/j;->K:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 480
    .line 481
    iget-object v5, v4, Lum/j;->D:Ljava/util/concurrent/Semaphore;

    .line 482
    .line 483
    iget-object v8, v4, Lum/j;->l:Ldn/c;

    .line 484
    .line 485
    iget-object v9, v4, Lum/j;->d:Lum/a;

    .line 486
    .line 487
    if-eqz v8, :cond_12

    .line 488
    .line 489
    if-nez v9, :cond_c

    .line 490
    .line 491
    goto/16 :goto_c

    .line 492
    .line 493
    :cond_c
    iget v9, v4, Lum/j;->I:I

    .line 494
    .line 495
    if-eqz v9, :cond_d

    .line 496
    .line 497
    goto :goto_6

    .line 498
    :cond_d
    move v9, v7

    .line 499
    :goto_6
    const/4 v12, 0x2

    .line 500
    if-ne v9, v12, :cond_e

    .line 501
    .line 502
    goto :goto_7

    .line 503
    :cond_e
    move v7, v11

    .line 504
    :goto_7
    if-eqz v7, :cond_f

    .line 505
    .line 506
    :try_start_0
    invoke-virtual {v5}, Ljava/util/concurrent/Semaphore;->acquire()V

    .line 507
    .line 508
    .line 509
    invoke-virtual {v4}, Lum/j;->m()Z

    .line 510
    .line 511
    .line 512
    move-result v9

    .line 513
    if-eqz v9, :cond_f

    .line 514
    .line 515
    invoke-virtual {v6}, Lgn/e;->a()F

    .line 516
    .line 517
    .line 518
    move-result v9

    .line 519
    invoke-virtual {v4, v9}, Lum/j;->l(F)V

    .line 520
    .line 521
    .line 522
    goto :goto_8

    .line 523
    :catchall_0
    move-exception v0

    .line 524
    goto :goto_b

    .line 525
    :cond_f
    :goto_8
    iget v9, v4, Lum/j;->m:I

    .line 526
    .line 527
    iget-boolean v12, v4, Lum/j;->o:Z

    .line 528
    .line 529
    if-eqz v12, :cond_10

    .line 530
    .line 531
    invoke-virtual {v0}, Landroid/graphics/Canvas;->save()I

    .line 532
    .line 533
    .line 534
    invoke-virtual {v0, v1}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v4, v0, v8}, Lum/j;->i(Landroid/graphics/Canvas;Ldn/c;)V

    .line 538
    .line 539
    .line 540
    invoke-virtual {v0}, Landroid/graphics/Canvas;->restore()V

    .line 541
    .line 542
    .line 543
    goto :goto_9

    .line 544
    :cond_10
    invoke-virtual {v8, v0, v1, v9, v10}, Ldn/b;->c(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V

    .line 545
    .line 546
    .line 547
    :goto_9
    iput-boolean v11, v4, Lum/j;->C:Z
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 548
    .line 549
    if-eqz v7, :cond_12

    .line 550
    .line 551
    invoke-virtual {v5}, Ljava/util/concurrent/Semaphore;->release()V

    .line 552
    .line 553
    .line 554
    iget v0, v8, Ldn/c;->H:F

    .line 555
    .line 556
    invoke-virtual {v6}, Lgn/e;->a()F

    .line 557
    .line 558
    .line 559
    move-result v1

    .line 560
    cmpl-float v0, v0, v1

    .line 561
    .line 562
    if-eqz v0, :cond_12

    .line 563
    .line 564
    :goto_a
    invoke-virtual {v3, v2}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 565
    .line 566
    .line 567
    goto :goto_c

    .line 568
    :goto_b
    if-eqz v7, :cond_11

    .line 569
    .line 570
    invoke-virtual {v5}, Ljava/util/concurrent/Semaphore;->release()V

    .line 571
    .line 572
    .line 573
    iget v1, v8, Ldn/c;->H:F

    .line 574
    .line 575
    invoke-virtual {v6}, Lgn/e;->a()F

    .line 576
    .line 577
    .line 578
    move-result v4

    .line 579
    cmpl-float v1, v1, v4

    .line 580
    .line 581
    if-eqz v1, :cond_11

    .line 582
    .line 583
    invoke-virtual {v3, v2}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 584
    .line 585
    .line 586
    :cond_11
    throw v0

    .line 587
    :catch_0
    if-eqz v7, :cond_12

    .line 588
    .line 589
    invoke-virtual {v5}, Ljava/util/concurrent/Semaphore;->release()V

    .line 590
    .line 591
    .line 592
    iget v0, v8, Ldn/c;->H:F

    .line 593
    .line 594
    invoke-virtual {v6}, Lgn/e;->a()F

    .line 595
    .line 596
    .line 597
    move-result v1

    .line 598
    cmpl-float v0, v0, v1

    .line 599
    .line 600
    if-eqz v0, :cond_12

    .line 601
    .line 602
    goto :goto_a

    .line 603
    :cond_12
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 604
    .line 605
    return-object v0

    .line 606
    :cond_13
    new-instance v0, Ljava/lang/ClassCastException;

    .line 607
    .line 608
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 609
    .line 610
    .line 611
    throw v0
.end method
