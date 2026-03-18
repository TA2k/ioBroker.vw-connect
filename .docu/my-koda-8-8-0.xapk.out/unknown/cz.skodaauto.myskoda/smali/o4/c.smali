.class public final Lo4/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg4/s;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lg4/p0;

.field public final f:Ljava/util/List;

.field public final g:Ljava/util/List;

.field public final h:Lk4/m;

.field public final i:Lt4/c;

.field public final j:Lo4/d;

.field public final k:Ljava/lang/CharSequence;

.field public final l:Lh4/f;

.field public m:Lil/g;

.field public final n:Z

.field public final o:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Lg4/p0;Ljava/util/List;Ljava/util/List;Lk4/m;Lt4/c;)V
    .locals 40

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
    move-object/from16 v3, p6

    .line 8
    .line 9
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    move-object/from16 v4, p1

    .line 13
    .line 14
    iput-object v4, v0, Lo4/c;->d:Ljava/lang/String;

    .line 15
    .line 16
    iput-object v1, v0, Lo4/c;->e:Lg4/p0;

    .line 17
    .line 18
    iput-object v2, v0, Lo4/c;->f:Ljava/util/List;

    .line 19
    .line 20
    move-object/from16 v4, p4

    .line 21
    .line 22
    iput-object v4, v0, Lo4/c;->g:Ljava/util/List;

    .line 23
    .line 24
    move-object/from16 v4, p5

    .line 25
    .line 26
    iput-object v4, v0, Lo4/c;->h:Lk4/m;

    .line 27
    .line 28
    iput-object v3, v0, Lo4/c;->i:Lt4/c;

    .line 29
    .line 30
    new-instance v4, Lo4/d;

    .line 31
    .line 32
    invoke-interface {v3}, Lt4/c;->a()F

    .line 33
    .line 34
    .line 35
    move-result v5

    .line 36
    const/4 v6, 0x1

    .line 37
    invoke-direct {v4, v6}, Landroid/text/TextPaint;-><init>(I)V

    .line 38
    .line 39
    .line 40
    iput v5, v4, Landroid/text/TextPaint;->density:F

    .line 41
    .line 42
    sget-object v5, Lr4/l;->b:Lr4/l;

    .line 43
    .line 44
    iput-object v5, v4, Lo4/d;->b:Lr4/l;

    .line 45
    .line 46
    const/4 v5, 0x3

    .line 47
    iput v5, v4, Lo4/d;->c:I

    .line 48
    .line 49
    sget-object v7, Le3/m0;->d:Le3/m0;

    .line 50
    .line 51
    iput-object v7, v4, Lo4/d;->d:Le3/m0;

    .line 52
    .line 53
    iput-object v4, v0, Lo4/c;->j:Lo4/d;

    .line 54
    .line 55
    iget-object v7, v1, Lg4/p0;->c:Lg4/y;

    .line 56
    .line 57
    iget-object v7, v1, Lg4/p0;->a:Lg4/g0;

    .line 58
    .line 59
    iget-object v1, v1, Lg4/p0;->b:Lg4/t;

    .line 60
    .line 61
    sget-object v8, Lo4/h;->a:Lhu/q;

    .line 62
    .line 63
    sget-object v8, Lo4/h;->a:Lhu/q;

    .line 64
    .line 65
    iget-object v9, v8, Lhu/q;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v9, Ll2/t2;

    .line 68
    .line 69
    if-eqz v9, :cond_0

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    invoke-static {}, Ls6/h;->d()Z

    .line 73
    .line 74
    .line 75
    move-result v9

    .line 76
    if-eqz v9, :cond_1

    .line 77
    .line 78
    invoke-virtual {v8}, Lhu/q;->B()Ll2/t2;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    iput-object v9, v8, Lhu/q;->e:Ljava/lang/Object;

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_1
    sget-object v9, Lo4/i;->a:Lo4/j;

    .line 86
    .line 87
    :goto_0
    invoke-interface {v9}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    check-cast v8, Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    iput-boolean v8, v0, Lo4/c;->n:Z

    .line 98
    .line 99
    iget v8, v1, Lg4/t;->b:I

    .line 100
    .line 101
    iget-object v9, v7, Lg4/g0;->k:Ln4/b;

    .line 102
    .line 103
    const/4 v10, 0x4

    .line 104
    const/4 v11, 0x2

    .line 105
    const/4 v12, 0x0

    .line 106
    if-ne v8, v10, :cond_3

    .line 107
    .line 108
    :cond_2
    :goto_1
    move v8, v11

    .line 109
    goto :goto_3

    .line 110
    :cond_3
    const/4 v10, 0x5

    .line 111
    if-ne v8, v10, :cond_5

    .line 112
    .line 113
    :cond_4
    move v8, v5

    .line 114
    goto :goto_3

    .line 115
    :cond_5
    if-ne v8, v6, :cond_6

    .line 116
    .line 117
    move v8, v12

    .line 118
    goto :goto_3

    .line 119
    :cond_6
    if-ne v8, v11, :cond_7

    .line 120
    .line 121
    move v8, v6

    .line 122
    goto :goto_3

    .line 123
    :cond_7
    if-ne v8, v5, :cond_8

    .line 124
    .line 125
    goto :goto_2

    .line 126
    :cond_8
    const/high16 v10, -0x80000000

    .line 127
    .line 128
    if-ne v8, v10, :cond_78

    .line 129
    .line 130
    :goto_2
    if-eqz v9, :cond_9

    .line 131
    .line 132
    iget-object v8, v9, Ln4/b;->d:Ljava/util/List;

    .line 133
    .line 134
    invoke-interface {v8, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v8

    .line 138
    check-cast v8, Ln4/a;

    .line 139
    .line 140
    iget-object v8, v8, Ln4/a;->a:Ljava/util/Locale;

    .line 141
    .line 142
    if-nez v8, :cond_a

    .line 143
    .line 144
    :cond_9
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 145
    .line 146
    .line 147
    move-result-object v8

    .line 148
    :cond_a
    invoke-static {v8}, Landroid/text/TextUtils;->getLayoutDirectionFromLocale(Ljava/util/Locale;)I

    .line 149
    .line 150
    .line 151
    move-result v8

    .line 152
    if-eqz v8, :cond_2

    .line 153
    .line 154
    if-eq v8, v6, :cond_4

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :goto_3
    iput v8, v0, Lo4/c;->o:I

    .line 158
    .line 159
    new-instance v8, Lge/a;

    .line 160
    .line 161
    const/4 v9, 0x6

    .line 162
    invoke-direct {v8, v0, v9}, Lge/a;-><init>(Ljava/lang/Object;I)V

    .line 163
    .line 164
    .line 165
    iget-object v1, v1, Lg4/t;->i:Lr4/s;

    .line 166
    .line 167
    if-nez v1, :cond_b

    .line 168
    .line 169
    sget-object v1, Lr4/s;->c:Lr4/s;

    .line 170
    .line 171
    :cond_b
    iget-boolean v9, v1, Lr4/s;->b:Z

    .line 172
    .line 173
    if-eqz v9, :cond_c

    .line 174
    .line 175
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 176
    .line 177
    .line 178
    move-result v9

    .line 179
    or-int/lit16 v9, v9, 0x80

    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_c
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 183
    .line 184
    .line 185
    move-result v9

    .line 186
    and-int/lit16 v9, v9, -0x81

    .line 187
    .line 188
    :goto_4
    invoke-virtual {v4, v9}, Landroid/graphics/Paint;->setFlags(I)V

    .line 189
    .line 190
    .line 191
    iget v1, v1, Lr4/s;->a:I

    .line 192
    .line 193
    if-ne v1, v6, :cond_d

    .line 194
    .line 195
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 196
    .line 197
    .line 198
    move-result v1

    .line 199
    or-int/lit8 v1, v1, 0x40

    .line 200
    .line 201
    invoke-virtual {v4, v1}, Landroid/graphics/Paint;->setFlags(I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v4, v12}, Landroid/graphics/Paint;->setHinting(I)V

    .line 205
    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_d
    if-ne v1, v11, :cond_e

    .line 209
    .line 210
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 211
    .line 212
    .line 213
    invoke-virtual {v4, v6}, Landroid/graphics/Paint;->setHinting(I)V

    .line 214
    .line 215
    .line 216
    goto :goto_5

    .line 217
    :cond_e
    if-ne v1, v5, :cond_f

    .line 218
    .line 219
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 220
    .line 221
    .line 222
    invoke-virtual {v4, v12}, Landroid/graphics/Paint;->setHinting(I)V

    .line 223
    .line 224
    .line 225
    goto :goto_5

    .line 226
    :cond_f
    invoke-virtual {v4}, Landroid/graphics/Paint;->getFlags()I

    .line 227
    .line 228
    .line 229
    :goto_5
    move-object v1, v2

    .line 230
    check-cast v1, Ljava/util/Collection;

    .line 231
    .line 232
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    move v5, v12

    .line 237
    :goto_6
    if-ge v5, v1, :cond_11

    .line 238
    .line 239
    invoke-interface {v2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v10

    .line 243
    move-object v13, v10

    .line 244
    check-cast v13, Lg4/e;

    .line 245
    .line 246
    iget-object v13, v13, Lg4/e;->a:Ljava/lang/Object;

    .line 247
    .line 248
    instance-of v13, v13, Lg4/g0;

    .line 249
    .line 250
    if-eqz v13, :cond_10

    .line 251
    .line 252
    goto :goto_7

    .line 253
    :cond_10
    add-int/lit8 v5, v5, 0x1

    .line 254
    .line 255
    goto :goto_6

    .line 256
    :cond_11
    const/4 v10, 0x0

    .line 257
    :goto_7
    if-eqz v10, :cond_12

    .line 258
    .line 259
    move v1, v6

    .line 260
    goto :goto_8

    .line 261
    :cond_12
    move v1, v12

    .line 262
    :goto_8
    iget-wide v13, v7, Lg4/g0;->b:J

    .line 263
    .line 264
    iget-object v2, v7, Lg4/g0;->c:Lk4/x;

    .line 265
    .line 266
    iget-object v5, v7, Lg4/g0;->d:Lk4/t;

    .line 267
    .line 268
    iget-object v10, v7, Lg4/g0;->g:Ljava/lang/String;

    .line 269
    .line 270
    iget-object v15, v7, Lg4/g0;->k:Ln4/b;

    .line 271
    .line 272
    iget-object v9, v7, Lg4/g0;->a:Lr4/o;

    .line 273
    .line 274
    iget-object v11, v7, Lg4/g0;->j:Lr4/p;

    .line 275
    .line 276
    move-wide/from16 v16, v13

    .line 277
    .line 278
    iget-wide v12, v7, Lg4/g0;->h:J

    .line 279
    .line 280
    move/from16 p5, v6

    .line 281
    .line 282
    move-object v14, v7

    .line 283
    invoke-static/range {v16 .. v17}, Lt4/o;->b(J)J

    .line 284
    .line 285
    .line 286
    move-result-wide v6

    .line 287
    move/from16 p3, v1

    .line 288
    .line 289
    move-object/from16 v18, v2

    .line 290
    .line 291
    const-wide v1, 0x100000000L

    .line 292
    .line 293
    .line 294
    .line 295
    .line 296
    invoke-static {v6, v7, v1, v2}, Lt4/p;->a(JJ)Z

    .line 297
    .line 298
    .line 299
    move-result v19

    .line 300
    if-eqz v19, :cond_13

    .line 301
    .line 302
    move-wide/from16 v1, v16

    .line 303
    .line 304
    invoke-interface {v3, v1, v2}, Lt4/c;->V(J)F

    .line 305
    .line 306
    .line 307
    move-result v1

    .line 308
    invoke-virtual {v4, v1}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 309
    .line 310
    .line 311
    goto :goto_9

    .line 312
    :cond_13
    const-wide v1, 0x200000000L

    .line 313
    .line 314
    .line 315
    .line 316
    .line 317
    invoke-static {v6, v7, v1, v2}, Lt4/p;->a(JJ)Z

    .line 318
    .line 319
    .line 320
    move-result v6

    .line 321
    if-eqz v6, :cond_14

    .line 322
    .line 323
    invoke-virtual {v4}, Landroid/graphics/Paint;->getTextSize()F

    .line 324
    .line 325
    .line 326
    move-result v1

    .line 327
    invoke-static/range {v16 .. v17}, Lt4/o;->c(J)F

    .line 328
    .line 329
    .line 330
    move-result v2

    .line 331
    mul-float/2addr v2, v1

    .line 332
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 333
    .line 334
    .line 335
    :cond_14
    :goto_9
    iget-object v1, v14, Lg4/g0;->f:Lk4/n;

    .line 336
    .line 337
    if-nez v1, :cond_16

    .line 338
    .line 339
    if-nez v5, :cond_16

    .line 340
    .line 341
    if-eqz v18, :cond_15

    .line 342
    .line 343
    goto :goto_a

    .line 344
    :cond_15
    move-object/from16 v16, v9

    .line 345
    .line 346
    goto :goto_f

    .line 347
    :cond_16
    :goto_a
    if-nez v18, :cond_17

    .line 348
    .line 349
    sget-object v2, Lk4/x;->l:Lk4/x;

    .line 350
    .line 351
    goto :goto_b

    .line 352
    :cond_17
    move-object/from16 v2, v18

    .line 353
    .line 354
    :goto_b
    if-eqz v5, :cond_18

    .line 355
    .line 356
    iget v5, v5, Lk4/t;->a:I

    .line 357
    .line 358
    goto :goto_c

    .line 359
    :cond_18
    const/4 v5, 0x0

    .line 360
    :goto_c
    iget-object v6, v14, Lg4/g0;->e:Lk4/u;

    .line 361
    .line 362
    if-eqz v6, :cond_19

    .line 363
    .line 364
    iget v6, v6, Lk4/u;->a:I

    .line 365
    .line 366
    goto :goto_d

    .line 367
    :cond_19
    const v6, 0xffff

    .line 368
    .line 369
    .line 370
    :goto_d
    iget-object v7, v8, Lge/a;->e:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast v7, Lo4/c;

    .line 373
    .line 374
    move-object/from16 v16, v9

    .line 375
    .line 376
    iget-object v9, v7, Lo4/c;->h:Lk4/m;

    .line 377
    .line 378
    check-cast v9, Lk4/o;

    .line 379
    .line 380
    invoke-virtual {v9, v1, v2, v5, v6}, Lk4/o;->b(Lk4/n;Lk4/x;II)Lk4/i0;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    instance-of v2, v1, Lk4/h0;

    .line 385
    .line 386
    const-string v5, "null cannot be cast to non-null type android.graphics.Typeface"

    .line 387
    .line 388
    if-nez v2, :cond_1a

    .line 389
    .line 390
    new-instance v2, Lil/g;

    .line 391
    .line 392
    iget-object v6, v7, Lo4/c;->m:Lil/g;

    .line 393
    .line 394
    invoke-direct {v2, v1, v6}, Lil/g;-><init>(Lk4/i0;Lil/g;)V

    .line 395
    .line 396
    .line 397
    iput-object v2, v7, Lo4/c;->m:Lil/g;

    .line 398
    .line 399
    iget-object v1, v2, Lil/g;->g:Ljava/lang/Object;

    .line 400
    .line 401
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 402
    .line 403
    .line 404
    check-cast v1, Landroid/graphics/Typeface;

    .line 405
    .line 406
    goto :goto_e

    .line 407
    :cond_1a
    check-cast v1, Lk4/h0;

    .line 408
    .line 409
    iget-object v1, v1, Lk4/h0;->d:Ljava/lang/Object;

    .line 410
    .line 411
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    check-cast v1, Landroid/graphics/Typeface;

    .line 415
    .line 416
    :goto_e
    invoke-virtual {v4, v1}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 417
    .line 418
    .line 419
    :goto_f
    const/16 v1, 0xa

    .line 420
    .line 421
    if-eqz v15, :cond_1c

    .line 422
    .line 423
    sget-object v2, Ln4/b;->f:Ln4/b;

    .line 424
    .line 425
    sget-object v2, Ln4/c;->a:Lil/g;

    .line 426
    .line 427
    invoke-virtual {v2}, Lil/g;->z()Ln4/b;

    .line 428
    .line 429
    .line 430
    move-result-object v2

    .line 431
    invoke-virtual {v15, v2}, Ln4/b;->equals(Ljava/lang/Object;)Z

    .line 432
    .line 433
    .line 434
    move-result v2

    .line 435
    if-nez v2, :cond_1c

    .line 436
    .line 437
    new-instance v2, Ljava/util/ArrayList;

    .line 438
    .line 439
    invoke-static {v15, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 440
    .line 441
    .line 442
    move-result v5

    .line 443
    invoke-direct {v2, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 444
    .line 445
    .line 446
    iget-object v5, v15, Ln4/b;->d:Ljava/util/List;

    .line 447
    .line 448
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 449
    .line 450
    .line 451
    move-result-object v5

    .line 452
    :goto_10
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 453
    .line 454
    .line 455
    move-result v6

    .line 456
    if-eqz v6, :cond_1b

    .line 457
    .line 458
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 459
    .line 460
    .line 461
    move-result-object v6

    .line 462
    check-cast v6, Ln4/a;

    .line 463
    .line 464
    iget-object v6, v6, Ln4/a;->a:Ljava/util/Locale;

    .line 465
    .line 466
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 467
    .line 468
    .line 469
    goto :goto_10

    .line 470
    :cond_1b
    const/4 v6, 0x0

    .line 471
    new-array v5, v6, [Ljava/util/Locale;

    .line 472
    .line 473
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v2

    .line 477
    check-cast v2, [Ljava/util/Locale;

    .line 478
    .line 479
    array-length v5, v2

    .line 480
    invoke-static {v2, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v2

    .line 484
    check-cast v2, [Ljava/util/Locale;

    .line 485
    .line 486
    new-instance v5, Landroid/os/LocaleList;

    .line 487
    .line 488
    invoke-direct {v5, v2}, Landroid/os/LocaleList;-><init>([Ljava/util/Locale;)V

    .line 489
    .line 490
    .line 491
    invoke-virtual {v4, v5}, Landroid/graphics/Paint;->setTextLocales(Landroid/os/LocaleList;)V

    .line 492
    .line 493
    .line 494
    :cond_1c
    if-eqz v10, :cond_1d

    .line 495
    .line 496
    const-string v2, ""

    .line 497
    .line 498
    invoke-virtual {v10, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 499
    .line 500
    .line 501
    move-result v2

    .line 502
    if-nez v2, :cond_1d

    .line 503
    .line 504
    invoke-virtual {v4, v10}, Landroid/graphics/Paint;->setFontFeatureSettings(Ljava/lang/String;)V

    .line 505
    .line 506
    .line 507
    :cond_1d
    if-eqz v11, :cond_1e

    .line 508
    .line 509
    sget-object v2, Lr4/p;->c:Lr4/p;

    .line 510
    .line 511
    invoke-virtual {v11, v2}, Lr4/p;->equals(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    move-result v2

    .line 515
    if-nez v2, :cond_1e

    .line 516
    .line 517
    invoke-virtual {v4}, Landroid/graphics/Paint;->getTextScaleX()F

    .line 518
    .line 519
    .line 520
    move-result v2

    .line 521
    iget v5, v11, Lr4/p;->a:F

    .line 522
    .line 523
    mul-float/2addr v2, v5

    .line 524
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->setTextScaleX(F)V

    .line 525
    .line 526
    .line 527
    invoke-virtual {v4}, Landroid/graphics/Paint;->getTextSkewX()F

    .line 528
    .line 529
    .line 530
    move-result v2

    .line 531
    iget v5, v11, Lr4/p;->b:F

    .line 532
    .line 533
    add-float/2addr v2, v5

    .line 534
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->setTextSkewX(F)V

    .line 535
    .line 536
    .line 537
    :cond_1e
    invoke-interface/range {v16 .. v16}, Lr4/o;->a()J

    .line 538
    .line 539
    .line 540
    move-result-wide v5

    .line 541
    invoke-virtual {v4, v5, v6}, Lo4/d;->d(J)V

    .line 542
    .line 543
    .line 544
    invoke-interface/range {v16 .. v16}, Lr4/o;->c()Le3/p;

    .line 545
    .line 546
    .line 547
    move-result-object v2

    .line 548
    const-wide v5, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 549
    .line 550
    .line 551
    .line 552
    .line 553
    invoke-interface/range {v16 .. v16}, Lr4/o;->b()F

    .line 554
    .line 555
    .line 556
    move-result v7

    .line 557
    invoke-virtual {v4, v2, v5, v6, v7}, Lo4/d;->c(Le3/p;JF)V

    .line 558
    .line 559
    .line 560
    iget-object v2, v14, Lg4/g0;->n:Le3/m0;

    .line 561
    .line 562
    invoke-virtual {v4, v2}, Lo4/d;->f(Le3/m0;)V

    .line 563
    .line 564
    .line 565
    iget-object v2, v14, Lg4/g0;->m:Lr4/l;

    .line 566
    .line 567
    invoke-virtual {v4, v2}, Lo4/d;->g(Lr4/l;)V

    .line 568
    .line 569
    .line 570
    iget-object v2, v14, Lg4/g0;->p:Lg3/e;

    .line 571
    .line 572
    invoke-virtual {v4, v2}, Lo4/d;->e(Lg3/e;)V

    .line 573
    .line 574
    .line 575
    invoke-static {v12, v13}, Lt4/o;->b(J)J

    .line 576
    .line 577
    .line 578
    move-result-wide v5

    .line 579
    const-wide v9, 0x100000000L

    .line 580
    .line 581
    .line 582
    .line 583
    .line 584
    invoke-static {v5, v6, v9, v10}, Lt4/p;->a(JJ)Z

    .line 585
    .line 586
    .line 587
    move-result v2

    .line 588
    const/4 v5, 0x0

    .line 589
    if-eqz v2, :cond_21

    .line 590
    .line 591
    invoke-static {v12, v13}, Lt4/o;->c(J)F

    .line 592
    .line 593
    .line 594
    move-result v2

    .line 595
    cmpg-float v2, v2, v5

    .line 596
    .line 597
    if-nez v2, :cond_1f

    .line 598
    .line 599
    goto :goto_11

    .line 600
    :cond_1f
    invoke-virtual {v4}, Landroid/graphics/Paint;->getTextSize()F

    .line 601
    .line 602
    .line 603
    move-result v2

    .line 604
    invoke-virtual {v4}, Landroid/graphics/Paint;->getTextScaleX()F

    .line 605
    .line 606
    .line 607
    move-result v6

    .line 608
    mul-float/2addr v6, v2

    .line 609
    invoke-interface {v3, v12, v13}, Lt4/c;->V(J)F

    .line 610
    .line 611
    .line 612
    move-result v2

    .line 613
    cmpg-float v3, v6, v5

    .line 614
    .line 615
    if-nez v3, :cond_20

    .line 616
    .line 617
    goto :goto_12

    .line 618
    :cond_20
    div-float/2addr v2, v6

    .line 619
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->setLetterSpacing(F)V

    .line 620
    .line 621
    .line 622
    goto :goto_12

    .line 623
    :cond_21
    :goto_11
    invoke-static {v12, v13}, Lt4/o;->b(J)J

    .line 624
    .line 625
    .line 626
    move-result-wide v2

    .line 627
    const-wide v6, 0x200000000L

    .line 628
    .line 629
    .line 630
    .line 631
    .line 632
    invoke-static {v2, v3, v6, v7}, Lt4/p;->a(JJ)Z

    .line 633
    .line 634
    .line 635
    move-result v2

    .line 636
    if-eqz v2, :cond_22

    .line 637
    .line 638
    invoke-static {v12, v13}, Lt4/o;->c(J)F

    .line 639
    .line 640
    .line 641
    move-result v2

    .line 642
    invoke-virtual {v4, v2}, Landroid/graphics/Paint;->setLetterSpacing(F)V

    .line 643
    .line 644
    .line 645
    :cond_22
    :goto_12
    iget-wide v2, v14, Lg4/g0;->l:J

    .line 646
    .line 647
    iget-object v4, v14, Lg4/g0;->i:Lr4/a;

    .line 648
    .line 649
    if-eqz p3, :cond_24

    .line 650
    .line 651
    invoke-static {v12, v13}, Lt4/o;->b(J)J

    .line 652
    .line 653
    .line 654
    move-result-wide v6

    .line 655
    const-wide v9, 0x100000000L

    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    invoke-static {v6, v7, v9, v10}, Lt4/p;->a(JJ)Z

    .line 661
    .line 662
    .line 663
    move-result v6

    .line 664
    if-eqz v6, :cond_24

    .line 665
    .line 666
    invoke-static {v12, v13}, Lt4/o;->c(J)F

    .line 667
    .line 668
    .line 669
    move-result v6

    .line 670
    cmpg-float v6, v6, v5

    .line 671
    .line 672
    if-nez v6, :cond_23

    .line 673
    .line 674
    goto :goto_13

    .line 675
    :cond_23
    move/from16 v6, p5

    .line 676
    .line 677
    goto :goto_14

    .line 678
    :cond_24
    :goto_13
    const/4 v6, 0x0

    .line 679
    :goto_14
    sget-wide v9, Le3/s;->i:J

    .line 680
    .line 681
    invoke-static {v2, v3, v9, v10}, Le3/s;->c(JJ)Z

    .line 682
    .line 683
    .line 684
    move-result v7

    .line 685
    if-nez v7, :cond_25

    .line 686
    .line 687
    sget-wide v14, Le3/s;->h:J

    .line 688
    .line 689
    invoke-static {v2, v3, v14, v15}, Le3/s;->c(JJ)Z

    .line 690
    .line 691
    .line 692
    move-result v7

    .line 693
    if-nez v7, :cond_25

    .line 694
    .line 695
    move/from16 v7, p5

    .line 696
    .line 697
    goto :goto_15

    .line 698
    :cond_25
    const/4 v7, 0x0

    .line 699
    :goto_15
    if-eqz v4, :cond_27

    .line 700
    .line 701
    iget v11, v4, Lr4/a;->a:F

    .line 702
    .line 703
    invoke-static {v11, v5}, Ljava/lang/Float;->compare(FF)I

    .line 704
    .line 705
    .line 706
    move-result v11

    .line 707
    if-nez v11, :cond_26

    .line 708
    .line 709
    goto :goto_16

    .line 710
    :cond_26
    move/from16 v11, p5

    .line 711
    .line 712
    goto :goto_17

    .line 713
    :cond_27
    :goto_16
    const/4 v11, 0x0

    .line 714
    :goto_17
    if-nez v6, :cond_28

    .line 715
    .line 716
    if-nez v7, :cond_28

    .line 717
    .line 718
    if-nez v11, :cond_28

    .line 719
    .line 720
    const/4 v2, 0x0

    .line 721
    goto :goto_1c

    .line 722
    :cond_28
    if-eqz v6, :cond_29

    .line 723
    .line 724
    :goto_18
    move-wide/from16 v30, v12

    .line 725
    .line 726
    goto :goto_19

    .line 727
    :cond_29
    sget-wide v12, Lt4/o;->c:J

    .line 728
    .line 729
    goto :goto_18

    .line 730
    :goto_19
    if-eqz v7, :cond_2a

    .line 731
    .line 732
    move-wide/from16 v35, v2

    .line 733
    .line 734
    goto :goto_1a

    .line 735
    :cond_2a
    move-wide/from16 v35, v9

    .line 736
    .line 737
    :goto_1a
    if-eqz v11, :cond_2b

    .line 738
    .line 739
    move-object/from16 v32, v4

    .line 740
    .line 741
    goto :goto_1b

    .line 742
    :cond_2b
    const/16 v32, 0x0

    .line 743
    .line 744
    :goto_1b
    new-instance v20, Lg4/g0;

    .line 745
    .line 746
    const/16 v38, 0x0

    .line 747
    .line 748
    const v39, 0xf67f

    .line 749
    .line 750
    .line 751
    const-wide/16 v21, 0x0

    .line 752
    .line 753
    const-wide/16 v23, 0x0

    .line 754
    .line 755
    const/16 v25, 0x0

    .line 756
    .line 757
    const/16 v26, 0x0

    .line 758
    .line 759
    const/16 v27, 0x0

    .line 760
    .line 761
    const/16 v28, 0x0

    .line 762
    .line 763
    const/16 v29, 0x0

    .line 764
    .line 765
    const/16 v33, 0x0

    .line 766
    .line 767
    const/16 v34, 0x0

    .line 768
    .line 769
    const/16 v37, 0x0

    .line 770
    .line 771
    invoke-direct/range {v20 .. v39}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 772
    .line 773
    .line 774
    move-object/from16 v2, v20

    .line 775
    .line 776
    :goto_1c
    if-eqz v2, :cond_2d

    .line 777
    .line 778
    iget-object v3, v0, Lo4/c;->f:Ljava/util/List;

    .line 779
    .line 780
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 781
    .line 782
    .line 783
    move-result v3

    .line 784
    add-int/lit8 v3, v3, 0x1

    .line 785
    .line 786
    new-instance v4, Ljava/util/ArrayList;

    .line 787
    .line 788
    invoke-direct {v4, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 789
    .line 790
    .line 791
    const/4 v6, 0x0

    .line 792
    :goto_1d
    if-ge v6, v3, :cond_2e

    .line 793
    .line 794
    if-nez v6, :cond_2c

    .line 795
    .line 796
    new-instance v7, Lg4/e;

    .line 797
    .line 798
    iget-object v9, v0, Lo4/c;->d:Ljava/lang/String;

    .line 799
    .line 800
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 801
    .line 802
    .line 803
    move-result v9

    .line 804
    const/4 v10, 0x0

    .line 805
    invoke-direct {v7, v2, v10, v9}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 806
    .line 807
    .line 808
    goto :goto_1e

    .line 809
    :cond_2c
    iget-object v7, v0, Lo4/c;->f:Ljava/util/List;

    .line 810
    .line 811
    add-int/lit8 v9, v6, -0x1

    .line 812
    .line 813
    invoke-interface {v7, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 814
    .line 815
    .line 816
    move-result-object v7

    .line 817
    check-cast v7, Lg4/e;

    .line 818
    .line 819
    :goto_1e
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 820
    .line 821
    .line 822
    add-int/lit8 v6, v6, 0x1

    .line 823
    .line 824
    goto :goto_1d

    .line 825
    :cond_2d
    iget-object v4, v0, Lo4/c;->f:Ljava/util/List;

    .line 826
    .line 827
    :cond_2e
    iget-object v2, v0, Lo4/c;->d:Ljava/lang/String;

    .line 828
    .line 829
    iget-object v3, v0, Lo4/c;->j:Lo4/d;

    .line 830
    .line 831
    invoke-virtual {v3}, Landroid/graphics/Paint;->getTextSize()F

    .line 832
    .line 833
    .line 834
    move-result v3

    .line 835
    iget-object v6, v0, Lo4/c;->e:Lg4/p0;

    .line 836
    .line 837
    iget-object v7, v0, Lo4/c;->g:Ljava/util/List;

    .line 838
    .line 839
    iget-object v12, v0, Lo4/c;->i:Lt4/c;

    .line 840
    .line 841
    iget-boolean v9, v0, Lo4/c;->n:Z

    .line 842
    .line 843
    sget-object v10, Lo4/b;->a:Lo4/a;

    .line 844
    .line 845
    if-eqz v9, :cond_30

    .line 846
    .line 847
    invoke-static {}, Ls6/h;->d()Z

    .line 848
    .line 849
    .line 850
    move-result v9

    .line 851
    if-eqz v9, :cond_30

    .line 852
    .line 853
    iget-object v9, v6, Lg4/p0;->c:Lg4/y;

    .line 854
    .line 855
    if-eqz v9, :cond_2f

    .line 856
    .line 857
    iget-object v9, v9, Lg4/y;->b:Lg4/w;

    .line 858
    .line 859
    :cond_2f
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 860
    .line 861
    .line 862
    move-result-object v9

    .line 863
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 864
    .line 865
    .line 866
    move-result v10

    .line 867
    const/4 v11, 0x0

    .line 868
    invoke-virtual {v9, v11, v10, v11, v2}, Ls6/h;->g(IIILjava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 869
    .line 870
    .line 871
    move-result-object v9

    .line 872
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 873
    .line 874
    .line 875
    goto :goto_1f

    .line 876
    :cond_30
    move-object v9, v2

    .line 877
    :goto_1f
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 878
    .line 879
    .line 880
    move-result v10

    .line 881
    const-wide/16 v13, 0x0

    .line 882
    .line 883
    const-wide v15, 0xff00000000L

    .line 884
    .line 885
    .line 886
    .line 887
    .line 888
    if-eqz v10, :cond_31

    .line 889
    .line 890
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 891
    .line 892
    .line 893
    move-result v10

    .line 894
    if-eqz v10, :cond_31

    .line 895
    .line 896
    iget-object v10, v6, Lg4/p0;->b:Lg4/t;

    .line 897
    .line 898
    iget-object v10, v10, Lg4/t;->d:Lr4/q;

    .line 899
    .line 900
    sget-object v11, Lr4/q;->c:Lr4/q;

    .line 901
    .line 902
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 903
    .line 904
    .line 905
    move-result v10

    .line 906
    if-eqz v10, :cond_31

    .line 907
    .line 908
    iget-object v10, v6, Lg4/p0;->b:Lg4/t;

    .line 909
    .line 910
    iget-wide v10, v10, Lg4/t;->c:J

    .line 911
    .line 912
    and-long/2addr v10, v15

    .line 913
    cmp-long v10, v10, v13

    .line 914
    .line 915
    if-nez v10, :cond_31

    .line 916
    .line 917
    goto/16 :goto_4f

    .line 918
    .line 919
    :cond_31
    instance-of v10, v9, Landroid/text/Spannable;

    .line 920
    .line 921
    if-eqz v10, :cond_32

    .line 922
    .line 923
    check-cast v9, Landroid/text/Spannable;

    .line 924
    .line 925
    goto :goto_20

    .line 926
    :cond_32
    new-instance v10, Landroid/text/SpannableString;

    .line 927
    .line 928
    invoke-direct {v10, v9}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 929
    .line 930
    .line 931
    move-object v9, v10

    .line 932
    :goto_20
    iget-object v10, v6, Lg4/p0;->a:Lg4/g0;

    .line 933
    .line 934
    iget-object v11, v6, Lg4/p0;->b:Lg4/t;

    .line 935
    .line 936
    iget-object v10, v10, Lg4/g0;->m:Lr4/l;

    .line 937
    .line 938
    move/from16 p3, v5

    .line 939
    .line 940
    sget-object v5, Lr4/l;->c:Lr4/l;

    .line 941
    .line 942
    invoke-static {v10, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 943
    .line 944
    .line 945
    move-result v5

    .line 946
    const/16 v10, 0x21

    .line 947
    .line 948
    if-eqz v5, :cond_33

    .line 949
    .line 950
    sget-object v5, Lo4/b;->a:Lo4/a;

    .line 951
    .line 952
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 953
    .line 954
    .line 955
    move-result v2

    .line 956
    move-wide/from16 v17, v13

    .line 957
    .line 958
    const/4 v13, 0x0

    .line 959
    invoke-interface {v9, v5, v13, v2, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 960
    .line 961
    .line 962
    goto :goto_21

    .line 963
    :cond_33
    move-wide/from16 v17, v13

    .line 964
    .line 965
    :goto_21
    iget-object v2, v6, Lg4/p0;->c:Lg4/y;

    .line 966
    .line 967
    if-eqz v2, :cond_34

    .line 968
    .line 969
    iget-object v2, v2, Lg4/y;->b:Lg4/w;

    .line 970
    .line 971
    if-eqz v2, :cond_34

    .line 972
    .line 973
    iget-boolean v2, v2, Lg4/w;->a:Z

    .line 974
    .line 975
    goto :goto_22

    .line 976
    :cond_34
    const/4 v2, 0x0

    .line 977
    :goto_22
    if-eqz v2, :cond_36

    .line 978
    .line 979
    iget-object v2, v11, Lg4/t;->f:Lr4/i;

    .line 980
    .line 981
    if-nez v2, :cond_36

    .line 982
    .line 983
    iget-wide v1, v11, Lg4/t;->c:J

    .line 984
    .line 985
    invoke-static {v1, v2, v3, v12}, Ljp/fd;->f(JFLt4/c;)F

    .line 986
    .line 987
    .line 988
    move-result v1

    .line 989
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 990
    .line 991
    .line 992
    move-result v2

    .line 993
    if-nez v2, :cond_35

    .line 994
    .line 995
    new-instance v2, Lj4/g;

    .line 996
    .line 997
    invoke-direct {v2, v1}, Lj4/g;-><init>(F)V

    .line 998
    .line 999
    .line 1000
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1001
    .line 1002
    .line 1003
    move-result v1

    .line 1004
    const/4 v13, 0x0

    .line 1005
    invoke-interface {v9, v2, v13, v1, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1006
    .line 1007
    .line 1008
    :cond_35
    const/4 v13, 0x0

    .line 1009
    goto :goto_28

    .line 1010
    :cond_36
    iget-object v2, v11, Lg4/t;->f:Lr4/i;

    .line 1011
    .line 1012
    if-nez v2, :cond_37

    .line 1013
    .line 1014
    sget-object v2, Lr4/i;->c:Lr4/i;

    .line 1015
    .line 1016
    :cond_37
    iget-wide v13, v11, Lg4/t;->c:J

    .line 1017
    .line 1018
    invoke-static {v13, v14, v3, v12}, Ljp/fd;->f(JFLt4/c;)F

    .line 1019
    .line 1020
    .line 1021
    move-result v21

    .line 1022
    invoke-static/range {v21 .. v21}, Ljava/lang/Float;->isNaN(F)Z

    .line 1023
    .line 1024
    .line 1025
    move-result v5

    .line 1026
    if-nez v5, :cond_35

    .line 1027
    .line 1028
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1029
    .line 1030
    .line 1031
    move-result v5

    .line 1032
    if-nez v5, :cond_38

    .line 1033
    .line 1034
    goto :goto_23

    .line 1035
    :cond_38
    invoke-static {v9}, Lly0/p;->N(Ljava/lang/CharSequence;)C

    .line 1036
    .line 1037
    .line 1038
    move-result v5

    .line 1039
    if-ne v5, v1, :cond_39

    .line 1040
    .line 1041
    :goto_23
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1042
    .line 1043
    .line 1044
    move-result v1

    .line 1045
    add-int/lit8 v1, v1, 0x1

    .line 1046
    .line 1047
    :goto_24
    move/from16 v22, v1

    .line 1048
    .line 1049
    goto :goto_25

    .line 1050
    :cond_39
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1051
    .line 1052
    .line 1053
    move-result v1

    .line 1054
    goto :goto_24

    .line 1055
    :goto_25
    new-instance v20, Lj4/h;

    .line 1056
    .line 1057
    iget v1, v2, Lr4/i;->b:I

    .line 1058
    .line 1059
    and-int/lit8 v5, v1, 0x1

    .line 1060
    .line 1061
    if-lez v5, :cond_3a

    .line 1062
    .line 1063
    move/from16 v23, p5

    .line 1064
    .line 1065
    goto :goto_26

    .line 1066
    :cond_3a
    const/16 v23, 0x0

    .line 1067
    .line 1068
    :goto_26
    and-int/lit8 v1, v1, 0x10

    .line 1069
    .line 1070
    if-lez v1, :cond_3b

    .line 1071
    .line 1072
    move/from16 v24, p5

    .line 1073
    .line 1074
    goto :goto_27

    .line 1075
    :cond_3b
    const/16 v24, 0x0

    .line 1076
    .line 1077
    :goto_27
    iget v1, v2, Lr4/i;->a:F

    .line 1078
    .line 1079
    const/16 v26, 0x0

    .line 1080
    .line 1081
    move/from16 v25, v1

    .line 1082
    .line 1083
    invoke-direct/range {v20 .. v26}, Lj4/h;-><init>(FIZZFZ)V

    .line 1084
    .line 1085
    .line 1086
    move-object/from16 v1, v20

    .line 1087
    .line 1088
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1089
    .line 1090
    .line 1091
    move-result v2

    .line 1092
    const/4 v13, 0x0

    .line 1093
    invoke-interface {v9, v1, v13, v2, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1094
    .line 1095
    .line 1096
    :goto_28
    iget-object v1, v11, Lg4/t;->d:Lr4/q;

    .line 1097
    .line 1098
    if-eqz v1, :cond_44

    .line 1099
    .line 1100
    move/from16 p4, v13

    .line 1101
    .line 1102
    iget-wide v13, v1, Lr4/q;->a:J

    .line 1103
    .line 1104
    iget-wide v1, v1, Lr4/q;->b:J

    .line 1105
    .line 1106
    move-object v5, v11

    .line 1107
    invoke-static/range {p4 .. p4}, Lgq/b;->c(I)J

    .line 1108
    .line 1109
    .line 1110
    move-result-wide v10

    .line 1111
    invoke-static {v13, v14, v10, v11}, Lt4/o;->a(JJ)Z

    .line 1112
    .line 1113
    .line 1114
    move-result v10

    .line 1115
    if-eqz v10, :cond_3c

    .line 1116
    .line 1117
    invoke-static/range {p4 .. p4}, Lgq/b;->c(I)J

    .line 1118
    .line 1119
    .line 1120
    move-result-wide v10

    .line 1121
    invoke-static {v1, v2, v10, v11}, Lt4/o;->a(JJ)Z

    .line 1122
    .line 1123
    .line 1124
    move-result v10

    .line 1125
    if-nez v10, :cond_3d

    .line 1126
    .line 1127
    :cond_3c
    and-long v10, v13, v15

    .line 1128
    .line 1129
    cmp-long v10, v10, v17

    .line 1130
    .line 1131
    if-nez v10, :cond_3e

    .line 1132
    .line 1133
    :cond_3d
    :goto_29
    move-object/from16 v16, v7

    .line 1134
    .line 1135
    move-object v15, v8

    .line 1136
    goto/16 :goto_2c

    .line 1137
    .line 1138
    :cond_3e
    and-long v10, v1, v15

    .line 1139
    .line 1140
    cmp-long v10, v10, v17

    .line 1141
    .line 1142
    if-nez v10, :cond_3f

    .line 1143
    .line 1144
    goto :goto_29

    .line 1145
    :cond_3f
    invoke-static {v13, v14}, Lt4/o;->b(J)J

    .line 1146
    .line 1147
    .line 1148
    move-result-wide v10

    .line 1149
    move-object/from16 v16, v7

    .line 1150
    .line 1151
    move-object v15, v8

    .line 1152
    const-wide v7, 0x100000000L

    .line 1153
    .line 1154
    .line 1155
    .line 1156
    .line 1157
    invoke-static {v10, v11, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1158
    .line 1159
    .line 1160
    move-result v17

    .line 1161
    if-eqz v17, :cond_40

    .line 1162
    .line 1163
    invoke-interface {v12, v13, v14}, Lt4/c;->V(J)F

    .line 1164
    .line 1165
    .line 1166
    move-result v10

    .line 1167
    const-wide v7, 0x200000000L

    .line 1168
    .line 1169
    .line 1170
    .line 1171
    .line 1172
    goto :goto_2a

    .line 1173
    :cond_40
    const-wide v7, 0x200000000L

    .line 1174
    .line 1175
    .line 1176
    .line 1177
    .line 1178
    invoke-static {v10, v11, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1179
    .line 1180
    .line 1181
    move-result v10

    .line 1182
    if-eqz v10, :cond_41

    .line 1183
    .line 1184
    invoke-static {v13, v14}, Lt4/o;->c(J)F

    .line 1185
    .line 1186
    .line 1187
    move-result v10

    .line 1188
    mul-float/2addr v10, v3

    .line 1189
    goto :goto_2a

    .line 1190
    :cond_41
    move/from16 v10, p3

    .line 1191
    .line 1192
    :goto_2a
    invoke-static {v1, v2}, Lt4/o;->b(J)J

    .line 1193
    .line 1194
    .line 1195
    move-result-wide v13

    .line 1196
    const-wide v7, 0x100000000L

    .line 1197
    .line 1198
    .line 1199
    .line 1200
    .line 1201
    invoke-static {v13, v14, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1202
    .line 1203
    .line 1204
    move-result v11

    .line 1205
    if-eqz v11, :cond_42

    .line 1206
    .line 1207
    invoke-interface {v12, v1, v2}, Lt4/c;->V(J)F

    .line 1208
    .line 1209
    .line 1210
    move-result v1

    .line 1211
    goto :goto_2b

    .line 1212
    :cond_42
    const-wide v7, 0x200000000L

    .line 1213
    .line 1214
    .line 1215
    .line 1216
    .line 1217
    invoke-static {v13, v14, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1218
    .line 1219
    .line 1220
    move-result v11

    .line 1221
    if-eqz v11, :cond_43

    .line 1222
    .line 1223
    invoke-static {v1, v2}, Lt4/o;->c(J)F

    .line 1224
    .line 1225
    .line 1226
    move-result v1

    .line 1227
    mul-float/2addr v1, v3

    .line 1228
    goto :goto_2b

    .line 1229
    :cond_43
    move/from16 v1, p3

    .line 1230
    .line 1231
    :goto_2b
    new-instance v2, Landroid/text/style/LeadingMarginSpan$Standard;

    .line 1232
    .line 1233
    float-to-double v7, v10

    .line 1234
    invoke-static {v7, v8}, Ljava/lang/Math;->ceil(D)D

    .line 1235
    .line 1236
    .line 1237
    move-result-wide v7

    .line 1238
    double-to-float v3, v7

    .line 1239
    float-to-int v3, v3

    .line 1240
    float-to-double v7, v1

    .line 1241
    invoke-static {v7, v8}, Ljava/lang/Math;->ceil(D)D

    .line 1242
    .line 1243
    .line 1244
    move-result-wide v7

    .line 1245
    double-to-float v1, v7

    .line 1246
    float-to-int v1, v1

    .line 1247
    invoke-direct {v2, v3, v1}, Landroid/text/style/LeadingMarginSpan$Standard;-><init>(II)V

    .line 1248
    .line 1249
    .line 1250
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1251
    .line 1252
    .line 1253
    move-result v1

    .line 1254
    const/16 v3, 0x21

    .line 1255
    .line 1256
    const/4 v13, 0x0

    .line 1257
    invoke-interface {v9, v2, v13, v1, v3}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1258
    .line 1259
    .line 1260
    goto :goto_2c

    .line 1261
    :cond_44
    move-object v5, v11

    .line 1262
    goto/16 :goto_29

    .line 1263
    .line 1264
    :goto_2c
    new-instance v1, Ljava/util/ArrayList;

    .line 1265
    .line 1266
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 1267
    .line 1268
    .line 1269
    move-result v2

    .line 1270
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 1271
    .line 1272
    .line 1273
    move-object v2, v4

    .line 1274
    check-cast v2, Ljava/util/Collection;

    .line 1275
    .line 1276
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 1277
    .line 1278
    .line 1279
    move-result v3

    .line 1280
    const/4 v7, 0x0

    .line 1281
    :goto_2d
    if-ge v7, v3, :cond_49

    .line 1282
    .line 1283
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1284
    .line 1285
    .line 1286
    move-result-object v8

    .line 1287
    check-cast v8, Lg4/e;

    .line 1288
    .line 1289
    iget-object v10, v8, Lg4/e;->a:Ljava/lang/Object;

    .line 1290
    .line 1291
    instance-of v11, v10, Lg4/g0;

    .line 1292
    .line 1293
    if-eqz v11, :cond_48

    .line 1294
    .line 1295
    move-object v11, v10

    .line 1296
    check-cast v11, Lg4/g0;

    .line 1297
    .line 1298
    iget-object v13, v11, Lg4/g0;->f:Lk4/n;

    .line 1299
    .line 1300
    if-nez v13, :cond_46

    .line 1301
    .line 1302
    iget-object v13, v11, Lg4/g0;->d:Lk4/t;

    .line 1303
    .line 1304
    if-nez v13, :cond_46

    .line 1305
    .line 1306
    iget-object v11, v11, Lg4/g0;->c:Lk4/x;

    .line 1307
    .line 1308
    if-eqz v11, :cond_45

    .line 1309
    .line 1310
    goto :goto_2e

    .line 1311
    :cond_45
    const/4 v11, 0x0

    .line 1312
    goto :goto_2f

    .line 1313
    :cond_46
    :goto_2e
    move/from16 v11, p5

    .line 1314
    .line 1315
    :goto_2f
    if-nez v11, :cond_47

    .line 1316
    .line 1317
    check-cast v10, Lg4/g0;

    .line 1318
    .line 1319
    iget-object v10, v10, Lg4/g0;->e:Lk4/u;

    .line 1320
    .line 1321
    if-eqz v10, :cond_48

    .line 1322
    .line 1323
    :cond_47
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1324
    .line 1325
    .line 1326
    :cond_48
    add-int/lit8 v7, v7, 0x1

    .line 1327
    .line 1328
    goto :goto_2d

    .line 1329
    :cond_49
    iget-object v3, v6, Lg4/p0;->a:Lg4/g0;

    .line 1330
    .line 1331
    iget-object v6, v3, Lg4/g0;->f:Lk4/n;

    .line 1332
    .line 1333
    if-nez v6, :cond_4b

    .line 1334
    .line 1335
    iget-object v7, v3, Lg4/g0;->d:Lk4/t;

    .line 1336
    .line 1337
    if-nez v7, :cond_4b

    .line 1338
    .line 1339
    iget-object v7, v3, Lg4/g0;->c:Lk4/x;

    .line 1340
    .line 1341
    if-eqz v7, :cond_4a

    .line 1342
    .line 1343
    goto :goto_30

    .line 1344
    :cond_4a
    const/4 v7, 0x0

    .line 1345
    goto :goto_31

    .line 1346
    :cond_4b
    :goto_30
    move/from16 v7, p5

    .line 1347
    .line 1348
    :goto_31
    if-nez v7, :cond_4d

    .line 1349
    .line 1350
    iget-object v7, v3, Lg4/g0;->e:Lk4/u;

    .line 1351
    .line 1352
    if-eqz v7, :cond_4c

    .line 1353
    .line 1354
    goto :goto_32

    .line 1355
    :cond_4c
    const/4 v3, 0x0

    .line 1356
    goto :goto_33

    .line 1357
    :cond_4d
    :goto_32
    iget-object v7, v3, Lg4/g0;->c:Lk4/x;

    .line 1358
    .line 1359
    iget-object v8, v3, Lg4/g0;->d:Lk4/t;

    .line 1360
    .line 1361
    iget-object v3, v3, Lg4/g0;->e:Lk4/u;

    .line 1362
    .line 1363
    new-instance v20, Lg4/g0;

    .line 1364
    .line 1365
    const/16 v38, 0x0

    .line 1366
    .line 1367
    const v39, 0xffc3

    .line 1368
    .line 1369
    .line 1370
    const-wide/16 v21, 0x0

    .line 1371
    .line 1372
    const-wide/16 v23, 0x0

    .line 1373
    .line 1374
    const/16 v29, 0x0

    .line 1375
    .line 1376
    const-wide/16 v30, 0x0

    .line 1377
    .line 1378
    const/16 v32, 0x0

    .line 1379
    .line 1380
    const/16 v33, 0x0

    .line 1381
    .line 1382
    const/16 v34, 0x0

    .line 1383
    .line 1384
    const-wide/16 v35, 0x0

    .line 1385
    .line 1386
    const/16 v37, 0x0

    .line 1387
    .line 1388
    move-object/from16 v27, v3

    .line 1389
    .line 1390
    move-object/from16 v28, v6

    .line 1391
    .line 1392
    move-object/from16 v25, v7

    .line 1393
    .line 1394
    move-object/from16 v26, v8

    .line 1395
    .line 1396
    invoke-direct/range {v20 .. v39}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 1397
    .line 1398
    .line 1399
    move-object/from16 v3, v20

    .line 1400
    .line 1401
    :goto_33
    new-instance v6, Lp4/a;

    .line 1402
    .line 1403
    const/4 v13, 0x0

    .line 1404
    invoke-direct {v6, v13, v9, v15}, Lp4/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1405
    .line 1406
    .line 1407
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1408
    .line 1409
    .line 1410
    move-result v7

    .line 1411
    move/from16 v8, p5

    .line 1412
    .line 1413
    if-gt v7, v8, :cond_50

    .line 1414
    .line 1415
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 1416
    .line 1417
    .line 1418
    move-result v7

    .line 1419
    if-nez v7, :cond_4f

    .line 1420
    .line 1421
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1422
    .line 1423
    .line 1424
    move-result-object v7

    .line 1425
    check-cast v7, Lg4/e;

    .line 1426
    .line 1427
    iget-object v7, v7, Lg4/e;->a:Ljava/lang/Object;

    .line 1428
    .line 1429
    check-cast v7, Lg4/g0;

    .line 1430
    .line 1431
    if-nez v3, :cond_4e

    .line 1432
    .line 1433
    goto :goto_34

    .line 1434
    :cond_4e
    invoke-virtual {v3, v7}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 1435
    .line 1436
    .line 1437
    move-result-object v7

    .line 1438
    :goto_34
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v3

    .line 1442
    check-cast v3, Lg4/e;

    .line 1443
    .line 1444
    iget v3, v3, Lg4/e;->b:I

    .line 1445
    .line 1446
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v3

    .line 1450
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1451
    .line 1452
    .line 1453
    move-result-object v1

    .line 1454
    check-cast v1, Lg4/e;

    .line 1455
    .line 1456
    iget v1, v1, Lg4/e;->c:I

    .line 1457
    .line 1458
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1459
    .line 1460
    .line 1461
    move-result-object v1

    .line 1462
    invoke-virtual {v6, v7, v3, v1}, Lp4/a;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1463
    .line 1464
    .line 1465
    :cond_4f
    move-object/from16 v17, v2

    .line 1466
    .line 1467
    move-object/from16 v20, v5

    .line 1468
    .line 1469
    goto/16 :goto_3b

    .line 1470
    .line 1471
    :cond_50
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1472
    .line 1473
    .line 1474
    move-result v7

    .line 1475
    mul-int/lit8 v8, v7, 0x2

    .line 1476
    .line 1477
    new-array v10, v8, [I

    .line 1478
    .line 1479
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1480
    .line 1481
    .line 1482
    move-result v11

    .line 1483
    const/4 v13, 0x0

    .line 1484
    :goto_35
    if-ge v13, v11, :cond_51

    .line 1485
    .line 1486
    invoke-virtual {v1, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1487
    .line 1488
    .line 1489
    move-result-object v14

    .line 1490
    check-cast v14, Lg4/e;

    .line 1491
    .line 1492
    iget v15, v14, Lg4/e;->b:I

    .line 1493
    .line 1494
    aput v15, v10, v13

    .line 1495
    .line 1496
    add-int v15, v13, v7

    .line 1497
    .line 1498
    iget v14, v14, Lg4/e;->c:I

    .line 1499
    .line 1500
    aput v14, v10, v15

    .line 1501
    .line 1502
    add-int/lit8 v13, v13, 0x1

    .line 1503
    .line 1504
    goto :goto_35

    .line 1505
    :cond_51
    const/4 v13, 0x1

    .line 1506
    if-le v8, v13, :cond_52

    .line 1507
    .line 1508
    invoke-static {v10}, Ljava/util/Arrays;->sort([I)V

    .line 1509
    .line 1510
    .line 1511
    :cond_52
    if-eqz v8, :cond_77

    .line 1512
    .line 1513
    const/4 v13, 0x0

    .line 1514
    aget v7, v10, v13

    .line 1515
    .line 1516
    move v11, v7

    .line 1517
    const/4 v7, 0x0

    .line 1518
    :goto_36
    if-ge v7, v8, :cond_4f

    .line 1519
    .line 1520
    aget v13, v10, v7

    .line 1521
    .line 1522
    if-ne v13, v11, :cond_53

    .line 1523
    .line 1524
    move-object/from16 v19, v1

    .line 1525
    .line 1526
    move-object/from16 v17, v2

    .line 1527
    .line 1528
    move-object/from16 v18, v3

    .line 1529
    .line 1530
    move-object/from16 v20, v5

    .line 1531
    .line 1532
    goto :goto_3a

    .line 1533
    :cond_53
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 1534
    .line 1535
    .line 1536
    move-result v14

    .line 1537
    move-object/from16 v17, v2

    .line 1538
    .line 1539
    move-object v2, v3

    .line 1540
    const/4 v15, 0x0

    .line 1541
    :goto_37
    if-ge v15, v14, :cond_56

    .line 1542
    .line 1543
    invoke-virtual {v1, v15}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1544
    .line 1545
    .line 1546
    move-result-object v18

    .line 1547
    move-object/from16 v19, v1

    .line 1548
    .line 1549
    move-object/from16 v1, v18

    .line 1550
    .line 1551
    check-cast v1, Lg4/e;

    .line 1552
    .line 1553
    move-object/from16 v18, v3

    .line 1554
    .line 1555
    iget v3, v1, Lg4/e;->b:I

    .line 1556
    .line 1557
    move-object/from16 v20, v5

    .line 1558
    .line 1559
    iget v5, v1, Lg4/e;->c:I

    .line 1560
    .line 1561
    if-eq v3, v5, :cond_55

    .line 1562
    .line 1563
    invoke-static {v11, v13, v3, v5}, Lg4/h;->b(IIII)Z

    .line 1564
    .line 1565
    .line 1566
    move-result v3

    .line 1567
    if-eqz v3, :cond_55

    .line 1568
    .line 1569
    iget-object v1, v1, Lg4/e;->a:Ljava/lang/Object;

    .line 1570
    .line 1571
    check-cast v1, Lg4/g0;

    .line 1572
    .line 1573
    if-nez v2, :cond_54

    .line 1574
    .line 1575
    :goto_38
    move-object v2, v1

    .line 1576
    goto :goto_39

    .line 1577
    :cond_54
    invoke-virtual {v2, v1}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 1578
    .line 1579
    .line 1580
    move-result-object v1

    .line 1581
    goto :goto_38

    .line 1582
    :cond_55
    :goto_39
    add-int/lit8 v15, v15, 0x1

    .line 1583
    .line 1584
    move-object/from16 v3, v18

    .line 1585
    .line 1586
    move-object/from16 v1, v19

    .line 1587
    .line 1588
    move-object/from16 v5, v20

    .line 1589
    .line 1590
    goto :goto_37

    .line 1591
    :cond_56
    move-object/from16 v19, v1

    .line 1592
    .line 1593
    move-object/from16 v18, v3

    .line 1594
    .line 1595
    move-object/from16 v20, v5

    .line 1596
    .line 1597
    if-eqz v2, :cond_57

    .line 1598
    .line 1599
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1600
    .line 1601
    .line 1602
    move-result-object v1

    .line 1603
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1604
    .line 1605
    .line 1606
    move-result-object v3

    .line 1607
    invoke-virtual {v6, v2, v1, v3}, Lp4/a;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1608
    .line 1609
    .line 1610
    :cond_57
    move v11, v13

    .line 1611
    :goto_3a
    add-int/lit8 v7, v7, 0x1

    .line 1612
    .line 1613
    move-object/from16 v2, v17

    .line 1614
    .line 1615
    move-object/from16 v3, v18

    .line 1616
    .line 1617
    move-object/from16 v1, v19

    .line 1618
    .line 1619
    move-object/from16 v5, v20

    .line 1620
    .line 1621
    goto :goto_36

    .line 1622
    :goto_3b
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 1623
    .line 1624
    .line 1625
    move-result v1

    .line 1626
    const/4 v2, 0x0

    .line 1627
    const/4 v6, 0x0

    .line 1628
    :goto_3c
    if-ge v6, v1, :cond_68

    .line 1629
    .line 1630
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v3

    .line 1634
    check-cast v3, Lg4/e;

    .line 1635
    .line 1636
    iget-object v5, v3, Lg4/e;->a:Ljava/lang/Object;

    .line 1637
    .line 1638
    instance-of v7, v5, Lg4/g0;

    .line 1639
    .line 1640
    if-eqz v7, :cond_58

    .line 1641
    .line 1642
    iget v13, v3, Lg4/e;->b:I

    .line 1643
    .line 1644
    iget v14, v3, Lg4/e;->c:I

    .line 1645
    .line 1646
    if-ltz v13, :cond_58

    .line 1647
    .line 1648
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1649
    .line 1650
    .line 1651
    move-result v3

    .line 1652
    if-ge v13, v3, :cond_58

    .line 1653
    .line 1654
    if-le v14, v13, :cond_58

    .line 1655
    .line 1656
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1657
    .line 1658
    .line 1659
    move-result v3

    .line 1660
    if-le v14, v3, :cond_59

    .line 1661
    .line 1662
    :cond_58
    move/from16 p6, v1

    .line 1663
    .line 1664
    move v15, v2

    .line 1665
    move/from16 v19, v6

    .line 1666
    .line 1667
    move-object v3, v12

    .line 1668
    move-object/from16 v1, v20

    .line 1669
    .line 1670
    goto/16 :goto_44

    .line 1671
    .line 1672
    :cond_59
    check-cast v5, Lg4/g0;

    .line 1673
    .line 1674
    iget-wide v7, v5, Lg4/g0;->h:J

    .line 1675
    .line 1676
    iget-object v3, v5, Lg4/g0;->i:Lr4/a;

    .line 1677
    .line 1678
    iget-object v10, v5, Lg4/g0;->a:Lr4/o;

    .line 1679
    .line 1680
    if-eqz v3, :cond_5a

    .line 1681
    .line 1682
    iget v3, v3, Lr4/a;->a:F

    .line 1683
    .line 1684
    new-instance v11, Lj4/a;

    .line 1685
    .line 1686
    const/4 v15, 0x0

    .line 1687
    invoke-direct {v11, v15, v3}, Lj4/a;-><init>(IF)V

    .line 1688
    .line 1689
    .line 1690
    const/16 v3, 0x21

    .line 1691
    .line 1692
    invoke-interface {v9, v11, v13, v14, v3}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1693
    .line 1694
    .line 1695
    :cond_5a
    move v3, v1

    .line 1696
    move v15, v2

    .line 1697
    invoke-interface {v10}, Lr4/o;->a()J

    .line 1698
    .line 1699
    .line 1700
    move-result-wide v1

    .line 1701
    invoke-static {v9, v1, v2, v13, v14}, Ljp/fd;->g(Landroid/text/Spannable;JII)V

    .line 1702
    .line 1703
    .line 1704
    invoke-interface {v10}, Lr4/o;->c()Le3/p;

    .line 1705
    .line 1706
    .line 1707
    move-result-object v1

    .line 1708
    invoke-interface {v10}, Lr4/o;->b()F

    .line 1709
    .line 1710
    .line 1711
    move-result v2

    .line 1712
    if-eqz v1, :cond_5c

    .line 1713
    .line 1714
    instance-of v10, v1, Le3/p0;

    .line 1715
    .line 1716
    if-eqz v10, :cond_5b

    .line 1717
    .line 1718
    check-cast v1, Le3/p0;

    .line 1719
    .line 1720
    iget-wide v1, v1, Le3/p0;->a:J

    .line 1721
    .line 1722
    invoke-static {v9, v1, v2, v13, v14}, Ljp/fd;->g(Landroid/text/Spannable;JII)V

    .line 1723
    .line 1724
    .line 1725
    goto :goto_3d

    .line 1726
    :cond_5b
    new-instance v10, Lq4/b;

    .line 1727
    .line 1728
    check-cast v1, Le3/l0;

    .line 1729
    .line 1730
    invoke-direct {v10, v1, v2}, Lq4/b;-><init>(Le3/l0;F)V

    .line 1731
    .line 1732
    .line 1733
    const/16 v1, 0x21

    .line 1734
    .line 1735
    invoke-interface {v9, v10, v13, v14, v1}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1736
    .line 1737
    .line 1738
    :cond_5c
    :goto_3d
    iget-object v1, v5, Lg4/g0;->m:Lr4/l;

    .line 1739
    .line 1740
    if-eqz v1, :cond_5f

    .line 1741
    .line 1742
    iget v1, v1, Lr4/l;->a:I

    .line 1743
    .line 1744
    new-instance v2, Lj4/k;

    .line 1745
    .line 1746
    or-int/lit8 v10, v1, 0x1

    .line 1747
    .line 1748
    if-ne v10, v1, :cond_5d

    .line 1749
    .line 1750
    const/4 v10, 0x1

    .line 1751
    goto :goto_3e

    .line 1752
    :cond_5d
    const/4 v10, 0x0

    .line 1753
    :goto_3e
    or-int/lit8 v11, v1, 0x2

    .line 1754
    .line 1755
    if-ne v11, v1, :cond_5e

    .line 1756
    .line 1757
    const/4 v1, 0x1

    .line 1758
    goto :goto_3f

    .line 1759
    :cond_5e
    const/4 v1, 0x0

    .line 1760
    :goto_3f
    invoke-direct {v2, v10, v1}, Lj4/k;-><init>(ZZ)V

    .line 1761
    .line 1762
    .line 1763
    const/16 v1, 0x21

    .line 1764
    .line 1765
    invoke-interface {v9, v2, v13, v14, v1}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1766
    .line 1767
    .line 1768
    goto :goto_40

    .line 1769
    :cond_5f
    const/16 v1, 0x21

    .line 1770
    .line 1771
    :goto_40
    iget-wide v10, v5, Lg4/g0;->b:J

    .line 1772
    .line 1773
    move v2, v1

    .line 1774
    move-object/from16 v1, v20

    .line 1775
    .line 1776
    invoke-static/range {v9 .. v14}, Ljp/fd;->h(Landroid/text/Spannable;JLt4/c;II)V

    .line 1777
    .line 1778
    .line 1779
    iget-object v10, v5, Lg4/g0;->g:Ljava/lang/String;

    .line 1780
    .line 1781
    if-eqz v10, :cond_60

    .line 1782
    .line 1783
    new-instance v11, Lj4/b;

    .line 1784
    .line 1785
    move/from16 p6, v3

    .line 1786
    .line 1787
    const/4 v3, 0x0

    .line 1788
    invoke-direct {v11, v10, v3}, Lj4/b;-><init>(Ljava/lang/Object;I)V

    .line 1789
    .line 1790
    .line 1791
    invoke-interface {v9, v11, v13, v14, v2}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1792
    .line 1793
    .line 1794
    goto :goto_41

    .line 1795
    :cond_60
    move/from16 p6, v3

    .line 1796
    .line 1797
    const/4 v3, 0x0

    .line 1798
    :goto_41
    iget-object v10, v5, Lg4/g0;->j:Lr4/p;

    .line 1799
    .line 1800
    if-eqz v10, :cond_61

    .line 1801
    .line 1802
    new-instance v11, Landroid/text/style/ScaleXSpan;

    .line 1803
    .line 1804
    iget v3, v10, Lr4/p;->a:F

    .line 1805
    .line 1806
    invoke-direct {v11, v3}, Landroid/text/style/ScaleXSpan;-><init>(F)V

    .line 1807
    .line 1808
    .line 1809
    invoke-interface {v9, v11, v13, v14, v2}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1810
    .line 1811
    .line 1812
    new-instance v3, Lj4/a;

    .line 1813
    .line 1814
    iget v10, v10, Lr4/p;->b:F

    .line 1815
    .line 1816
    const/4 v11, 0x1

    .line 1817
    invoke-direct {v3, v11, v10}, Lj4/a;-><init>(IF)V

    .line 1818
    .line 1819
    .line 1820
    invoke-interface {v9, v3, v13, v14, v2}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1821
    .line 1822
    .line 1823
    goto :goto_42

    .line 1824
    :cond_61
    const/4 v11, 0x1

    .line 1825
    :goto_42
    iget-object v3, v5, Lg4/g0;->k:Ln4/b;

    .line 1826
    .line 1827
    invoke-static {v9, v3, v13, v14}, Ljp/fd;->i(Landroid/text/Spannable;Ln4/b;II)V

    .line 1828
    .line 1829
    .line 1830
    move-object v3, v12

    .line 1831
    iget-wide v11, v5, Lg4/g0;->l:J

    .line 1832
    .line 1833
    const-wide/16 v18, 0x10

    .line 1834
    .line 1835
    cmp-long v10, v11, v18

    .line 1836
    .line 1837
    if-eqz v10, :cond_62

    .line 1838
    .line 1839
    new-instance v10, Landroid/text/style/BackgroundColorSpan;

    .line 1840
    .line 1841
    invoke-static {v11, v12}, Le3/j0;->z(J)I

    .line 1842
    .line 1843
    .line 1844
    move-result v11

    .line 1845
    invoke-direct {v10, v11}, Landroid/text/style/BackgroundColorSpan;-><init>(I)V

    .line 1846
    .line 1847
    .line 1848
    invoke-interface {v9, v10, v13, v14, v2}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1849
    .line 1850
    .line 1851
    :cond_62
    iget-object v10, v5, Lg4/g0;->n:Le3/m0;

    .line 1852
    .line 1853
    if-eqz v10, :cond_64

    .line 1854
    .line 1855
    iget-wide v11, v10, Le3/m0;->b:J

    .line 1856
    .line 1857
    new-instance v2, Lj4/j;

    .line 1858
    .line 1859
    move/from16 v19, v6

    .line 1860
    .line 1861
    move-wide/from16 v20, v7

    .line 1862
    .line 1863
    iget-wide v6, v10, Le3/m0;->a:J

    .line 1864
    .line 1865
    invoke-static {v6, v7}, Le3/j0;->z(J)I

    .line 1866
    .line 1867
    .line 1868
    move-result v6

    .line 1869
    const/16 v7, 0x20

    .line 1870
    .line 1871
    shr-long v7, v11, v7

    .line 1872
    .line 1873
    long-to-int v7, v7

    .line 1874
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1875
    .line 1876
    .line 1877
    move-result v7

    .line 1878
    const-wide v22, 0xffffffffL

    .line 1879
    .line 1880
    .line 1881
    .line 1882
    .line 1883
    and-long v11, v11, v22

    .line 1884
    .line 1885
    long-to-int v8, v11

    .line 1886
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1887
    .line 1888
    .line 1889
    move-result v8

    .line 1890
    iget v10, v10, Le3/m0;->c:F

    .line 1891
    .line 1892
    cmpg-float v11, v10, p3

    .line 1893
    .line 1894
    if-nez v11, :cond_63

    .line 1895
    .line 1896
    const/4 v10, 0x1

    .line 1897
    :cond_63
    invoke-direct {v2, v6, v7, v8, v10}, Lj4/j;-><init>(IFFF)V

    .line 1898
    .line 1899
    .line 1900
    const/16 v6, 0x21

    .line 1901
    .line 1902
    invoke-interface {v9, v2, v13, v14, v6}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1903
    .line 1904
    .line 1905
    goto :goto_43

    .line 1906
    :cond_64
    move/from16 v19, v6

    .line 1907
    .line 1908
    move-wide/from16 v20, v7

    .line 1909
    .line 1910
    move v6, v2

    .line 1911
    :goto_43
    iget-object v2, v5, Lg4/g0;->p:Lg3/e;

    .line 1912
    .line 1913
    if-eqz v2, :cond_65

    .line 1914
    .line 1915
    new-instance v5, Lq4/a;

    .line 1916
    .line 1917
    invoke-direct {v5, v2}, Lq4/a;-><init>(Lg3/e;)V

    .line 1918
    .line 1919
    .line 1920
    invoke-interface {v9, v5, v13, v14, v6}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 1921
    .line 1922
    .line 1923
    :cond_65
    invoke-static/range {v20 .. v21}, Lt4/o;->b(J)J

    .line 1924
    .line 1925
    .line 1926
    move-result-wide v5

    .line 1927
    const-wide v7, 0x100000000L

    .line 1928
    .line 1929
    .line 1930
    .line 1931
    .line 1932
    invoke-static {v5, v6, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1933
    .line 1934
    .line 1935
    move-result v2

    .line 1936
    if-nez v2, :cond_66

    .line 1937
    .line 1938
    invoke-static/range {v20 .. v21}, Lt4/o;->b(J)J

    .line 1939
    .line 1940
    .line 1941
    move-result-wide v5

    .line 1942
    const-wide v7, 0x200000000L

    .line 1943
    .line 1944
    .line 1945
    .line 1946
    .line 1947
    invoke-static {v5, v6, v7, v8}, Lt4/p;->a(JJ)Z

    .line 1948
    .line 1949
    .line 1950
    move-result v2

    .line 1951
    if-eqz v2, :cond_67

    .line 1952
    .line 1953
    :cond_66
    const/4 v2, 0x1

    .line 1954
    goto :goto_45

    .line 1955
    :cond_67
    :goto_44
    move v2, v15

    .line 1956
    :goto_45
    add-int/lit8 v6, v19, 0x1

    .line 1957
    .line 1958
    move-object/from16 v20, v1

    .line 1959
    .line 1960
    move-object v12, v3

    .line 1961
    move/from16 v1, p6

    .line 1962
    .line 1963
    goto/16 :goto_3c

    .line 1964
    .line 1965
    :cond_68
    move v15, v2

    .line 1966
    move-object v3, v12

    .line 1967
    move-object/from16 v1, v20

    .line 1968
    .line 1969
    if-eqz v15, :cond_6d

    .line 1970
    .line 1971
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 1972
    .line 1973
    .line 1974
    move-result v2

    .line 1975
    const/4 v6, 0x0

    .line 1976
    :goto_46
    if-ge v6, v2, :cond_6d

    .line 1977
    .line 1978
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1979
    .line 1980
    .line 1981
    move-result-object v5

    .line 1982
    check-cast v5, Lg4/e;

    .line 1983
    .line 1984
    iget-object v7, v5, Lg4/e;->a:Ljava/lang/Object;

    .line 1985
    .line 1986
    check-cast v7, Lg4/b;

    .line 1987
    .line 1988
    instance-of v8, v7, Lg4/g0;

    .line 1989
    .line 1990
    if-eqz v8, :cond_6c

    .line 1991
    .line 1992
    iget v8, v5, Lg4/e;->b:I

    .line 1993
    .line 1994
    iget v5, v5, Lg4/e;->c:I

    .line 1995
    .line 1996
    if-ltz v8, :cond_6c

    .line 1997
    .line 1998
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 1999
    .line 2000
    .line 2001
    move-result v10

    .line 2002
    if-ge v8, v10, :cond_6c

    .line 2003
    .line 2004
    if-le v5, v8, :cond_6c

    .line 2005
    .line 2006
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 2007
    .line 2008
    .line 2009
    move-result v10

    .line 2010
    if-le v5, v10, :cond_69

    .line 2011
    .line 2012
    goto :goto_48

    .line 2013
    :cond_69
    check-cast v7, Lg4/g0;

    .line 2014
    .line 2015
    iget-wide v10, v7, Lg4/g0;->h:J

    .line 2016
    .line 2017
    invoke-static {v10, v11}, Lt4/o;->b(J)J

    .line 2018
    .line 2019
    .line 2020
    move-result-wide v12

    .line 2021
    const-wide v14, 0x100000000L

    .line 2022
    .line 2023
    .line 2024
    .line 2025
    .line 2026
    invoke-static {v12, v13, v14, v15}, Lt4/p;->a(JJ)Z

    .line 2027
    .line 2028
    .line 2029
    move-result v7

    .line 2030
    if-eqz v7, :cond_6a

    .line 2031
    .line 2032
    new-instance v7, Lj4/f;

    .line 2033
    .line 2034
    invoke-interface {v3, v10, v11}, Lt4/c;->V(J)F

    .line 2035
    .line 2036
    .line 2037
    move-result v10

    .line 2038
    invoke-direct {v7, v10}, Lj4/f;-><init>(F)V

    .line 2039
    .line 2040
    .line 2041
    goto :goto_47

    .line 2042
    :cond_6a
    const-wide v14, 0x200000000L

    .line 2043
    .line 2044
    .line 2045
    .line 2046
    .line 2047
    invoke-static {v12, v13, v14, v15}, Lt4/p;->a(JJ)Z

    .line 2048
    .line 2049
    .line 2050
    move-result v7

    .line 2051
    if-eqz v7, :cond_6b

    .line 2052
    .line 2053
    new-instance v7, Lj4/e;

    .line 2054
    .line 2055
    invoke-static {v10, v11}, Lt4/o;->c(J)F

    .line 2056
    .line 2057
    .line 2058
    move-result v10

    .line 2059
    invoke-direct {v7, v10}, Lj4/e;-><init>(F)V

    .line 2060
    .line 2061
    .line 2062
    goto :goto_47

    .line 2063
    :cond_6b
    const/4 v7, 0x0

    .line 2064
    :goto_47
    if-eqz v7, :cond_6c

    .line 2065
    .line 2066
    const/16 v10, 0x21

    .line 2067
    .line 2068
    invoke-interface {v9, v7, v8, v5, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 2069
    .line 2070
    .line 2071
    :cond_6c
    :goto_48
    add-int/lit8 v6, v6, 0x1

    .line 2072
    .line 2073
    goto :goto_46

    .line 2074
    :cond_6d
    iget-object v1, v1, Lg4/t;->d:Lr4/q;

    .line 2075
    .line 2076
    if-eqz v1, :cond_6f

    .line 2077
    .line 2078
    iget-wide v1, v1, Lr4/q;->a:J

    .line 2079
    .line 2080
    invoke-static {v1, v2}, Lt4/o;->b(J)J

    .line 2081
    .line 2082
    .line 2083
    move-result-wide v5

    .line 2084
    const-wide v7, 0x100000000L

    .line 2085
    .line 2086
    .line 2087
    .line 2088
    .line 2089
    invoke-static {v5, v6, v7, v8}, Lt4/p;->a(JJ)Z

    .line 2090
    .line 2091
    .line 2092
    move-result v10

    .line 2093
    if-eqz v10, :cond_6e

    .line 2094
    .line 2095
    invoke-interface {v3, v1, v2}, Lt4/c;->V(J)F

    .line 2096
    .line 2097
    .line 2098
    goto :goto_49

    .line 2099
    :cond_6e
    const-wide v7, 0x200000000L

    .line 2100
    .line 2101
    .line 2102
    .line 2103
    .line 2104
    invoke-static {v5, v6, v7, v8}, Lt4/p;->a(JJ)Z

    .line 2105
    .line 2106
    .line 2107
    move-result v5

    .line 2108
    if-eqz v5, :cond_6f

    .line 2109
    .line 2110
    invoke-static {v1, v2}, Lt4/o;->c(J)F

    .line 2111
    .line 2112
    .line 2113
    :cond_6f
    :goto_49
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 2114
    .line 2115
    .line 2116
    move-result v1

    .line 2117
    const/4 v6, 0x0

    .line 2118
    :goto_4a
    if-ge v6, v1, :cond_70

    .line 2119
    .line 2120
    invoke-interface {v4, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2121
    .line 2122
    .line 2123
    move-result-object v2

    .line 2124
    check-cast v2, Lg4/e;

    .line 2125
    .line 2126
    iget-object v2, v2, Lg4/e;->a:Ljava/lang/Object;

    .line 2127
    .line 2128
    add-int/lit8 v6, v6, 0x1

    .line 2129
    .line 2130
    goto :goto_4a

    .line 2131
    :cond_70
    move-object/from16 v7, v16

    .line 2132
    .line 2133
    check-cast v7, Ljava/util/Collection;

    .line 2134
    .line 2135
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 2136
    .line 2137
    .line 2138
    move-result v1

    .line 2139
    const/4 v6, 0x0

    .line 2140
    :goto_4b
    if-ge v6, v1, :cond_76

    .line 2141
    .line 2142
    move-object/from16 v2, v16

    .line 2143
    .line 2144
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2145
    .line 2146
    .line 2147
    move-result-object v4

    .line 2148
    check-cast v4, Lg4/e;

    .line 2149
    .line 2150
    iget-object v5, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 2151
    .line 2152
    check-cast v5, Lg4/v;

    .line 2153
    .line 2154
    iget v7, v4, Lg4/e;->b:I

    .line 2155
    .line 2156
    iget v4, v4, Lg4/e;->c:I

    .line 2157
    .line 2158
    const-class v8, Ls6/u;

    .line 2159
    .line 2160
    invoke-interface {v9, v7, v4, v8}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 2161
    .line 2162
    .line 2163
    move-result-object v8

    .line 2164
    array-length v10, v8

    .line 2165
    const/4 v11, 0x0

    .line 2166
    :goto_4c
    if-ge v11, v10, :cond_71

    .line 2167
    .line 2168
    aget-object v12, v8, v11

    .line 2169
    .line 2170
    check-cast v12, Ls6/u;

    .line 2171
    .line 2172
    invoke-interface {v9, v12}, Landroid/text/Spannable;->removeSpan(Ljava/lang/Object;)V

    .line 2173
    .line 2174
    .line 2175
    add-int/lit8 v11, v11, 0x1

    .line 2176
    .line 2177
    goto :goto_4c

    .line 2178
    :cond_71
    new-instance v20, Lj4/i;

    .line 2179
    .line 2180
    iget-wide v10, v5, Lg4/v;->a:J

    .line 2181
    .line 2182
    iget-wide v12, v5, Lg4/v;->b:J

    .line 2183
    .line 2184
    invoke-static {v10, v11}, Lt4/o;->c(J)F

    .line 2185
    .line 2186
    .line 2187
    move-result v21

    .line 2188
    iget-wide v10, v5, Lg4/v;->a:J

    .line 2189
    .line 2190
    invoke-static {v10, v11}, Lt4/o;->b(J)J

    .line 2191
    .line 2192
    .line 2193
    move-result-wide v10

    .line 2194
    const-wide v14, 0x100000000L

    .line 2195
    .line 2196
    .line 2197
    .line 2198
    .line 2199
    invoke-static {v10, v11, v14, v15}, Lt4/p;->a(JJ)Z

    .line 2200
    .line 2201
    .line 2202
    move-result v5

    .line 2203
    if-eqz v5, :cond_72

    .line 2204
    .line 2205
    const-wide v14, 0x200000000L

    .line 2206
    .line 2207
    .line 2208
    .line 2209
    .line 2210
    const/16 v22, 0x0

    .line 2211
    .line 2212
    goto :goto_4d

    .line 2213
    :cond_72
    const-wide v14, 0x200000000L

    .line 2214
    .line 2215
    .line 2216
    .line 2217
    .line 2218
    invoke-static {v10, v11, v14, v15}, Lt4/p;->a(JJ)Z

    .line 2219
    .line 2220
    .line 2221
    move-result v5

    .line 2222
    if-eqz v5, :cond_73

    .line 2223
    .line 2224
    const/16 v22, 0x1

    .line 2225
    .line 2226
    goto :goto_4d

    .line 2227
    :cond_73
    const/16 v22, 0x2

    .line 2228
    .line 2229
    :goto_4d
    invoke-static {v12, v13}, Lt4/o;->c(J)F

    .line 2230
    .line 2231
    .line 2232
    move-result v23

    .line 2233
    invoke-static {v12, v13}, Lt4/o;->b(J)J

    .line 2234
    .line 2235
    .line 2236
    move-result-wide v10

    .line 2237
    const-wide v12, 0x100000000L

    .line 2238
    .line 2239
    .line 2240
    .line 2241
    .line 2242
    invoke-static {v10, v11, v12, v13}, Lt4/p;->a(JJ)Z

    .line 2243
    .line 2244
    .line 2245
    move-result v5

    .line 2246
    if-eqz v5, :cond_74

    .line 2247
    .line 2248
    const/16 v24, 0x0

    .line 2249
    .line 2250
    goto :goto_4e

    .line 2251
    :cond_74
    invoke-static {v10, v11, v14, v15}, Lt4/p;->a(JJ)Z

    .line 2252
    .line 2253
    .line 2254
    move-result v5

    .line 2255
    if-eqz v5, :cond_75

    .line 2256
    .line 2257
    const/16 v24, 0x1

    .line 2258
    .line 2259
    goto :goto_4e

    .line 2260
    :cond_75
    const/16 v24, 0x2

    .line 2261
    .line 2262
    :goto_4e
    invoke-interface {v3}, Lt4/c;->t0()F

    .line 2263
    .line 2264
    .line 2265
    move-result v5

    .line 2266
    invoke-interface {v3}, Lt4/c;->a()F

    .line 2267
    .line 2268
    .line 2269
    move-result v8

    .line 2270
    mul-float v25, v8, v5

    .line 2271
    .line 2272
    const/16 v26, 0x0

    .line 2273
    .line 2274
    invoke-direct/range {v20 .. v26}, Lj4/i;-><init>(FIFIFI)V

    .line 2275
    .line 2276
    .line 2277
    move-object/from16 v5, v20

    .line 2278
    .line 2279
    const/16 v10, 0x21

    .line 2280
    .line 2281
    invoke-interface {v9, v5, v7, v4, v10}, Landroid/text/Spannable;->setSpan(Ljava/lang/Object;III)V

    .line 2282
    .line 2283
    .line 2284
    add-int/lit8 v6, v6, 0x1

    .line 2285
    .line 2286
    move-object/from16 v16, v2

    .line 2287
    .line 2288
    goto/16 :goto_4b

    .line 2289
    .line 2290
    :cond_76
    :goto_4f
    iput-object v9, v0, Lo4/c;->k:Ljava/lang/CharSequence;

    .line 2291
    .line 2292
    new-instance v1, Lh4/f;

    .line 2293
    .line 2294
    iget-object v2, v0, Lo4/c;->j:Lo4/d;

    .line 2295
    .line 2296
    iget v3, v0, Lo4/c;->o:I

    .line 2297
    .line 2298
    invoke-direct {v1, v9, v2, v3}, Lh4/f;-><init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;I)V

    .line 2299
    .line 2300
    .line 2301
    iput-object v1, v0, Lo4/c;->l:Lh4/f;

    .line 2302
    .line 2303
    return-void

    .line 2304
    :cond_77
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 2305
    .line 2306
    const-string v1, "Array is empty."

    .line 2307
    .line 2308
    invoke-direct {v0, v1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 2309
    .line 2310
    .line 2311
    throw v0

    .line 2312
    :cond_78
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2313
    .line 2314
    const-string v1, "Invalid TextDirection."

    .line 2315
    .line 2316
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2317
    .line 2318
    .line 2319
    throw v0
.end method


# virtual methods
.method public final a()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lo4/c;->m:Lil/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lil/g;->P()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move v0, v1

    .line 12
    :goto_0
    if-nez v0, :cond_4

    .line 13
    .line 14
    iget-boolean v0, p0, Lo4/c;->n:Z

    .line 15
    .line 16
    if-nez v0, :cond_3

    .line 17
    .line 18
    iget-object p0, p0, Lo4/c;->e:Lg4/p0;

    .line 19
    .line 20
    iget-object p0, p0, Lg4/p0;->c:Lg4/y;

    .line 21
    .line 22
    sget-object p0, Lo4/h;->a:Lhu/q;

    .line 23
    .line 24
    sget-object p0, Lo4/h;->a:Lhu/q;

    .line 25
    .line 26
    iget-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Ll2/t2;

    .line 29
    .line 30
    if-eqz v0, :cond_1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    invoke-static {}, Ls6/h;->d()Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_2

    .line 38
    .line 39
    invoke-virtual {p0}, Lhu/q;->B()Ll2/t2;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iput-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_2
    sget-object v0, Lo4/i;->a:Lo4/j;

    .line 47
    .line 48
    :goto_1
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    check-cast p0, Ljava/lang/Boolean;

    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    if-eqz p0, :cond_3

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_3
    return v1

    .line 62
    :cond_4
    :goto_2
    const/4 p0, 0x1

    .line 63
    return p0
.end method

.method public final b()F
    .locals 0

    .line 1
    iget-object p0, p0, Lo4/c;->l:Lh4/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh4/f;->c()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final c()F
    .locals 9

    .line 1
    iget-object p0, p0, Lo4/c;->l:Lh4/f;

    .line 2
    .line 3
    iget v0, p0, Lh4/f;->e:F

    .line 4
    .line 5
    iget-object v1, p0, Lh4/f;->b:Landroid/text/TextPaint;

    .line 6
    .line 7
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    iget p0, p0, Lh4/f;->e:F

    .line 14
    .line 15
    return p0

    .line 16
    :cond_0
    invoke-virtual {v1}, Landroid/graphics/Paint;->getTextLocale()Ljava/util/Locale;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Ljava/text/BreakIterator;->getLineInstance(Ljava/util/Locale;)Ljava/text/BreakIterator;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v2, Lh4/c;

    .line 25
    .line 26
    iget-object v3, p0, Lh4/f;->a:Ljava/lang/CharSequence;

    .line 27
    .line 28
    invoke-interface {v3}, Ljava/lang/CharSequence;->length()I

    .line 29
    .line 30
    .line 31
    move-result v4

    .line 32
    invoke-direct {v2, v4, v3}, Lh4/c;-><init>(ILjava/lang/CharSequence;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v2}, Ljava/text/BreakIterator;->setText(Ljava/text/CharacterIterator;)V

    .line 36
    .line 37
    .line 38
    new-instance v2, Ljava/util/PriorityQueue;

    .line 39
    .line 40
    new-instance v3, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 41
    .line 42
    const/4 v4, 0x3

    .line 43
    invoke-direct {v3, v4}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 44
    .line 45
    .line 46
    const/16 v4, 0xa

    .line 47
    .line 48
    invoke-direct {v2, v4, v3}, Ljava/util/PriorityQueue;-><init>(ILjava/util/Comparator;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/text/BreakIterator;->next()I

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    const/4 v5, 0x0

    .line 56
    :goto_0
    const/4 v6, -0x1

    .line 57
    if-eq v3, v6, :cond_3

    .line 58
    .line 59
    invoke-virtual {v2}, Ljava/util/PriorityQueue;->size()I

    .line 60
    .line 61
    .line 62
    move-result v6

    .line 63
    if-ge v6, v4, :cond_1

    .line 64
    .line 65
    new-instance v6, Llx0/l;

    .line 66
    .line 67
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 72
    .line 73
    .line 74
    move-result-object v7

    .line 75
    invoke-direct {v6, v5, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v2, v6}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    invoke-virtual {v2}, Ljava/util/PriorityQueue;->peek()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v6

    .line 86
    check-cast v6, Llx0/l;

    .line 87
    .line 88
    if-eqz v6, :cond_2

    .line 89
    .line 90
    iget-object v7, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v7, Ljava/lang/Number;

    .line 93
    .line 94
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 95
    .line 96
    .line 97
    move-result v7

    .line 98
    iget-object v6, v6, Llx0/l;->d:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v6, Ljava/lang/Number;

    .line 101
    .line 102
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 103
    .line 104
    .line 105
    move-result v6

    .line 106
    sub-int/2addr v7, v6

    .line 107
    sub-int v6, v3, v5

    .line 108
    .line 109
    if-ge v7, v6, :cond_2

    .line 110
    .line 111
    invoke-virtual {v2}, Ljava/util/PriorityQueue;->poll()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    new-instance v6, Llx0/l;

    .line 115
    .line 116
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    invoke-direct {v6, v5, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v2, v6}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    :cond_2
    :goto_1
    invoke-virtual {v0}, Ljava/text/BreakIterator;->next()I

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    move v8, v5

    .line 135
    move v5, v3

    .line 136
    move v3, v8

    .line 137
    goto :goto_0

    .line 138
    :cond_3
    invoke-virtual {v2}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    if-eqz v0, :cond_4

    .line 143
    .line 144
    const/4 v0, 0x0

    .line 145
    goto :goto_3

    .line 146
    :cond_4
    invoke-virtual {v2}, Ljava/util/PriorityQueue;->iterator()Ljava/util/Iterator;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    if-eqz v2, :cond_6

    .line 155
    .line 156
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    check-cast v2, Llx0/l;

    .line 161
    .line 162
    iget-object v3, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast v3, Ljava/lang/Number;

    .line 165
    .line 166
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 167
    .line 168
    .line 169
    move-result v3

    .line 170
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v2, Ljava/lang/Number;

    .line 173
    .line 174
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    invoke-virtual {p0}, Lh4/f;->b()Ljava/lang/CharSequence;

    .line 179
    .line 180
    .line 181
    move-result-object v4

    .line 182
    invoke-static {v4, v3, v2, v1}, Landroid/text/Layout;->getDesiredWidth(Ljava/lang/CharSequence;IILandroid/text/TextPaint;)F

    .line 183
    .line 184
    .line 185
    move-result v2

    .line 186
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v3

    .line 190
    if-eqz v3, :cond_5

    .line 191
    .line 192
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    check-cast v3, Llx0/l;

    .line 197
    .line 198
    iget-object v4, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v4, Ljava/lang/Number;

    .line 201
    .line 202
    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    .line 203
    .line 204
    .line 205
    move-result v4

    .line 206
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v3, Ljava/lang/Number;

    .line 209
    .line 210
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 211
    .line 212
    .line 213
    move-result v3

    .line 214
    invoke-virtual {p0}, Lh4/f;->b()Ljava/lang/CharSequence;

    .line 215
    .line 216
    .line 217
    move-result-object v5

    .line 218
    invoke-static {v5, v4, v3, v1}, Landroid/text/Layout;->getDesiredWidth(Ljava/lang/CharSequence;IILandroid/text/TextPaint;)F

    .line 219
    .line 220
    .line 221
    move-result v3

    .line 222
    invoke-static {v2, v3}, Ljava/lang/Math;->max(FF)F

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    goto :goto_2

    .line 227
    :cond_5
    move v0, v2

    .line 228
    :goto_3
    iput v0, p0, Lh4/f;->e:F

    .line 229
    .line 230
    return v0

    .line 231
    :cond_6
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 232
    .line 233
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 234
    .line 235
    .line 236
    throw p0
.end method
