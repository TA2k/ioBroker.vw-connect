.class public final Lc2/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lc2/a;

.field public final b:Lc2/k;

.field public final c:Ljava/lang/Object;

.field public d:Z

.field public e:Z

.field public f:Z

.field public g:Z

.field public h:Z

.field public i:Z

.field public j:Ll4/v;

.field public k:Lg4/l0;

.field public l:Ll4/p;

.field public m:Ld3/c;

.field public n:Ld3/c;

.field public final o:Landroid/view/inputmethod/CursorAnchorInfo$Builder;

.field public final p:[F

.field public final q:Landroid/graphics/Matrix;


# direct methods
.method public constructor <init>(Lc2/a;Lc2/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc2/m;->a:Lc2/a;

    .line 5
    .line 6
    iput-object p2, p0, Lc2/m;->b:Lc2/k;

    .line 7
    .line 8
    new-instance p1, Ljava/lang/Object;

    .line 9
    .line 10
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lc2/m;->c:Ljava/lang/Object;

    .line 14
    .line 15
    new-instance p1, Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 16
    .line 17
    invoke-direct {p1}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Lc2/m;->o:Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 21
    .line 22
    invoke-static {}, Le3/c0;->a()[F

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lc2/m;->p:[F

    .line 27
    .line 28
    new-instance p1, Landroid/graphics/Matrix;

    .line 29
    .line 30
    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lc2/m;->q:Landroid/graphics/Matrix;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 29

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lc2/m;->b:Lc2/k;

    .line 4
    .line 5
    invoke-virtual {v1}, Lc2/k;->v()Landroid/view/inputmethod/InputMethodManager;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    iget-object v3, v1, Lc2/k;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v3, Landroid/view/View;

    .line 12
    .line 13
    invoke-virtual {v2, v3}, Landroid/view/inputmethod/InputMethodManager;->isActive(Landroid/view/View;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    if-eqz v2, :cond_18

    .line 18
    .line 19
    iget-object v2, v0, Lc2/m;->j:Ll4/v;

    .line 20
    .line 21
    if-eqz v2, :cond_18

    .line 22
    .line 23
    iget-object v2, v0, Lc2/m;->l:Ll4/p;

    .line 24
    .line 25
    if-eqz v2, :cond_18

    .line 26
    .line 27
    iget-object v2, v0, Lc2/m;->k:Lg4/l0;

    .line 28
    .line 29
    if-eqz v2, :cond_18

    .line 30
    .line 31
    iget-object v2, v0, Lc2/m;->m:Ld3/c;

    .line 32
    .line 33
    if-eqz v2, :cond_18

    .line 34
    .line 35
    iget-object v2, v0, Lc2/m;->n:Ld3/c;

    .line 36
    .line 37
    if-nez v2, :cond_0

    .line 38
    .line 39
    goto/16 :goto_e

    .line 40
    .line 41
    :cond_0
    iget-object v2, v0, Lc2/m;->p:[F

    .line 42
    .line 43
    invoke-static {v2}, Le3/c0;->d([F)V

    .line 44
    .line 45
    .line 46
    iget-object v4, v0, Lc2/m;->a:Lc2/a;

    .line 47
    .line 48
    iget-object v4, v4, Lc2/a;->d:Lc2/l;

    .line 49
    .line 50
    iget-object v4, v4, Lc2/l;->u:Ll2/j1;

    .line 51
    .line 52
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    check-cast v4, Lt3/y;

    .line 57
    .line 58
    if-eqz v4, :cond_3

    .line 59
    .line 60
    invoke-interface {v4}, Lt3/y;->g()Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    const/4 v4, 0x0

    .line 68
    :goto_0
    if-nez v4, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    invoke-interface {v4, v2}, Lt3/y;->F([F)V

    .line 72
    .line 73
    .line 74
    :cond_3
    :goto_1
    iget-object v4, v0, Lc2/m;->n:Ld3/c;

    .line 75
    .line 76
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget v4, v4, Ld3/c;->a:F

    .line 80
    .line 81
    neg-float v4, v4

    .line 82
    iget-object v5, v0, Lc2/m;->n:Ld3/c;

    .line 83
    .line 84
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget v5, v5, Ld3/c;->b:F

    .line 88
    .line 89
    neg-float v5, v5

    .line 90
    invoke-static {v2, v4, v5}, Le3/c0;->f([FFF)V

    .line 91
    .line 92
    .line 93
    iget-object v4, v0, Lc2/m;->q:Landroid/graphics/Matrix;

    .line 94
    .line 95
    invoke-static {v4, v2}, Le3/j0;->s(Landroid/graphics/Matrix;[F)V

    .line 96
    .line 97
    .line 98
    iget-object v2, v0, Lc2/m;->j:Ll4/v;

    .line 99
    .line 100
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    iget-wide v5, v2, Ll4/v;->b:J

    .line 104
    .line 105
    iget-object v7, v0, Lc2/m;->l:Ll4/p;

    .line 106
    .line 107
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    iget-object v8, v0, Lc2/m;->k:Lg4/l0;

    .line 111
    .line 112
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iget-object v9, v8, Lg4/l0;->b:Lg4/o;

    .line 116
    .line 117
    iget-object v10, v0, Lc2/m;->m:Ld3/c;

    .line 118
    .line 119
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iget v11, v10, Ld3/c;->d:F

    .line 123
    .line 124
    iget v12, v10, Ld3/c;->b:F

    .line 125
    .line 126
    iget-object v13, v0, Lc2/m;->n:Ld3/c;

    .line 127
    .line 128
    invoke-static {v13}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget-boolean v14, v0, Lc2/m;->f:Z

    .line 132
    .line 133
    iget-boolean v15, v0, Lc2/m;->g:Z

    .line 134
    .line 135
    move-object/from16 v16, v1

    .line 136
    .line 137
    iget-boolean v1, v0, Lc2/m;->h:Z

    .line 138
    .line 139
    move/from16 v17, v1

    .line 140
    .line 141
    iget-boolean v1, v0, Lc2/m;->i:Z

    .line 142
    .line 143
    move/from16 v25, v1

    .line 144
    .line 145
    iget-object v1, v0, Lc2/m;->o:Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 146
    .line 147
    invoke-virtual {v1}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->reset()V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v1, v4}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->setMatrix(Landroid/graphics/Matrix;)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 151
    .line 152
    .line 153
    iget-object v4, v2, Ll4/v;->c:Lg4/o0;

    .line 154
    .line 155
    move-wide/from16 v18, v5

    .line 156
    .line 157
    invoke-static/range {v18 .. v19}, Lg4/o0;->f(J)I

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    invoke-static/range {v18 .. v19}, Lg4/o0;->e(J)I

    .line 162
    .line 163
    .line 164
    move-result v6

    .line 165
    invoke-virtual {v1, v5, v6}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->setSelectionRange(II)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 166
    .line 167
    .line 168
    const/16 v26, 0x1

    .line 169
    .line 170
    if-eqz v14, :cond_b

    .line 171
    .line 172
    if-gez v5, :cond_4

    .line 173
    .line 174
    goto :goto_5

    .line 175
    :cond_4
    invoke-interface {v7, v5}, Ll4/p;->R(I)I

    .line 176
    .line 177
    .line 178
    move-result v5

    .line 179
    invoke-virtual {v8, v5}, Lg4/l0;->c(I)Ld3/c;

    .line 180
    .line 181
    .line 182
    move-result-object v14

    .line 183
    iget v6, v14, Ld3/c;->a:F

    .line 184
    .line 185
    move-object/from16 v18, v1

    .line 186
    .line 187
    iget-wide v0, v8, Lg4/l0;->c:J

    .line 188
    .line 189
    const/16 v19, 0x20

    .line 190
    .line 191
    shr-long v0, v0, v19

    .line 192
    .line 193
    long-to-int v0, v0

    .line 194
    int-to-float v0, v0

    .line 195
    const/4 v1, 0x0

    .line 196
    invoke-static {v6, v1, v0}, Lkp/r9;->d(FFF)F

    .line 197
    .line 198
    .line 199
    move-result v0

    .line 200
    iget v1, v14, Ld3/c;->b:F

    .line 201
    .line 202
    invoke-static {v10, v0, v1}, Ljp/jc;->a(Ld3/c;FF)Z

    .line 203
    .line 204
    .line 205
    move-result v1

    .line 206
    iget v6, v14, Ld3/c;->d:F

    .line 207
    .line 208
    invoke-static {v10, v0, v6}, Ljp/jc;->a(Ld3/c;FF)Z

    .line 209
    .line 210
    .line 211
    move-result v6

    .line 212
    invoke-virtual {v8, v5}, Lg4/l0;->a(I)Lr4/j;

    .line 213
    .line 214
    .line 215
    move-result-object v5

    .line 216
    move/from16 v19, v0

    .line 217
    .line 218
    sget-object v0, Lr4/j;->e:Lr4/j;

    .line 219
    .line 220
    if-ne v5, v0, :cond_5

    .line 221
    .line 222
    move/from16 v0, v26

    .line 223
    .line 224
    goto :goto_2

    .line 225
    :cond_5
    const/4 v0, 0x0

    .line 226
    :goto_2
    if-nez v1, :cond_7

    .line 227
    .line 228
    if-eqz v6, :cond_6

    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_6
    const/4 v5, 0x0

    .line 232
    goto :goto_4

    .line 233
    :cond_7
    :goto_3
    move/from16 v5, v26

    .line 234
    .line 235
    :goto_4
    if-eqz v1, :cond_8

    .line 236
    .line 237
    if-nez v6, :cond_9

    .line 238
    .line 239
    :cond_8
    or-int/lit8 v5, v5, 0x2

    .line 240
    .line 241
    :cond_9
    if-eqz v0, :cond_a

    .line 242
    .line 243
    or-int/lit8 v5, v5, 0x4

    .line 244
    .line 245
    :cond_a
    move/from16 v23, v5

    .line 246
    .line 247
    iget v0, v14, Ld3/c;->b:F

    .line 248
    .line 249
    iget v1, v14, Ld3/c;->d:F

    .line 250
    .line 251
    move/from16 v22, v1

    .line 252
    .line 253
    move/from16 v20, v0

    .line 254
    .line 255
    move/from16 v21, v1

    .line 256
    .line 257
    invoke-virtual/range {v18 .. v23}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->setInsertionMarkerLocation(FFFFI)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 258
    .line 259
    .line 260
    move-object/from16 v0, v18

    .line 261
    .line 262
    goto :goto_6

    .line 263
    :cond_b
    :goto_5
    move-object v0, v1

    .line 264
    :goto_6
    if-eqz v15, :cond_15

    .line 265
    .line 266
    const/4 v1, -0x1

    .line 267
    if-eqz v4, :cond_c

    .line 268
    .line 269
    iget-wide v5, v4, Lg4/o0;->a:J

    .line 270
    .line 271
    invoke-static {v5, v6}, Lg4/o0;->f(J)I

    .line 272
    .line 273
    .line 274
    move-result v5

    .line 275
    goto :goto_7

    .line 276
    :cond_c
    move v5, v1

    .line 277
    :goto_7
    if-eqz v4, :cond_d

    .line 278
    .line 279
    iget-wide v14, v4, Lg4/o0;->a:J

    .line 280
    .line 281
    invoke-static {v14, v15}, Lg4/o0;->e(J)I

    .line 282
    .line 283
    .line 284
    move-result v1

    .line 285
    :cond_d
    if-ltz v5, :cond_15

    .line 286
    .line 287
    if-ge v5, v1, :cond_15

    .line 288
    .line 289
    iget-object v2, v2, Ll4/v;->a:Lg4/g;

    .line 290
    .line 291
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 292
    .line 293
    invoke-virtual {v2, v5, v1}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 294
    .line 295
    .line 296
    move-result-object v2

    .line 297
    invoke-virtual {v0, v5, v2}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->setComposingText(ILjava/lang/CharSequence;)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 298
    .line 299
    .line 300
    invoke-interface {v7, v5}, Ll4/p;->R(I)I

    .line 301
    .line 302
    .line 303
    move-result v2

    .line 304
    invoke-interface {v7, v1}, Ll4/p;->R(I)I

    .line 305
    .line 306
    .line 307
    move-result v4

    .line 308
    sub-int v6, v4, v2

    .line 309
    .line 310
    mul-int/lit8 v6, v6, 0x4

    .line 311
    .line 312
    new-array v6, v6, [F

    .line 313
    .line 314
    invoke-static {v2, v4}, Lg4/f0;->b(II)J

    .line 315
    .line 316
    .line 317
    move-result-wide v14

    .line 318
    invoke-virtual {v9, v14, v15, v6}, Lg4/o;->a(J[F)V

    .line 319
    .line 320
    .line 321
    :goto_8
    if-ge v5, v1, :cond_15

    .line 322
    .line 323
    invoke-interface {v7, v5}, Ll4/p;->R(I)I

    .line 324
    .line 325
    .line 326
    move-result v4

    .line 327
    sub-int v14, v4, v2

    .line 328
    .line 329
    mul-int/lit8 v14, v14, 0x4

    .line 330
    .line 331
    aget v15, v6, v14

    .line 332
    .line 333
    add-int/lit8 v18, v14, 0x1

    .line 334
    .line 335
    move-object/from16 v19, v0

    .line 336
    .line 337
    aget v0, v6, v18

    .line 338
    .line 339
    add-int/lit8 v18, v14, 0x2

    .line 340
    .line 341
    move/from16 v27, v1

    .line 342
    .line 343
    aget v1, v6, v18

    .line 344
    .line 345
    add-int/lit8 v14, v14, 0x3

    .line 346
    .line 347
    aget v14, v6, v14

    .line 348
    .line 349
    move/from16 v28, v2

    .line 350
    .line 351
    iget v2, v10, Ld3/c;->a:F

    .line 352
    .line 353
    cmpg-float v2, v2, v1

    .line 354
    .line 355
    if-gez v2, :cond_e

    .line 356
    .line 357
    move/from16 v18, v26

    .line 358
    .line 359
    goto :goto_9

    .line 360
    :cond_e
    const/16 v18, 0x0

    .line 361
    .line 362
    :goto_9
    iget v2, v10, Ld3/c;->c:F

    .line 363
    .line 364
    cmpg-float v2, v15, v2

    .line 365
    .line 366
    if-gez v2, :cond_f

    .line 367
    .line 368
    move/from16 v2, v26

    .line 369
    .line 370
    goto :goto_a

    .line 371
    :cond_f
    const/4 v2, 0x0

    .line 372
    :goto_a
    and-int v2, v18, v2

    .line 373
    .line 374
    cmpg-float v18, v12, v14

    .line 375
    .line 376
    if-gez v18, :cond_10

    .line 377
    .line 378
    move/from16 v18, v26

    .line 379
    .line 380
    goto :goto_b

    .line 381
    :cond_10
    const/16 v18, 0x0

    .line 382
    .line 383
    :goto_b
    and-int v2, v2, v18

    .line 384
    .line 385
    cmpg-float v18, v0, v11

    .line 386
    .line 387
    if-gez v18, :cond_11

    .line 388
    .line 389
    move/from16 v18, v26

    .line 390
    .line 391
    goto :goto_c

    .line 392
    :cond_11
    const/16 v18, 0x0

    .line 393
    .line 394
    :goto_c
    and-int v2, v2, v18

    .line 395
    .line 396
    invoke-static {v10, v15, v0}, Ljp/jc;->a(Ld3/c;FF)Z

    .line 397
    .line 398
    .line 399
    move-result v18

    .line 400
    if-eqz v18, :cond_12

    .line 401
    .line 402
    invoke-static {v10, v1, v14}, Ljp/jc;->a(Ld3/c;FF)Z

    .line 403
    .line 404
    .line 405
    move-result v18

    .line 406
    if-nez v18, :cond_13

    .line 407
    .line 408
    :cond_12
    or-int/lit8 v2, v2, 0x2

    .line 409
    .line 410
    :cond_13
    invoke-virtual {v8, v4}, Lg4/l0;->a(I)Lr4/j;

    .line 411
    .line 412
    .line 413
    move-result-object v4

    .line 414
    move/from16 v21, v0

    .line 415
    .line 416
    sget-object v0, Lr4/j;->e:Lr4/j;

    .line 417
    .line 418
    if-ne v4, v0, :cond_14

    .line 419
    .line 420
    or-int/lit8 v2, v2, 0x4

    .line 421
    .line 422
    :cond_14
    move/from16 v22, v1

    .line 423
    .line 424
    move/from16 v24, v2

    .line 425
    .line 426
    move/from16 v23, v14

    .line 427
    .line 428
    move/from16 v20, v15

    .line 429
    .line 430
    move-object/from16 v18, v19

    .line 431
    .line 432
    move/from16 v19, v5

    .line 433
    .line 434
    invoke-virtual/range {v18 .. v24}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->addCharacterBounds(IFFFFI)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 435
    .line 436
    .line 437
    move-object/from16 v0, v18

    .line 438
    .line 439
    add-int/lit8 v5, v19, 0x1

    .line 440
    .line 441
    move/from16 v1, v27

    .line 442
    .line 443
    move/from16 v2, v28

    .line 444
    .line 445
    goto :goto_8

    .line 446
    :cond_15
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 447
    .line 448
    const/16 v2, 0x21

    .line 449
    .line 450
    if-lt v1, v2, :cond_16

    .line 451
    .line 452
    if-eqz v17, :cond_16

    .line 453
    .line 454
    invoke-static {}, Lb/s;->l()Landroid/view/inputmethod/EditorBoundsInfo$Builder;

    .line 455
    .line 456
    .line 457
    move-result-object v2

    .line 458
    invoke-static {v13}, Le3/j0;->x(Ld3/c;)Landroid/graphics/RectF;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    invoke-static {v2, v4}, Lb/s;->m(Landroid/view/inputmethod/EditorBoundsInfo$Builder;Landroid/graphics/RectF;)Landroid/view/inputmethod/EditorBoundsInfo$Builder;

    .line 463
    .line 464
    .line 465
    move-result-object v2

    .line 466
    invoke-static {v13}, Le3/j0;->x(Ld3/c;)Landroid/graphics/RectF;

    .line 467
    .line 468
    .line 469
    move-result-object v4

    .line 470
    invoke-static {v2, v4}, Lb/s;->C(Landroid/view/inputmethod/EditorBoundsInfo$Builder;Landroid/graphics/RectF;)Landroid/view/inputmethod/EditorBoundsInfo$Builder;

    .line 471
    .line 472
    .line 473
    move-result-object v2

    .line 474
    invoke-static {v2}, Lb/s;->n(Landroid/view/inputmethod/EditorBoundsInfo$Builder;)Landroid/view/inputmethod/EditorBoundsInfo;

    .line 475
    .line 476
    .line 477
    move-result-object v2

    .line 478
    invoke-static {v0, v2}, Lb/s;->k(Landroid/view/inputmethod/CursorAnchorInfo$Builder;Landroid/view/inputmethod/EditorBoundsInfo;)Landroid/view/inputmethod/CursorAnchorInfo$Builder;

    .line 479
    .line 480
    .line 481
    :cond_16
    const/16 v2, 0x22

    .line 482
    .line 483
    if-lt v1, v2, :cond_17

    .line 484
    .line 485
    if-eqz v25, :cond_17

    .line 486
    .line 487
    invoke-virtual {v10}, Ld3/c;->f()Z

    .line 488
    .line 489
    .line 490
    move-result v1

    .line 491
    if-nez v1, :cond_17

    .line 492
    .line 493
    invoke-virtual {v9, v12}, Lg4/o;->e(F)I

    .line 494
    .line 495
    .line 496
    move-result v1

    .line 497
    invoke-virtual {v9, v11}, Lg4/o;->e(F)I

    .line 498
    .line 499
    .line 500
    move-result v2

    .line 501
    if-gt v1, v2, :cond_17

    .line 502
    .line 503
    :goto_d
    invoke-virtual {v8, v1}, Lg4/l0;->e(I)F

    .line 504
    .line 505
    .line 506
    move-result v4

    .line 507
    invoke-virtual {v9, v1}, Lg4/o;->f(I)F

    .line 508
    .line 509
    .line 510
    move-result v5

    .line 511
    invoke-virtual {v8, v1}, Lg4/l0;->f(I)F

    .line 512
    .line 513
    .line 514
    move-result v6

    .line 515
    invoke-virtual {v9, v1}, Lg4/o;->b(I)F

    .line 516
    .line 517
    .line 518
    move-result v7

    .line 519
    invoke-static {v0, v4, v5, v6, v7}, Lc2/f;->q(Landroid/view/inputmethod/CursorAnchorInfo$Builder;FFFF)V

    .line 520
    .line 521
    .line 522
    if-eq v1, v2, :cond_17

    .line 523
    .line 524
    add-int/lit8 v1, v1, 0x1

    .line 525
    .line 526
    goto :goto_d

    .line 527
    :cond_17
    invoke-virtual {v0}, Landroid/view/inputmethod/CursorAnchorInfo$Builder;->build()Landroid/view/inputmethod/CursorAnchorInfo;

    .line 528
    .line 529
    .line 530
    move-result-object v0

    .line 531
    invoke-virtual/range {v16 .. v16}, Lc2/k;->v()Landroid/view/inputmethod/InputMethodManager;

    .line 532
    .line 533
    .line 534
    move-result-object v1

    .line 535
    invoke-virtual {v1, v3, v0}, Landroid/view/inputmethod/InputMethodManager;->updateCursorAnchorInfo(Landroid/view/View;Landroid/view/inputmethod/CursorAnchorInfo;)V

    .line 536
    .line 537
    .line 538
    const/4 v1, 0x0

    .line 539
    move-object/from16 v0, p0

    .line 540
    .line 541
    iput-boolean v1, v0, Lc2/m;->e:Z

    .line 542
    .line 543
    :cond_18
    :goto_e
    return-void
.end method
