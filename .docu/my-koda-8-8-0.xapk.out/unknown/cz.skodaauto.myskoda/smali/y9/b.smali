.class public final Ly9/b;
.super Landroid/view/View;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly9/g0;


# instance fields
.field public final d:Ljava/util/ArrayList;

.field public e:Ljava/util/List;

.field public f:F

.field public g:Ly9/c;

.field public h:F


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 0

    .line 1
    const/4 p2, 0x0

    .line 2
    invoke-direct {p0, p1, p2}, Landroid/view/View;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    .line 3
    .line 4
    .line 5
    new-instance p1, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Ly9/b;->d:Ljava/util/ArrayList;

    .line 11
    .line 12
    sget-object p1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 13
    .line 14
    iput-object p1, p0, Ly9/b;->e:Ljava/util/List;

    .line 15
    .line 16
    const p1, 0x3d5a511a    # 0.0533f

    .line 17
    .line 18
    .line 19
    iput p1, p0, Ly9/b;->f:F

    .line 20
    .line 21
    sget-object p1, Ly9/c;->g:Ly9/c;

    .line 22
    .line 23
    iput-object p1, p0, Ly9/b;->g:Ly9/c;

    .line 24
    .line 25
    const p1, 0x3da3d70a    # 0.08f

    .line 26
    .line 27
    .line 28
    iput p1, p0, Ly9/b;->h:F

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final a(Ljava/util/List;Ly9/c;FF)V
    .locals 0

    .line 1
    iput-object p1, p0, Ly9/b;->e:Ljava/util/List;

    .line 2
    .line 3
    iput-object p2, p0, Ly9/b;->g:Ly9/c;

    .line 4
    .line 5
    iput p3, p0, Ly9/b;->f:F

    .line 6
    .line 7
    iput p4, p0, Ly9/b;->h:F

    .line 8
    .line 9
    :goto_0
    iget-object p2, p0, Ly9/b;->d:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 12
    .line 13
    .line 14
    move-result p3

    .line 15
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result p4

    .line 19
    if-ge p3, p4, :cond_0

    .line 20
    .line 21
    new-instance p3, Ly9/f0;

    .line 22
    .line 23
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 24
    .line 25
    .line 26
    move-result-object p4

    .line 27
    invoke-direct {p3, p4}, Ly9/f0;-><init>(Landroid/content/Context;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p2, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Ly9/b;->e:Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    if-eqz v3, :cond_0

    .line 12
    .line 13
    goto/16 :goto_1d

    .line 14
    .line 15
    :cond_0
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {v0}, Landroid/view/View;->getPaddingLeft()I

    .line 20
    .line 21
    .line 22
    move-result v4

    .line 23
    invoke-virtual {v0}, Landroid/view/View;->getPaddingTop()I

    .line 24
    .line 25
    .line 26
    move-result v5

    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 28
    .line 29
    .line 30
    move-result v6

    .line 31
    invoke-virtual {v0}, Landroid/view/View;->getPaddingRight()I

    .line 32
    .line 33
    .line 34
    move-result v7

    .line 35
    sub-int/2addr v6, v7

    .line 36
    invoke-virtual {v0}, Landroid/view/View;->getPaddingBottom()I

    .line 37
    .line 38
    .line 39
    move-result v7

    .line 40
    sub-int v7, v3, v7

    .line 41
    .line 42
    if-le v7, v5, :cond_2a

    .line 43
    .line 44
    if-gt v6, v4, :cond_1

    .line 45
    .line 46
    goto/16 :goto_1d

    .line 47
    .line 48
    :cond_1
    sub-int v8, v7, v5

    .line 49
    .line 50
    iget v9, v0, Ly9/b;->f:F

    .line 51
    .line 52
    const/4 v10, 0x0

    .line 53
    invoke-static {v10, v3, v8, v9}, Lqp/i;->d(IIIF)F

    .line 54
    .line 55
    .line 56
    move-result v9

    .line 57
    const/4 v11, 0x0

    .line 58
    cmpg-float v12, v9, v11

    .line 59
    .line 60
    if-gtz v12, :cond_2

    .line 61
    .line 62
    goto/16 :goto_1d

    .line 63
    .line 64
    :cond_2
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 65
    .line 66
    .line 67
    move-result v12

    .line 68
    move v13, v10

    .line 69
    :goto_0
    if-ge v13, v12, :cond_2a

    .line 70
    .line 71
    invoke-interface {v2, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v14

    .line 75
    check-cast v14, Lv7/b;

    .line 76
    .line 77
    iget v15, v14, Lv7/b;->p:I

    .line 78
    .line 79
    move/from16 v16, v11

    .line 80
    .line 81
    const/high16 v17, 0x3f800000    # 1.0f

    .line 82
    .line 83
    const/high16 v10, -0x80000000

    .line 84
    .line 85
    if-eq v15, v10, :cond_6

    .line 86
    .line 87
    invoke-virtual {v14}, Lv7/b;->a()Lv7/a;

    .line 88
    .line 89
    .line 90
    move-result-object v15

    .line 91
    iget v11, v14, Lv7/b;->e:F

    .line 92
    .line 93
    move-object/from16 v19, v2

    .line 94
    .line 95
    const v2, -0x800001

    .line 96
    .line 97
    .line 98
    iput v2, v15, Lv7/a;->h:F

    .line 99
    .line 100
    iput v10, v15, Lv7/a;->i:I

    .line 101
    .line 102
    const/4 v2, 0x0

    .line 103
    iput-object v2, v15, Lv7/a;->c:Landroid/text/Layout$Alignment;

    .line 104
    .line 105
    iget v2, v14, Lv7/b;->f:I

    .line 106
    .line 107
    if-nez v2, :cond_3

    .line 108
    .line 109
    sub-float v2, v17, v11

    .line 110
    .line 111
    iput v2, v15, Lv7/a;->e:F

    .line 112
    .line 113
    const/4 v2, 0x0

    .line 114
    iput v2, v15, Lv7/a;->f:I

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_3
    const/4 v2, 0x0

    .line 118
    neg-float v10, v11

    .line 119
    sub-float v10, v10, v17

    .line 120
    .line 121
    iput v10, v15, Lv7/a;->e:F

    .line 122
    .line 123
    const/4 v10, 0x1

    .line 124
    iput v10, v15, Lv7/a;->f:I

    .line 125
    .line 126
    :goto_1
    iget v10, v14, Lv7/b;->g:I

    .line 127
    .line 128
    if-eqz v10, :cond_5

    .line 129
    .line 130
    const/4 v11, 0x2

    .line 131
    if-eq v10, v11, :cond_4

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_4
    iput v2, v15, Lv7/a;->g:I

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_5
    const/4 v11, 0x2

    .line 138
    iput v11, v15, Lv7/a;->g:I

    .line 139
    .line 140
    :goto_2
    invoke-virtual {v15}, Lv7/a;->a()Lv7/b;

    .line 141
    .line 142
    .line 143
    move-result-object v14

    .line 144
    goto :goto_3

    .line 145
    :cond_6
    move-object/from16 v19, v2

    .line 146
    .line 147
    :goto_3
    iget v2, v14, Lv7/b;->n:I

    .line 148
    .line 149
    iget v10, v14, Lv7/b;->o:F

    .line 150
    .line 151
    invoke-static {v2, v3, v8, v10}, Lqp/i;->d(IIIF)F

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    iget-object v10, v0, Ly9/b;->d:Ljava/util/ArrayList;

    .line 156
    .line 157
    invoke-virtual {v10, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v10

    .line 161
    check-cast v10, Ly9/f0;

    .line 162
    .line 163
    iget-object v11, v0, Ly9/b;->g:Ly9/c;

    .line 164
    .line 165
    iget v15, v0, Ly9/b;->h:F

    .line 166
    .line 167
    iget-object v0, v10, Ly9/f0;->f:Landroid/text/TextPaint;

    .line 168
    .line 169
    move/from16 v28, v3

    .line 170
    .line 171
    iget-object v3, v14, Lv7/b;->d:Landroid/graphics/Bitmap;

    .line 172
    .line 173
    move/from16 v29, v8

    .line 174
    .line 175
    iget v8, v14, Lv7/b;->k:F

    .line 176
    .line 177
    move/from16 v30, v12

    .line 178
    .line 179
    iget v12, v14, Lv7/b;->j:F

    .line 180
    .line 181
    move/from16 v31, v13

    .line 182
    .line 183
    iget v13, v14, Lv7/b;->i:I

    .line 184
    .line 185
    move/from16 v20, v15

    .line 186
    .line 187
    iget v15, v14, Lv7/b;->h:F

    .line 188
    .line 189
    move/from16 v21, v2

    .line 190
    .line 191
    iget v2, v14, Lv7/b;->g:I

    .line 192
    .line 193
    move/from16 v32, v9

    .line 194
    .line 195
    iget v9, v14, Lv7/b;->f:I

    .line 196
    .line 197
    move-object/from16 v22, v0

    .line 198
    .line 199
    iget v0, v14, Lv7/b;->e:F

    .line 200
    .line 201
    move/from16 v23, v8

    .line 202
    .line 203
    iget-object v8, v14, Lv7/b;->b:Landroid/text/Layout$Alignment;

    .line 204
    .line 205
    move/from16 v24, v12

    .line 206
    .line 207
    iget-object v12, v14, Lv7/b;->a:Ljava/lang/CharSequence;

    .line 208
    .line 209
    move/from16 v25, v13

    .line 210
    .line 211
    if-nez v3, :cond_7

    .line 212
    .line 213
    const/4 v13, 0x1

    .line 214
    goto :goto_4

    .line 215
    :cond_7
    const/4 v13, 0x0

    .line 216
    :goto_4
    if-eqz v13, :cond_a

    .line 217
    .line 218
    invoke-static {v12}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 219
    .line 220
    .line 221
    move-result v26

    .line 222
    if-eqz v26, :cond_8

    .line 223
    .line 224
    :goto_5
    move/from16 v33, v4

    .line 225
    .line 226
    move/from16 v34, v5

    .line 227
    .line 228
    const/4 v15, 0x0

    .line 229
    goto/16 :goto_1c

    .line 230
    .line 231
    :cond_8
    move/from16 v26, v15

    .line 232
    .line 233
    iget-boolean v15, v14, Lv7/b;->l:Z

    .line 234
    .line 235
    if-eqz v15, :cond_9

    .line 236
    .line 237
    iget v14, v14, Lv7/b;->m:I

    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_9
    iget v14, v11, Ly9/c;->c:I

    .line 241
    .line 242
    goto :goto_6

    .line 243
    :cond_a
    move/from16 v26, v15

    .line 244
    .line 245
    const/high16 v14, -0x1000000

    .line 246
    .line 247
    :goto_6
    iget-object v15, v10, Ly9/f0;->i:Ljava/lang/CharSequence;

    .line 248
    .line 249
    if-eq v15, v12, :cond_c

    .line 250
    .line 251
    if-eqz v15, :cond_b

    .line 252
    .line 253
    invoke-virtual {v15, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 254
    .line 255
    .line 256
    move-result v15

    .line 257
    if-eqz v15, :cond_b

    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_b
    move/from16 v27, v2

    .line 261
    .line 262
    goto/16 :goto_8

    .line 263
    .line 264
    :cond_c
    :goto_7
    iget-object v15, v10, Ly9/f0;->j:Landroid/text/Layout$Alignment;

    .line 265
    .line 266
    invoke-static {v15, v8}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v15

    .line 270
    if-eqz v15, :cond_b

    .line 271
    .line 272
    iget-object v15, v10, Ly9/f0;->k:Landroid/graphics/Bitmap;

    .line 273
    .line 274
    if-ne v15, v3, :cond_b

    .line 275
    .line 276
    iget v15, v10, Ly9/f0;->l:F

    .line 277
    .line 278
    cmpl-float v15, v15, v0

    .line 279
    .line 280
    if-nez v15, :cond_b

    .line 281
    .line 282
    iget v15, v10, Ly9/f0;->m:I

    .line 283
    .line 284
    if-ne v15, v9, :cond_b

    .line 285
    .line 286
    iget v15, v10, Ly9/f0;->n:I

    .line 287
    .line 288
    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 289
    .line 290
    .line 291
    move-result-object v15

    .line 292
    move/from16 v27, v2

    .line 293
    .line 294
    invoke-static/range {v27 .. v27}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    invoke-virtual {v15, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    move-result v2

    .line 302
    if-eqz v2, :cond_d

    .line 303
    .line 304
    iget v2, v10, Ly9/f0;->o:F

    .line 305
    .line 306
    cmpl-float v2, v2, v26

    .line 307
    .line 308
    if-nez v2, :cond_d

    .line 309
    .line 310
    iget v2, v10, Ly9/f0;->p:I

    .line 311
    .line 312
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 313
    .line 314
    .line 315
    move-result-object v2

    .line 316
    invoke-static/range {v25 .. v25}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 317
    .line 318
    .line 319
    move-result-object v15

    .line 320
    invoke-virtual {v2, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    move-result v2

    .line 324
    if-eqz v2, :cond_d

    .line 325
    .line 326
    iget v2, v10, Ly9/f0;->q:F

    .line 327
    .line 328
    cmpl-float v2, v2, v24

    .line 329
    .line 330
    if-nez v2, :cond_d

    .line 331
    .line 332
    iget v2, v10, Ly9/f0;->r:F

    .line 333
    .line 334
    cmpl-float v2, v2, v23

    .line 335
    .line 336
    if-nez v2, :cond_d

    .line 337
    .line 338
    iget v2, v10, Ly9/f0;->s:I

    .line 339
    .line 340
    iget v15, v11, Ly9/c;->a:I

    .line 341
    .line 342
    if-ne v2, v15, :cond_d

    .line 343
    .line 344
    iget v2, v10, Ly9/f0;->t:I

    .line 345
    .line 346
    iget v15, v11, Ly9/c;->b:I

    .line 347
    .line 348
    if-ne v2, v15, :cond_d

    .line 349
    .line 350
    iget v2, v10, Ly9/f0;->u:I

    .line 351
    .line 352
    if-ne v2, v14, :cond_d

    .line 353
    .line 354
    iget v2, v10, Ly9/f0;->w:I

    .line 355
    .line 356
    iget v15, v11, Ly9/c;->d:I

    .line 357
    .line 358
    if-ne v2, v15, :cond_d

    .line 359
    .line 360
    iget v2, v10, Ly9/f0;->v:I

    .line 361
    .line 362
    iget v15, v11, Ly9/c;->e:I

    .line 363
    .line 364
    if-ne v2, v15, :cond_d

    .line 365
    .line 366
    invoke-virtual/range {v22 .. v22}, Landroid/graphics/Paint;->getTypeface()Landroid/graphics/Typeface;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    iget-object v15, v11, Ly9/c;->f:Landroid/graphics/Typeface;

    .line 371
    .line 372
    invoke-static {v2, v15}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    move-result v2

    .line 376
    if-eqz v2, :cond_d

    .line 377
    .line 378
    iget v2, v10, Ly9/f0;->x:F

    .line 379
    .line 380
    cmpl-float v2, v2, v32

    .line 381
    .line 382
    if-nez v2, :cond_d

    .line 383
    .line 384
    iget v2, v10, Ly9/f0;->y:F

    .line 385
    .line 386
    cmpl-float v2, v2, v21

    .line 387
    .line 388
    if-nez v2, :cond_d

    .line 389
    .line 390
    iget v2, v10, Ly9/f0;->z:F

    .line 391
    .line 392
    cmpl-float v2, v2, v20

    .line 393
    .line 394
    if-nez v2, :cond_d

    .line 395
    .line 396
    iget v2, v10, Ly9/f0;->A:I

    .line 397
    .line 398
    if-ne v2, v4, :cond_d

    .line 399
    .line 400
    iget v2, v10, Ly9/f0;->B:I

    .line 401
    .line 402
    if-ne v2, v5, :cond_d

    .line 403
    .line 404
    iget v2, v10, Ly9/f0;->C:I

    .line 405
    .line 406
    if-ne v2, v6, :cond_d

    .line 407
    .line 408
    iget v2, v10, Ly9/f0;->D:I

    .line 409
    .line 410
    if-ne v2, v7, :cond_d

    .line 411
    .line 412
    invoke-virtual {v10, v1, v13}, Ly9/f0;->a(Landroid/graphics/Canvas;Z)V

    .line 413
    .line 414
    .line 415
    goto/16 :goto_5

    .line 416
    .line 417
    :cond_d
    :goto_8
    iput-object v12, v10, Ly9/f0;->i:Ljava/lang/CharSequence;

    .line 418
    .line 419
    iput-object v8, v10, Ly9/f0;->j:Landroid/text/Layout$Alignment;

    .line 420
    .line 421
    iput-object v3, v10, Ly9/f0;->k:Landroid/graphics/Bitmap;

    .line 422
    .line 423
    iput v0, v10, Ly9/f0;->l:F

    .line 424
    .line 425
    iput v9, v10, Ly9/f0;->m:I

    .line 426
    .line 427
    move/from16 v0, v27

    .line 428
    .line 429
    iput v0, v10, Ly9/f0;->n:I

    .line 430
    .line 431
    move/from16 v0, v26

    .line 432
    .line 433
    iput v0, v10, Ly9/f0;->o:F

    .line 434
    .line 435
    move/from16 v0, v25

    .line 436
    .line 437
    iput v0, v10, Ly9/f0;->p:I

    .line 438
    .line 439
    move/from16 v0, v24

    .line 440
    .line 441
    iput v0, v10, Ly9/f0;->q:F

    .line 442
    .line 443
    move/from16 v0, v23

    .line 444
    .line 445
    iput v0, v10, Ly9/f0;->r:F

    .line 446
    .line 447
    iget v0, v11, Ly9/c;->a:I

    .line 448
    .line 449
    iput v0, v10, Ly9/f0;->s:I

    .line 450
    .line 451
    iget v0, v11, Ly9/c;->b:I

    .line 452
    .line 453
    iput v0, v10, Ly9/f0;->t:I

    .line 454
    .line 455
    iput v14, v10, Ly9/f0;->u:I

    .line 456
    .line 457
    iget v0, v11, Ly9/c;->d:I

    .line 458
    .line 459
    iput v0, v10, Ly9/f0;->w:I

    .line 460
    .line 461
    iget v0, v11, Ly9/c;->e:I

    .line 462
    .line 463
    iput v0, v10, Ly9/f0;->v:I

    .line 464
    .line 465
    iget-object v0, v11, Ly9/c;->f:Landroid/graphics/Typeface;

    .line 466
    .line 467
    move-object/from16 v2, v22

    .line 468
    .line 469
    invoke-virtual {v2, v0}, Landroid/graphics/Paint;->setTypeface(Landroid/graphics/Typeface;)Landroid/graphics/Typeface;

    .line 470
    .line 471
    .line 472
    move/from16 v0, v32

    .line 473
    .line 474
    iput v0, v10, Ly9/f0;->x:F

    .line 475
    .line 476
    move/from16 v3, v21

    .line 477
    .line 478
    iput v3, v10, Ly9/f0;->y:F

    .line 479
    .line 480
    move/from16 v3, v20

    .line 481
    .line 482
    iput v3, v10, Ly9/f0;->z:F

    .line 483
    .line 484
    iput v4, v10, Ly9/f0;->A:I

    .line 485
    .line 486
    iput v5, v10, Ly9/f0;->B:I

    .line 487
    .line 488
    iput v6, v10, Ly9/f0;->C:I

    .line 489
    .line 490
    iput v7, v10, Ly9/f0;->D:I

    .line 491
    .line 492
    if-eqz v13, :cond_24

    .line 493
    .line 494
    iget-object v3, v10, Ly9/f0;->i:Ljava/lang/CharSequence;

    .line 495
    .line 496
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 497
    .line 498
    .line 499
    iget-object v3, v10, Ly9/f0;->i:Ljava/lang/CharSequence;

    .line 500
    .line 501
    instance-of v8, v3, Landroid/text/SpannableStringBuilder;

    .line 502
    .line 503
    if-eqz v8, :cond_e

    .line 504
    .line 505
    check-cast v3, Landroid/text/SpannableStringBuilder;

    .line 506
    .line 507
    goto :goto_9

    .line 508
    :cond_e
    new-instance v3, Landroid/text/SpannableStringBuilder;

    .line 509
    .line 510
    iget-object v8, v10, Ly9/f0;->i:Ljava/lang/CharSequence;

    .line 511
    .line 512
    invoke-direct {v3, v8}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    .line 513
    .line 514
    .line 515
    :goto_9
    iget v8, v10, Ly9/f0;->C:I

    .line 516
    .line 517
    iget v9, v10, Ly9/f0;->A:I

    .line 518
    .line 519
    sub-int/2addr v8, v9

    .line 520
    iget v9, v10, Ly9/f0;->D:I

    .line 521
    .line 522
    iget v11, v10, Ly9/f0;->B:I

    .line 523
    .line 524
    sub-int/2addr v9, v11

    .line 525
    iget v11, v10, Ly9/f0;->x:F

    .line 526
    .line 527
    invoke-virtual {v2, v11}, Landroid/graphics/Paint;->setTextSize(F)V

    .line 528
    .line 529
    .line 530
    iget v11, v10, Ly9/f0;->x:F

    .line 531
    .line 532
    const/high16 v12, 0x3e000000    # 0.125f

    .line 533
    .line 534
    mul-float/2addr v11, v12

    .line 535
    const/high16 v12, 0x3f000000    # 0.5f

    .line 536
    .line 537
    add-float/2addr v11, v12

    .line 538
    float-to-int v11, v11

    .line 539
    mul-int/lit8 v12, v11, 0x2

    .line 540
    .line 541
    sub-int v14, v8, v12

    .line 542
    .line 543
    iget v15, v10, Ly9/f0;->q:F

    .line 544
    .line 545
    const v18, -0x800001

    .line 546
    .line 547
    .line 548
    cmpl-float v20, v15, v18

    .line 549
    .line 550
    if-eqz v20, :cond_f

    .line 551
    .line 552
    int-to-float v14, v14

    .line 553
    mul-float/2addr v14, v15

    .line 554
    float-to-int v14, v14

    .line 555
    :cond_f
    move/from16 v23, v14

    .line 556
    .line 557
    const-string v14, "SubtitlePainter"

    .line 558
    .line 559
    if-gtz v23, :cond_10

    .line 560
    .line 561
    const-string v2, "Skipped drawing subtitle cue (insufficient space)"

    .line 562
    .line 563
    invoke-static {v14, v2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 564
    .line 565
    .line 566
    move/from16 v32, v0

    .line 567
    .line 568
    move/from16 v33, v4

    .line 569
    .line 570
    move/from16 v34, v5

    .line 571
    .line 572
    :goto_a
    const/4 v15, 0x0

    .line 573
    goto/16 :goto_1b

    .line 574
    .line 575
    :cond_10
    iget v15, v10, Ly9/f0;->y:F

    .line 576
    .line 577
    cmpl-float v15, v15, v16

    .line 578
    .line 579
    move/from16 v32, v0

    .line 580
    .line 581
    if-lez v15, :cond_11

    .line 582
    .line 583
    new-instance v15, Landroid/text/style/AbsoluteSizeSpan;

    .line 584
    .line 585
    iget v0, v10, Ly9/f0;->y:F

    .line 586
    .line 587
    float-to-int v0, v0

    .line 588
    invoke-direct {v15, v0}, Landroid/text/style/AbsoluteSizeSpan;-><init>(I)V

    .line 589
    .line 590
    .line 591
    invoke-virtual {v3}, Landroid/text/SpannableStringBuilder;->length()I

    .line 592
    .line 593
    .line 594
    move-result v0

    .line 595
    move-object/from16 v22, v2

    .line 596
    .line 597
    move/from16 v33, v4

    .line 598
    .line 599
    const/4 v2, 0x0

    .line 600
    const/high16 v4, 0xff0000

    .line 601
    .line 602
    invoke-virtual {v3, v15, v2, v0, v4}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 603
    .line 604
    .line 605
    goto :goto_b

    .line 606
    :cond_11
    move-object/from16 v22, v2

    .line 607
    .line 608
    move/from16 v33, v4

    .line 609
    .line 610
    const/4 v2, 0x0

    .line 611
    :goto_b
    new-instance v0, Landroid/text/SpannableStringBuilder;

    .line 612
    .line 613
    invoke-direct {v0, v3}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    .line 614
    .line 615
    .line 616
    iget v4, v10, Ly9/f0;->w:I

    .line 617
    .line 618
    const/4 v15, 0x1

    .line 619
    if-ne v4, v15, :cond_12

    .line 620
    .line 621
    invoke-virtual {v0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 622
    .line 623
    .line 624
    move-result v4

    .line 625
    const-class v15, Landroid/text/style/ForegroundColorSpan;

    .line 626
    .line 627
    invoke-virtual {v0, v2, v4, v15}, Landroid/text/SpannableStringBuilder;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    move-result-object v4

    .line 631
    check-cast v4, [Landroid/text/style/ForegroundColorSpan;

    .line 632
    .line 633
    array-length v2, v4

    .line 634
    const/4 v15, 0x0

    .line 635
    :goto_c
    if-ge v15, v2, :cond_12

    .line 636
    .line 637
    move/from16 v21, v2

    .line 638
    .line 639
    aget-object v2, v4, v15

    .line 640
    .line 641
    invoke-virtual {v0, v2}, Landroid/text/SpannableStringBuilder;->removeSpan(Ljava/lang/Object;)V

    .line 642
    .line 643
    .line 644
    add-int/lit8 v15, v15, 0x1

    .line 645
    .line 646
    move/from16 v2, v21

    .line 647
    .line 648
    goto :goto_c

    .line 649
    :cond_12
    iget v2, v10, Ly9/f0;->t:I

    .line 650
    .line 651
    invoke-static {v2}, Landroid/graphics/Color;->alpha(I)I

    .line 652
    .line 653
    .line 654
    move-result v2

    .line 655
    if-lez v2, :cond_15

    .line 656
    .line 657
    iget v2, v10, Ly9/f0;->w:I

    .line 658
    .line 659
    if-eqz v2, :cond_13

    .line 660
    .line 661
    const/4 v4, 0x2

    .line 662
    if-ne v2, v4, :cond_14

    .line 663
    .line 664
    :cond_13
    move/from16 v34, v5

    .line 665
    .line 666
    const/high16 v5, 0xff0000

    .line 667
    .line 668
    const/4 v15, 0x0

    .line 669
    goto :goto_d

    .line 670
    :cond_14
    new-instance v2, Landroid/text/style/BackgroundColorSpan;

    .line 671
    .line 672
    iget v4, v10, Ly9/f0;->t:I

    .line 673
    .line 674
    invoke-direct {v2, v4}, Landroid/text/style/BackgroundColorSpan;-><init>(I)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 678
    .line 679
    .line 680
    move-result v4

    .line 681
    move/from16 v34, v5

    .line 682
    .line 683
    const/high16 v5, 0xff0000

    .line 684
    .line 685
    const/4 v15, 0x0

    .line 686
    invoke-virtual {v0, v2, v15, v4, v5}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 687
    .line 688
    .line 689
    goto :goto_e

    .line 690
    :goto_d
    new-instance v2, Landroid/text/style/BackgroundColorSpan;

    .line 691
    .line 692
    iget v4, v10, Ly9/f0;->t:I

    .line 693
    .line 694
    invoke-direct {v2, v4}, Landroid/text/style/BackgroundColorSpan;-><init>(I)V

    .line 695
    .line 696
    .line 697
    invoke-virtual {v3}, Landroid/text/SpannableStringBuilder;->length()I

    .line 698
    .line 699
    .line 700
    move-result v4

    .line 701
    invoke-virtual {v3, v2, v15, v4, v5}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 702
    .line 703
    .line 704
    goto :goto_e

    .line 705
    :cond_15
    move/from16 v34, v5

    .line 706
    .line 707
    :goto_e
    iget-object v2, v10, Ly9/f0;->j:Landroid/text/Layout$Alignment;

    .line 708
    .line 709
    if-nez v2, :cond_16

    .line 710
    .line 711
    sget-object v2, Landroid/text/Layout$Alignment;->ALIGN_CENTER:Landroid/text/Layout$Alignment;

    .line 712
    .line 713
    :cond_16
    move-object/from16 v24, v2

    .line 714
    .line 715
    new-instance v20, Landroid/text/StaticLayout;

    .line 716
    .line 717
    iget v2, v10, Ly9/f0;->d:F

    .line 718
    .line 719
    iget v4, v10, Ly9/f0;->e:F

    .line 720
    .line 721
    const/16 v27, 0x1

    .line 722
    .line 723
    move/from16 v25, v2

    .line 724
    .line 725
    move-object/from16 v21, v3

    .line 726
    .line 727
    move/from16 v26, v4

    .line 728
    .line 729
    invoke-direct/range {v20 .. v27}, Landroid/text/StaticLayout;-><init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;ILandroid/text/Layout$Alignment;FFZ)V

    .line 730
    .line 731
    .line 732
    move-object/from16 v3, v20

    .line 733
    .line 734
    move/from16 v2, v23

    .line 735
    .line 736
    iput-object v3, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 737
    .line 738
    invoke-virtual {v3}, Landroid/text/Layout;->getHeight()I

    .line 739
    .line 740
    .line 741
    move-result v3

    .line 742
    iget-object v4, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 743
    .line 744
    invoke-virtual {v4}, Landroid/text/StaticLayout;->getLineCount()I

    .line 745
    .line 746
    .line 747
    move-result v4

    .line 748
    const/4 v5, 0x0

    .line 749
    const/4 v15, 0x0

    .line 750
    :goto_f
    if-ge v5, v4, :cond_17

    .line 751
    .line 752
    move-object/from16 v35, v0

    .line 753
    .line 754
    iget-object v0, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 755
    .line 756
    invoke-virtual {v0, v5}, Landroid/text/Layout;->getLineWidth(I)F

    .line 757
    .line 758
    .line 759
    move-result v0

    .line 760
    move/from16 v20, v3

    .line 761
    .line 762
    move/from16 v23, v4

    .line 763
    .line 764
    float-to-double v3, v0

    .line 765
    invoke-static {v3, v4}, Ljava/lang/Math;->ceil(D)D

    .line 766
    .line 767
    .line 768
    move-result-wide v3

    .line 769
    double-to-int v0, v3

    .line 770
    invoke-static {v0, v15}, Ljava/lang/Math;->max(II)I

    .line 771
    .line 772
    .line 773
    move-result v15

    .line 774
    add-int/lit8 v5, v5, 0x1

    .line 775
    .line 776
    move/from16 v3, v20

    .line 777
    .line 778
    move/from16 v4, v23

    .line 779
    .line 780
    move-object/from16 v0, v35

    .line 781
    .line 782
    goto :goto_f

    .line 783
    :cond_17
    move-object/from16 v35, v0

    .line 784
    .line 785
    move/from16 v20, v3

    .line 786
    .line 787
    iget v0, v10, Ly9/f0;->q:F

    .line 788
    .line 789
    const v18, -0x800001

    .line 790
    .line 791
    .line 792
    cmpl-float v0, v0, v18

    .line 793
    .line 794
    if-eqz v0, :cond_18

    .line 795
    .line 796
    if-ge v15, v2, :cond_18

    .line 797
    .line 798
    move/from16 v23, v2

    .line 799
    .line 800
    goto :goto_10

    .line 801
    :cond_18
    move/from16 v23, v15

    .line 802
    .line 803
    :goto_10
    add-int v23, v23, v12

    .line 804
    .line 805
    iget v0, v10, Ly9/f0;->o:F

    .line 806
    .line 807
    cmpl-float v2, v0, v18

    .line 808
    .line 809
    if-eqz v2, :cond_1b

    .line 810
    .line 811
    int-to-float v2, v8

    .line 812
    mul-float/2addr v2, v0

    .line 813
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 814
    .line 815
    .line 816
    move-result v0

    .line 817
    iget v2, v10, Ly9/f0;->A:I

    .line 818
    .line 819
    add-int/2addr v0, v2

    .line 820
    iget v3, v10, Ly9/f0;->p:I

    .line 821
    .line 822
    const/4 v15, 0x1

    .line 823
    if-eq v3, v15, :cond_1a

    .line 824
    .line 825
    const/4 v4, 0x2

    .line 826
    if-eq v3, v4, :cond_19

    .line 827
    .line 828
    goto :goto_11

    .line 829
    :cond_19
    sub-int v0, v0, v23

    .line 830
    .line 831
    goto :goto_11

    .line 832
    :cond_1a
    const/4 v4, 0x2

    .line 833
    mul-int/lit8 v0, v0, 0x2

    .line 834
    .line 835
    sub-int v0, v0, v23

    .line 836
    .line 837
    div-int/2addr v0, v4

    .line 838
    :goto_11
    invoke-static {v0, v2}, Ljava/lang/Math;->max(II)I

    .line 839
    .line 840
    .line 841
    move-result v0

    .line 842
    add-int v2, v0, v23

    .line 843
    .line 844
    iget v3, v10, Ly9/f0;->C:I

    .line 845
    .line 846
    invoke-static {v2, v3}, Ljava/lang/Math;->min(II)I

    .line 847
    .line 848
    .line 849
    move-result v2

    .line 850
    goto :goto_12

    .line 851
    :cond_1b
    const/4 v4, 0x2

    .line 852
    sub-int v8, v8, v23

    .line 853
    .line 854
    div-int/2addr v8, v4

    .line 855
    iget v0, v10, Ly9/f0;->A:I

    .line 856
    .line 857
    add-int/2addr v0, v8

    .line 858
    add-int v2, v0, v23

    .line 859
    .line 860
    :goto_12
    sub-int v23, v2, v0

    .line 861
    .line 862
    if-gtz v23, :cond_1c

    .line 863
    .line 864
    const-string v0, "Skipped drawing subtitle cue (invalid horizontal positioning)"

    .line 865
    .line 866
    invoke-static {v14, v0}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 867
    .line 868
    .line 869
    goto/16 :goto_a

    .line 870
    .line 871
    :cond_1c
    iget v2, v10, Ly9/f0;->l:F

    .line 872
    .line 873
    const v18, -0x800001

    .line 874
    .line 875
    .line 876
    cmpl-float v3, v2, v18

    .line 877
    .line 878
    if-eqz v3, :cond_22

    .line 879
    .line 880
    iget v3, v10, Ly9/f0;->m:I

    .line 881
    .line 882
    if-nez v3, :cond_1f

    .line 883
    .line 884
    int-to-float v3, v9

    .line 885
    mul-float/2addr v3, v2

    .line 886
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 887
    .line 888
    .line 889
    move-result v2

    .line 890
    iget v3, v10, Ly9/f0;->B:I

    .line 891
    .line 892
    add-int/2addr v2, v3

    .line 893
    iget v3, v10, Ly9/f0;->n:I

    .line 894
    .line 895
    const/4 v4, 0x2

    .line 896
    if-ne v3, v4, :cond_1d

    .line 897
    .line 898
    sub-int v2, v2, v20

    .line 899
    .line 900
    goto :goto_13

    .line 901
    :cond_1d
    const/4 v15, 0x1

    .line 902
    if-ne v3, v15, :cond_1e

    .line 903
    .line 904
    mul-int/lit8 v2, v2, 0x2

    .line 905
    .line 906
    sub-int v2, v2, v20

    .line 907
    .line 908
    div-int/2addr v2, v4

    .line 909
    :cond_1e
    :goto_13
    const/4 v15, 0x0

    .line 910
    goto :goto_14

    .line 911
    :cond_1f
    iget-object v2, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 912
    .line 913
    const/4 v15, 0x0

    .line 914
    invoke-virtual {v2, v15}, Landroid/text/Layout;->getLineBottom(I)I

    .line 915
    .line 916
    .line 917
    move-result v2

    .line 918
    iget-object v3, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 919
    .line 920
    invoke-virtual {v3, v15}, Landroid/text/StaticLayout;->getLineTop(I)I

    .line 921
    .line 922
    .line 923
    move-result v3

    .line 924
    sub-int/2addr v2, v3

    .line 925
    iget v3, v10, Ly9/f0;->l:F

    .line 926
    .line 927
    cmpl-float v4, v3, v16

    .line 928
    .line 929
    if-ltz v4, :cond_20

    .line 930
    .line 931
    int-to-float v2, v2

    .line 932
    mul-float/2addr v3, v2

    .line 933
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 934
    .line 935
    .line 936
    move-result v2

    .line 937
    iget v3, v10, Ly9/f0;->B:I

    .line 938
    .line 939
    add-int/2addr v2, v3

    .line 940
    goto :goto_14

    .line 941
    :cond_20
    add-float v3, v3, v17

    .line 942
    .line 943
    int-to-float v2, v2

    .line 944
    mul-float/2addr v3, v2

    .line 945
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 946
    .line 947
    .line 948
    move-result v2

    .line 949
    iget v3, v10, Ly9/f0;->D:I

    .line 950
    .line 951
    add-int/2addr v2, v3

    .line 952
    sub-int v2, v2, v20

    .line 953
    .line 954
    :goto_14
    add-int v3, v2, v20

    .line 955
    .line 956
    iget v4, v10, Ly9/f0;->D:I

    .line 957
    .line 958
    if-le v3, v4, :cond_21

    .line 959
    .line 960
    sub-int v2, v4, v20

    .line 961
    .line 962
    goto :goto_15

    .line 963
    :cond_21
    iget v3, v10, Ly9/f0;->B:I

    .line 964
    .line 965
    if-ge v2, v3, :cond_23

    .line 966
    .line 967
    move v2, v3

    .line 968
    goto :goto_15

    .line 969
    :cond_22
    const/4 v15, 0x0

    .line 970
    iget v2, v10, Ly9/f0;->D:I

    .line 971
    .line 972
    sub-int v2, v2, v20

    .line 973
    .line 974
    int-to-float v3, v9

    .line 975
    iget v4, v10, Ly9/f0;->z:F

    .line 976
    .line 977
    mul-float/2addr v3, v4

    .line 978
    float-to-int v3, v3

    .line 979
    sub-int/2addr v2, v3

    .line 980
    :cond_23
    :goto_15
    new-instance v20, Landroid/text/StaticLayout;

    .line 981
    .line 982
    iget v3, v10, Ly9/f0;->d:F

    .line 983
    .line 984
    iget v4, v10, Ly9/f0;->e:F

    .line 985
    .line 986
    const/16 v27, 0x1

    .line 987
    .line 988
    move/from16 v25, v3

    .line 989
    .line 990
    move/from16 v26, v4

    .line 991
    .line 992
    invoke-direct/range {v20 .. v27}, Landroid/text/StaticLayout;-><init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;ILandroid/text/Layout$Alignment;FFZ)V

    .line 993
    .line 994
    .line 995
    move-object/from16 v3, v20

    .line 996
    .line 997
    iput-object v3, v10, Ly9/f0;->E:Landroid/text/StaticLayout;

    .line 998
    .line 999
    new-instance v20, Landroid/text/StaticLayout;

    .line 1000
    .line 1001
    iget v3, v10, Ly9/f0;->d:F

    .line 1002
    .line 1003
    iget v4, v10, Ly9/f0;->e:F

    .line 1004
    .line 1005
    move/from16 v25, v3

    .line 1006
    .line 1007
    move/from16 v26, v4

    .line 1008
    .line 1009
    move-object/from16 v21, v35

    .line 1010
    .line 1011
    invoke-direct/range {v20 .. v27}, Landroid/text/StaticLayout;-><init>(Ljava/lang/CharSequence;Landroid/text/TextPaint;ILandroid/text/Layout$Alignment;FFZ)V

    .line 1012
    .line 1013
    .line 1014
    move-object/from16 v3, v20

    .line 1015
    .line 1016
    iput-object v3, v10, Ly9/f0;->F:Landroid/text/StaticLayout;

    .line 1017
    .line 1018
    iput v0, v10, Ly9/f0;->G:I

    .line 1019
    .line 1020
    iput v2, v10, Ly9/f0;->H:I

    .line 1021
    .line 1022
    iput v11, v10, Ly9/f0;->I:I

    .line 1023
    .line 1024
    goto/16 :goto_1b

    .line 1025
    .line 1026
    :cond_24
    move/from16 v32, v0

    .line 1027
    .line 1028
    move/from16 v33, v4

    .line 1029
    .line 1030
    move/from16 v34, v5

    .line 1031
    .line 1032
    const/4 v15, 0x0

    .line 1033
    iget-object v0, v10, Ly9/f0;->k:Landroid/graphics/Bitmap;

    .line 1034
    .line 1035
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1036
    .line 1037
    .line 1038
    iget-object v0, v10, Ly9/f0;->k:Landroid/graphics/Bitmap;

    .line 1039
    .line 1040
    iget v2, v10, Ly9/f0;->C:I

    .line 1041
    .line 1042
    iget v3, v10, Ly9/f0;->A:I

    .line 1043
    .line 1044
    sub-int/2addr v2, v3

    .line 1045
    iget v4, v10, Ly9/f0;->D:I

    .line 1046
    .line 1047
    iget v5, v10, Ly9/f0;->B:I

    .line 1048
    .line 1049
    sub-int/2addr v4, v5

    .line 1050
    int-to-float v3, v3

    .line 1051
    int-to-float v2, v2

    .line 1052
    iget v8, v10, Ly9/f0;->o:F

    .line 1053
    .line 1054
    mul-float/2addr v8, v2

    .line 1055
    add-float/2addr v8, v3

    .line 1056
    int-to-float v3, v5

    .line 1057
    int-to-float v4, v4

    .line 1058
    iget v5, v10, Ly9/f0;->l:F

    .line 1059
    .line 1060
    mul-float/2addr v5, v4

    .line 1061
    add-float/2addr v5, v3

    .line 1062
    iget v3, v10, Ly9/f0;->q:F

    .line 1063
    .line 1064
    mul-float/2addr v2, v3

    .line 1065
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 1066
    .line 1067
    .line 1068
    move-result v2

    .line 1069
    iget v3, v10, Ly9/f0;->r:F

    .line 1070
    .line 1071
    const v18, -0x800001

    .line 1072
    .line 1073
    .line 1074
    cmpl-float v9, v3, v18

    .line 1075
    .line 1076
    if-eqz v9, :cond_25

    .line 1077
    .line 1078
    mul-float/2addr v4, v3

    .line 1079
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 1080
    .line 1081
    .line 1082
    move-result v0

    .line 1083
    goto :goto_16

    .line 1084
    :cond_25
    int-to-float v3, v2

    .line 1085
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 1086
    .line 1087
    .line 1088
    move-result v4

    .line 1089
    int-to-float v4, v4

    .line 1090
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 1091
    .line 1092
    .line 1093
    move-result v0

    .line 1094
    int-to-float v0, v0

    .line 1095
    div-float/2addr v4, v0

    .line 1096
    mul-float/2addr v4, v3

    .line 1097
    invoke-static {v4}, Ljava/lang/Math;->round(F)I

    .line 1098
    .line 1099
    .line 1100
    move-result v0

    .line 1101
    :goto_16
    iget v3, v10, Ly9/f0;->p:I

    .line 1102
    .line 1103
    const/4 v4, 0x2

    .line 1104
    if-ne v3, v4, :cond_26

    .line 1105
    .line 1106
    int-to-float v3, v2

    .line 1107
    :goto_17
    sub-float/2addr v8, v3

    .line 1108
    goto :goto_18

    .line 1109
    :cond_26
    const/4 v4, 0x1

    .line 1110
    if-ne v3, v4, :cond_27

    .line 1111
    .line 1112
    div-int/lit8 v3, v2, 0x2

    .line 1113
    .line 1114
    int-to-float v3, v3

    .line 1115
    goto :goto_17

    .line 1116
    :cond_27
    :goto_18
    invoke-static {v8}, Ljava/lang/Math;->round(F)I

    .line 1117
    .line 1118
    .line 1119
    move-result v3

    .line 1120
    iget v4, v10, Ly9/f0;->n:I

    .line 1121
    .line 1122
    const/4 v11, 0x2

    .line 1123
    if-ne v4, v11, :cond_28

    .line 1124
    .line 1125
    int-to-float v4, v0

    .line 1126
    :goto_19
    sub-float/2addr v5, v4

    .line 1127
    goto :goto_1a

    .line 1128
    :cond_28
    const/4 v8, 0x1

    .line 1129
    if-ne v4, v8, :cond_29

    .line 1130
    .line 1131
    div-int/lit8 v4, v0, 0x2

    .line 1132
    .line 1133
    int-to-float v4, v4

    .line 1134
    goto :goto_19

    .line 1135
    :cond_29
    :goto_1a
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 1136
    .line 1137
    .line 1138
    move-result v4

    .line 1139
    new-instance v5, Landroid/graphics/Rect;

    .line 1140
    .line 1141
    add-int/2addr v2, v3

    .line 1142
    add-int/2addr v0, v4

    .line 1143
    invoke-direct {v5, v3, v4, v2, v0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 1144
    .line 1145
    .line 1146
    iput-object v5, v10, Ly9/f0;->J:Landroid/graphics/Rect;

    .line 1147
    .line 1148
    :goto_1b
    invoke-virtual {v10, v1, v13}, Ly9/f0;->a(Landroid/graphics/Canvas;Z)V

    .line 1149
    .line 1150
    .line 1151
    :goto_1c
    add-int/lit8 v13, v31, 0x1

    .line 1152
    .line 1153
    move-object/from16 v0, p0

    .line 1154
    .line 1155
    move v10, v15

    .line 1156
    move/from16 v11, v16

    .line 1157
    .line 1158
    move-object/from16 v2, v19

    .line 1159
    .line 1160
    move/from16 v3, v28

    .line 1161
    .line 1162
    move/from16 v8, v29

    .line 1163
    .line 1164
    move/from16 v12, v30

    .line 1165
    .line 1166
    move/from16 v9, v32

    .line 1167
    .line 1168
    move/from16 v4, v33

    .line 1169
    .line 1170
    move/from16 v5, v34

    .line 1171
    .line 1172
    goto/16 :goto_0

    .line 1173
    .line 1174
    :cond_2a
    :goto_1d
    return-void
.end method
