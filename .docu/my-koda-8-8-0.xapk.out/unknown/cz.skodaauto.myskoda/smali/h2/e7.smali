.class public final Lh2/e7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final a:Lay0/k;

.field public final b:Z

.field public final c:Lh2/nb;

.field public final d:Li2/g1;

.field public final e:Lk1/z0;

.field public final f:F


# direct methods
.method public constructor <init>(Lay0/k;ZLh2/nb;Li2/g1;Lk1/z0;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/e7;->a:Lay0/k;

    .line 5
    .line 6
    iput-boolean p2, p0, Lh2/e7;->b:Z

    .line 7
    .line 8
    iput-object p3, p0, Lh2/e7;->c:Lh2/nb;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/e7;->d:Li2/g1;

    .line 11
    .line 12
    iput-object p5, p0, Lh2/e7;->e:Lk1/z0;

    .line 13
    .line 14
    iput p6, p0, Lh2/e7;->f:F

    .line 15
    .line 16
    return-void
.end method

.method public static final m(ILh2/e7;IILt3/e1;Lt3/e1;)I
    .locals 0

    .line 1
    iget-boolean p1, p1, Lh2/e7;->b:Z

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    iget p1, p5, Lt3/e1;->e:I

    .line 6
    .line 7
    sub-int/2addr p2, p1

    .line 8
    int-to-float p1, p2

    .line 9
    const/high16 p2, 0x40000000    # 2.0f

    .line 10
    .line 11
    div-float/2addr p1, p2

    .line 12
    const/4 p2, 0x1

    .line 13
    int-to-float p2, p2

    .line 14
    const/4 p3, 0x0

    .line 15
    add-float/2addr p2, p3

    .line 16
    mul-float/2addr p2, p1

    .line 17
    invoke-static {p2}, Ljava/lang/Math;->round(F)I

    .line 18
    .line 19
    .line 20
    move-result p3

    .line 21
    :cond_0
    add-int/2addr p0, p3

    .line 22
    if-eqz p4, :cond_1

    .line 23
    .line 24
    iget p1, p4, Lt3/e1;->e:I

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 p1, 0x0

    .line 28
    :goto_0
    div-int/lit8 p1, p1, 0x2

    .line 29
    .line 30
    invoke-static {p0, p1}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0xb

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/e7;->l(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 43

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v13, p2

    .line 6
    .line 7
    iget-object v2, v0, Lh2/e7;->d:Li2/g1;

    .line 8
    .line 9
    invoke-virtual {v2}, Li2/g1;->invoke()F

    .line 10
    .line 11
    .line 12
    move-result v11

    .line 13
    iget-object v2, v0, Lh2/e7;->e:Lk1/z0;

    .line 14
    .line 15
    invoke-interface {v2}, Lk1/z0;->c()F

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-interface {v1, v3}, Lt4/c;->Q(F)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/4 v9, 0x0

    .line 24
    const/16 v10, 0xa

    .line 25
    .line 26
    const/4 v6, 0x0

    .line 27
    const/4 v7, 0x0

    .line 28
    const/4 v8, 0x0

    .line 29
    move-wide/from16 v4, p3

    .line 30
    .line 31
    invoke-static/range {v4 .. v10}, Lt4/a;->a(JIIIII)J

    .line 32
    .line 33
    .line 34
    move-result-wide v14

    .line 35
    move-object v4, v13

    .line 36
    check-cast v4, Ljava/util/Collection;

    .line 37
    .line 38
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    const/4 v12, 0x0

    .line 43
    move v6, v12

    .line 44
    :goto_0
    const/16 v16, 0x0

    .line 45
    .line 46
    if-ge v6, v5, :cond_1

    .line 47
    .line 48
    invoke-interface {v13, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object v7

    .line 52
    move-object v8, v7

    .line 53
    check-cast v8, Lt3/p0;

    .line 54
    .line 55
    invoke-static {v8}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    const-string v9, "Leading"

    .line 60
    .line 61
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v8

    .line 65
    if-eqz v8, :cond_0

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_0
    add-int/lit8 v6, v6, 0x1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    move-object/from16 v7, v16

    .line 72
    .line 73
    :goto_1
    check-cast v7, Lt3/p0;

    .line 74
    .line 75
    if-eqz v7, :cond_2

    .line 76
    .line 77
    invoke-interface {v7, v14, v15}, Lt3/p0;->L(J)Lt3/e1;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    goto :goto_2

    .line 82
    :cond_2
    move-object/from16 v5, v16

    .line 83
    .line 84
    :goto_2
    if-eqz v5, :cond_3

    .line 85
    .line 86
    iget v6, v5, Lt3/e1;->d:I

    .line 87
    .line 88
    goto :goto_3

    .line 89
    :cond_3
    move v6, v12

    .line 90
    :goto_3
    if-eqz v5, :cond_4

    .line 91
    .line 92
    iget v7, v5, Lt3/e1;->e:I

    .line 93
    .line 94
    goto :goto_4

    .line 95
    :cond_4
    move v7, v12

    .line 96
    :goto_4
    invoke-static {v12, v7}, Ljava/lang/Math;->max(II)I

    .line 97
    .line 98
    .line 99
    move-result v7

    .line 100
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 101
    .line 102
    .line 103
    move-result v8

    .line 104
    move v9, v12

    .line 105
    :goto_5
    if-ge v9, v8, :cond_6

    .line 106
    .line 107
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v10

    .line 111
    move-object/from16 v17, v10

    .line 112
    .line 113
    check-cast v17, Lt3/p0;

    .line 114
    .line 115
    invoke-static/range {v17 .. v17}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v12

    .line 119
    move-object/from16 v17, v4

    .line 120
    .line 121
    const-string v4, "Trailing"

    .line 122
    .line 123
    invoke-static {v12, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v4

    .line 127
    if-eqz v4, :cond_5

    .line 128
    .line 129
    goto :goto_6

    .line 130
    :cond_5
    add-int/lit8 v9, v9, 0x1

    .line 131
    .line 132
    move-object/from16 v4, v17

    .line 133
    .line 134
    const/4 v12, 0x0

    .line 135
    goto :goto_5

    .line 136
    :cond_6
    move-object/from16 v17, v4

    .line 137
    .line 138
    move-object/from16 v10, v16

    .line 139
    .line 140
    :goto_6
    check-cast v10, Lt3/p0;

    .line 141
    .line 142
    const/4 v4, 0x2

    .line 143
    if-eqz v10, :cond_7

    .line 144
    .line 145
    neg-int v8, v6

    .line 146
    move-object v12, v5

    .line 147
    move/from16 v19, v6

    .line 148
    .line 149
    const/4 v9, 0x0

    .line 150
    invoke-static {v14, v15, v8, v9, v4}, Lt4/b;->j(JIII)J

    .line 151
    .line 152
    .line 153
    move-result-wide v5

    .line 154
    invoke-interface {v10, v5, v6}, Lt3/p0;->L(J)Lt3/e1;

    .line 155
    .line 156
    .line 157
    move-result-object v5

    .line 158
    goto :goto_7

    .line 159
    :cond_7
    move-object v12, v5

    .line 160
    move/from16 v19, v6

    .line 161
    .line 162
    move-object/from16 v5, v16

    .line 163
    .line 164
    :goto_7
    if-eqz v5, :cond_8

    .line 165
    .line 166
    iget v6, v5, Lt3/e1;->d:I

    .line 167
    .line 168
    goto :goto_8

    .line 169
    :cond_8
    const/4 v6, 0x0

    .line 170
    :goto_8
    add-int v6, v19, v6

    .line 171
    .line 172
    if-eqz v5, :cond_9

    .line 173
    .line 174
    iget v8, v5, Lt3/e1;->e:I

    .line 175
    .line 176
    goto :goto_9

    .line 177
    :cond_9
    const/4 v8, 0x0

    .line 178
    :goto_9
    invoke-static {v7, v8}, Ljava/lang/Math;->max(II)I

    .line 179
    .line 180
    .line 181
    move-result v7

    .line 182
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 183
    .line 184
    .line 185
    move-result v8

    .line 186
    const/4 v9, 0x0

    .line 187
    :goto_a
    if-ge v9, v8, :cond_b

    .line 188
    .line 189
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v10

    .line 193
    move-object/from16 v19, v10

    .line 194
    .line 195
    check-cast v19, Lt3/p0;

    .line 196
    .line 197
    invoke-static/range {v19 .. v19}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    move/from16 v19, v8

    .line 202
    .line 203
    const-string v8, "Prefix"

    .line 204
    .line 205
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result v4

    .line 209
    if-eqz v4, :cond_a

    .line 210
    .line 211
    goto :goto_b

    .line 212
    :cond_a
    add-int/lit8 v9, v9, 0x1

    .line 213
    .line 214
    move/from16 v8, v19

    .line 215
    .line 216
    const/4 v4, 0x2

    .line 217
    goto :goto_a

    .line 218
    :cond_b
    move-object/from16 v10, v16

    .line 219
    .line 220
    :goto_b
    check-cast v10, Lt3/p0;

    .line 221
    .line 222
    if-eqz v10, :cond_c

    .line 223
    .line 224
    neg-int v4, v6

    .line 225
    move-object/from16 v19, v5

    .line 226
    .line 227
    const/4 v8, 0x2

    .line 228
    const/4 v9, 0x0

    .line 229
    invoke-static {v14, v15, v4, v9, v8}, Lt4/b;->j(JIII)J

    .line 230
    .line 231
    .line 232
    move-result-wide v4

    .line 233
    invoke-interface {v10, v4, v5}, Lt3/p0;->L(J)Lt3/e1;

    .line 234
    .line 235
    .line 236
    move-result-object v4

    .line 237
    goto :goto_c

    .line 238
    :cond_c
    move-object/from16 v19, v5

    .line 239
    .line 240
    move-object/from16 v4, v16

    .line 241
    .line 242
    :goto_c
    if-eqz v4, :cond_d

    .line 243
    .line 244
    iget v5, v4, Lt3/e1;->d:I

    .line 245
    .line 246
    goto :goto_d

    .line 247
    :cond_d
    const/4 v5, 0x0

    .line 248
    :goto_d
    add-int/2addr v6, v5

    .line 249
    if-eqz v4, :cond_e

    .line 250
    .line 251
    iget v5, v4, Lt3/e1;->e:I

    .line 252
    .line 253
    goto :goto_e

    .line 254
    :cond_e
    const/4 v5, 0x0

    .line 255
    :goto_e
    invoke-static {v7, v5}, Ljava/lang/Math;->max(II)I

    .line 256
    .line 257
    .line 258
    move-result v5

    .line 259
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 260
    .line 261
    .line 262
    move-result v7

    .line 263
    const/4 v8, 0x0

    .line 264
    :goto_f
    if-ge v8, v7, :cond_10

    .line 265
    .line 266
    invoke-interface {v13, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v9

    .line 270
    move-object v10, v9

    .line 271
    check-cast v10, Lt3/p0;

    .line 272
    .line 273
    invoke-static {v10}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v10

    .line 277
    move/from16 v21, v7

    .line 278
    .line 279
    const-string v7, "Suffix"

    .line 280
    .line 281
    invoke-static {v10, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v7

    .line 285
    if-eqz v7, :cond_f

    .line 286
    .line 287
    goto :goto_10

    .line 288
    :cond_f
    add-int/lit8 v8, v8, 0x1

    .line 289
    .line 290
    move/from16 v7, v21

    .line 291
    .line 292
    goto :goto_f

    .line 293
    :cond_10
    move-object/from16 v9, v16

    .line 294
    .line 295
    :goto_10
    check-cast v9, Lt3/p0;

    .line 296
    .line 297
    if-eqz v9, :cond_11

    .line 298
    .line 299
    neg-int v7, v6

    .line 300
    move/from16 v21, v6

    .line 301
    .line 302
    const/4 v8, 0x2

    .line 303
    const/4 v10, 0x0

    .line 304
    invoke-static {v14, v15, v7, v10, v8}, Lt4/b;->j(JIII)J

    .line 305
    .line 306
    .line 307
    move-result-wide v6

    .line 308
    invoke-interface {v9, v6, v7}, Lt3/p0;->L(J)Lt3/e1;

    .line 309
    .line 310
    .line 311
    move-result-object v6

    .line 312
    goto :goto_11

    .line 313
    :cond_11
    move/from16 v21, v6

    .line 314
    .line 315
    move-object/from16 v6, v16

    .line 316
    .line 317
    :goto_11
    if-eqz v6, :cond_12

    .line 318
    .line 319
    iget v9, v6, Lt3/e1;->d:I

    .line 320
    .line 321
    goto :goto_12

    .line 322
    :cond_12
    const/4 v9, 0x0

    .line 323
    :goto_12
    add-int v7, v21, v9

    .line 324
    .line 325
    if-eqz v6, :cond_13

    .line 326
    .line 327
    iget v9, v6, Lt3/e1;->e:I

    .line 328
    .line 329
    goto :goto_13

    .line 330
    :cond_13
    const/4 v9, 0x0

    .line 331
    :goto_13
    invoke-static {v5, v9}, Ljava/lang/Math;->max(II)I

    .line 332
    .line 333
    .line 334
    move-result v5

    .line 335
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 336
    .line 337
    .line 338
    move-result v8

    .line 339
    const/4 v9, 0x0

    .line 340
    :goto_14
    if-ge v9, v8, :cond_15

    .line 341
    .line 342
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 343
    .line 344
    .line 345
    move-result-object v10

    .line 346
    move-object/from16 v21, v10

    .line 347
    .line 348
    check-cast v21, Lt3/p0;

    .line 349
    .line 350
    move/from16 v22, v8

    .line 351
    .line 352
    invoke-static/range {v21 .. v21}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v8

    .line 356
    move/from16 v21, v9

    .line 357
    .line 358
    const-string v9, "Label"

    .line 359
    .line 360
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    move-result v8

    .line 364
    if-eqz v8, :cond_14

    .line 365
    .line 366
    goto :goto_15

    .line 367
    :cond_14
    add-int/lit8 v9, v21, 0x1

    .line 368
    .line 369
    move/from16 v8, v22

    .line 370
    .line 371
    goto :goto_14

    .line 372
    :cond_15
    move-object/from16 v10, v16

    .line 373
    .line 374
    :goto_15
    check-cast v10, Lt3/p0;

    .line 375
    .line 376
    new-instance v8, Lkotlin/jvm/internal/f0;

    .line 377
    .line 378
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 379
    .line 380
    .line 381
    invoke-interface {v1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 382
    .line 383
    .line 384
    move-result-object v9

    .line 385
    invoke-interface {v2, v9}, Lk1/z0;->b(Lt4/m;)F

    .line 386
    .line 387
    .line 388
    move-result v9

    .line 389
    invoke-interface {v1, v9}, Lt4/c;->Q(F)I

    .line 390
    .line 391
    .line 392
    move-result v9

    .line 393
    move/from16 v21, v9

    .line 394
    .line 395
    invoke-interface {v1}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 396
    .line 397
    .line 398
    move-result-object v9

    .line 399
    invoke-interface {v2, v9}, Lk1/z0;->a(Lt4/m;)F

    .line 400
    .line 401
    .line 402
    move-result v9

    .line 403
    invoke-interface {v1, v9}, Lt4/c;->Q(F)I

    .line 404
    .line 405
    .line 406
    move-result v9

    .line 407
    add-int v9, v9, v21

    .line 408
    .line 409
    move-object/from16 v21, v2

    .line 410
    .line 411
    add-int v2, v7, v9

    .line 412
    .line 413
    invoke-static {v11, v2, v9}, Llp/wa;->c(FII)I

    .line 414
    .line 415
    .line 416
    move-result v2

    .line 417
    neg-int v2, v2

    .line 418
    neg-int v9, v3

    .line 419
    move/from16 v22, v3

    .line 420
    .line 421
    invoke-static {v14, v15, v2, v9}, Lt4/b;->i(JII)J

    .line 422
    .line 423
    .line 424
    move-result-wide v2

    .line 425
    if-eqz v10, :cond_16

    .line 426
    .line 427
    invoke-interface {v10, v2, v3}, Lt3/p0;->L(J)Lt3/e1;

    .line 428
    .line 429
    .line 430
    move-result-object v2

    .line 431
    goto :goto_16

    .line 432
    :cond_16
    move-object/from16 v2, v16

    .line 433
    .line 434
    :goto_16
    iput-object v2, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 435
    .line 436
    if-eqz v2, :cond_17

    .line 437
    .line 438
    iget v3, v2, Lt3/e1;->d:I

    .line 439
    .line 440
    int-to-float v3, v3

    .line 441
    iget v2, v2, Lt3/e1;->e:I

    .line 442
    .line 443
    int-to-float v2, v2

    .line 444
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 445
    .line 446
    .line 447
    move-result v3

    .line 448
    move v10, v2

    .line 449
    int-to-long v2, v3

    .line 450
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 451
    .line 452
    .line 453
    move-result v10

    .line 454
    move-wide/from16 v23, v2

    .line 455
    .line 456
    int-to-long v2, v10

    .line 457
    const/16 v10, 0x20

    .line 458
    .line 459
    shl-long v23, v23, v10

    .line 460
    .line 461
    const-wide v25, 0xffffffffL

    .line 462
    .line 463
    .line 464
    .line 465
    .line 466
    and-long v2, v2, v25

    .line 467
    .line 468
    or-long v2, v23, v2

    .line 469
    .line 470
    goto :goto_17

    .line 471
    :cond_17
    const-wide/16 v2, 0x0

    .line 472
    .line 473
    :goto_17
    new-instance v10, Ld3/e;

    .line 474
    .line 475
    invoke-direct {v10, v2, v3}, Ld3/e;-><init>(J)V

    .line 476
    .line 477
    .line 478
    iget-object v2, v0, Lh2/e7;->a:Lay0/k;

    .line 479
    .line 480
    invoke-interface {v2, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 484
    .line 485
    .line 486
    move-result v2

    .line 487
    const/4 v3, 0x0

    .line 488
    :goto_18
    if-ge v3, v2, :cond_19

    .line 489
    .line 490
    invoke-interface {v13, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 491
    .line 492
    .line 493
    move-result-object v10

    .line 494
    move-object/from16 v23, v10

    .line 495
    .line 496
    check-cast v23, Lt3/p0;

    .line 497
    .line 498
    invoke-static/range {v23 .. v23}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 499
    .line 500
    .line 501
    move-result-object v0

    .line 502
    move/from16 v23, v2

    .line 503
    .line 504
    const-string v2, "Supporting"

    .line 505
    .line 506
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 507
    .line 508
    .line 509
    move-result v0

    .line 510
    if-eqz v0, :cond_18

    .line 511
    .line 512
    goto :goto_19

    .line 513
    :cond_18
    add-int/lit8 v3, v3, 0x1

    .line 514
    .line 515
    move-object/from16 v0, p0

    .line 516
    .line 517
    move/from16 v2, v23

    .line 518
    .line 519
    goto :goto_18

    .line 520
    :cond_19
    move-object/from16 v10, v16

    .line 521
    .line 522
    :goto_19
    move-object v0, v10

    .line 523
    check-cast v0, Lt3/p0;

    .line 524
    .line 525
    if-eqz v0, :cond_1a

    .line 526
    .line 527
    invoke-static/range {p3 .. p4}, Lt4/a;->j(J)I

    .line 528
    .line 529
    .line 530
    move-result v2

    .line 531
    invoke-interface {v0, v2}, Lt3/p0;->A(I)I

    .line 532
    .line 533
    .line 534
    move-result v2

    .line 535
    goto :goto_1a

    .line 536
    :cond_1a
    const/4 v2, 0x0

    .line 537
    :goto_1a
    iget-object v3, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 538
    .line 539
    check-cast v3, Lt3/e1;

    .line 540
    .line 541
    if-eqz v3, :cond_1b

    .line 542
    .line 543
    iget v3, v3, Lt3/e1;->e:I

    .line 544
    .line 545
    :goto_1b
    const/16 v20, 0x2

    .line 546
    .line 547
    goto :goto_1c

    .line 548
    :cond_1b
    const/4 v3, 0x0

    .line 549
    goto :goto_1b

    .line 550
    :goto_1c
    div-int/lit8 v3, v3, 0x2

    .line 551
    .line 552
    invoke-interface/range {v21 .. v21}, Lk1/z0;->d()F

    .line 553
    .line 554
    .line 555
    move-result v10

    .line 556
    invoke-interface {v1, v10}, Lt4/c;->Q(F)I

    .line 557
    .line 558
    .line 559
    move-result v10

    .line 560
    invoke-static {v3, v10}, Ljava/lang/Math;->max(II)I

    .line 561
    .line 562
    .line 563
    move-result v3

    .line 564
    neg-int v7, v7

    .line 565
    sub-int/2addr v9, v3

    .line 566
    sub-int/2addr v9, v2

    .line 567
    move-object v2, v0

    .line 568
    move-wide/from16 v0, p3

    .line 569
    .line 570
    invoke-static {v0, v1, v7, v9}, Lt4/b;->i(JII)J

    .line 571
    .line 572
    .line 573
    move-result-wide v23

    .line 574
    const/16 v28, 0x0

    .line 575
    .line 576
    const/16 v29, 0xb

    .line 577
    .line 578
    const/16 v25, 0x0

    .line 579
    .line 580
    const/16 v26, 0x0

    .line 581
    .line 582
    const/16 v27, 0x0

    .line 583
    .line 584
    invoke-static/range {v23 .. v29}, Lt4/a;->a(JIIIII)J

    .line 585
    .line 586
    .line 587
    move-result-wide v9

    .line 588
    invoke-interface/range {v17 .. v17}, Ljava/util/Collection;->size()I

    .line 589
    .line 590
    .line 591
    move-result v7

    .line 592
    const/4 v0, 0x0

    .line 593
    :goto_1d
    const-string v17, "Collection contains no element matching the predicate."

    .line 594
    .line 595
    if-ge v0, v7, :cond_34

    .line 596
    .line 597
    invoke-interface {v13, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 598
    .line 599
    .line 600
    move-result-object v1

    .line 601
    check-cast v1, Lt3/p0;

    .line 602
    .line 603
    move/from16 v20, v0

    .line 604
    .line 605
    invoke-static {v1}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 606
    .line 607
    .line 608
    move-result-object v0

    .line 609
    move-object/from16 v21, v2

    .line 610
    .line 611
    const-string v2, "TextField"

    .line 612
    .line 613
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 614
    .line 615
    .line 616
    move-result v0

    .line 617
    if-eqz v0, :cond_33

    .line 618
    .line 619
    invoke-interface {v1, v9, v10}, Lt3/p0;->L(J)Lt3/e1;

    .line 620
    .line 621
    .line 622
    move-result-object v0

    .line 623
    const/16 v35, 0x0

    .line 624
    .line 625
    const/16 v36, 0xe

    .line 626
    .line 627
    const/16 v32, 0x0

    .line 628
    .line 629
    const/16 v33, 0x0

    .line 630
    .line 631
    const/16 v34, 0x0

    .line 632
    .line 633
    move-wide/from16 v30, v9

    .line 634
    .line 635
    invoke-static/range {v30 .. v36}, Lt4/a;->a(JIIIII)J

    .line 636
    .line 637
    .line 638
    move-result-wide v1

    .line 639
    move-object/from16 v20, v13

    .line 640
    .line 641
    check-cast v20, Ljava/util/Collection;

    .line 642
    .line 643
    invoke-interface/range {v20 .. v20}, Ljava/util/Collection;->size()I

    .line 644
    .line 645
    .line 646
    move-result v7

    .line 647
    const/4 v9, 0x0

    .line 648
    :goto_1e
    if-ge v9, v7, :cond_1d

    .line 649
    .line 650
    invoke-interface {v13, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 651
    .line 652
    .line 653
    move-result-object v10

    .line 654
    move-object/from16 v23, v10

    .line 655
    .line 656
    check-cast v23, Lt3/p0;

    .line 657
    .line 658
    move/from16 v24, v3

    .line 659
    .line 660
    invoke-static/range {v23 .. v23}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 661
    .line 662
    .line 663
    move-result-object v3

    .line 664
    move/from16 v23, v7

    .line 665
    .line 666
    const-string v7, "Hint"

    .line 667
    .line 668
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 669
    .line 670
    .line 671
    move-result v3

    .line 672
    if-eqz v3, :cond_1c

    .line 673
    .line 674
    goto :goto_1f

    .line 675
    :cond_1c
    add-int/lit8 v9, v9, 0x1

    .line 676
    .line 677
    move/from16 v7, v23

    .line 678
    .line 679
    move/from16 v3, v24

    .line 680
    .line 681
    goto :goto_1e

    .line 682
    :cond_1d
    move/from16 v24, v3

    .line 683
    .line 684
    move-object/from16 v10, v16

    .line 685
    .line 686
    :goto_1f
    check-cast v10, Lt3/p0;

    .line 687
    .line 688
    if-eqz v10, :cond_1e

    .line 689
    .line 690
    invoke-interface {v10, v1, v2}, Lt3/p0;->L(J)Lt3/e1;

    .line 691
    .line 692
    .line 693
    move-result-object v1

    .line 694
    goto :goto_20

    .line 695
    :cond_1e
    move-object/from16 v1, v16

    .line 696
    .line 697
    :goto_20
    iget v2, v0, Lt3/e1;->e:I

    .line 698
    .line 699
    if-eqz v1, :cond_1f

    .line 700
    .line 701
    iget v9, v1, Lt3/e1;->e:I

    .line 702
    .line 703
    goto :goto_21

    .line 704
    :cond_1f
    const/4 v9, 0x0

    .line 705
    :goto_21
    invoke-static {v2, v9}, Ljava/lang/Math;->max(II)I

    .line 706
    .line 707
    .line 708
    move-result v2

    .line 709
    add-int v2, v2, v24

    .line 710
    .line 711
    add-int v2, v2, v22

    .line 712
    .line 713
    invoke-static {v5, v2}, Ljava/lang/Math;->max(II)I

    .line 714
    .line 715
    .line 716
    move-result v2

    .line 717
    if-eqz v12, :cond_20

    .line 718
    .line 719
    iget v9, v12, Lt3/e1;->d:I

    .line 720
    .line 721
    goto :goto_22

    .line 722
    :cond_20
    const/4 v9, 0x0

    .line 723
    :goto_22
    move-object/from16 v5, v19

    .line 724
    .line 725
    if-eqz v19, :cond_21

    .line 726
    .line 727
    iget v3, v5, Lt3/e1;->d:I

    .line 728
    .line 729
    goto :goto_23

    .line 730
    :cond_21
    const/4 v3, 0x0

    .line 731
    :goto_23
    if-eqz v4, :cond_22

    .line 732
    .line 733
    iget v7, v4, Lt3/e1;->d:I

    .line 734
    .line 735
    move/from16 v42, v7

    .line 736
    .line 737
    move-object v7, v4

    .line 738
    move/from16 v4, v42

    .line 739
    .line 740
    goto :goto_24

    .line 741
    :cond_22
    move-object v7, v4

    .line 742
    const/4 v4, 0x0

    .line 743
    :goto_24
    if-eqz v6, :cond_23

    .line 744
    .line 745
    iget v10, v6, Lt3/e1;->d:I

    .line 746
    .line 747
    move-object/from16 v19, v5

    .line 748
    .line 749
    move v5, v10

    .line 750
    :goto_25
    move-object v10, v6

    .line 751
    goto :goto_26

    .line 752
    :cond_23
    move-object/from16 v19, v5

    .line 753
    .line 754
    const/4 v5, 0x0

    .line 755
    goto :goto_25

    .line 756
    :goto_26
    iget v6, v0, Lt3/e1;->d:I

    .line 757
    .line 758
    move-object/from16 v23, v0

    .line 759
    .line 760
    iget-object v0, v8, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 761
    .line 762
    check-cast v0, Lt3/e1;

    .line 763
    .line 764
    if-eqz v0, :cond_24

    .line 765
    .line 766
    iget v0, v0, Lt3/e1;->d:I

    .line 767
    .line 768
    move-object/from16 v42, v7

    .line 769
    .line 770
    move v7, v0

    .line 771
    move-object/from16 v0, v42

    .line 772
    .line 773
    goto :goto_27

    .line 774
    :cond_24
    move-object v0, v7

    .line 775
    const/4 v7, 0x0

    .line 776
    :goto_27
    if-eqz v1, :cond_25

    .line 777
    .line 778
    move-object/from16 v22, v0

    .line 779
    .line 780
    iget v0, v1, Lt3/e1;->d:I

    .line 781
    .line 782
    move-object/from16 v39, v8

    .line 783
    .line 784
    move-object/from16 v37, v22

    .line 785
    .line 786
    move v8, v0

    .line 787
    move-object/from16 v41, v1

    .line 788
    .line 789
    move-object/from16 v38, v10

    .line 790
    .line 791
    move-object/from16 v13, v21

    .line 792
    .line 793
    move-object/from16 v40, v23

    .line 794
    .line 795
    move-object/from16 v1, p1

    .line 796
    .line 797
    move-object/from16 v21, v12

    .line 798
    .line 799
    move-object/from16 v0, p0

    .line 800
    .line 801
    :goto_28
    move v12, v2

    .line 802
    move v2, v9

    .line 803
    move-wide/from16 v9, p3

    .line 804
    .line 805
    goto :goto_29

    .line 806
    :cond_25
    move-object/from16 v37, v0

    .line 807
    .line 808
    move-object/from16 v39, v8

    .line 809
    .line 810
    const/4 v8, 0x0

    .line 811
    move-object/from16 v41, v1

    .line 812
    .line 813
    move-object/from16 v38, v10

    .line 814
    .line 815
    move-object/from16 v13, v21

    .line 816
    .line 817
    move-object/from16 v40, v23

    .line 818
    .line 819
    move-object/from16 v0, p0

    .line 820
    .line 821
    move-object/from16 v1, p1

    .line 822
    .line 823
    move-object/from16 v21, v12

    .line 824
    .line 825
    goto :goto_28

    .line 826
    :goto_29
    invoke-virtual/range {v0 .. v11}, Lh2/e7;->i(Lt3/t;IIIIIIIJF)I

    .line 827
    .line 828
    .line 829
    move-result v3

    .line 830
    neg-int v0, v12

    .line 831
    const/4 v1, 0x1

    .line 832
    const/4 v9, 0x0

    .line 833
    invoke-static {v14, v15, v9, v0, v1}, Lt4/b;->j(JIII)J

    .line 834
    .line 835
    .line 836
    move-result-wide v22

    .line 837
    const/16 v27, 0x0

    .line 838
    .line 839
    const/16 v28, 0x9

    .line 840
    .line 841
    const/16 v24, 0x0

    .line 842
    .line 843
    const/16 v26, 0x0

    .line 844
    .line 845
    move/from16 v25, v3

    .line 846
    .line 847
    invoke-static/range {v22 .. v28}, Lt4/a;->a(JIIIII)J

    .line 848
    .line 849
    .line 850
    move-result-wide v0

    .line 851
    move/from16 v14, v25

    .line 852
    .line 853
    if-eqz v13, :cond_26

    .line 854
    .line 855
    invoke-interface {v13, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 856
    .line 857
    .line 858
    move-result-object v16

    .line 859
    :cond_26
    move-object/from16 v13, v16

    .line 860
    .line 861
    if-eqz v13, :cond_27

    .line 862
    .line 863
    iget v0, v13, Lt3/e1;->e:I

    .line 864
    .line 865
    move v15, v0

    .line 866
    goto :goto_2a

    .line 867
    :cond_27
    move v15, v9

    .line 868
    :goto_2a
    move-object/from16 v12, v21

    .line 869
    .line 870
    if-eqz v21, :cond_28

    .line 871
    .line 872
    iget v0, v12, Lt3/e1;->e:I

    .line 873
    .line 874
    move v2, v0

    .line 875
    goto :goto_2b

    .line 876
    :cond_28
    move v2, v9

    .line 877
    :goto_2b
    move-object/from16 v0, v19

    .line 878
    .line 879
    if-eqz v19, :cond_29

    .line 880
    .line 881
    iget v1, v0, Lt3/e1;->e:I

    .line 882
    .line 883
    move v3, v1

    .line 884
    :goto_2c
    move-object/from16 v1, v37

    .line 885
    .line 886
    goto :goto_2d

    .line 887
    :cond_29
    move v3, v9

    .line 888
    goto :goto_2c

    .line 889
    :goto_2d
    if-eqz v1, :cond_2a

    .line 890
    .line 891
    iget v4, v1, Lt3/e1;->e:I

    .line 892
    .line 893
    :goto_2e
    move-object/from16 v5, v38

    .line 894
    .line 895
    goto :goto_2f

    .line 896
    :cond_2a
    move v4, v9

    .line 897
    goto :goto_2e

    .line 898
    :goto_2f
    if-eqz v5, :cond_2b

    .line 899
    .line 900
    iget v6, v5, Lt3/e1;->e:I

    .line 901
    .line 902
    :goto_30
    move-object/from16 v7, v40

    .line 903
    .line 904
    goto :goto_31

    .line 905
    :cond_2b
    move v6, v9

    .line 906
    goto :goto_30

    .line 907
    :goto_31
    iget v8, v7, Lt3/e1;->e:I

    .line 908
    .line 909
    move-object/from16 v10, v39

    .line 910
    .line 911
    iget-object v9, v10, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 912
    .line 913
    check-cast v9, Lt3/e1;

    .line 914
    .line 915
    if-eqz v9, :cond_2c

    .line 916
    .line 917
    iget v9, v9, Lt3/e1;->e:I

    .line 918
    .line 919
    :goto_32
    move/from16 v16, v15

    .line 920
    .line 921
    move-object/from16 v15, v41

    .line 922
    .line 923
    goto :goto_33

    .line 924
    :cond_2c
    const/4 v9, 0x0

    .line 925
    goto :goto_32

    .line 926
    :goto_33
    move-object/from16 v19, v0

    .line 927
    .line 928
    if-eqz v15, :cond_2d

    .line 929
    .line 930
    iget v0, v15, Lt3/e1;->e:I

    .line 931
    .line 932
    move-object/from16 v38, v5

    .line 933
    .line 934
    move v5, v6

    .line 935
    move v6, v8

    .line 936
    move v8, v0

    .line 937
    goto :goto_34

    .line 938
    :cond_2d
    move-object/from16 v38, v5

    .line 939
    .line 940
    move v5, v6

    .line 941
    move v6, v8

    .line 942
    const/4 v8, 0x0

    .line 943
    :goto_34
    if-eqz v13, :cond_2e

    .line 944
    .line 945
    iget v0, v13, Lt3/e1;->e:I

    .line 946
    .line 947
    move-object/from16 v23, v7

    .line 948
    .line 949
    move v7, v9

    .line 950
    move v9, v0

    .line 951
    move-object/from16 v37, v1

    .line 952
    .line 953
    move-object/from16 v39, v10

    .line 954
    .line 955
    move-object/from16 v21, v12

    .line 956
    .line 957
    const/16 v18, 0x0

    .line 958
    .line 959
    move-object/from16 v1, p1

    .line 960
    .line 961
    move v12, v11

    .line 962
    move-object/from16 v0, p0

    .line 963
    .line 964
    :goto_35
    move-wide/from16 v10, p3

    .line 965
    .line 966
    goto :goto_36

    .line 967
    :cond_2e
    move-object/from16 v23, v7

    .line 968
    .line 969
    move v7, v9

    .line 970
    const/4 v9, 0x0

    .line 971
    move-object/from16 v0, p0

    .line 972
    .line 973
    move-object/from16 v37, v1

    .line 974
    .line 975
    move-object/from16 v39, v10

    .line 976
    .line 977
    move-object/from16 v21, v12

    .line 978
    .line 979
    const/16 v18, 0x0

    .line 980
    .line 981
    move-object/from16 v1, p1

    .line 982
    .line 983
    move v12, v11

    .line 984
    goto :goto_35

    .line 985
    :goto_36
    invoke-virtual/range {v0 .. v12}, Lh2/e7;->f(Lt3/t;IIIIIIIIJF)I

    .line 986
    .line 987
    .line 988
    move-result v2

    .line 989
    move v11, v12

    .line 990
    sub-int v12, v2, v16

    .line 991
    .line 992
    invoke-interface/range {v20 .. v20}, Ljava/util/Collection;->size()I

    .line 993
    .line 994
    .line 995
    move-result v0

    .line 996
    move/from16 v1, v18

    .line 997
    .line 998
    :goto_37
    if-ge v1, v0, :cond_32

    .line 999
    .line 1000
    move-object/from16 v3, p2

    .line 1001
    .line 1002
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1003
    .line 1004
    .line 1005
    move-result-object v4

    .line 1006
    check-cast v4, Lt3/p0;

    .line 1007
    .line 1008
    invoke-static {v4}, Landroidx/compose/ui/layout/a;->a(Lt3/p0;)Ljava/lang/Object;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v5

    .line 1012
    const-string v6, "Container"

    .line 1013
    .line 1014
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1015
    .line 1016
    .line 1017
    move-result v5

    .line 1018
    if-eqz v5, :cond_31

    .line 1019
    .line 1020
    const v0, 0x7fffffff

    .line 1021
    .line 1022
    .line 1023
    if-eq v14, v0, :cond_2f

    .line 1024
    .line 1025
    move v1, v14

    .line 1026
    goto :goto_38

    .line 1027
    :cond_2f
    move/from16 v1, v18

    .line 1028
    .line 1029
    :goto_38
    if-eq v12, v0, :cond_30

    .line 1030
    .line 1031
    move v0, v12

    .line 1032
    goto :goto_39

    .line 1033
    :cond_30
    move/from16 v0, v18

    .line 1034
    .line 1035
    :goto_39
    invoke-static {v1, v14, v0, v12}, Lt4/b;->a(IIII)J

    .line 1036
    .line 1037
    .line 1038
    move-result-wide v0

    .line 1039
    invoke-interface {v4, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 1040
    .line 1041
    .line 1042
    move-result-object v0

    .line 1043
    move v12, v11

    .line 1044
    move-object v11, v0

    .line 1045
    new-instance v0, Lh2/d7;

    .line 1046
    .line 1047
    move-object/from16 v1, p0

    .line 1048
    .line 1049
    move v3, v14

    .line 1050
    move-object v10, v15

    .line 1051
    move-object/from16 v5, v19

    .line 1052
    .line 1053
    move-object/from16 v4, v21

    .line 1054
    .line 1055
    move-object/from16 v8, v23

    .line 1056
    .line 1057
    move-object/from16 v6, v37

    .line 1058
    .line 1059
    move-object/from16 v7, v38

    .line 1060
    .line 1061
    move-object/from16 v9, v39

    .line 1062
    .line 1063
    move v14, v12

    .line 1064
    move-object v12, v13

    .line 1065
    move-object/from16 v13, p1

    .line 1066
    .line 1067
    invoke-direct/range {v0 .. v14}, Lh2/d7;-><init>(Lh2/e7;IILt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lkotlin/jvm/internal/f0;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/s0;F)V

    .line 1068
    .line 1069
    .line 1070
    move v4, v2

    .line 1071
    move v14, v3

    .line 1072
    move-object v2, v13

    .line 1073
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 1074
    .line 1075
    invoke-interface {v2, v14, v4, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 1076
    .line 1077
    .line 1078
    move-result-object v0

    .line 1079
    return-object v0

    .line 1080
    :cond_31
    move v4, v2

    .line 1081
    move-object/from16 v16, v13

    .line 1082
    .line 1083
    move-object/from16 v2, p1

    .line 1084
    .line 1085
    add-int/lit8 v1, v1, 0x1

    .line 1086
    .line 1087
    move v2, v4

    .line 1088
    goto :goto_37

    .line 1089
    :cond_32
    invoke-static/range {v17 .. v17}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 1090
    .line 1091
    .line 1092
    move-result-object v0

    .line 1093
    throw v0

    .line 1094
    :cond_33
    move-object/from16 v2, p1

    .line 1095
    .line 1096
    move/from16 v24, v3

    .line 1097
    .line 1098
    move-object/from16 v37, v4

    .line 1099
    .line 1100
    move-object/from16 v38, v6

    .line 1101
    .line 1102
    move-object/from16 v39, v8

    .line 1103
    .line 1104
    move-wide/from16 v30, v9

    .line 1105
    .line 1106
    move-object v3, v13

    .line 1107
    move-object/from16 v13, v21

    .line 1108
    .line 1109
    const/16 v18, 0x0

    .line 1110
    .line 1111
    move-object/from16 v21, v12

    .line 1112
    .line 1113
    add-int/lit8 v0, v20, 0x1

    .line 1114
    .line 1115
    move-object v2, v13

    .line 1116
    move-object v13, v3

    .line 1117
    move/from16 v3, v24

    .line 1118
    .line 1119
    goto/16 :goto_1d

    .line 1120
    .line 1121
    :cond_34
    invoke-static/range {v17 .. v17}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v0

    .line 1125
    throw v0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/e7;->k(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/e7;->k(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 3

    .line 1
    new-instance v0, Lgv0/a;

    .line 2
    .line 3
    const/16 v1, 0x9

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v2, v1}, Lgv0/a;-><init>(BI)V

    .line 7
    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, v0}, Lh2/e7;->l(Lt3/t;Ljava/util/List;ILay0/n;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final f(Lt3/t;IIIIIIIIJF)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {p12, p7, v0}, Llp/wa;->c(FII)I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    filled-new-array {p8, p4, p5, v1}, [I

    .line 7
    .line 8
    .line 9
    move-result-object p4

    .line 10
    :goto_0
    const/4 p5, 0x4

    .line 11
    if-ge v0, p5, :cond_0

    .line 12
    .line 13
    aget p5, p4, v0

    .line 14
    .line 15
    invoke-static {p6, p5}, Ljava/lang/Math;->max(II)I

    .line 16
    .line 17
    .line 18
    move-result p6

    .line 19
    add-int/lit8 v0, v0, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Lh2/e7;->e:Lk1/z0;

    .line 23
    .line 24
    invoke-interface {p0}, Lk1/z0;->d()F

    .line 25
    .line 26
    .line 27
    move-result p4

    .line 28
    invoke-interface {p1, p4}, Lt4/c;->w0(F)F

    .line 29
    .line 30
    .line 31
    move-result p4

    .line 32
    int-to-float p5, p7

    .line 33
    const/high16 p7, 0x40000000    # 2.0f

    .line 34
    .line 35
    div-float/2addr p5, p7

    .line 36
    invoke-static {p4, p5}, Ljava/lang/Math;->max(FF)F

    .line 37
    .line 38
    .line 39
    move-result p5

    .line 40
    invoke-static {p4, p5, p12}, Llp/wa;->b(FFF)F

    .line 41
    .line 42
    .line 43
    move-result p4

    .line 44
    invoke-interface {p0}, Lk1/z0;->c()F

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    invoke-interface {p1, p0}, Lt4/c;->w0(F)F

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    int-to-float p1, p6

    .line 53
    add-float/2addr p4, p1

    .line 54
    add-float/2addr p4, p0

    .line 55
    invoke-static {p4}, Lcy0/a;->i(F)I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    invoke-static {p3, p0}, Ljava/lang/Math;->max(II)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    invoke-static {p2, p0}, Ljava/lang/Math;->max(II)I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    add-int/2addr p0, p9

    .line 68
    invoke-static {p0, p10, p11}, Lt4/b;->f(IJ)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    return p0
.end method

.method public final i(Lt3/t;IIIIIIIJF)I
    .locals 0

    .line 1
    add-int/2addr p4, p5

    .line 2
    add-int/2addr p6, p4

    .line 3
    add-int/2addr p8, p4

    .line 4
    const/4 p4, 0x0

    .line 5
    invoke-static {p11, p7, p4}, Llp/wa;->c(FII)I

    .line 6
    .line 7
    .line 8
    move-result p4

    .line 9
    invoke-static {p8, p4}, Ljava/lang/Math;->max(II)I

    .line 10
    .line 11
    .line 12
    move-result p4

    .line 13
    invoke-static {p6, p4}, Ljava/lang/Math;->max(II)I

    .line 14
    .line 15
    .line 16
    move-result p4

    .line 17
    add-int/2addr p4, p2

    .line 18
    add-int/2addr p4, p3

    .line 19
    sget-object p2, Lt4/m;->d:Lt4/m;

    .line 20
    .line 21
    iget-object p0, p0, Lh2/e7;->e:Lk1/z0;

    .line 22
    .line 23
    invoke-interface {p0, p2}, Lk1/z0;->b(Lt4/m;)F

    .line 24
    .line 25
    .line 26
    move-result p3

    .line 27
    invoke-interface {p0, p2}, Lk1/z0;->a(Lt4/m;)F

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    add-float/2addr p0, p3

    .line 32
    invoke-interface {p1, p0}, Lt4/c;->w0(F)F

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    int-to-float p1, p7

    .line 37
    add-float/2addr p1, p0

    .line 38
    mul-float/2addr p1, p11

    .line 39
    invoke-static {p1}, Lcy0/a;->i(F)I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p4, p0}, Ljava/lang/Math;->max(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    invoke-static {p0, p9, p10}, Lt4/b;->g(IJ)I

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    return p0
.end method

.method public final k(Lt3/t;Ljava/util/List;ILay0/n;)I
    .locals 20

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p0

    .line 6
    .line 7
    move-object/from16 v3, p4

    .line 8
    .line 9
    iget-object v4, v2, Lh2/e7;->d:Li2/g1;

    .line 10
    .line 11
    invoke-virtual {v4}, Li2/g1;->invoke()F

    .line 12
    .line 13
    .line 14
    move-result v12

    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Ljava/util/Collection;

    .line 17
    .line 18
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    const/4 v7, 0x0

    .line 23
    :goto_0
    if-ge v7, v5, :cond_1

    .line 24
    .line 25
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    move-object v10, v9

    .line 30
    check-cast v10, Lt3/p0;

    .line 31
    .line 32
    invoke-static {v10}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v10

    .line 36
    const-string v11, "Leading"

    .line 37
    .line 38
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v10

    .line 42
    if-eqz v10, :cond_0

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_0
    add-int/lit8 v7, v7, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    const/4 v9, 0x0

    .line 49
    :goto_1
    check-cast v9, Lt3/p0;

    .line 50
    .line 51
    const v5, 0x7fffffff

    .line 52
    .line 53
    .line 54
    if-eqz v9, :cond_2

    .line 55
    .line 56
    invoke-interface {v9, v5}, Lt3/p0;->J(I)I

    .line 57
    .line 58
    .line 59
    move-result v7

    .line 60
    invoke-static {v1, v7}, Li2/a1;->m(II)I

    .line 61
    .line 62
    .line 63
    move-result v7

    .line 64
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 65
    .line 66
    .line 67
    move-result-object v10

    .line 68
    invoke-interface {v3, v9, v10}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    check-cast v9, Ljava/lang/Number;

    .line 73
    .line 74
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v9

    .line 78
    goto :goto_2

    .line 79
    :cond_2
    move v7, v1

    .line 80
    const/4 v9, 0x0

    .line 81
    :goto_2
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 82
    .line 83
    .line 84
    move-result v10

    .line 85
    const/4 v11, 0x0

    .line 86
    :goto_3
    if-ge v11, v10, :cond_4

    .line 87
    .line 88
    invoke-interface {v0, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v13

    .line 92
    move-object v14, v13

    .line 93
    check-cast v14, Lt3/p0;

    .line 94
    .line 95
    invoke-static {v14}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v14

    .line 99
    const-string v15, "Trailing"

    .line 100
    .line 101
    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v14

    .line 105
    if-eqz v14, :cond_3

    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_3
    add-int/lit8 v11, v11, 0x1

    .line 109
    .line 110
    goto :goto_3

    .line 111
    :cond_4
    const/4 v13, 0x0

    .line 112
    :goto_4
    check-cast v13, Lt3/p0;

    .line 113
    .line 114
    if-eqz v13, :cond_5

    .line 115
    .line 116
    invoke-interface {v13, v5}, Lt3/p0;->J(I)I

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    invoke-static {v7, v10}, Li2/a1;->m(II)I

    .line 121
    .line 122
    .line 123
    move-result v7

    .line 124
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 125
    .line 126
    .line 127
    move-result-object v10

    .line 128
    invoke-interface {v3, v13, v10}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v10

    .line 132
    check-cast v10, Ljava/lang/Number;

    .line 133
    .line 134
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 135
    .line 136
    .line 137
    move-result v10

    .line 138
    goto :goto_5

    .line 139
    :cond_5
    const/4 v10, 0x0

    .line 140
    :goto_5
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 141
    .line 142
    .line 143
    move-result v11

    .line 144
    const/4 v13, 0x0

    .line 145
    :goto_6
    if-ge v13, v11, :cond_7

    .line 146
    .line 147
    invoke-interface {v0, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v14

    .line 151
    move-object v15, v14

    .line 152
    check-cast v15, Lt3/p0;

    .line 153
    .line 154
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v15

    .line 158
    const-string v8, "Label"

    .line 159
    .line 160
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v8

    .line 164
    if-eqz v8, :cond_6

    .line 165
    .line 166
    goto :goto_7

    .line 167
    :cond_6
    add-int/lit8 v13, v13, 0x1

    .line 168
    .line 169
    goto :goto_6

    .line 170
    :cond_7
    const/4 v14, 0x0

    .line 171
    :goto_7
    check-cast v14, Lt3/p0;

    .line 172
    .line 173
    if-eqz v14, :cond_8

    .line 174
    .line 175
    invoke-static {v12, v7, v1}, Llp/wa;->c(FII)I

    .line 176
    .line 177
    .line 178
    move-result v8

    .line 179
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 180
    .line 181
    .line 182
    move-result-object v8

    .line 183
    invoke-interface {v3, v14, v8}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    check-cast v8, Ljava/lang/Number;

    .line 188
    .line 189
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 190
    .line 191
    .line 192
    move-result v8

    .line 193
    goto :goto_8

    .line 194
    :cond_8
    const/4 v8, 0x0

    .line 195
    :goto_8
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 196
    .line 197
    .line 198
    move-result v11

    .line 199
    const/4 v13, 0x0

    .line 200
    :goto_9
    if-ge v13, v11, :cond_a

    .line 201
    .line 202
    invoke-interface {v0, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object v14

    .line 206
    move-object v15, v14

    .line 207
    check-cast v15, Lt3/p0;

    .line 208
    .line 209
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v15

    .line 213
    const-string v6, "Prefix"

    .line 214
    .line 215
    invoke-static {v15, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 216
    .line 217
    .line 218
    move-result v6

    .line 219
    if-eqz v6, :cond_9

    .line 220
    .line 221
    goto :goto_a

    .line 222
    :cond_9
    add-int/lit8 v13, v13, 0x1

    .line 223
    .line 224
    goto :goto_9

    .line 225
    :cond_a
    const/4 v14, 0x0

    .line 226
    :goto_a
    check-cast v14, Lt3/p0;

    .line 227
    .line 228
    if-eqz v14, :cond_b

    .line 229
    .line 230
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 231
    .line 232
    .line 233
    move-result-object v6

    .line 234
    invoke-interface {v3, v14, v6}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v6

    .line 238
    check-cast v6, Ljava/lang/Number;

    .line 239
    .line 240
    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    .line 241
    .line 242
    .line 243
    move-result v6

    .line 244
    invoke-interface {v14, v5}, Lt3/p0;->J(I)I

    .line 245
    .line 246
    .line 247
    move-result v11

    .line 248
    invoke-static {v7, v11}, Li2/a1;->m(II)I

    .line 249
    .line 250
    .line 251
    move-result v7

    .line 252
    goto :goto_b

    .line 253
    :cond_b
    const/4 v6, 0x0

    .line 254
    :goto_b
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 255
    .line 256
    .line 257
    move-result v11

    .line 258
    const/4 v13, 0x0

    .line 259
    :goto_c
    if-ge v13, v11, :cond_d

    .line 260
    .line 261
    invoke-interface {v0, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 262
    .line 263
    .line 264
    move-result-object v14

    .line 265
    move-object v15, v14

    .line 266
    check-cast v15, Lt3/p0;

    .line 267
    .line 268
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v15

    .line 272
    const-string v5, "Suffix"

    .line 273
    .line 274
    invoke-static {v15, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 275
    .line 276
    .line 277
    move-result v5

    .line 278
    if-eqz v5, :cond_c

    .line 279
    .line 280
    goto :goto_d

    .line 281
    :cond_c
    add-int/lit8 v13, v13, 0x1

    .line 282
    .line 283
    const v5, 0x7fffffff

    .line 284
    .line 285
    .line 286
    goto :goto_c

    .line 287
    :cond_d
    const/4 v14, 0x0

    .line 288
    :goto_d
    check-cast v14, Lt3/p0;

    .line 289
    .line 290
    if-eqz v14, :cond_e

    .line 291
    .line 292
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 293
    .line 294
    .line 295
    move-result-object v5

    .line 296
    invoke-interface {v3, v14, v5}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    move-result-object v5

    .line 300
    check-cast v5, Ljava/lang/Number;

    .line 301
    .line 302
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 303
    .line 304
    .line 305
    move-result v5

    .line 306
    const v11, 0x7fffffff

    .line 307
    .line 308
    .line 309
    invoke-interface {v14, v11}, Lt3/p0;->J(I)I

    .line 310
    .line 311
    .line 312
    move-result v11

    .line 313
    invoke-static {v7, v11}, Li2/a1;->m(II)I

    .line 314
    .line 315
    .line 316
    move-result v7

    .line 317
    goto :goto_e

    .line 318
    :cond_e
    const/4 v5, 0x0

    .line 319
    :goto_e
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 320
    .line 321
    .line 322
    move-result v11

    .line 323
    const/4 v13, 0x0

    .line 324
    :goto_f
    if-ge v13, v11, :cond_16

    .line 325
    .line 326
    invoke-interface {v0, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v14

    .line 330
    move-object v15, v14

    .line 331
    check-cast v15, Lt3/p0;

    .line 332
    .line 333
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 334
    .line 335
    .line 336
    move-result-object v15

    .line 337
    const-string v1, "TextField"

    .line 338
    .line 339
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    move-result v1

    .line 343
    if-eqz v1, :cond_15

    .line 344
    .line 345
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 346
    .line 347
    .line 348
    move-result-object v1

    .line 349
    invoke-interface {v3, v14, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v1

    .line 353
    check-cast v1, Ljava/lang/Number;

    .line 354
    .line 355
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 356
    .line 357
    .line 358
    move-result v1

    .line 359
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 360
    .line 361
    .line 362
    move-result v11

    .line 363
    const/4 v13, 0x0

    .line 364
    :goto_10
    if-ge v13, v11, :cond_10

    .line 365
    .line 366
    invoke-interface {v0, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v14

    .line 370
    move-object v15, v14

    .line 371
    check-cast v15, Lt3/p0;

    .line 372
    .line 373
    invoke-static {v15}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v15

    .line 377
    move/from16 v17, v1

    .line 378
    .line 379
    const-string v1, "Hint"

    .line 380
    .line 381
    invoke-static {v15, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    move-result v1

    .line 385
    if-eqz v1, :cond_f

    .line 386
    .line 387
    goto :goto_11

    .line 388
    :cond_f
    add-int/lit8 v13, v13, 0x1

    .line 389
    .line 390
    move/from16 v1, v17

    .line 391
    .line 392
    goto :goto_10

    .line 393
    :cond_10
    move/from16 v17, v1

    .line 394
    .line 395
    const/4 v14, 0x0

    .line 396
    :goto_11
    check-cast v14, Lt3/p0;

    .line 397
    .line 398
    if-eqz v14, :cond_11

    .line 399
    .line 400
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 401
    .line 402
    .line 403
    move-result-object v1

    .line 404
    invoke-interface {v3, v14, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    check-cast v1, Ljava/lang/Number;

    .line 409
    .line 410
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 411
    .line 412
    .line 413
    move-result v1

    .line 414
    goto :goto_12

    .line 415
    :cond_11
    const/4 v1, 0x0

    .line 416
    :goto_12
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 417
    .line 418
    .line 419
    move-result v4

    .line 420
    const/4 v7, 0x0

    .line 421
    :goto_13
    if-ge v7, v4, :cond_13

    .line 422
    .line 423
    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 424
    .line 425
    .line 426
    move-result-object v11

    .line 427
    move-object v13, v11

    .line 428
    check-cast v13, Lt3/p0;

    .line 429
    .line 430
    invoke-static {v13}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v13

    .line 434
    const-string v14, "Supporting"

    .line 435
    .line 436
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 437
    .line 438
    .line 439
    move-result v13

    .line 440
    if-eqz v13, :cond_12

    .line 441
    .line 442
    goto :goto_14

    .line 443
    :cond_12
    add-int/lit8 v7, v7, 0x1

    .line 444
    .line 445
    goto :goto_13

    .line 446
    :cond_13
    const/4 v11, 0x0

    .line 447
    :goto_14
    check-cast v11, Lt3/p0;

    .line 448
    .line 449
    if-eqz v11, :cond_14

    .line 450
    .line 451
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 452
    .line 453
    .line 454
    move-result-object v0

    .line 455
    invoke-interface {v3, v11, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v0

    .line 459
    check-cast v0, Ljava/lang/Number;

    .line 460
    .line 461
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 462
    .line 463
    .line 464
    move-result v0

    .line 465
    goto :goto_15

    .line 466
    :cond_14
    const/4 v0, 0x0

    .line 467
    :goto_15
    const/16 v3, 0xf

    .line 468
    .line 469
    const/4 v14, 0x0

    .line 470
    invoke-static {v14, v14, v3}, Lt4/b;->b(III)J

    .line 471
    .line 472
    .line 473
    move-result-wide v3

    .line 474
    move v7, v9

    .line 475
    move v9, v0

    .line 476
    move-object v0, v2

    .line 477
    move v2, v7

    .line 478
    move-wide/from16 v18, v3

    .line 479
    .line 480
    move v3, v10

    .line 481
    move-wide/from16 v10, v18

    .line 482
    .line 483
    move v4, v6

    .line 484
    move v7, v8

    .line 485
    move/from16 v6, v17

    .line 486
    .line 487
    move v8, v1

    .line 488
    move-object/from16 v1, p1

    .line 489
    .line 490
    invoke-virtual/range {v0 .. v12}, Lh2/e7;->f(Lt3/t;IIIIIIIIJF)I

    .line 491
    .line 492
    .line 493
    move-result v0

    .line 494
    return v0

    .line 495
    :cond_15
    move/from16 v16, v6

    .line 496
    .line 497
    move v2, v9

    .line 498
    move v6, v10

    .line 499
    const/4 v14, 0x0

    .line 500
    add-int/lit8 v13, v13, 0x1

    .line 501
    .line 502
    move/from16 v1, p3

    .line 503
    .line 504
    move/from16 v6, v16

    .line 505
    .line 506
    move-object/from16 v2, p0

    .line 507
    .line 508
    goto/16 :goto_f

    .line 509
    .line 510
    :cond_16
    const-string v0, "Collection contains no element matching the predicate."

    .line 511
    .line 512
    invoke-static {v0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    throw v0
.end method

.method public final l(Lt3/t;Ljava/util/List;ILay0/n;)I
    .locals 17

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p4

    .line 4
    .line 5
    move-object v2, v0

    .line 6
    check-cast v2, Ljava/util/Collection;

    .line 7
    .line 8
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const/4 v4, 0x0

    .line 13
    move v5, v4

    .line 14
    :goto_0
    if-ge v5, v3, :cond_13

    .line 15
    .line 16
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v6

    .line 20
    move-object v7, v6

    .line 21
    check-cast v7, Lt3/p0;

    .line 22
    .line 23
    invoke-static {v7}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v7

    .line 27
    const-string v8, "TextField"

    .line 28
    .line 29
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v7

    .line 33
    if-eqz v7, :cond_12

    .line 34
    .line 35
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-interface {v1, v6, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    check-cast v3, Ljava/lang/Number;

    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 46
    .line 47
    .line 48
    move-result v11

    .line 49
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    move v5, v4

    .line 54
    :goto_1
    const/4 v6, 0x0

    .line 55
    if-ge v5, v3, :cond_1

    .line 56
    .line 57
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    move-object v8, v7

    .line 62
    check-cast v8, Lt3/p0;

    .line 63
    .line 64
    invoke-static {v8}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v8

    .line 68
    const-string v9, "Label"

    .line 69
    .line 70
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    if-eqz v8, :cond_0

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_0
    add-int/lit8 v5, v5, 0x1

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_1
    move-object v7, v6

    .line 81
    :goto_2
    check-cast v7, Lt3/p0;

    .line 82
    .line 83
    if-eqz v7, :cond_2

    .line 84
    .line 85
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 86
    .line 87
    .line 88
    move-result-object v3

    .line 89
    invoke-interface {v1, v7, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v3

    .line 93
    check-cast v3, Ljava/lang/Number;

    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    move v12, v3

    .line 100
    goto :goto_3

    .line 101
    :cond_2
    move v12, v4

    .line 102
    :goto_3
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    move v5, v4

    .line 107
    :goto_4
    if-ge v5, v3, :cond_4

    .line 108
    .line 109
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v7

    .line 113
    move-object v8, v7

    .line 114
    check-cast v8, Lt3/p0;

    .line 115
    .line 116
    invoke-static {v8}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    const-string v9, "Trailing"

    .line 121
    .line 122
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 123
    .line 124
    .line 125
    move-result v8

    .line 126
    if-eqz v8, :cond_3

    .line 127
    .line 128
    goto :goto_5

    .line 129
    :cond_3
    add-int/lit8 v5, v5, 0x1

    .line 130
    .line 131
    goto :goto_4

    .line 132
    :cond_4
    move-object v7, v6

    .line 133
    :goto_5
    check-cast v7, Lt3/p0;

    .line 134
    .line 135
    if-eqz v7, :cond_5

    .line 136
    .line 137
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    invoke-interface {v1, v7, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    check-cast v3, Ljava/lang/Number;

    .line 146
    .line 147
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    move v8, v3

    .line 152
    goto :goto_6

    .line 153
    :cond_5
    move v8, v4

    .line 154
    :goto_6
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 155
    .line 156
    .line 157
    move-result v3

    .line 158
    move v5, v4

    .line 159
    :goto_7
    if-ge v5, v3, :cond_7

    .line 160
    .line 161
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    move-object v9, v7

    .line 166
    check-cast v9, Lt3/p0;

    .line 167
    .line 168
    invoke-static {v9}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object v9

    .line 172
    const-string v10, "Leading"

    .line 173
    .line 174
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v9

    .line 178
    if-eqz v9, :cond_6

    .line 179
    .line 180
    goto :goto_8

    .line 181
    :cond_6
    add-int/lit8 v5, v5, 0x1

    .line 182
    .line 183
    goto :goto_7

    .line 184
    :cond_7
    move-object v7, v6

    .line 185
    :goto_8
    check-cast v7, Lt3/p0;

    .line 186
    .line 187
    if-eqz v7, :cond_8

    .line 188
    .line 189
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v3

    .line 193
    invoke-interface {v1, v7, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v3

    .line 197
    check-cast v3, Ljava/lang/Number;

    .line 198
    .line 199
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    move v7, v3

    .line 204
    goto :goto_9

    .line 205
    :cond_8
    move v7, v4

    .line 206
    :goto_9
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    move v5, v4

    .line 211
    :goto_a
    if-ge v5, v3, :cond_a

    .line 212
    .line 213
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v9

    .line 217
    move-object v10, v9

    .line 218
    check-cast v10, Lt3/p0;

    .line 219
    .line 220
    invoke-static {v10}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    move-result-object v10

    .line 224
    const-string v13, "Prefix"

    .line 225
    .line 226
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result v10

    .line 230
    if-eqz v10, :cond_9

    .line 231
    .line 232
    goto :goto_b

    .line 233
    :cond_9
    add-int/lit8 v5, v5, 0x1

    .line 234
    .line 235
    goto :goto_a

    .line 236
    :cond_a
    move-object v9, v6

    .line 237
    :goto_b
    check-cast v9, Lt3/p0;

    .line 238
    .line 239
    if-eqz v9, :cond_b

    .line 240
    .line 241
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    invoke-interface {v1, v9, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v3

    .line 249
    check-cast v3, Ljava/lang/Number;

    .line 250
    .line 251
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 252
    .line 253
    .line 254
    move-result v3

    .line 255
    move v9, v3

    .line 256
    goto :goto_c

    .line 257
    :cond_b
    move v9, v4

    .line 258
    :goto_c
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 259
    .line 260
    .line 261
    move-result v3

    .line 262
    move v5, v4

    .line 263
    :goto_d
    if-ge v5, v3, :cond_d

    .line 264
    .line 265
    invoke-interface {v0, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v10

    .line 269
    move-object v13, v10

    .line 270
    check-cast v13, Lt3/p0;

    .line 271
    .line 272
    invoke-static {v13}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v13

    .line 276
    const-string v14, "Suffix"

    .line 277
    .line 278
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    move-result v13

    .line 282
    if-eqz v13, :cond_c

    .line 283
    .line 284
    goto :goto_e

    .line 285
    :cond_c
    add-int/lit8 v5, v5, 0x1

    .line 286
    .line 287
    goto :goto_d

    .line 288
    :cond_d
    move-object v10, v6

    .line 289
    :goto_e
    check-cast v10, Lt3/p0;

    .line 290
    .line 291
    if-eqz v10, :cond_e

    .line 292
    .line 293
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 294
    .line 295
    .line 296
    move-result-object v3

    .line 297
    invoke-interface {v1, v10, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 298
    .line 299
    .line 300
    move-result-object v3

    .line 301
    check-cast v3, Ljava/lang/Number;

    .line 302
    .line 303
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 304
    .line 305
    .line 306
    move-result v3

    .line 307
    move v10, v3

    .line 308
    goto :goto_f

    .line 309
    :cond_e
    move v10, v4

    .line 310
    :goto_f
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 311
    .line 312
    .line 313
    move-result v2

    .line 314
    move v3, v4

    .line 315
    :goto_10
    if-ge v3, v2, :cond_10

    .line 316
    .line 317
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v5

    .line 321
    move-object v13, v5

    .line 322
    check-cast v13, Lt3/p0;

    .line 323
    .line 324
    invoke-static {v13}, Li2/a1;->j(Lt3/p0;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v13

    .line 328
    const-string v14, "Hint"

    .line 329
    .line 330
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 331
    .line 332
    .line 333
    move-result v13

    .line 334
    if-eqz v13, :cond_f

    .line 335
    .line 336
    move-object v6, v5

    .line 337
    goto :goto_11

    .line 338
    :cond_f
    add-int/lit8 v3, v3, 0x1

    .line 339
    .line 340
    goto :goto_10

    .line 341
    :cond_10
    :goto_11
    check-cast v6, Lt3/p0;

    .line 342
    .line 343
    if-eqz v6, :cond_11

    .line 344
    .line 345
    invoke-static/range {p3 .. p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    invoke-interface {v1, v6, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    check-cast v0, Ljava/lang/Number;

    .line 354
    .line 355
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 356
    .line 357
    .line 358
    move-result v0

    .line 359
    move v13, v0

    .line 360
    goto :goto_12

    .line 361
    :cond_11
    move v13, v4

    .line 362
    :goto_12
    const/16 v0, 0xf

    .line 363
    .line 364
    invoke-static {v4, v4, v0}, Lt4/b;->b(III)J

    .line 365
    .line 366
    .line 367
    move-result-wide v14

    .line 368
    move-object/from16 v5, p0

    .line 369
    .line 370
    iget-object v0, v5, Lh2/e7;->d:Li2/g1;

    .line 371
    .line 372
    invoke-virtual {v0}, Li2/g1;->invoke()F

    .line 373
    .line 374
    .line 375
    move-result v16

    .line 376
    move-object/from16 v6, p1

    .line 377
    .line 378
    invoke-virtual/range {v5 .. v16}, Lh2/e7;->i(Lt3/t;IIIIIIIJF)I

    .line 379
    .line 380
    .line 381
    move-result v0

    .line 382
    return v0

    .line 383
    :cond_12
    add-int/lit8 v5, v5, 0x1

    .line 384
    .line 385
    goto/16 :goto_0

    .line 386
    .line 387
    :cond_13
    const-string v0, "Collection contains no element matching the predicate."

    .line 388
    .line 389
    invoke-static {v0}, Lf2/m0;->c(Ljava/lang/String;)La8/r0;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    throw v0
.end method
