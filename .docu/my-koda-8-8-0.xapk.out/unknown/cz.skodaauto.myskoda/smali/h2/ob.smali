.class public final synthetic Lh2/ob;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lkotlin/jvm/internal/f0;

.field public final synthetic e:Lh2/pb;

.field public final synthetic f:I

.field public final synthetic g:I

.field public final synthetic h:Lt3/s0;

.field public final synthetic i:I

.field public final synthetic j:I

.field public final synthetic k:Lt3/e1;

.field public final synthetic l:Lt3/e1;

.field public final synthetic m:Lt3/e1;

.field public final synthetic n:Lt3/e1;

.field public final synthetic o:Lt3/e1;

.field public final synthetic p:Lt3/e1;

.field public final synthetic q:Lt3/e1;

.field public final synthetic r:Lt3/e1;

.field public final synthetic s:F


# direct methods
.method public synthetic constructor <init>(Lkotlin/jvm/internal/f0;Lh2/pb;IILt3/s0;IILt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;Lt3/e1;F)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/ob;->d:Lkotlin/jvm/internal/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lh2/ob;->e:Lh2/pb;

    .line 7
    .line 8
    iput p3, p0, Lh2/ob;->f:I

    .line 9
    .line 10
    iput p4, p0, Lh2/ob;->g:I

    .line 11
    .line 12
    iput-object p5, p0, Lh2/ob;->h:Lt3/s0;

    .line 13
    .line 14
    iput p6, p0, Lh2/ob;->i:I

    .line 15
    .line 16
    iput p7, p0, Lh2/ob;->j:I

    .line 17
    .line 18
    iput-object p8, p0, Lh2/ob;->k:Lt3/e1;

    .line 19
    .line 20
    iput-object p9, p0, Lh2/ob;->l:Lt3/e1;

    .line 21
    .line 22
    iput-object p10, p0, Lh2/ob;->m:Lt3/e1;

    .line 23
    .line 24
    iput-object p11, p0, Lh2/ob;->n:Lt3/e1;

    .line 25
    .line 26
    iput-object p12, p0, Lh2/ob;->o:Lt3/e1;

    .line 27
    .line 28
    iput-object p13, p0, Lh2/ob;->p:Lt3/e1;

    .line 29
    .line 30
    iput-object p14, p0, Lh2/ob;->q:Lt3/e1;

    .line 31
    .line 32
    iput-object p15, p0, Lh2/ob;->r:Lt3/e1;

    .line 33
    .line 34
    move/from16 p1, p16

    .line 35
    .line 36
    iput p1, p0, Lh2/ob;->s:F

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lt3/d1;

    .line 6
    .line 7
    iget-object v2, v0, Lh2/ob;->d:Lkotlin/jvm/internal/f0;

    .line 8
    .line 9
    iget-object v3, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v4, v0, Lh2/ob;->e:Lh2/pb;

    .line 12
    .line 13
    iget-object v5, v0, Lh2/ob;->h:Lt3/s0;

    .line 14
    .line 15
    iget v6, v0, Lh2/ob;->i:I

    .line 16
    .line 17
    iget v7, v0, Lh2/ob;->j:I

    .line 18
    .line 19
    iget-object v8, v0, Lh2/ob;->k:Lt3/e1;

    .line 20
    .line 21
    iget-object v9, v0, Lh2/ob;->l:Lt3/e1;

    .line 22
    .line 23
    iget-object v10, v0, Lh2/ob;->m:Lt3/e1;

    .line 24
    .line 25
    iget-object v11, v0, Lh2/ob;->n:Lt3/e1;

    .line 26
    .line 27
    iget-object v12, v0, Lh2/ob;->o:Lt3/e1;

    .line 28
    .line 29
    iget-object v13, v0, Lh2/ob;->p:Lt3/e1;

    .line 30
    .line 31
    iget-object v14, v0, Lh2/ob;->q:Lt3/e1;

    .line 32
    .line 33
    iget-object v15, v0, Lh2/ob;->r:Lt3/e1;

    .line 34
    .line 35
    move-object/from16 p1, v3

    .line 36
    .line 37
    const/16 v16, 0x0

    .line 38
    .line 39
    const/high16 v17, 0x40000000    # 2.0f

    .line 40
    .line 41
    if-eqz p1, :cond_11

    .line 42
    .line 43
    iget-boolean v3, v4, Lh2/pb;->a:Z

    .line 44
    .line 45
    move/from16 v18, v3

    .line 46
    .line 47
    iget v3, v0, Lh2/ob;->g:I

    .line 48
    .line 49
    if-eqz v18, :cond_0

    .line 50
    .line 51
    move/from16 v18, v6

    .line 52
    .line 53
    move-object/from16 v6, p1

    .line 54
    .line 55
    check-cast v6, Lt3/e1;

    .line 56
    .line 57
    iget v6, v6, Lt3/e1;->e:I

    .line 58
    .line 59
    move/from16 p1, v6

    .line 60
    .line 61
    iget v6, v0, Lh2/ob;->f:I

    .line 62
    .line 63
    sub-int v6, v6, p1

    .line 64
    .line 65
    int-to-float v6, v6

    .line 66
    div-float v6, v6, v17

    .line 67
    .line 68
    move/from16 p1, v6

    .line 69
    .line 70
    move/from16 v19, v7

    .line 71
    .line 72
    const/4 v6, 0x1

    .line 73
    int-to-float v7, v6

    .line 74
    add-float v7, v7, v16

    .line 75
    .line 76
    mul-float v7, v7, p1

    .line 77
    .line 78
    invoke-static {v7}, Ljava/lang/Math;->round(F)I

    .line 79
    .line 80
    .line 81
    move-result v6

    .line 82
    goto :goto_0

    .line 83
    :cond_0
    move/from16 v18, v6

    .line 84
    .line 85
    move/from16 v19, v7

    .line 86
    .line 87
    iget v6, v4, Lh2/pb;->e:F

    .line 88
    .line 89
    invoke-interface {v5, v6}, Lt4/c;->Q(F)I

    .line 90
    .line 91
    .line 92
    move-result v6

    .line 93
    add-int/2addr v6, v3

    .line 94
    :goto_0
    iget-object v2, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v2, Lt3/e1;

    .line 97
    .line 98
    iget v7, v2, Lt3/e1;->e:I

    .line 99
    .line 100
    add-int/2addr v7, v3

    .line 101
    invoke-interface {v5}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 102
    .line 103
    .line 104
    move-result-object v5

    .line 105
    iget-object v4, v4, Lh2/pb;->b:Lh2/nb;

    .line 106
    .line 107
    move-object/from16 p1, v13

    .line 108
    .line 109
    const/4 v13, 0x0

    .line 110
    invoke-static {v1, v14, v13, v13}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 111
    .line 112
    .line 113
    if-eqz v15, :cond_1

    .line 114
    .line 115
    iget v13, v15, Lt3/e1;->e:I

    .line 116
    .line 117
    goto :goto_1

    .line 118
    :cond_1
    const/4 v13, 0x0

    .line 119
    :goto_1
    sub-int v13, v19, v13

    .line 120
    .line 121
    if-eqz v10, :cond_2

    .line 122
    .line 123
    iget v14, v10, Lt3/e1;->e:I

    .line 124
    .line 125
    sub-int v14, v13, v14

    .line 126
    .line 127
    int-to-float v14, v14

    .line 128
    div-float v14, v14, v17

    .line 129
    .line 130
    move/from16 v20, v13

    .line 131
    .line 132
    move/from16 v19, v14

    .line 133
    .line 134
    const/4 v14, 0x1

    .line 135
    int-to-float v13, v14

    .line 136
    add-float v13, v13, v16

    .line 137
    .line 138
    mul-float v13, v13, v19

    .line 139
    .line 140
    invoke-static {v13}, Ljava/lang/Math;->round(F)I

    .line 141
    .line 142
    .line 143
    move-result v13

    .line 144
    const/4 v14, 0x0

    .line 145
    invoke-static {v1, v10, v14, v13}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 146
    .line 147
    .line 148
    goto :goto_2

    .line 149
    :cond_2
    move/from16 v20, v13

    .line 150
    .line 151
    :goto_2
    iget v0, v0, Lh2/ob;->s:F

    .line 152
    .line 153
    invoke-static {v0, v6, v3}, Llp/wa;->c(FII)I

    .line 154
    .line 155
    .line 156
    move-result v3

    .line 157
    sget-object v6, Lt4/m;->d:Lt4/m;

    .line 158
    .line 159
    if-ne v5, v6, :cond_4

    .line 160
    .line 161
    if-eqz v10, :cond_3

    .line 162
    .line 163
    iget v6, v10, Lt3/e1;->d:I

    .line 164
    .line 165
    goto :goto_3

    .line 166
    :cond_3
    const/4 v6, 0x0

    .line 167
    goto :goto_3

    .line 168
    :cond_4
    if-eqz v11, :cond_3

    .line 169
    .line 170
    iget v6, v11, Lt3/e1;->d:I

    .line 171
    .line 172
    :goto_3
    sget v13, Li2/h1;->a:F

    .line 173
    .line 174
    iget-object v13, v4, Lh2/nb;->b:Lx2/h;

    .line 175
    .line 176
    iget v14, v2, Lt3/e1;->d:I

    .line 177
    .line 178
    move-object/from16 v21, v4

    .line 179
    .line 180
    if-eqz v10, :cond_5

    .line 181
    .line 182
    iget v4, v10, Lt3/e1;->d:I

    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_5
    const/4 v4, 0x0

    .line 186
    :goto_4
    sub-int v4, v18, v4

    .line 187
    .line 188
    move/from16 p0, v4

    .line 189
    .line 190
    if-eqz v11, :cond_6

    .line 191
    .line 192
    iget v4, v11, Lt3/e1;->d:I

    .line 193
    .line 194
    goto :goto_5

    .line 195
    :cond_6
    const/4 v4, 0x0

    .line 196
    :goto_5
    sub-int v4, p0, v4

    .line 197
    .line 198
    invoke-virtual {v13, v14, v4, v5}, Lx2/h;->a(IILt4/m;)I

    .line 199
    .line 200
    .line 201
    move-result v4

    .line 202
    add-int/2addr v4, v6

    .line 203
    invoke-static/range {v21 .. v21}, Li2/h1;->c(Lh2/nb;)Lx2/d;

    .line 204
    .line 205
    .line 206
    move-result-object v13

    .line 207
    iget v14, v2, Lt3/e1;->d:I

    .line 208
    .line 209
    move/from16 p0, v6

    .line 210
    .line 211
    if-eqz v10, :cond_7

    .line 212
    .line 213
    iget v6, v10, Lt3/e1;->d:I

    .line 214
    .line 215
    goto :goto_6

    .line 216
    :cond_7
    const/4 v6, 0x0

    .line 217
    :goto_6
    sub-int v6, v18, v6

    .line 218
    .line 219
    move/from16 v19, v6

    .line 220
    .line 221
    if-eqz v11, :cond_8

    .line 222
    .line 223
    iget v6, v11, Lt3/e1;->d:I

    .line 224
    .line 225
    goto :goto_7

    .line 226
    :cond_8
    const/4 v6, 0x0

    .line 227
    :goto_7
    sub-int v6, v19, v6

    .line 228
    .line 229
    check-cast v13, Lx2/h;

    .line 230
    .line 231
    invoke-virtual {v13, v14, v6, v5}, Lx2/h;->a(IILt4/m;)I

    .line 232
    .line 233
    .line 234
    move-result v5

    .line 235
    add-int v5, v5, p0

    .line 236
    .line 237
    invoke-static {v0, v4, v5}, Llp/wa;->c(FII)I

    .line 238
    .line 239
    .line 240
    move-result v0

    .line 241
    move/from16 v4, v16

    .line 242
    .line 243
    invoke-virtual {v1, v2, v0, v3, v4}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 244
    .line 245
    .line 246
    if-eqz v12, :cond_a

    .line 247
    .line 248
    if-eqz v10, :cond_9

    .line 249
    .line 250
    iget v0, v10, Lt3/e1;->d:I

    .line 251
    .line 252
    goto :goto_8

    .line 253
    :cond_9
    const/4 v0, 0x0

    .line 254
    :goto_8
    invoke-static {v1, v12, v0, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 255
    .line 256
    .line 257
    :cond_a
    if-eqz v10, :cond_b

    .line 258
    .line 259
    iget v0, v10, Lt3/e1;->d:I

    .line 260
    .line 261
    goto :goto_9

    .line 262
    :cond_b
    const/4 v0, 0x0

    .line 263
    :goto_9
    if-eqz v12, :cond_c

    .line 264
    .line 265
    iget v2, v12, Lt3/e1;->d:I

    .line 266
    .line 267
    goto :goto_a

    .line 268
    :cond_c
    const/4 v2, 0x0

    .line 269
    :goto_a
    add-int/2addr v0, v2

    .line 270
    invoke-static {v1, v8, v0, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 271
    .line 272
    .line 273
    if-eqz v9, :cond_d

    .line 274
    .line 275
    invoke-static {v1, v9, v0, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 276
    .line 277
    .line 278
    :cond_d
    if-eqz p1, :cond_f

    .line 279
    .line 280
    if-eqz v11, :cond_e

    .line 281
    .line 282
    iget v0, v11, Lt3/e1;->d:I

    .line 283
    .line 284
    goto :goto_b

    .line 285
    :cond_e
    const/4 v0, 0x0

    .line 286
    :goto_b
    sub-int v6, v18, v0

    .line 287
    .line 288
    move-object/from16 v0, p1

    .line 289
    .line 290
    iget v2, v0, Lt3/e1;->d:I

    .line 291
    .line 292
    sub-int/2addr v6, v2

    .line 293
    invoke-static {v1, v0, v6, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 294
    .line 295
    .line 296
    :cond_f
    if-eqz v11, :cond_10

    .line 297
    .line 298
    iget v0, v11, Lt3/e1;->d:I

    .line 299
    .line 300
    sub-int v6, v18, v0

    .line 301
    .line 302
    iget v0, v11, Lt3/e1;->e:I

    .line 303
    .line 304
    sub-int v13, v20, v0

    .line 305
    .line 306
    int-to-float v0, v13

    .line 307
    div-float v0, v0, v17

    .line 308
    .line 309
    const/4 v14, 0x1

    .line 310
    int-to-float v2, v14

    .line 311
    const/16 v16, 0x0

    .line 312
    .line 313
    add-float v2, v2, v16

    .line 314
    .line 315
    mul-float/2addr v2, v0

    .line 316
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 317
    .line 318
    .line 319
    move-result v0

    .line 320
    invoke-static {v1, v11, v6, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 321
    .line 322
    .line 323
    :cond_10
    if-eqz v15, :cond_1c

    .line 324
    .line 325
    move/from16 v7, v20

    .line 326
    .line 327
    const/4 v14, 0x0

    .line 328
    invoke-static {v1, v15, v14, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 329
    .line 330
    .line 331
    goto/16 :goto_11

    .line 332
    .line 333
    :cond_11
    move/from16 v18, v6

    .line 334
    .line 335
    move/from16 v19, v7

    .line 336
    .line 337
    move-object v0, v13

    .line 338
    invoke-interface {v5}, Lt4/c;->a()F

    .line 339
    .line 340
    .line 341
    move-result v2

    .line 342
    const-wide/16 v5, 0x0

    .line 343
    .line 344
    invoke-static {v1, v14, v5, v6}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 345
    .line 346
    .line 347
    if-eqz v15, :cond_12

    .line 348
    .line 349
    iget v3, v15, Lt3/e1;->e:I

    .line 350
    .line 351
    goto :goto_c

    .line 352
    :cond_12
    const/4 v3, 0x0

    .line 353
    :goto_c
    sub-int v7, v19, v3

    .line 354
    .line 355
    iget-object v3, v4, Lh2/pb;->d:Lk1/z0;

    .line 356
    .line 357
    invoke-interface {v3}, Lk1/z0;->d()F

    .line 358
    .line 359
    .line 360
    move-result v3

    .line 361
    mul-float/2addr v3, v2

    .line 362
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 363
    .line 364
    .line 365
    move-result v2

    .line 366
    if-eqz v10, :cond_13

    .line 367
    .line 368
    iget v3, v10, Lt3/e1;->e:I

    .line 369
    .line 370
    sub-int v3, v7, v3

    .line 371
    .line 372
    int-to-float v3, v3

    .line 373
    div-float v3, v3, v17

    .line 374
    .line 375
    const/4 v14, 0x1

    .line 376
    int-to-float v5, v14

    .line 377
    const/16 v16, 0x0

    .line 378
    .line 379
    add-float v5, v5, v16

    .line 380
    .line 381
    mul-float/2addr v5, v3

    .line 382
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 383
    .line 384
    .line 385
    move-result v3

    .line 386
    const/4 v14, 0x0

    .line 387
    invoke-static {v1, v10, v14, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 388
    .line 389
    .line 390
    :cond_13
    if-eqz v12, :cond_15

    .line 391
    .line 392
    if-eqz v10, :cond_14

    .line 393
    .line 394
    iget v13, v10, Lt3/e1;->d:I

    .line 395
    .line 396
    goto :goto_d

    .line 397
    :cond_14
    const/4 v13, 0x0

    .line 398
    :goto_d
    invoke-static {v4, v7, v2, v12}, Lh2/pb;->l(Lh2/pb;IILt3/e1;)I

    .line 399
    .line 400
    .line 401
    move-result v3

    .line 402
    invoke-static {v1, v12, v13, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 403
    .line 404
    .line 405
    :cond_15
    if-eqz v10, :cond_16

    .line 406
    .line 407
    iget v13, v10, Lt3/e1;->d:I

    .line 408
    .line 409
    goto :goto_e

    .line 410
    :cond_16
    const/4 v13, 0x0

    .line 411
    :goto_e
    if-eqz v12, :cond_17

    .line 412
    .line 413
    iget v3, v12, Lt3/e1;->d:I

    .line 414
    .line 415
    goto :goto_f

    .line 416
    :cond_17
    const/4 v3, 0x0

    .line 417
    :goto_f
    add-int/2addr v13, v3

    .line 418
    invoke-static {v4, v7, v2, v8}, Lh2/pb;->l(Lh2/pb;IILt3/e1;)I

    .line 419
    .line 420
    .line 421
    move-result v3

    .line 422
    invoke-static {v1, v8, v13, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 423
    .line 424
    .line 425
    if-eqz v9, :cond_18

    .line 426
    .line 427
    invoke-static {v4, v7, v2, v9}, Lh2/pb;->l(Lh2/pb;IILt3/e1;)I

    .line 428
    .line 429
    .line 430
    move-result v3

    .line 431
    invoke-static {v1, v9, v13, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 432
    .line 433
    .line 434
    :cond_18
    if-eqz v0, :cond_1a

    .line 435
    .line 436
    if-eqz v11, :cond_19

    .line 437
    .line 438
    iget v13, v11, Lt3/e1;->d:I

    .line 439
    .line 440
    goto :goto_10

    .line 441
    :cond_19
    const/4 v13, 0x0

    .line 442
    :goto_10
    sub-int v6, v18, v13

    .line 443
    .line 444
    iget v3, v0, Lt3/e1;->d:I

    .line 445
    .line 446
    sub-int/2addr v6, v3

    .line 447
    invoke-static {v4, v7, v2, v0}, Lh2/pb;->l(Lh2/pb;IILt3/e1;)I

    .line 448
    .line 449
    .line 450
    move-result v2

    .line 451
    invoke-static {v1, v0, v6, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 452
    .line 453
    .line 454
    :cond_1a
    if-eqz v11, :cond_1b

    .line 455
    .line 456
    iget v0, v11, Lt3/e1;->d:I

    .line 457
    .line 458
    sub-int v6, v18, v0

    .line 459
    .line 460
    iget v0, v11, Lt3/e1;->e:I

    .line 461
    .line 462
    sub-int v0, v7, v0

    .line 463
    .line 464
    int-to-float v0, v0

    .line 465
    div-float v0, v0, v17

    .line 466
    .line 467
    const/4 v14, 0x1

    .line 468
    int-to-float v2, v14

    .line 469
    const/16 v16, 0x0

    .line 470
    .line 471
    add-float v2, v2, v16

    .line 472
    .line 473
    mul-float/2addr v2, v0

    .line 474
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 475
    .line 476
    .line 477
    move-result v0

    .line 478
    invoke-static {v1, v11, v6, v0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 479
    .line 480
    .line 481
    :cond_1b
    if-eqz v15, :cond_1c

    .line 482
    .line 483
    const/4 v14, 0x0

    .line 484
    invoke-static {v1, v15, v14, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 485
    .line 486
    .line 487
    :cond_1c
    :goto_11
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 488
    .line 489
    return-object v0
.end method
