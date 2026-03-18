.class public final Lm8/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lm8/l;

.field public final b:Lm8/c0;

.field public final c:J

.field public d:Z

.field public e:I

.field public f:J

.field public g:J

.field public h:J

.field public i:J

.field public j:Z

.field public k:F

.field public l:Lw7/r;

.field public m:Z

.field public n:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Lm8/l;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lm8/y;->a:Lm8/l;

    .line 5
    .line 6
    iput-wide p3, p0, Lm8/y;->c:J

    .line 7
    .line 8
    new-instance p2, Lm8/c0;

    .line 9
    .line 10
    invoke-direct {p2, p1}, Lm8/c0;-><init>(Landroid/content/Context;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lm8/y;->b:Lm8/c0;

    .line 14
    .line 15
    const/4 p1, 0x0

    .line 16
    iput p1, p0, Lm8/y;->e:I

    .line 17
    .line 18
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    iput-wide p1, p0, Lm8/y;->f:J

    .line 24
    .line 25
    iput-wide p1, p0, Lm8/y;->h:J

    .line 26
    .line 27
    iput-wide p1, p0, Lm8/y;->i:J

    .line 28
    .line 29
    const/high16 p1, 0x3f800000    # 1.0f

    .line 30
    .line 31
    iput p1, p0, Lm8/y;->k:F

    .line 32
    .line 33
    sget-object p1, Lw7/r;->a:Lw7/r;

    .line 34
    .line 35
    iput-object p1, p0, Lm8/y;->l:Lw7/r;

    .line 36
    .line 37
    return-void
.end method


# virtual methods
.method public final a(JJJJZZLi9/a;)I
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v8, p11

    .line 8
    .line 9
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    iput-wide v6, v8, Li9/a;->a:J

    .line 15
    .line 16
    iput-wide v6, v8, Li9/a;->b:J

    .line 17
    .line 18
    iget-boolean v3, v0, Lm8/y;->d:Z

    .line 19
    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iget-wide v9, v0, Lm8/y;->f:J

    .line 23
    .line 24
    cmp-long v3, v9, v6

    .line 25
    .line 26
    if-nez v3, :cond_0

    .line 27
    .line 28
    iput-wide v4, v0, Lm8/y;->f:J

    .line 29
    .line 30
    :cond_0
    iget-wide v9, v0, Lm8/y;->h:J

    .line 31
    .line 32
    cmp-long v3, v9, v1

    .line 33
    .line 34
    const-wide/16 v11, -0x1

    .line 35
    .line 36
    const/4 v15, 0x0

    .line 37
    move-wide/from16 v16, v6

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    if-eqz v3, :cond_9

    .line 41
    .line 42
    iget-object v3, v0, Lm8/y;->b:Lm8/c0;

    .line 43
    .line 44
    const-wide/16 v18, 0x3e8

    .line 45
    .line 46
    iget-wide v13, v3, Lm8/c0;->n:J

    .line 47
    .line 48
    cmp-long v6, v13, v11

    .line 49
    .line 50
    if-eqz v6, :cond_1

    .line 51
    .line 52
    iput-wide v13, v3, Lm8/c0;->p:J

    .line 53
    .line 54
    iget-wide v13, v3, Lm8/c0;->o:J

    .line 55
    .line 56
    iput-wide v13, v3, Lm8/c0;->q:J

    .line 57
    .line 58
    :cond_1
    iget-wide v13, v3, Lm8/c0;->m:J

    .line 59
    .line 60
    const-wide/16 v20, 0x1

    .line 61
    .line 62
    add-long v13, v13, v20

    .line 63
    .line 64
    iput-wide v13, v3, Lm8/c0;->m:J

    .line 65
    .line 66
    iget-object v6, v3, Lm8/c0;->a:Lm8/e;

    .line 67
    .line 68
    mul-long v13, v1, v18

    .line 69
    .line 70
    move-wide/from16 v22, v11

    .line 71
    .line 72
    iget-object v11, v6, Lm8/e;->a:Lm8/d;

    .line 73
    .line 74
    invoke-virtual {v11, v13, v14}, Lm8/d;->b(J)V

    .line 75
    .line 76
    .line 77
    iget-object v11, v6, Lm8/e;->a:Lm8/d;

    .line 78
    .line 79
    invoke-virtual {v11}, Lm8/d;->a()Z

    .line 80
    .line 81
    .line 82
    move-result v11

    .line 83
    if-eqz v11, :cond_3

    .line 84
    .line 85
    iput-boolean v15, v6, Lm8/e;->c:Z

    .line 86
    .line 87
    :cond_2
    const-wide/16 v24, 0x0

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_3
    iget-wide v11, v6, Lm8/e;->d:J

    .line 91
    .line 92
    cmp-long v11, v11, v16

    .line 93
    .line 94
    if-eqz v11, :cond_2

    .line 95
    .line 96
    iget-boolean v11, v6, Lm8/e;->c:Z

    .line 97
    .line 98
    if-eqz v11, :cond_5

    .line 99
    .line 100
    iget-object v11, v6, Lm8/e;->b:Lm8/d;

    .line 101
    .line 102
    const-wide/16 v24, 0x0

    .line 103
    .line 104
    iget-wide v9, v11, Lm8/d;->d:J

    .line 105
    .line 106
    cmp-long v12, v9, v24

    .line 107
    .line 108
    if-nez v12, :cond_4

    .line 109
    .line 110
    move v9, v15

    .line 111
    goto :goto_0

    .line 112
    :cond_4
    iget-object v11, v11, Lm8/d;->g:[Z

    .line 113
    .line 114
    sub-long v9, v9, v20

    .line 115
    .line 116
    const-wide/16 v20, 0xf

    .line 117
    .line 118
    rem-long v9, v9, v20

    .line 119
    .line 120
    long-to-int v9, v9

    .line 121
    aget-boolean v9, v11, v9

    .line 122
    .line 123
    :goto_0
    if-eqz v9, :cond_6

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_5
    const-wide/16 v24, 0x0

    .line 127
    .line 128
    :goto_1
    iget-object v9, v6, Lm8/e;->b:Lm8/d;

    .line 129
    .line 130
    invoke-virtual {v9}, Lm8/d;->c()V

    .line 131
    .line 132
    .line 133
    iget-object v9, v6, Lm8/e;->b:Lm8/d;

    .line 134
    .line 135
    iget-wide v10, v6, Lm8/e;->d:J

    .line 136
    .line 137
    invoke-virtual {v9, v10, v11}, Lm8/d;->b(J)V

    .line 138
    .line 139
    .line 140
    :cond_6
    iput-boolean v7, v6, Lm8/e;->c:Z

    .line 141
    .line 142
    iget-object v9, v6, Lm8/e;->b:Lm8/d;

    .line 143
    .line 144
    invoke-virtual {v9, v13, v14}, Lm8/d;->b(J)V

    .line 145
    .line 146
    .line 147
    :goto_2
    iget-boolean v9, v6, Lm8/e;->c:Z

    .line 148
    .line 149
    if-eqz v9, :cond_7

    .line 150
    .line 151
    iget-object v9, v6, Lm8/e;->b:Lm8/d;

    .line 152
    .line 153
    invoke-virtual {v9}, Lm8/d;->a()Z

    .line 154
    .line 155
    .line 156
    move-result v9

    .line 157
    if-eqz v9, :cond_7

    .line 158
    .line 159
    iget-object v9, v6, Lm8/e;->a:Lm8/d;

    .line 160
    .line 161
    iget-object v10, v6, Lm8/e;->b:Lm8/d;

    .line 162
    .line 163
    iput-object v10, v6, Lm8/e;->a:Lm8/d;

    .line 164
    .line 165
    iput-object v9, v6, Lm8/e;->b:Lm8/d;

    .line 166
    .line 167
    iput-boolean v15, v6, Lm8/e;->c:Z

    .line 168
    .line 169
    :cond_7
    iput-wide v13, v6, Lm8/e;->d:J

    .line 170
    .line 171
    iget-object v9, v6, Lm8/e;->a:Lm8/d;

    .line 172
    .line 173
    invoke-virtual {v9}, Lm8/d;->a()Z

    .line 174
    .line 175
    .line 176
    move-result v9

    .line 177
    if-eqz v9, :cond_8

    .line 178
    .line 179
    move v9, v15

    .line 180
    goto :goto_3

    .line 181
    :cond_8
    iget v9, v6, Lm8/e;->e:I

    .line 182
    .line 183
    add-int/2addr v9, v7

    .line 184
    :goto_3
    iput v9, v6, Lm8/e;->e:I

    .line 185
    .line 186
    invoke-virtual {v3}, Lm8/c0;->c()V

    .line 187
    .line 188
    .line 189
    iput-wide v1, v0, Lm8/y;->h:J

    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_9
    move-wide/from16 v22, v11

    .line 193
    .line 194
    const-wide/16 v18, 0x3e8

    .line 195
    .line 196
    const-wide/16 v24, 0x0

    .line 197
    .line 198
    :goto_4
    sub-long/2addr v1, v4

    .line 199
    long-to-double v1, v1

    .line 200
    iget v3, v0, Lm8/y;->k:F

    .line 201
    .line 202
    float-to-double v9, v3

    .line 203
    div-double/2addr v1, v9

    .line 204
    double-to-long v1, v1

    .line 205
    iget-boolean v3, v0, Lm8/y;->d:Z

    .line 206
    .line 207
    if-eqz v3, :cond_a

    .line 208
    .line 209
    iget-object v3, v0, Lm8/y;->l:Lw7/r;

    .line 210
    .line 211
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 212
    .line 213
    .line 214
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 215
    .line 216
    .line 217
    move-result-wide v9

    .line 218
    invoke-static {v9, v10}, Lw7/w;->D(J)J

    .line 219
    .line 220
    .line 221
    move-result-wide v9

    .line 222
    sub-long v9, v9, p5

    .line 223
    .line 224
    sub-long/2addr v1, v9

    .line 225
    :cond_a
    move-wide v2, v1

    .line 226
    iput-wide v2, v8, Li9/a;->a:J

    .line 227
    .line 228
    const/4 v9, 0x3

    .line 229
    if-eqz p9, :cond_b

    .line 230
    .line 231
    if-nez p10, :cond_b

    .line 232
    .line 233
    :goto_5
    move/from16 p1, v9

    .line 234
    .line 235
    goto/16 :goto_f

    .line 236
    .line 237
    :cond_b
    iget-boolean v1, v0, Lm8/y;->m:Z

    .line 238
    .line 239
    if-nez v1, :cond_d

    .line 240
    .line 241
    iput-boolean v7, v0, Lm8/y;->n:Z

    .line 242
    .line 243
    iget-object v1, v0, Lm8/y;->a:Lm8/l;

    .line 244
    .line 245
    const/4 v7, 0x1

    .line 246
    move/from16 v6, p10

    .line 247
    .line 248
    invoke-virtual/range {v1 .. v7}, Lm8/l;->L0(JJZZ)Z

    .line 249
    .line 250
    .line 251
    move-result v1

    .line 252
    if-eqz v1, :cond_c

    .line 253
    .line 254
    goto/16 :goto_e

    .line 255
    .line 256
    :cond_c
    iget-boolean v0, v0, Lm8/y;->d:Z

    .line 257
    .line 258
    if-eqz v0, :cond_25

    .line 259
    .line 260
    iget-wide v0, v8, Li9/a;->a:J

    .line 261
    .line 262
    const-wide/16 v2, 0x7530

    .line 263
    .line 264
    cmp-long v0, v0, v2

    .line 265
    .line 266
    if-gez v0, :cond_25

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_d
    iget-wide v4, v0, Lm8/y;->i:J

    .line 270
    .line 271
    cmp-long v1, v4, v16

    .line 272
    .line 273
    const-wide/16 v10, -0x7530

    .line 274
    .line 275
    const/4 v12, 0x2

    .line 276
    if-eqz v1, :cond_f

    .line 277
    .line 278
    iget-boolean v1, v0, Lm8/y;->j:Z

    .line 279
    .line 280
    if-nez v1, :cond_f

    .line 281
    .line 282
    :cond_e
    move v1, v15

    .line 283
    goto :goto_7

    .line 284
    :cond_f
    iget v1, v0, Lm8/y;->e:I

    .line 285
    .line 286
    if-eqz v1, :cond_13

    .line 287
    .line 288
    if-eq v1, v7, :cond_10

    .line 289
    .line 290
    if-eq v1, v12, :cond_12

    .line 291
    .line 292
    if-ne v1, v9, :cond_11

    .line 293
    .line 294
    iget-object v1, v0, Lm8/y;->l:Lw7/r;

    .line 295
    .line 296
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 297
    .line 298
    .line 299
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 300
    .line 301
    .line 302
    move-result-wide v4

    .line 303
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 304
    .line 305
    .line 306
    move-result-wide v4

    .line 307
    iget-wide v13, v0, Lm8/y;->g:J

    .line 308
    .line 309
    sub-long/2addr v4, v13

    .line 310
    iget-boolean v1, v0, Lm8/y;->d:Z

    .line 311
    .line 312
    if-eqz v1, :cond_e

    .line 313
    .line 314
    iget-wide v13, v0, Lm8/y;->f:J

    .line 315
    .line 316
    cmp-long v1, v13, v16

    .line 317
    .line 318
    if-eqz v1, :cond_e

    .line 319
    .line 320
    cmp-long v1, v13, p3

    .line 321
    .line 322
    if-eqz v1, :cond_e

    .line 323
    .line 324
    cmp-long v1, v2, v10

    .line 325
    .line 326
    if-gez v1, :cond_e

    .line 327
    .line 328
    const-wide/32 v1, 0x186a0

    .line 329
    .line 330
    .line 331
    cmp-long v1, v4, v1

    .line 332
    .line 333
    if-lez v1, :cond_e

    .line 334
    .line 335
    :cond_10
    :goto_6
    move v1, v7

    .line 336
    goto :goto_7

    .line 337
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 340
    .line 341
    .line 342
    throw v0

    .line 343
    :cond_12
    cmp-long v1, p3, p7

    .line 344
    .line 345
    if-ltz v1, :cond_e

    .line 346
    .line 347
    goto :goto_6

    .line 348
    :cond_13
    iget-boolean v1, v0, Lm8/y;->d:Z

    .line 349
    .line 350
    :goto_7
    if-eqz v1, :cond_14

    .line 351
    .line 352
    return v15

    .line 353
    :cond_14
    iget-boolean v1, v0, Lm8/y;->d:Z

    .line 354
    .line 355
    if-eqz v1, :cond_25

    .line 356
    .line 357
    iget-wide v1, v0, Lm8/y;->f:J

    .line 358
    .line 359
    cmp-long v1, p3, v1

    .line 360
    .line 361
    if-nez v1, :cond_15

    .line 362
    .line 363
    goto/16 :goto_10

    .line 364
    .line 365
    :cond_15
    iget-object v1, v0, Lm8/y;->l:Lw7/r;

    .line 366
    .line 367
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 368
    .line 369
    .line 370
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 371
    .line 372
    .line 373
    move-result-wide v1

    .line 374
    iget-object v3, v0, Lm8/y;->b:Lm8/c0;

    .line 375
    .line 376
    iget-wide v4, v8, Li9/a;->a:J

    .line 377
    .line 378
    mul-long v4, v4, v18

    .line 379
    .line 380
    add-long/2addr v4, v1

    .line 381
    iget-wide v13, v3, Lm8/c0;->p:J

    .line 382
    .line 383
    cmp-long v6, v13, v22

    .line 384
    .line 385
    if-eqz v6, :cond_19

    .line 386
    .line 387
    iget-object v6, v3, Lm8/c0;->a:Lm8/e;

    .line 388
    .line 389
    iget-object v6, v6, Lm8/e;->a:Lm8/d;

    .line 390
    .line 391
    invoke-virtual {v6}, Lm8/d;->a()Z

    .line 392
    .line 393
    .line 394
    move-result v6

    .line 395
    if-eqz v6, :cond_19

    .line 396
    .line 397
    iget-object v6, v3, Lm8/c0;->a:Lm8/e;

    .line 398
    .line 399
    iget-object v13, v6, Lm8/e;->a:Lm8/d;

    .line 400
    .line 401
    invoke-virtual {v13}, Lm8/d;->a()Z

    .line 402
    .line 403
    .line 404
    move-result v13

    .line 405
    if-eqz v13, :cond_17

    .line 406
    .line 407
    iget-object v6, v6, Lm8/e;->a:Lm8/d;

    .line 408
    .line 409
    iget-wide v13, v6, Lm8/d;->e:J

    .line 410
    .line 411
    cmp-long v20, v13, v24

    .line 412
    .line 413
    move/from16 p1, v9

    .line 414
    .line 415
    move-wide/from16 p5, v10

    .line 416
    .line 417
    if-nez v20, :cond_16

    .line 418
    .line 419
    move-wide/from16 v9, v24

    .line 420
    .line 421
    goto :goto_8

    .line 422
    :cond_16
    iget-wide v9, v6, Lm8/d;->f:J

    .line 423
    .line 424
    div-long/2addr v9, v13

    .line 425
    goto :goto_8

    .line 426
    :cond_17
    move/from16 p1, v9

    .line 427
    .line 428
    move-wide/from16 p5, v10

    .line 429
    .line 430
    move-wide/from16 v9, v16

    .line 431
    .line 432
    :goto_8
    iget-wide v13, v3, Lm8/c0;->q:J

    .line 433
    .line 434
    move/from16 p2, v12

    .line 435
    .line 436
    move-wide/from16 v20, v13

    .line 437
    .line 438
    iget-wide v12, v3, Lm8/c0;->m:J

    .line 439
    .line 440
    move v11, v7

    .line 441
    iget-wide v7, v3, Lm8/c0;->p:J

    .line 442
    .line 443
    sub-long/2addr v12, v7

    .line 444
    mul-long/2addr v12, v9

    .line 445
    long-to-float v6, v12

    .line 446
    iget v7, v3, Lm8/c0;->i:F

    .line 447
    .line 448
    div-float/2addr v6, v7

    .line 449
    float-to-long v6, v6

    .line 450
    add-long v13, v20, v6

    .line 451
    .line 452
    sub-long v6, v4, v13

    .line 453
    .line 454
    invoke-static {v6, v7}, Ljava/lang/Math;->abs(J)J

    .line 455
    .line 456
    .line 457
    move-result-wide v6

    .line 458
    const-wide/32 v8, 0x1312d00

    .line 459
    .line 460
    .line 461
    cmp-long v6, v6, v8

    .line 462
    .line 463
    if-gtz v6, :cond_18

    .line 464
    .line 465
    move-wide v4, v13

    .line 466
    goto :goto_9

    .line 467
    :cond_18
    move-wide/from16 v6, v24

    .line 468
    .line 469
    iput-wide v6, v3, Lm8/c0;->m:J

    .line 470
    .line 471
    move-wide/from16 v6, v22

    .line 472
    .line 473
    iput-wide v6, v3, Lm8/c0;->p:J

    .line 474
    .line 475
    iput-wide v6, v3, Lm8/c0;->n:J

    .line 476
    .line 477
    goto :goto_9

    .line 478
    :cond_19
    move/from16 p1, v9

    .line 479
    .line 480
    move-wide/from16 p5, v10

    .line 481
    .line 482
    move/from16 p2, v12

    .line 483
    .line 484
    move v11, v7

    .line 485
    :goto_9
    iget-wide v6, v3, Lm8/c0;->m:J

    .line 486
    .line 487
    iput-wide v6, v3, Lm8/c0;->n:J

    .line 488
    .line 489
    iput-wide v4, v3, Lm8/c0;->o:J

    .line 490
    .line 491
    iget-object v6, v3, Lm8/c0;->c:Lm8/b0;

    .line 492
    .line 493
    if-eqz v6, :cond_1e

    .line 494
    .line 495
    iget-wide v7, v3, Lm8/c0;->k:J

    .line 496
    .line 497
    cmp-long v7, v7, v16

    .line 498
    .line 499
    if-nez v7, :cond_1a

    .line 500
    .line 501
    goto :goto_c

    .line 502
    :cond_1a
    iget-wide v6, v6, Lm8/b0;->d:J

    .line 503
    .line 504
    cmp-long v8, v6, v16

    .line 505
    .line 506
    if-nez v8, :cond_1b

    .line 507
    .line 508
    goto :goto_c

    .line 509
    :cond_1b
    iget-wide v8, v3, Lm8/c0;->k:J

    .line 510
    .line 511
    sub-long v12, v4, v6

    .line 512
    .line 513
    div-long/2addr v12, v8

    .line 514
    mul-long/2addr v12, v8

    .line 515
    add-long/2addr v12, v6

    .line 516
    cmp-long v6, v4, v12

    .line 517
    .line 518
    if-gtz v6, :cond_1c

    .line 519
    .line 520
    sub-long v6, v12, v8

    .line 521
    .line 522
    goto :goto_a

    .line 523
    :cond_1c
    add-long/2addr v8, v12

    .line 524
    move-wide v6, v12

    .line 525
    move-wide v12, v8

    .line 526
    :goto_a
    sub-long v8, v12, v4

    .line 527
    .line 528
    sub-long/2addr v4, v6

    .line 529
    cmp-long v4, v8, v4

    .line 530
    .line 531
    if-gez v4, :cond_1d

    .line 532
    .line 533
    goto :goto_b

    .line 534
    :cond_1d
    move-wide v12, v6

    .line 535
    :goto_b
    iget-wide v3, v3, Lm8/c0;->l:J

    .line 536
    .line 537
    sub-long v4, v12, v3

    .line 538
    .line 539
    :cond_1e
    :goto_c
    move-object/from16 v8, p11

    .line 540
    .line 541
    iput-wide v4, v8, Li9/a;->b:J

    .line 542
    .line 543
    sub-long/2addr v4, v1

    .line 544
    div-long v1, v4, v18

    .line 545
    .line 546
    iput-wide v1, v8, Li9/a;->a:J

    .line 547
    .line 548
    iget-wide v3, v0, Lm8/y;->i:J

    .line 549
    .line 550
    cmp-long v3, v3, v16

    .line 551
    .line 552
    if-eqz v3, :cond_1f

    .line 553
    .line 554
    iget-boolean v3, v0, Lm8/y;->j:Z

    .line 555
    .line 556
    if-nez v3, :cond_1f

    .line 557
    .line 558
    move v6, v11

    .line 559
    goto :goto_d

    .line 560
    :cond_1f
    move v6, v15

    .line 561
    :goto_d
    iget-object v0, v0, Lm8/y;->a:Lm8/l;

    .line 562
    .line 563
    move-wide/from16 v3, p3

    .line 564
    .line 565
    move/from16 v5, p10

    .line 566
    .line 567
    invoke-virtual/range {v0 .. v6}, Lm8/l;->L0(JJZZ)Z

    .line 568
    .line 569
    .line 570
    move-result v0

    .line 571
    if-eqz v0, :cond_20

    .line 572
    .line 573
    :goto_e
    const/4 v0, 0x4

    .line 574
    return v0

    .line 575
    :cond_20
    iget-wide v0, v8, Li9/a;->a:J

    .line 576
    .line 577
    cmp-long v2, v0, p5

    .line 578
    .line 579
    if-gez v2, :cond_21

    .line 580
    .line 581
    if-nez p10, :cond_21

    .line 582
    .line 583
    move v15, v11

    .line 584
    :cond_21
    if-eqz v15, :cond_23

    .line 585
    .line 586
    if-eqz v6, :cond_22

    .line 587
    .line 588
    :goto_f
    return p1

    .line 589
    :cond_22
    return p2

    .line 590
    :cond_23
    const-wide/32 v2, 0xc350

    .line 591
    .line 592
    .line 593
    cmp-long v0, v0, v2

    .line 594
    .line 595
    if-lez v0, :cond_24

    .line 596
    .line 597
    goto :goto_10

    .line 598
    :cond_24
    return v11

    .line 599
    :cond_25
    :goto_10
    const/4 v0, 0x5

    .line 600
    return v0
.end method

.method public final b(Z)Z
    .locals 8

    .line 1
    const/4 v0, 0x1

    .line 2
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 3
    .line 4
    .line 5
    .line 6
    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    iget p1, p0, Lm8/y;->e:I

    .line 10
    .line 11
    const/4 v3, 0x3

    .line 12
    if-eq p1, v3, :cond_0

    .line 13
    .line 14
    iget-boolean p1, p0, Lm8/y;->m:Z

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    iget-boolean p1, p0, Lm8/y;->n:Z

    .line 19
    .line 20
    if-eqz p1, :cond_1

    .line 21
    .line 22
    :cond_0
    iput-wide v1, p0, Lm8/y;->i:J

    .line 23
    .line 24
    return v0

    .line 25
    :cond_1
    iget-wide v3, p0, Lm8/y;->i:J

    .line 26
    .line 27
    cmp-long p1, v3, v1

    .line 28
    .line 29
    const/4 v3, 0x0

    .line 30
    if-nez p1, :cond_2

    .line 31
    .line 32
    return v3

    .line 33
    :cond_2
    iget-object p1, p0, Lm8/y;->l:Lw7/r;

    .line 34
    .line 35
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 39
    .line 40
    .line 41
    move-result-wide v4

    .line 42
    iget-wide v6, p0, Lm8/y;->i:J

    .line 43
    .line 44
    cmp-long p1, v4, v6

    .line 45
    .line 46
    if-gez p1, :cond_3

    .line 47
    .line 48
    return v0

    .line 49
    :cond_3
    iput-wide v1, p0, Lm8/y;->i:J

    .line 50
    .line 51
    return v3
.end method

.method public final c(Z)V
    .locals 4

    .line 1
    iput-boolean p1, p0, Lm8/y;->j:Z

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    iget-wide v2, p0, Lm8/y;->c:J

    .line 6
    .line 7
    cmp-long p1, v2, v0

    .line 8
    .line 9
    if-lez p1, :cond_0

    .line 10
    .line 11
    iget-object p1, p0, Lm8/y;->l:Lw7/r;

    .line 12
    .line 13
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    add-long/2addr v0, v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    :goto_0
    iput-wide v0, p0, Lm8/y;->i:J

    .line 28
    .line 29
    return-void
.end method

.method public final d()V
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lm8/y;->d:Z

    .line 3
    .line 4
    iget-object v1, p0, Lm8/y;->l:Lw7/r;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    invoke-static {v1, v2}, Lw7/w;->D(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide v1

    .line 17
    iput-wide v1, p0, Lm8/y;->g:J

    .line 18
    .line 19
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 20
    .line 21
    iput-boolean v0, p0, Lm8/c0;->d:Z

    .line 22
    .line 23
    const-wide/16 v0, 0x0

    .line 24
    .line 25
    iput-wide v0, p0, Lm8/c0;->m:J

    .line 26
    .line 27
    const-wide/16 v0, -0x1

    .line 28
    .line 29
    iput-wide v0, p0, Lm8/c0;->p:J

    .line 30
    .line 31
    iput-wide v0, p0, Lm8/c0;->n:J

    .line 32
    .line 33
    iget-object v0, p0, Lm8/c0;->b:Lm8/a0;

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    iget-object v2, v0, Lm8/a0;->a:Landroid/hardware/display/DisplayManager;

    .line 39
    .line 40
    iget-object v3, p0, Lm8/c0;->c:Lm8/b0;

    .line 41
    .line 42
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    iget-object v3, v3, Lm8/b0;->e:Landroid/os/Handler;

    .line 46
    .line 47
    const/4 v4, 0x2

    .line 48
    invoke-virtual {v3, v4}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 49
    .line 50
    .line 51
    const/4 v3, 0x0

    .line 52
    invoke-static {v3}, Lw7/w;->k(Lm8/k;)Landroid/os/Handler;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-virtual {v2, v0, v3}, Landroid/hardware/display/DisplayManager;->registerDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;Landroid/os/Handler;)V

    .line 57
    .line 58
    .line 59
    iget-object v0, v0, Lm8/a0;->b:Lm8/c0;

    .line 60
    .line 61
    invoke-virtual {v2, v1}, Landroid/hardware/display/DisplayManager;->getDisplay(I)Landroid/view/Display;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-static {v0, v2}, Lm8/c0;->a(Lm8/c0;Landroid/view/Display;)V

    .line 66
    .line 67
    .line 68
    :cond_0
    invoke-virtual {p0, v1}, Lm8/c0;->d(Z)V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public final e()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lm8/y;->d:Z

    .line 3
    .line 4
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    iput-wide v1, p0, Lm8/y;->i:J

    .line 10
    .line 11
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 12
    .line 13
    iput-boolean v0, p0, Lm8/c0;->d:Z

    .line 14
    .line 15
    iget-object v0, p0, Lm8/c0;->b:Lm8/a0;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v1, v0, Lm8/a0;->a:Landroid/hardware/display/DisplayManager;

    .line 20
    .line 21
    invoke-virtual {v1, v0}, Landroid/hardware/display/DisplayManager;->unregisterDisplayListener(Landroid/hardware/display/DisplayManager$DisplayListener;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lm8/c0;->c:Lm8/b0;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    iget-object v0, v0, Lm8/b0;->e:Landroid/os/Handler;

    .line 30
    .line 31
    const/4 v1, 0x3

    .line 32
    invoke-virtual {v0, v1}, Landroid/os/Handler;->sendEmptyMessage(I)Z

    .line 33
    .line 34
    .line 35
    :cond_0
    invoke-virtual {p0}, Lm8/c0;->b()V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final f(I)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p1, :cond_2

    .line 3
    .line 4
    if-eq p1, v0, :cond_1

    .line 5
    .line 6
    const/4 v0, 0x2

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget p1, p0, Lm8/y;->e:I

    .line 10
    .line 11
    invoke-static {p1, v0}, Ljava/lang/Math;->min(II)I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    iput p1, p0, Lm8/y;->e:I

    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    const/4 p1, 0x0

    .line 25
    iput p1, p0, Lm8/y;->e:I

    .line 26
    .line 27
    return-void

    .line 28
    :cond_2
    iput v0, p0, Lm8/y;->e:I

    .line 29
    .line 30
    return-void
.end method

.method public final g(F)V
    .locals 3

    .line 1
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 2
    .line 3
    iput p1, p0, Lm8/c0;->f:F

    .line 4
    .line 5
    iget-object p1, p0, Lm8/c0;->a:Lm8/e;

    .line 6
    .line 7
    iget-object v0, p1, Lm8/e;->a:Lm8/d;

    .line 8
    .line 9
    invoke-virtual {v0}, Lm8/d;->c()V

    .line 10
    .line 11
    .line 12
    iget-object v0, p1, Lm8/e;->b:Lm8/d;

    .line 13
    .line 14
    invoke-virtual {v0}, Lm8/d;->c()V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    iput-boolean v0, p1, Lm8/e;->c:Z

    .line 19
    .line 20
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    iput-wide v1, p1, Lm8/e;->d:J

    .line 26
    .line 27
    iput v0, p1, Lm8/e;->e:I

    .line 28
    .line 29
    invoke-virtual {p0}, Lm8/c0;->c()V

    .line 30
    .line 31
    .line 32
    return-void
.end method

.method public final h(Landroid/view/Surface;)V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    move v2, v1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v2, v0

    .line 8
    :goto_0
    iput-boolean v2, p0, Lm8/y;->m:Z

    .line 9
    .line 10
    iput-boolean v0, p0, Lm8/y;->n:Z

    .line 11
    .line 12
    iget-object v0, p0, Lm8/y;->b:Lm8/c0;

    .line 13
    .line 14
    iget-object v2, v0, Lm8/c0;->e:Landroid/view/Surface;

    .line 15
    .line 16
    if-ne v2, p1, :cond_1

    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_1
    invoke-virtual {v0}, Lm8/c0;->b()V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Lm8/c0;->e:Landroid/view/Surface;

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Lm8/c0;->d(Z)V

    .line 25
    .line 26
    .line 27
    :goto_1
    iget p1, p0, Lm8/y;->e:I

    .line 28
    .line 29
    invoke-static {p1, v1}, Ljava/lang/Math;->min(II)I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    iput p1, p0, Lm8/y;->e:I

    .line 34
    .line 35
    return-void
.end method

.method public final i(F)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpl-float v0, p1, v0

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-lez v0, :cond_0

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v0, v1

    .line 10
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 11
    .line 12
    .line 13
    iget v0, p0, Lm8/y;->k:F

    .line 14
    .line 15
    cmpl-float v0, p1, v0

    .line 16
    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    return-void

    .line 20
    :cond_1
    iput p1, p0, Lm8/y;->k:F

    .line 21
    .line 22
    iget-object p0, p0, Lm8/y;->b:Lm8/c0;

    .line 23
    .line 24
    iput p1, p0, Lm8/c0;->i:F

    .line 25
    .line 26
    const-wide/16 v2, 0x0

    .line 27
    .line 28
    iput-wide v2, p0, Lm8/c0;->m:J

    .line 29
    .line 30
    const-wide/16 v2, -0x1

    .line 31
    .line 32
    iput-wide v2, p0, Lm8/c0;->p:J

    .line 33
    .line 34
    iput-wide v2, p0, Lm8/c0;->n:J

    .line 35
    .line 36
    invoke-virtual {p0, v1}, Lm8/c0;->d(Z)V

    .line 37
    .line 38
    .line 39
    return-void
.end method
