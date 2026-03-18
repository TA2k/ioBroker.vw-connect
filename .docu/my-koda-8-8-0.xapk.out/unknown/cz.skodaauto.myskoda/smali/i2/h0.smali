.class public abstract Li2/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide/high16 v0, 0x3fc0000000000000L    # 0.125

    .line 2
    .line 3
    double-to-float v0, v0

    .line 4
    const/16 v1, 0x12

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    div-float/2addr v0, v1

    .line 8
    sput v0, Li2/h0;->a:F

    .line 9
    .line 10
    return-void
.end method

.method public static final a(Lp3/i0;JILg1/r0;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-wide/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    instance-of v3, v2, Li2/g0;

    .line 6
    .line 7
    if-eqz v3, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    check-cast v3, Li2/g0;

    .line 11
    .line 12
    iget v4, v3, Li2/g0;->k:I

    .line 13
    .line 14
    const/high16 v5, -0x80000000

    .line 15
    .line 16
    and-int v6, v4, v5

    .line 17
    .line 18
    if-eqz v6, :cond_0

    .line 19
    .line 20
    sub-int/2addr v4, v5

    .line 21
    iput v4, v3, Li2/g0;->k:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v3, Li2/g0;

    .line 25
    .line 26
    invoke-direct {v3, v2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v2, v3, Li2/g0;->j:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v5, v3, Li2/g0;->k:I

    .line 34
    .line 35
    const/4 v7, 0x2

    .line 36
    const/4 v9, 0x1

    .line 37
    const/4 v10, 0x0

    .line 38
    if-eqz v5, :cond_3

    .line 39
    .line 40
    if-eq v5, v9, :cond_2

    .line 41
    .line 42
    if-ne v5, v7, :cond_1

    .line 43
    .line 44
    iget v0, v3, Li2/g0;->i:F

    .line 45
    .line 46
    iget v1, v3, Li2/g0;->h:F

    .line 47
    .line 48
    iget-object v5, v3, Li2/g0;->g:Lp3/t;

    .line 49
    .line 50
    iget-object v11, v3, Li2/g0;->f:Lkotlin/jvm/internal/e0;

    .line 51
    .line 52
    iget-object v12, v3, Li2/g0;->e:Lp3/i0;

    .line 53
    .line 54
    iget-object v13, v3, Li2/g0;->d:Lay0/n;

    .line 55
    .line 56
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    move v8, v1

    .line 60
    move-object v6, v10

    .line 61
    move-object v2, v12

    .line 62
    move v1, v0

    .line 63
    move-object v0, v13

    .line 64
    goto/16 :goto_c

    .line 65
    .line 66
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 69
    .line 70
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw v0

    .line 74
    :cond_2
    iget v0, v3, Li2/g0;->i:F

    .line 75
    .line 76
    iget v1, v3, Li2/g0;->h:F

    .line 77
    .line 78
    iget-object v5, v3, Li2/g0;->f:Lkotlin/jvm/internal/e0;

    .line 79
    .line 80
    iget-object v11, v3, Li2/g0;->e:Lp3/i0;

    .line 81
    .line 82
    iget-object v12, v3, Li2/g0;->d:Lay0/n;

    .line 83
    .line 84
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    move/from16 v17, v1

    .line 88
    .line 89
    move v1, v0

    .line 90
    move-object v0, v12

    .line 91
    move-object v12, v5

    .line 92
    move/from16 v5, v17

    .line 93
    .line 94
    goto/16 :goto_5

    .line 95
    .line 96
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    move-object/from16 v2, p0

    .line 100
    .line 101
    iget-object v5, v2, Lp3/i0;->i:Lp3/j0;

    .line 102
    .line 103
    iget-object v5, v5, Lp3/j0;->w:Lp3/k;

    .line 104
    .line 105
    iget-object v5, v5, Lp3/k;->a:Ljava/lang/Object;

    .line 106
    .line 107
    move-object v11, v5

    .line 108
    check-cast v11, Ljava/util/Collection;

    .line 109
    .line 110
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 111
    .line 112
    .line 113
    move-result v11

    .line 114
    const/4 v12, 0x0

    .line 115
    :goto_1
    if-ge v12, v11, :cond_5

    .line 116
    .line 117
    invoke-interface {v5, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v13

    .line 121
    move-object v14, v13

    .line 122
    check-cast v14, Lp3/t;

    .line 123
    .line 124
    iget-wide v14, v14, Lp3/t;->a:J

    .line 125
    .line 126
    invoke-static {v14, v15, v0, v1}, Lp3/s;->e(JJ)Z

    .line 127
    .line 128
    .line 129
    move-result v14

    .line 130
    if-eqz v14, :cond_4

    .line 131
    .line 132
    goto :goto_2

    .line 133
    :cond_4
    add-int/lit8 v12, v12, 0x1

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_5
    move-object v13, v10

    .line 137
    :goto_2
    check-cast v13, Lp3/t;

    .line 138
    .line 139
    if-eqz v13, :cond_13

    .line 140
    .line 141
    iget-boolean v5, v13, Lp3/t;->d:Z

    .line 142
    .line 143
    if-ne v5, v9, :cond_13

    .line 144
    .line 145
    invoke-virtual {v2}, Lp3/i0;->f()Lw3/h2;

    .line 146
    .line 147
    .line 148
    move-result-object v5

    .line 149
    move/from16 v11, p3

    .line 150
    .line 151
    if-ne v11, v7, :cond_6

    .line 152
    .line 153
    invoke-interface {v5}, Lw3/h2;->f()F

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    sget v11, Li2/h0;->a:F

    .line 158
    .line 159
    mul-float/2addr v5, v11

    .line 160
    goto :goto_3

    .line 161
    :cond_6
    invoke-interface {v5}, Lw3/h2;->f()F

    .line 162
    .line 163
    .line 164
    move-result v5

    .line 165
    :goto_3
    new-instance v11, Lkotlin/jvm/internal/e0;

    .line 166
    .line 167
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 168
    .line 169
    .line 170
    iput-wide v0, v11, Lkotlin/jvm/internal/e0;->d:J

    .line 171
    .line 172
    move-object/from16 v0, p4

    .line 173
    .line 174
    const/4 v1, 0x0

    .line 175
    :goto_4
    iput-object v0, v3, Li2/g0;->d:Lay0/n;

    .line 176
    .line 177
    iput-object v2, v3, Li2/g0;->e:Lp3/i0;

    .line 178
    .line 179
    iput-object v11, v3, Li2/g0;->f:Lkotlin/jvm/internal/e0;

    .line 180
    .line 181
    iput-object v10, v3, Li2/g0;->g:Lp3/t;

    .line 182
    .line 183
    iput v5, v3, Li2/g0;->h:F

    .line 184
    .line 185
    iput v1, v3, Li2/g0;->i:F

    .line 186
    .line 187
    iput v9, v3, Li2/g0;->k:I

    .line 188
    .line 189
    sget-object v12, Lp3/l;->e:Lp3/l;

    .line 190
    .line 191
    invoke-virtual {v2, v12, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v12

    .line 195
    if-ne v12, v4, :cond_7

    .line 196
    .line 197
    goto/16 :goto_b

    .line 198
    .line 199
    :cond_7
    move-object/from16 v17, v11

    .line 200
    .line 201
    move-object v11, v2

    .line 202
    move-object v2, v12

    .line 203
    move-object/from16 v12, v17

    .line 204
    .line 205
    :goto_5
    check-cast v2, Lp3/k;

    .line 206
    .line 207
    iget-object v13, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 208
    .line 209
    move-object v14, v13

    .line 210
    check-cast v14, Ljava/util/Collection;

    .line 211
    .line 212
    invoke-interface {v14}, Ljava/util/Collection;->size()I

    .line 213
    .line 214
    .line 215
    move-result v14

    .line 216
    const/4 v15, 0x0

    .line 217
    :goto_6
    if-ge v15, v14, :cond_9

    .line 218
    .line 219
    invoke-interface {v13, v15}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v16

    .line 223
    move-object/from16 v6, v16

    .line 224
    .line 225
    check-cast v6, Lp3/t;

    .line 226
    .line 227
    iget-wide v8, v6, Lp3/t;->a:J

    .line 228
    .line 229
    move-object v6, v10

    .line 230
    move-object/from16 p0, v11

    .line 231
    .line 232
    iget-wide v10, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 233
    .line 234
    invoke-static {v8, v9, v10, v11}, Lp3/s;->e(JJ)Z

    .line 235
    .line 236
    .line 237
    move-result v8

    .line 238
    if-eqz v8, :cond_8

    .line 239
    .line 240
    goto :goto_7

    .line 241
    :cond_8
    add-int/lit8 v15, v15, 0x1

    .line 242
    .line 243
    move-object/from16 v11, p0

    .line 244
    .line 245
    move-object v10, v6

    .line 246
    const/4 v9, 0x1

    .line 247
    goto :goto_6

    .line 248
    :cond_9
    move-object v6, v10

    .line 249
    move-object/from16 p0, v11

    .line 250
    .line 251
    move-object/from16 v16, v6

    .line 252
    .line 253
    :goto_7
    invoke-static/range {v16 .. v16}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    move-object/from16 v8, v16

    .line 257
    .line 258
    check-cast v8, Lp3/t;

    .line 259
    .line 260
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 261
    .line 262
    .line 263
    move-result v9

    .line 264
    if-eqz v9, :cond_a

    .line 265
    .line 266
    goto/16 :goto_d

    .line 267
    .line 268
    :cond_a
    invoke-static {v8}, Lp3/s;->d(Lp3/t;)Z

    .line 269
    .line 270
    .line 271
    move-result v9

    .line 272
    if-eqz v9, :cond_e

    .line 273
    .line 274
    iget-object v2, v2, Lp3/k;->a:Ljava/lang/Object;

    .line 275
    .line 276
    move-object v8, v2

    .line 277
    check-cast v8, Ljava/util/Collection;

    .line 278
    .line 279
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 280
    .line 281
    .line 282
    move-result v8

    .line 283
    const/4 v9, 0x0

    .line 284
    :goto_8
    if-ge v9, v8, :cond_c

    .line 285
    .line 286
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v10

    .line 290
    move-object v11, v10

    .line 291
    check-cast v11, Lp3/t;

    .line 292
    .line 293
    iget-boolean v11, v11, Lp3/t;->d:Z

    .line 294
    .line 295
    if-eqz v11, :cond_b

    .line 296
    .line 297
    goto :goto_9

    .line 298
    :cond_b
    add-int/lit8 v9, v9, 0x1

    .line 299
    .line 300
    goto :goto_8

    .line 301
    :cond_c
    move-object v10, v6

    .line 302
    :goto_9
    check-cast v10, Lp3/t;

    .line 303
    .line 304
    if-nez v10, :cond_d

    .line 305
    .line 306
    goto/16 :goto_d

    .line 307
    .line 308
    :cond_d
    iget-wide v8, v10, Lp3/t;->a:J

    .line 309
    .line 310
    iput-wide v8, v12, Lkotlin/jvm/internal/e0;->d:J

    .line 311
    .line 312
    move-object/from16 v2, p0

    .line 313
    .line 314
    move-object v10, v6

    .line 315
    move-object v11, v12

    .line 316
    :goto_a
    const/4 v9, 0x1

    .line 317
    goto/16 :goto_4

    .line 318
    .line 319
    :cond_e
    iget-wide v9, v8, Lp3/t;->c:J

    .line 320
    .line 321
    iget-wide v13, v8, Lp3/t;->g:J

    .line 322
    .line 323
    const/16 v2, 0x20

    .line 324
    .line 325
    shr-long/2addr v9, v2

    .line 326
    long-to-int v9, v9

    .line 327
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 328
    .line 329
    .line 330
    move-result v9

    .line 331
    shr-long v10, v13, v2

    .line 332
    .line 333
    long-to-int v2, v10

    .line 334
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 335
    .line 336
    .line 337
    move-result v2

    .line 338
    sub-float/2addr v9, v2

    .line 339
    add-float/2addr v1, v9

    .line 340
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 341
    .line 342
    .line 343
    move-result v2

    .line 344
    cmpg-float v2, v2, v5

    .line 345
    .line 346
    if-gez v2, :cond_11

    .line 347
    .line 348
    sget-object v2, Lp3/l;->f:Lp3/l;

    .line 349
    .line 350
    iput-object v0, v3, Li2/g0;->d:Lay0/n;

    .line 351
    .line 352
    move-object/from16 v11, p0

    .line 353
    .line 354
    iput-object v11, v3, Li2/g0;->e:Lp3/i0;

    .line 355
    .line 356
    iput-object v12, v3, Li2/g0;->f:Lkotlin/jvm/internal/e0;

    .line 357
    .line 358
    iput-object v8, v3, Li2/g0;->g:Lp3/t;

    .line 359
    .line 360
    iput v5, v3, Li2/g0;->h:F

    .line 361
    .line 362
    iput v1, v3, Li2/g0;->i:F

    .line 363
    .line 364
    iput v7, v3, Li2/g0;->k:I

    .line 365
    .line 366
    invoke-virtual {v11, v2, v3}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    if-ne v2, v4, :cond_f

    .line 371
    .line 372
    :goto_b
    return-object v4

    .line 373
    :cond_f
    move-object v2, v8

    .line 374
    move v8, v5

    .line 375
    move-object v5, v2

    .line 376
    move-object v2, v11

    .line 377
    move-object v11, v12

    .line 378
    :goto_c
    invoke-virtual {v5}, Lp3/t;->b()Z

    .line 379
    .line 380
    .line 381
    move-result v5

    .line 382
    if-eqz v5, :cond_10

    .line 383
    .line 384
    goto :goto_d

    .line 385
    :cond_10
    move-object v10, v6

    .line 386
    move v5, v8

    .line 387
    goto :goto_a

    .line 388
    :cond_11
    move-object/from16 v11, p0

    .line 389
    .line 390
    invoke-static {v1}, Ljava/lang/Math;->signum(F)F

    .line 391
    .line 392
    .line 393
    move-result v2

    .line 394
    mul-float/2addr v2, v5

    .line 395
    sub-float/2addr v1, v2

    .line 396
    new-instance v2, Ljava/lang/Float;

    .line 397
    .line 398
    invoke-direct {v2, v1}, Ljava/lang/Float;-><init>(F)V

    .line 399
    .line 400
    .line 401
    invoke-interface {v0, v8, v2}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    invoke-virtual {v8}, Lp3/t;->b()Z

    .line 405
    .line 406
    .line 407
    move-result v1

    .line 408
    if-eqz v1, :cond_12

    .line 409
    .line 410
    return-object v8

    .line 411
    :cond_12
    move-object v10, v6

    .line 412
    move-object v2, v11

    .line 413
    move-object v11, v12

    .line 414
    const/4 v1, 0x0

    .line 415
    goto :goto_a

    .line 416
    :cond_13
    move-object v6, v10

    .line 417
    :goto_d
    return-object v6
.end method
