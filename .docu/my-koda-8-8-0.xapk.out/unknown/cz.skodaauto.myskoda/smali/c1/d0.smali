.class public final Lc1/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/b0;


# instance fields
.field public final a:F

.field public final b:Lc1/e1;


# direct methods
.method public constructor <init>(FFF)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lc1/d0;->a:F

    .line 5
    .line 6
    new-instance p3, Lc1/e1;

    .line 7
    .line 8
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    const/high16 v0, 0x3f800000    # 1.0f

    .line 12
    .line 13
    iput v0, p3, Lc1/e1;->a:F

    .line 14
    .line 15
    const-wide/high16 v1, 0x4049000000000000L    # 50.0

    .line 16
    .line 17
    invoke-static {v1, v2}, Ljava/lang/Math;->sqrt(D)D

    .line 18
    .line 19
    .line 20
    move-result-wide v1

    .line 21
    iput-wide v1, p3, Lc1/e1;->b:D

    .line 22
    .line 23
    iput v0, p3, Lc1/e1;->c:F

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    cmpg-float v1, p1, v0

    .line 27
    .line 28
    if-gez v1, :cond_0

    .line 29
    .line 30
    const-string v1, "Damping ratio must be non-negative"

    .line 31
    .line 32
    invoke-static {v1}, Lc1/s0;->a(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    :cond_0
    iput p1, p3, Lc1/e1;->c:F

    .line 36
    .line 37
    iget-wide v1, p3, Lc1/e1;->b:D

    .line 38
    .line 39
    mul-double/2addr v1, v1

    .line 40
    double-to-float p1, v1

    .line 41
    cmpg-float p1, p1, v0

    .line 42
    .line 43
    if-gtz p1, :cond_1

    .line 44
    .line 45
    const-string p1, "Spring stiffness constant must be positive."

    .line 46
    .line 47
    invoke-static {p1}, Lc1/s0;->a(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    float-to-double p1, p2

    .line 51
    invoke-static {p1, p2}, Ljava/lang/Math;->sqrt(D)D

    .line 52
    .line 53
    .line 54
    move-result-wide p1

    .line 55
    iput-wide p1, p3, Lc1/e1;->b:D

    .line 56
    .line 57
    iput-object p3, p0, Lc1/d0;->b:Lc1/e1;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final b(FFF)F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final c(JFFF)F
    .locals 2

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    iget-object p0, p0, Lc1/d0;->b:Lc1/e1;

    .line 6
    .line 7
    iput p4, p0, Lc1/e1;->a:F

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, p5}, Lc1/e1;->a(JFF)J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    const/16 p2, 0x20

    .line 14
    .line 15
    shr-long/2addr p0, p2

    .line 16
    long-to-int p0, p0

    .line 17
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method

.method public final d(JFFF)F
    .locals 2

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    iget-object p0, p0, Lc1/d0;->b:Lc1/e1;

    .line 6
    .line 7
    iput p4, p0, Lc1/e1;->a:F

    .line 8
    .line 9
    invoke-virtual {p0, p1, p2, p3, p5}, Lc1/e1;->a(JFF)J

    .line 10
    .line 11
    .line 12
    move-result-wide p0

    .line 13
    const-wide p2, 0xffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    and-long/2addr p0, p2

    .line 19
    long-to-int p0, p0

    .line 20
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0
.end method

.method public final e(FFF)J
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lc1/d0;->b:Lc1/e1;

    .line 4
    .line 5
    iget-wide v2, v1, Lc1/e1;->b:D

    .line 6
    .line 7
    mul-double/2addr v2, v2

    .line 8
    double-to-float v2, v2

    .line 9
    iget v1, v1, Lc1/e1;->c:F

    .line 10
    .line 11
    sub-float v3, p1, p2

    .line 12
    .line 13
    iget v0, v0, Lc1/d0;->a:F

    .line 14
    .line 15
    div-float/2addr v3, v0

    .line 16
    div-float v0, p3, v0

    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    cmpg-float v4, v1, v4

    .line 20
    .line 21
    if-nez v4, :cond_0

    .line 22
    .line 23
    const-wide v0, 0x8637bd05af6L

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    goto/16 :goto_d

    .line 29
    .line 30
    :cond_0
    float-to-double v4, v2

    .line 31
    float-to-double v1, v1

    .line 32
    float-to-double v6, v0

    .line 33
    float-to-double v8, v3

    .line 34
    const/high16 v0, 0x3f800000    # 1.0f

    .line 35
    .line 36
    float-to-double v10, v0

    .line 37
    const-wide/high16 v12, 0x4000000000000000L    # 2.0

    .line 38
    .line 39
    mul-double v14, v1, v12

    .line 40
    .line 41
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 42
    .line 43
    .line 44
    move-result-wide v16

    .line 45
    mul-double v14, v14, v16

    .line 46
    .line 47
    mul-double v16, v14, v14

    .line 48
    .line 49
    const-wide/high16 v18, 0x4010000000000000L    # 4.0

    .line 50
    .line 51
    mul-double v4, v4, v18

    .line 52
    .line 53
    sub-double v16, v16, v4

    .line 54
    .line 55
    const-wide/16 v3, 0x0

    .line 56
    .line 57
    cmpg-double v0, v16, v3

    .line 58
    .line 59
    if-gez v0, :cond_1

    .line 60
    .line 61
    move-wide/from16 v18, v3

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->sqrt(D)D

    .line 65
    .line 66
    .line 67
    move-result-wide v18

    .line 68
    :goto_0
    if-gez v0, :cond_2

    .line 69
    .line 70
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->abs(D)D

    .line 71
    .line 72
    .line 73
    move-result-wide v16

    .line 74
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->sqrt(D)D

    .line 75
    .line 76
    .line 77
    move-result-wide v16

    .line 78
    goto :goto_1

    .line 79
    :cond_2
    move-wide/from16 v16, v3

    .line 80
    .line 81
    :goto_1
    neg-double v14, v14

    .line 82
    add-double v20, v14, v18

    .line 83
    .line 84
    const-wide/high16 v22, 0x3fe0000000000000L    # 0.5

    .line 85
    .line 86
    mul-double v20, v20, v22

    .line 87
    .line 88
    mul-double v16, v16, v22

    .line 89
    .line 90
    sub-double v14, v14, v18

    .line 91
    .line 92
    mul-double v14, v14, v22

    .line 93
    .line 94
    cmpg-double v0, v8, v3

    .line 95
    .line 96
    if-nez v0, :cond_3

    .line 97
    .line 98
    cmpg-double v5, v6, v3

    .line 99
    .line 100
    if-nez v5, :cond_3

    .line 101
    .line 102
    const-wide/16 v0, 0x0

    .line 103
    .line 104
    goto/16 :goto_d

    .line 105
    .line 106
    :cond_3
    if-gez v0, :cond_4

    .line 107
    .line 108
    neg-double v6, v6

    .line 109
    :cond_4
    invoke-static {v8, v9}, Ljava/lang/Math;->abs(D)D

    .line 110
    .line 111
    .line 112
    move-result-wide v8

    .line 113
    const-wide/high16 v18, 0x3ff0000000000000L    # 1.0

    .line 114
    .line 115
    cmpl-double v0, v1, v18

    .line 116
    .line 117
    const-wide v22, 0x3f50624dd2f1a9fcL    # 0.001

    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    const-wide v24, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 123
    .line 124
    .line 125
    .line 126
    .line 127
    const-wide/high16 v26, 0x7ff0000000000000L    # Double.POSITIVE_INFINITY

    .line 128
    .line 129
    const-wide v28, 0x7fffffffffffffffL

    .line 130
    .line 131
    .line 132
    .line 133
    .line 134
    const/16 v30, 0x0

    .line 135
    .line 136
    if-lez v0, :cond_b

    .line 137
    .line 138
    mul-double v0, v20, v8

    .line 139
    .line 140
    sub-double/2addr v0, v6

    .line 141
    sub-double v6, v20, v14

    .line 142
    .line 143
    div-double/2addr v0, v6

    .line 144
    sub-double/2addr v8, v0

    .line 145
    div-double v12, v10, v8

    .line 146
    .line 147
    invoke-static {v12, v13}, Ljava/lang/Math;->abs(D)D

    .line 148
    .line 149
    .line 150
    move-result-wide v12

    .line 151
    invoke-static {v12, v13}, Ljava/lang/Math;->log(D)D

    .line 152
    .line 153
    .line 154
    move-result-wide v12

    .line 155
    div-double v12, v12, v20

    .line 156
    .line 157
    div-double v16, v10, v0

    .line 158
    .line 159
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->abs(D)D

    .line 160
    .line 161
    .line 162
    move-result-wide v16

    .line 163
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->log(D)D

    .line 164
    .line 165
    .line 166
    move-result-wide v16

    .line 167
    move-wide/from16 p0, v3

    .line 168
    .line 169
    div-double v3, v16, v14

    .line 170
    .line 171
    invoke-static {v12, v13}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 172
    .line 173
    .line 174
    move-result-wide v16

    .line 175
    and-long v16, v16, v28

    .line 176
    .line 177
    cmp-long v2, v16, v26

    .line 178
    .line 179
    if-gez v2, :cond_5

    .line 180
    .line 181
    invoke-static {v3, v4}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 182
    .line 183
    .line 184
    move-result-wide v16

    .line 185
    and-long v16, v16, v28

    .line 186
    .line 187
    cmp-long v2, v16, v26

    .line 188
    .line 189
    if-gez v2, :cond_6

    .line 190
    .line 191
    invoke-static {v12, v13, v3, v4}, Ljava/lang/Math;->max(DD)D

    .line 192
    .line 193
    .line 194
    move-result-wide v12

    .line 195
    goto :goto_2

    .line 196
    :cond_5
    move-wide v12, v3

    .line 197
    :cond_6
    :goto_2
    mul-double v2, v8, v20

    .line 198
    .line 199
    move-wide/from16 v16, v6

    .line 200
    .line 201
    neg-double v5, v0

    .line 202
    mul-double/2addr v5, v14

    .line 203
    div-double v4, v2, v5

    .line 204
    .line 205
    invoke-static {v4, v5}, Ljava/lang/Math;->log(D)D

    .line 206
    .line 207
    .line 208
    move-result-wide v4

    .line 209
    sub-double v6, v14, v20

    .line 210
    .line 211
    div-double/2addr v4, v6

    .line 212
    invoke-static {v4, v5}, Ljava/lang/Double;->isNaN(D)Z

    .line 213
    .line 214
    .line 215
    move-result v6

    .line 216
    if-nez v6, :cond_8

    .line 217
    .line 218
    cmpg-double v6, v4, p0

    .line 219
    .line 220
    if-gtz v6, :cond_7

    .line 221
    .line 222
    goto :goto_3

    .line 223
    :cond_7
    cmpl-double v6, v4, p0

    .line 224
    .line 225
    if-lez v6, :cond_9

    .line 226
    .line 227
    mul-double v6, v20, v4

    .line 228
    .line 229
    invoke-static {v6, v7}, Ljava/lang/Math;->exp(D)D

    .line 230
    .line 231
    .line 232
    move-result-wide v6

    .line 233
    mul-double/2addr v6, v8

    .line 234
    mul-double/2addr v4, v14

    .line 235
    invoke-static {v4, v5}, Ljava/lang/Math;->exp(D)D

    .line 236
    .line 237
    .line 238
    move-result-wide v4

    .line 239
    mul-double/2addr v4, v0

    .line 240
    add-double/2addr v4, v6

    .line 241
    neg-double v4, v4

    .line 242
    cmpg-double v4, v4, v10

    .line 243
    .line 244
    if-gez v4, :cond_9

    .line 245
    .line 246
    cmpl-double v4, v0, p0

    .line 247
    .line 248
    if-lez v4, :cond_8

    .line 249
    .line 250
    cmpg-double v4, v8, p0

    .line 251
    .line 252
    if-gez v4, :cond_8

    .line 253
    .line 254
    move-wide/from16 v12, p0

    .line 255
    .line 256
    :cond_8
    :goto_3
    neg-double v10, v10

    .line 257
    goto :goto_4

    .line 258
    :cond_9
    mul-double v4, v0, v14

    .line 259
    .line 260
    mul-double/2addr v4, v14

    .line 261
    neg-double v4, v4

    .line 262
    mul-double v6, v2, v20

    .line 263
    .line 264
    div-double/2addr v4, v6

    .line 265
    invoke-static {v4, v5}, Ljava/lang/Math;->log(D)D

    .line 266
    .line 267
    .line 268
    move-result-wide v4

    .line 269
    div-double v12, v4, v16

    .line 270
    .line 271
    :goto_4
    mul-double v4, v20, v12

    .line 272
    .line 273
    invoke-static {v4, v5}, Ljava/lang/Math;->exp(D)D

    .line 274
    .line 275
    .line 276
    move-result-wide v4

    .line 277
    mul-double/2addr v4, v2

    .line 278
    mul-double v6, v0, v14

    .line 279
    .line 280
    mul-double v16, v14, v12

    .line 281
    .line 282
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->exp(D)D

    .line 283
    .line 284
    .line 285
    move-result-wide v16

    .line 286
    mul-double v16, v16, v6

    .line 287
    .line 288
    add-double v16, v16, v4

    .line 289
    .line 290
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->abs(D)D

    .line 291
    .line 292
    .line 293
    move-result-wide v4

    .line 294
    const-wide v16, 0x3f1a36e2eb1c432dL    # 1.0E-4

    .line 295
    .line 296
    .line 297
    .line 298
    .line 299
    cmpg-double v4, v4, v16

    .line 300
    .line 301
    if-gez v4, :cond_a

    .line 302
    .line 303
    goto/16 :goto_c

    .line 304
    .line 305
    :cond_a
    move/from16 v4, v30

    .line 306
    .line 307
    :goto_5
    cmpl-double v5, v24, v22

    .line 308
    .line 309
    if-lez v5, :cond_14

    .line 310
    .line 311
    const/16 v5, 0x64

    .line 312
    .line 313
    if-ge v4, v5, :cond_14

    .line 314
    .line 315
    add-int/lit8 v4, v4, 0x1

    .line 316
    .line 317
    mul-double v16, v20, v12

    .line 318
    .line 319
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->exp(D)D

    .line 320
    .line 321
    .line 322
    move-result-wide v18

    .line 323
    mul-double v18, v18, v8

    .line 324
    .line 325
    mul-double v24, v14, v12

    .line 326
    .line 327
    invoke-static/range {v24 .. v25}, Ljava/lang/Math;->exp(D)D

    .line 328
    .line 329
    .line 330
    move-result-wide v26

    .line 331
    mul-double v26, v26, v0

    .line 332
    .line 333
    add-double v26, v26, v18

    .line 334
    .line 335
    add-double v26, v26, v10

    .line 336
    .line 337
    invoke-static/range {v16 .. v17}, Ljava/lang/Math;->exp(D)D

    .line 338
    .line 339
    .line 340
    move-result-wide v16

    .line 341
    mul-double v16, v16, v2

    .line 342
    .line 343
    invoke-static/range {v24 .. v25}, Ljava/lang/Math;->exp(D)D

    .line 344
    .line 345
    .line 346
    move-result-wide v18

    .line 347
    mul-double v18, v18, v6

    .line 348
    .line 349
    add-double v18, v18, v16

    .line 350
    .line 351
    div-double v26, v26, v18

    .line 352
    .line 353
    sub-double v16, v12, v26

    .line 354
    .line 355
    sub-double v12, v12, v16

    .line 356
    .line 357
    invoke-static {v12, v13}, Ljava/lang/Math;->abs(D)D

    .line 358
    .line 359
    .line 360
    move-result-wide v24

    .line 361
    move-wide/from16 v12, v16

    .line 362
    .line 363
    goto :goto_5

    .line 364
    :cond_b
    move-wide/from16 p0, v3

    .line 365
    .line 366
    cmpg-double v0, v1, v18

    .line 367
    .line 368
    if-gez v0, :cond_c

    .line 369
    .line 370
    mul-double v0, v20, v8

    .line 371
    .line 372
    sub-double/2addr v6, v0

    .line 373
    div-double v6, v6, v16

    .line 374
    .line 375
    mul-double/2addr v8, v8

    .line 376
    mul-double/2addr v6, v6

    .line 377
    add-double/2addr v6, v8

    .line 378
    invoke-static {v6, v7}, Ljava/lang/Math;->sqrt(D)D

    .line 379
    .line 380
    .line 381
    move-result-wide v0

    .line 382
    div-double/2addr v10, v0

    .line 383
    invoke-static {v10, v11}, Ljava/lang/Math;->log(D)D

    .line 384
    .line 385
    .line 386
    move-result-wide v0

    .line 387
    div-double v12, v0, v20

    .line 388
    .line 389
    goto/16 :goto_c

    .line 390
    .line 391
    :cond_c
    mul-double v0, v20, v8

    .line 392
    .line 393
    sub-double/2addr v6, v0

    .line 394
    div-double v2, v10, v8

    .line 395
    .line 396
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(D)D

    .line 397
    .line 398
    .line 399
    move-result-wide v2

    .line 400
    invoke-static {v2, v3}, Ljava/lang/Math;->log(D)D

    .line 401
    .line 402
    .line 403
    move-result-wide v2

    .line 404
    div-double v2, v2, v20

    .line 405
    .line 406
    div-double v4, v10, v6

    .line 407
    .line 408
    invoke-static {v4, v5}, Ljava/lang/Math;->abs(D)D

    .line 409
    .line 410
    .line 411
    move-result-wide v4

    .line 412
    invoke-static {v4, v5}, Ljava/lang/Math;->log(D)D

    .line 413
    .line 414
    .line 415
    move-result-wide v4

    .line 416
    move-wide v15, v4

    .line 417
    move-wide/from16 v17, v12

    .line 418
    .line 419
    move/from16 v14, v30

    .line 420
    .line 421
    :goto_6
    const/4 v12, 0x6

    .line 422
    if-ge v14, v12, :cond_d

    .line 423
    .line 424
    div-double v15, v15, v20

    .line 425
    .line 426
    invoke-static/range {v15 .. v16}, Ljava/lang/Math;->abs(D)D

    .line 427
    .line 428
    .line 429
    move-result-wide v12

    .line 430
    invoke-static {v12, v13}, Ljava/lang/Math;->log(D)D

    .line 431
    .line 432
    .line 433
    move-result-wide v12

    .line 434
    sub-double v15, v4, v12

    .line 435
    .line 436
    add-int/lit8 v14, v14, 0x1

    .line 437
    .line 438
    goto :goto_6

    .line 439
    :cond_d
    div-double v4, v15, v20

    .line 440
    .line 441
    invoke-static {v2, v3}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 442
    .line 443
    .line 444
    move-result-wide v12

    .line 445
    and-long v12, v12, v28

    .line 446
    .line 447
    cmp-long v12, v12, v26

    .line 448
    .line 449
    if-gez v12, :cond_e

    .line 450
    .line 451
    invoke-static {v4, v5}, Ljava/lang/Double;->doubleToRawLongBits(D)J

    .line 452
    .line 453
    .line 454
    move-result-wide v12

    .line 455
    and-long v12, v12, v28

    .line 456
    .line 457
    cmp-long v12, v12, v26

    .line 458
    .line 459
    if-gez v12, :cond_f

    .line 460
    .line 461
    invoke-static {v2, v3, v4, v5}, Ljava/lang/Math;->max(DD)D

    .line 462
    .line 463
    .line 464
    move-result-wide v2

    .line 465
    goto :goto_7

    .line 466
    :cond_e
    move-wide v2, v4

    .line 467
    :cond_f
    :goto_7
    add-double v4, v0, v6

    .line 468
    .line 469
    neg-double v4, v4

    .line 470
    mul-double v12, v20, v6

    .line 471
    .line 472
    div-double/2addr v4, v12

    .line 473
    mul-double v12, v20, v4

    .line 474
    .line 475
    invoke-static {v12, v13}, Ljava/lang/Math;->exp(D)D

    .line 476
    .line 477
    .line 478
    move-result-wide v14

    .line 479
    mul-double/2addr v14, v8

    .line 480
    mul-double v26, v6, v4

    .line 481
    .line 482
    invoke-static {v12, v13}, Ljava/lang/Math;->exp(D)D

    .line 483
    .line 484
    .line 485
    move-result-wide v12

    .line 486
    mul-double v12, v12, v26

    .line 487
    .line 488
    add-double/2addr v12, v14

    .line 489
    invoke-static {v4, v5}, Ljava/lang/Double;->isNaN(D)Z

    .line 490
    .line 491
    .line 492
    move-result v14

    .line 493
    if-nez v14, :cond_13

    .line 494
    .line 495
    cmpg-double v14, v4, p0

    .line 496
    .line 497
    if-gtz v14, :cond_10

    .line 498
    .line 499
    goto :goto_9

    .line 500
    :cond_10
    cmpl-double v4, v4, p0

    .line 501
    .line 502
    if-lez v4, :cond_12

    .line 503
    .line 504
    neg-double v4, v12

    .line 505
    cmpg-double v4, v4, v10

    .line 506
    .line 507
    if-gez v4, :cond_12

    .line 508
    .line 509
    cmpg-double v4, v6, p0

    .line 510
    .line 511
    if-gez v4, :cond_11

    .line 512
    .line 513
    cmpl-double v4, v8, p0

    .line 514
    .line 515
    if-lez v4, :cond_11

    .line 516
    .line 517
    move-wide/from16 v3, p0

    .line 518
    .line 519
    goto :goto_8

    .line 520
    :cond_11
    move-wide v3, v2

    .line 521
    :goto_8
    neg-double v10, v10

    .line 522
    move-wide v2, v3

    .line 523
    goto :goto_a

    .line 524
    :cond_12
    div-double v12, v17, v20

    .line 525
    .line 526
    neg-double v2, v12

    .line 527
    div-double v4, v8, v6

    .line 528
    .line 529
    sub-double/2addr v2, v4

    .line 530
    goto :goto_a

    .line 531
    :cond_13
    :goto_9
    neg-double v10, v10

    .line 532
    :goto_a
    move-wide v12, v2

    .line 533
    move/from16 v2, v30

    .line 534
    .line 535
    :goto_b
    cmpl-double v3, v24, v22

    .line 536
    .line 537
    if-lez v3, :cond_14

    .line 538
    .line 539
    const/16 v5, 0x64

    .line 540
    .line 541
    if-ge v2, v5, :cond_14

    .line 542
    .line 543
    add-int/lit8 v2, v2, 0x1

    .line 544
    .line 545
    mul-double v3, v6, v12

    .line 546
    .line 547
    add-double/2addr v3, v8

    .line 548
    mul-double v14, v20, v12

    .line 549
    .line 550
    invoke-static {v14, v15}, Ljava/lang/Math;->exp(D)D

    .line 551
    .line 552
    .line 553
    move-result-wide v16

    .line 554
    mul-double v16, v16, v3

    .line 555
    .line 556
    add-double v16, v16, v10

    .line 557
    .line 558
    const/4 v3, 0x1

    .line 559
    int-to-double v3, v3

    .line 560
    add-double/2addr v3, v14

    .line 561
    mul-double/2addr v3, v6

    .line 562
    add-double/2addr v3, v0

    .line 563
    invoke-static {v14, v15}, Ljava/lang/Math;->exp(D)D

    .line 564
    .line 565
    .line 566
    move-result-wide v14

    .line 567
    mul-double/2addr v14, v3

    .line 568
    div-double v16, v16, v14

    .line 569
    .line 570
    sub-double v3, v12, v16

    .line 571
    .line 572
    sub-double/2addr v12, v3

    .line 573
    invoke-static {v12, v13}, Ljava/lang/Math;->abs(D)D

    .line 574
    .line 575
    .line 576
    move-result-wide v24

    .line 577
    move-wide v12, v3

    .line 578
    goto :goto_b

    .line 579
    :cond_14
    :goto_c
    const-wide v0, 0x408f400000000000L    # 1000.0

    .line 580
    .line 581
    .line 582
    .line 583
    .line 584
    mul-double/2addr v12, v0

    .line 585
    double-to-long v0, v12

    .line 586
    :goto_d
    const-wide/32 v2, 0xf4240

    .line 587
    .line 588
    .line 589
    mul-long/2addr v0, v2

    .line 590
    return-wide v0
.end method
