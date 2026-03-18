.class public final synthetic Lxf0/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lg3/h;

.field public final synthetic e:Lxf0/w0;

.field public final synthetic f:I

.field public final synthetic g:Z

.field public final synthetic h:Lc1/c;


# direct methods
.method public synthetic constructor <init>(Lg3/h;Lxf0/w0;IZLc1/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/c1;->d:Lg3/h;

    .line 5
    .line 6
    iput-object p2, p0, Lxf0/c1;->e:Lxf0/w0;

    .line 7
    .line 8
    iput p3, p0, Lxf0/c1;->f:I

    .line 9
    .line 10
    iput-boolean p4, p0, Lxf0/c1;->g:Z

    .line 11
    .line 12
    iput-object p5, p0, Lxf0/c1;->h:Lc1/c;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Lg3/d;

    .line 6
    .line 7
    const-string v2, "$this$drawBehind"

    .line 8
    .line 9
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1}, Lg3/d;->e()J

    .line 13
    .line 14
    .line 15
    move-result-wide v2

    .line 16
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 17
    .line 18
    .line 19
    move-result v13

    .line 20
    sget v2, Lxf0/x0;->c:F

    .line 21
    .line 22
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 23
    .line 24
    .line 25
    move-result v14

    .line 26
    iget-object v11, v0, Lxf0/c1;->d:Lg3/h;

    .line 27
    .line 28
    iget-object v15, v0, Lxf0/c1;->e:Lxf0/w0;

    .line 29
    .line 30
    const-wide v16, 0xffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    const/16 v18, 0x20

    .line 36
    .line 37
    const/4 v2, 0x2

    .line 38
    if-eqz v11, :cond_0

    .line 39
    .line 40
    iget-wide v3, v15, Lxf0/w0;->d:J

    .line 41
    .line 42
    const v5, 0x3f4ccccd    # 0.8f

    .line 43
    .line 44
    .line 45
    invoke-static {v3, v4, v5}, Le3/s;->b(JF)J

    .line 46
    .line 47
    .line 48
    move-result-wide v3

    .line 49
    neg-float v5, v14

    .line 50
    int-to-float v6, v2

    .line 51
    div-float/2addr v5, v6

    .line 52
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    int-to-long v6, v6

    .line 57
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    int-to-long v8, v5

    .line 62
    shl-long v5, v6, v18

    .line 63
    .line 64
    and-long v7, v8, v16

    .line 65
    .line 66
    or-long v6, v5, v7

    .line 67
    .line 68
    add-float v5, v13, v14

    .line 69
    .line 70
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 71
    .line 72
    .line 73
    move-result v8

    .line 74
    int-to-long v8, v8

    .line 75
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    move-wide/from16 v19, v3

    .line 80
    .line 81
    int-to-long v2, v5

    .line 82
    shl-long v4, v8, v18

    .line 83
    .line 84
    and-long v2, v2, v16

    .line 85
    .line 86
    or-long v8, v4, v2

    .line 87
    .line 88
    const/4 v10, 0x0

    .line 89
    const/16 v12, 0x340

    .line 90
    .line 91
    const/high16 v4, 0x42fc0000    # 126.0f

    .line 92
    .line 93
    const/high16 v5, 0x43900000    # 288.0f

    .line 94
    .line 95
    move/from16 v21, v13

    .line 96
    .line 97
    move-wide/from16 v2, v19

    .line 98
    .line 99
    const/4 v13, 0x2

    .line 100
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 101
    .line 102
    .line 103
    goto :goto_0

    .line 104
    :cond_0
    move/from16 v21, v13

    .line 105
    .line 106
    move v13, v2

    .line 107
    :goto_0
    new-instance v4, Lxf0/d1;

    .line 108
    .line 109
    iget-boolean v5, v0, Lxf0/c1;->g:Z

    .line 110
    .line 111
    iget-object v6, v0, Lxf0/c1;->h:Lc1/c;

    .line 112
    .line 113
    iget v10, v0, Lxf0/c1;->f:I

    .line 114
    .line 115
    move v8, v14

    .line 116
    move-object v9, v15

    .line 117
    move/from16 v7, v21

    .line 118
    .line 119
    invoke-direct/range {v4 .. v10}, Lxf0/d1;-><init>(ZLc1/c;FFLxf0/w0;I)V

    .line 120
    .line 121
    .line 122
    move-object v12, v4

    .line 123
    move v4, v8

    .line 124
    move-object v14, v9

    .line 125
    move v15, v10

    .line 126
    int-to-float v13, v13

    .line 127
    mul-float v0, v4, v13

    .line 128
    .line 129
    const/4 v2, 0x3

    .line 130
    int-to-float v2, v2

    .line 131
    div-float/2addr v0, v2

    .line 132
    sub-float v19, v21, v0

    .line 133
    .line 134
    invoke-interface {v1}, Lg3/d;->e()J

    .line 135
    .line 136
    .line 137
    move-result-wide v5

    .line 138
    invoke-static {v5, v6}, Ld3/e;->c(J)F

    .line 139
    .line 140
    .line 141
    move-result v0

    .line 142
    sub-float v0, v0, v19

    .line 143
    .line 144
    div-float v20, v0, v13

    .line 145
    .line 146
    invoke-static/range {v21 .. v21}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    int-to-long v5, v0

    .line 151
    invoke-static/range {v21 .. v21}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    int-to-long v7, v0

    .line 156
    shl-long v5, v5, v18

    .line 157
    .line 158
    and-long v7, v7, v16

    .line 159
    .line 160
    or-long v10, v5, v7

    .line 161
    .line 162
    move-object v0, v1

    .line 163
    move/from16 v22, v2

    .line 164
    .line 165
    iget-wide v1, v14, Lxf0/w0;->a:J

    .line 166
    .line 167
    new-instance v3, Lg3/h;

    .line 168
    .line 169
    const/4 v8, 0x0

    .line 170
    const/16 v9, 0x1e

    .line 171
    .line 172
    const/4 v5, 0x0

    .line 173
    const/4 v6, 0x0

    .line 174
    const/4 v7, 0x0

    .line 175
    invoke-direct/range {v3 .. v9}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 176
    .line 177
    .line 178
    move/from16 v23, v4

    .line 179
    .line 180
    const/4 v9, 0x0

    .line 181
    move-wide v7, v10

    .line 182
    const/16 v11, 0x350

    .line 183
    .line 184
    move-object v10, v3

    .line 185
    const/high16 v3, 0x42fc0000    # 126.0f

    .line 186
    .line 187
    const/high16 v4, 0x43900000    # 288.0f

    .line 188
    .line 189
    const-wide/16 v5, 0x0

    .line 190
    .line 191
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v12, v0}, Lxf0/d1;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    invoke-static/range {v20 .. v20}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 198
    .line 199
    .line 200
    move-result v1

    .line 201
    int-to-long v1, v1

    .line 202
    invoke-static/range {v20 .. v20}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 203
    .line 204
    .line 205
    move-result v3

    .line 206
    int-to-long v3, v3

    .line 207
    shl-long v1, v1, v18

    .line 208
    .line 209
    and-long v3, v3, v16

    .line 210
    .line 211
    or-long v5, v1, v3

    .line 212
    .line 213
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    int-to-long v1, v1

    .line 218
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 219
    .line 220
    .line 221
    move-result v3

    .line 222
    int-to-long v3, v3

    .line 223
    shl-long v1, v1, v18

    .line 224
    .line 225
    and-long v3, v3, v16

    .line 226
    .line 227
    or-long v7, v1, v3

    .line 228
    .line 229
    iget-wide v1, v14, Lxf0/w0;->b:J

    .line 230
    .line 231
    new-instance v24, Lg3/h;

    .line 232
    .line 233
    const/4 v12, 0x1

    .line 234
    int-to-float v3, v12

    .line 235
    mul-float v3, v3, v23

    .line 236
    .line 237
    div-float v25, v3, v22

    .line 238
    .line 239
    const/16 v29, 0x0

    .line 240
    .line 241
    const/16 v30, 0x1e

    .line 242
    .line 243
    const/16 v26, 0x0

    .line 244
    .line 245
    const/16 v27, 0x0

    .line 246
    .line 247
    const/16 v28, 0x0

    .line 248
    .line 249
    invoke-direct/range {v24 .. v30}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 250
    .line 251
    .line 252
    const/16 v11, 0x340

    .line 253
    .line 254
    const/high16 v3, 0x42fc0000    # 126.0f

    .line 255
    .line 256
    const/high16 v4, 0x43900000    # 288.0f

    .line 257
    .line 258
    move-object/from16 v10, v24

    .line 259
    .line 260
    invoke-static/range {v0 .. v11}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 261
    .line 262
    .line 263
    const/high16 v1, 0x40000000    # 2.0f

    .line 264
    .line 265
    div-float v11, v21, v1

    .line 266
    .line 267
    iget-wide v1, v14, Lxf0/w0;->c:J

    .line 268
    .line 269
    sget v3, Lxf0/y0;->a:F

    .line 270
    .line 271
    invoke-interface {v0, v3}, Lt4/c;->w0(F)F

    .line 272
    .line 273
    .line 274
    move-result v7

    .line 275
    :goto_1
    if-ge v12, v15, :cond_1

    .line 276
    .line 277
    const/high16 v3, -0x3df00000    # -36.0f

    .line 278
    .line 279
    float-to-double v3, v3

    .line 280
    int-to-double v5, v12

    .line 281
    const/high16 v8, 0x43900000    # 288.0f

    .line 282
    .line 283
    int-to-float v9, v15

    .line 284
    div-float/2addr v8, v9

    .line 285
    float-to-double v8, v8

    .line 286
    mul-double/2addr v5, v8

    .line 287
    sub-double/2addr v3, v5

    .line 288
    invoke-static {v3, v4}, Ljava/lang/Math;->toRadians(D)D

    .line 289
    .line 290
    .line 291
    move-result-wide v3

    .line 292
    invoke-interface {v0}, Lg3/d;->e()J

    .line 293
    .line 294
    .line 295
    move-result-wide v5

    .line 296
    invoke-static {v5, v6}, Ljp/ef;->d(J)J

    .line 297
    .line 298
    .line 299
    move-result-wide v5

    .line 300
    shr-long v5, v5, v18

    .line 301
    .line 302
    long-to-int v5, v5

    .line 303
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 304
    .line 305
    .line 306
    move-result v5

    .line 307
    const/4 v6, 0x6

    .line 308
    int-to-float v6, v6

    .line 309
    div-float v14, v23, v6

    .line 310
    .line 311
    sub-float v6, v11, v14

    .line 312
    .line 313
    invoke-static {v3, v4}, Ljava/lang/Math;->sin(D)D

    .line 314
    .line 315
    .line 316
    move-result-wide v8

    .line 317
    double-to-float v8, v8

    .line 318
    mul-float/2addr v8, v6

    .line 319
    add-float/2addr v8, v5

    .line 320
    invoke-interface {v0}, Lg3/d;->e()J

    .line 321
    .line 322
    .line 323
    move-result-wide v9

    .line 324
    invoke-static {v9, v10}, Ljp/ef;->d(J)J

    .line 325
    .line 326
    .line 327
    move-result-wide v9

    .line 328
    and-long v9, v9, v16

    .line 329
    .line 330
    long-to-int v5, v9

    .line 331
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 332
    .line 333
    .line 334
    move-result v5

    .line 335
    invoke-static {v3, v4}, Ljava/lang/Math;->cos(D)D

    .line 336
    .line 337
    .line 338
    move-result-wide v9

    .line 339
    double-to-float v9, v9

    .line 340
    mul-float/2addr v6, v9

    .line 341
    add-float/2addr v6, v5

    .line 342
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 343
    .line 344
    .line 345
    move-result v5

    .line 346
    int-to-long v8, v5

    .line 347
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 348
    .line 349
    .line 350
    move-result v5

    .line 351
    int-to-long v5, v5

    .line 352
    shl-long v8, v8, v18

    .line 353
    .line 354
    and-long v5, v5, v16

    .line 355
    .line 356
    or-long/2addr v5, v8

    .line 357
    invoke-interface {v0}, Lg3/d;->e()J

    .line 358
    .line 359
    .line 360
    move-result-wide v8

    .line 361
    invoke-static {v8, v9}, Ljp/ef;->d(J)J

    .line 362
    .line 363
    .line 364
    move-result-wide v8

    .line 365
    shr-long v8, v8, v18

    .line 366
    .line 367
    long-to-int v8, v8

    .line 368
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 369
    .line 370
    .line 371
    move-result v8

    .line 372
    div-float v14, v23, v13

    .line 373
    .line 374
    sub-float v9, v11, v14

    .line 375
    .line 376
    move-object v10, v0

    .line 377
    move-wide/from16 v19, v1

    .line 378
    .line 379
    invoke-static {v3, v4}, Ljava/lang/Math;->sin(D)D

    .line 380
    .line 381
    .line 382
    move-result-wide v0

    .line 383
    double-to-float v0, v0

    .line 384
    mul-float/2addr v0, v9

    .line 385
    add-float/2addr v0, v8

    .line 386
    invoke-interface {v10}, Lg3/d;->e()J

    .line 387
    .line 388
    .line 389
    move-result-wide v1

    .line 390
    invoke-static {v1, v2}, Ljp/ef;->d(J)J

    .line 391
    .line 392
    .line 393
    move-result-wide v1

    .line 394
    and-long v1, v1, v16

    .line 395
    .line 396
    long-to-int v1, v1

    .line 397
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 398
    .line 399
    .line 400
    move-result v1

    .line 401
    invoke-static {v3, v4}, Ljava/lang/Math;->cos(D)D

    .line 402
    .line 403
    .line 404
    move-result-wide v2

    .line 405
    double-to-float v2, v2

    .line 406
    mul-float/2addr v9, v2

    .line 407
    add-float/2addr v9, v1

    .line 408
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 409
    .line 410
    .line 411
    move-result v0

    .line 412
    int-to-long v0, v0

    .line 413
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 414
    .line 415
    .line 416
    move-result v2

    .line 417
    int-to-long v2, v2

    .line 418
    shl-long v0, v0, v18

    .line 419
    .line 420
    and-long v2, v2, v16

    .line 421
    .line 422
    or-long/2addr v0, v2

    .line 423
    const/4 v9, 0x0

    .line 424
    move-wide v3, v5

    .line 425
    move-wide v5, v0

    .line 426
    move-object v0, v10

    .line 427
    const/16 v10, 0x1f0

    .line 428
    .line 429
    const/4 v8, 0x0

    .line 430
    move-wide/from16 v1, v19

    .line 431
    .line 432
    invoke-static/range {v0 .. v10}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 433
    .line 434
    .line 435
    add-int/lit8 v12, v12, 0x1

    .line 436
    .line 437
    goto/16 :goto_1

    .line 438
    .line 439
    :cond_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 440
    .line 441
    return-object v0
.end method
