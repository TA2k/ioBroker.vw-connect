.class public final Lxf0/g3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lvf0/j;

.field public final synthetic e:J

.field public final synthetic f:J

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:J


# direct methods
.method public constructor <init>(Lvf0/j;JJJJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lxf0/g3;->d:Lvf0/j;

    .line 5
    .line 6
    iput-wide p2, p0, Lxf0/g3;->e:J

    .line 7
    .line 8
    iput-wide p4, p0, Lxf0/g3;->f:J

    .line 9
    .line 10
    iput-wide p6, p0, Lxf0/g3;->g:J

    .line 11
    .line 12
    iput-wide p8, p0, Lxf0/g3;->h:J

    .line 13
    .line 14
    iput-wide p10, p0, Lxf0/g3;->i:J

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 33

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
    const-string v2, "$this$Canvas"

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
    sget v2, Lxf0/e3;->c:F

    .line 21
    .line 22
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    iget-object v2, v0, Lxf0/g3;->d:Lvf0/j;

    .line 27
    .line 28
    iget-boolean v14, v2, Lvf0/j;->h:Z

    .line 29
    .line 30
    new-instance v15, Lxf0/z;

    .line 31
    .line 32
    iget-wide v5, v0, Lxf0/g3;->i:J

    .line 33
    .line 34
    invoke-direct {v15, v2, v13, v5, v6}, Lxf0/z;-><init>(Lvf0/j;FJ)V

    .line 35
    .line 36
    .line 37
    invoke-interface {v1}, Lg3/d;->e()J

    .line 38
    .line 39
    .line 40
    move-result-wide v2

    .line 41
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    const/4 v3, 0x2

    .line 46
    int-to-float v10, v3

    .line 47
    mul-float v3, v4, v10

    .line 48
    .line 49
    const/4 v5, 0x3

    .line 50
    int-to-float v11, v5

    .line 51
    div-float/2addr v3, v11

    .line 52
    sub-float v16, v2, v3

    .line 53
    .line 54
    invoke-interface {v1}, Lg3/d;->e()J

    .line 55
    .line 56
    .line 57
    move-result-wide v2

    .line 58
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    sub-float v2, v2, v16

    .line 63
    .line 64
    div-float v17, v2, v10

    .line 65
    .line 66
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 67
    .line 68
    .line 69
    move-result v2

    .line 70
    int-to-long v2, v2

    .line 71
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 72
    .line 73
    .line 74
    move-result v5

    .line 75
    int-to-long v5, v5

    .line 76
    const/16 v18, 0x20

    .line 77
    .line 78
    shl-long v2, v2, v18

    .line 79
    .line 80
    const-wide v19, 0xffffffffL

    .line 81
    .line 82
    .line 83
    .line 84
    .line 85
    and-long v5, v5, v19

    .line 86
    .line 87
    or-long v21, v2, v5

    .line 88
    .line 89
    new-instance v3, Lg3/h;

    .line 90
    .line 91
    const/4 v8, 0x0

    .line 92
    const/16 v9, 0x1a

    .line 93
    .line 94
    const/4 v5, 0x0

    .line 95
    const/4 v6, 0x0

    .line 96
    const/4 v7, 0x0

    .line 97
    invoke-direct/range {v3 .. v9}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 98
    .line 99
    .line 100
    move/from16 v23, v4

    .line 101
    .line 102
    move v2, v10

    .line 103
    const/4 v10, 0x0

    .line 104
    const/16 v12, 0x350

    .line 105
    .line 106
    move v4, v2

    .line 107
    move v5, v11

    .line 108
    move-object v11, v3

    .line 109
    iget-wide v2, v0, Lxf0/g3;->e:J

    .line 110
    .line 111
    move v6, v4

    .line 112
    const/high16 v4, 0x42f00000    # 120.0f

    .line 113
    .line 114
    move v7, v5

    .line 115
    const/high16 v5, 0x43960000    # 300.0f

    .line 116
    .line 117
    move v8, v6

    .line 118
    move v9, v7

    .line 119
    const-wide/16 v6, 0x0

    .line 120
    .line 121
    move-wide/from16 v31, v21

    .line 122
    .line 123
    move/from16 v21, v8

    .line 124
    .line 125
    move/from16 v22, v9

    .line 126
    .line 127
    move-wide/from16 v8, v31

    .line 128
    .line 129
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v15, v1}, Lxf0/z;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 136
    .line 137
    .line 138
    move-result v2

    .line 139
    int-to-long v2, v2

    .line 140
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 141
    .line 142
    .line 143
    move-result v4

    .line 144
    int-to-long v4, v4

    .line 145
    shl-long v2, v2, v18

    .line 146
    .line 147
    and-long v4, v4, v19

    .line 148
    .line 149
    or-long v6, v2, v4

    .line 150
    .line 151
    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    int-to-long v2, v2

    .line 156
    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 157
    .line 158
    .line 159
    move-result v4

    .line 160
    int-to-long v4, v4

    .line 161
    shl-long v2, v2, v18

    .line 162
    .line 163
    and-long v4, v4, v19

    .line 164
    .line 165
    or-long v8, v2, v4

    .line 166
    .line 167
    new-instance v24, Lg3/h;

    .line 168
    .line 169
    const/4 v15, 0x1

    .line 170
    int-to-float v2, v15

    .line 171
    mul-float v4, v23, v2

    .line 172
    .line 173
    div-float v25, v4, v22

    .line 174
    .line 175
    const/16 v29, 0x0

    .line 176
    .line 177
    const/16 v30, 0x1a

    .line 178
    .line 179
    const/16 v26, 0x0

    .line 180
    .line 181
    const/16 v27, 0x0

    .line 182
    .line 183
    const/16 v28, 0x0

    .line 184
    .line 185
    invoke-direct/range {v24 .. v30}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 186
    .line 187
    .line 188
    const/16 v12, 0x340

    .line 189
    .line 190
    iget-wide v2, v0, Lxf0/g3;->f:J

    .line 191
    .line 192
    const/high16 v4, 0x42f00000    # 120.0f

    .line 193
    .line 194
    const/high16 v5, 0x43960000    # 300.0f

    .line 195
    .line 196
    move-object/from16 v11, v24

    .line 197
    .line 198
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 199
    .line 200
    .line 201
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    int-to-long v2, v2

    .line 206
    invoke-static {v13}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 207
    .line 208
    .line 209
    move-result v4

    .line 210
    int-to-long v4, v4

    .line 211
    shl-long v2, v2, v18

    .line 212
    .line 213
    and-long v4, v4, v19

    .line 214
    .line 215
    or-long v10, v2, v4

    .line 216
    .line 217
    new-instance v3, Lg3/h;

    .line 218
    .line 219
    const/4 v8, 0x0

    .line 220
    const/16 v9, 0x1a

    .line 221
    .line 222
    const/4 v5, 0x0

    .line 223
    const/4 v6, 0x0

    .line 224
    const/4 v7, 0x0

    .line 225
    move/from16 v4, v23

    .line 226
    .line 227
    invoke-direct/range {v3 .. v9}, Lg3/h;-><init>(FFIILe3/j;I)V

    .line 228
    .line 229
    .line 230
    move-wide v8, v10

    .line 231
    const/4 v10, 0x0

    .line 232
    const/16 v12, 0x350

    .line 233
    .line 234
    move-object v11, v3

    .line 235
    iget-wide v2, v0, Lxf0/g3;->g:J

    .line 236
    .line 237
    const/high16 v4, 0x42f00000    # 120.0f

    .line 238
    .line 239
    const/high16 v5, -0x3d900000    # -60.0f

    .line 240
    .line 241
    const-wide/16 v6, 0x0

    .line 242
    .line 243
    invoke-static/range {v1 .. v12}, Lg3/d;->o(Lg3/d;JFFJJFLg3/e;I)V

    .line 244
    .line 245
    .line 246
    if-nez v14, :cond_0

    .line 247
    .line 248
    sget v2, Lxf0/d3;->a:F

    .line 249
    .line 250
    invoke-interface {v1, v2}, Lt4/c;->w0(F)F

    .line 251
    .line 252
    .line 253
    move-result v12

    .line 254
    invoke-interface {v1}, Lg3/d;->e()J

    .line 255
    .line 256
    .line 257
    move-result-wide v2

    .line 258
    invoke-static {v2, v3}, Ld3/e;->c(J)F

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    const/high16 v3, 0x40000000    # 2.0f

    .line 263
    .line 264
    div-float v13, v2, v3

    .line 265
    .line 266
    :goto_0
    const/16 v2, 0x1e

    .line 267
    .line 268
    mul-int v3, v2, v15

    .line 269
    .line 270
    add-int/2addr v3, v2

    .line 271
    int-to-double v2, v3

    .line 272
    neg-double v2, v2

    .line 273
    invoke-static {v2, v3}, Ljava/lang/Math;->toRadians(D)D

    .line 274
    .line 275
    .line 276
    move-result-wide v2

    .line 277
    invoke-interface {v1}, Lg3/d;->e()J

    .line 278
    .line 279
    .line 280
    move-result-wide v4

    .line 281
    invoke-static {v4, v5}, Ljp/ef;->d(J)J

    .line 282
    .line 283
    .line 284
    move-result-wide v4

    .line 285
    shr-long v4, v4, v18

    .line 286
    .line 287
    long-to-int v4, v4

    .line 288
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 289
    .line 290
    .line 291
    move-result v4

    .line 292
    const/4 v5, 0x6

    .line 293
    int-to-float v5, v5

    .line 294
    div-float v8, v12, v5

    .line 295
    .line 296
    sub-float v5, v13, v8

    .line 297
    .line 298
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 299
    .line 300
    .line 301
    move-result-wide v6

    .line 302
    double-to-float v6, v6

    .line 303
    mul-float/2addr v6, v5

    .line 304
    add-float/2addr v6, v4

    .line 305
    invoke-interface {v1}, Lg3/d;->e()J

    .line 306
    .line 307
    .line 308
    move-result-wide v9

    .line 309
    invoke-static {v9, v10}, Ljp/ef;->d(J)J

    .line 310
    .line 311
    .line 312
    move-result-wide v9

    .line 313
    and-long v9, v9, v19

    .line 314
    .line 315
    long-to-int v4, v9

    .line 316
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 317
    .line 318
    .line 319
    move-result v4

    .line 320
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 321
    .line 322
    .line 323
    move-result-wide v9

    .line 324
    double-to-float v7, v9

    .line 325
    mul-float/2addr v5, v7

    .line 326
    add-float/2addr v5, v4

    .line 327
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 328
    .line 329
    .line 330
    move-result v4

    .line 331
    int-to-long v6, v4

    .line 332
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 333
    .line 334
    .line 335
    move-result v4

    .line 336
    int-to-long v4, v4

    .line 337
    shl-long v6, v6, v18

    .line 338
    .line 339
    and-long v4, v4, v19

    .line 340
    .line 341
    or-long/2addr v4, v6

    .line 342
    invoke-interface {v1}, Lg3/d;->e()J

    .line 343
    .line 344
    .line 345
    move-result-wide v6

    .line 346
    invoke-static {v6, v7}, Ljp/ef;->d(J)J

    .line 347
    .line 348
    .line 349
    move-result-wide v6

    .line 350
    shr-long v6, v6, v18

    .line 351
    .line 352
    long-to-int v6, v6

    .line 353
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 354
    .line 355
    .line 356
    move-result v6

    .line 357
    div-float v7, v12, v21

    .line 358
    .line 359
    sub-float v7, v13, v7

    .line 360
    .line 361
    invoke-static {v2, v3}, Ljava/lang/Math;->sin(D)D

    .line 362
    .line 363
    .line 364
    move-result-wide v9

    .line 365
    double-to-float v9, v9

    .line 366
    mul-float/2addr v9, v7

    .line 367
    add-float/2addr v9, v6

    .line 368
    invoke-interface {v1}, Lg3/d;->e()J

    .line 369
    .line 370
    .line 371
    move-result-wide v10

    .line 372
    invoke-static {v10, v11}, Ljp/ef;->d(J)J

    .line 373
    .line 374
    .line 375
    move-result-wide v10

    .line 376
    and-long v10, v10, v19

    .line 377
    .line 378
    long-to-int v6, v10

    .line 379
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 380
    .line 381
    .line 382
    move-result v6

    .line 383
    invoke-static {v2, v3}, Ljava/lang/Math;->cos(D)D

    .line 384
    .line 385
    .line 386
    move-result-wide v2

    .line 387
    double-to-float v2, v2

    .line 388
    mul-float/2addr v7, v2

    .line 389
    add-float/2addr v7, v6

    .line 390
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 391
    .line 392
    .line 393
    move-result v2

    .line 394
    int-to-long v2, v2

    .line 395
    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 396
    .line 397
    .line 398
    move-result v6

    .line 399
    int-to-long v6, v6

    .line 400
    shl-long v2, v2, v18

    .line 401
    .line 402
    and-long v6, v6, v19

    .line 403
    .line 404
    or-long/2addr v6, v2

    .line 405
    const/4 v10, 0x0

    .line 406
    const/16 v11, 0x1f0

    .line 407
    .line 408
    iget-wide v2, v0, Lxf0/g3;->h:J

    .line 409
    .line 410
    const/4 v9, 0x0

    .line 411
    invoke-static/range {v1 .. v11}, Lg3/d;->q(Lg3/d;JJJFILe3/j;I)V

    .line 412
    .line 413
    .line 414
    const/16 v2, 0x9

    .line 415
    .line 416
    if-eq v15, v2, :cond_0

    .line 417
    .line 418
    add-int/lit8 v15, v15, 0x1

    .line 419
    .line 420
    goto/16 :goto_0

    .line 421
    .line 422
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 423
    .line 424
    return-object v0
.end method
