.class public final Lj3/e0;
.super Lj3/c0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Lj3/c;

.field public c:Ljava/lang/String;

.field public d:Z

.field public final e:Lj3/a;

.field public f:Lkotlin/jvm/internal/n;

.field public final g:Ll2/j1;

.field public h:Le3/m;

.field public final i:Ll2/j1;

.field public j:J

.field public k:F

.field public l:F

.field public final m:Lj3/d0;


# direct methods
.method public constructor <init>(Lj3/c;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj3/e0;->b:Lj3/c;

    .line 5
    .line 6
    new-instance v0, Lj3/d0;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v0, p0, v1}, Lj3/d0;-><init>(Lj3/e0;I)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p1, Lj3/c;->i:Lay0/k;

    .line 13
    .line 14
    const-string p1, ""

    .line 15
    .line 16
    iput-object p1, p0, Lj3/e0;->c:Ljava/lang/String;

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, p0, Lj3/e0;->d:Z

    .line 20
    .line 21
    new-instance p1, Lj3/a;

    .line 22
    .line 23
    invoke-direct {p1}, Lj3/a;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lj3/e0;->e:Lj3/a;

    .line 27
    .line 28
    sget-object p1, Lj3/g;->h:Lj3/g;

    .line 29
    .line 30
    iput-object p1, p0, Lj3/e0;->f:Lkotlin/jvm/internal/n;

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    iput-object p1, p0, Lj3/e0;->g:Ll2/j1;

    .line 38
    .line 39
    new-instance p1, Ld3/e;

    .line 40
    .line 41
    const-wide/16 v0, 0x0

    .line 42
    .line 43
    invoke-direct {p1, v0, v1}, Ld3/e;-><init>(J)V

    .line 44
    .line 45
    .line 46
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    iput-object p1, p0, Lj3/e0;->i:Ll2/j1;

    .line 51
    .line 52
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    iput-wide v0, p0, Lj3/e0;->j:J

    .line 58
    .line 59
    const/high16 p1, 0x3f800000    # 1.0f

    .line 60
    .line 61
    iput p1, p0, Lj3/e0;->k:F

    .line 62
    .line 63
    iput p1, p0, Lj3/e0;->l:F

    .line 64
    .line 65
    new-instance p1, Lj3/d0;

    .line 66
    .line 67
    const/4 v0, 0x1

    .line 68
    invoke-direct {p1, p0, v0}, Lj3/d0;-><init>(Lj3/e0;I)V

    .line 69
    .line 70
    .line 71
    iput-object p1, p0, Lj3/e0;->m:Lj3/d0;

    .line 72
    .line 73
    return-void
.end method


# virtual methods
.method public final a(Lg3/d;)V
    .locals 2

    .line 1
    const/high16 v0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, p1, v0, v1}, Lj3/e0;->e(Lg3/d;FLe3/m;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final e(Lg3/d;FLe3/m;)V
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    iget-object v2, v0, Lj3/e0;->b:Lj3/c;

    .line 6
    .line 7
    iget-boolean v3, v2, Lj3/c;->d:Z

    .line 8
    .line 9
    const/4 v4, 0x5

    .line 10
    iget-object v5, v0, Lj3/e0;->g:Ll2/j1;

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    if-eqz v3, :cond_4

    .line 14
    .line 15
    iget-wide v8, v2, Lj3/c;->e:J

    .line 16
    .line 17
    const-wide/16 v10, 0x10

    .line 18
    .line 19
    cmp-long v3, v8, v10

    .line 20
    .line 21
    if-eqz v3, :cond_4

    .line 22
    .line 23
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Le3/m;

    .line 28
    .line 29
    sget v8, Lj3/h0;->a:I

    .line 30
    .line 31
    const/4 v8, 0x3

    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    iget v3, v3, Le3/m;->c:I

    .line 35
    .line 36
    if-ne v3, v4, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    if-ne v3, v8, :cond_4

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_1
    if-nez v3, :cond_4

    .line 43
    .line 44
    :goto_0
    if-eqz v1, :cond_3

    .line 45
    .line 46
    iget v3, v1, Le3/m;->c:I

    .line 47
    .line 48
    if-ne v3, v4, :cond_2

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_2
    if-ne v3, v8, :cond_4

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    if-nez v1, :cond_4

    .line 55
    .line 56
    :goto_1
    move v3, v6

    .line 57
    goto :goto_2

    .line 58
    :cond_4
    const/4 v3, 0x0

    .line 59
    :goto_2
    iget-boolean v8, v0, Lj3/e0;->d:Z

    .line 60
    .line 61
    iget-object v9, v0, Lj3/e0;->e:Lj3/a;

    .line 62
    .line 63
    if-nez v8, :cond_6

    .line 64
    .line 65
    iget-wide v10, v0, Lj3/e0;->j:J

    .line 66
    .line 67
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 68
    .line 69
    .line 70
    move-result-wide v12

    .line 71
    invoke-static {v10, v11, v12, v13}, Ld3/e;->a(JJ)Z

    .line 72
    .line 73
    .line 74
    move-result v8

    .line 75
    if-eqz v8, :cond_6

    .line 76
    .line 77
    iget-object v8, v9, Lj3/a;->a:Le3/f;

    .line 78
    .line 79
    if-eqz v8, :cond_5

    .line 80
    .line 81
    invoke-virtual {v8}, Le3/f;->a()I

    .line 82
    .line 83
    .line 84
    move-result v8

    .line 85
    goto :goto_3

    .line 86
    :cond_5
    const/4 v8, 0x0

    .line 87
    :goto_3
    if-ne v3, v8, :cond_6

    .line 88
    .line 89
    goto/16 :goto_7

    .line 90
    .line 91
    :cond_6
    if-ne v3, v6, :cond_8

    .line 92
    .line 93
    iget-wide v10, v2, Lj3/c;->e:J

    .line 94
    .line 95
    sget v2, Lj3/h0;->a:I

    .line 96
    .line 97
    invoke-static {v10, v11}, Le3/s;->d(J)F

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    const/high16 v6, 0x3f800000    # 1.0f

    .line 102
    .line 103
    cmpg-float v2, v2, v6

    .line 104
    .line 105
    if-nez v2, :cond_7

    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_7
    invoke-static {v10, v11, v6}, Le3/s;->b(JF)J

    .line 109
    .line 110
    .line 111
    move-result-wide v10

    .line 112
    :goto_4
    new-instance v2, Le3/m;

    .line 113
    .line 114
    invoke-direct {v2, v10, v11, v4}, Le3/m;-><init>(JI)V

    .line 115
    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_8
    const/4 v2, 0x0

    .line 119
    :goto_5
    iput-object v2, v0, Lj3/e0;->h:Le3/m;

    .line 120
    .line 121
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 122
    .line 123
    .line 124
    move-result-wide v10

    .line 125
    const/16 v2, 0x20

    .line 126
    .line 127
    shr-long/2addr v10, v2

    .line 128
    long-to-int v4, v10

    .line 129
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    iget-object v6, v0, Lj3/e0;->i:Ll2/j1;

    .line 134
    .line 135
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v8

    .line 139
    check-cast v8, Ld3/e;

    .line 140
    .line 141
    iget-wide v10, v8, Ld3/e;->a:J

    .line 142
    .line 143
    shr-long/2addr v10, v2

    .line 144
    long-to-int v8, v10

    .line 145
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 146
    .line 147
    .line 148
    move-result v8

    .line 149
    div-float/2addr v4, v8

    .line 150
    iput v4, v0, Lj3/e0;->k:F

    .line 151
    .line 152
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 153
    .line 154
    .line 155
    move-result-wide v10

    .line 156
    const-wide v12, 0xffffffffL

    .line 157
    .line 158
    .line 159
    .line 160
    .line 161
    and-long/2addr v10, v12

    .line 162
    long-to-int v4, v10

    .line 163
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 164
    .line 165
    .line 166
    move-result v4

    .line 167
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v6

    .line 171
    check-cast v6, Ld3/e;

    .line 172
    .line 173
    iget-wide v10, v6, Ld3/e;->a:J

    .line 174
    .line 175
    and-long/2addr v10, v12

    .line 176
    long-to-int v6, v10

    .line 177
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 178
    .line 179
    .line 180
    move-result v6

    .line 181
    div-float/2addr v4, v6

    .line 182
    iput v4, v0, Lj3/e0;->l:F

    .line 183
    .line 184
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 185
    .line 186
    .line 187
    move-result-wide v10

    .line 188
    shr-long/2addr v10, v2

    .line 189
    long-to-int v4, v10

    .line 190
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 191
    .line 192
    .line 193
    move-result v4

    .line 194
    float-to-double v10, v4

    .line 195
    invoke-static {v10, v11}, Ljava/lang/Math;->ceil(D)D

    .line 196
    .line 197
    .line 198
    move-result-wide v10

    .line 199
    double-to-float v4, v10

    .line 200
    float-to-int v4, v4

    .line 201
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 202
    .line 203
    .line 204
    move-result-wide v10

    .line 205
    and-long/2addr v10, v12

    .line 206
    long-to-int v6, v10

    .line 207
    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 208
    .line 209
    .line 210
    move-result v6

    .line 211
    float-to-double v10, v6

    .line 212
    invoke-static {v10, v11}, Ljava/lang/Math;->ceil(D)D

    .line 213
    .line 214
    .line 215
    move-result-wide v10

    .line 216
    double-to-float v6, v10

    .line 217
    float-to-int v6, v6

    .line 218
    int-to-long v10, v4

    .line 219
    shl-long/2addr v10, v2

    .line 220
    int-to-long v14, v6

    .line 221
    and-long/2addr v14, v12

    .line 222
    or-long/2addr v10, v14

    .line 223
    invoke-interface/range {p1 .. p1}, Lg3/d;->getLayoutDirection()Lt4/m;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    iget-object v6, v9, Lj3/a;->a:Le3/f;

    .line 228
    .line 229
    iget-object v8, v9, Lj3/a;->b:Le3/a;

    .line 230
    .line 231
    if-eqz v6, :cond_9

    .line 232
    .line 233
    if-eqz v8, :cond_9

    .line 234
    .line 235
    shr-long v14, v10, v2

    .line 236
    .line 237
    long-to-int v14, v14

    .line 238
    iget-object v15, v6, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 239
    .line 240
    move/from16 v16, v2

    .line 241
    .line 242
    invoke-virtual {v15}, Landroid/graphics/Bitmap;->getWidth()I

    .line 243
    .line 244
    .line 245
    move-result v2

    .line 246
    move-wide/from16 v17, v12

    .line 247
    .line 248
    if-gt v14, v2, :cond_a

    .line 249
    .line 250
    and-long v12, v10, v17

    .line 251
    .line 252
    long-to-int v2, v12

    .line 253
    invoke-virtual {v15}, Landroid/graphics/Bitmap;->getHeight()I

    .line 254
    .line 255
    .line 256
    move-result v12

    .line 257
    if-gt v2, v12, :cond_a

    .line 258
    .line 259
    iget v2, v9, Lj3/a;->d:I

    .line 260
    .line 261
    if-ne v2, v3, :cond_a

    .line 262
    .line 263
    goto :goto_6

    .line 264
    :cond_9
    move/from16 v16, v2

    .line 265
    .line 266
    move-wide/from16 v17, v12

    .line 267
    .line 268
    :cond_a
    shr-long v12, v10, v16

    .line 269
    .line 270
    long-to-int v2, v12

    .line 271
    and-long v12, v10, v17

    .line 272
    .line 273
    long-to-int v6, v12

    .line 274
    invoke-static {v2, v6, v3}, Le3/j0;->g(III)Le3/f;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    invoke-static {v6}, Le3/j0;->a(Le3/f;)Le3/a;

    .line 279
    .line 280
    .line 281
    move-result-object v8

    .line 282
    iput-object v6, v9, Lj3/a;->a:Le3/f;

    .line 283
    .line 284
    iput-object v8, v9, Lj3/a;->b:Le3/a;

    .line 285
    .line 286
    iput v3, v9, Lj3/a;->d:I

    .line 287
    .line 288
    :goto_6
    iput-wide v10, v9, Lj3/a;->c:J

    .line 289
    .line 290
    iget-object v12, v9, Lj3/a;->e:Lg3/b;

    .line 291
    .line 292
    invoke-static {v10, v11}, Lkp/f9;->c(J)J

    .line 293
    .line 294
    .line 295
    move-result-wide v2

    .line 296
    iget-object v10, v12, Lg3/b;->d:Lg3/a;

    .line 297
    .line 298
    iget-object v11, v10, Lg3/a;->a:Lt4/c;

    .line 299
    .line 300
    iget-object v13, v10, Lg3/a;->b:Lt4/m;

    .line 301
    .line 302
    iget-object v14, v10, Lg3/a;->c:Le3/r;

    .line 303
    .line 304
    move-object/from16 v23, v8

    .line 305
    .line 306
    iget-wide v7, v10, Lg3/a;->d:J

    .line 307
    .line 308
    move-object/from16 v15, p1

    .line 309
    .line 310
    iput-object v15, v10, Lg3/a;->a:Lt4/c;

    .line 311
    .line 312
    iput-object v4, v10, Lg3/a;->b:Lt4/m;

    .line 313
    .line 314
    move-object/from16 v4, v23

    .line 315
    .line 316
    iput-object v4, v10, Lg3/a;->c:Le3/r;

    .line 317
    .line 318
    iput-wide v2, v10, Lg3/a;->d:J

    .line 319
    .line 320
    invoke-virtual {v4}, Le3/a;->o()V

    .line 321
    .line 322
    .line 323
    move-object v2, v13

    .line 324
    move-object v3, v14

    .line 325
    sget-wide v13, Le3/s;->b:J

    .line 326
    .line 327
    const/16 v21, 0x0

    .line 328
    .line 329
    const/16 v22, 0x3e

    .line 330
    .line 331
    const-wide/16 v15, 0x0

    .line 332
    .line 333
    const-wide/16 v17, 0x0

    .line 334
    .line 335
    const/16 v19, 0x0

    .line 336
    .line 337
    const/16 v20, 0x0

    .line 338
    .line 339
    invoke-static/range {v12 .. v22}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 340
    .line 341
    .line 342
    iget-object v10, v0, Lj3/e0;->m:Lj3/d0;

    .line 343
    .line 344
    invoke-virtual {v10, v12}, Lj3/d0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    invoke-virtual {v4}, Le3/a;->i()V

    .line 348
    .line 349
    .line 350
    iget-object v4, v12, Lg3/b;->d:Lg3/a;

    .line 351
    .line 352
    iput-object v11, v4, Lg3/a;->a:Lt4/c;

    .line 353
    .line 354
    iput-object v2, v4, Lg3/a;->b:Lt4/m;

    .line 355
    .line 356
    iput-object v3, v4, Lg3/a;->c:Le3/r;

    .line 357
    .line 358
    iput-wide v7, v4, Lg3/a;->d:J

    .line 359
    .line 360
    iget-object v2, v6, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 361
    .line 362
    invoke-virtual {v2}, Landroid/graphics/Bitmap;->prepareToDraw()V

    .line 363
    .line 364
    .line 365
    const/4 v2, 0x0

    .line 366
    iput-boolean v2, v0, Lj3/e0;->d:Z

    .line 367
    .line 368
    invoke-interface/range {p1 .. p1}, Lg3/d;->e()J

    .line 369
    .line 370
    .line 371
    move-result-wide v2

    .line 372
    iput-wide v2, v0, Lj3/e0;->j:J

    .line 373
    .line 374
    :goto_7
    if-eqz v1, :cond_b

    .line 375
    .line 376
    move-object/from16 v31, v1

    .line 377
    .line 378
    goto :goto_9

    .line 379
    :cond_b
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    check-cast v1, Le3/m;

    .line 384
    .line 385
    if-eqz v1, :cond_c

    .line 386
    .line 387
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    check-cast v0, Le3/m;

    .line 392
    .line 393
    :goto_8
    move-object/from16 v31, v0

    .line 394
    .line 395
    goto :goto_9

    .line 396
    :cond_c
    iget-object v0, v0, Lj3/e0;->h:Le3/m;

    .line 397
    .line 398
    goto :goto_8

    .line 399
    :goto_9
    iget-object v0, v9, Lj3/a;->a:Le3/f;

    .line 400
    .line 401
    if-eqz v0, :cond_d

    .line 402
    .line 403
    goto :goto_a

    .line 404
    :cond_d
    const-string v1, "drawCachedImage must be invoked first before attempting to draw the result into another destination"

    .line 405
    .line 406
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 407
    .line 408
    .line 409
    :goto_a
    iget-wide v1, v9, Lj3/a;->c:J

    .line 410
    .line 411
    const/16 v32, 0x0

    .line 412
    .line 413
    const/16 v33, 0x35a

    .line 414
    .line 415
    const-wide/16 v28, 0x0

    .line 416
    .line 417
    move-object/from16 v24, p1

    .line 418
    .line 419
    move/from16 v30, p2

    .line 420
    .line 421
    move-object/from16 v25, v0

    .line 422
    .line 423
    move-wide/from16 v26, v1

    .line 424
    .line 425
    invoke-static/range {v24 .. v33}, Lg3/d;->g0(Lg3/d;Le3/f;JJFLe3/m;II)V

    .line 426
    .line 427
    .line 428
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "Params: \tname: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lj3/e0;->c:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, "\n\tviewportWidth: "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lj3/e0;->i:Ll2/j1;

    .line 19
    .line 20
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Ld3/e;

    .line 25
    .line 26
    iget-wide v1, v1, Ld3/e;->a:J

    .line 27
    .line 28
    const/16 v3, 0x20

    .line 29
    .line 30
    shr-long/2addr v1, v3

    .line 31
    long-to-int v1, v1

    .line 32
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v1, "\n\tviewportHeight: "

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Ld3/e;

    .line 49
    .line 50
    iget-wide v1, p0, Ld3/e;->a:J

    .line 51
    .line 52
    const-wide v3, 0xffffffffL

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    and-long/2addr v1, v3

    .line 58
    long-to-int p0, v1

    .line 59
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string p0, "\n"

    .line 67
    .line 68
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    const-string v0, "toString(...)"

    .line 76
    .line 77
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    return-object p0
.end method
