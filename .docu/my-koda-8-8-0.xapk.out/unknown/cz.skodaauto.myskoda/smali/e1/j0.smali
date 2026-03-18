.class public final Le1/j0;
.super Lv3/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/p;


# instance fields
.field public final synthetic t:I

.field public final u:Le1/j;

.field public final v:Le1/f0;

.field public w:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lp3/j0;Le1/j;Le1/f0;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Le1/j0;->t:I

    .line 1
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 2
    iput-object p2, p0, Le1/j0;->u:Le1/j;

    .line 3
    iput-object p3, p0, Le1/j0;->v:Le1/f0;

    .line 4
    invoke-virtual {p0, p1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    return-void
.end method

.method public constructor <init>(Lp3/j0;Le1/j;Le1/f0;Lk1/z0;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Le1/j0;->t:I

    .line 5
    invoke-direct {p0}, Lv3/n;-><init>()V

    .line 6
    iput-object p2, p0, Le1/j0;->u:Le1/j;

    .line 7
    iput-object p3, p0, Le1/j0;->v:Le1/f0;

    .line 8
    iput-object p4, p0, Le1/j0;->w:Ljava/lang/Object;

    .line 9
    invoke-virtual {p0, p1}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    return-void
.end method

.method public static a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v0, p0, v0

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {p1, p2}, Landroid/widget/EdgeEffect;->draw(Landroid/graphics/Canvas;)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :cond_0
    invoke-virtual {p2}, Landroid/graphics/Canvas;->save()I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    invoke-virtual {p2, p0}, Landroid/graphics/Canvas;->rotate(F)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, p2}, Landroid/widget/EdgeEffect;->draw(Landroid/graphics/Canvas;)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-virtual {p2, v0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 23
    .line 24
    .line 25
    return p0
.end method

.method public static b1(FJLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z
    .locals 3

    .line 1
    invoke-virtual {p4}, Landroid/graphics/Canvas;->save()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p4, p0}, Landroid/graphics/Canvas;->rotate(F)V

    .line 6
    .line 7
    .line 8
    const/16 p0, 0x20

    .line 9
    .line 10
    shr-long v1, p1, p0

    .line 11
    .line 12
    long-to-int p0, v1

    .line 13
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    const-wide v1, 0xffffffffL

    .line 18
    .line 19
    .line 20
    .line 21
    .line 22
    and-long/2addr p1, v1

    .line 23
    long-to-int p1, p1

    .line 24
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p4, p0, p1}, Landroid/graphics/Canvas;->translate(FF)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p3, p4}, Landroid/widget/EdgeEffect;->draw(Landroid/graphics/Canvas;)Z

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    invoke-virtual {p4, v0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 36
    .line 37
    .line 38
    return p0
.end method


# virtual methods
.method public final C0(Lv3/j0;)V
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget v2, v0, Le1/j0;->t:I

    .line 6
    .line 7
    packed-switch v2, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    iget-object v2, v1, Lv3/j0;->d:Lg3/b;

    .line 11
    .line 12
    invoke-interface {v2}, Lg3/d;->e()J

    .line 13
    .line 14
    .line 15
    move-result-wide v3

    .line 16
    iget-object v5, v0, Le1/j0;->u:Le1/j;

    .line 17
    .line 18
    invoke-virtual {v5, v3, v4}, Le1/j;->i(J)V

    .line 19
    .line 20
    .line 21
    iget-object v3, v2, Lg3/b;->e:Lgw0/c;

    .line 22
    .line 23
    invoke-virtual {v3}, Lgw0/c;->h()Le3/r;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-static {v3}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    iget-object v4, v5, Le1/j;->d:Ll2/j1;

    .line 32
    .line 33
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    invoke-interface {v2}, Lg3/d;->e()J

    .line 37
    .line 38
    .line 39
    move-result-wide v6

    .line 40
    invoke-static {v6, v7}, Ld3/e;->e(J)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-eqz v4, :cond_0

    .line 45
    .line 46
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 47
    .line 48
    .line 49
    goto/16 :goto_19

    .line 50
    .line 51
    :cond_0
    invoke-virtual {v3}, Landroid/graphics/Canvas;->isHardwareAccelerated()Z

    .line 52
    .line 53
    .line 54
    move-result v4

    .line 55
    iget-object v6, v0, Le1/j0;->v:Le1/f0;

    .line 56
    .line 57
    if-nez v4, :cond_9

    .line 58
    .line 59
    iget-object v0, v6, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 60
    .line 61
    if-eqz v0, :cond_1

    .line 62
    .line 63
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 64
    .line 65
    .line 66
    :cond_1
    iget-object v0, v6, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 67
    .line 68
    if-eqz v0, :cond_2

    .line 69
    .line 70
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 71
    .line 72
    .line 73
    :cond_2
    iget-object v0, v6, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 74
    .line 75
    if-eqz v0, :cond_3

    .line 76
    .line 77
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 78
    .line 79
    .line 80
    :cond_3
    iget-object v0, v6, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 81
    .line 82
    if-eqz v0, :cond_4

    .line 83
    .line 84
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 85
    .line 86
    .line 87
    :cond_4
    iget-object v0, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 88
    .line 89
    if-eqz v0, :cond_5

    .line 90
    .line 91
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 92
    .line 93
    .line 94
    :cond_5
    iget-object v0, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 95
    .line 96
    if-eqz v0, :cond_6

    .line 97
    .line 98
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 99
    .line 100
    .line 101
    :cond_6
    iget-object v0, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 102
    .line 103
    if-eqz v0, :cond_7

    .line 104
    .line 105
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 106
    .line 107
    .line 108
    :cond_7
    iget-object v0, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 109
    .line 110
    if-eqz v0, :cond_8

    .line 111
    .line 112
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->finish()V

    .line 113
    .line 114
    .line 115
    :cond_8
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 116
    .line 117
    .line 118
    goto/16 :goto_19

    .line 119
    .line 120
    :cond_9
    sget v4, Le1/x;->a:F

    .line 121
    .line 122
    invoke-virtual {v1, v4}, Lv3/j0;->w0(F)F

    .line 123
    .line 124
    .line 125
    move-result v4

    .line 126
    iget-object v7, v6, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 127
    .line 128
    invoke-static {v7}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 129
    .line 130
    .line 131
    move-result v7

    .line 132
    const/4 v8, 0x1

    .line 133
    const/4 v9, 0x0

    .line 134
    if-nez v7, :cond_b

    .line 135
    .line 136
    iget-object v7, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 137
    .line 138
    invoke-static {v7}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    if-nez v7, :cond_b

    .line 143
    .line 144
    iget-object v7, v6, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 145
    .line 146
    invoke-static {v7}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 147
    .line 148
    .line 149
    move-result v7

    .line 150
    if-nez v7, :cond_b

    .line 151
    .line 152
    iget-object v7, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 153
    .line 154
    invoke-static {v7}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 155
    .line 156
    .line 157
    move-result v7

    .line 158
    if-eqz v7, :cond_a

    .line 159
    .line 160
    goto :goto_0

    .line 161
    :cond_a
    move v7, v9

    .line 162
    goto :goto_1

    .line 163
    :cond_b
    :goto_0
    move v7, v8

    .line 164
    :goto_1
    iget-object v10, v6, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 165
    .line 166
    invoke-static {v10}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 167
    .line 168
    .line 169
    move-result v10

    .line 170
    if-nez v10, :cond_d

    .line 171
    .line 172
    iget-object v10, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 173
    .line 174
    invoke-static {v10}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 175
    .line 176
    .line 177
    move-result v10

    .line 178
    if-nez v10, :cond_d

    .line 179
    .line 180
    iget-object v10, v6, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 181
    .line 182
    invoke-static {v10}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 183
    .line 184
    .line 185
    move-result v10

    .line 186
    if-nez v10, :cond_d

    .line 187
    .line 188
    iget-object v10, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 189
    .line 190
    invoke-static {v10}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 191
    .line 192
    .line 193
    move-result v10

    .line 194
    if-eqz v10, :cond_c

    .line 195
    .line 196
    goto :goto_2

    .line 197
    :cond_c
    move v10, v9

    .line 198
    goto :goto_3

    .line 199
    :cond_d
    :goto_2
    move v10, v8

    .line 200
    :goto_3
    if-eqz v7, :cond_e

    .line 201
    .line 202
    if-eqz v10, :cond_e

    .line 203
    .line 204
    invoke-virtual {v0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 205
    .line 206
    .line 207
    move-result-object v11

    .line 208
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getWidth()I

    .line 209
    .line 210
    .line 211
    move-result v12

    .line 212
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getHeight()I

    .line 213
    .line 214
    .line 215
    move-result v13

    .line 216
    invoke-virtual {v11, v9, v9, v12, v13}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 217
    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_e
    if-eqz v7, :cond_f

    .line 221
    .line 222
    invoke-virtual {v0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 223
    .line 224
    .line 225
    move-result-object v11

    .line 226
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getWidth()I

    .line 227
    .line 228
    .line 229
    move-result v12

    .line 230
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 231
    .line 232
    .line 233
    move-result v13

    .line 234
    mul-int/lit8 v13, v13, 0x2

    .line 235
    .line 236
    add-int/2addr v13, v12

    .line 237
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getHeight()I

    .line 238
    .line 239
    .line 240
    move-result v12

    .line 241
    invoke-virtual {v11, v9, v9, v13, v12}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_f
    if-eqz v10, :cond_33

    .line 246
    .line 247
    invoke-virtual {v0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 248
    .line 249
    .line 250
    move-result-object v11

    .line 251
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getWidth()I

    .line 252
    .line 253
    .line 254
    move-result v12

    .line 255
    invoke-virtual {v3}, Landroid/graphics/Canvas;->getHeight()I

    .line 256
    .line 257
    .line 258
    move-result v13

    .line 259
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 260
    .line 261
    .line 262
    move-result v14

    .line 263
    mul-int/lit8 v14, v14, 0x2

    .line 264
    .line 265
    add-int/2addr v14, v13

    .line 266
    invoke-virtual {v11, v9, v9, v12, v14}, Landroid/graphics/RenderNode;->setPosition(IIII)Z

    .line 267
    .line 268
    .line 269
    :goto_4
    invoke-virtual {v0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 270
    .line 271
    .line 272
    move-result-object v11

    .line 273
    invoke-virtual {v11}, Landroid/graphics/RenderNode;->beginRecording()Landroid/graphics/RecordingCanvas;

    .line 274
    .line 275
    .line 276
    move-result-object v11

    .line 277
    iget-object v12, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 278
    .line 279
    invoke-static {v12}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 280
    .line 281
    .line 282
    move-result v12

    .line 283
    const/high16 v13, 0x42b40000    # 90.0f

    .line 284
    .line 285
    if-eqz v12, :cond_11

    .line 286
    .line 287
    iget-object v12, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 288
    .line 289
    if-nez v12, :cond_10

    .line 290
    .line 291
    sget-object v12, Lg1/w1;->e:Lg1/w1;

    .line 292
    .line 293
    invoke-virtual {v6, v12}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 294
    .line 295
    .line 296
    move-result-object v12

    .line 297
    iput-object v12, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 298
    .line 299
    :cond_10
    invoke-static {v13, v12, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 300
    .line 301
    .line 302
    invoke-virtual {v12}, Landroid/widget/EdgeEffect;->finish()V

    .line 303
    .line 304
    .line 305
    :cond_11
    iget-object v12, v6, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 306
    .line 307
    invoke-static {v12}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 308
    .line 309
    .line 310
    move-result v12

    .line 311
    const/high16 v14, 0x43870000    # 270.0f

    .line 312
    .line 313
    const-wide v18, 0xffffffffL

    .line 314
    .line 315
    .line 316
    .line 317
    .line 318
    const/16 v15, 0x1f

    .line 319
    .line 320
    if-eqz v12, :cond_16

    .line 321
    .line 322
    invoke-virtual {v6}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 323
    .line 324
    .line 325
    move-result-object v12

    .line 326
    invoke-static {v14, v12, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 327
    .line 328
    .line 329
    move-result v16

    .line 330
    iget-object v13, v6, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 331
    .line 332
    invoke-static {v13}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 333
    .line 334
    .line 335
    move-result v13

    .line 336
    if-eqz v13, :cond_15

    .line 337
    .line 338
    invoke-virtual {v5}, Le1/j;->c()J

    .line 339
    .line 340
    .line 341
    move-result-wide v20

    .line 342
    move v13, v10

    .line 343
    and-long v9, v20, v18

    .line 344
    .line 345
    long-to-int v9, v9

    .line 346
    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 347
    .line 348
    .line 349
    move-result v9

    .line 350
    iget-object v10, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 351
    .line 352
    if-nez v10, :cond_12

    .line 353
    .line 354
    sget-object v10, Lg1/w1;->e:Lg1/w1;

    .line 355
    .line 356
    invoke-virtual {v6, v10}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 357
    .line 358
    .line 359
    move-result-object v10

    .line 360
    iput-object v10, v6, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 361
    .line 362
    :cond_12
    sget v14, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 363
    .line 364
    if-lt v14, v15, :cond_13

    .line 365
    .line 366
    invoke-static {v12}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 367
    .line 368
    .line 369
    move-result v12

    .line 370
    :goto_5
    move/from16 v21, v4

    .line 371
    .line 372
    goto :goto_6

    .line 373
    :cond_13
    const/4 v12, 0x0

    .line 374
    goto :goto_5

    .line 375
    :goto_6
    int-to-float v4, v8

    .line 376
    sub-float/2addr v4, v9

    .line 377
    if-lt v14, v15, :cond_14

    .line 378
    .line 379
    invoke-static {v10, v12, v4}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 380
    .line 381
    .line 382
    goto :goto_7

    .line 383
    :cond_14
    invoke-virtual {v10, v12, v4}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 384
    .line 385
    .line 386
    goto :goto_7

    .line 387
    :cond_15
    move/from16 v21, v4

    .line 388
    .line 389
    move v13, v10

    .line 390
    goto :goto_7

    .line 391
    :cond_16
    move/from16 v21, v4

    .line 392
    .line 393
    move v13, v10

    .line 394
    const/16 v16, 0x0

    .line 395
    .line 396
    :goto_7
    iget-object v4, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 397
    .line 398
    invoke-static {v4}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 399
    .line 400
    .line 401
    move-result v4

    .line 402
    const/high16 v9, 0x43340000    # 180.0f

    .line 403
    .line 404
    if-eqz v4, :cond_18

    .line 405
    .line 406
    iget-object v4, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 407
    .line 408
    if-nez v4, :cond_17

    .line 409
    .line 410
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 411
    .line 412
    invoke-virtual {v6, v4}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 413
    .line 414
    .line 415
    move-result-object v4

    .line 416
    iput-object v4, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 417
    .line 418
    :cond_17
    invoke-static {v9, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 419
    .line 420
    .line 421
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->finish()V

    .line 422
    .line 423
    .line 424
    :cond_18
    iget-object v4, v6, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 425
    .line 426
    invoke-static {v4}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 427
    .line 428
    .line 429
    move-result v4

    .line 430
    const/16 v10, 0x20

    .line 431
    .line 432
    if-eqz v4, :cond_1e

    .line 433
    .line 434
    invoke-virtual {v6}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 435
    .line 436
    .line 437
    move-result-object v4

    .line 438
    const/4 v12, 0x0

    .line 439
    invoke-static {v12, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 440
    .line 441
    .line 442
    move-result v14

    .line 443
    if-nez v14, :cond_1a

    .line 444
    .line 445
    if-eqz v16, :cond_19

    .line 446
    .line 447
    goto :goto_8

    .line 448
    :cond_19
    const/16 v16, 0x0

    .line 449
    .line 450
    goto :goto_9

    .line 451
    :cond_1a
    :goto_8
    move/from16 v16, v8

    .line 452
    .line 453
    :goto_9
    iget-object v12, v6, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 454
    .line 455
    invoke-static {v12}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 456
    .line 457
    .line 458
    move-result v12

    .line 459
    if-eqz v12, :cond_1e

    .line 460
    .line 461
    invoke-virtual {v5}, Le1/j;->c()J

    .line 462
    .line 463
    .line 464
    move-result-wide v22

    .line 465
    shr-long v8, v22, v10

    .line 466
    .line 467
    long-to-int v8, v8

    .line 468
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 469
    .line 470
    .line 471
    move-result v8

    .line 472
    iget-object v9, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 473
    .line 474
    if-nez v9, :cond_1b

    .line 475
    .line 476
    sget-object v9, Lg1/w1;->d:Lg1/w1;

    .line 477
    .line 478
    invoke-virtual {v6, v9}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 479
    .line 480
    .line 481
    move-result-object v9

    .line 482
    iput-object v9, v6, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 483
    .line 484
    :cond_1b
    move/from16 v22, v10

    .line 485
    .line 486
    sget v10, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 487
    .line 488
    if-lt v10, v15, :cond_1c

    .line 489
    .line 490
    invoke-static {v4}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 491
    .line 492
    .line 493
    move-result v4

    .line 494
    goto :goto_a

    .line 495
    :cond_1c
    const/4 v4, 0x0

    .line 496
    :goto_a
    if-lt v10, v15, :cond_1d

    .line 497
    .line 498
    invoke-static {v9, v4, v8}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 499
    .line 500
    .line 501
    goto :goto_b

    .line 502
    :cond_1d
    invoke-virtual {v9, v4, v8}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 503
    .line 504
    .line 505
    goto :goto_b

    .line 506
    :cond_1e
    move/from16 v22, v10

    .line 507
    .line 508
    :goto_b
    iget-object v4, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 509
    .line 510
    invoke-static {v4}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 511
    .line 512
    .line 513
    move-result v4

    .line 514
    if-eqz v4, :cond_20

    .line 515
    .line 516
    iget-object v4, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 517
    .line 518
    if-nez v4, :cond_1f

    .line 519
    .line 520
    sget-object v4, Lg1/w1;->e:Lg1/w1;

    .line 521
    .line 522
    invoke-virtual {v6, v4}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 523
    .line 524
    .line 525
    move-result-object v4

    .line 526
    iput-object v4, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 527
    .line 528
    :cond_1f
    const/high16 v8, 0x43870000    # 270.0f

    .line 529
    .line 530
    invoke-static {v8, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 531
    .line 532
    .line 533
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->finish()V

    .line 534
    .line 535
    .line 536
    :cond_20
    iget-object v4, v6, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 537
    .line 538
    invoke-static {v4}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 539
    .line 540
    .line 541
    move-result v4

    .line 542
    if-eqz v4, :cond_26

    .line 543
    .line 544
    invoke-virtual {v6}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 545
    .line 546
    .line 547
    move-result-object v4

    .line 548
    const/high16 v8, 0x42b40000    # 90.0f

    .line 549
    .line 550
    invoke-static {v8, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 551
    .line 552
    .line 553
    move-result v8

    .line 554
    if-nez v8, :cond_22

    .line 555
    .line 556
    if-eqz v16, :cond_21

    .line 557
    .line 558
    goto :goto_c

    .line 559
    :cond_21
    const/16 v16, 0x0

    .line 560
    .line 561
    goto :goto_d

    .line 562
    :cond_22
    :goto_c
    const/16 v16, 0x1

    .line 563
    .line 564
    :goto_d
    iget-object v8, v6, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 565
    .line 566
    invoke-static {v8}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 567
    .line 568
    .line 569
    move-result v8

    .line 570
    if-eqz v8, :cond_26

    .line 571
    .line 572
    invoke-virtual {v5}, Le1/j;->c()J

    .line 573
    .line 574
    .line 575
    move-result-wide v8

    .line 576
    and-long v8, v8, v18

    .line 577
    .line 578
    long-to-int v8, v8

    .line 579
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 580
    .line 581
    .line 582
    move-result v8

    .line 583
    iget-object v9, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 584
    .line 585
    if-nez v9, :cond_23

    .line 586
    .line 587
    sget-object v9, Lg1/w1;->e:Lg1/w1;

    .line 588
    .line 589
    invoke-virtual {v6, v9}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 590
    .line 591
    .line 592
    move-result-object v9

    .line 593
    iput-object v9, v6, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 594
    .line 595
    :cond_23
    sget v10, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 596
    .line 597
    if-lt v10, v15, :cond_24

    .line 598
    .line 599
    invoke-static {v4}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 600
    .line 601
    .line 602
    move-result v4

    .line 603
    goto :goto_e

    .line 604
    :cond_24
    const/4 v4, 0x0

    .line 605
    :goto_e
    if-lt v10, v15, :cond_25

    .line 606
    .line 607
    invoke-static {v9, v4, v8}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 608
    .line 609
    .line 610
    goto :goto_f

    .line 611
    :cond_25
    invoke-virtual {v9, v4, v8}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 612
    .line 613
    .line 614
    :cond_26
    :goto_f
    iget-object v4, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 615
    .line 616
    invoke-static {v4}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 617
    .line 618
    .line 619
    move-result v4

    .line 620
    if-eqz v4, :cond_28

    .line 621
    .line 622
    iget-object v4, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 623
    .line 624
    if-nez v4, :cond_27

    .line 625
    .line 626
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 627
    .line 628
    invoke-virtual {v6, v4}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 629
    .line 630
    .line 631
    move-result-object v4

    .line 632
    iput-object v4, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 633
    .line 634
    :cond_27
    const/4 v8, 0x0

    .line 635
    invoke-static {v8, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 636
    .line 637
    .line 638
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->finish()V

    .line 639
    .line 640
    .line 641
    goto :goto_10

    .line 642
    :cond_28
    const/4 v8, 0x0

    .line 643
    :goto_10
    iget-object v4, v6, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 644
    .line 645
    invoke-static {v4}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 646
    .line 647
    .line 648
    move-result v4

    .line 649
    if-eqz v4, :cond_2f

    .line 650
    .line 651
    invoke-virtual {v6}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 652
    .line 653
    .line 654
    move-result-object v4

    .line 655
    const/high16 v14, 0x43340000    # 180.0f

    .line 656
    .line 657
    invoke-static {v14, v4, v11}, Le1/j0;->a1(FLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 658
    .line 659
    .line 660
    move-result v9

    .line 661
    if-nez v9, :cond_2a

    .line 662
    .line 663
    if-eqz v16, :cond_29

    .line 664
    .line 665
    goto :goto_11

    .line 666
    :cond_29
    const/4 v9, 0x0

    .line 667
    goto :goto_12

    .line 668
    :cond_2a
    :goto_11
    const/4 v9, 0x1

    .line 669
    :goto_12
    iget-object v10, v6, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 670
    .line 671
    invoke-static {v10}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 672
    .line 673
    .line 674
    move-result v10

    .line 675
    if-eqz v10, :cond_2e

    .line 676
    .line 677
    invoke-virtual {v5}, Le1/j;->c()J

    .line 678
    .line 679
    .line 680
    move-result-wide v16

    .line 681
    move v10, v9

    .line 682
    shr-long v8, v16, v22

    .line 683
    .line 684
    long-to-int v8, v8

    .line 685
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 686
    .line 687
    .line 688
    move-result v8

    .line 689
    iget-object v9, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 690
    .line 691
    if-nez v9, :cond_2b

    .line 692
    .line 693
    sget-object v9, Lg1/w1;->d:Lg1/w1;

    .line 694
    .line 695
    invoke-virtual {v6, v9}, Le1/f0;->a(Lg1/w1;)Landroid/widget/EdgeEffect;

    .line 696
    .line 697
    .line 698
    move-result-object v9

    .line 699
    iput-object v9, v6, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 700
    .line 701
    :cond_2b
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 702
    .line 703
    if-lt v6, v15, :cond_2c

    .line 704
    .line 705
    invoke-static {v4}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 706
    .line 707
    .line 708
    move-result v4

    .line 709
    move v12, v4

    .line 710
    :goto_13
    const/4 v4, 0x1

    .line 711
    goto :goto_14

    .line 712
    :cond_2c
    const/4 v12, 0x0

    .line 713
    goto :goto_13

    .line 714
    :goto_14
    int-to-float v4, v4

    .line 715
    sub-float/2addr v4, v8

    .line 716
    if-lt v6, v15, :cond_2d

    .line 717
    .line 718
    invoke-static {v9, v12, v4}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 719
    .line 720
    .line 721
    goto :goto_15

    .line 722
    :cond_2d
    invoke-virtual {v9, v12, v4}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 723
    .line 724
    .line 725
    goto :goto_15

    .line 726
    :cond_2e
    move v10, v9

    .line 727
    :goto_15
    move/from16 v16, v10

    .line 728
    .line 729
    :cond_2f
    if-eqz v16, :cond_30

    .line 730
    .line 731
    invoke-virtual {v5}, Le1/j;->d()V

    .line 732
    .line 733
    .line 734
    :cond_30
    if-eqz v13, :cond_31

    .line 735
    .line 736
    const/4 v12, 0x0

    .line 737
    goto :goto_16

    .line 738
    :cond_31
    move/from16 v12, v21

    .line 739
    .line 740
    :goto_16
    if-eqz v7, :cond_32

    .line 741
    .line 742
    const/4 v4, 0x0

    .line 743
    goto :goto_17

    .line 744
    :cond_32
    move/from16 v4, v21

    .line 745
    .line 746
    :goto_17
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 747
    .line 748
    .line 749
    move-result-object v5

    .line 750
    new-instance v6, Le3/a;

    .line 751
    .line 752
    invoke-direct {v6}, Le3/a;-><init>()V

    .line 753
    .line 754
    .line 755
    iput-object v11, v6, Le3/a;->a:Landroid/graphics/Canvas;

    .line 756
    .line 757
    invoke-interface {v2}, Lg3/d;->e()J

    .line 758
    .line 759
    .line 760
    move-result-wide v7

    .line 761
    iget-object v9, v2, Lg3/b;->e:Lgw0/c;

    .line 762
    .line 763
    invoke-virtual {v9}, Lgw0/c;->k()Lt4/c;

    .line 764
    .line 765
    .line 766
    move-result-object v9

    .line 767
    iget-object v10, v2, Lg3/b;->e:Lgw0/c;

    .line 768
    .line 769
    invoke-virtual {v10}, Lgw0/c;->l()Lt4/m;

    .line 770
    .line 771
    .line 772
    move-result-object v10

    .line 773
    iget-object v11, v2, Lg3/b;->e:Lgw0/c;

    .line 774
    .line 775
    invoke-virtual {v11}, Lgw0/c;->h()Le3/r;

    .line 776
    .line 777
    .line 778
    move-result-object v11

    .line 779
    iget-object v13, v2, Lg3/b;->e:Lgw0/c;

    .line 780
    .line 781
    invoke-virtual {v13}, Lgw0/c;->o()J

    .line 782
    .line 783
    .line 784
    move-result-wide v13

    .line 785
    iget-object v15, v2, Lg3/b;->e:Lgw0/c;

    .line 786
    .line 787
    iget-object v0, v15, Lgw0/c;->f:Ljava/lang/Object;

    .line 788
    .line 789
    move-object/from16 v16, v3

    .line 790
    .line 791
    move-object v3, v0

    .line 792
    check-cast v3, Lh3/c;

    .line 793
    .line 794
    invoke-virtual {v15, v1}, Lgw0/c;->z(Lt4/c;)V

    .line 795
    .line 796
    .line 797
    invoke-virtual {v15, v5}, Lgw0/c;->A(Lt4/m;)V

    .line 798
    .line 799
    .line 800
    invoke-virtual {v15, v6}, Lgw0/c;->x(Le3/r;)V

    .line 801
    .line 802
    .line 803
    invoke-virtual {v15, v7, v8}, Lgw0/c;->B(J)V

    .line 804
    .line 805
    .line 806
    const/4 v0, 0x0

    .line 807
    iput-object v0, v15, Lgw0/c;->f:Ljava/lang/Object;

    .line 808
    .line 809
    invoke-virtual {v6}, Le3/a;->o()V

    .line 810
    .line 811
    .line 812
    :try_start_0
    iget-object v0, v2, Lg3/b;->e:Lgw0/c;

    .line 813
    .line 814
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 815
    .line 816
    check-cast v0, Lbu/c;

    .line 817
    .line 818
    invoke-virtual {v0, v12, v4}, Lbu/c;->B(FF)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 819
    .line 820
    .line 821
    :try_start_1
    invoke-virtual {v1}, Lv3/j0;->b()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 822
    .line 823
    .line 824
    :try_start_2
    iget-object v0, v2, Lg3/b;->e:Lgw0/c;

    .line 825
    .line 826
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 827
    .line 828
    check-cast v0, Lbu/c;

    .line 829
    .line 830
    neg-float v1, v12

    .line 831
    neg-float v4, v4

    .line 832
    invoke-virtual {v0, v1, v4}, Lbu/c;->B(FF)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 833
    .line 834
    .line 835
    invoke-virtual {v6}, Le3/a;->i()V

    .line 836
    .line 837
    .line 838
    iget-object v0, v2, Lg3/b;->e:Lgw0/c;

    .line 839
    .line 840
    invoke-virtual {v0, v9}, Lgw0/c;->z(Lt4/c;)V

    .line 841
    .line 842
    .line 843
    invoke-virtual {v0, v10}, Lgw0/c;->A(Lt4/m;)V

    .line 844
    .line 845
    .line 846
    invoke-virtual {v0, v11}, Lgw0/c;->x(Le3/r;)V

    .line 847
    .line 848
    .line 849
    invoke-virtual {v0, v13, v14}, Lgw0/c;->B(J)V

    .line 850
    .line 851
    .line 852
    iput-object v3, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 853
    .line 854
    invoke-virtual/range {p0 .. p0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 855
    .line 856
    .line 857
    move-result-object v0

    .line 858
    invoke-virtual {v0}, Landroid/graphics/RenderNode;->endRecording()V

    .line 859
    .line 860
    .line 861
    invoke-virtual/range {v16 .. v16}, Landroid/graphics/Canvas;->save()I

    .line 862
    .line 863
    .line 864
    move-result v0

    .line 865
    move-object/from16 v2, v16

    .line 866
    .line 867
    invoke-virtual {v2, v1, v4}, Landroid/graphics/Canvas;->translate(FF)V

    .line 868
    .line 869
    .line 870
    invoke-virtual/range {p0 .. p0}, Le1/j0;->c1()Landroid/graphics/RenderNode;

    .line 871
    .line 872
    .line 873
    move-result-object v1

    .line 874
    invoke-virtual {v2, v1}, Landroid/graphics/Canvas;->drawRenderNode(Landroid/graphics/RenderNode;)V

    .line 875
    .line 876
    .line 877
    invoke-virtual {v2, v0}, Landroid/graphics/Canvas;->restoreToCount(I)V

    .line 878
    .line 879
    .line 880
    goto :goto_19

    .line 881
    :catchall_0
    move-exception v0

    .line 882
    goto :goto_18

    .line 883
    :catchall_1
    move-exception v0

    .line 884
    :try_start_3
    iget-object v1, v2, Lg3/b;->e:Lgw0/c;

    .line 885
    .line 886
    iget-object v1, v1, Lgw0/c;->e:Ljava/lang/Object;

    .line 887
    .line 888
    check-cast v1, Lbu/c;

    .line 889
    .line 890
    neg-float v5, v12

    .line 891
    neg-float v4, v4

    .line 892
    invoke-virtual {v1, v5, v4}, Lbu/c;->B(FF)V

    .line 893
    .line 894
    .line 895
    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 896
    :goto_18
    invoke-virtual {v6}, Le3/a;->i()V

    .line 897
    .line 898
    .line 899
    iget-object v1, v2, Lg3/b;->e:Lgw0/c;

    .line 900
    .line 901
    invoke-virtual {v1, v9}, Lgw0/c;->z(Lt4/c;)V

    .line 902
    .line 903
    .line 904
    invoke-virtual {v1, v10}, Lgw0/c;->A(Lt4/m;)V

    .line 905
    .line 906
    .line 907
    invoke-virtual {v1, v11}, Lgw0/c;->x(Le3/r;)V

    .line 908
    .line 909
    .line 910
    invoke-virtual {v1, v13, v14}, Lgw0/c;->B(J)V

    .line 911
    .line 912
    .line 913
    iput-object v3, v1, Lgw0/c;->f:Ljava/lang/Object;

    .line 914
    .line 915
    throw v0

    .line 916
    :cond_33
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 917
    .line 918
    .line 919
    :goto_19
    return-void

    .line 920
    :pswitch_0
    iget-object v2, v0, Le1/j0;->w:Ljava/lang/Object;

    .line 921
    .line 922
    check-cast v2, Lk1/z0;

    .line 923
    .line 924
    iget-object v3, v1, Lv3/j0;->d:Lg3/b;

    .line 925
    .line 926
    invoke-interface {v3}, Lg3/d;->e()J

    .line 927
    .line 928
    .line 929
    move-result-wide v4

    .line 930
    iget-object v6, v0, Le1/j0;->u:Le1/j;

    .line 931
    .line 932
    invoke-virtual {v6, v4, v5}, Le1/j;->i(J)V

    .line 933
    .line 934
    .line 935
    invoke-interface {v3}, Lg3/d;->e()J

    .line 936
    .line 937
    .line 938
    move-result-wide v4

    .line 939
    invoke-static {v4, v5}, Ld3/e;->e(J)Z

    .line 940
    .line 941
    .line 942
    move-result v4

    .line 943
    if-eqz v4, :cond_34

    .line 944
    .line 945
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 946
    .line 947
    .line 948
    goto/16 :goto_1f

    .line 949
    .line 950
    :cond_34
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 951
    .line 952
    .line 953
    iget-object v4, v6, Le1/j;->d:Ll2/j1;

    .line 954
    .line 955
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 956
    .line 957
    .line 958
    iget-object v4, v3, Lg3/b;->e:Lgw0/c;

    .line 959
    .line 960
    invoke-virtual {v4}, Lgw0/c;->h()Le3/r;

    .line 961
    .line 962
    .line 963
    move-result-object v4

    .line 964
    invoke-static {v4}, Le3/b;->a(Le3/r;)Landroid/graphics/Canvas;

    .line 965
    .line 966
    .line 967
    move-result-object v4

    .line 968
    iget-object v0, v0, Le1/j0;->v:Le1/f0;

    .line 969
    .line 970
    iget-object v5, v0, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 971
    .line 972
    invoke-static {v5}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 973
    .line 974
    .line 975
    move-result v5

    .line 976
    const/16 v7, 0x20

    .line 977
    .line 978
    const-wide v8, 0xffffffffL

    .line 979
    .line 980
    .line 981
    .line 982
    .line 983
    const/4 v10, 0x0

    .line 984
    if-eqz v5, :cond_35

    .line 985
    .line 986
    invoke-virtual {v0}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 987
    .line 988
    .line 989
    move-result-object v5

    .line 990
    invoke-interface {v3}, Lg3/d;->e()J

    .line 991
    .line 992
    .line 993
    move-result-wide v11

    .line 994
    and-long/2addr v11, v8

    .line 995
    long-to-int v11, v11

    .line 996
    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 997
    .line 998
    .line 999
    move-result v11

    .line 1000
    neg-float v11, v11

    .line 1001
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v12

    .line 1005
    invoke-interface {v2, v12}, Lk1/z0;->b(Lt4/m;)F

    .line 1006
    .line 1007
    .line 1008
    move-result v12

    .line 1009
    invoke-virtual {v1, v12}, Lv3/j0;->w0(F)F

    .line 1010
    .line 1011
    .line 1012
    move-result v12

    .line 1013
    invoke-static {v11}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1014
    .line 1015
    .line 1016
    move-result v11

    .line 1017
    int-to-long v13, v11

    .line 1018
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1019
    .line 1020
    .line 1021
    move-result v11

    .line 1022
    int-to-long v11, v11

    .line 1023
    shl-long/2addr v13, v7

    .line 1024
    and-long/2addr v11, v8

    .line 1025
    or-long/2addr v11, v13

    .line 1026
    const/high16 v13, 0x43870000    # 270.0f

    .line 1027
    .line 1028
    invoke-static {v13, v11, v12, v5, v4}, Le1/j0;->b1(FJLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 1029
    .line 1030
    .line 1031
    move-result v5

    .line 1032
    goto :goto_1a

    .line 1033
    :cond_35
    move v5, v10

    .line 1034
    :goto_1a
    iget-object v11, v0, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 1035
    .line 1036
    invoke-static {v11}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 1037
    .line 1038
    .line 1039
    move-result v11

    .line 1040
    const/4 v12, 0x0

    .line 1041
    const/4 v13, 0x1

    .line 1042
    if-eqz v11, :cond_38

    .line 1043
    .line 1044
    invoke-virtual {v0}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 1045
    .line 1046
    .line 1047
    move-result-object v11

    .line 1048
    invoke-interface {v2}, Lk1/z0;->d()F

    .line 1049
    .line 1050
    .line 1051
    move-result v14

    .line 1052
    invoke-virtual {v1, v14}, Lv3/j0;->w0(F)F

    .line 1053
    .line 1054
    .line 1055
    move-result v14

    .line 1056
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1057
    .line 1058
    .line 1059
    move-result v15

    .line 1060
    move/from16 p0, v7

    .line 1061
    .line 1062
    move-wide/from16 v16, v8

    .line 1063
    .line 1064
    int-to-long v7, v15

    .line 1065
    invoke-static {v14}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1066
    .line 1067
    .line 1068
    move-result v9

    .line 1069
    int-to-long v14, v9

    .line 1070
    shl-long v7, v7, p0

    .line 1071
    .line 1072
    and-long v14, v14, v16

    .line 1073
    .line 1074
    or-long/2addr v7, v14

    .line 1075
    invoke-static {v12, v7, v8, v11, v4}, Le1/j0;->b1(FJLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 1076
    .line 1077
    .line 1078
    move-result v7

    .line 1079
    if-nez v7, :cond_37

    .line 1080
    .line 1081
    if-eqz v5, :cond_36

    .line 1082
    .line 1083
    goto :goto_1b

    .line 1084
    :cond_36
    move v5, v10

    .line 1085
    goto :goto_1c

    .line 1086
    :cond_37
    :goto_1b
    move v5, v13

    .line 1087
    goto :goto_1c

    .line 1088
    :cond_38
    move/from16 p0, v7

    .line 1089
    .line 1090
    move-wide/from16 v16, v8

    .line 1091
    .line 1092
    :goto_1c
    iget-object v7, v0, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 1093
    .line 1094
    invoke-static {v7}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 1095
    .line 1096
    .line 1097
    move-result v7

    .line 1098
    if-eqz v7, :cond_3b

    .line 1099
    .line 1100
    invoke-virtual {v0}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v7

    .line 1104
    invoke-interface {v3}, Lg3/d;->e()J

    .line 1105
    .line 1106
    .line 1107
    move-result-wide v8

    .line 1108
    shr-long v8, v8, p0

    .line 1109
    .line 1110
    long-to-int v8, v8

    .line 1111
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1112
    .line 1113
    .line 1114
    move-result v8

    .line 1115
    invoke-static {v8}, Lcy0/a;->i(F)I

    .line 1116
    .line 1117
    .line 1118
    move-result v8

    .line 1119
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 1120
    .line 1121
    .line 1122
    move-result-object v9

    .line 1123
    invoke-interface {v2, v9}, Lk1/z0;->a(Lt4/m;)F

    .line 1124
    .line 1125
    .line 1126
    move-result v9

    .line 1127
    int-to-float v8, v8

    .line 1128
    neg-float v8, v8

    .line 1129
    invoke-virtual {v1, v9}, Lv3/j0;->w0(F)F

    .line 1130
    .line 1131
    .line 1132
    move-result v9

    .line 1133
    add-float/2addr v9, v8

    .line 1134
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1135
    .line 1136
    .line 1137
    move-result v8

    .line 1138
    int-to-long v11, v8

    .line 1139
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1140
    .line 1141
    .line 1142
    move-result v8

    .line 1143
    int-to-long v8, v8

    .line 1144
    shl-long v11, v11, p0

    .line 1145
    .line 1146
    and-long v8, v8, v16

    .line 1147
    .line 1148
    or-long/2addr v8, v11

    .line 1149
    const/high16 v11, 0x42b40000    # 90.0f

    .line 1150
    .line 1151
    invoke-static {v11, v8, v9, v7, v4}, Le1/j0;->b1(FJLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 1152
    .line 1153
    .line 1154
    move-result v7

    .line 1155
    if-nez v7, :cond_3a

    .line 1156
    .line 1157
    if-eqz v5, :cond_39

    .line 1158
    .line 1159
    goto :goto_1d

    .line 1160
    :cond_39
    move v5, v10

    .line 1161
    goto :goto_1e

    .line 1162
    :cond_3a
    :goto_1d
    move v5, v13

    .line 1163
    :cond_3b
    :goto_1e
    iget-object v7, v0, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 1164
    .line 1165
    invoke-static {v7}, Le1/f0;->f(Landroid/widget/EdgeEffect;)Z

    .line 1166
    .line 1167
    .line 1168
    move-result v7

    .line 1169
    if-eqz v7, :cond_3e

    .line 1170
    .line 1171
    invoke-virtual {v0}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v0

    .line 1175
    invoke-interface {v2}, Lk1/z0;->c()F

    .line 1176
    .line 1177
    .line 1178
    move-result v2

    .line 1179
    invoke-virtual {v1, v2}, Lv3/j0;->w0(F)F

    .line 1180
    .line 1181
    .line 1182
    move-result v1

    .line 1183
    invoke-interface {v3}, Lg3/d;->e()J

    .line 1184
    .line 1185
    .line 1186
    move-result-wide v7

    .line 1187
    shr-long v7, v7, p0

    .line 1188
    .line 1189
    long-to-int v2, v7

    .line 1190
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1191
    .line 1192
    .line 1193
    move-result v2

    .line 1194
    neg-float v2, v2

    .line 1195
    invoke-interface {v3}, Lg3/d;->e()J

    .line 1196
    .line 1197
    .line 1198
    move-result-wide v7

    .line 1199
    and-long v7, v7, v16

    .line 1200
    .line 1201
    long-to-int v3, v7

    .line 1202
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 1203
    .line 1204
    .line 1205
    move-result v3

    .line 1206
    neg-float v3, v3

    .line 1207
    add-float/2addr v3, v1

    .line 1208
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1209
    .line 1210
    .line 1211
    move-result v1

    .line 1212
    int-to-long v1, v1

    .line 1213
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 1214
    .line 1215
    .line 1216
    move-result v3

    .line 1217
    int-to-long v7, v3

    .line 1218
    shl-long v1, v1, p0

    .line 1219
    .line 1220
    and-long v7, v7, v16

    .line 1221
    .line 1222
    or-long/2addr v1, v7

    .line 1223
    const/high16 v3, 0x43340000    # 180.0f

    .line 1224
    .line 1225
    invoke-static {v3, v1, v2, v0, v4}, Le1/j0;->b1(FJLandroid/widget/EdgeEffect;Landroid/graphics/Canvas;)Z

    .line 1226
    .line 1227
    .line 1228
    move-result v0

    .line 1229
    if-nez v0, :cond_3c

    .line 1230
    .line 1231
    if-eqz v5, :cond_3d

    .line 1232
    .line 1233
    :cond_3c
    move v10, v13

    .line 1234
    :cond_3d
    move v5, v10

    .line 1235
    :cond_3e
    if-eqz v5, :cond_3f

    .line 1236
    .line 1237
    invoke-virtual {v6}, Le1/j;->d()V

    .line 1238
    .line 1239
    .line 1240
    :cond_3f
    :goto_1f
    return-void

    .line 1241
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public c1()Landroid/graphics/RenderNode;
    .locals 2

    .line 1
    iget-object v0, p0, Le1/j0;->w:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/graphics/RenderNode;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, Landroid/graphics/RenderNode;

    .line 8
    .line 9
    const-string v1, "AndroidEdgeEffectOverscrollEffect"

    .line 10
    .line 11
    invoke-direct {v0, v1}, Landroid/graphics/RenderNode;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Le1/j0;->w:Ljava/lang/Object;

    .line 15
    .line 16
    :cond_0
    return-object v0
.end method
