.class public final synthetic Lmc/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lmc/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmc/e;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lmc/e;->d:I

    .line 4
    .line 5
    iget-object v0, v0, Lmc/e;->e:Ljava/lang/Object;

    .line 6
    .line 7
    packed-switch v1, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    check-cast v0, Lqz0/d;

    .line 11
    .line 12
    sget-object v1, Lsz0/c;->b:Lsz0/c;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    new-array v2, v2, [Lsz0/g;

    .line 16
    .line 17
    new-instance v3, Lpg/m;

    .line 18
    .line 19
    const/16 v4, 0x8

    .line 20
    .line 21
    invoke-direct {v3, v0, v4}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 22
    .line 23
    .line 24
    const-string v4, "kotlinx.serialization.Polymorphic"

    .line 25
    .line 26
    invoke-static {v4, v1, v2, v3}, Lkp/x8;->d(Ljava/lang/String;Lkp/y8;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v0, v0, Lqz0/d;->a:Lhy0/d;

    .line 31
    .line 32
    const-string v2, "context"

    .line 33
    .line 34
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    new-instance v2, Lsz0/b;

    .line 38
    .line 39
    invoke-direct {v2, v1, v0}, Lsz0/b;-><init>(Lsz0/h;Lhy0/d;)V

    .line 40
    .line 41
    .line 42
    return-object v2

    .line 43
    :pswitch_0
    check-cast v0, Lt3/y;

    .line 44
    .line 45
    new-instance v1, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    const-string v2, "Layout changed:  "

    .line 48
    .line 49
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    return-object v0

    .line 60
    :pswitch_1
    check-cast v0, Le81/t;

    .line 61
    .line 62
    invoke-interface {v0}, Lz71/h;->getRepresentingScreen()Ls71/l;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    new-instance v1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    const-string v2, "navigateTo(): viewModelController = "

    .line 69
    .line 70
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    return-object v0

    .line 81
    :pswitch_2
    check-cast v0, Landroid/view/View;

    .line 82
    .line 83
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->g(Landroid/view/View;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    return-object v0

    .line 88
    :pswitch_3
    check-cast v0, Landroid/util/Size;

    .line 89
    .line 90
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/fragment/RPACompose;->i(Landroid/util/Size;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    return-object v0

    .line 95
    :pswitch_4
    check-cast v0, Lq4/b;

    .line 96
    .line 97
    iget-object v1, v0, Lq4/b;->f:Ll2/j1;

    .line 98
    .line 99
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v2

    .line 103
    check-cast v2, Ld3/e;

    .line 104
    .line 105
    iget-wide v2, v2, Ld3/e;->a:J

    .line 106
    .line 107
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    cmp-long v2, v2, v4

    .line 113
    .line 114
    if-nez v2, :cond_0

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_0
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    check-cast v2, Ld3/e;

    .line 122
    .line 123
    iget-wide v2, v2, Ld3/e;->a:J

    .line 124
    .line 125
    invoke-static {v2, v3}, Ld3/e;->e(J)Z

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    if-eqz v2, :cond_1

    .line 130
    .line 131
    :goto_0
    const/4 v0, 0x0

    .line 132
    goto :goto_1

    .line 133
    :cond_1
    iget-object v0, v0, Lq4/b;->d:Le3/l0;

    .line 134
    .line 135
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v1

    .line 139
    check-cast v1, Ld3/e;

    .line 140
    .line 141
    iget-wide v1, v1, Ld3/e;->a:J

    .line 142
    .line 143
    invoke-virtual {v0, v1, v2}, Le3/l0;->b(J)Landroid/graphics/Shader;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    :goto_1
    return-object v0

    .line 148
    :pswitch_5
    check-cast v0, Lq10/q;

    .line 149
    .line 150
    iget-object v0, v0, Lq10/q;->c:Lq10/c;

    .line 151
    .line 152
    new-instance v1, Lq10/b;

    .line 153
    .line 154
    const/4 v2, 0x0

    .line 155
    invoke-direct {v1, v2}, Lq10/b;-><init>(Z)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0, v1}, Lq10/c;->a(Lq10/b;)Lzy0/j;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    sget-object v1, Lge0/a;->d:Lge0/a;

    .line 163
    .line 164
    invoke-static {v0, v1}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 165
    .line 166
    .line 167
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    return-object v0

    .line 170
    :pswitch_6
    check-cast v0, Ld3/c;

    .line 171
    .line 172
    return-object v0

    .line 173
    :pswitch_7
    check-cast v0, Lpv0/g;

    .line 174
    .line 175
    new-instance v1, Llj0/a;

    .line 176
    .line 177
    iget-object v0, v0, Lpv0/g;->o:Lij0/a;

    .line 178
    .line 179
    const/4 v2, 0x0

    .line 180
    new-array v2, v2, [Ljava/lang/Object;

    .line 181
    .line 182
    check-cast v0, Ljj0/f;

    .line 183
    .line 184
    const v3, 0x7f1211fc

    .line 185
    .line 186
    .line 187
    invoke-virtual {v0, v3, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v0

    .line 191
    invoke-direct {v1, v0}, Llj0/a;-><init>(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    return-object v1

    .line 195
    :pswitch_8
    check-cast v0, Lph/i;

    .line 196
    .line 197
    sget-object v1, Lph/e;->a:Lph/e;

    .line 198
    .line 199
    invoke-virtual {v0, v1}, Lph/i;->a(Lph/f;)V

    .line 200
    .line 201
    .line 202
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 203
    .line 204
    return-object v0

    .line 205
    :pswitch_9
    move-object v1, v0

    .line 206
    check-cast v1, Lom/f;

    .line 207
    .line 208
    iget-object v0, v1, Lom/f;->a:Lbm/q;

    .line 209
    .line 210
    iget-boolean v2, v1, Lom/f;->f:Z

    .line 211
    .line 212
    iget-object v3, v1, Lom/f;->b:Lmm/n;

    .line 213
    .line 214
    invoke-interface {v0}, Lbm/q;->p0()Lu01/h;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    iget-object v0, v1, Lom/f;->c:Lom/c;

    .line 219
    .line 220
    const/4 v5, 0x0

    .line 221
    :try_start_0
    invoke-virtual {v0, v4}, Lom/c;->a(Lu01/h;)Lb81/a;

    .line 222
    .line 223
    .line 224
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 225
    :try_start_1
    invoke-interface {v4}, Ljava/io/Closeable;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 226
    .line 227
    .line 228
    move-object v0, v5

    .line 229
    goto :goto_3

    .line 230
    :catchall_0
    move-exception v0

    .line 231
    goto :goto_3

    .line 232
    :catchall_1
    move-exception v0

    .line 233
    move-object v6, v0

    .line 234
    :try_start_2
    invoke-interface {v4}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 235
    .line 236
    .line 237
    goto :goto_2

    .line 238
    :catchall_2
    move-exception v0

    .line 239
    invoke-static {v6, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 240
    .line 241
    .line 242
    :goto_2
    move-object v0, v6

    .line 243
    move-object v6, v5

    .line 244
    :goto_3
    if-nez v0, :cond_14

    .line 245
    .line 246
    iget-object v0, v6, Lb81/a;->e:Ljava/lang/Object;

    .line 247
    .line 248
    check-cast v0, Lil/g;

    .line 249
    .line 250
    iget-object v4, v0, Lil/g;->e:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v4, Lin/t0;

    .line 253
    .line 254
    const-string v7, "SVG document is empty"

    .line 255
    .line 256
    if-eqz v4, :cond_13

    .line 257
    .line 258
    iget-object v4, v4, Lin/e1;->o:Ld3/a;

    .line 259
    .line 260
    if-nez v4, :cond_2

    .line 261
    .line 262
    move-object v8, v5

    .line 263
    goto :goto_4

    .line 264
    :cond_2
    new-instance v8, Landroid/graphics/RectF;

    .line 265
    .line 266
    iget v9, v4, Ld3/a;->b:F

    .line 267
    .line 268
    iget v10, v4, Ld3/a;->c:F

    .line 269
    .line 270
    invoke-virtual {v4}, Ld3/a;->h()F

    .line 271
    .line 272
    .line 273
    move-result v11

    .line 274
    invoke-virtual {v4}, Ld3/a;->i()F

    .line 275
    .line 276
    .line 277
    move-result v4

    .line 278
    invoke-direct {v8, v9, v10, v11, v4}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 279
    .line 280
    .line 281
    :goto_4
    if-eqz v8, :cond_3

    .line 282
    .line 283
    new-instance v5, Lom/d;

    .line 284
    .line 285
    iget v4, v8, Landroid/graphics/RectF;->left:F

    .line 286
    .line 287
    iget v9, v8, Landroid/graphics/RectF;->top:F

    .line 288
    .line 289
    iget v10, v8, Landroid/graphics/RectF;->right:F

    .line 290
    .line 291
    iget v8, v8, Landroid/graphics/RectF;->bottom:F

    .line 292
    .line 293
    invoke-direct {v5, v4, v9, v10, v8}, Lom/d;-><init>(FFFF)V

    .line 294
    .line 295
    .line 296
    :cond_3
    iget-boolean v4, v1, Lom/f;->e:Z

    .line 297
    .line 298
    if-eqz v4, :cond_4

    .line 299
    .line 300
    if-eqz v5, :cond_4

    .line 301
    .line 302
    iget v4, v5, Lom/d;->c:F

    .line 303
    .line 304
    iget v8, v5, Lom/d;->a:F

    .line 305
    .line 306
    sub-float/2addr v4, v8

    .line 307
    iget v8, v5, Lom/d;->d:F

    .line 308
    .line 309
    iget v9, v5, Lom/d;->b:F

    .line 310
    .line 311
    sub-float/2addr v8, v9

    .line 312
    goto :goto_5

    .line 313
    :cond_4
    iget-object v4, v0, Lil/g;->e:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast v4, Lin/t0;

    .line 316
    .line 317
    if-eqz v4, :cond_12

    .line 318
    .line 319
    invoke-virtual {v0}, Lil/g;->A()Ld3/a;

    .line 320
    .line 321
    .line 322
    move-result-object v4

    .line 323
    iget v4, v4, Ld3/a;->d:F

    .line 324
    .line 325
    iget-object v8, v0, Lil/g;->e:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast v8, Lin/t0;

    .line 328
    .line 329
    if-eqz v8, :cond_11

    .line 330
    .line 331
    invoke-virtual {v0}, Lil/g;->A()Ld3/a;

    .line 332
    .line 333
    .line 334
    move-result-object v8

    .line 335
    iget v8, v8, Ld3/a;->e:F

    .line 336
    .line 337
    :goto_5
    iget-object v9, v3, Lmm/n;->b:Lnm/h;

    .line 338
    .line 339
    iget-object v10, v3, Lmm/n;->c:Lnm/g;

    .line 340
    .line 341
    sget-object v11, Lnm/h;->c:Lnm/h;

    .line 342
    .line 343
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 344
    .line 345
    .line 346
    move-result v9

    .line 347
    const/4 v11, 0x0

    .line 348
    if-eqz v9, :cond_6

    .line 349
    .line 350
    iget-object v1, v1, Lom/f;->d:Lay0/k;

    .line 351
    .line 352
    iget-object v9, v3, Lmm/n;->a:Landroid/content/Context;

    .line 353
    .line 354
    invoke-interface {v1, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v1

    .line 358
    check-cast v1, Ljava/lang/Number;

    .line 359
    .line 360
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 361
    .line 362
    .line 363
    move-result v1

    .line 364
    cmpl-float v9, v4, v11

    .line 365
    .line 366
    if-lez v9, :cond_5

    .line 367
    .line 368
    mul-float/2addr v4, v1

    .line 369
    :cond_5
    cmpl-float v9, v8, v11

    .line 370
    .line 371
    if-lez v9, :cond_6

    .line 372
    .line 373
    mul-float/2addr v8, v1

    .line 374
    :cond_6
    cmpl-float v1, v4, v11

    .line 375
    .line 376
    const/16 v9, 0x200

    .line 377
    .line 378
    if-lez v1, :cond_7

    .line 379
    .line 380
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 381
    .line 382
    .line 383
    move-result v12

    .line 384
    goto :goto_6

    .line 385
    :cond_7
    move v12, v9

    .line 386
    :goto_6
    cmpl-float v13, v8, v11

    .line 387
    .line 388
    if-lez v13, :cond_8

    .line 389
    .line 390
    invoke-static {v8}, Lcy0/a;->i(F)I

    .line 391
    .line 392
    .line 393
    move-result v9

    .line 394
    :cond_8
    iget-object v14, v3, Lmm/n;->b:Lnm/h;

    .line 395
    .line 396
    sget-object v15, Lmm/h;->b:Ld8/c;

    .line 397
    .line 398
    invoke-static {v3, v15}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 399
    .line 400
    .line 401
    move-result-object v15

    .line 402
    check-cast v15, Lnm/h;

    .line 403
    .line 404
    invoke-static {v12, v9, v14, v10, v15}, Lno/nordicsemi/android/ble/d;->d(IILnm/h;Lnm/g;Lnm/h;)J

    .line 405
    .line 406
    .line 407
    move-result-wide v14

    .line 408
    const/16 v9, 0x20

    .line 409
    .line 410
    move/from16 p0, v11

    .line 411
    .line 412
    shr-long v11, v14, v9

    .line 413
    .line 414
    long-to-int v9, v11

    .line 415
    const-wide v11, 0xffffffffL

    .line 416
    .line 417
    .line 418
    .line 419
    .line 420
    and-long/2addr v11, v14

    .line 421
    long-to-int v11, v11

    .line 422
    if-lez v1, :cond_c

    .line 423
    .line 424
    if-lez v13, :cond_c

    .line 425
    .line 426
    int-to-float v1, v9

    .line 427
    int-to-float v9, v11

    .line 428
    div-float/2addr v1, v4

    .line 429
    div-float/2addr v9, v8

    .line 430
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 431
    .line 432
    .line 433
    move-result v10

    .line 434
    if-eqz v10, :cond_a

    .line 435
    .line 436
    const/4 v11, 0x1

    .line 437
    if-ne v10, v11, :cond_9

    .line 438
    .line 439
    invoke-static {v1, v9}, Ljava/lang/Math;->min(FF)F

    .line 440
    .line 441
    .line 442
    move-result v1

    .line 443
    goto :goto_7

    .line 444
    :cond_9
    new-instance v0, La8/r0;

    .line 445
    .line 446
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 447
    .line 448
    .line 449
    throw v0

    .line 450
    :cond_a
    invoke-static {v1, v9}, Ljava/lang/Math;->max(FF)F

    .line 451
    .line 452
    .line 453
    move-result v1

    .line 454
    :goto_7
    mul-float v9, v1, v4

    .line 455
    .line 456
    float-to-int v9, v9

    .line 457
    mul-float/2addr v1, v8

    .line 458
    float-to-int v11, v1

    .line 459
    if-nez v5, :cond_c

    .line 460
    .line 461
    sub-float v4, v4, p0

    .line 462
    .line 463
    sub-float v8, v8, p0

    .line 464
    .line 465
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 466
    .line 467
    check-cast v1, Lin/t0;

    .line 468
    .line 469
    if-eqz v1, :cond_b

    .line 470
    .line 471
    new-instance v5, Ld3/a;

    .line 472
    .line 473
    move/from16 v10, p0

    .line 474
    .line 475
    invoke-direct {v5, v10, v10, v4, v8}, Ld3/a;-><init>(FFFF)V

    .line 476
    .line 477
    .line 478
    iput-object v5, v1, Lin/e1;->o:Ld3/a;

    .line 479
    .line 480
    goto :goto_8

    .line 481
    :cond_b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 482
    .line 483
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 484
    .line 485
    .line 486
    throw v0

    .line 487
    :cond_c
    :goto_8
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 488
    .line 489
    check-cast v1, Lin/t0;

    .line 490
    .line 491
    if-eqz v1, :cond_10

    .line 492
    .line 493
    const-string v4, "100%"

    .line 494
    .line 495
    invoke-static {v4}, Lin/j2;->s(Ljava/lang/String;)Lin/e0;

    .line 496
    .line 497
    .line 498
    move-result-object v5

    .line 499
    iput-object v5, v1, Lin/t0;->r:Lin/e0;

    .line 500
    .line 501
    iget-object v1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 502
    .line 503
    check-cast v1, Lin/t0;

    .line 504
    .line 505
    if-eqz v1, :cond_f

    .line 506
    .line 507
    invoke-static {v4}, Lin/j2;->s(Ljava/lang/String;)Lin/e0;

    .line 508
    .line 509
    .line 510
    move-result-object v4

    .line 511
    iput-object v4, v1, Lin/t0;->s:Lin/e0;

    .line 512
    .line 513
    sget-object v1, Lom/b;->a:Ld8/c;

    .line 514
    .line 515
    invoke-static {v3, v1}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 516
    .line 517
    .line 518
    move-result-object v1

    .line 519
    check-cast v1, Ljava/lang/String;

    .line 520
    .line 521
    if-eqz v1, :cond_d

    .line 522
    .line 523
    new-instance v3, Lb81/c;

    .line 524
    .line 525
    const/16 v4, 0xa

    .line 526
    .line 527
    invoke-direct {v3, v4}, Lb81/c;-><init>(I)V

    .line 528
    .line 529
    .line 530
    new-instance v4, Lin/o;

    .line 531
    .line 532
    const/4 v5, 0x2

    .line 533
    invoke-direct {v4, v5}, Lin/o;-><init>(I)V

    .line 534
    .line 535
    .line 536
    new-instance v5, Lin/c;

    .line 537
    .line 538
    invoke-direct {v5, v1}, Lin/c;-><init>(Ljava/lang/String;)V

    .line 539
    .line 540
    .line 541
    invoke-virtual {v5}, Li4/c;->R()V

    .line 542
    .line 543
    .line 544
    invoke-virtual {v4, v5}, Lin/o;->i(Lin/c;)Ld01/x;

    .line 545
    .line 546
    .line 547
    move-result-object v1

    .line 548
    iput-object v1, v3, Lb81/c;->e:Ljava/lang/Object;

    .line 549
    .line 550
    iput-object v3, v6, Lb81/a;->f:Ljava/lang/Object;

    .line 551
    .line 552
    :cond_d
    new-instance v1, Lom/g;

    .line 553
    .line 554
    iget-object v3, v6, Lb81/a;->f:Ljava/lang/Object;

    .line 555
    .line 556
    check-cast v3, Lb81/c;

    .line 557
    .line 558
    invoke-direct {v1, v0, v3, v9, v11}, Lom/g;-><init>(Lil/g;Lb81/c;II)V

    .line 559
    .line 560
    .line 561
    if-eqz v2, :cond_e

    .line 562
    .line 563
    invoke-static {v1}, Lyl/m;->i(Lyl/j;)Landroid/graphics/Bitmap;

    .line 564
    .line 565
    .line 566
    move-result-object v0

    .line 567
    new-instance v1, Lyl/a;

    .line 568
    .line 569
    invoke-direct {v1, v0}, Lyl/a;-><init>(Landroid/graphics/Bitmap;)V

    .line 570
    .line 571
    .line 572
    :cond_e
    new-instance v0, Lbm/i;

    .line 573
    .line 574
    invoke-direct {v0, v1, v2}, Lbm/i;-><init>(Lyl/j;Z)V

    .line 575
    .line 576
    .line 577
    return-object v0

    .line 578
    :cond_f
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 579
    .line 580
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 581
    .line 582
    .line 583
    throw v0

    .line 584
    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 585
    .line 586
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    throw v0

    .line 590
    :cond_11
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 591
    .line 592
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 593
    .line 594
    .line 595
    throw v0

    .line 596
    :cond_12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 597
    .line 598
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 599
    .line 600
    .line 601
    throw v0

    .line 602
    :cond_13
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 603
    .line 604
    invoke-direct {v0, v7}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 605
    .line 606
    .line 607
    throw v0

    .line 608
    :cond_14
    throw v0

    .line 609
    :pswitch_a
    check-cast v0, Loi/d;

    .line 610
    .line 611
    iget-object v1, v0, Loi/d;->b:Ljava/lang/String;

    .line 612
    .line 613
    invoke-static {v1}, Ljp/vb;->d(Ljava/lang/String;)Li3/a;

    .line 614
    .line 615
    .line 616
    move-result-object v1

    .line 617
    new-instance v2, Loi/e;

    .line 618
    .line 619
    iget-object v0, v0, Loi/d;->a:Ljava/lang/String;

    .line 620
    .line 621
    invoke-direct {v2, v0, v1}, Loi/e;-><init>(Ljava/lang/String;Li3/a;)V

    .line 622
    .line 623
    .line 624
    return-object v2

    .line 625
    :pswitch_b
    check-cast v0, Lfh/g;

    .line 626
    .line 627
    sget-object v1, Lfh/d;->a:Lfh/d;

    .line 628
    .line 629
    invoke-virtual {v0, v1}, Lfh/g;->a(Lfh/e;)V

    .line 630
    .line 631
    .line 632
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 633
    .line 634
    return-object v0

    .line 635
    :pswitch_c
    check-cast v0, Landroidx/compose/foundation/lazy/layout/b;

    .line 636
    .line 637
    iget-object v0, v0, Landroidx/compose/foundation/lazy/layout/b;->j:Lo1/v;

    .line 638
    .line 639
    if-eqz v0, :cond_15

    .line 640
    .line 641
    invoke-static {v0}, Lv3/f;->m(Lv3/p;)V

    .line 642
    .line 643
    .line 644
    :cond_15
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 645
    .line 646
    return-object v0

    .line 647
    :pswitch_d
    check-cast v0, Ljava/lang/SecurityException;

    .line 648
    .line 649
    invoke-static {v0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v0

    .line 653
    return-object v0

    .line 654
    :pswitch_e
    check-cast v0, Lnn0/t;

    .line 655
    .line 656
    iget-object v0, v0, Lnn0/t;->a:Lnn0/r;

    .line 657
    .line 658
    check-cast v0, Lln0/f;

    .line 659
    .line 660
    iget-object v1, v0, Lln0/f;->a:Lwe0/a;

    .line 661
    .line 662
    check-cast v1, Lwe0/c;

    .line 663
    .line 664
    invoke-virtual {v1}, Lwe0/c;->b()Z

    .line 665
    .line 666
    .line 667
    move-result v1

    .line 668
    if-eqz v1, :cond_1b

    .line 669
    .line 670
    iget-object v0, v0, Lln0/f;->c:Lyy0/c2;

    .line 671
    .line 672
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 673
    .line 674
    .line 675
    move-result-object v0

    .line 676
    check-cast v0, Lne0/s;

    .line 677
    .line 678
    instance-of v1, v0, Lne0/e;

    .line 679
    .line 680
    if-eqz v1, :cond_17

    .line 681
    .line 682
    :try_start_3
    check-cast v0, Lne0/e;

    .line 683
    .line 684
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 685
    .line 686
    check-cast v0, Lon0/t;

    .line 687
    .line 688
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 689
    .line 690
    .line 691
    move-result-object v1

    .line 692
    sget-object v2, Ljava/time/ZoneOffset;->UTC:Ljava/time/ZoneOffset;

    .line 693
    .line 694
    invoke-virtual {v1, v2}, Ljava/time/Instant;->atOffset(Ljava/time/ZoneOffset;)Ljava/time/OffsetDateTime;

    .line 695
    .line 696
    .line 697
    move-result-object v1

    .line 698
    iget-object v0, v0, Lon0/t;->h:Ljava/time/OffsetDateTime;

    .line 699
    .line 700
    invoke-virtual {v1, v0}, Ljava/time/OffsetDateTime;->isAfter(Ljava/time/OffsetDateTime;)Z

    .line 701
    .line 702
    .line 703
    move-result v0

    .line 704
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 705
    .line 706
    .line 707
    move-result-object v0

    .line 708
    new-instance v1, Lne0/e;

    .line 709
    .line 710
    invoke-direct {v1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 711
    .line 712
    .line 713
    goto :goto_9

    .line 714
    :catchall_3
    move-exception v0

    .line 715
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 716
    .line 717
    .line 718
    move-result-object v1

    .line 719
    :goto_9
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 720
    .line 721
    .line 722
    move-result-object v3

    .line 723
    if-nez v3, :cond_16

    .line 724
    .line 725
    goto :goto_a

    .line 726
    :cond_16
    new-instance v2, Lne0/c;

    .line 727
    .line 728
    const/4 v6, 0x0

    .line 729
    const/16 v7, 0x1e

    .line 730
    .line 731
    const/4 v4, 0x0

    .line 732
    const/4 v5, 0x0

    .line 733
    invoke-direct/range {v2 .. v7}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 734
    .line 735
    .line 736
    move-object v1, v2

    .line 737
    :goto_a
    move-object v0, v1

    .line 738
    check-cast v0, Lne0/s;

    .line 739
    .line 740
    goto :goto_b

    .line 741
    :cond_17
    instance-of v1, v0, Lne0/c;

    .line 742
    .line 743
    if-eqz v1, :cond_18

    .line 744
    .line 745
    goto :goto_b

    .line 746
    :cond_18
    instance-of v1, v0, Lne0/d;

    .line 747
    .line 748
    if-eqz v1, :cond_1a

    .line 749
    .line 750
    :goto_b
    instance-of v1, v0, Lne0/e;

    .line 751
    .line 752
    if-eqz v1, :cond_19

    .line 753
    .line 754
    check-cast v0, Lne0/e;

    .line 755
    .line 756
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 757
    .line 758
    check-cast v0, Ljava/lang/Boolean;

    .line 759
    .line 760
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 761
    .line 762
    .line 763
    move-result v0

    .line 764
    if-eqz v0, :cond_19

    .line 765
    .line 766
    goto :goto_c

    .line 767
    :cond_19
    const/4 v0, 0x1

    .line 768
    goto :goto_d

    .line 769
    :cond_1a
    new-instance v0, La8/r0;

    .line 770
    .line 771
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 772
    .line 773
    .line 774
    throw v0

    .line 775
    :cond_1b
    :goto_c
    const/4 v0, 0x0

    .line 776
    :goto_d
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 777
    .line 778
    .line 779
    move-result-object v0

    .line 780
    return-object v0

    .line 781
    :pswitch_f
    check-cast v0, Lmm0/a;

    .line 782
    .line 783
    new-instance v1, Ljava/lang/StringBuilder;

    .line 784
    .line 785
    const-string v2, "Changing night mode to "

    .line 786
    .line 787
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 788
    .line 789
    .line 790
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 791
    .line 792
    .line 793
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 794
    .line 795
    .line 796
    move-result-object v0

    .line 797
    return-object v0

    .line 798
    :pswitch_10
    check-cast v0, Lnh/u;

    .line 799
    .line 800
    sget-object v1, Lnh/k;->a:Lnh/k;

    .line 801
    .line 802
    invoke-virtual {v0, v1}, Lnh/u;->a(Lnh/q;)V

    .line 803
    .line 804
    .line 805
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 806
    .line 807
    return-object v0

    .line 808
    :pswitch_11
    check-cast v0, Ljava/io/UnsupportedEncodingException;

    .line 809
    .line 810
    invoke-static {v0}, Llp/od;->a(Ljava/lang/Throwable;)Ljava/lang/String;

    .line 811
    .line 812
    .line 813
    move-result-object v0

    .line 814
    const-string v1, "ISO-8859-1 encoding not supported on this device!\n"

    .line 815
    .line 816
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 817
    .line 818
    .line 819
    move-result-object v0

    .line 820
    return-object v0

    .line 821
    :pswitch_12
    check-cast v0, Lna/q;

    .line 822
    .line 823
    iget-object v1, v0, Lna/q;->d:Lua/b;

    .line 824
    .line 825
    iget-object v0, v0, Lna/q;->e:Ljava/lang/String;

    .line 826
    .line 827
    invoke-interface {v1, v0}, Lua/b;->open(Ljava/lang/String;)Lua/a;

    .line 828
    .line 829
    .line 830
    move-result-object v0

    .line 831
    return-object v0

    .line 832
    :pswitch_13
    check-cast v0, Lb81/c;

    .line 833
    .line 834
    const-string v1, ":memory:"

    .line 835
    .line 836
    invoke-virtual {v0, v1}, Lb81/c;->open(Ljava/lang/String;)Lua/a;

    .line 837
    .line 838
    .line 839
    move-result-object v0

    .line 840
    return-object v0

    .line 841
    :pswitch_14
    check-cast v0, Lxj0/f;

    .line 842
    .line 843
    invoke-static {v0}, Lzj0/d;->l(Lxj0/f;)Lcom/google/android/gms/maps/model/LatLng;

    .line 844
    .line 845
    .line 846
    move-result-object v0

    .line 847
    new-instance v1, Luu/l1;

    .line 848
    .line 849
    invoke-direct {v1, v0}, Luu/l1;-><init>(Lcom/google/android/gms/maps/model/LatLng;)V

    .line 850
    .line 851
    .line 852
    return-object v1

    .line 853
    :pswitch_15
    check-cast v0, Ljava/lang/Class;

    .line 854
    .line 855
    invoke-static {v0}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 856
    .line 857
    .line 858
    move-result-object v0

    .line 859
    sget-object v1, Lz11/a;->b:Landroidx/lifecycle/c1;

    .line 860
    .line 861
    if-eqz v1, :cond_1c

    .line 862
    .line 863
    const-string v2, "clazz"

    .line 864
    .line 865
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 866
    .line 867
    .line 868
    iget-object v1, v1, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 869
    .line 870
    check-cast v1, Li21/b;

    .line 871
    .line 872
    iget-object v1, v1, Li21/b;->d:Lk21/a;

    .line 873
    .line 874
    const/4 v2, 0x0

    .line 875
    invoke-virtual {v1, v0, v2, v2}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 876
    .line 877
    .line 878
    move-result-object v0

    .line 879
    return-object v0

    .line 880
    :cond_1c
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 881
    .line 882
    const-string v1, "KoinApplication has not been started"

    .line 883
    .line 884
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 885
    .line 886
    .line 887
    throw v0

    .line 888
    :pswitch_16
    check-cast v0, Lm10/c;

    .line 889
    .line 890
    iget-object v0, v0, Lm10/c;->a:Ljava/util/List;

    .line 891
    .line 892
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 893
    .line 894
    .line 895
    move-result v0

    .line 896
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 897
    .line 898
    .line 899
    move-result-object v0

    .line 900
    return-object v0

    .line 901
    :pswitch_17
    check-cast v0, Ljava/lang/Iterable;

    .line 902
    .line 903
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 904
    .line 905
    .line 906
    move-result-object v0

    .line 907
    return-object v0

    .line 908
    :pswitch_18
    check-cast v0, [Ljava/lang/Object;

    .line 909
    .line 910
    invoke-static {v0}, Lkotlin/jvm/internal/m;->j([Ljava/lang/Object;)Landroidx/collection/d1;

    .line 911
    .line 912
    .line 913
    move-result-object v0

    .line 914
    return-object v0

    .line 915
    :pswitch_19
    check-cast v0, Lmh/t;

    .line 916
    .line 917
    sget-object v1, Lmh/m;->a:Lmh/m;

    .line 918
    .line 919
    invoke-virtual {v0, v1}, Lmh/t;->b(Lmh/q;)V

    .line 920
    .line 921
    .line 922
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 923
    .line 924
    return-object v0

    .line 925
    :pswitch_1a
    check-cast v0, Lmg0/e;

    .line 926
    .line 927
    new-instance v1, Lmg0/b;

    .line 928
    .line 929
    invoke-direct {v1, v0}, Lmg0/b;-><init>(Lmg0/e;)V

    .line 930
    .line 931
    .line 932
    return-object v1

    .line 933
    :pswitch_1b
    check-cast v0, Lme/f;

    .line 934
    .line 935
    sget-object v1, Lme/b;->a:Lme/b;

    .line 936
    .line 937
    invoke-virtual {v0, v1}, Lme/f;->a(Lme/c;)V

    .line 938
    .line 939
    .line 940
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 941
    .line 942
    return-object v0

    .line 943
    :pswitch_1c
    check-cast v0, Lmc/p;

    .line 944
    .line 945
    sget-object v1, Lmc/g;->a:Lmc/g;

    .line 946
    .line 947
    invoke-virtual {v0, v1}, Lmc/p;->d(Lmc/l;)V

    .line 948
    .line 949
    .line 950
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 951
    .line 952
    return-object v0

    .line 953
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
