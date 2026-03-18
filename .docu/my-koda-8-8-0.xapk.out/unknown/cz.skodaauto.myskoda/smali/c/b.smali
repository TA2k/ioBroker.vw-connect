.class public final synthetic Lc/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroid/content/Context;Landroidx/lifecycle/x;Lb0/r;Ll2/b1;Lrb/b;)V
    .locals 1

    .line 1
    const/16 v0, 0x8

    iput v0, p0, Lc/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc/b;->f:Ljava/lang/Object;

    iput-object p3, p0, Lc/b;->g:Ljava/lang/Object;

    iput-object p4, p0, Lc/b;->i:Ljava/lang/Object;

    iput-object p5, p0, Lc/b;->h:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Lc/b;->d:I

    iput-object p1, p0, Lc/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc/b;->f:Ljava/lang/Object;

    iput-object p3, p0, Lc/b;->g:Ljava/lang/Object;

    iput-object p4, p0, Lc/b;->h:Ljava/lang/Object;

    iput-object p5, p0, Lc/b;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/String;Lyj/b;Lxh/e;Lh2/d6;Lyy0/l1;)V
    .locals 1

    .line 3
    const/4 v0, 0x7

    iput v0, p0, Lc/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc/b;->g:Ljava/lang/Object;

    iput-object p2, p0, Lc/b;->e:Ljava/lang/Object;

    iput-object p3, p0, Lc/b;->f:Ljava/lang/Object;

    iput-object p4, p0, Lc/b;->h:Ljava/lang/Object;

    iput-object p5, p0, Lc/b;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lvy0/b0;Ll2/b1;Lm1/t;Lgy0/j;Li2/c0;)V
    .locals 1

    .line 4
    const/4 v0, 0x4

    iput v0, p0, Lc/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lc/b;->i:Ljava/lang/Object;

    iput-object p3, p0, Lc/b;->f:Ljava/lang/Object;

    iput-object p4, p0, Lc/b;->g:Ljava/lang/Object;

    iput-object p5, p0, Lc/b;->h:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc/b;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    const/4 v4, 0x0

    .line 8
    const-string v5, "$this$sdkViewModel"

    .line 9
    .line 10
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v7, 0x1

    .line 13
    iget-object v8, v0, Lc/b;->i:Ljava/lang/Object;

    .line 14
    .line 15
    iget-object v9, v0, Lc/b;->h:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v10, v0, Lc/b;->g:Ljava/lang/Object;

    .line 18
    .line 19
    iget-object v11, v0, Lc/b;->f:Ljava/lang/Object;

    .line 20
    .line 21
    iget-object v0, v0, Lc/b;->e:Ljava/lang/Object;

    .line 22
    .line 23
    packed-switch v1, :pswitch_data_0

    .line 24
    .line 25
    .line 26
    check-cast v0, Lc2/g;

    .line 27
    .line 28
    check-cast v11, Ll4/p;

    .line 29
    .line 30
    check-cast v10, Ll4/v;

    .line 31
    .line 32
    check-cast v9, Lt1/p0;

    .line 33
    .line 34
    move-object v13, v8

    .line 35
    check-cast v13, Le3/p0;

    .line 36
    .line 37
    move-object/from16 v12, p1

    .line 38
    .line 39
    check-cast v12, Lv3/j0;

    .line 40
    .line 41
    invoke-virtual {v12}, Lv3/j0;->b()V

    .line 42
    .line 43
    .line 44
    iget-object v0, v0, Lc2/g;->c:Ll2/f1;

    .line 45
    .line 46
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 47
    .line 48
    .line 49
    move-result v20

    .line 50
    const/4 v0, 0x0

    .line 51
    cmpg-float v1, v20, v0

    .line 52
    .line 53
    if-nez v1, :cond_0

    .line 54
    .line 55
    goto/16 :goto_3

    .line 56
    .line 57
    :cond_0
    iget-wide v1, v10, Ll4/v;->b:J

    .line 58
    .line 59
    sget v4, Lg4/o0;->c:I

    .line 60
    .line 61
    const/16 v4, 0x20

    .line 62
    .line 63
    shr-long/2addr v1, v4

    .line 64
    long-to-int v1, v1

    .line 65
    invoke-interface {v11, v1}, Ll4/p;->R(I)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    invoke-virtual {v9}, Lt1/p0;->d()Lt1/j1;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    if-eqz v2, :cond_1

    .line 74
    .line 75
    iget-object v0, v2, Lt1/j1;->a:Lg4/l0;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Lg4/l0;->c(I)Ld3/c;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    goto :goto_0

    .line 82
    :cond_1
    new-instance v1, Ld3/c;

    .line 83
    .line 84
    invoke-direct {v1, v0, v0, v0, v0}, Ld3/c;-><init>(FFFF)V

    .line 85
    .line 86
    .line 87
    move-object v0, v1

    .line 88
    :goto_0
    sget v1, Lt1/x0;->a:F

    .line 89
    .line 90
    invoke-virtual {v12, v1}, Lv3/j0;->w0(F)F

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    float-to-double v1, v1

    .line 95
    invoke-static {v1, v2}, Ljava/lang/Math;->floor(D)D

    .line 96
    .line 97
    .line 98
    move-result-wide v1

    .line 99
    double-to-float v1, v1

    .line 100
    const/high16 v2, 0x3f800000    # 1.0f

    .line 101
    .line 102
    cmpg-float v5, v1, v2

    .line 103
    .line 104
    if-gez v5, :cond_2

    .line 105
    .line 106
    move v1, v2

    .line 107
    :cond_2
    iget v2, v0, Ld3/c;->a:F

    .line 108
    .line 109
    int-to-float v5, v3

    .line 110
    div-float v5, v1, v5

    .line 111
    .line 112
    add-float/2addr v2, v5

    .line 113
    iget-object v8, v12, Lv3/j0;->d:Lg3/b;

    .line 114
    .line 115
    invoke-interface {v8}, Lg3/d;->e()J

    .line 116
    .line 117
    .line 118
    move-result-wide v8

    .line 119
    shr-long/2addr v8, v4

    .line 120
    long-to-int v8, v8

    .line 121
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 122
    .line 123
    .line 124
    move-result v8

    .line 125
    sub-float/2addr v8, v5

    .line 126
    cmpl-float v9, v2, v8

    .line 127
    .line 128
    if-lez v9, :cond_3

    .line 129
    .line 130
    move v2, v8

    .line 131
    :cond_3
    cmpg-float v8, v2, v5

    .line 132
    .line 133
    if-gez v8, :cond_4

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_4
    move v5, v2

    .line 137
    :goto_1
    float-to-int v2, v1

    .line 138
    rem-int/2addr v2, v3

    .line 139
    if-ne v2, v7, :cond_5

    .line 140
    .line 141
    float-to-double v2, v5

    .line 142
    invoke-static {v2, v3}, Ljava/lang/Math;->floor(D)D

    .line 143
    .line 144
    .line 145
    move-result-wide v2

    .line 146
    double-to-float v2, v2

    .line 147
    const/high16 v3, 0x3f000000    # 0.5f

    .line 148
    .line 149
    add-float/2addr v2, v3

    .line 150
    goto :goto_2

    .line 151
    :cond_5
    float-to-double v2, v5

    .line 152
    invoke-static {v2, v3}, Ljava/lang/Math;->rint(D)D

    .line 153
    .line 154
    .line 155
    move-result-wide v2

    .line 156
    double-to-float v2, v2

    .line 157
    :goto_2
    iget v3, v0, Ld3/c;->b:F

    .line 158
    .line 159
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 160
    .line 161
    .line 162
    move-result v5

    .line 163
    int-to-long v7, v5

    .line 164
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 165
    .line 166
    .line 167
    move-result v3

    .line 168
    int-to-long v9, v3

    .line 169
    shl-long/2addr v7, v4

    .line 170
    const-wide v14, 0xffffffffL

    .line 171
    .line 172
    .line 173
    .line 174
    .line 175
    and-long/2addr v9, v14

    .line 176
    or-long/2addr v7, v9

    .line 177
    iget v0, v0, Ld3/c;->d:F

    .line 178
    .line 179
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 180
    .line 181
    .line 182
    move-result v2

    .line 183
    int-to-long v2, v2

    .line 184
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 185
    .line 186
    .line 187
    move-result v0

    .line 188
    int-to-long v9, v0

    .line 189
    shl-long/2addr v2, v4

    .line 190
    and-long v4, v9, v14

    .line 191
    .line 192
    or-long v16, v2, v4

    .line 193
    .line 194
    const/16 v19, 0x0

    .line 195
    .line 196
    const/16 v21, 0x1b0

    .line 197
    .line 198
    move/from16 v18, v1

    .line 199
    .line 200
    move-wide v14, v7

    .line 201
    invoke-static/range {v12 .. v21}, Lg3/d;->A0(Lg3/d;Le3/p;JJFIFI)V

    .line 202
    .line 203
    .line 204
    :goto_3
    return-object v6

    .line 205
    :pswitch_0
    move-object/from16 v28, v0

    .line 206
    .line 207
    check-cast v28, Landroid/content/Context;

    .line 208
    .line 209
    move-object/from16 v24, v11

    .line 210
    .line 211
    check-cast v24, Landroidx/lifecycle/x;

    .line 212
    .line 213
    move-object/from16 v25, v10

    .line 214
    .line 215
    check-cast v25, Lb0/r;

    .line 216
    .line 217
    move-object/from16 v26, v8

    .line 218
    .line 219
    check-cast v26, Ll2/b1;

    .line 220
    .line 221
    move-object/from16 v27, v9

    .line 222
    .line 223
    check-cast v27, Lrb/b;

    .line 224
    .line 225
    move-object/from16 v0, p1

    .line 226
    .line 227
    check-cast v0, Landroidx/compose/runtime/DisposableEffectScope;

    .line 228
    .line 229
    const-string v1, "$this$DisposableEffect"

    .line 230
    .line 231
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    sget-object v0, Lv0/f;->b:Lv0/f;

    .line 235
    .line 236
    invoke-static/range {v28 .. v28}, Llp/ua;->a(Landroid/content/Context;)Lk0/b;

    .line 237
    .line 238
    .line 239
    move-result-object v23

    .line 240
    new-instance v22, Lq0/f;

    .line 241
    .line 242
    const/16 v29, 0x1

    .line 243
    .line 244
    invoke-direct/range {v22 .. v29}, Lq0/f;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 245
    .line 246
    .line 247
    move-object/from16 v1, v22

    .line 248
    .line 249
    move-object/from16 v0, v23

    .line 250
    .line 251
    invoke-virtual/range {v28 .. v28}, Landroid/content/Context;->getMainExecutor()Ljava/util/concurrent/Executor;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    invoke-virtual {v0, v2, v1}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 256
    .line 257
    .line 258
    new-instance v1, La2/j;

    .line 259
    .line 260
    const/16 v2, 0xd

    .line 261
    .line 262
    invoke-direct {v1, v0, v2}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 263
    .line 264
    .line 265
    return-object v1

    .line 266
    :pswitch_1
    check-cast v10, Ljava/lang/String;

    .line 267
    .line 268
    check-cast v0, Lyj/b;

    .line 269
    .line 270
    move-object v7, v11

    .line 271
    check-cast v7, Lxh/e;

    .line 272
    .line 273
    check-cast v9, Lh2/d6;

    .line 274
    .line 275
    check-cast v8, Lyy0/l1;

    .line 276
    .line 277
    move-object/from16 v1, p1

    .line 278
    .line 279
    check-cast v1, Lhi/a;

    .line 280
    .line 281
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    const-class v2, Llg/h;

    .line 285
    .line 286
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 287
    .line 288
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 289
    .line 290
    .line 291
    move-result-object v2

    .line 292
    check-cast v1, Lii/a;

    .line 293
    .line 294
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    move-object v13, v1

    .line 299
    check-cast v13, Llg/h;

    .line 300
    .line 301
    new-instance v6, Ljd/b;

    .line 302
    .line 303
    const/16 v17, 0x0

    .line 304
    .line 305
    const/16 v18, 0x12

    .line 306
    .line 307
    const/4 v12, 0x2

    .line 308
    const-class v14, Llg/h;

    .line 309
    .line 310
    const-string v15, "getSubscriptionOverview"

    .line 311
    .line 312
    const-string v16, "getSubscriptionOverview-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 313
    .line 314
    move-object v11, v6

    .line 315
    invoke-direct/range {v11 .. v18}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 316
    .line 317
    .line 318
    new-instance v3, Lqg/n;

    .line 319
    .line 320
    new-instance v1, Llo0/b;

    .line 321
    .line 322
    const/16 v2, 0x10

    .line 323
    .line 324
    invoke-direct {v1, v2, v13, v10, v4}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 325
    .line 326
    .line 327
    move-object v4, v9

    .line 328
    move-object v9, v8

    .line 329
    move-object v8, v4

    .line 330
    move-object v5, v0

    .line 331
    move-object v4, v10

    .line 332
    move-object v10, v1

    .line 333
    invoke-direct/range {v3 .. v10}, Lqg/n;-><init>(Ljava/lang/String;Lyj/b;Ljd/b;Lxh/e;Lh2/d6;Lyy0/l1;Llo0/b;)V

    .line 334
    .line 335
    .line 336
    return-object v3

    .line 337
    :pswitch_2
    move-object v7, v0

    .line 338
    check-cast v7, Lac/a0;

    .line 339
    .line 340
    check-cast v11, Lxh/e;

    .line 341
    .line 342
    check-cast v10, Lac/e;

    .line 343
    .line 344
    move-object v6, v9

    .line 345
    check-cast v6, Log/i;

    .line 346
    .line 347
    move-object v9, v8

    .line 348
    check-cast v9, Ljava/util/List;

    .line 349
    .line 350
    move-object/from16 v0, p1

    .line 351
    .line 352
    check-cast v0, Lhi/a;

    .line 353
    .line 354
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    new-instance v4, Log/h;

    .line 358
    .line 359
    move-object v5, v10

    .line 360
    move-object v8, v11

    .line 361
    invoke-direct/range {v4 .. v9}, Log/h;-><init>(Lac/e;Log/i;Lac/a0;Lxh/e;Ljava/util/List;)V

    .line 362
    .line 363
    .line 364
    return-object v4

    .line 365
    :pswitch_3
    check-cast v0, Lyj/b;

    .line 366
    .line 367
    check-cast v11, Ljava/util/List;

    .line 368
    .line 369
    check-cast v10, Lgz0/p;

    .line 370
    .line 371
    check-cast v9, Lgz0/p;

    .line 372
    .line 373
    check-cast v8, Landroid/content/Context;

    .line 374
    .line 375
    move-object/from16 v1, p1

    .line 376
    .line 377
    check-cast v1, Lhi/a;

    .line 378
    .line 379
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 380
    .line 381
    .line 382
    const-class v2, Led/e;

    .line 383
    .line 384
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 385
    .line 386
    invoke-virtual {v4, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 387
    .line 388
    .line 389
    move-result-object v2

    .line 390
    check-cast v1, Lii/a;

    .line 391
    .line 392
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 393
    .line 394
    .line 395
    move-result-object v1

    .line 396
    move-object v14, v1

    .line 397
    check-cast v14, Led/e;

    .line 398
    .line 399
    new-instance v5, Ljd/j;

    .line 400
    .line 401
    new-instance v6, Ljd/b;

    .line 402
    .line 403
    const/16 v18, 0x0

    .line 404
    .line 405
    const/16 v19, 0x0

    .line 406
    .line 407
    const/4 v13, 0x2

    .line 408
    const-class v15, Led/e;

    .line 409
    .line 410
    const-string v16, "getHomeChargingRecordsPdf"

    .line 411
    .line 412
    const-string v17, "getHomeChargingRecordsPdf-gIAlu-s(Lcariad/charging/multicharge/kitten/charginghistory/models/home/HomeChargingRecordsPdfRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 413
    .line 414
    move-object v12, v6

    .line 415
    invoke-direct/range {v12 .. v19}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 416
    .line 417
    .line 418
    new-instance v7, Laa/y;

    .line 419
    .line 420
    invoke-direct {v7, v8, v3}, Laa/y;-><init>(Landroid/content/Context;I)V

    .line 421
    .line 422
    .line 423
    move-object v8, v11

    .line 424
    move-object v11, v9

    .line 425
    move-object v9, v8

    .line 426
    move-object v8, v0

    .line 427
    invoke-direct/range {v5 .. v11}, Ljd/j;-><init>(Ljd/b;Laa/y;Lyj/b;Ljava/util/List;Lgz0/p;Lgz0/p;)V

    .line 428
    .line 429
    .line 430
    return-object v5

    .line 431
    :pswitch_4
    check-cast v0, Lvy0/b0;

    .line 432
    .line 433
    check-cast v8, Ll2/b1;

    .line 434
    .line 435
    move-object v13, v11

    .line 436
    check-cast v13, Lm1/t;

    .line 437
    .line 438
    move-object v15, v10

    .line 439
    check-cast v15, Lgy0/j;

    .line 440
    .line 441
    move-object/from16 v16, v9

    .line 442
    .line 443
    check-cast v16, Li2/c0;

    .line 444
    .line 445
    move-object/from16 v1, p1

    .line 446
    .line 447
    check-cast v1, Ljava/lang/Integer;

    .line 448
    .line 449
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 450
    .line 451
    .line 452
    move-result v14

    .line 453
    sget v1, Lh2/m3;->a:F

    .line 454
    .line 455
    invoke-interface {v8}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 456
    .line 457
    .line 458
    move-result-object v1

    .line 459
    check-cast v1, Ljava/lang/Boolean;

    .line 460
    .line 461
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 462
    .line 463
    .line 464
    move-result v1

    .line 465
    xor-int/2addr v1, v7

    .line 466
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 467
    .line 468
    .line 469
    move-result-object v1

    .line 470
    invoke-interface {v8, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 471
    .line 472
    .line 473
    new-instance v12, Lci0/a;

    .line 474
    .line 475
    const/16 v17, 0x0

    .line 476
    .line 477
    const/16 v18, 0x1

    .line 478
    .line 479
    invoke-direct/range {v12 .. v18}, Lci0/a;-><init>(Ljava/lang/Object;ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 480
    .line 481
    .line 482
    const/4 v1, 0x3

    .line 483
    invoke-static {v0, v4, v4, v12, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 484
    .line 485
    .line 486
    return-object v6

    .line 487
    :pswitch_5
    check-cast v0, Lb0/d1;

    .line 488
    .line 489
    check-cast v11, Lkotlin/jvm/internal/f0;

    .line 490
    .line 491
    check-cast v10, Lkotlin/jvm/internal/c0;

    .line 492
    .line 493
    check-cast v9, Lg1/u2;

    .line 494
    .line 495
    check-cast v8, Lkotlin/jvm/internal/b0;

    .line 496
    .line 497
    move-object/from16 v1, p1

    .line 498
    .line 499
    check-cast v1, Ljava/lang/Float;

    .line 500
    .line 501
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 502
    .line 503
    .line 504
    move-result v1

    .line 505
    iget-object v3, v0, Lb0/d1;->i:Ljava/lang/Object;

    .line 506
    .line 507
    check-cast v3, Lxy0/j;

    .line 508
    .line 509
    invoke-static {v3}, Lb0/d1;->j(Lxy0/j;)Lg1/r1;

    .line 510
    .line 511
    .line 512
    move-result-object v3

    .line 513
    if-eqz v3, :cond_6

    .line 514
    .line 515
    invoke-virtual {v0, v3}, Lb0/d1;->k(Lg1/r1;)V

    .line 516
    .line 517
    .line 518
    iget-object v0, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 519
    .line 520
    check-cast v0, Lg1/r1;

    .line 521
    .line 522
    invoke-virtual {v0, v3}, Lg1/r1;->a(Lg1/r1;)Lg1/r1;

    .line 523
    .line 524
    .line 525
    move-result-object v0

    .line 526
    iput-object v0, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 527
    .line 528
    iget-wide v4, v0, Lg1/r1;->a:J

    .line 529
    .line 530
    invoke-virtual {v9, v4, v5}, Lg1/u2;->e(J)J

    .line 531
    .line 532
    .line 533
    move-result-wide v4

    .line 534
    invoke-virtual {v9, v4, v5}, Lg1/u2;->g(J)F

    .line 535
    .line 536
    .line 537
    move-result v0

    .line 538
    iput v0, v10, Lkotlin/jvm/internal/c0;->d:F

    .line 539
    .line 540
    sub-float/2addr v0, v1

    .line 541
    invoke-static {v0}, Lg1/q1;->a(F)Z

    .line 542
    .line 543
    .line 544
    move-result v0

    .line 545
    xor-int/2addr v0, v7

    .line 546
    iput-boolean v0, v8, Lkotlin/jvm/internal/b0;->d:Z

    .line 547
    .line 548
    :cond_6
    if-eqz v3, :cond_7

    .line 549
    .line 550
    move v2, v7

    .line 551
    :cond_7
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 552
    .line 553
    .line 554
    move-result-object v0

    .line 555
    return-object v0

    .line 556
    :pswitch_6
    check-cast v0, Lkotlin/jvm/internal/b0;

    .line 557
    .line 558
    check-cast v11, Ljava/util/ArrayList;

    .line 559
    .line 560
    check-cast v10, Lkotlin/jvm/internal/d0;

    .line 561
    .line 562
    check-cast v9, Lca/g;

    .line 563
    .line 564
    check-cast v8, Landroid/os/Bundle;

    .line 565
    .line 566
    move-object/from16 v1, p1

    .line 567
    .line 568
    check-cast v1, Lz9/k;

    .line 569
    .line 570
    const-string v2, "entry"

    .line 571
    .line 572
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    iput-boolean v7, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 576
    .line 577
    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 578
    .line 579
    .line 580
    move-result v0

    .line 581
    const/4 v2, -0x1

    .line 582
    if-eq v0, v2, :cond_8

    .line 583
    .line 584
    iget v2, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 585
    .line 586
    add-int/2addr v0, v7

    .line 587
    invoke-virtual {v11, v2, v0}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    .line 588
    .line 589
    .line 590
    move-result-object v2

    .line 591
    iput v0, v10, Lkotlin/jvm/internal/d0;->d:I

    .line 592
    .line 593
    goto :goto_4

    .line 594
    :cond_8
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 595
    .line 596
    :goto_4
    iget-object v0, v1, Lz9/k;->e:Lz9/u;

    .line 597
    .line 598
    invoke-virtual {v9, v0, v8, v1, v2}, Lca/g;->a(Lz9/u;Landroid/os/Bundle;Lz9/k;Ljava/util/List;)V

    .line 599
    .line 600
    .line 601
    return-object v6

    .line 602
    :pswitch_7
    check-cast v0, Ll4/v;

    .line 603
    .line 604
    check-cast v11, Lc2/b;

    .line 605
    .line 606
    check-cast v10, Ll4/j;

    .line 607
    .line 608
    check-cast v9, Lkv0/e;

    .line 609
    .line 610
    check-cast v8, Lay0/k;

    .line 611
    .line 612
    move-object/from16 v1, p1

    .line 613
    .line 614
    check-cast v1, Lc2/p;

    .line 615
    .line 616
    iget-object v2, v11, Lc2/b;->a:Lc2/l;

    .line 617
    .line 618
    iput-object v0, v1, Lc2/p;->h:Ll4/v;

    .line 619
    .line 620
    iput-object v10, v1, Lc2/p;->i:Ll4/j;

    .line 621
    .line 622
    iput-object v9, v1, Lc2/p;->c:Lay0/k;

    .line 623
    .line 624
    iput-object v8, v1, Lc2/p;->d:Lay0/k;

    .line 625
    .line 626
    if-eqz v2, :cond_9

    .line 627
    .line 628
    iget-object v0, v2, Lc2/l;->s:Lt1/p0;

    .line 629
    .line 630
    goto :goto_5

    .line 631
    :cond_9
    move-object v0, v4

    .line 632
    :goto_5
    iput-object v0, v1, Lc2/p;->e:Lt1/p0;

    .line 633
    .line 634
    if-eqz v2, :cond_a

    .line 635
    .line 636
    iget-object v0, v2, Lc2/l;->t:Le2/w0;

    .line 637
    .line 638
    goto :goto_6

    .line 639
    :cond_a
    move-object v0, v4

    .line 640
    :goto_6
    iput-object v0, v1, Lc2/p;->f:Le2/w0;

    .line 641
    .line 642
    if-eqz v2, :cond_b

    .line 643
    .line 644
    sget-object v0, Lw3/h1;->s:Ll2/u2;

    .line 645
    .line 646
    invoke-static {v2, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 647
    .line 648
    .line 649
    move-result-object v0

    .line 650
    move-object v4, v0

    .line 651
    check-cast v4, Lw3/h2;

    .line 652
    .line 653
    :cond_b
    iput-object v4, v1, Lc2/p;->g:Lw3/h2;

    .line 654
    .line 655
    return-object v6

    .line 656
    :pswitch_8
    check-cast v0, Lc/a;

    .line 657
    .line 658
    check-cast v11, Le/h;

    .line 659
    .line 660
    check-cast v10, Ljava/lang/String;

    .line 661
    .line 662
    check-cast v9, Lf/a;

    .line 663
    .line 664
    check-cast v8, Ll2/b1;

    .line 665
    .line 666
    move-object/from16 v1, p1

    .line 667
    .line 668
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 669
    .line 670
    new-instance v1, Lc/c;

    .line 671
    .line 672
    invoke-direct {v1, v8, v2}, Lc/c;-><init>(Ljava/lang/Object;I)V

    .line 673
    .line 674
    .line 675
    invoke-virtual {v11, v10, v9, v1}, Le/h;->d(Ljava/lang/String;Lf/a;Le/b;)Le/g;

    .line 676
    .line 677
    .line 678
    move-result-object v1

    .line 679
    iput-object v1, v0, Lc/a;->a:Le/g;

    .line 680
    .line 681
    new-instance v1, La2/j;

    .line 682
    .line 683
    invoke-direct {v1, v0, v7}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 684
    .line 685
    .line 686
    return-object v1

    .line 687
    :pswitch_data_0
    .packed-switch 0x0
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
