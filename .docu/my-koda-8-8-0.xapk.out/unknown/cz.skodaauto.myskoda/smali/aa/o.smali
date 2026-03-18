.class public final synthetic Laa/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lcp0/t;Ljava/time/LocalDate;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    const/4 p1, 0x6

    iput p1, p0, Laa/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Laa/o;->e:Ljava/lang/Object;

    iput-object p3, p0, Laa/o;->f:Ljava/lang/Object;

    iput-object p4, p0, Laa/o;->g:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p4, p0, Laa/o;->d:I

    iput-object p1, p0, Laa/o;->e:Ljava/lang/Object;

    iput-object p2, p0, Laa/o;->f:Ljava/lang/Object;

    iput-object p3, p0, Laa/o;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 3
    iput p5, p0, Laa/o;->d:I

    iput-object p1, p0, Laa/o;->e:Ljava/lang/Object;

    iput-object p3, p0, Laa/o;->f:Ljava/lang/Object;

    iput-object p4, p0, Laa/o;->g:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/c0;Lg1/e2;Lkotlin/jvm/internal/c0;Lg1/d0;)V
    .locals 0

    .line 4
    const/16 p4, 0x10

    iput p4, p0, Laa/o;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laa/o;->e:Ljava/lang/Object;

    iput-object p2, p0, Laa/o;->f:Ljava/lang/Object;

    iput-object p3, p0, Laa/o;->g:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/o;->d:I

    .line 4
    .line 5
    const-string v2, "id"

    .line 6
    .line 7
    const-string v3, "Ordered"

    .line 8
    .line 9
    const-string v4, "Delivered"

    .line 10
    .line 11
    const v7, 0x799532c4

    .line 12
    .line 13
    .line 14
    const-string v8, "_connection"

    .line 15
    .line 16
    const-string v9, "$this$LazyColumn"

    .line 17
    .line 18
    const-string v10, "$this$sdkViewModel"

    .line 19
    .line 20
    const/4 v11, 0x0

    .line 21
    const/4 v13, 0x3

    .line 22
    const/4 v14, 0x2

    .line 23
    const/4 v15, 0x0

    .line 24
    sget-object v16, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    iget-object v6, v0, Laa/o;->g:Ljava/lang/Object;

    .line 28
    .line 29
    iget-object v12, v0, Laa/o;->f:Ljava/lang/Object;

    .line 30
    .line 31
    iget-object v0, v0, Laa/o;->e:Ljava/lang/Object;

    .line 32
    .line 33
    packed-switch v1, :pswitch_data_0

    .line 34
    .line 35
    .line 36
    move-object/from16 v21, v0

    .line 37
    .line 38
    check-cast v21, Ly1/i;

    .line 39
    .line 40
    move-object/from16 v22, v12

    .line 41
    .line 42
    check-cast v22, Lay0/a;

    .line 43
    .line 44
    move-object/from16 v23, v6

    .line 45
    .line 46
    check-cast v23, Lxh/e;

    .line 47
    .line 48
    move-object/from16 v0, p1

    .line 49
    .line 50
    check-cast v0, Lhi/a;

    .line 51
    .line 52
    invoke-static {v0, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 56
    .line 57
    const-class v2, Lec/c;

    .line 58
    .line 59
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    check-cast v0, Lii/a;

    .line 64
    .line 65
    invoke-virtual {v0, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v2

    .line 69
    move-object v5, v2

    .line 70
    check-cast v5, Lec/c;

    .line 71
    .line 72
    const-class v2, Ldj/f;

    .line 73
    .line 74
    invoke-virtual {v1, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    check-cast v0, Ldj/f;

    .line 83
    .line 84
    new-instance v20, Lic/q;

    .line 85
    .line 86
    new-instance v3, Lag/c;

    .line 87
    .line 88
    const/4 v9, 0x0

    .line 89
    const/16 v10, 0x19

    .line 90
    .line 91
    const/4 v4, 0x2

    .line 92
    const-class v6, Lec/c;

    .line 93
    .line 94
    const-string v7, "getConsents"

    .line 95
    .line 96
    const-string v8, "getConsents-gIAlu-s(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 97
    .line 98
    invoke-direct/range {v3 .. v10}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 99
    .line 100
    .line 101
    move-object/from16 v24, v3

    .line 102
    .line 103
    new-instance v3, Lag/c;

    .line 104
    .line 105
    const/16 v10, 0x1a

    .line 106
    .line 107
    const-class v6, Lec/c;

    .line 108
    .line 109
    const-string v7, "completeConsents"

    .line 110
    .line 111
    const-string v8, "completeConsents-gIAlu-s(Lcariad/charging/multicharge/common/presentation/consent/models/ConsentCompleteRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 112
    .line 113
    invoke-direct/range {v3 .. v10}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 114
    .line 115
    .line 116
    new-instance v6, Lc4/i;

    .line 117
    .line 118
    const/4 v12, 0x4

    .line 119
    const/4 v13, 0x6

    .line 120
    const/4 v7, 0x1

    .line 121
    const-class v9, Ldj/f;

    .line 122
    .line 123
    const-string v10, "refresh"

    .line 124
    .line 125
    const-string v11, "refresh()V"

    .line 126
    .line 127
    move-object v8, v0

    .line 128
    invoke-direct/range {v6 .. v13}, Lc4/i;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 129
    .line 130
    .line 131
    move-object/from16 v25, v3

    .line 132
    .line 133
    move-object/from16 v26, v6

    .line 134
    .line 135
    invoke-direct/range {v20 .. v26}, Lic/q;-><init>(Ly1/i;Lay0/a;Lxh/e;Lag/c;Lag/c;Lc4/i;)V

    .line 136
    .line 137
    .line 138
    return-object v20

    .line 139
    :pswitch_0
    check-cast v0, Lh40/h2;

    .line 140
    .line 141
    check-cast v12, Lay0/k;

    .line 142
    .line 143
    check-cast v6, Lay0/k;

    .line 144
    .line 145
    move-object/from16 v1, p1

    .line 146
    .line 147
    check-cast v1, Lm1/f;

    .line 148
    .line 149
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    sget-object v2, Li40/q;->o:Lt2/b;

    .line 153
    .line 154
    invoke-static {v1, v2, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 155
    .line 156
    .line 157
    new-instance v2, Lf30/h;

    .line 158
    .line 159
    const/16 v3, 0x13

    .line 160
    .line 161
    invoke-direct {v2, v3, v0, v12}, Lf30/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    new-instance v3, Lt2/b;

    .line 165
    .line 166
    const v4, -0x59050eb5

    .line 167
    .line 168
    .line 169
    invoke-direct {v3, v2, v5, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 170
    .line 171
    .line 172
    invoke-static {v1, v3, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 173
    .line 174
    .line 175
    iget-boolean v2, v0, Lh40/h2;->d:Z

    .line 176
    .line 177
    if-nez v2, :cond_1

    .line 178
    .line 179
    invoke-virtual {v0}, Lh40/h2;->b()Ljava/util/List;

    .line 180
    .line 181
    .line 182
    move-result-object v2

    .line 183
    check-cast v2, Ljava/util/ArrayList;

    .line 184
    .line 185
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    if-eqz v2, :cond_0

    .line 190
    .line 191
    goto :goto_0

    .line 192
    :cond_0
    invoke-virtual {v0}, Lh40/h2;->b()Ljava/util/List;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    new-instance v3, Li40/q0;

    .line 197
    .line 198
    invoke-direct {v3}, Li40/q0;-><init>()V

    .line 199
    .line 200
    .line 201
    check-cast v2, Ljava/util/ArrayList;

    .line 202
    .line 203
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 204
    .line 205
    .line 206
    move-result v4

    .line 207
    new-instance v8, Lc41/g;

    .line 208
    .line 209
    const/16 v9, 0x9

    .line 210
    .line 211
    invoke-direct {v8, v9, v3, v2}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    new-instance v3, Lal/n;

    .line 215
    .line 216
    invoke-direct {v3, v2, v13}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 217
    .line 218
    .line 219
    new-instance v9, Lal/o;

    .line 220
    .line 221
    const/4 v10, 0x4

    .line 222
    invoke-direct {v9, v2, v6, v0, v10}, Lal/o;-><init>(Ljava/util/List;Lay0/k;Ljava/lang/Object;I)V

    .line 223
    .line 224
    .line 225
    new-instance v0, Lt2/b;

    .line 226
    .line 227
    invoke-direct {v0, v9, v5, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v1, v4, v8, v3, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 231
    .line 232
    .line 233
    goto :goto_1

    .line 234
    :cond_1
    :goto_0
    new-instance v2, Lb50/c;

    .line 235
    .line 236
    const/16 v3, 0x18

    .line 237
    .line 238
    invoke-direct {v2, v0, v3}, Lb50/c;-><init>(Ljava/lang/Object;I)V

    .line 239
    .line 240
    .line 241
    new-instance v0, Lt2/b;

    .line 242
    .line 243
    const v3, 0x3db4710c

    .line 244
    .line 245
    .line 246
    invoke-direct {v0, v2, v5, v3}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 247
    .line 248
    .line 249
    invoke-static {v1, v0, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 250
    .line 251
    .line 252
    :goto_1
    return-object v16

    .line 253
    :pswitch_1
    check-cast v0, Lt3/s0;

    .line 254
    .line 255
    check-cast v12, Li2/j0;

    .line 256
    .line 257
    check-cast v6, Lt3/e1;

    .line 258
    .line 259
    move-object/from16 v1, p1

    .line 260
    .line 261
    check-cast v1, Lt3/d1;

    .line 262
    .line 263
    invoke-interface {v0}, Lt3/t;->I()Z

    .line 264
    .line 265
    .line 266
    move-result v0

    .line 267
    if-eqz v0, :cond_2

    .line 268
    .line 269
    iget-object v0, v12, Li2/j0;->r:Lg1/q;

    .line 270
    .line 271
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    iget-object v2, v12, Li2/j0;->r:Lg1/q;

    .line 276
    .line 277
    iget-object v2, v2, Lg1/q;->h:Ljava/lang/Object;

    .line 278
    .line 279
    check-cast v2, Ll2/h0;

    .line 280
    .line 281
    invoke-virtual {v2}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v2

    .line 285
    invoke-virtual {v0, v2}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    goto :goto_2

    .line 290
    :cond_2
    iget-object v0, v12, Li2/j0;->r:Lg1/q;

    .line 291
    .line 292
    invoke-virtual {v0}, Lg1/q;->k()F

    .line 293
    .line 294
    .line 295
    move-result v0

    .line 296
    :goto_2
    invoke-static {v12}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 297
    .line 298
    .line 299
    move-result-object v2

    .line 300
    iget-object v2, v2, Lv3/h0;->B:Lt4/m;

    .line 301
    .line 302
    sget-object v3, Lt4/m;->e:Lt4/m;

    .line 303
    .line 304
    if-ne v2, v3, :cond_3

    .line 305
    .line 306
    iget-object v2, v12, Li2/j0;->t:Lg1/w1;

    .line 307
    .line 308
    sget-object v3, Lg1/w1;->e:Lg1/w1;

    .line 309
    .line 310
    if-ne v2, v3, :cond_3

    .line 311
    .line 312
    const/high16 v17, -0x40800000    # -1.0f

    .line 313
    .line 314
    goto :goto_3

    .line 315
    :cond_3
    const/high16 v17, 0x3f800000    # 1.0f

    .line 316
    .line 317
    :goto_3
    iget-object v2, v12, Li2/j0;->t:Lg1/w1;

    .line 318
    .line 319
    sget-object v3, Lg1/w1;->e:Lg1/w1;

    .line 320
    .line 321
    if-ne v2, v3, :cond_4

    .line 322
    .line 323
    mul-float v17, v17, v0

    .line 324
    .line 325
    goto :goto_4

    .line 326
    :cond_4
    move/from16 v17, v11

    .line 327
    .line 328
    :goto_4
    sget-object v3, Lg1/w1;->d:Lg1/w1;

    .line 329
    .line 330
    if-ne v2, v3, :cond_5

    .line 331
    .line 332
    goto :goto_5

    .line 333
    :cond_5
    move v0, v11

    .line 334
    :goto_5
    iput-boolean v5, v1, Lt3/d1;->d:Z

    .line 335
    .line 336
    invoke-static/range {v17 .. v17}, Lcy0/a;->i(F)I

    .line 337
    .line 338
    .line 339
    move-result v2

    .line 340
    invoke-static {v0}, Lcy0/a;->i(F)I

    .line 341
    .line 342
    .line 343
    move-result v0

    .line 344
    invoke-virtual {v1, v6, v2, v0, v11}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 345
    .line 346
    .line 347
    iput-boolean v15, v1, Lt3/d1;->d:Z

    .line 348
    .line 349
    return-object v16

    .line 350
    :pswitch_2
    check-cast v0, Lt3/s0;

    .line 351
    .line 352
    check-cast v12, Li2/i0;

    .line 353
    .line 354
    check-cast v6, Lt3/e1;

    .line 355
    .line 356
    move-object/from16 v1, p1

    .line 357
    .line 358
    check-cast v1, Lt3/d1;

    .line 359
    .line 360
    invoke-interface {v0}, Lt3/t;->I()Z

    .line 361
    .line 362
    .line 363
    move-result v0

    .line 364
    if-eqz v0, :cond_6

    .line 365
    .line 366
    iget-object v0, v12, Li2/i0;->r:Li2/p;

    .line 367
    .line 368
    invoke-virtual {v0}, Li2/p;->d()Li2/u0;

    .line 369
    .line 370
    .line 371
    move-result-object v0

    .line 372
    iget-object v2, v12, Li2/i0;->r:Li2/p;

    .line 373
    .line 374
    iget-object v2, v2, Li2/p;->h:Ll2/h0;

    .line 375
    .line 376
    invoke-virtual {v2}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object v2

    .line 380
    invoke-virtual {v0, v2}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 381
    .line 382
    .line 383
    move-result v0

    .line 384
    goto :goto_6

    .line 385
    :cond_6
    iget-object v0, v12, Li2/i0;->r:Li2/p;

    .line 386
    .line 387
    invoke-virtual {v0}, Li2/p;->f()F

    .line 388
    .line 389
    .line 390
    move-result v0

    .line 391
    :goto_6
    iget-object v2, v12, Li2/i0;->t:Lg1/w1;

    .line 392
    .line 393
    sget-object v3, Lg1/w1;->e:Lg1/w1;

    .line 394
    .line 395
    if-ne v2, v3, :cond_7

    .line 396
    .line 397
    move v3, v0

    .line 398
    goto :goto_7

    .line 399
    :cond_7
    move v3, v11

    .line 400
    :goto_7
    sget-object v4, Lg1/w1;->d:Lg1/w1;

    .line 401
    .line 402
    if-ne v2, v4, :cond_8

    .line 403
    .line 404
    goto :goto_8

    .line 405
    :cond_8
    move v0, v11

    .line 406
    :goto_8
    iput-boolean v5, v1, Lt3/d1;->d:Z

    .line 407
    .line 408
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 409
    .line 410
    .line 411
    move-result v2

    .line 412
    invoke-static {v0}, Lcy0/a;->i(F)I

    .line 413
    .line 414
    .line 415
    move-result v0

    .line 416
    invoke-virtual {v1, v6, v2, v0, v11}, Lt3/d1;->g(Lt3/e1;IIF)V

    .line 417
    .line 418
    .line 419
    iput-boolean v15, v1, Lt3/d1;->d:Z

    .line 420
    .line 421
    return-object v16

    .line 422
    :pswitch_3
    check-cast v0, Ljava/lang/String;

    .line 423
    .line 424
    check-cast v12, Lvy0/b0;

    .line 425
    .line 426
    check-cast v6, Lh2/yb;

    .line 427
    .line 428
    move-object/from16 v1, p1

    .line 429
    .line 430
    check-cast v1, Ld4/l;

    .line 431
    .line 432
    new-instance v2, Li2/t;

    .line 433
    .line 434
    invoke-direct {v2, v15, v12, v6}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 435
    .line 436
    .line 437
    sget-object v3, Ld4/x;->a:[Lhy0/z;

    .line 438
    .line 439
    sget-object v3, Ld4/k;->c:Ld4/z;

    .line 440
    .line 441
    new-instance v4, Ld4/a;

    .line 442
    .line 443
    invoke-direct {v4, v0, v2}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 444
    .line 445
    .line 446
    invoke-virtual {v1, v3, v4}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 447
    .line 448
    .line 449
    return-object v16

    .line 450
    :pswitch_4
    check-cast v0, Landroidx/lifecycle/x;

    .line 451
    .line 452
    check-cast v12, Lay0/k;

    .line 453
    .line 454
    check-cast v6, Lay0/a;

    .line 455
    .line 456
    move-object/from16 v1, p1

    .line 457
    .line 458
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 459
    .line 460
    new-instance v1, Landroidx/lifecycle/m;

    .line 461
    .line 462
    invoke-direct {v1, v12, v14}, Landroidx/lifecycle/m;-><init>(Ljava/lang/Object;I)V

    .line 463
    .line 464
    .line 465
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 466
    .line 467
    .line 468
    move-result-object v2

    .line 469
    invoke-virtual {v2, v1}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 470
    .line 471
    .line 472
    new-instance v2, Laa/q;

    .line 473
    .line 474
    invoke-direct {v2, v6, v0, v1, v14}, Laa/q;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 475
    .line 476
    .line 477
    return-object v2

    .line 478
    :pswitch_5
    check-cast v0, Lhz0/o;

    .line 479
    .line 480
    check-cast v12, Lk1/z0;

    .line 481
    .line 482
    check-cast v6, Lx2/d;

    .line 483
    .line 484
    move-object/from16 v1, p1

    .line 485
    .line 486
    check-cast v1, Lv3/j0;

    .line 487
    .line 488
    invoke-virtual {v0}, Lhz0/o;->get()Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    check-cast v0, Ld3/e;

    .line 493
    .line 494
    iget-wide v2, v0, Ld3/e;->a:J

    .line 495
    .line 496
    const/16 v0, 0x20

    .line 497
    .line 498
    shr-long v4, v2, v0

    .line 499
    .line 500
    long-to-int v4, v4

    .line 501
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 502
    .line 503
    .line 504
    move-result v4

    .line 505
    cmpl-float v5, v4, v11

    .line 506
    .line 507
    if-lez v5, :cond_b

    .line 508
    .line 509
    sget v5, Lh2/c7;->a:F

    .line 510
    .line 511
    invoke-virtual {v1, v5}, Lv3/j0;->w0(F)F

    .line 512
    .line 513
    .line 514
    move-result v5

    .line 515
    iget-object v7, v1, Lv3/j0;->d:Lg3/b;

    .line 516
    .line 517
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 518
    .line 519
    .line 520
    move-result-object v8

    .line 521
    invoke-interface {v12, v8}, Lk1/z0;->b(Lt4/m;)F

    .line 522
    .line 523
    .line 524
    move-result v8

    .line 525
    invoke-virtual {v1, v8}, Lv3/j0;->w0(F)F

    .line 526
    .line 527
    .line 528
    move-result v8

    .line 529
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 530
    .line 531
    .line 532
    move-result-object v9

    .line 533
    invoke-interface {v12, v9}, Lk1/z0;->a(Lt4/m;)F

    .line 534
    .line 535
    .line 536
    move-result v9

    .line 537
    invoke-virtual {v1, v9}, Lv3/j0;->w0(F)F

    .line 538
    .line 539
    .line 540
    move-result v9

    .line 541
    invoke-static {v4}, Lcy0/a;->i(F)I

    .line 542
    .line 543
    .line 544
    move-result v10

    .line 545
    invoke-interface {v7}, Lg3/d;->e()J

    .line 546
    .line 547
    .line 548
    move-result-wide v12

    .line 549
    shr-long/2addr v12, v0

    .line 550
    long-to-int v12, v12

    .line 551
    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 552
    .line 553
    .line 554
    move-result v12

    .line 555
    sub-float/2addr v12, v8

    .line 556
    sub-float/2addr v12, v9

    .line 557
    invoke-static {v12}, Lcy0/a;->i(F)I

    .line 558
    .line 559
    .line 560
    move-result v9

    .line 561
    invoke-virtual {v1}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 562
    .line 563
    .line 564
    move-result-object v12

    .line 565
    invoke-interface {v6, v10, v9, v12}, Lx2/d;->a(IILt4/m;)I

    .line 566
    .line 567
    .line 568
    move-result v6

    .line 569
    int-to-float v6, v6

    .line 570
    add-float/2addr v6, v8

    .line 571
    int-to-float v8, v14

    .line 572
    div-float/2addr v4, v8

    .line 573
    add-float/2addr v6, v4

    .line 574
    sub-float v9, v6, v4

    .line 575
    .line 576
    sub-float/2addr v9, v5

    .line 577
    cmpg-float v10, v9, v11

    .line 578
    .line 579
    if-gez v10, :cond_9

    .line 580
    .line 581
    move/from16 v18, v11

    .line 582
    .line 583
    goto :goto_9

    .line 584
    :cond_9
    move/from16 v18, v9

    .line 585
    .line 586
    :goto_9
    add-float/2addr v6, v4

    .line 587
    add-float/2addr v6, v5

    .line 588
    invoke-interface {v7}, Lg3/d;->e()J

    .line 589
    .line 590
    .line 591
    move-result-wide v4

    .line 592
    shr-long/2addr v4, v0

    .line 593
    long-to-int v0, v4

    .line 594
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 595
    .line 596
    .line 597
    move-result v0

    .line 598
    cmpl-float v4, v6, v0

    .line 599
    .line 600
    if-lez v4, :cond_a

    .line 601
    .line 602
    move/from16 v20, v0

    .line 603
    .line 604
    goto :goto_a

    .line 605
    :cond_a
    move/from16 v20, v6

    .line 606
    .line 607
    :goto_a
    const-wide v4, 0xffffffffL

    .line 608
    .line 609
    .line 610
    .line 611
    .line 612
    and-long/2addr v2, v4

    .line 613
    long-to-int v0, v2

    .line 614
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 615
    .line 616
    .line 617
    move-result v0

    .line 618
    neg-float v2, v0

    .line 619
    div-float v19, v2, v8

    .line 620
    .line 621
    div-float v21, v0, v8

    .line 622
    .line 623
    iget-object v2, v7, Lg3/b;->e:Lgw0/c;

    .line 624
    .line 625
    invoke-virtual {v2}, Lgw0/c;->o()J

    .line 626
    .line 627
    .line 628
    move-result-wide v3

    .line 629
    invoke-virtual {v2}, Lgw0/c;->h()Le3/r;

    .line 630
    .line 631
    .line 632
    move-result-object v0

    .line 633
    invoke-interface {v0}, Le3/r;->o()V

    .line 634
    .line 635
    .line 636
    :try_start_0
    iget-object v0, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 637
    .line 638
    check-cast v0, Lbu/c;

    .line 639
    .line 640
    iget-object v0, v0, Lbu/c;->e:Ljava/lang/Object;

    .line 641
    .line 642
    check-cast v0, Lgw0/c;

    .line 643
    .line 644
    invoke-virtual {v0}, Lgw0/c;->h()Le3/r;

    .line 645
    .line 646
    .line 647
    move-result-object v17

    .line 648
    const/16 v22, 0x0

    .line 649
    .line 650
    invoke-interface/range {v17 .. v22}, Le3/r;->g(FFFFI)V

    .line 651
    .line 652
    .line 653
    invoke-virtual {v1}, Lv3/j0;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 654
    .line 655
    .line 656
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 657
    .line 658
    .line 659
    goto :goto_b

    .line 660
    :catchall_0
    move-exception v0

    .line 661
    invoke-static {v2, v3, v4}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->y(Lgw0/c;J)V

    .line 662
    .line 663
    .line 664
    throw v0

    .line 665
    :cond_b
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 666
    .line 667
    .line 668
    :goto_b
    return-object v16

    .line 669
    :pswitch_6
    check-cast v0, Lvy0/b0;

    .line 670
    .line 671
    check-cast v12, Lh2/r8;

    .line 672
    .line 673
    check-cast v6, Lay0/a;

    .line 674
    .line 675
    move-object/from16 v1, p1

    .line 676
    .line 677
    check-cast v1, Ljava/lang/Float;

    .line 678
    .line 679
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 680
    .line 681
    .line 682
    move-result v1

    .line 683
    new-instance v2, Lh2/l0;

    .line 684
    .line 685
    const/4 v3, 0x0

    .line 686
    invoke-direct {v2, v12, v1, v3, v5}, Lh2/l0;-><init>(Lh2/r8;FLkotlin/coroutines/Continuation;I)V

    .line 687
    .line 688
    .line 689
    invoke-static {v0, v3, v3, v2, v13}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 690
    .line 691
    .line 692
    move-result-object v0

    .line 693
    new-instance v1, Lh2/c6;

    .line 694
    .line 695
    invoke-direct {v1, v12, v6, v5}, Lh2/c6;-><init>(Lh2/r8;Lay0/a;I)V

    .line 696
    .line 697
    .line 698
    invoke-virtual {v0, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 699
    .line 700
    .line 701
    return-object v16

    .line 702
    :pswitch_7
    check-cast v0, Ljava/lang/Long;

    .line 703
    .line 704
    check-cast v12, Ljava/lang/Long;

    .line 705
    .line 706
    check-cast v6, Lay0/n;

    .line 707
    .line 708
    move-object/from16 v1, p1

    .line 709
    .line 710
    check-cast v1, Ljava/lang/Long;

    .line 711
    .line 712
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 713
    .line 714
    .line 715
    move-result-wide v2

    .line 716
    sget-object v4, Lh2/f4;->a:Lk1/a1;

    .line 717
    .line 718
    if-nez v0, :cond_d

    .line 719
    .line 720
    if-eqz v12, :cond_c

    .line 721
    .line 722
    goto :goto_d

    .line 723
    :cond_c
    :goto_c
    const/4 v3, 0x0

    .line 724
    goto :goto_e

    .line 725
    :cond_d
    :goto_d
    if-eqz v0, :cond_e

    .line 726
    .line 727
    if-eqz v12, :cond_e

    .line 728
    .line 729
    goto :goto_c

    .line 730
    :goto_e
    invoke-interface {v6, v1, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 731
    .line 732
    .line 733
    goto :goto_f

    .line 734
    :cond_e
    if-eqz v0, :cond_f

    .line 735
    .line 736
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 737
    .line 738
    .line 739
    move-result-wide v4

    .line 740
    cmp-long v2, v2, v4

    .line 741
    .line 742
    if-ltz v2, :cond_f

    .line 743
    .line 744
    invoke-interface {v6, v0, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 745
    .line 746
    .line 747
    goto :goto_f

    .line 748
    :cond_f
    const/4 v3, 0x0

    .line 749
    invoke-interface {v6, v1, v3}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    :goto_f
    return-object v16

    .line 753
    :pswitch_8
    check-cast v0, Ljava/lang/String;

    .line 754
    .line 755
    check-cast v12, Lhp0/f;

    .line 756
    .line 757
    check-cast v6, Lhp0/d;

    .line 758
    .line 759
    move-object/from16 v1, p1

    .line 760
    .line 761
    check-cast v1, Lua/a;

    .line 762
    .line 763
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 764
    .line 765
    .line 766
    const-string v2, "DELETE FROM composite_render WHERE vehicle_id = ? AND vehicle_type = ? AND view_type = ?"

    .line 767
    .line 768
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    :try_start_1
    invoke-interface {v1, v5, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 773
    .line 774
    .line 775
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 776
    .line 777
    .line 778
    move-result v0

    .line 779
    if-eqz v0, :cond_11

    .line 780
    .line 781
    if-ne v0, v5, :cond_10

    .line 782
    .line 783
    move-object v3, v4

    .line 784
    goto :goto_10

    .line 785
    :cond_10
    new-instance v0, La8/r0;

    .line 786
    .line 787
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 788
    .line 789
    .line 790
    throw v0

    .line 791
    :cond_11
    :goto_10
    invoke-interface {v1, v14, v3}, Lua/c;->w(ILjava/lang/String;)V

    .line 792
    .line 793
    .line 794
    invoke-static {v6}, Lgp0/a;->a(Lhp0/d;)Ljava/lang/String;

    .line 795
    .line 796
    .line 797
    move-result-object v0

    .line 798
    invoke-interface {v1, v13, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 799
    .line 800
    .line 801
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 802
    .line 803
    .line 804
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 805
    .line 806
    .line 807
    return-object v16

    .line 808
    :catchall_1
    move-exception v0

    .line 809
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 810
    .line 811
    .line 812
    throw v0

    .line 813
    :pswitch_9
    check-cast v0, Ljava/lang/String;

    .line 814
    .line 815
    check-cast v12, Lgp0/a;

    .line 816
    .line 817
    check-cast v6, Lhp0/f;

    .line 818
    .line 819
    move-object/from16 v1, p1

    .line 820
    .line 821
    check-cast v1, Lua/a;

    .line 822
    .line 823
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 824
    .line 825
    .line 826
    const-string v7, "SELECT * FROM composite_render WHERE vehicle_id = ? AND vehicle_type = ?"

    .line 827
    .line 828
    invoke-interface {v1, v7}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 829
    .line 830
    .line 831
    move-result-object v7

    .line 832
    :try_start_2
    invoke-interface {v7, v5, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 833
    .line 834
    .line 835
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    .line 836
    .line 837
    .line 838
    move-result v0

    .line 839
    if-eqz v0, :cond_13

    .line 840
    .line 841
    if-ne v0, v5, :cond_12

    .line 842
    .line 843
    move-object v3, v4

    .line 844
    goto :goto_11

    .line 845
    :cond_12
    new-instance v0, La8/r0;

    .line 846
    .line 847
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 848
    .line 849
    .line 850
    throw v0

    .line 851
    :cond_13
    :goto_11
    invoke-interface {v7, v14, v3}, Lua/c;->w(ILjava/lang/String;)V

    .line 852
    .line 853
    .line 854
    invoke-static {v7, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 855
    .line 856
    .line 857
    move-result v0

    .line 858
    const-string v2, "vehicle_id"

    .line 859
    .line 860
    invoke-static {v7, v2}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 861
    .line 862
    .line 863
    move-result v2

    .line 864
    const-string v3, "vehicle_type"

    .line 865
    .line 866
    invoke-static {v7, v3}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 867
    .line 868
    .line 869
    move-result v3

    .line 870
    const-string v4, "view_type"

    .line 871
    .line 872
    invoke-static {v7, v4}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 873
    .line 874
    .line 875
    move-result v4

    .line 876
    const-string v6, "modifications_adjust_space_left"

    .line 877
    .line 878
    invoke-static {v7, v6}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 879
    .line 880
    .line 881
    move-result v6

    .line 882
    const-string v8, "modifications_adjust_space_right"

    .line 883
    .line 884
    invoke-static {v7, v8}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 885
    .line 886
    .line 887
    move-result v8

    .line 888
    const-string v9, "modifications_adjust_space_top"

    .line 889
    .line 890
    invoke-static {v7, v9}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 891
    .line 892
    .line 893
    move-result v9

    .line 894
    const-string v10, "modifications_adjust_space_bottom"

    .line 895
    .line 896
    invoke-static {v7, v10}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 897
    .line 898
    .line 899
    move-result v10

    .line 900
    const-string v11, "modifications_flip_horizontal"

    .line 901
    .line 902
    invoke-static {v7, v11}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 903
    .line 904
    .line 905
    move-result v11

    .line 906
    const-string v13, "modifications_anchor_to"

    .line 907
    .line 908
    invoke-static {v7, v13}, Ljp/af;->d(Lua/c;Ljava/lang/String;)I

    .line 909
    .line 910
    .line 911
    move-result v13

    .line 912
    new-instance v14, Landroidx/collection/u;

    .line 913
    .line 914
    const/4 v5, 0x0

    .line 915
    invoke-direct {v14, v5}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 916
    .line 917
    .line 918
    :goto_12
    invoke-interface {v7}, Lua/c;->s0()Z

    .line 919
    .line 920
    .line 921
    move-result v5

    .line 922
    if-eqz v5, :cond_16

    .line 923
    .line 924
    move/from16 p0, v10

    .line 925
    .line 926
    move/from16 p1, v11

    .line 927
    .line 928
    invoke-interface {v7, v0}, Lua/c;->getLong(I)J

    .line 929
    .line 930
    .line 931
    move-result-wide v10

    .line 932
    invoke-virtual {v14, v10, v11}, Landroidx/collection/u;->c(J)I

    .line 933
    .line 934
    .line 935
    move-result v5

    .line 936
    if-ltz v5, :cond_14

    .line 937
    .line 938
    const/4 v5, 0x1

    .line 939
    goto :goto_13

    .line 940
    :cond_14
    move v5, v15

    .line 941
    :goto_13
    if-nez v5, :cond_15

    .line 942
    .line 943
    new-instance v5, Ljava/util/ArrayList;

    .line 944
    .line 945
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 946
    .line 947
    .line 948
    invoke-virtual {v14, v10, v11, v5}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 949
    .line 950
    .line 951
    :cond_15
    move/from16 v10, p0

    .line 952
    .line 953
    move/from16 v11, p1

    .line 954
    .line 955
    goto :goto_12

    .line 956
    :catchall_2
    move-exception v0

    .line 957
    goto/16 :goto_1e

    .line 958
    .line 959
    :cond_16
    move/from16 p0, v10

    .line 960
    .line 961
    move/from16 p1, v11

    .line 962
    .line 963
    invoke-interface {v7}, Lua/c;->reset()V

    .line 964
    .line 965
    .line 966
    invoke-virtual {v12, v1, v14}, Lgp0/a;->b(Lua/a;Landroidx/collection/u;)V

    .line 967
    .line 968
    .line 969
    new-instance v1, Ljava/util/ArrayList;

    .line 970
    .line 971
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 972
    .line 973
    .line 974
    :goto_14
    invoke-interface {v7}, Lua/c;->s0()Z

    .line 975
    .line 976
    .line 977
    move-result v5

    .line 978
    if-eqz v5, :cond_22

    .line 979
    .line 980
    invoke-interface {v7, v0}, Lua/c;->getLong(I)J

    .line 981
    .line 982
    .line 983
    move-result-wide v22

    .line 984
    invoke-interface {v7, v2}, Lua/c;->g0(I)Ljava/lang/String;

    .line 985
    .line 986
    .line 987
    move-result-object v24

    .line 988
    invoke-interface {v7, v3}, Lua/c;->g0(I)Ljava/lang/String;

    .line 989
    .line 990
    .line 991
    move-result-object v25

    .line 992
    invoke-interface {v7, v4}, Lua/c;->g0(I)Ljava/lang/String;

    .line 993
    .line 994
    .line 995
    move-result-object v26

    .line 996
    invoke-interface {v7, v6}, Lua/c;->isNull(I)Z

    .line 997
    .line 998
    .line 999
    move-result v5

    .line 1000
    if-eqz v5, :cond_19

    .line 1001
    .line 1002
    invoke-interface {v7, v8}, Lua/c;->isNull(I)Z

    .line 1003
    .line 1004
    .line 1005
    move-result v5

    .line 1006
    if-eqz v5, :cond_19

    .line 1007
    .line 1008
    invoke-interface {v7, v9}, Lua/c;->isNull(I)Z

    .line 1009
    .line 1010
    .line 1011
    move-result v5

    .line 1012
    if-eqz v5, :cond_19

    .line 1013
    .line 1014
    move/from16 v5, p0

    .line 1015
    .line 1016
    invoke-interface {v7, v5}, Lua/c;->isNull(I)Z

    .line 1017
    .line 1018
    .line 1019
    move-result v10

    .line 1020
    if-eqz v10, :cond_18

    .line 1021
    .line 1022
    move/from16 v10, p1

    .line 1023
    .line 1024
    invoke-interface {v7, v10}, Lua/c;->isNull(I)Z

    .line 1025
    .line 1026
    .line 1027
    move-result v11

    .line 1028
    if-eqz v11, :cond_1a

    .line 1029
    .line 1030
    invoke-interface {v7, v13}, Lua/c;->isNull(I)Z

    .line 1031
    .line 1032
    .line 1033
    move-result v11

    .line 1034
    if-nez v11, :cond_17

    .line 1035
    .line 1036
    goto :goto_16

    .line 1037
    :cond_17
    const/16 v27, 0x0

    .line 1038
    .line 1039
    goto/16 :goto_1d

    .line 1040
    .line 1041
    :cond_18
    :goto_15
    move/from16 v10, p1

    .line 1042
    .line 1043
    goto :goto_16

    .line 1044
    :cond_19
    move/from16 v5, p0

    .line 1045
    .line 1046
    goto :goto_15

    .line 1047
    :cond_1a
    :goto_16
    invoke-interface {v7, v6}, Lua/c;->isNull(I)Z

    .line 1048
    .line 1049
    .line 1050
    move-result v11

    .line 1051
    if-eqz v11, :cond_1b

    .line 1052
    .line 1053
    const/16 v28, 0x0

    .line 1054
    .line 1055
    goto :goto_17

    .line 1056
    :cond_1b
    invoke-interface {v7, v6}, Lua/c;->getLong(I)J

    .line 1057
    .line 1058
    .line 1059
    move-result-wide v11

    .line 1060
    long-to-int v11, v11

    .line 1061
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v11

    .line 1065
    move-object/from16 v28, v11

    .line 1066
    .line 1067
    :goto_17
    invoke-interface {v7, v8}, Lua/c;->isNull(I)Z

    .line 1068
    .line 1069
    .line 1070
    move-result v11

    .line 1071
    if-eqz v11, :cond_1c

    .line 1072
    .line 1073
    const/16 v29, 0x0

    .line 1074
    .line 1075
    goto :goto_18

    .line 1076
    :cond_1c
    invoke-interface {v7, v8}, Lua/c;->getLong(I)J

    .line 1077
    .line 1078
    .line 1079
    move-result-wide v11

    .line 1080
    long-to-int v11, v11

    .line 1081
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v11

    .line 1085
    move-object/from16 v29, v11

    .line 1086
    .line 1087
    :goto_18
    invoke-interface {v7, v9}, Lua/c;->isNull(I)Z

    .line 1088
    .line 1089
    .line 1090
    move-result v11

    .line 1091
    if-eqz v11, :cond_1d

    .line 1092
    .line 1093
    const/16 v30, 0x0

    .line 1094
    .line 1095
    goto :goto_19

    .line 1096
    :cond_1d
    invoke-interface {v7, v9}, Lua/c;->getLong(I)J

    .line 1097
    .line 1098
    .line 1099
    move-result-wide v11

    .line 1100
    long-to-int v11, v11

    .line 1101
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1102
    .line 1103
    .line 1104
    move-result-object v11

    .line 1105
    move-object/from16 v30, v11

    .line 1106
    .line 1107
    :goto_19
    invoke-interface {v7, v5}, Lua/c;->isNull(I)Z

    .line 1108
    .line 1109
    .line 1110
    move-result v11

    .line 1111
    if-eqz v11, :cond_1e

    .line 1112
    .line 1113
    const/16 v31, 0x0

    .line 1114
    .line 1115
    goto :goto_1a

    .line 1116
    :cond_1e
    invoke-interface {v7, v5}, Lua/c;->getLong(I)J

    .line 1117
    .line 1118
    .line 1119
    move-result-wide v11

    .line 1120
    long-to-int v11, v11

    .line 1121
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1122
    .line 1123
    .line 1124
    move-result-object v11

    .line 1125
    move-object/from16 v31, v11

    .line 1126
    .line 1127
    :goto_1a
    invoke-interface {v7, v10}, Lua/c;->getLong(I)J

    .line 1128
    .line 1129
    .line 1130
    move-result-wide v11

    .line 1131
    long-to-int v11, v11

    .line 1132
    if-eqz v11, :cond_1f

    .line 1133
    .line 1134
    const/16 v32, 0x1

    .line 1135
    .line 1136
    goto :goto_1b

    .line 1137
    :cond_1f
    move/from16 v32, v15

    .line 1138
    .line 1139
    :goto_1b
    invoke-interface {v7, v13}, Lua/c;->isNull(I)Z

    .line 1140
    .line 1141
    .line 1142
    move-result v11

    .line 1143
    if-eqz v11, :cond_20

    .line 1144
    .line 1145
    const/16 v33, 0x0

    .line 1146
    .line 1147
    goto :goto_1c

    .line 1148
    :cond_20
    invoke-interface {v7, v13}, Lua/c;->g0(I)Ljava/lang/String;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v11

    .line 1152
    move-object/from16 v33, v11

    .line 1153
    .line 1154
    :goto_1c
    new-instance v27, Lgp0/e;

    .line 1155
    .line 1156
    invoke-direct/range {v27 .. v33}, Lgp0/e;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;Ljava/lang/Integer;ZLjava/lang/String;)V

    .line 1157
    .line 1158
    .line 1159
    :goto_1d
    new-instance v21, Lgp0/b;

    .line 1160
    .line 1161
    invoke-direct/range {v21 .. v27}, Lgp0/b;-><init>(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lgp0/e;)V

    .line 1162
    .line 1163
    .line 1164
    move-object/from16 v11, v21

    .line 1165
    .line 1166
    move/from16 p0, v2

    .line 1167
    .line 1168
    move/from16 p1, v3

    .line 1169
    .line 1170
    invoke-interface {v7, v0}, Lua/c;->getLong(I)J

    .line 1171
    .line 1172
    .line 1173
    move-result-wide v2

    .line 1174
    invoke-virtual {v14, v2, v3}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 1175
    .line 1176
    .line 1177
    move-result-object v2

    .line 1178
    if-eqz v2, :cond_21

    .line 1179
    .line 1180
    check-cast v2, Ljava/util/List;

    .line 1181
    .line 1182
    new-instance v3, Lgp0/f;

    .line 1183
    .line 1184
    invoke-direct {v3, v11, v2}, Lgp0/f;-><init>(Lgp0/b;Ljava/util/List;)V

    .line 1185
    .line 1186
    .line 1187
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1188
    .line 1189
    .line 1190
    move/from16 v2, p0

    .line 1191
    .line 1192
    move/from16 v3, p1

    .line 1193
    .line 1194
    move/from16 p0, v5

    .line 1195
    .line 1196
    move/from16 p1, v10

    .line 1197
    .line 1198
    goto/16 :goto_14

    .line 1199
    .line 1200
    :cond_21
    const-string v0, "Required value was null."

    .line 1201
    .line 1202
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 1203
    .line 1204
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1205
    .line 1206
    .line 1207
    throw v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 1208
    :cond_22
    invoke-interface {v7}, Ljava/lang/AutoCloseable;->close()V

    .line 1209
    .line 1210
    .line 1211
    return-object v1

    .line 1212
    :goto_1e
    invoke-interface {v7}, Ljava/lang/AutoCloseable;->close()V

    .line 1213
    .line 1214
    .line 1215
    throw v0

    .line 1216
    :pswitch_a
    check-cast v0, Lay0/n;

    .line 1217
    .line 1218
    check-cast v12, Ly1/i;

    .line 1219
    .line 1220
    check-cast v6, Lxh/e;

    .line 1221
    .line 1222
    move-object/from16 v1, p1

    .line 1223
    .line 1224
    check-cast v1, Lz9/w;

    .line 1225
    .line 1226
    const-string v3, "$this$NavHost"

    .line 1227
    .line 1228
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1229
    .line 1230
    .line 1231
    new-instance v3, Lge/a;

    .line 1232
    .line 1233
    invoke-direct {v3, v6, v15}, Lge/a;-><init>(Ljava/lang/Object;I)V

    .line 1234
    .line 1235
    .line 1236
    new-instance v4, Lt2/b;

    .line 1237
    .line 1238
    const v5, 0x2a360e32

    .line 1239
    .line 1240
    .line 1241
    const/4 v6, 0x1

    .line 1242
    invoke-direct {v4, v3, v6, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1243
    .line 1244
    .line 1245
    const/16 v29, 0xfe

    .line 1246
    .line 1247
    const-string v22, "/overview"

    .line 1248
    .line 1249
    const/16 v23, 0x0

    .line 1250
    .line 1251
    const/16 v24, 0x0

    .line 1252
    .line 1253
    const/16 v25, 0x0

    .line 1254
    .line 1255
    const/16 v26, 0x0

    .line 1256
    .line 1257
    const/16 v27, 0x0

    .line 1258
    .line 1259
    move-object/from16 v21, v1

    .line 1260
    .line 1261
    move-object/from16 v28, v4

    .line 1262
    .line 1263
    invoke-static/range {v21 .. v29}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 1264
    .line 1265
    .line 1266
    const-string v1, "downloadFileUseCaseFactory"

    .line 1267
    .line 1268
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1269
    .line 1270
    .line 1271
    const-string v1, "/pdfDownload"

    .line 1272
    .line 1273
    invoke-static {v1, v2}, Lzb/b;->E(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1274
    .line 1275
    .line 1276
    move-result-object v22

    .line 1277
    invoke-static {v1, v2}, Lzb/b;->D(Ljava/lang/String;Ljava/lang/String;)Ljava/util/List;

    .line 1278
    .line 1279
    .line 1280
    move-result-object v23

    .line 1281
    new-instance v1, Ldl/h;

    .line 1282
    .line 1283
    const/4 v2, 0x5

    .line 1284
    invoke-direct {v1, v2, v12, v0}, Ldl/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1285
    .line 1286
    .line 1287
    new-instance v0, Lt2/b;

    .line 1288
    .line 1289
    const v2, -0x4cb69fe4

    .line 1290
    .line 1291
    .line 1292
    const/4 v6, 0x1

    .line 1293
    invoke-direct {v0, v1, v6, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1294
    .line 1295
    .line 1296
    const/16 v29, 0xfc

    .line 1297
    .line 1298
    move-object/from16 v28, v0

    .line 1299
    .line 1300
    invoke-static/range {v21 .. v29}, Ljp/r0;->b(Lz9/w;Ljava/lang/String;Ljava/util/List;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lt2/b;I)V

    .line 1301
    .line 1302
    .line 1303
    return-object v16

    .line 1304
    :pswitch_b
    check-cast v0, Lh6/j;

    .line 1305
    .line 1306
    check-cast v12, Lp3/x;

    .line 1307
    .line 1308
    check-cast v6, Lg1/d1;

    .line 1309
    .line 1310
    move-object/from16 v1, p1

    .line 1311
    .line 1312
    check-cast v1, Lp3/t;

    .line 1313
    .line 1314
    const-wide/16 v2, 0x0

    .line 1315
    .line 1316
    invoke-static {v0, v1, v2, v3}, Ljp/le;->a(Lh6/j;Lp3/t;J)V

    .line 1317
    .line 1318
    .line 1319
    check-cast v12, Lp3/j0;

    .line 1320
    .line 1321
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1322
    .line 1323
    .line 1324
    invoke-static {v12}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 1325
    .line 1326
    .line 1327
    move-result-object v1

    .line 1328
    iget-object v1, v1, Lv3/h0;->C:Lw3/h2;

    .line 1329
    .line 1330
    invoke-interface {v1}, Lw3/h2;->e()F

    .line 1331
    .line 1332
    .line 1333
    move-result v1

    .line 1334
    invoke-static {v1, v1}, Lkp/g9;->a(FF)J

    .line 1335
    .line 1336
    .line 1337
    move-result-wide v1

    .line 1338
    invoke-virtual {v0, v1, v2}, Lh6/j;->e(J)J

    .line 1339
    .line 1340
    .line 1341
    move-result-wide v1

    .line 1342
    invoke-virtual {v0}, Lh6/j;->g()V

    .line 1343
    .line 1344
    .line 1345
    iget-object v0, v6, Lg1/d1;->x:Lxy0/j;

    .line 1346
    .line 1347
    if-eqz v0, :cond_25

    .line 1348
    .line 1349
    new-instance v3, Lg1/j0;

    .line 1350
    .line 1351
    sget-object v4, Lg1/f1;->a:Lg1/e1;

    .line 1352
    .line 1353
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 1354
    .line 1355
    .line 1356
    move-result v4

    .line 1357
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 1358
    .line 1359
    .line 1360
    move-result v4

    .line 1361
    if-eqz v4, :cond_23

    .line 1362
    .line 1363
    move v4, v11

    .line 1364
    goto :goto_1f

    .line 1365
    :cond_23
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 1366
    .line 1367
    .line 1368
    move-result v4

    .line 1369
    :goto_1f
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 1370
    .line 1371
    .line 1372
    move-result v5

    .line 1373
    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    .line 1374
    .line 1375
    .line 1376
    move-result v5

    .line 1377
    if-eqz v5, :cond_24

    .line 1378
    .line 1379
    goto :goto_20

    .line 1380
    :cond_24
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 1381
    .line 1382
    .line 1383
    move-result v11

    .line 1384
    :goto_20
    invoke-static {v4, v11}, Lkp/g9;->a(FF)J

    .line 1385
    .line 1386
    .line 1387
    move-result-wide v1

    .line 1388
    invoke-direct {v3, v1, v2}, Lg1/j0;-><init>(J)V

    .line 1389
    .line 1390
    .line 1391
    invoke-interface {v0, v3}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1392
    .line 1393
    .line 1394
    :cond_25
    return-object v16

    .line 1395
    :pswitch_c
    check-cast v0, Lkotlin/jvm/internal/c0;

    .line 1396
    .line 1397
    check-cast v12, Lg1/e2;

    .line 1398
    .line 1399
    check-cast v6, Lkotlin/jvm/internal/c0;

    .line 1400
    .line 1401
    move-object/from16 v1, p1

    .line 1402
    .line 1403
    check-cast v1, Lc1/i;

    .line 1404
    .line 1405
    iget-object v2, v1, Lc1/i;->e:Ll2/j1;

    .line 1406
    .line 1407
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v2

    .line 1411
    check-cast v2, Ljava/lang/Number;

    .line 1412
    .line 1413
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1414
    .line 1415
    .line 1416
    move-result v2

    .line 1417
    iget v3, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 1418
    .line 1419
    sub-float/2addr v2, v3

    .line 1420
    invoke-interface {v12, v2}, Lg1/e2;->a(F)F

    .line 1421
    .line 1422
    .line 1423
    move-result v3

    .line 1424
    iget-object v4, v1, Lc1/i;->e:Ll2/j1;

    .line 1425
    .line 1426
    invoke-virtual {v4}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v4

    .line 1430
    check-cast v4, Ljava/lang/Number;

    .line 1431
    .line 1432
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 1433
    .line 1434
    .line 1435
    move-result v4

    .line 1436
    iput v4, v0, Lkotlin/jvm/internal/c0;->d:F

    .line 1437
    .line 1438
    invoke-virtual {v1}, Lc1/i;->b()Ljava/lang/Object;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v0

    .line 1442
    check-cast v0, Ljava/lang/Number;

    .line 1443
    .line 1444
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 1445
    .line 1446
    .line 1447
    move-result v0

    .line 1448
    iput v0, v6, Lkotlin/jvm/internal/c0;->d:F

    .line 1449
    .line 1450
    sub-float/2addr v2, v3

    .line 1451
    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    .line 1452
    .line 1453
    .line 1454
    move-result v0

    .line 1455
    const/high16 v2, 0x3f000000    # 0.5f

    .line 1456
    .line 1457
    cmpl-float v0, v0, v2

    .line 1458
    .line 1459
    if-lez v0, :cond_26

    .line 1460
    .line 1461
    invoke-virtual {v1}, Lc1/i;->a()V

    .line 1462
    .line 1463
    .line 1464
    :cond_26
    return-object v16

    .line 1465
    :pswitch_d
    check-cast v0, Lg1/y;

    .line 1466
    .line 1467
    check-cast v12, Lvy0/i1;

    .line 1468
    .line 1469
    check-cast v6, Lg1/t2;

    .line 1470
    .line 1471
    move-object/from16 v1, p1

    .line 1472
    .line 1473
    check-cast v1, Ljava/lang/Float;

    .line 1474
    .line 1475
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1476
    .line 1477
    .line 1478
    move-result v1

    .line 1479
    iget-boolean v2, v0, Lg1/y;->t:Z

    .line 1480
    .line 1481
    if-eqz v2, :cond_27

    .line 1482
    .line 1483
    const/high16 v5, 0x3f800000    # 1.0f

    .line 1484
    .line 1485
    goto :goto_21

    .line 1486
    :cond_27
    const/high16 v5, -0x40800000    # -1.0f

    .line 1487
    .line 1488
    :goto_21
    mul-float v2, v5, v1

    .line 1489
    .line 1490
    iget-object v0, v0, Lg1/y;->s:Lg1/u2;

    .line 1491
    .line 1492
    invoke-virtual {v0, v2}, Lg1/u2;->h(F)J

    .line 1493
    .line 1494
    .line 1495
    move-result-wide v2

    .line 1496
    invoke-virtual {v0, v2, v3}, Lg1/u2;->e(J)J

    .line 1497
    .line 1498
    .line 1499
    move-result-wide v2

    .line 1500
    iget-object v4, v6, Lg1/t2;->a:Lg1/u2;

    .line 1501
    .line 1502
    iget-object v6, v4, Lg1/u2;->k:Lg1/e2;

    .line 1503
    .line 1504
    const/4 v7, 0x1

    .line 1505
    invoke-virtual {v4, v6, v2, v3, v7}, Lg1/u2;->c(Lg1/e2;JI)J

    .line 1506
    .line 1507
    .line 1508
    move-result-wide v2

    .line 1509
    invoke-virtual {v0, v2, v3}, Lg1/u2;->e(J)J

    .line 1510
    .line 1511
    .line 1512
    move-result-wide v2

    .line 1513
    invoke-virtual {v0, v2, v3}, Lg1/u2;->g(J)F

    .line 1514
    .line 1515
    .line 1516
    move-result v0

    .line 1517
    mul-float/2addr v0, v5

    .line 1518
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 1519
    .line 1520
    .line 1521
    move-result v2

    .line 1522
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 1523
    .line 1524
    .line 1525
    move-result v3

    .line 1526
    cmpg-float v2, v2, v3

    .line 1527
    .line 1528
    if-gez v2, :cond_28

    .line 1529
    .line 1530
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1531
    .line 1532
    const-string v3, "Scroll animation cancelled because scroll was not consumed ("

    .line 1533
    .line 1534
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1535
    .line 1536
    .line 1537
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 1538
    .line 1539
    .line 1540
    const-string v0, " < "

    .line 1541
    .line 1542
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1543
    .line 1544
    .line 1545
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 1546
    .line 1547
    .line 1548
    const/16 v0, 0x29

    .line 1549
    .line 1550
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 1551
    .line 1552
    .line 1553
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1554
    .line 1555
    .line 1556
    move-result-object v0

    .line 1557
    invoke-static {v0, v12}, Lvy0/e0;->k(Ljava/lang/String;Lvy0/i1;)V

    .line 1558
    .line 1559
    .line 1560
    :cond_28
    return-object v16

    .line 1561
    :pswitch_e
    check-cast v0, Le30/o;

    .line 1562
    .line 1563
    check-cast v12, Ld01/h0;

    .line 1564
    .line 1565
    check-cast v6, Lay0/k;

    .line 1566
    .line 1567
    move-object/from16 v1, p1

    .line 1568
    .line 1569
    check-cast v1, Lm1/f;

    .line 1570
    .line 1571
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1572
    .line 1573
    .line 1574
    iget-boolean v2, v0, Le30/o;->b:Z

    .line 1575
    .line 1576
    if-nez v2, :cond_2a

    .line 1577
    .line 1578
    iget-object v2, v0, Le30/o;->f:Ljava/util/ArrayList;

    .line 1579
    .line 1580
    const/16 v3, 0xd

    .line 1581
    .line 1582
    if-eqz v2, :cond_29

    .line 1583
    .line 1584
    sget-object v4, Lf30/a;->b:Lt2/b;

    .line 1585
    .line 1586
    invoke-static {v1, v4, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1587
    .line 1588
    .line 1589
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 1590
    .line 1591
    .line 1592
    move-result v4

    .line 1593
    new-instance v5, Lak/p;

    .line 1594
    .line 1595
    invoke-direct {v5, v2, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1596
    .line 1597
    .line 1598
    new-instance v8, Lf30/f;

    .line 1599
    .line 1600
    const/4 v9, 0x1

    .line 1601
    invoke-direct {v8, v2, v12, v6, v9}, Lf30/f;-><init>(Ljava/util/List;Ld01/h0;Lay0/k;Z)V

    .line 1602
    .line 1603
    .line 1604
    new-instance v2, Lt2/b;

    .line 1605
    .line 1606
    invoke-direct {v2, v8, v9, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1607
    .line 1608
    .line 1609
    const/4 v8, 0x0

    .line 1610
    invoke-virtual {v1, v4, v8, v5, v2}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1611
    .line 1612
    .line 1613
    :cond_29
    iget-object v0, v0, Le30/o;->g:Ljava/util/ArrayList;

    .line 1614
    .line 1615
    if-eqz v0, :cond_2b

    .line 1616
    .line 1617
    sget-object v2, Lf30/a;->c:Lt2/b;

    .line 1618
    .line 1619
    invoke-static {v1, v2, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1620
    .line 1621
    .line 1622
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 1623
    .line 1624
    .line 1625
    move-result v2

    .line 1626
    new-instance v4, Lak/p;

    .line 1627
    .line 1628
    invoke-direct {v4, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1629
    .line 1630
    .line 1631
    new-instance v3, Lf30/f;

    .line 1632
    .line 1633
    invoke-direct {v3, v0, v12, v6, v15}, Lf30/f;-><init>(Ljava/util/List;Ld01/h0;Lay0/k;Z)V

    .line 1634
    .line 1635
    .line 1636
    new-instance v0, Lt2/b;

    .line 1637
    .line 1638
    const/4 v6, 0x1

    .line 1639
    invoke-direct {v0, v3, v6, v7}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1640
    .line 1641
    .line 1642
    const/4 v3, 0x0

    .line 1643
    invoke-virtual {v1, v2, v3, v4, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1644
    .line 1645
    .line 1646
    goto :goto_22

    .line 1647
    :cond_2a
    sget-object v0, Lf30/a;->d:Lt2/b;

    .line 1648
    .line 1649
    invoke-static {v1, v0, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1650
    .line 1651
    .line 1652
    sget-object v0, Lf30/a;->e:Lt2/b;

    .line 1653
    .line 1654
    invoke-static {v1, v0, v13}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 1655
    .line 1656
    .line 1657
    :cond_2b
    :goto_22
    return-object v16

    .line 1658
    :pswitch_f
    check-cast v0, Ll2/b1;

    .line 1659
    .line 1660
    check-cast v12, Ll2/t2;

    .line 1661
    .line 1662
    check-cast v6, Ll2/t2;

    .line 1663
    .line 1664
    move-object/from16 v1, p1

    .line 1665
    .line 1666
    check-cast v1, Le3/k0;

    .line 1667
    .line 1668
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1669
    .line 1670
    .line 1671
    move-result-object v2

    .line 1672
    check-cast v2, Ljava/lang/Number;

    .line 1673
    .line 1674
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1675
    .line 1676
    .line 1677
    move-result v2

    .line 1678
    invoke-virtual {v1, v2}, Le3/k0;->l(F)V

    .line 1679
    .line 1680
    .line 1681
    invoke-interface {v12}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1682
    .line 1683
    .line 1684
    move-result-object v2

    .line 1685
    check-cast v2, Ljava/lang/Number;

    .line 1686
    .line 1687
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1688
    .line 1689
    .line 1690
    move-result v2

    .line 1691
    invoke-virtual {v1, v2}, Le3/k0;->p(F)V

    .line 1692
    .line 1693
    .line 1694
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1695
    .line 1696
    .line 1697
    move-result-object v2

    .line 1698
    check-cast v2, Ljava/lang/Number;

    .line 1699
    .line 1700
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 1701
    .line 1702
    .line 1703
    move-result v2

    .line 1704
    invoke-virtual {v1, v2}, Le3/k0;->b(F)V

    .line 1705
    .line 1706
    .line 1707
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 1708
    .line 1709
    .line 1710
    move-result-object v0

    .line 1711
    check-cast v0, Le3/q0;

    .line 1712
    .line 1713
    iget-wide v2, v0, Le3/q0;->a:J

    .line 1714
    .line 1715
    invoke-virtual {v1, v2, v3}, Le3/k0;->A(J)V

    .line 1716
    .line 1717
    .line 1718
    return-object v16

    .line 1719
    :pswitch_10
    move-object v5, v0

    .line 1720
    check-cast v5, Lkw/p;

    .line 1721
    .line 1722
    check-cast v12, Lkw/p;

    .line 1723
    .line 1724
    move-object v7, v6

    .line 1725
    check-cast v7, Lkw/p;

    .line 1726
    .line 1727
    move-object/from16 v0, p1

    .line 1728
    .line 1729
    check-cast v0, Llx0/l;

    .line 1730
    .line 1731
    const-string v1, "<destruct>"

    .line 1732
    .line 1733
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1734
    .line 1735
    .line 1736
    iget-object v1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 1737
    .line 1738
    check-cast v1, Ljava/lang/Number;

    .line 1739
    .line 1740
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 1741
    .line 1742
    .line 1743
    move-result v8

    .line 1744
    iget-object v0, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 1745
    .line 1746
    check-cast v0, Ljava/lang/Boolean;

    .line 1747
    .line 1748
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1749
    .line 1750
    .line 1751
    move-result v9

    .line 1752
    new-instance v4, Lew/j;

    .line 1753
    .line 1754
    move-object v6, v12

    .line 1755
    invoke-direct/range {v4 .. v9}, Lew/j;-><init>(Lkw/p;Lkw/p;Lkw/p;FZ)V

    .line 1756
    .line 1757
    .line 1758
    return-object v4

    .line 1759
    :pswitch_11
    check-cast v0, Lqe/a;

    .line 1760
    .line 1761
    check-cast v12, Ljava/util/List;

    .line 1762
    .line 1763
    check-cast v6, Lay0/k;

    .line 1764
    .line 1765
    move-object/from16 v1, p1

    .line 1766
    .line 1767
    check-cast v1, Lhi/a;

    .line 1768
    .line 1769
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1770
    .line 1771
    .line 1772
    new-instance v1, Lef/b;

    .line 1773
    .line 1774
    invoke-direct {v1, v0, v12, v6}, Lef/b;-><init>(Lqe/a;Ljava/util/List;Lay0/k;)V

    .line 1775
    .line 1776
    .line 1777
    return-object v1

    .line 1778
    :pswitch_12
    check-cast v0, Le2/w0;

    .line 1779
    .line 1780
    check-cast v12, Lvy0/b0;

    .line 1781
    .line 1782
    check-cast v6, Landroid/content/Context;

    .line 1783
    .line 1784
    move-object/from16 v1, p1

    .line 1785
    .line 1786
    check-cast v1, Lv1/a;

    .line 1787
    .line 1788
    iget-object v2, v1, Lv1/a;->a:Landroidx/collection/l0;

    .line 1789
    .line 1790
    iget-object v1, v1, Lv1/a;->a:Landroidx/collection/l0;

    .line 1791
    .line 1792
    sget-object v3, Lw1/f;->b:Lw1/f;

    .line 1793
    .line 1794
    invoke-virtual {v2, v3}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 1795
    .line 1796
    .line 1797
    sget-object v2, Lt1/u0;->e:[Lt1/u0;

    .line 1798
    .line 1799
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 1800
    .line 1801
    .line 1802
    move-result-object v2

    .line 1803
    iget-wide v4, v2, Ll4/v;->b:J

    .line 1804
    .line 1805
    invoke-static {v4, v5}, Lg4/o0;->c(J)Z

    .line 1806
    .line 1807
    .line 1808
    move-result v2

    .line 1809
    if-nez v2, :cond_2c

    .line 1810
    .line 1811
    iget-object v2, v0, Le2/w0;->l:Ll2/j1;

    .line 1812
    .line 1813
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1814
    .line 1815
    .line 1816
    move-result-object v2

    .line 1817
    check-cast v2, Ljava/lang/Boolean;

    .line 1818
    .line 1819
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1820
    .line 1821
    .line 1822
    move-result v2

    .line 1823
    if-eqz v2, :cond_2c

    .line 1824
    .line 1825
    const/4 v2, 0x1

    .line 1826
    goto :goto_23

    .line 1827
    :cond_2c
    move v2, v15

    .line 1828
    :goto_23
    new-instance v4, Le2/p0;

    .line 1829
    .line 1830
    const/4 v5, 0x0

    .line 1831
    const/4 v7, 0x1

    .line 1832
    invoke-direct {v4, v0, v5, v7}, Le2/p0;-><init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V

    .line 1833
    .line 1834
    .line 1835
    new-instance v8, Ld90/w;

    .line 1836
    .line 1837
    invoke-direct {v8, v12, v4}, Ld90/w;-><init>(Lvy0/b0;Lay0/k;)V

    .line 1838
    .line 1839
    .line 1840
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1841
    .line 1842
    .line 1843
    move-result-object v4

    .line 1844
    new-instance v9, Lbf/a;

    .line 1845
    .line 1846
    invoke-direct {v9, v8, v5, v7}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 1847
    .line 1848
    .line 1849
    if-eqz v2, :cond_2d

    .line 1850
    .line 1851
    const v2, 0x1040003

    .line 1852
    .line 1853
    .line 1854
    invoke-virtual {v4, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1855
    .line 1856
    .line 1857
    move-result-object v2

    .line 1858
    new-instance v4, Lw1/d;

    .line 1859
    .line 1860
    sget-object v5, Lw1/e;->a:Ljava/lang/Object;

    .line 1861
    .line 1862
    const v7, 0x1010311

    .line 1863
    .line 1864
    .line 1865
    invoke-direct {v4, v5, v2, v7, v9}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 1866
    .line 1867
    .line 1868
    invoke-virtual {v1, v4}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 1869
    .line 1870
    .line 1871
    :cond_2d
    sget-object v2, Lt1/u0;->e:[Lt1/u0;

    .line 1872
    .line 1873
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 1874
    .line 1875
    .line 1876
    move-result-object v2

    .line 1877
    iget-wide v4, v2, Ll4/v;->b:J

    .line 1878
    .line 1879
    invoke-static {v4, v5}, Lg4/o0;->c(J)Z

    .line 1880
    .line 1881
    .line 1882
    move-result v2

    .line 1883
    new-instance v4, Le2/p0;

    .line 1884
    .line 1885
    const/4 v5, 0x0

    .line 1886
    invoke-direct {v4, v0, v5, v14}, Le2/p0;-><init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V

    .line 1887
    .line 1888
    .line 1889
    new-instance v7, Ld90/w;

    .line 1890
    .line 1891
    invoke-direct {v7, v12, v4}, Ld90/w;-><init>(Lvy0/b0;Lay0/k;)V

    .line 1892
    .line 1893
    .line 1894
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1895
    .line 1896
    .line 1897
    move-result-object v4

    .line 1898
    new-instance v8, Lbf/a;

    .line 1899
    .line 1900
    const/4 v9, 0x1

    .line 1901
    invoke-direct {v8, v7, v5, v9}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 1902
    .line 1903
    .line 1904
    if-nez v2, :cond_2e

    .line 1905
    .line 1906
    const v2, 0x1040001

    .line 1907
    .line 1908
    .line 1909
    invoke-virtual {v4, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1910
    .line 1911
    .line 1912
    move-result-object v2

    .line 1913
    new-instance v4, Lw1/d;

    .line 1914
    .line 1915
    sget-object v5, Lw1/e;->b:Ljava/lang/Object;

    .line 1916
    .line 1917
    const v7, 0x1010312

    .line 1918
    .line 1919
    .line 1920
    invoke-direct {v4, v5, v2, v7, v8}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 1921
    .line 1922
    .line 1923
    invoke-virtual {v1, v4}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 1924
    .line 1925
    .line 1926
    :cond_2e
    sget-object v2, Lt1/u0;->e:[Lt1/u0;

    .line 1927
    .line 1928
    iget-object v2, v0, Le2/w0;->l:Ll2/j1;

    .line 1929
    .line 1930
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1931
    .line 1932
    .line 1933
    move-result-object v2

    .line 1934
    check-cast v2, Ljava/lang/Boolean;

    .line 1935
    .line 1936
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1937
    .line 1938
    .line 1939
    move-result v2

    .line 1940
    if-eqz v2, :cond_2f

    .line 1941
    .line 1942
    iget-object v2, v0, Le2/w0;->w:Ll2/j1;

    .line 1943
    .line 1944
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 1945
    .line 1946
    .line 1947
    move-result-object v2

    .line 1948
    check-cast v2, Lw3/b1;

    .line 1949
    .line 1950
    if-eqz v2, :cond_2f

    .line 1951
    .line 1952
    iget-object v2, v2, Lw3/b1;->a:Landroid/content/ClipData;

    .line 1953
    .line 1954
    invoke-virtual {v2}, Landroid/content/ClipData;->getDescription()Landroid/content/ClipDescription;

    .line 1955
    .line 1956
    .line 1957
    move-result-object v2

    .line 1958
    const-string v4, "text/*"

    .line 1959
    .line 1960
    invoke-virtual {v2, v4}, Landroid/content/ClipDescription;->hasMimeType(Ljava/lang/String;)Z

    .line 1961
    .line 1962
    .line 1963
    move-result v2

    .line 1964
    const/4 v7, 0x1

    .line 1965
    if-ne v2, v7, :cond_2f

    .line 1966
    .line 1967
    const/4 v2, 0x1

    .line 1968
    goto :goto_24

    .line 1969
    :cond_2f
    move v2, v15

    .line 1970
    :goto_24
    new-instance v4, Le2/p0;

    .line 1971
    .line 1972
    const/4 v5, 0x0

    .line 1973
    invoke-direct {v4, v0, v5, v13}, Le2/p0;-><init>(Le2/w0;Lkotlin/coroutines/Continuation;I)V

    .line 1974
    .line 1975
    .line 1976
    new-instance v7, Ld90/w;

    .line 1977
    .line 1978
    invoke-direct {v7, v12, v4}, Ld90/w;-><init>(Lvy0/b0;Lay0/k;)V

    .line 1979
    .line 1980
    .line 1981
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 1982
    .line 1983
    .line 1984
    move-result-object v4

    .line 1985
    new-instance v8, Lbf/a;

    .line 1986
    .line 1987
    const/4 v9, 0x1

    .line 1988
    invoke-direct {v8, v7, v5, v9}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 1989
    .line 1990
    .line 1991
    if-eqz v2, :cond_30

    .line 1992
    .line 1993
    const v2, 0x104000b

    .line 1994
    .line 1995
    .line 1996
    invoke-virtual {v4, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 1997
    .line 1998
    .line 1999
    move-result-object v2

    .line 2000
    new-instance v4, Lw1/d;

    .line 2001
    .line 2002
    sget-object v5, Lw1/e;->c:Ljava/lang/Object;

    .line 2003
    .line 2004
    const v7, 0x1010313

    .line 2005
    .line 2006
    .line 2007
    invoke-direct {v4, v5, v2, v7, v8}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 2008
    .line 2009
    .line 2010
    invoke-virtual {v1, v4}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 2011
    .line 2012
    .line 2013
    :cond_30
    sget-object v2, Lt1/u0;->e:[Lt1/u0;

    .line 2014
    .line 2015
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 2016
    .line 2017
    .line 2018
    move-result-object v2

    .line 2019
    iget-wide v4, v2, Ll4/v;->b:J

    .line 2020
    .line 2021
    invoke-static {v4, v5}, Lg4/o0;->d(J)I

    .line 2022
    .line 2023
    .line 2024
    move-result v2

    .line 2025
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 2026
    .line 2027
    .line 2028
    move-result-object v4

    .line 2029
    iget-object v4, v4, Ll4/v;->a:Lg4/g;

    .line 2030
    .line 2031
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    .line 2032
    .line 2033
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 2034
    .line 2035
    .line 2036
    move-result v4

    .line 2037
    if-eq v2, v4, :cond_31

    .line 2038
    .line 2039
    const/4 v2, 0x1

    .line 2040
    goto :goto_25

    .line 2041
    :cond_31
    move v2, v15

    .line 2042
    :goto_25
    new-instance v4, Le2/a1;

    .line 2043
    .line 2044
    invoke-direct {v4, v0, v15}, Le2/a1;-><init>(Le2/w0;I)V

    .line 2045
    .line 2046
    .line 2047
    new-instance v5, Le2/a1;

    .line 2048
    .line 2049
    const/4 v7, 0x1

    .line 2050
    invoke-direct {v5, v0, v7}, Le2/a1;-><init>(Le2/w0;I)V

    .line 2051
    .line 2052
    .line 2053
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2054
    .line 2055
    .line 2056
    move-result-object v8

    .line 2057
    new-instance v9, Lbf/a;

    .line 2058
    .line 2059
    invoke-direct {v9, v5, v4, v7}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 2060
    .line 2061
    .line 2062
    if-eqz v2, :cond_32

    .line 2063
    .line 2064
    const v2, 0x104000d

    .line 2065
    .line 2066
    .line 2067
    invoke-virtual {v8, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 2068
    .line 2069
    .line 2070
    move-result-object v2

    .line 2071
    new-instance v4, Lw1/d;

    .line 2072
    .line 2073
    sget-object v5, Lw1/e;->d:Ljava/lang/Object;

    .line 2074
    .line 2075
    const v7, 0x101037e

    .line 2076
    .line 2077
    .line 2078
    invoke-direct {v4, v5, v2, v7, v9}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 2079
    .line 2080
    .line 2081
    invoke-virtual {v1, v4}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 2082
    .line 2083
    .line 2084
    :cond_32
    sget-object v2, Lt1/u0;->e:[Lt1/u0;

    .line 2085
    .line 2086
    iget-object v2, v0, Le2/w0;->l:Ll2/j1;

    .line 2087
    .line 2088
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 2089
    .line 2090
    .line 2091
    move-result-object v2

    .line 2092
    check-cast v2, Ljava/lang/Boolean;

    .line 2093
    .line 2094
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 2095
    .line 2096
    .line 2097
    move-result v2

    .line 2098
    if-eqz v2, :cond_33

    .line 2099
    .line 2100
    invoke-virtual {v0}, Le2/w0;->m()Ll4/v;

    .line 2101
    .line 2102
    .line 2103
    move-result-object v2

    .line 2104
    iget-wide v4, v2, Ll4/v;->b:J

    .line 2105
    .line 2106
    invoke-static {v4, v5}, Lg4/o0;->c(J)Z

    .line 2107
    .line 2108
    .line 2109
    move-result v2

    .line 2110
    if-eqz v2, :cond_33

    .line 2111
    .line 2112
    const/4 v2, 0x1

    .line 2113
    goto :goto_26

    .line 2114
    :cond_33
    move v2, v15

    .line 2115
    :goto_26
    new-instance v4, Le2/a1;

    .line 2116
    .line 2117
    invoke-direct {v4, v0, v14}, Le2/a1;-><init>(Le2/w0;I)V

    .line 2118
    .line 2119
    .line 2120
    invoke-virtual {v6}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 2121
    .line 2122
    .line 2123
    move-result-object v0

    .line 2124
    new-instance v5, Lbf/a;

    .line 2125
    .line 2126
    const/4 v7, 0x1

    .line 2127
    const/4 v8, 0x0

    .line 2128
    invoke-direct {v5, v4, v8, v7}, Lbf/a;-><init>(Lay0/a;Lay0/a;I)V

    .line 2129
    .line 2130
    .line 2131
    if-eqz v2, :cond_34

    .line 2132
    .line 2133
    const v2, 0x104001a

    .line 2134
    .line 2135
    .line 2136
    invoke-virtual {v0, v2}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 2137
    .line 2138
    .line 2139
    move-result-object v0

    .line 2140
    new-instance v2, Lw1/d;

    .line 2141
    .line 2142
    sget-object v4, Lw1/e;->e:Ljava/lang/Object;

    .line 2143
    .line 2144
    invoke-direct {v2, v4, v0, v15, v5}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 2145
    .line 2146
    .line 2147
    invoke-virtual {v1, v2}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 2148
    .line 2149
    .line 2150
    :cond_34
    invoke-virtual {v1, v3}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 2151
    .line 2152
    .line 2153
    return-object v16

    .line 2154
    :pswitch_13
    check-cast v0, Lcom/google/android/gms/internal/measurement/i4;

    .line 2155
    .line 2156
    move-object v11, v12

    .line 2157
    check-cast v11, Lc1/y;

    .line 2158
    .line 2159
    move-object v1, v6

    .line 2160
    check-cast v1, Lkotlin/jvm/internal/b0;

    .line 2161
    .line 2162
    move-object/from16 v2, p1

    .line 2163
    .line 2164
    check-cast v2, Lp3/t;

    .line 2165
    .line 2166
    iget-wide v8, v2, Lp3/t;->c:J

    .line 2167
    .line 2168
    iget-object v3, v0, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 2169
    .line 2170
    check-cast v3, Le2/w0;

    .line 2171
    .line 2172
    invoke-virtual {v3}, Le2/w0;->j()Z

    .line 2173
    .line 2174
    .line 2175
    move-result v4

    .line 2176
    if-eqz v4, :cond_37

    .line 2177
    .line 2178
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 2179
    .line 2180
    .line 2181
    move-result-object v4

    .line 2182
    iget-object v4, v4, Ll4/v;->a:Lg4/g;

    .line 2183
    .line 2184
    iget-object v4, v4, Lg4/g;->e:Ljava/lang/String;

    .line 2185
    .line 2186
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 2187
    .line 2188
    .line 2189
    move-result v4

    .line 2190
    if-nez v4, :cond_35

    .line 2191
    .line 2192
    goto :goto_27

    .line 2193
    :cond_35
    iget-object v4, v3, Le2/w0;->d:Lt1/p0;

    .line 2194
    .line 2195
    if-eqz v4, :cond_37

    .line 2196
    .line 2197
    invoke-virtual {v4}, Lt1/p0;->d()Lt1/j1;

    .line 2198
    .line 2199
    .line 2200
    move-result-object v4

    .line 2201
    if-nez v4, :cond_36

    .line 2202
    .line 2203
    goto :goto_27

    .line 2204
    :cond_36
    invoke-virtual {v3}, Le2/w0;->m()Ll4/v;

    .line 2205
    .line 2206
    .line 2207
    move-result-object v7

    .line 2208
    const/4 v10, 0x0

    .line 2209
    move-object v6, v0

    .line 2210
    invoke-virtual/range {v6 .. v11}, Lcom/google/android/gms/internal/measurement/i4;->x(Ll4/v;JZLc1/y;)J

    .line 2211
    .line 2212
    .line 2213
    const/4 v15, 0x1

    .line 2214
    :cond_37
    :goto_27
    if-eqz v15, :cond_38

    .line 2215
    .line 2216
    invoke-virtual {v2}, Lp3/t;->a()V

    .line 2217
    .line 2218
    .line 2219
    const/4 v7, 0x1

    .line 2220
    iput-boolean v7, v1, Lkotlin/jvm/internal/b0;->d:Z

    .line 2221
    .line 2222
    :cond_38
    return-object v16

    .line 2223
    :pswitch_14
    check-cast v12, Lay0/k;

    .line 2224
    .line 2225
    check-cast v6, Li91/i4;

    .line 2226
    .line 2227
    move-object/from16 v1, p1

    .line 2228
    .line 2229
    check-cast v1, Lhi/a;

    .line 2230
    .line 2231
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2232
    .line 2233
    .line 2234
    new-instance v1, Ldf/d;

    .line 2235
    .line 2236
    invoke-direct {v1, v0, v12, v6}, Ldf/d;-><init>(Ljava/util/List;Lay0/k;Li91/i4;)V

    .line 2237
    .line 2238
    .line 2239
    return-object v1

    .line 2240
    :pswitch_15
    check-cast v0, Lbz/d;

    .line 2241
    .line 2242
    check-cast v12, Lay0/k;

    .line 2243
    .line 2244
    check-cast v6, Lay0/k;

    .line 2245
    .line 2246
    move-object/from16 v1, p1

    .line 2247
    .line 2248
    check-cast v1, Lm1/f;

    .line 2249
    .line 2250
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2251
    .line 2252
    .line 2253
    iget-object v2, v0, Lbz/d;->a:Ljava/util/List;

    .line 2254
    .line 2255
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 2256
    .line 2257
    .line 2258
    move-result v3

    .line 2259
    new-instance v4, Lak/p;

    .line 2260
    .line 2261
    const/16 v5, 0x8

    .line 2262
    .line 2263
    invoke-direct {v4, v2, v5}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 2264
    .line 2265
    .line 2266
    new-instance v5, Lcz/b;

    .line 2267
    .line 2268
    invoke-direct {v5, v2, v12, v0, v6}, Lcz/b;-><init>(Ljava/util/List;Lay0/k;Lbz/d;Lay0/k;)V

    .line 2269
    .line 2270
    .line 2271
    new-instance v0, Lt2/b;

    .line 2272
    .line 2273
    const v2, 0x2fd4df92

    .line 2274
    .line 2275
    .line 2276
    const/4 v7, 0x1

    .line 2277
    invoke-direct {v0, v5, v7, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 2278
    .line 2279
    .line 2280
    const/4 v5, 0x0

    .line 2281
    invoke-virtual {v1, v3, v5, v4, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 2282
    .line 2283
    .line 2284
    return-object v16

    .line 2285
    :pswitch_16
    check-cast v0, Ljava/time/LocalDate;

    .line 2286
    .line 2287
    check-cast v12, Ljava/lang/String;

    .line 2288
    .line 2289
    check-cast v6, Ljava/lang/String;

    .line 2290
    .line 2291
    move-object/from16 v1, p1

    .line 2292
    .line 2293
    check-cast v1, Lua/a;

    .line 2294
    .line 2295
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2296
    .line 2297
    .line 2298
    const-string v2, "UPDATE vehicle_fuel_level SET last_notification_date = ? WHERE vin = ? AND fuel_type = ?"

    .line 2299
    .line 2300
    invoke-interface {v1, v2}, Lua/a;->v0(Ljava/lang/String;)Lua/c;

    .line 2301
    .line 2302
    .line 2303
    move-result-object v1

    .line 2304
    :try_start_3
    invoke-static {v0}, Lwe0/b;->w(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 2305
    .line 2306
    .line 2307
    move-result-object v0

    .line 2308
    if-nez v0, :cond_39

    .line 2309
    .line 2310
    const/4 v7, 0x1

    .line 2311
    invoke-interface {v1, v7}, Lua/c;->bindNull(I)V

    .line 2312
    .line 2313
    .line 2314
    goto :goto_28

    .line 2315
    :catchall_3
    move-exception v0

    .line 2316
    goto :goto_29

    .line 2317
    :cond_39
    const/4 v7, 0x1

    .line 2318
    invoke-interface {v1, v7, v0}, Lua/c;->w(ILjava/lang/String;)V

    .line 2319
    .line 2320
    .line 2321
    :goto_28
    invoke-interface {v1, v14, v12}, Lua/c;->w(ILjava/lang/String;)V

    .line 2322
    .line 2323
    .line 2324
    invoke-interface {v1, v13, v6}, Lua/c;->w(ILjava/lang/String;)V

    .line 2325
    .line 2326
    .line 2327
    invoke-interface {v1}, Lua/c;->s0()Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 2328
    .line 2329
    .line 2330
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2331
    .line 2332
    .line 2333
    return-object v16

    .line 2334
    :goto_29
    invoke-interface {v1}, Ljava/lang/AutoCloseable;->close()V

    .line 2335
    .line 2336
    .line 2337
    throw v0

    .line 2338
    :pswitch_17
    check-cast v0, Lc3/j;

    .line 2339
    .line 2340
    check-cast v12, Lay0/k;

    .line 2341
    .line 2342
    check-cast v6, Lba0/f;

    .line 2343
    .line 2344
    move-object/from16 v1, p1

    .line 2345
    .line 2346
    check-cast v1, Lt1/m0;

    .line 2347
    .line 2348
    const-string v2, "$this$KeyboardActions"

    .line 2349
    .line 2350
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2351
    .line 2352
    .line 2353
    invoke-static {v0}, Lc3/j;->a(Lc3/j;)V

    .line 2354
    .line 2355
    .line 2356
    iget-object v0, v6, Lba0/f;->a:Ljava/lang/String;

    .line 2357
    .line 2358
    invoke-interface {v12, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2359
    .line 2360
    .line 2361
    return-object v16

    .line 2362
    :pswitch_18
    check-cast v0, Lb/h0;

    .line 2363
    .line 2364
    check-cast v12, Landroidx/lifecycle/x;

    .line 2365
    .line 2366
    check-cast v6, Lc/l;

    .line 2367
    .line 2368
    move-object/from16 v1, p1

    .line 2369
    .line 2370
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 2371
    .line 2372
    invoke-virtual {v0, v12, v6}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 2373
    .line 2374
    .line 2375
    new-instance v0, La2/j;

    .line 2376
    .line 2377
    invoke-direct {v0, v6, v13}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 2378
    .line 2379
    .line 2380
    return-object v0

    .line 2381
    :pswitch_19
    check-cast v0, Lb/h0;

    .line 2382
    .line 2383
    check-cast v12, Landroidx/lifecycle/x;

    .line 2384
    .line 2385
    check-cast v6, Lc/f;

    .line 2386
    .line 2387
    move-object/from16 v1, p1

    .line 2388
    .line 2389
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 2390
    .line 2391
    invoke-virtual {v0, v12, v6}, Lb/h0;->a(Landroidx/lifecycle/x;Lb/a0;)V

    .line 2392
    .line 2393
    .line 2394
    new-instance v0, La2/j;

    .line 2395
    .line 2396
    invoke-direct {v0, v6, v14}, La2/j;-><init>(Ljava/lang/Object;I)V

    .line 2397
    .line 2398
    .line 2399
    return-object v0

    .line 2400
    :pswitch_1a
    check-cast v0, Lay0/k;

    .line 2401
    .line 2402
    check-cast v12, Lay0/k;

    .line 2403
    .line 2404
    check-cast v6, Lay0/k;

    .line 2405
    .line 2406
    move-object/from16 v1, p1

    .line 2407
    .line 2408
    check-cast v1, Lzl/g;

    .line 2409
    .line 2410
    instance-of v2, v1, Lzl/e;

    .line 2411
    .line 2412
    if-eqz v2, :cond_3a

    .line 2413
    .line 2414
    if-eqz v0, :cond_3d

    .line 2415
    .line 2416
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2417
    .line 2418
    .line 2419
    goto :goto_2a

    .line 2420
    :cond_3a
    instance-of v0, v1, Lzl/f;

    .line 2421
    .line 2422
    if-eqz v0, :cond_3b

    .line 2423
    .line 2424
    if-eqz v12, :cond_3d

    .line 2425
    .line 2426
    invoke-interface {v12, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2427
    .line 2428
    .line 2429
    goto :goto_2a

    .line 2430
    :cond_3b
    instance-of v0, v1, Lzl/d;

    .line 2431
    .line 2432
    if-eqz v0, :cond_3c

    .line 2433
    .line 2434
    if-eqz v6, :cond_3d

    .line 2435
    .line 2436
    invoke-interface {v6, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2437
    .line 2438
    .line 2439
    goto :goto_2a

    .line 2440
    :cond_3c
    instance-of v0, v1, Lzl/c;

    .line 2441
    .line 2442
    if-eqz v0, :cond_3e

    .line 2443
    .line 2444
    :cond_3d
    :goto_2a
    return-object v16

    .line 2445
    :cond_3e
    new-instance v0, La8/r0;

    .line 2446
    .line 2447
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2448
    .line 2449
    .line 2450
    throw v0

    .line 2451
    :pswitch_1b
    check-cast v0, Li3/c;

    .line 2452
    .line 2453
    check-cast v12, Li3/c;

    .line 2454
    .line 2455
    check-cast v6, Li3/c;

    .line 2456
    .line 2457
    move-object/from16 v1, p1

    .line 2458
    .line 2459
    check-cast v1, Lzl/g;

    .line 2460
    .line 2461
    instance-of v2, v1, Lzl/e;

    .line 2462
    .line 2463
    if-eqz v2, :cond_40

    .line 2464
    .line 2465
    if-eqz v0, :cond_3f

    .line 2466
    .line 2467
    new-instance v1, Lzl/e;

    .line 2468
    .line 2469
    invoke-direct {v1, v0}, Lzl/e;-><init>(Li3/c;)V

    .line 2470
    .line 2471
    .line 2472
    goto :goto_2b

    .line 2473
    :cond_3f
    check-cast v1, Lzl/e;

    .line 2474
    .line 2475
    goto :goto_2b

    .line 2476
    :cond_40
    instance-of v0, v1, Lzl/d;

    .line 2477
    .line 2478
    if-eqz v0, :cond_42

    .line 2479
    .line 2480
    check-cast v1, Lzl/d;

    .line 2481
    .line 2482
    iget-object v0, v1, Lzl/d;->b:Lmm/c;

    .line 2483
    .line 2484
    iget-object v2, v0, Lmm/c;->c:Ljava/lang/Throwable;

    .line 2485
    .line 2486
    instance-of v2, v2, Lmm/m;

    .line 2487
    .line 2488
    if-eqz v2, :cond_41

    .line 2489
    .line 2490
    if-eqz v12, :cond_42

    .line 2491
    .line 2492
    new-instance v1, Lzl/d;

    .line 2493
    .line 2494
    invoke-direct {v1, v12, v0}, Lzl/d;-><init>(Li3/c;Lmm/c;)V

    .line 2495
    .line 2496
    .line 2497
    goto :goto_2b

    .line 2498
    :cond_41
    if-eqz v6, :cond_42

    .line 2499
    .line 2500
    new-instance v1, Lzl/d;

    .line 2501
    .line 2502
    invoke-direct {v1, v6, v0}, Lzl/d;-><init>(Li3/c;Lmm/c;)V

    .line 2503
    .line 2504
    .line 2505
    :cond_42
    :goto_2b
    return-object v1

    .line 2506
    :pswitch_1c
    check-cast v0, Lv2/o;

    .line 2507
    .line 2508
    check-cast v12, Lz9/k;

    .line 2509
    .line 2510
    check-cast v6, Laa/v;

    .line 2511
    .line 2512
    move-object/from16 v1, p1

    .line 2513
    .line 2514
    check-cast v1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 2515
    .line 2516
    invoke-virtual {v0, v12}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 2517
    .line 2518
    .line 2519
    new-instance v1, Laa/q;

    .line 2520
    .line 2521
    invoke-direct {v1, v6, v12, v0, v15}, Laa/q;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 2522
    .line 2523
    .line 2524
    return-object v1

    .line 2525
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
