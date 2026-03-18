.class public final synthetic Laa/d0;
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

.field public final synthetic i:Llx0/e;

.field public final synthetic j:Ljava/lang/Object;

.field public final synthetic k:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llx0/e;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p8, p0, Laa/d0;->d:I

    iput-object p1, p0, Laa/d0;->e:Ljava/lang/Object;

    iput-object p2, p0, Laa/d0;->f:Ljava/lang/Object;

    iput-object p3, p0, Laa/d0;->g:Ljava/lang/Object;

    iput-object p4, p0, Laa/d0;->h:Ljava/lang/Object;

    iput-object p5, p0, Laa/d0;->i:Llx0/e;

    iput-object p6, p0, Laa/d0;->j:Ljava/lang/Object;

    iput-object p7, p0, Laa/d0;->k:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lm70/c1;Lay0/k;Lay0/k;Ll2/g1;Lay0/a;Lvy0/b0;Lm1/t;)V
    .locals 1

    .line 2
    const/4 v0, 0x4

    iput v0, p0, Laa/d0;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laa/d0;->e:Ljava/lang/Object;

    iput-object p2, p0, Laa/d0;->g:Ljava/lang/Object;

    iput-object p3, p0, Laa/d0;->h:Ljava/lang/Object;

    iput-object p4, p0, Laa/d0;->f:Ljava/lang/Object;

    iput-object p5, p0, Laa/d0;->i:Llx0/e;

    iput-object p6, p0, Laa/d0;->j:Ljava/lang/Object;

    iput-object p7, p0, Laa/d0;->k:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/d0;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v5, v1

    .line 11
    check-cast v5, Lxh/e;

    .line 12
    .line 13
    iget-object v1, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v7, v1

    .line 16
    check-cast v7, Lxh/e;

    .line 17
    .line 18
    iget-object v1, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v3, v1

    .line 21
    check-cast v3, Lmg/b;

    .line 22
    .line 23
    iget-object v1, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v9, v1

    .line 26
    check-cast v9, Ljava/lang/String;

    .line 27
    .line 28
    iget-object v1, v0, Laa/d0;->i:Llx0/e;

    .line 29
    .line 30
    check-cast v1, Lyj/b;

    .line 31
    .line 32
    iget-object v2, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v2, Lh2/d6;

    .line 35
    .line 36
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v0, Lxh/e;

    .line 39
    .line 40
    move-object/from16 v4, p1

    .line 41
    .line 42
    check-cast v4, Lhi/a;

    .line 43
    .line 44
    const-string v6, "$this$sdkViewModel"

    .line 45
    .line 46
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    new-instance v12, Lpg/p;

    .line 50
    .line 51
    sget-object v6, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 52
    .line 53
    const-class v8, Llg/h;

    .line 54
    .line 55
    invoke-virtual {v6, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 56
    .line 57
    .line 58
    move-result-object v8

    .line 59
    check-cast v4, Lii/a;

    .line 60
    .line 61
    invoke-virtual {v4, v8}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    move-object v10, v8

    .line 66
    check-cast v10, Llg/h;

    .line 67
    .line 68
    const-class v8, Lyi/a;

    .line 69
    .line 70
    invoke-virtual {v6, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    invoke-virtual {v4, v6}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    move-object v11, v4

    .line 79
    check-cast v11, Lyi/a;

    .line 80
    .line 81
    move-object v8, v3

    .line 82
    move-object v6, v12

    .line 83
    invoke-direct/range {v6 .. v11}, Lpg/p;-><init>(Lxh/e;Lmg/b;Ljava/lang/String;Llg/h;Lyi/a;)V

    .line 84
    .line 85
    .line 86
    new-instance v4, Loz/c;

    .line 87
    .line 88
    const/16 v16, 0x0

    .line 89
    .line 90
    const/16 v17, 0x3

    .line 91
    .line 92
    const/4 v11, 0x0

    .line 93
    const-class v13, Lpg/p;

    .line 94
    .line 95
    const-string v14, "gotoSuccess"

    .line 96
    .line 97
    const-string v15, "gotoSuccess()V"

    .line 98
    .line 99
    move-object v10, v4

    .line 100
    invoke-direct/range {v10 .. v17}, Loz/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 101
    .line 102
    .line 103
    new-instance v6, Ljd/b;

    .line 104
    .line 105
    const/16 v17, 0x11

    .line 106
    .line 107
    const/4 v11, 0x2

    .line 108
    const-class v13, Lpg/p;

    .line 109
    .line 110
    const-string v14, "complete"

    .line 111
    .line 112
    const-string v15, "complete-gIAlu-s(Lcariad/charging/multicharge/kitten/subscription/models/SubscriptionUpgradeOrFollowUpCompleteRequest$Action;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 113
    .line 114
    move-object v10, v6

    .line 115
    invoke-direct/range {v10 .. v17}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 116
    .line 117
    .line 118
    move-object v11, v2

    .line 119
    new-instance v2, Lpg/n;

    .line 120
    .line 121
    new-instance v8, Lz81/g;

    .line 122
    .line 123
    const/4 v7, 0x2

    .line 124
    invoke-direct {v8, v7}, Lz81/g;-><init>(I)V

    .line 125
    .line 126
    .line 127
    new-instance v9, Lz81/g;

    .line 128
    .line 129
    invoke-direct {v9, v7}, Lz81/g;-><init>(I)V

    .line 130
    .line 131
    .line 132
    const/4 v12, 0x0

    .line 133
    move-object v10, v0

    .line 134
    move-object v7, v1

    .line 135
    invoke-direct/range {v2 .. v12}, Lpg/n;-><init>(Lmg/b;Lay0/a;Lxh/e;Lay0/n;Lyj/b;Lay0/a;Lay0/a;Lxh/e;Lh2/d6;Z)V

    .line 136
    .line 137
    .line 138
    return-object v2

    .line 139
    :pswitch_0
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v1, Lm70/c1;

    .line 142
    .line 143
    iget-object v2, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 144
    .line 145
    move-object v5, v2

    .line 146
    check-cast v5, Lay0/k;

    .line 147
    .line 148
    iget-object v2, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v6, v2

    .line 151
    check-cast v6, Lay0/k;

    .line 152
    .line 153
    iget-object v2, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 154
    .line 155
    move-object v7, v2

    .line 156
    check-cast v7, Ll2/g1;

    .line 157
    .line 158
    iget-object v2, v0, Laa/d0;->i:Llx0/e;

    .line 159
    .line 160
    check-cast v2, Lay0/a;

    .line 161
    .line 162
    iget-object v3, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 163
    .line 164
    move-object v9, v3

    .line 165
    check-cast v9, Lvy0/b0;

    .line 166
    .line 167
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v0, Lm1/t;

    .line 170
    .line 171
    move-object/from16 v10, p1

    .line 172
    .line 173
    check-cast v10, Lm1/f;

    .line 174
    .line 175
    const-string v3, "$this$LazyColumn"

    .line 176
    .line 177
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    sget-object v3, Ln70/a;->g:Lt2/b;

    .line 181
    .line 182
    const/4 v11, 0x3

    .line 183
    invoke-static {v10, v3, v11}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 184
    .line 185
    .line 186
    iget-object v3, v1, Lm70/c1;->f:Ljava/util/List;

    .line 187
    .line 188
    check-cast v3, Ljava/lang/Iterable;

    .line 189
    .line 190
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 191
    .line 192
    .line 193
    move-result-object v12

    .line 194
    :goto_0
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 195
    .line 196
    .line 197
    move-result v3

    .line 198
    const/4 v13, 0x1

    .line 199
    if-eqz v3, :cond_1

    .line 200
    .line 201
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v3

    .line 205
    check-cast v3, Lm70/b1;

    .line 206
    .line 207
    iget-boolean v14, v1, Lm70/c1;->j:Z

    .line 208
    .line 209
    new-instance v4, Ln70/f0;

    .line 210
    .line 211
    invoke-direct {v4, v3, v14}, Ln70/f0;-><init>(Lm70/b1;Z)V

    .line 212
    .line 213
    .line 214
    new-instance v8, Lt2/b;

    .line 215
    .line 216
    const v15, 0x579930f4

    .line 217
    .line 218
    .line 219
    invoke-direct {v8, v4, v13, v15}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 220
    .line 221
    .line 222
    invoke-static {v10, v8}, Lm1/f;->r(Lm1/f;Lt2/b;)V

    .line 223
    .line 224
    .line 225
    iget-object v3, v3, Lm70/b1;->b:Ljava/util/List;

    .line 226
    .line 227
    check-cast v3, Ljava/lang/Iterable;

    .line 228
    .line 229
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 230
    .line 231
    .line 232
    move-result-object v15

    .line 233
    :goto_1
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 234
    .line 235
    .line 236
    move-result v3

    .line 237
    if-eqz v3, :cond_0

    .line 238
    .line 239
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v3

    .line 243
    check-cast v3, Lm70/x0;

    .line 244
    .line 245
    new-instance v4, Ldl0/b;

    .line 246
    .line 247
    const/4 v8, 0x2

    .line 248
    invoke-direct {v4, v3, v14, v8}, Ldl0/b;-><init>(Ljava/lang/Object;ZI)V

    .line 249
    .line 250
    .line 251
    new-instance v8, Lt2/b;

    .line 252
    .line 253
    move-object/from16 v16, v5

    .line 254
    .line 255
    const v5, -0x70d3d530

    .line 256
    .line 257
    .line 258
    invoke-direct {v8, v4, v13, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 259
    .line 260
    .line 261
    invoke-static {v10, v8, v11}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 262
    .line 263
    .line 264
    iget-object v4, v3, Lm70/x0;->d:Ljava/util/List;

    .line 265
    .line 266
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    new-instance v5, Lak/p;

    .line 271
    .line 272
    const/16 v8, 0x1d

    .line 273
    .line 274
    invoke-direct {v5, v4, v8}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 275
    .line 276
    .line 277
    move v8, v3

    .line 278
    new-instance v3, Lcz/b;

    .line 279
    .line 280
    move/from16 v17, v8

    .line 281
    .line 282
    const/4 v8, 0x1

    .line 283
    move-object/from16 v18, v5

    .line 284
    .line 285
    move-object/from16 v5, v16

    .line 286
    .line 287
    move/from16 v11, v17

    .line 288
    .line 289
    invoke-direct/range {v3 .. v8}, Lcz/b;-><init>(Ljava/util/List;Lay0/k;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 290
    .line 291
    .line 292
    new-instance v4, Lt2/b;

    .line 293
    .line 294
    const v5, 0x799532c4

    .line 295
    .line 296
    .line 297
    invoke-direct {v4, v3, v13, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 298
    .line 299
    .line 300
    const/4 v3, 0x0

    .line 301
    move-object/from16 v5, v18

    .line 302
    .line 303
    invoke-virtual {v10, v11, v3, v5, v4}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 304
    .line 305
    .line 306
    new-instance v3, La71/m;

    .line 307
    .line 308
    const/4 v4, 0x4

    .line 309
    invoke-direct {v3, v4, v14}, La71/m;-><init>(IZ)V

    .line 310
    .line 311
    .line 312
    new-instance v4, Lt2/b;

    .line 313
    .line 314
    const v5, -0x7d92e1f9

    .line 315
    .line 316
    .line 317
    invoke-direct {v4, v3, v13, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 318
    .line 319
    .line 320
    const/4 v3, 0x3

    .line 321
    invoke-static {v10, v4, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 322
    .line 323
    .line 324
    move v11, v3

    .line 325
    move-object/from16 v5, v16

    .line 326
    .line 327
    goto :goto_1

    .line 328
    :cond_0
    move-object/from16 v16, v5

    .line 329
    .line 330
    move v3, v11

    .line 331
    sget-object v4, Ln70/a;->h:Lt2/b;

    .line 332
    .line 333
    invoke-static {v10, v4, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 334
    .line 335
    .line 336
    goto/16 :goto_0

    .line 337
    .line 338
    :cond_1
    move v3, v11

    .line 339
    iget-object v4, v1, Lm70/c1;->f:Ljava/util/List;

    .line 340
    .line 341
    check-cast v4, Ljava/util/Collection;

    .line 342
    .line 343
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 344
    .line 345
    .line 346
    move-result v4

    .line 347
    if-nez v4, :cond_2

    .line 348
    .line 349
    new-instance v4, La71/u0;

    .line 350
    .line 351
    invoke-direct {v4, v1, v2, v9, v0}, La71/u0;-><init>(Lm70/c1;Lay0/a;Lvy0/b0;Lm1/t;)V

    .line 352
    .line 353
    .line 354
    new-instance v0, Lt2/b;

    .line 355
    .line 356
    const v1, -0x1872b8c3

    .line 357
    .line 358
    .line 359
    invoke-direct {v0, v4, v13, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 360
    .line 361
    .line 362
    invoke-static {v10, v0, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 363
    .line 364
    .line 365
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object v0

    .line 368
    :pswitch_1
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 369
    .line 370
    move-object v3, v1

    .line 371
    check-cast v3, Ljava/lang/String;

    .line 372
    .line 373
    iget-object v1, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 374
    .line 375
    move-object v4, v1

    .line 376
    check-cast v4, Lxh/e;

    .line 377
    .line 378
    iget-object v1, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 379
    .line 380
    move-object v6, v1

    .line 381
    check-cast v6, Lyj/b;

    .line 382
    .line 383
    iget-object v1, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 384
    .line 385
    move-object v12, v1

    .line 386
    check-cast v12, Lxh/e;

    .line 387
    .line 388
    iget-object v1, v0, Laa/d0;->i:Llx0/e;

    .line 389
    .line 390
    move-object v7, v1

    .line 391
    check-cast v7, Lyj/b;

    .line 392
    .line 393
    iget-object v1, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 394
    .line 395
    move-object v5, v1

    .line 396
    check-cast v5, Lxh/e;

    .line 397
    .line 398
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast v0, Lxh/e;

    .line 401
    .line 402
    move-object/from16 v1, p1

    .line 403
    .line 404
    check-cast v1, Lhi/a;

    .line 405
    .line 406
    const-string v2, "$this$sdkViewModel"

    .line 407
    .line 408
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 409
    .line 410
    .line 411
    const-class v2, Ldh/u;

    .line 412
    .line 413
    sget-object v8, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 414
    .line 415
    invoke-virtual {v8, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 416
    .line 417
    .line 418
    move-result-object v2

    .line 419
    check-cast v1, Lii/a;

    .line 420
    .line 421
    invoke-virtual {v1, v2}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v1

    .line 425
    move-object v15, v1

    .line 426
    check-cast v15, Ldh/u;

    .line 427
    .line 428
    new-instance v9, Lag/c;

    .line 429
    .line 430
    const/16 v19, 0x0

    .line 431
    .line 432
    const/16 v20, 0xe

    .line 433
    .line 434
    const/4 v14, 0x2

    .line 435
    const-class v16, Ldh/u;

    .line 436
    .line 437
    const-string v17, "reboot"

    .line 438
    .line 439
    const-string v18, "reboot-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChargingStationRebootRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 440
    .line 441
    move-object v13, v9

    .line 442
    invoke-direct/range {v13 .. v20}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 443
    .line 444
    .line 445
    new-instance v10, Lag/c;

    .line 446
    .line 447
    const/16 v20, 0xf

    .line 448
    .line 449
    const-class v16, Ldh/u;

    .line 450
    .line 451
    const-string v17, "unlink"

    .line 452
    .line 453
    const-string v18, "unlink-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChargingStationUnclaimRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 454
    .line 455
    move-object v13, v10

    .line 456
    invoke-direct/range {v13 .. v20}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 457
    .line 458
    .line 459
    new-instance v2, Lei/e;

    .line 460
    .line 461
    new-instance v8, Lai/e;

    .line 462
    .line 463
    const/4 v1, 0x3

    .line 464
    const/4 v11, 0x0

    .line 465
    invoke-direct {v8, v15, v3, v11, v1}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 466
    .line 467
    .line 468
    new-instance v1, Lai/e;

    .line 469
    .line 470
    const/4 v13, 0x4

    .line 471
    invoke-direct {v1, v15, v3, v11, v13}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 472
    .line 473
    .line 474
    new-instance v13, Lbi/b;

    .line 475
    .line 476
    const/4 v11, 0x1

    .line 477
    invoke-direct {v13, v0, v11}, Lbi/b;-><init>(Lxh/e;I)V

    .line 478
    .line 479
    .line 480
    move-object v11, v1

    .line 481
    invoke-direct/range {v2 .. v13}, Lei/e;-><init>(Ljava/lang/String;Lxh/e;Lxh/e;Lyj/b;Lyj/b;Lai/e;Lag/c;Lag/c;Lai/e;Lxh/e;Lbi/b;)V

    .line 482
    .line 483
    .line 484
    return-object v2

    .line 485
    :pswitch_2
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 486
    .line 487
    move-object v3, v1

    .line 488
    check-cast v3, Ljava/lang/String;

    .line 489
    .line 490
    iget-object v1, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 491
    .line 492
    move-object v4, v1

    .line 493
    check-cast v4, Lxh/e;

    .line 494
    .line 495
    iget-object v1, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 496
    .line 497
    move-object v6, v1

    .line 498
    check-cast v6, Lyj/b;

    .line 499
    .line 500
    iget-object v1, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 501
    .line 502
    move-object v12, v1

    .line 503
    check-cast v12, Lxh/e;

    .line 504
    .line 505
    iget-object v1, v0, Laa/d0;->i:Llx0/e;

    .line 506
    .line 507
    move-object v7, v1

    .line 508
    check-cast v7, Lyj/b;

    .line 509
    .line 510
    iget-object v1, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 511
    .line 512
    move-object v5, v1

    .line 513
    check-cast v5, Lxh/e;

    .line 514
    .line 515
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 516
    .line 517
    move-object v13, v0

    .line 518
    check-cast v13, Lzb/s0;

    .line 519
    .line 520
    move-object/from16 v0, p1

    .line 521
    .line 522
    check-cast v0, Lhi/a;

    .line 523
    .line 524
    const-string v1, "$this$sdkViewModel"

    .line 525
    .line 526
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    const-class v1, Ldh/u;

    .line 530
    .line 531
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 532
    .line 533
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 534
    .line 535
    .line 536
    move-result-object v1

    .line 537
    check-cast v0, Lii/a;

    .line 538
    .line 539
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object v0

    .line 543
    move-object/from16 v16, v0

    .line 544
    .line 545
    check-cast v16, Ldh/u;

    .line 546
    .line 547
    new-instance v14, Lag/c;

    .line 548
    .line 549
    const/16 v20, 0x0

    .line 550
    .line 551
    const/16 v21, 0xb

    .line 552
    .line 553
    const/4 v15, 0x2

    .line 554
    const-class v17, Ldh/u;

    .line 555
    .line 556
    const-string v18, "reboot"

    .line 557
    .line 558
    const-string v19, "reboot-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChargingStationRebootRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 559
    .line 560
    invoke-direct/range {v14 .. v21}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 561
    .line 562
    .line 563
    move-object v9, v14

    .line 564
    new-instance v14, Lag/c;

    .line 565
    .line 566
    const/16 v21, 0xc

    .line 567
    .line 568
    const-class v17, Ldh/u;

    .line 569
    .line 570
    const-string v18, "unlink"

    .line 571
    .line 572
    const-string v19, "unlink-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/ChargingStationUnclaimRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 573
    .line 574
    invoke-direct/range {v14 .. v21}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 575
    .line 576
    .line 577
    move-object/from16 v0, v16

    .line 578
    .line 579
    new-instance v2, Ldi/o;

    .line 580
    .line 581
    new-instance v8, Lai/e;

    .line 582
    .line 583
    const/4 v1, 0x1

    .line 584
    const/4 v10, 0x0

    .line 585
    invoke-direct {v8, v0, v3, v10, v1}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 586
    .line 587
    .line 588
    new-instance v11, Lai/e;

    .line 589
    .line 590
    const/4 v1, 0x2

    .line 591
    invoke-direct {v11, v0, v3, v10, v1}, Lai/e;-><init>(Ldh/u;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 592
    .line 593
    .line 594
    move-object v10, v14

    .line 595
    invoke-direct/range {v2 .. v13}, Ldi/o;-><init>(Ljava/lang/String;Lxh/e;Lxh/e;Lyj/b;Lyj/b;Lai/e;Lag/c;Lag/c;Lai/e;Lxh/e;Lzb/s0;)V

    .line 596
    .line 597
    .line 598
    return-object v2

    .line 599
    :pswitch_3
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 600
    .line 601
    move-object v4, v1

    .line 602
    check-cast v4, Lx40/j;

    .line 603
    .line 604
    iget-object v1, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 605
    .line 606
    move-object v5, v1

    .line 607
    check-cast v5, Lxh/e;

    .line 608
    .line 609
    iget-object v1, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 610
    .line 611
    move-object v6, v1

    .line 612
    check-cast v6, Lzb/d;

    .line 613
    .line 614
    iget-object v1, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 615
    .line 616
    move-object v13, v1

    .line 617
    check-cast v13, Lxh/e;

    .line 618
    .line 619
    iget-object v1, v0, Laa/d0;->i:Llx0/e;

    .line 620
    .line 621
    move-object v11, v1

    .line 622
    check-cast v11, Lxh/e;

    .line 623
    .line 624
    iget-object v1, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 625
    .line 626
    move-object v12, v1

    .line 627
    check-cast v12, Lxh/e;

    .line 628
    .line 629
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 630
    .line 631
    move-object v14, v0

    .line 632
    check-cast v14, Ljava/lang/String;

    .line 633
    .line 634
    move-object/from16 v0, p1

    .line 635
    .line 636
    check-cast v0, Lhi/a;

    .line 637
    .line 638
    const-string v1, "$this$sdkViewModel"

    .line 639
    .line 640
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 641
    .line 642
    .line 643
    const-class v1, Ldh/u;

    .line 644
    .line 645
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 646
    .line 647
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 648
    .line 649
    .line 650
    move-result-object v1

    .line 651
    check-cast v0, Lii/a;

    .line 652
    .line 653
    invoke-virtual {v0, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v0

    .line 657
    move-object/from16 v17, v0

    .line 658
    .line 659
    check-cast v17, Ldh/u;

    .line 660
    .line 661
    new-instance v15, La50/d;

    .line 662
    .line 663
    const/16 v21, 0x0

    .line 664
    .line 665
    const/16 v22, 0x2

    .line 666
    .line 667
    const/16 v16, 0x2

    .line 668
    .line 669
    const-class v18, Ldh/u;

    .line 670
    .line 671
    const-string v19, "getHomeChargingInfrastructure"

    .line 672
    .line 673
    const-string v20, "getHomeChargingInfrastructure-0E7RQCE(Ljava/lang/String;Ljava/lang/Boolean;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 674
    .line 675
    invoke-direct/range {v15 .. v22}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 676
    .line 677
    .line 678
    move-object v3, v15

    .line 679
    new-instance v15, Lag/c;

    .line 680
    .line 681
    const/16 v22, 0x3

    .line 682
    .line 683
    const-class v18, Ldh/u;

    .line 684
    .line 685
    const-string v19, "startCharging"

    .line 686
    .line 687
    const-string v20, "startCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StartChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 688
    .line 689
    invoke-direct/range {v15 .. v22}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 690
    .line 691
    .line 692
    move-object v7, v15

    .line 693
    new-instance v15, Lag/c;

    .line 694
    .line 695
    const/16 v22, 0x4

    .line 696
    .line 697
    const-class v18, Ldh/u;

    .line 698
    .line 699
    const-string v19, "stopCharging"

    .line 700
    .line 701
    const-string v20, "stopCharging-gIAlu-s(Lcariad/charging/multicharge/kitten/wallboxes/models/StopChargingSessionRequest;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 702
    .line 703
    invoke-direct/range {v15 .. v22}, Lag/c;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 704
    .line 705
    .line 706
    move-object/from16 v0, v17

    .line 707
    .line 708
    new-instance v2, Lai/l;

    .line 709
    .line 710
    new-instance v9, La71/a0;

    .line 711
    .line 712
    const/4 v1, 0x2

    .line 713
    invoke-direct {v9, v0, v1}, La71/a0;-><init>(Ljava/lang/Object;I)V

    .line 714
    .line 715
    .line 716
    new-instance v10, Lai/d;

    .line 717
    .line 718
    const/4 v1, 0x0

    .line 719
    invoke-direct {v10, v0, v1}, Lai/d;-><init>(Ldh/u;I)V

    .line 720
    .line 721
    .line 722
    move-object v8, v15

    .line 723
    invoke-direct/range {v2 .. v14}, Lai/l;-><init>(La50/d;Lx40/j;Lxh/e;Lzb/d;Lag/c;Lag/c;La71/a0;Lai/d;Lxh/e;Lxh/e;Lxh/e;Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    return-object v2

    .line 727
    :pswitch_4
    iget-object v1, v0, Laa/d0;->e:Ljava/lang/Object;

    .line 728
    .line 729
    check-cast v1, Landroidx/collection/g0;

    .line 730
    .line 731
    iget-object v2, v0, Laa/d0;->f:Ljava/lang/Object;

    .line 732
    .line 733
    check-cast v2, Laa/i;

    .line 734
    .line 735
    iget-object v3, v0, Laa/d0;->g:Ljava/lang/Object;

    .line 736
    .line 737
    check-cast v3, Lay0/k;

    .line 738
    .line 739
    iget-object v4, v0, Laa/d0;->h:Ljava/lang/Object;

    .line 740
    .line 741
    check-cast v4, Lay0/k;

    .line 742
    .line 743
    iget-object v5, v0, Laa/d0;->i:Llx0/e;

    .line 744
    .line 745
    check-cast v5, Lay0/k;

    .line 746
    .line 747
    iget-object v6, v0, Laa/d0;->j:Ljava/lang/Object;

    .line 748
    .line 749
    check-cast v6, Ll2/t2;

    .line 750
    .line 751
    iget-object v0, v0, Laa/d0;->k:Ljava/lang/Object;

    .line 752
    .line 753
    check-cast v0, Ll2/b1;

    .line 754
    .line 755
    move-object/from16 v7, p1

    .line 756
    .line 757
    check-cast v7, Lb1/t;

    .line 758
    .line 759
    invoke-interface {v6}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 760
    .line 761
    .line 762
    move-result-object v6

    .line 763
    check-cast v6, Ljava/util/List;

    .line 764
    .line 765
    invoke-virtual {v7}, Lb1/t;->b()Ljava/lang/Object;

    .line 766
    .line 767
    .line 768
    move-result-object v8

    .line 769
    invoke-interface {v6, v8}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 770
    .line 771
    .line 772
    move-result v6

    .line 773
    if-eqz v6, :cond_7

    .line 774
    .line 775
    invoke-virtual {v7}, Lb1/t;->b()Ljava/lang/Object;

    .line 776
    .line 777
    .line 778
    move-result-object v6

    .line 779
    check-cast v6, Lz9/k;

    .line 780
    .line 781
    iget-object v6, v6, Lz9/k;->i:Ljava/lang/String;

    .line 782
    .line 783
    invoke-virtual {v1, v6}, Landroidx/collection/g0;->b(Ljava/lang/Object;)I

    .line 784
    .line 785
    .line 786
    move-result v8

    .line 787
    if-ltz v8, :cond_3

    .line 788
    .line 789
    iget-object v6, v1, Landroidx/collection/g0;->c:[F

    .line 790
    .line 791
    aget v6, v6, v8

    .line 792
    .line 793
    goto :goto_2

    .line 794
    :cond_3
    const/4 v8, 0x0

    .line 795
    invoke-virtual {v1, v6, v8}, Landroidx/collection/g0;->d(Ljava/lang/String;F)V

    .line 796
    .line 797
    .line 798
    move v6, v8

    .line 799
    :goto_2
    invoke-virtual {v7}, Lb1/t;->a()Ljava/lang/Object;

    .line 800
    .line 801
    .line 802
    move-result-object v8

    .line 803
    check-cast v8, Lz9/k;

    .line 804
    .line 805
    iget-object v8, v8, Lz9/k;->i:Ljava/lang/String;

    .line 806
    .line 807
    invoke-virtual {v7}, Lb1/t;->b()Ljava/lang/Object;

    .line 808
    .line 809
    .line 810
    move-result-object v9

    .line 811
    check-cast v9, Lz9/k;

    .line 812
    .line 813
    iget-object v9, v9, Lz9/k;->i:Ljava/lang/String;

    .line 814
    .line 815
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 816
    .line 817
    .line 818
    move-result v8

    .line 819
    if-eqz v8, :cond_4

    .line 820
    .line 821
    goto :goto_4

    .line 822
    :cond_4
    iget-object v2, v2, Laa/i;->c:Ll2/j1;

    .line 823
    .line 824
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 825
    .line 826
    .line 827
    move-result-object v2

    .line 828
    check-cast v2, Ljava/lang/Boolean;

    .line 829
    .line 830
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 831
    .line 832
    .line 833
    move-result v2

    .line 834
    const/high16 v8, 0x3f800000    # 1.0f

    .line 835
    .line 836
    if-nez v2, :cond_6

    .line 837
    .line 838
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 839
    .line 840
    .line 841
    move-result-object v0

    .line 842
    check-cast v0, Ljava/lang/Boolean;

    .line 843
    .line 844
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 845
    .line 846
    .line 847
    move-result v0

    .line 848
    if-eqz v0, :cond_5

    .line 849
    .line 850
    goto :goto_3

    .line 851
    :cond_5
    add-float/2addr v6, v8

    .line 852
    goto :goto_4

    .line 853
    :cond_6
    :goto_3
    sub-float/2addr v6, v8

    .line 854
    :goto_4
    invoke-virtual {v7}, Lb1/t;->a()Ljava/lang/Object;

    .line 855
    .line 856
    .line 857
    move-result-object v0

    .line 858
    check-cast v0, Lz9/k;

    .line 859
    .line 860
    iget-object v0, v0, Lz9/k;->i:Ljava/lang/String;

    .line 861
    .line 862
    invoke-virtual {v1, v0, v6}, Landroidx/collection/g0;->d(Ljava/lang/String;F)V

    .line 863
    .line 864
    .line 865
    new-instance v0, Lb1/d0;

    .line 866
    .line 867
    invoke-interface {v3, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 868
    .line 869
    .line 870
    move-result-object v1

    .line 871
    check-cast v1, Lb1/t0;

    .line 872
    .line 873
    invoke-interface {v4, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 874
    .line 875
    .line 876
    move-result-object v2

    .line 877
    check-cast v2, Lb1/u0;

    .line 878
    .line 879
    invoke-interface {v5, v7}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 880
    .line 881
    .line 882
    move-result-object v3

    .line 883
    check-cast v3, Lb1/f1;

    .line 884
    .line 885
    invoke-direct {v0, v1, v2, v6, v3}, Lb1/d0;-><init>(Lb1/t0;Lb1/u0;FLb1/f1;)V

    .line 886
    .line 887
    .line 888
    goto :goto_5

    .line 889
    :cond_7
    sget-object v0, Lb1/t0;->b:Lb1/t0;

    .line 890
    .line 891
    sget-object v1, Lb1/u0;->b:Lb1/u0;

    .line 892
    .line 893
    invoke-static {v0, v1}, Landroidx/compose/animation/a;->c(Lb1/t0;Lb1/u0;)Lb1/d0;

    .line 894
    .line 895
    .line 896
    move-result-object v0

    .line 897
    :goto_5
    return-object v0

    .line 898
    nop

    .line 899
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
