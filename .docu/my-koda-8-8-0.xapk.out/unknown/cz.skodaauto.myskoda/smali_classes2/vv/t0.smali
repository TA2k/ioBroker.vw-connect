.class public final Lvv/t0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:F

.field public final synthetic i:Lay0/k;


# direct methods
.method public constructor <init>(ILjava/util/List;FLay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/t0;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lvv/t0;->g:Ljava/util/List;

    .line 4
    .line 5
    iput p3, p0, Lvv/t0;->h:F

    .line 6
    .line 7
    iput-object p4, p0, Lvv/t0;->i:Lay0/k;

    .line 8
    .line 9
    const/4 p1, 0x2

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v3, p1

    .line 4
    .line 5
    check-cast v3, Lt3/p1;

    .line 6
    .line 7
    move-object/from16 v1, p2

    .line 8
    .line 9
    check-cast v1, Lt4/a;

    .line 10
    .line 11
    iget-wide v1, v1, Lt4/a;->a:J

    .line 12
    .line 13
    const-string v4, "$this$SubcomposeLayout"

    .line 14
    .line 15
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 19
    .line 20
    new-instance v5, Lvv/z;

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    iget-object v7, v0, Lvv/t0;->g:Ljava/util/List;

    .line 24
    .line 25
    iget v8, v0, Lvv/t0;->f:I

    .line 26
    .line 27
    invoke-direct {v5, v7, v8, v6}, Lvv/z;-><init>(Ljava/lang/Object;II)V

    .line 28
    .line 29
    .line 30
    new-instance v6, Lt2/b;

    .line 31
    .line 32
    const/4 v9, 0x1

    .line 33
    const v10, -0xd57f0d3

    .line 34
    .line 35
    .line 36
    invoke-direct {v6, v5, v9, v10}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 37
    .line 38
    .line 39
    invoke-interface {v3, v4, v6}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Ljava/lang/Iterable;

    .line 44
    .line 45
    if-lez v8, :cond_11

    .line 46
    .line 47
    if-lez v8, :cond_11

    .line 48
    .line 49
    instance-of v5, v4, Ljava/util/RandomAccess;

    .line 50
    .line 51
    const/4 v6, 0x0

    .line 52
    const/4 v10, 0x0

    .line 53
    if-eqz v5, :cond_4

    .line 54
    .line 55
    instance-of v5, v4, Ljava/util/List;

    .line 56
    .line 57
    if-eqz v5, :cond_4

    .line 58
    .line 59
    check-cast v4, Ljava/util/List;

    .line 60
    .line 61
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    div-int v11, v5, v8

    .line 66
    .line 67
    rem-int v12, v5, v8

    .line 68
    .line 69
    if-nez v12, :cond_0

    .line 70
    .line 71
    move v12, v10

    .line 72
    goto :goto_0

    .line 73
    :cond_0
    move v12, v9

    .line 74
    :goto_0
    add-int/2addr v11, v12

    .line 75
    new-instance v12, Ljava/util/ArrayList;

    .line 76
    .line 77
    invoke-direct {v12, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 78
    .line 79
    .line 80
    move v11, v10

    .line 81
    :goto_1
    if-ltz v11, :cond_3

    .line 82
    .line 83
    if-ge v11, v5, :cond_3

    .line 84
    .line 85
    sub-int v13, v5, v11

    .line 86
    .line 87
    if-le v8, v13, :cond_1

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_1
    move v13, v8

    .line 91
    :goto_2
    new-instance v14, Ljava/util/ArrayList;

    .line 92
    .line 93
    invoke-direct {v14, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 94
    .line 95
    .line 96
    move v15, v10

    .line 97
    :goto_3
    move/from16 p1, v9

    .line 98
    .line 99
    if-ge v15, v13, :cond_2

    .line 100
    .line 101
    add-int v9, v15, v11

    .line 102
    .line 103
    invoke-interface {v4, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v9

    .line 107
    invoke-virtual {v14, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    add-int/lit8 v15, v15, 0x1

    .line 111
    .line 112
    move/from16 v9, p1

    .line 113
    .line 114
    goto :goto_3

    .line 115
    :cond_2
    invoke-virtual {v12, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    add-int/2addr v11, v8

    .line 119
    goto :goto_1

    .line 120
    :cond_3
    move/from16 p1, v9

    .line 121
    .line 122
    goto :goto_5

    .line 123
    :cond_4
    move/from16 p1, v9

    .line 124
    .line 125
    new-instance v12, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 128
    .line 129
    .line 130
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 131
    .line 132
    .line 133
    move-result-object v4

    .line 134
    const-string v5, "iterator"

    .line 135
    .line 136
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result v5

    .line 143
    if-nez v5, :cond_5

    .line 144
    .line 145
    sget-object v4, Lmx0/r;->d:Lmx0/r;

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_5
    new-instance v5, Lmx0/c0;

    .line 149
    .line 150
    invoke-direct {v5, v8, v8, v4, v6}, Lmx0/c0;-><init>(IILjava/util/Iterator;Lkotlin/coroutines/Continuation;)V

    .line 151
    .line 152
    .line 153
    invoke-static {v5}, Llp/ke;->a(Lay0/n;)Lky0/k;

    .line 154
    .line 155
    .line 156
    move-result-object v4

    .line 157
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-eqz v5, :cond_6

    .line 162
    .line 163
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    check-cast v5, Ljava/util/List;

    .line 168
    .line 169
    invoke-virtual {v12, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    goto :goto_4

    .line 173
    :cond_6
    :goto_5
    invoke-interface {v12}, Ljava/util/List;->size()I

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 178
    .line 179
    .line 180
    move-result v5

    .line 181
    if-ne v4, v5, :cond_10

    .line 182
    .line 183
    invoke-static {v1, v2}, Lt4/a;->d(J)Z

    .line 184
    .line 185
    .line 186
    move-result v4

    .line 187
    if-eqz v4, :cond_f

    .line 188
    .line 189
    add-int/lit8 v4, v8, 0x1

    .line 190
    .line 191
    int-to-float v4, v4

    .line 192
    iget v5, v0, Lvv/t0;->h:F

    .line 193
    .line 194
    mul-float/2addr v4, v5

    .line 195
    invoke-static {v1, v2}, Lt4/a;->h(J)I

    .line 196
    .line 197
    .line 198
    move-result v7

    .line 199
    int-to-float v7, v7

    .line 200
    sub-float/2addr v7, v4

    .line 201
    int-to-float v4, v8

    .line 202
    div-float/2addr v7, v4

    .line 203
    invoke-interface {v12}, Ljava/util/List;->size()I

    .line 204
    .line 205
    .line 206
    move-result v4

    .line 207
    add-int/lit8 v4, v4, 0x1

    .line 208
    .line 209
    int-to-float v4, v4

    .line 210
    mul-float/2addr v5, v4

    .line 211
    invoke-static {v7}, Lcy0/a;->i(F)I

    .line 212
    .line 213
    .line 214
    move-result v4

    .line 215
    const/16 v8, 0xd

    .line 216
    .line 217
    invoke-static {v4, v10, v8}, Lt4/b;->b(III)J

    .line 218
    .line 219
    .line 220
    move-result-wide v8

    .line 221
    invoke-static {v8, v9, v1, v2}, Lt4/b;->e(JJ)J

    .line 222
    .line 223
    .line 224
    move-result-wide v8

    .line 225
    move-wide v13, v1

    .line 226
    new-instance v2, Ljava/util/ArrayList;

    .line 227
    .line 228
    const/16 v1, 0xa

    .line 229
    .line 230
    invoke-static {v12, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 231
    .line 232
    .line 233
    move-result v4

    .line 234
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 235
    .line 236
    .line 237
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 238
    .line 239
    .line 240
    move-result-object v4

    .line 241
    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 242
    .line 243
    .line 244
    move-result v11

    .line 245
    if-eqz v11, :cond_8

    .line 246
    .line 247
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    move-result-object v11

    .line 251
    check-cast v11, Ljava/util/List;

    .line 252
    .line 253
    check-cast v11, Ljava/lang/Iterable;

    .line 254
    .line 255
    new-instance v12, Ljava/util/ArrayList;

    .line 256
    .line 257
    invoke-static {v11, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 258
    .line 259
    .line 260
    move-result v15

    .line 261
    invoke-direct {v12, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 262
    .line 263
    .line 264
    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 265
    .line 266
    .line 267
    move-result-object v11

    .line 268
    :goto_7
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 269
    .line 270
    .line 271
    move-result v15

    .line 272
    if-eqz v15, :cond_7

    .line 273
    .line 274
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v15

    .line 278
    check-cast v15, Lt3/p0;

    .line 279
    .line 280
    invoke-interface {v15, v8, v9}, Lt3/p0;->L(J)Lt3/e1;

    .line 281
    .line 282
    .line 283
    move-result-object v15

    .line 284
    invoke-virtual {v12, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    goto :goto_7

    .line 288
    :cond_7
    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 289
    .line 290
    .line 291
    goto :goto_6

    .line 292
    :cond_8
    new-instance v4, Ljava/util/ArrayList;

    .line 293
    .line 294
    invoke-static {v2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 295
    .line 296
    .line 297
    move-result v1

    .line 298
    invoke-direct {v4, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 302
    .line 303
    .line 304
    move-result-object v1

    .line 305
    :goto_8
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 306
    .line 307
    .line 308
    move-result v8

    .line 309
    if-eqz v8, :cond_d

    .line 310
    .line 311
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v8

    .line 315
    check-cast v8, Ljava/util/List;

    .line 316
    .line 317
    check-cast v8, Ljava/lang/Iterable;

    .line 318
    .line 319
    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 320
    .line 321
    .line 322
    move-result-object v8

    .line 323
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 324
    .line 325
    .line 326
    move-result v9

    .line 327
    if-nez v9, :cond_9

    .line 328
    .line 329
    move-object v9, v6

    .line 330
    goto :goto_9

    .line 331
    :cond_9
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v9

    .line 335
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 336
    .line 337
    .line 338
    move-result v11

    .line 339
    if-nez v11, :cond_a

    .line 340
    .line 341
    goto :goto_9

    .line 342
    :cond_a
    move-object v11, v9

    .line 343
    check-cast v11, Lt3/e1;

    .line 344
    .line 345
    iget v11, v11, Lt3/e1;->e:I

    .line 346
    .line 347
    :cond_b
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v12

    .line 351
    move-object v15, v12

    .line 352
    check-cast v15, Lt3/e1;

    .line 353
    .line 354
    iget v15, v15, Lt3/e1;->e:I

    .line 355
    .line 356
    if-ge v11, v15, :cond_c

    .line 357
    .line 358
    move-object v9, v12

    .line 359
    move v11, v15

    .line 360
    :cond_c
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 361
    .line 362
    .line 363
    move-result v12

    .line 364
    if-nez v12, :cond_b

    .line 365
    .line 366
    :goto_9
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 367
    .line 368
    .line 369
    check-cast v9, Lt3/e1;

    .line 370
    .line 371
    iget v8, v9, Lt3/e1;->e:I

    .line 372
    .line 373
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 374
    .line 375
    .line 376
    move-result-object v8

    .line 377
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 378
    .line 379
    .line 380
    goto :goto_8

    .line 381
    :cond_d
    invoke-static {v13, v14}, Lt4/a;->h(J)I

    .line 382
    .line 383
    .line 384
    move-result v1

    .line 385
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 386
    .line 387
    .line 388
    move-result-object v6

    .line 389
    :goto_a
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 390
    .line 391
    .line 392
    move-result v8

    .line 393
    if-eqz v8, :cond_e

    .line 394
    .line 395
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v8

    .line 399
    check-cast v8, Ljava/lang/Number;

    .line 400
    .line 401
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 402
    .line 403
    .line 404
    move-result v8

    .line 405
    add-int/2addr v10, v8

    .line 406
    goto :goto_a

    .line 407
    :cond_e
    int-to-float v6, v10

    .line 408
    add-float/2addr v6, v5

    .line 409
    invoke-static {v6}, Lcy0/a;->i(F)I

    .line 410
    .line 411
    .line 412
    move-result v5

    .line 413
    new-instance v6, Lvv/s0;

    .line 414
    .line 415
    move-object v8, v6

    .line 416
    move-object v6, v4

    .line 417
    move v4, v1

    .line 418
    iget v1, v0, Lvv/t0;->h:F

    .line 419
    .line 420
    iget-object v0, v0, Lvv/t0;->i:Lay0/k;

    .line 421
    .line 422
    move-object/from16 v16, v8

    .line 423
    .line 424
    move-object v8, v0

    .line 425
    move-object/from16 v0, v16

    .line 426
    .line 427
    invoke-direct/range {v0 .. v8}, Lvv/s0;-><init>(FLjava/util/ArrayList;Lt3/p1;IILjava/util/ArrayList;FLay0/k;)V

    .line 428
    .line 429
    .line 430
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 431
    .line 432
    invoke-interface {v3, v4, v5, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    return-object v0

    .line 437
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 438
    .line 439
    const-string v1, "Table must have bounded width"

    .line 440
    .line 441
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    throw v0

    .line 445
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 446
    .line 447
    const-string v1, "Check failed."

    .line 448
    .line 449
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 450
    .line 451
    .line 452
    throw v0

    .line 453
    :cond_11
    const-string v0, "size "

    .line 454
    .line 455
    const-string v1, " must be greater than zero."

    .line 456
    .line 457
    invoke-static {v0, v8, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 458
    .line 459
    .line 460
    move-result-object v0

    .line 461
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 462
    .line 463
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 464
    .line 465
    .line 466
    move-result-object v0

    .line 467
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    throw v1
.end method
