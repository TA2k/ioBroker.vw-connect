.class public final synthetic Li91/t3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lay0/k;

.field public final synthetic e:Z

.field public final synthetic f:I

.field public final synthetic g:Lgy0/f;

.field public final synthetic h:Lay0/k;

.field public final synthetic i:Lx2/s;

.field public final synthetic j:Lgy0/f;

.field public final synthetic k:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;ZILgy0/f;Lay0/k;Lx2/s;Lgy0/f;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Li91/t3;->d:Lay0/k;

    .line 5
    .line 6
    iput-boolean p2, p0, Li91/t3;->e:Z

    .line 7
    .line 8
    iput p3, p0, Li91/t3;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Li91/t3;->g:Lgy0/f;

    .line 11
    .line 12
    iput-object p5, p0, Li91/t3;->h:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Li91/t3;->i:Lx2/s;

    .line 15
    .line 16
    iput-object p7, p0, Li91/t3;->j:Lgy0/f;

    .line 17
    .line 18
    iput-object p8, p0, Li91/t3;->k:Lay0/k;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Landroidx/compose/foundation/layout/c;

    .line 6
    .line 7
    move-object/from16 v2, p2

    .line 8
    .line 9
    check-cast v2, Ll2/o;

    .line 10
    .line 11
    move-object/from16 v3, p3

    .line 12
    .line 13
    check-cast v3, Ljava/lang/Integer;

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    const-string v4, "$this$BoxWithConstraints"

    .line 20
    .line 21
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    iget-wide v4, v1, Landroidx/compose/foundation/layout/c;->b:J

    .line 25
    .line 26
    and-int/lit8 v6, v3, 0x6

    .line 27
    .line 28
    if-nez v6, :cond_1

    .line 29
    .line 30
    move-object v6, v2

    .line 31
    check-cast v6, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v6, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    const/4 v1, 0x4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/4 v1, 0x2

    .line 42
    :goto_0
    or-int/2addr v3, v1

    .line 43
    :cond_1
    and-int/lit8 v1, v3, 0x13

    .line 44
    .line 45
    const/16 v6, 0x12

    .line 46
    .line 47
    const/4 v7, 0x1

    .line 48
    const/4 v8, 0x0

    .line 49
    if-eq v1, v6, :cond_2

    .line 50
    .line 51
    move v1, v7

    .line 52
    goto :goto_1

    .line 53
    :cond_2
    move v1, v8

    .line 54
    :goto_1
    and-int/2addr v3, v7

    .line 55
    move-object v14, v2

    .line 56
    check-cast v14, Ll2/t;

    .line 57
    .line 58
    invoke-virtual {v14, v3, v1}, Ll2/t;->O(IZ)Z

    .line 59
    .line 60
    .line 61
    move-result v1

    .line 62
    if-eqz v1, :cond_f

    .line 63
    .line 64
    iget-object v1, v0, Li91/t3;->d:Lay0/k;

    .line 65
    .line 66
    const/4 v2, 0x0

    .line 67
    if-eqz v1, :cond_3

    .line 68
    .line 69
    const v3, -0x1cc877f5

    .line 70
    .line 71
    .line 72
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 73
    .line 74
    .line 75
    new-instance v3, Llx0/l;

    .line 76
    .line 77
    invoke-static {v14}, Li91/u3;->g(Ll2/t;)Li91/v3;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    invoke-static {v14}, Li91/u3;->g(Ll2/t;)Li91/v3;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    invoke-direct {v3, v6, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_3
    const v3, -0x1cc72089

    .line 93
    .line 94
    .line 95
    invoke-virtual {v14, v3}, Ll2/t;->Y(I)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 99
    .line 100
    .line 101
    new-instance v3, Llx0/l;

    .line 102
    .line 103
    invoke-direct {v3, v2, v2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 104
    .line 105
    .line 106
    :goto_2
    iget-object v6, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v6, Li91/v3;

    .line 109
    .line 110
    iget-object v3, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v3, Li91/v3;

    .line 113
    .line 114
    iget-object v7, v0, Li91/t3;->g:Lgy0/f;

    .line 115
    .line 116
    iget-object v11, v0, Li91/t3;->j:Lgy0/f;

    .line 117
    .line 118
    const-string v9, "Required value was null."

    .line 119
    .line 120
    if-nez v6, :cond_4

    .line 121
    .line 122
    const v10, -0x1cc5e2ab

    .line 123
    .line 124
    .line 125
    invoke-virtual {v14, v10}, Ll2/t;->Y(I)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 129
    .line 130
    .line 131
    move-object/from16 v24, v9

    .line 132
    .line 133
    goto :goto_3

    .line 134
    :cond_4
    const v10, -0x1cc5e2aa

    .line 135
    .line 136
    .line 137
    invoke-virtual {v14, v10}, Ll2/t;->Y(I)V

    .line 138
    .line 139
    .line 140
    if-eqz v1, :cond_e

    .line 141
    .line 142
    invoke-interface {v7}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 143
    .line 144
    .line 145
    move-result-object v10

    .line 146
    check-cast v10, Ljava/lang/Number;

    .line 147
    .line 148
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 149
    .line 150
    .line 151
    move-result v10

    .line 152
    invoke-static {v10}, Lcy0/a;->i(F)I

    .line 153
    .line 154
    .line 155
    move-result v10

    .line 156
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 157
    .line 158
    .line 159
    move-result-object v10

    .line 160
    invoke-interface {v1, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v10

    .line 164
    check-cast v10, Ljava/lang/String;

    .line 165
    .line 166
    invoke-interface {v7}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 167
    .line 168
    .line 169
    move-result-object v12

    .line 170
    check-cast v12, Ljava/lang/Number;

    .line 171
    .line 172
    invoke-virtual {v12}, Ljava/lang/Number;->floatValue()F

    .line 173
    .line 174
    .line 175
    move-result v12

    .line 176
    move-object v13, v9

    .line 177
    move-object v9, v10

    .line 178
    move v10, v12

    .line 179
    invoke-static {v4, v5}, Lt4/a;->h(J)I

    .line 180
    .line 181
    .line 182
    move-result v12

    .line 183
    iget-object v15, v6, Li91/v3;->a:Ll2/b1;

    .line 184
    .line 185
    invoke-interface {v15}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v15

    .line 189
    check-cast v15, Ljava/lang/Boolean;

    .line 190
    .line 191
    invoke-virtual {v15}, Ljava/lang/Boolean;->booleanValue()Z

    .line 192
    .line 193
    .line 194
    move-result v15

    .line 195
    move-object/from16 v16, v13

    .line 196
    .line 197
    move v13, v15

    .line 198
    const/4 v15, 0x0

    .line 199
    move-object/from16 v24, v16

    .line 200
    .line 201
    invoke-static/range {v9 .. v15}, Li91/u3;->e(Ljava/lang/String;FLgy0/f;IZLl2/o;I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 205
    .line 206
    .line 207
    :goto_3
    if-nez v3, :cond_5

    .line 208
    .line 209
    const v1, -0x1cbfea1a

    .line 210
    .line 211
    .line 212
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 213
    .line 214
    .line 215
    :goto_4
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    goto :goto_5

    .line 219
    :cond_5
    const v9, -0x1cbfea19

    .line 220
    .line 221
    .line 222
    invoke-virtual {v14, v9}, Ll2/t;->Y(I)V

    .line 223
    .line 224
    .line 225
    if-eqz v1, :cond_d

    .line 226
    .line 227
    invoke-interface {v7}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    check-cast v9, Ljava/lang/Number;

    .line 232
    .line 233
    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    .line 234
    .line 235
    .line 236
    move-result v9

    .line 237
    invoke-static {v9}, Lcy0/a;->i(F)I

    .line 238
    .line 239
    .line 240
    move-result v9

    .line 241
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 242
    .line 243
    .line 244
    move-result-object v9

    .line 245
    invoke-interface {v1, v9}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    move-object v9, v1

    .line 250
    check-cast v9, Ljava/lang/String;

    .line 251
    .line 252
    invoke-interface {v7}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    check-cast v1, Ljava/lang/Number;

    .line 257
    .line 258
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 259
    .line 260
    .line 261
    move-result v10

    .line 262
    invoke-static {v4, v5}, Lt4/a;->h(J)I

    .line 263
    .line 264
    .line 265
    move-result v12

    .line 266
    iget-object v1, v3, Li91/v3;->a:Ll2/b1;

    .line 267
    .line 268
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    check-cast v1, Ljava/lang/Boolean;

    .line 273
    .line 274
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 275
    .line 276
    .line 277
    move-result v13

    .line 278
    const/4 v15, 0x0

    .line 279
    invoke-static/range {v9 .. v15}, Li91/u3;->e(Ljava/lang/String;FLgy0/f;IZLl2/o;I)V

    .line 280
    .line 281
    .line 282
    goto :goto_4

    .line 283
    :goto_5
    iget-boolean v1, v0, Li91/t3;->e:Z

    .line 284
    .line 285
    if-eqz v1, :cond_6

    .line 286
    .line 287
    const v4, 0x7f0804c7

    .line 288
    .line 289
    .line 290
    goto :goto_6

    .line 291
    :cond_6
    const v4, 0x7f0804c6

    .line 292
    .line 293
    .line 294
    :goto_6
    iget v5, v0, Li91/t3;->f:I

    .line 295
    .line 296
    if-gez v5, :cond_7

    .line 297
    .line 298
    move/from16 v21, v8

    .line 299
    .line 300
    goto :goto_7

    .line 301
    :cond_7
    move/from16 v21, v5

    .line 302
    .line 303
    :goto_7
    invoke-virtual {v14, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    move-result v9

    .line 307
    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 308
    .line 309
    .line 310
    move-result v10

    .line 311
    or-int/2addr v9, v10

    .line 312
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    move-result v10

    .line 316
    or-int/2addr v9, v10

    .line 317
    iget-object v10, v0, Li91/t3;->h:Lay0/k;

    .line 318
    .line 319
    invoke-virtual {v14, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result v12

    .line 323
    or-int/2addr v9, v12

    .line 324
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v12

    .line 328
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 329
    .line 330
    if-nez v9, :cond_9

    .line 331
    .line 332
    if-ne v12, v13, :cond_8

    .line 333
    .line 334
    goto :goto_8

    .line 335
    :cond_8
    move-object/from16 v16, v7

    .line 336
    .line 337
    goto :goto_9

    .line 338
    :cond_9
    :goto_8
    new-instance v15, Lbg/a;

    .line 339
    .line 340
    const/16 v20, 0xa

    .line 341
    .line 342
    move-object/from16 v18, v3

    .line 343
    .line 344
    move-object/from16 v17, v6

    .line 345
    .line 346
    move-object/from16 v16, v7

    .line 347
    .line 348
    move-object/from16 v19, v10

    .line 349
    .line 350
    invoke-direct/range {v15 .. v20}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 351
    .line 352
    .line 353
    invoke-virtual {v14, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 354
    .line 355
    .line 356
    move-object v12, v15

    .line 357
    :goto_9
    move-object v10, v12

    .line 358
    check-cast v10, Lay0/k;

    .line 359
    .line 360
    invoke-virtual {v14, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 361
    .line 362
    .line 363
    move-result v7

    .line 364
    invoke-virtual {v14, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 365
    .line 366
    .line 367
    move-result v9

    .line 368
    or-int/2addr v7, v9

    .line 369
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    move-result v2

    .line 373
    or-int/2addr v2, v7

    .line 374
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v7

    .line 378
    if-nez v2, :cond_a

    .line 379
    .line 380
    if-ne v7, v13, :cond_b

    .line 381
    .line 382
    :cond_a
    new-instance v7, Li2/t;

    .line 383
    .line 384
    const/16 v2, 0xd

    .line 385
    .line 386
    invoke-direct {v7, v2, v6, v3}, Li2/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 387
    .line 388
    .line 389
    invoke-virtual {v14, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 390
    .line 391
    .line 392
    :cond_b
    check-cast v7, Lay0/a;

    .line 393
    .line 394
    new-instance v2, Ldl0/a;

    .line 395
    .line 396
    const/4 v3, 0x5

    .line 397
    invoke-direct {v2, v4, v3}, Ldl0/a;-><init>(II)V

    .line 398
    .line 399
    .line 400
    const v3, 0x59a22d80

    .line 401
    .line 402
    .line 403
    invoke-static {v3, v14, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 404
    .line 405
    .line 406
    move-result-object v18

    .line 407
    new-instance v2, Ldl0/a;

    .line 408
    .line 409
    const/4 v3, 0x6

    .line 410
    invoke-direct {v2, v4, v3}, Ldl0/a;-><init>(II)V

    .line 411
    .line 412
    .line 413
    const v3, 0xfde86ac

    .line 414
    .line 415
    .line 416
    invoke-static {v3, v14, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 417
    .line 418
    .line 419
    move-result-object v19

    .line 420
    new-instance v2, La71/m;

    .line 421
    .line 422
    const/4 v3, 0x2

    .line 423
    invoke-direct {v2, v3, v1}, La71/m;-><init>(IZ)V

    .line 424
    .line 425
    .line 426
    const v1, 0xb59524b

    .line 427
    .line 428
    .line 429
    invoke-static {v1, v14, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 430
    .line 431
    .line 432
    move-result-object v20

    .line 433
    const/high16 v23, 0x30000000

    .line 434
    .line 435
    move-object v13, v11

    .line 436
    iget-object v11, v0, Li91/t3;->i:Lx2/s;

    .line 437
    .line 438
    const/4 v12, 0x0

    .line 439
    const/4 v15, 0x0

    .line 440
    move-object/from16 v9, v16

    .line 441
    .line 442
    const/16 v16, 0x0

    .line 443
    .line 444
    const/16 v17, 0x0

    .line 445
    .line 446
    move-object/from16 v22, v14

    .line 447
    .line 448
    move-object v14, v7

    .line 449
    invoke-static/range {v9 .. v23}, Lh2/q9;->a(Lgy0/f;Lay0/k;Lx2/s;ZLgy0/f;Lay0/a;Lh2/u8;Li1/l;Li1/l;Lt2/b;Lt2/b;Lt2/b;ILl2/o;I)V

    .line 450
    .line 451
    .line 452
    move-object v11, v13

    .line 453
    move-object/from16 v14, v22

    .line 454
    .line 455
    iget-object v0, v0, Li91/t3;->k:Lay0/k;

    .line 456
    .line 457
    if-nez v0, :cond_c

    .line 458
    .line 459
    const v0, -0x1c9dbd52

    .line 460
    .line 461
    .line 462
    invoke-virtual {v14, v0}, Ll2/t;->Y(I)V

    .line 463
    .line 464
    .line 465
    :goto_a
    invoke-virtual {v14, v8}, Ll2/t;->q(Z)V

    .line 466
    .line 467
    .line 468
    goto :goto_b

    .line 469
    :cond_c
    const v1, -0x1c9dbd51

    .line 470
    .line 471
    .line 472
    invoke-virtual {v14, v1}, Ll2/t;->Y(I)V

    .line 473
    .line 474
    .line 475
    const/4 v12, 0x0

    .line 476
    move-object v13, v14

    .line 477
    const/4 v14, 0x0

    .line 478
    move v10, v5

    .line 479
    move-object v9, v11

    .line 480
    move-object v11, v0

    .line 481
    invoke-static/range {v9 .. v14}, Li91/u3;->d(Lgy0/f;ILay0/k;Lx2/s;Ll2/o;I)V

    .line 482
    .line 483
    .line 484
    move-object v14, v13

    .line 485
    goto :goto_a

    .line 486
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 487
    .line 488
    move-object/from16 v13, v24

    .line 489
    .line 490
    invoke-direct {v0, v13}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 491
    .line 492
    .line 493
    throw v0

    .line 494
    :cond_e
    move-object v13, v9

    .line 495
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 496
    .line 497
    invoke-direct {v0, v13}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    throw v0

    .line 501
    :cond_f
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 502
    .line 503
    .line 504
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 505
    .line 506
    return-object v0
.end method
