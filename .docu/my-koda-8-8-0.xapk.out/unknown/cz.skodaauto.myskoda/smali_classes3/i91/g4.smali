.class public final synthetic Li91/g4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Z

.field public final synthetic g:Ljava/lang/String;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ZLjava/lang/Boolean;ZLjava/lang/String;Ll2/b1;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    iput v0, p0, Li91/g4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li91/g4;->e:Z

    iput-object p2, p0, Li91/g4;->h:Ljava/lang/Object;

    iput-boolean p3, p0, Li91/g4;->f:Z

    iput-object p4, p0, Li91/g4;->g:Ljava/lang/String;

    iput-object p5, p0, Li91/g4;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Integer;Ll4/v;ZLjava/lang/String;)V
    .locals 1

    .line 2
    const/4 v0, 0x0

    iput v0, p0, Li91/g4;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Li91/g4;->e:Z

    iput-object p2, p0, Li91/g4;->h:Ljava/lang/Object;

    iput-object p3, p0, Li91/g4;->i:Ljava/lang/Object;

    iput-boolean p4, p0, Li91/g4;->f:Z

    iput-object p5, p0, Li91/g4;->g:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li91/g4;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Li91/g4;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/lang/Boolean;

    .line 11
    .line 12
    iget-object v2, v0, Li91/g4;->i:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ll2/b1;

    .line 15
    .line 16
    move-object/from16 v3, p1

    .line 17
    .line 18
    check-cast v3, Lk1/k0;

    .line 19
    .line 20
    move-object/from16 v4, p2

    .line 21
    .line 22
    check-cast v4, Ll2/o;

    .line 23
    .line 24
    move-object/from16 v5, p3

    .line 25
    .line 26
    check-cast v5, Ljava/lang/Integer;

    .line 27
    .line 28
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    sget-object v6, Lx2/c;->n:Lx2/i;

    .line 33
    .line 34
    const-string v7, "$this$FlowRow"

    .line 35
    .line 36
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    and-int/lit8 v7, v5, 0x6

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    if-nez v7, :cond_1

    .line 43
    .line 44
    move-object v7, v4

    .line 45
    check-cast v7, Ll2/t;

    .line 46
    .line 47
    invoke-virtual {v7, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v7

    .line 51
    if-eqz v7, :cond_0

    .line 52
    .line 53
    const/4 v7, 0x4

    .line 54
    goto :goto_0

    .line 55
    :cond_0
    move v7, v8

    .line 56
    :goto_0
    or-int/2addr v5, v7

    .line 57
    :cond_1
    and-int/lit8 v7, v5, 0x13

    .line 58
    .line 59
    const/16 v9, 0x12

    .line 60
    .line 61
    const/4 v10, 0x0

    .line 62
    if-eq v7, v9, :cond_2

    .line 63
    .line 64
    const/4 v7, 0x1

    .line 65
    goto :goto_1

    .line 66
    :cond_2
    move v7, v10

    .line 67
    :goto_1
    and-int/lit8 v9, v5, 0x1

    .line 68
    .line 69
    move-object v15, v4

    .line 70
    check-cast v15, Ll2/t;

    .line 71
    .line 72
    invoke-virtual {v15, v9, v7}, Ll2/t;->O(IZ)Z

    .line 73
    .line 74
    .line 75
    move-result v4

    .line 76
    if-eqz v4, :cond_b

    .line 77
    .line 78
    iget-boolean v4, v0, Li91/g4;->e:Z

    .line 79
    .line 80
    const v7, -0xec5037a

    .line 81
    .line 82
    .line 83
    if-eqz v4, :cond_3

    .line 84
    .line 85
    const v9, -0xea1dc84    # -1.0999771E30f

    .line 86
    .line 87
    .line 88
    invoke-virtual {v15, v9}, Ll2/t;->Y(I)V

    .line 89
    .line 90
    .line 91
    and-int/lit8 v5, v5, 0xe

    .line 92
    .line 93
    invoke-static {v3, v15, v5}, Lxk0/e0;->c(Lk1/k0;Ll2/o;I)V

    .line 94
    .line 95
    .line 96
    :goto_2
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 97
    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_3
    invoke-virtual {v15, v7}, Ll2/t;->Y(I)V

    .line 101
    .line 102
    .line 103
    goto :goto_2

    .line 104
    :goto_3
    sget-object v5, Lx2/p;->b:Lx2/p;

    .line 105
    .line 106
    iget-boolean v9, v0, Li91/g4;->f:Z

    .line 107
    .line 108
    const/4 v11, 0x0

    .line 109
    if-eqz v4, :cond_4

    .line 110
    .line 111
    if-nez v1, :cond_5

    .line 112
    .line 113
    if-eqz v9, :cond_4

    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_4
    move v4, v11

    .line 117
    goto :goto_6

    .line 118
    :cond_5
    :goto_4
    const v4, -0xe9fa56f

    .line 119
    .line 120
    .line 121
    invoke-virtual {v15, v4}, Ll2/t;->Y(I)V

    .line 122
    .line 123
    .line 124
    sget-object v4, Lj91/h;->a:Ll2/u2;

    .line 125
    .line 126
    invoke-virtual {v15, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v4

    .line 130
    check-cast v4, Lj91/e;

    .line 131
    .line 132
    invoke-virtual {v4}, Lj91/e;->l()J

    .line 133
    .line 134
    .line 135
    move-result-wide v13

    .line 136
    sget-object v4, Lj91/a;->a:Ll2/u2;

    .line 137
    .line 138
    invoke-virtual {v15, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v12

    .line 142
    check-cast v12, Lj91/c;

    .line 143
    .line 144
    iget v12, v12, Lj91/c;->d:F

    .line 145
    .line 146
    invoke-static {v5, v12}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 147
    .line 148
    .line 149
    move-result-object v12

    .line 150
    invoke-virtual {v3, v12, v6}, Lk1/k0;->b(Lx2/s;Lx2/i;)Lx2/s;

    .line 151
    .line 152
    .line 153
    move-result-object v12

    .line 154
    invoke-virtual {v15, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 155
    .line 156
    .line 157
    move-result-object v4

    .line 158
    check-cast v4, Lj91/c;

    .line 159
    .line 160
    iget v4, v4, Lj91/c;->c:F

    .line 161
    .line 162
    invoke-static {v12, v4, v11, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v4

    .line 166
    const/16 v16, 0x0

    .line 167
    .line 168
    const/16 v17, 0x2

    .line 169
    .line 170
    const/4 v12, 0x0

    .line 171
    move/from16 v27, v11

    .line 172
    .line 173
    move-object v11, v4

    .line 174
    move/from16 v4, v27

    .line 175
    .line 176
    invoke-static/range {v11 .. v17}, Lh2/r;->v(Lx2/s;FJLl2/o;II)V

    .line 177
    .line 178
    .line 179
    :goto_5
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 180
    .line 181
    .line 182
    goto :goto_7

    .line 183
    :goto_6
    invoke-virtual {v15, v7}, Ll2/t;->Y(I)V

    .line 184
    .line 185
    .line 186
    goto :goto_5

    .line 187
    :goto_7
    if-nez v1, :cond_6

    .line 188
    .line 189
    const v11, -0xe9a9e93

    .line 190
    .line 191
    .line 192
    invoke-virtual {v15, v11}, Ll2/t;->Y(I)V

    .line 193
    .line 194
    .line 195
    :goto_8
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 196
    .line 197
    .line 198
    goto :goto_9

    .line 199
    :cond_6
    const v11, -0xe9a9e92

    .line 200
    .line 201
    .line 202
    invoke-virtual {v15, v11}, Ll2/t;->Y(I)V

    .line 203
    .line 204
    .line 205
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 206
    .line 207
    .line 208
    move-result v11

    .line 209
    invoke-virtual {v3, v5, v6}, Lk1/k0;->b(Lx2/s;Lx2/i;)Lx2/s;

    .line 210
    .line 211
    .line 212
    move-result-object v12

    .line 213
    invoke-static {v10, v10, v15, v12, v11}, Lxk0/h;->J(IILl2/o;Lx2/s;Z)V

    .line 214
    .line 215
    .line 216
    goto :goto_8

    .line 217
    :goto_9
    iget-object v0, v0, Li91/g4;->g:Ljava/lang/String;

    .line 218
    .line 219
    if-eqz v0, :cond_a

    .line 220
    .line 221
    if-eqz v9, :cond_a

    .line 222
    .line 223
    const v9, -0xe95db47

    .line 224
    .line 225
    .line 226
    invoke-virtual {v15, v9}, Ll2/t;->Y(I)V

    .line 227
    .line 228
    .line 229
    if-eqz v1, :cond_9

    .line 230
    .line 231
    const v1, -0xe951f57

    .line 232
    .line 233
    .line 234
    invoke-virtual {v15, v1}, Ll2/t;->Y(I)V

    .line 235
    .line 236
    .line 237
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 238
    .line 239
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v1

    .line 243
    check-cast v1, Lj91/e;

    .line 244
    .line 245
    invoke-virtual {v1}, Lj91/e;->l()J

    .line 246
    .line 247
    .line 248
    move-result-wide v11

    .line 249
    new-instance v1, Le3/s;

    .line 250
    .line 251
    invoke-direct {v1, v11, v12}, Le3/s;-><init>(J)V

    .line 252
    .line 253
    .line 254
    invoke-interface {v2}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    check-cast v2, Ljava/lang/Boolean;

    .line 259
    .line 260
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 261
    .line 262
    .line 263
    move-result v2

    .line 264
    if-eqz v2, :cond_7

    .line 265
    .line 266
    goto :goto_a

    .line 267
    :cond_7
    const/4 v1, 0x0

    .line 268
    :goto_a
    if-eqz v1, :cond_8

    .line 269
    .line 270
    iget-wide v1, v1, Le3/s;->a:J

    .line 271
    .line 272
    :goto_b
    move-wide v13, v1

    .line 273
    goto :goto_c

    .line 274
    :cond_8
    sget-wide v1, Le3/s;->h:J

    .line 275
    .line 276
    goto :goto_b

    .line 277
    :goto_c
    sget-object v1, Lj91/a;->a:Ll2/u2;

    .line 278
    .line 279
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 280
    .line 281
    .line 282
    move-result-object v2

    .line 283
    check-cast v2, Lj91/c;

    .line 284
    .line 285
    iget v2, v2, Lj91/c;->d:F

    .line 286
    .line 287
    invoke-static {v5, v2}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 288
    .line 289
    .line 290
    move-result-object v2

    .line 291
    invoke-virtual {v3, v2, v6}, Lk1/k0;->b(Lx2/s;Lx2/i;)Lx2/s;

    .line 292
    .line 293
    .line 294
    move-result-object v2

    .line 295
    invoke-virtual {v15, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    check-cast v1, Lj91/c;

    .line 300
    .line 301
    iget v1, v1, Lj91/c;->c:F

    .line 302
    .line 303
    invoke-static {v2, v1, v4, v8}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 304
    .line 305
    .line 306
    move-result-object v11

    .line 307
    const/16 v16, 0x0

    .line 308
    .line 309
    const/16 v17, 0x2

    .line 310
    .line 311
    const/4 v12, 0x0

    .line 312
    invoke-static/range {v11 .. v17}, Lh2/r;->v(Lx2/s;FJLl2/o;II)V

    .line 313
    .line 314
    .line 315
    :goto_d
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 316
    .line 317
    .line 318
    goto :goto_e

    .line 319
    :cond_9
    invoke-virtual {v15, v7}, Ll2/t;->Y(I)V

    .line 320
    .line 321
    .line 322
    goto :goto_d

    .line 323
    :goto_e
    invoke-static {v0, v15, v10}, Lxk0/h;->v(Ljava/lang/String;Ll2/o;I)V

    .line 324
    .line 325
    .line 326
    :goto_f
    invoke-virtual {v15, v10}, Ll2/t;->q(Z)V

    .line 327
    .line 328
    .line 329
    goto :goto_10

    .line 330
    :cond_a
    invoke-virtual {v15, v7}, Ll2/t;->Y(I)V

    .line 331
    .line 332
    .line 333
    goto :goto_f

    .line 334
    :cond_b
    invoke-virtual {v15}, Ll2/t;->R()V

    .line 335
    .line 336
    .line 337
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 338
    .line 339
    return-object v0

    .line 340
    :pswitch_0
    iget-object v1, v0, Li91/g4;->h:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v1, Ljava/lang/Integer;

    .line 343
    .line 344
    iget-object v2, v0, Li91/g4;->i:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v2, Ll4/v;

    .line 347
    .line 348
    move-object/from16 v3, p1

    .line 349
    .line 350
    check-cast v3, Lb1/a0;

    .line 351
    .line 352
    move-object/from16 v23, p2

    .line 353
    .line 354
    check-cast v23, Ll2/o;

    .line 355
    .line 356
    move-object/from16 v4, p3

    .line 357
    .line 358
    check-cast v4, Ljava/lang/Integer;

    .line 359
    .line 360
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 361
    .line 362
    .line 363
    const-string v4, "$this$AnimatedVisibility"

    .line 364
    .line 365
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 366
    .line 367
    .line 368
    iget-boolean v3, v0, Li91/g4;->e:Z

    .line 369
    .line 370
    if-eqz v3, :cond_d

    .line 371
    .line 372
    if-eqz v1, :cond_c

    .line 373
    .line 374
    new-instance v3, Ljava/lang/StringBuilder;

    .line 375
    .line 376
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 377
    .line 378
    .line 379
    iget-object v2, v2, Ll4/v;->a:Lg4/g;

    .line 380
    .line 381
    iget-object v2, v2, Lg4/g;->e:Ljava/lang/String;

    .line 382
    .line 383
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 384
    .line 385
    .line 386
    move-result v2

    .line 387
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 388
    .line 389
    .line 390
    const-string v2, " / "

    .line 391
    .line 392
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 393
    .line 394
    .line 395
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 396
    .line 397
    .line 398
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    :goto_11
    move-object v4, v1

    .line 403
    goto :goto_12

    .line 404
    :cond_c
    iget-object v1, v2, Ll4/v;->a:Lg4/g;

    .line 405
    .line 406
    iget-object v1, v1, Lg4/g;->e:Ljava/lang/String;

    .line 407
    .line 408
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 409
    .line 410
    .line 411
    move-result v1

    .line 412
    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    goto :goto_11

    .line 417
    :cond_d
    const-string v1, ""

    .line 418
    .line 419
    goto :goto_11

    .line 420
    :goto_12
    iget-boolean v1, v0, Li91/g4;->f:Z

    .line 421
    .line 422
    const/4 v2, 0x0

    .line 423
    if-nez v1, :cond_e

    .line 424
    .line 425
    move-object/from16 v0, v23

    .line 426
    .line 427
    check-cast v0, Ll2/t;

    .line 428
    .line 429
    const v1, 0x7f9ae9d2

    .line 430
    .line 431
    .line 432
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 433
    .line 434
    .line 435
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 436
    .line 437
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    check-cast v1, Lj91/e;

    .line 442
    .line 443
    invoke-virtual {v1}, Lj91/e;->r()J

    .line 444
    .line 445
    .line 446
    move-result-wide v5

    .line 447
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 448
    .line 449
    .line 450
    :goto_13
    move-wide v6, v5

    .line 451
    goto :goto_14

    .line 452
    :cond_e
    iget-object v0, v0, Li91/g4;->g:Ljava/lang/String;

    .line 453
    .line 454
    if-eqz v0, :cond_f

    .line 455
    .line 456
    move-object/from16 v0, v23

    .line 457
    .line 458
    check-cast v0, Ll2/t;

    .line 459
    .line 460
    const v1, 0x7f9af3c9

    .line 461
    .line 462
    .line 463
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 464
    .line 465
    .line 466
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 467
    .line 468
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v1

    .line 472
    check-cast v1, Lj91/e;

    .line 473
    .line 474
    invoke-virtual {v1}, Lj91/e;->a()J

    .line 475
    .line 476
    .line 477
    move-result-wide v5

    .line 478
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 479
    .line 480
    .line 481
    goto :goto_13

    .line 482
    :cond_f
    move-object/from16 v0, v23

    .line 483
    .line 484
    check-cast v0, Ll2/t;

    .line 485
    .line 486
    const v1, 0x7f9afab0

    .line 487
    .line 488
    .line 489
    invoke-virtual {v0, v1}, Ll2/t;->Y(I)V

    .line 490
    .line 491
    .line 492
    sget-object v1, Lj91/h;->a:Ll2/u2;

    .line 493
    .line 494
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v1

    .line 498
    check-cast v1, Lj91/e;

    .line 499
    .line 500
    invoke-virtual {v1}, Lj91/e;->t()J

    .line 501
    .line 502
    .line 503
    move-result-wide v5

    .line 504
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 505
    .line 506
    .line 507
    goto :goto_13

    .line 508
    :goto_14
    invoke-static/range {v23 .. v23}, Li91/j4;->f(Ll2/o;)Lg4/p0;

    .line 509
    .line 510
    .line 511
    move-result-object v22

    .line 512
    const/4 v0, 0x4

    .line 513
    int-to-float v10, v0

    .line 514
    const/4 v12, 0x0

    .line 515
    const/16 v13, 0xd

    .line 516
    .line 517
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 518
    .line 519
    const/4 v9, 0x0

    .line 520
    const/4 v11, 0x0

    .line 521
    invoke-static/range {v8 .. v13}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 522
    .line 523
    .line 524
    move-result-object v5

    .line 525
    const/16 v25, 0x0

    .line 526
    .line 527
    const v26, 0x1fff8

    .line 528
    .line 529
    .line 530
    const-wide/16 v8, 0x0

    .line 531
    .line 532
    const/4 v10, 0x0

    .line 533
    const-wide/16 v11, 0x0

    .line 534
    .line 535
    const/4 v13, 0x0

    .line 536
    const/4 v14, 0x0

    .line 537
    const-wide/16 v15, 0x0

    .line 538
    .line 539
    const/16 v17, 0x0

    .line 540
    .line 541
    const/16 v18, 0x0

    .line 542
    .line 543
    const/16 v19, 0x0

    .line 544
    .line 545
    const/16 v20, 0x0

    .line 546
    .line 547
    const/16 v21, 0x0

    .line 548
    .line 549
    const/16 v24, 0x30

    .line 550
    .line 551
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 552
    .line 553
    .line 554
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 555
    .line 556
    return-object v0

    .line 557
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
