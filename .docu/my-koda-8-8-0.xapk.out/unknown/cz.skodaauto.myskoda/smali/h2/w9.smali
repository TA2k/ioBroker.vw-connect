.class public final Lh2/w9;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p5, p0, Lh2/w9;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/w9;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/w9;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Lh2/w9;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/w9;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/w9;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lx2/s;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v3, p3

    .line 17
    .line 18
    check-cast v3, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    iget-object v3, v0, Lh2/w9;->f:Ljava/lang/Object;

    .line 24
    .line 25
    move-object v8, v3

    .line 26
    check-cast v8, Lt1/p0;

    .line 27
    .line 28
    iget-object v3, v0, Lh2/w9;->e:Ljava/lang/Object;

    .line 29
    .line 30
    move-object v9, v3

    .line 31
    check-cast v9, Le3/p0;

    .line 32
    .line 33
    iget-object v3, v0, Lh2/w9;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v3, Ll4/v;

    .line 36
    .line 37
    check-cast v2, Ll2/t;

    .line 38
    .line 39
    const v4, -0x5097aed    # -6.4000205E35f

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 43
    .line 44
    .line 45
    sget-object v4, Lw3/h1;->w:Ll2/u2;

    .line 46
    .line 47
    invoke-virtual {v2, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Ljava/lang/Boolean;

    .line 52
    .line 53
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    invoke-virtual {v2, v4}, Ll2/t;->h(Z)Z

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 66
    .line 67
    if-nez v5, :cond_0

    .line 68
    .line 69
    if-ne v6, v7, :cond_1

    .line 70
    .line 71
    :cond_0
    new-instance v6, Lc2/g;

    .line 72
    .line 73
    invoke-direct {v6, v4}, Lc2/g;-><init>(Z)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v2, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    :cond_1
    move-object v5, v6

    .line 80
    check-cast v5, Lc2/g;

    .line 81
    .line 82
    iget-wide v10, v9, Le3/p0;->a:J

    .line 83
    .line 84
    const-wide/16 v12, 0x10

    .line 85
    .line 86
    cmp-long v4, v10, v12

    .line 87
    .line 88
    const/4 v11, 0x0

    .line 89
    if-nez v4, :cond_2

    .line 90
    .line 91
    move v4, v11

    .line 92
    goto :goto_0

    .line 93
    :cond_2
    const/4 v4, 0x1

    .line 94
    :goto_0
    sget-object v6, Lw3/h1;->t:Ll2/u2;

    .line 95
    .line 96
    invoke-virtual {v2, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    check-cast v6, Lw3/j2;

    .line 101
    .line 102
    check-cast v6, Lw3/r1;

    .line 103
    .line 104
    iget-object v6, v6, Lw3/r1;->c:Ll2/j1;

    .line 105
    .line 106
    invoke-virtual {v6}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v6

    .line 110
    check-cast v6, Ljava/lang/Boolean;

    .line 111
    .line 112
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 113
    .line 114
    .line 115
    move-result v6

    .line 116
    if-eqz v6, :cond_7

    .line 117
    .line 118
    invoke-virtual {v8}, Lt1/p0;->b()Z

    .line 119
    .line 120
    .line 121
    move-result v6

    .line 122
    if-eqz v6, :cond_7

    .line 123
    .line 124
    iget-wide v12, v3, Ll4/v;->b:J

    .line 125
    .line 126
    invoke-static {v12, v13}, Lg4/o0;->c(J)Z

    .line 127
    .line 128
    .line 129
    move-result v6

    .line 130
    if-eqz v6, :cond_7

    .line 131
    .line 132
    if-eqz v4, :cond_7

    .line 133
    .line 134
    const v4, -0x2a2b68da

    .line 135
    .line 136
    .line 137
    invoke-virtual {v2, v4}, Ll2/t;->Y(I)V

    .line 138
    .line 139
    .line 140
    iget-object v4, v3, Ll4/v;->a:Lg4/g;

    .line 141
    .line 142
    iget-wide v12, v3, Ll4/v;->b:J

    .line 143
    .line 144
    new-instance v6, Lg4/o0;

    .line 145
    .line 146
    invoke-direct {v6, v12, v13}, Lg4/o0;-><init>(J)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v10

    .line 153
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v12

    .line 157
    if-nez v10, :cond_3

    .line 158
    .line 159
    if-ne v12, v7, :cond_4

    .line 160
    .line 161
    :cond_3
    new-instance v12, Lrp0/a;

    .line 162
    .line 163
    const/4 v10, 0x0

    .line 164
    const/16 v13, 0xa

    .line 165
    .line 166
    invoke-direct {v12, v5, v10, v13}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 167
    .line 168
    .line 169
    invoke-virtual {v2, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    :cond_4
    check-cast v12, Lay0/n;

    .line 173
    .line 174
    invoke-static {v4, v6, v12, v2}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 175
    .line 176
    .line 177
    invoke-virtual {v2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    iget-object v6, v0, Lh2/w9;->h:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast v6, Ll4/p;

    .line 184
    .line 185
    invoke-virtual {v2, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v6

    .line 189
    or-int/2addr v4, v6

    .line 190
    invoke-virtual {v2, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 191
    .line 192
    .line 193
    move-result v3

    .line 194
    or-int/2addr v3, v4

    .line 195
    invoke-virtual {v2, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 196
    .line 197
    .line 198
    move-result v4

    .line 199
    or-int/2addr v3, v4

    .line 200
    invoke-virtual {v2, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    or-int/2addr v3, v4

    .line 205
    iget-object v4, v0, Lh2/w9;->h:Ljava/lang/Object;

    .line 206
    .line 207
    move-object v6, v4

    .line 208
    check-cast v6, Ll4/p;

    .line 209
    .line 210
    iget-object v0, v0, Lh2/w9;->g:Ljava/lang/Object;

    .line 211
    .line 212
    check-cast v0, Ll4/v;

    .line 213
    .line 214
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    if-nez v3, :cond_5

    .line 219
    .line 220
    if-ne v4, v7, :cond_6

    .line 221
    .line 222
    :cond_5
    new-instance v4, Lc/b;

    .line 223
    .line 224
    const/16 v10, 0x9

    .line 225
    .line 226
    move-object v7, v0

    .line 227
    invoke-direct/range {v4 .. v10}, Lc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v2, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    :cond_6
    check-cast v4, Lay0/k;

    .line 234
    .line 235
    invoke-static {v1, v4}, Landroidx/compose/ui/draw/a;->c(Lx2/s;Lay0/k;)Lx2/s;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    invoke-virtual {v2, v11}, Ll2/t;->q(Z)V

    .line 240
    .line 241
    .line 242
    goto :goto_1

    .line 243
    :cond_7
    const v0, -0x2a0caad9

    .line 244
    .line 245
    .line 246
    invoke-virtual {v2, v0}, Ll2/t;->Y(I)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v2, v11}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 253
    .line 254
    :goto_1
    invoke-virtual {v2, v11}, Ll2/t;->q(Z)V

    .line 255
    .line 256
    .line 257
    return-object v0

    .line 258
    :pswitch_0
    move-object/from16 v1, p1

    .line 259
    .line 260
    check-cast v1, Lay0/n;

    .line 261
    .line 262
    move-object/from16 v2, p2

    .line 263
    .line 264
    check-cast v2, Ll2/o;

    .line 265
    .line 266
    move-object/from16 v3, p3

    .line 267
    .line 268
    check-cast v3, Ljava/lang/Number;

    .line 269
    .line 270
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 271
    .line 272
    .line 273
    move-result v3

    .line 274
    iget-object v4, v0, Lh2/w9;->h:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast v4, Ljava/lang/String;

    .line 277
    .line 278
    iget-object v5, v0, Lh2/w9;->g:Ljava/lang/Object;

    .line 279
    .line 280
    check-cast v5, Lh2/c5;

    .line 281
    .line 282
    iget-object v6, v0, Lh2/w9;->e:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v6, Lh2/t9;

    .line 285
    .line 286
    and-int/lit8 v7, v3, 0x6

    .line 287
    .line 288
    if-nez v7, :cond_9

    .line 289
    .line 290
    move-object v7, v2

    .line 291
    check-cast v7, Ll2/t;

    .line 292
    .line 293
    invoke-virtual {v7, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 294
    .line 295
    .line 296
    move-result v7

    .line 297
    if-eqz v7, :cond_8

    .line 298
    .line 299
    const/4 v7, 0x4

    .line 300
    goto :goto_2

    .line 301
    :cond_8
    const/4 v7, 0x2

    .line 302
    :goto_2
    or-int/2addr v3, v7

    .line 303
    :cond_9
    and-int/lit8 v7, v3, 0x13

    .line 304
    .line 305
    const/16 v8, 0x12

    .line 306
    .line 307
    const/4 v9, 0x1

    .line 308
    const/4 v10, 0x0

    .line 309
    if-eq v7, v8, :cond_a

    .line 310
    .line 311
    move v7, v9

    .line 312
    goto :goto_3

    .line 313
    :cond_a
    move v7, v10

    .line 314
    :goto_3
    and-int/lit8 v8, v3, 0x1

    .line 315
    .line 316
    check-cast v2, Ll2/t;

    .line 317
    .line 318
    invoke-virtual {v2, v8, v7}, Ll2/t;->O(IZ)Z

    .line 319
    .line 320
    .line 321
    move-result v7

    .line 322
    if-eqz v7, :cond_1a

    .line 323
    .line 324
    iget-object v0, v0, Lh2/w9;->f:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast v0, Lh2/t9;

    .line 327
    .line 328
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 329
    .line 330
    .line 331
    move-result v13

    .line 332
    sget-object v0, Lk2/w;->g:Lk2/w;

    .line 333
    .line 334
    invoke-static {v0, v2}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 335
    .line 336
    .line 337
    move-result-object v14

    .line 338
    invoke-virtual {v2, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 339
    .line 340
    .line 341
    move-result v0

    .line 342
    invoke-virtual {v2, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 343
    .line 344
    .line 345
    move-result v7

    .line 346
    or-int/2addr v0, v7

    .line 347
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object v7

    .line 351
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 352
    .line 353
    if-nez v0, :cond_b

    .line 354
    .line 355
    if-ne v7, v8, :cond_c

    .line 356
    .line 357
    :cond_b
    new-instance v7, Ld90/w;

    .line 358
    .line 359
    const/16 v0, 0x18

    .line 360
    .line 361
    invoke-direct {v7, v0, v6, v5}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 365
    .line 366
    .line 367
    :cond_c
    move-object v15, v7

    .line 368
    check-cast v15, Lay0/a;

    .line 369
    .line 370
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v0

    .line 374
    const/high16 v5, 0x3f800000    # 1.0f

    .line 375
    .line 376
    if-ne v0, v8, :cond_e

    .line 377
    .line 378
    if-nez v13, :cond_d

    .line 379
    .line 380
    move v0, v5

    .line 381
    goto :goto_4

    .line 382
    :cond_d
    const/4 v0, 0x0

    .line 383
    :goto_4
    invoke-static {v0}, Lc1/d;->a(F)Lc1/c;

    .line 384
    .line 385
    .line 386
    move-result-object v0

    .line 387
    invoke-virtual {v2, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 388
    .line 389
    .line 390
    :cond_e
    move-object v12, v0

    .line 391
    check-cast v12, Lc1/c;

    .line 392
    .line 393
    invoke-static {v13}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 394
    .line 395
    .line 396
    move-result-object v0

    .line 397
    invoke-virtual {v2, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    move-result v7

    .line 401
    invoke-virtual {v2, v13}, Ll2/t;->h(Z)Z

    .line 402
    .line 403
    .line 404
    move-result v11

    .line 405
    or-int/2addr v7, v11

    .line 406
    invoke-virtual {v2, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 407
    .line 408
    .line 409
    move-result v11

    .line 410
    or-int/2addr v7, v11

    .line 411
    invoke-virtual {v2, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result v11

    .line 415
    or-int/2addr v7, v11

    .line 416
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 417
    .line 418
    .line 419
    move-result-object v11

    .line 420
    if-nez v7, :cond_f

    .line 421
    .line 422
    if-ne v11, v8, :cond_10

    .line 423
    .line 424
    :cond_f
    new-instance v11, Lau0/b;

    .line 425
    .line 426
    const/16 v16, 0x0

    .line 427
    .line 428
    const/16 v17, 0x1

    .line 429
    .line 430
    invoke-direct/range {v11 .. v17}, Lau0/b;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 431
    .line 432
    .line 433
    invoke-virtual {v2, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 434
    .line 435
    .line 436
    :cond_10
    check-cast v11, Lay0/n;

    .line 437
    .line 438
    invoke-static {v11, v0, v2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 439
    .line 440
    .line 441
    iget-object v0, v12, Lc1/c;->c:Lc1/k;

    .line 442
    .line 443
    sget-object v7, Lk2/w;->e:Lk2/w;

    .line 444
    .line 445
    invoke-static {v7, v2}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 446
    .line 447
    .line 448
    move-result-object v14

    .line 449
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v7

    .line 453
    if-ne v7, v8, :cond_12

    .line 454
    .line 455
    if-nez v13, :cond_11

    .line 456
    .line 457
    goto :goto_5

    .line 458
    :cond_11
    const v5, 0x3f4ccccd    # 0.8f

    .line 459
    .line 460
    .line 461
    :goto_5
    invoke-static {v5}, Lc1/d;->a(F)Lc1/c;

    .line 462
    .line 463
    .line 464
    move-result-object v7

    .line 465
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 466
    .line 467
    .line 468
    :cond_12
    move-object v12, v7

    .line 469
    check-cast v12, Lc1/c;

    .line 470
    .line 471
    invoke-static {v13}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 472
    .line 473
    .line 474
    move-result-object v5

    .line 475
    invoke-virtual {v2, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    move-result v7

    .line 479
    invoke-virtual {v2, v13}, Ll2/t;->h(Z)Z

    .line 480
    .line 481
    .line 482
    move-result v11

    .line 483
    or-int/2addr v7, v11

    .line 484
    invoke-virtual {v2, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 485
    .line 486
    .line 487
    move-result v11

    .line 488
    or-int/2addr v7, v11

    .line 489
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    move-result-object v11

    .line 493
    if-nez v7, :cond_13

    .line 494
    .line 495
    if-ne v11, v8, :cond_14

    .line 496
    .line 497
    :cond_13
    new-instance v11, Lbp0/g;

    .line 498
    .line 499
    const/16 v16, 0x4

    .line 500
    .line 501
    const/4 v15, 0x0

    .line 502
    invoke-direct/range {v11 .. v16}, Lbp0/g;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 503
    .line 504
    .line 505
    invoke-virtual {v2, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 506
    .line 507
    .line 508
    :cond_14
    check-cast v11, Lay0/n;

    .line 509
    .line 510
    invoke-static {v11, v5, v2}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 511
    .line 512
    .line 513
    iget-object v5, v12, Lc1/c;->c:Lc1/k;

    .line 514
    .line 515
    iget-object v7, v5, Lc1/k;->e:Ll2/j1;

    .line 516
    .line 517
    invoke-virtual {v7}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 518
    .line 519
    .line 520
    move-result-object v7

    .line 521
    check-cast v7, Ljava/lang/Number;

    .line 522
    .line 523
    invoke-virtual {v7}, Ljava/lang/Number;->floatValue()F

    .line 524
    .line 525
    .line 526
    move-result v15

    .line 527
    iget-object v5, v5, Lc1/k;->e:Ll2/j1;

    .line 528
    .line 529
    invoke-virtual {v5}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object v5

    .line 533
    check-cast v5, Ljava/lang/Number;

    .line 534
    .line 535
    invoke-virtual {v5}, Ljava/lang/Number;->floatValue()F

    .line 536
    .line 537
    .line 538
    move-result v16

    .line 539
    iget-object v0, v0, Lc1/k;->e:Ll2/j1;

    .line 540
    .line 541
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 542
    .line 543
    .line 544
    move-result-object v0

    .line 545
    check-cast v0, Ljava/lang/Number;

    .line 546
    .line 547
    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    .line 548
    .line 549
    .line 550
    move-result v17

    .line 551
    const/16 v19, 0x0

    .line 552
    .line 553
    const v20, 0x1fff8

    .line 554
    .line 555
    .line 556
    sget-object v14, Lx2/p;->b:Lx2/p;

    .line 557
    .line 558
    const/16 v18, 0x0

    .line 559
    .line 560
    invoke-static/range {v14 .. v20}, Landroidx/compose/ui/graphics/a;->b(Lx2/s;FFFFLe3/n0;I)Lx2/s;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    invoke-virtual {v2, v13}, Ll2/t;->h(Z)Z

    .line 565
    .line 566
    .line 567
    move-result v5

    .line 568
    invoke-virtual {v2, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 569
    .line 570
    .line 571
    move-result v7

    .line 572
    or-int/2addr v5, v7

    .line 573
    invoke-virtual {v2, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    move-result v7

    .line 577
    or-int/2addr v5, v7

    .line 578
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 579
    .line 580
    .line 581
    move-result-object v7

    .line 582
    if-nez v5, :cond_15

    .line 583
    .line 584
    if-ne v7, v8, :cond_16

    .line 585
    .line 586
    :cond_15
    new-instance v7, Laa/l;

    .line 587
    .line 588
    const/4 v5, 0x1

    .line 589
    invoke-direct {v7, v13, v4, v6, v5}, Laa/l;-><init>(ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 590
    .line 591
    .line 592
    invoke-virtual {v2, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 593
    .line 594
    .line 595
    :cond_16
    check-cast v7, Lay0/k;

    .line 596
    .line 597
    invoke-static {v0, v10, v7}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 598
    .line 599
    .line 600
    move-result-object v0

    .line 601
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 602
    .line 603
    invoke-static {v4, v10}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 604
    .line 605
    .line 606
    move-result-object v4

    .line 607
    iget-wide v5, v2, Ll2/t;->T:J

    .line 608
    .line 609
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 610
    .line 611
    .line 612
    move-result v5

    .line 613
    invoke-virtual {v2}, Ll2/t;->m()Ll2/p1;

    .line 614
    .line 615
    .line 616
    move-result-object v6

    .line 617
    invoke-static {v2, v0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 618
    .line 619
    .line 620
    move-result-object v0

    .line 621
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 622
    .line 623
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 624
    .line 625
    .line 626
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 627
    .line 628
    invoke-virtual {v2}, Ll2/t;->c0()V

    .line 629
    .line 630
    .line 631
    iget-boolean v8, v2, Ll2/t;->S:Z

    .line 632
    .line 633
    if-eqz v8, :cond_17

    .line 634
    .line 635
    invoke-virtual {v2, v7}, Ll2/t;->l(Lay0/a;)V

    .line 636
    .line 637
    .line 638
    goto :goto_6

    .line 639
    :cond_17
    invoke-virtual {v2}, Ll2/t;->m0()V

    .line 640
    .line 641
    .line 642
    :goto_6
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 643
    .line 644
    invoke-static {v7, v4, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 645
    .line 646
    .line 647
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 648
    .line 649
    invoke-static {v4, v6, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 650
    .line 651
    .line 652
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 653
    .line 654
    iget-boolean v6, v2, Ll2/t;->S:Z

    .line 655
    .line 656
    if-nez v6, :cond_18

    .line 657
    .line 658
    invoke-virtual {v2}, Ll2/t;->L()Ljava/lang/Object;

    .line 659
    .line 660
    .line 661
    move-result-object v6

    .line 662
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 663
    .line 664
    .line 665
    move-result-object v7

    .line 666
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 667
    .line 668
    .line 669
    move-result v6

    .line 670
    if-nez v6, :cond_19

    .line 671
    .line 672
    :cond_18
    invoke-static {v5, v2, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 673
    .line 674
    .line 675
    :cond_19
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 676
    .line 677
    invoke-static {v4, v0, v2}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 678
    .line 679
    .line 680
    and-int/lit8 v0, v3, 0xe

    .line 681
    .line 682
    invoke-static {v0, v1, v2, v9}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 683
    .line 684
    .line 685
    goto :goto_7

    .line 686
    :cond_1a
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 687
    .line 688
    .line 689
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 690
    .line 691
    return-object v0

    .line 692
    nop

    .line 693
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
