.class public final Laa/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Laa/p;->d:I

    iput-object p2, p0, Laa/p;->e:Ljava/lang/Object;

    iput-object p3, p0, Laa/p;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lz9/k;Lb1/n;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Laa/p;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Laa/p;->f:Ljava/lang/Object;

    iput-object p2, p0, Laa/p;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Laa/p;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x1

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v6

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v5

    .line 30
    :goto_0
    and-int/2addr v2, v6

    .line 31
    check-cast v1, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_3

    .line 38
    .line 39
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v2, La2/k;

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    iget-object v3, v0, Laa/p;->e:Ljava/lang/Object;

    .line 48
    .line 49
    move-object v8, v3

    .line 50
    check-cast v8, La2/k;

    .line 51
    .line 52
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    if-nez v2, :cond_1

    .line 57
    .line 58
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 59
    .line 60
    if-ne v3, v2, :cond_2

    .line 61
    .line 62
    :cond_1
    new-instance v6, Lxk0/u;

    .line 63
    .line 64
    const/4 v12, 0x0

    .line 65
    const/16 v13, 0x17

    .line 66
    .line 67
    const/4 v7, 0x0

    .line 68
    const-class v9, La2/k;

    .line 69
    .line 70
    const-string v10, "data"

    .line 71
    .line 72
    const-string v11, "data()Landroidx/compose/foundation/text/contextmenu/data/TextContextMenuData;"

    .line 73
    .line 74
    invoke-direct/range {v6 .. v13}, Lxk0/u;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 75
    .line 76
    .line 77
    invoke-static {v6}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 78
    .line 79
    .line 80
    move-result-object v3

    .line 81
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_2
    check-cast v3, Ll2/t2;

    .line 85
    .line 86
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Lw1/g;

    .line 89
    .line 90
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v2

    .line 94
    check-cast v2, Lw1/c;

    .line 95
    .line 96
    invoke-static {v0, v2, v1, v5}, Ly1/k;->a(Lw1/g;Lw1/c;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_3
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 101
    .line 102
    .line 103
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object v0

    .line 106
    :pswitch_0
    move-object/from16 v1, p1

    .line 107
    .line 108
    check-cast v1, Ll2/o;

    .line 109
    .line 110
    move-object/from16 v2, p2

    .line 111
    .line 112
    check-cast v2, Ljava/lang/Number;

    .line 113
    .line 114
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 115
    .line 116
    .line 117
    move-result v2

    .line 118
    and-int/lit8 v3, v2, 0x3

    .line 119
    .line 120
    const/4 v4, 0x2

    .line 121
    const/4 v5, 0x0

    .line 122
    const/4 v6, 0x1

    .line 123
    if-eq v3, v4, :cond_4

    .line 124
    .line 125
    move v3, v6

    .line 126
    goto :goto_2

    .line 127
    :cond_4
    move v3, v5

    .line 128
    :goto_2
    and-int/2addr v2, v6

    .line 129
    check-cast v1, Ll2/t;

    .line 130
    .line 131
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 132
    .line 133
    .line 134
    move-result v2

    .line 135
    if-eqz v2, :cond_5

    .line 136
    .line 137
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v2, Lt2/b;

    .line 140
    .line 141
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v0, Lo1/v0;

    .line 144
    .line 145
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-virtual {v2, v0, v1, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    goto :goto_3

    .line 153
    :cond_5
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 154
    .line 155
    .line 156
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 157
    .line 158
    return-object v0

    .line 159
    :pswitch_1
    move-object/from16 v1, p1

    .line 160
    .line 161
    check-cast v1, Ll2/o;

    .line 162
    .line 163
    move-object/from16 v2, p2

    .line 164
    .line 165
    check-cast v2, Ljava/lang/Number;

    .line 166
    .line 167
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    iget-object v3, v0, Laa/p;->e:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v3, Lo1/a0;

    .line 174
    .line 175
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lo1/z;

    .line 178
    .line 179
    and-int/lit8 v4, v2, 0x3

    .line 180
    .line 181
    const/4 v5, 0x2

    .line 182
    const/4 v6, 0x1

    .line 183
    const/4 v7, 0x0

    .line 184
    if-eq v4, v5, :cond_6

    .line 185
    .line 186
    move v4, v6

    .line 187
    goto :goto_4

    .line 188
    :cond_6
    move v4, v7

    .line 189
    :goto_4
    and-int/2addr v2, v6

    .line 190
    move-object v12, v1

    .line 191
    check-cast v12, Ll2/t;

    .line 192
    .line 193
    invoke-virtual {v12, v2, v4}, Ll2/t;->O(IZ)Z

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    if-eqz v1, :cond_c

    .line 198
    .line 199
    iget-object v1, v3, Lo1/a0;->b:Lio0/f;

    .line 200
    .line 201
    invoke-virtual {v1}, Lio0/f;->invoke()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object v1

    .line 205
    move-object v8, v1

    .line 206
    check-cast v8, Lo1/b0;

    .line 207
    .line 208
    iget v1, v0, Lo1/z;->c:I

    .line 209
    .line 210
    iget-object v2, v0, Lo1/z;->a:Ljava/lang/Object;

    .line 211
    .line 212
    invoke-interface {v8}, Lo1/b0;->a()I

    .line 213
    .line 214
    .line 215
    move-result v4

    .line 216
    const/4 v5, -0x1

    .line 217
    if-ge v1, v4, :cond_8

    .line 218
    .line 219
    invoke-interface {v8, v1}, Lo1/b0;->d(I)Ljava/lang/Object;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    invoke-virtual {v4, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 224
    .line 225
    .line 226
    move-result v4

    .line 227
    if-nez v4, :cond_7

    .line 228
    .line 229
    goto :goto_6

    .line 230
    :cond_7
    :goto_5
    move v10, v1

    .line 231
    goto :goto_7

    .line 232
    :cond_8
    :goto_6
    invoke-interface {v8, v2}, Lo1/b0;->c(Ljava/lang/Object;)I

    .line 233
    .line 234
    .line 235
    move-result v1

    .line 236
    if-eq v1, v5, :cond_7

    .line 237
    .line 238
    iput v1, v0, Lo1/z;->c:I

    .line 239
    .line 240
    goto :goto_5

    .line 241
    :goto_7
    if-eq v10, v5, :cond_9

    .line 242
    .line 243
    const v1, -0x6339ef97

    .line 244
    .line 245
    .line 246
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 247
    .line 248
    .line 249
    iget-object v9, v3, Lo1/a0;->a:Lu2/c;

    .line 250
    .line 251
    iget-object v11, v0, Lo1/z;->a:Ljava/lang/Object;

    .line 252
    .line 253
    const/4 v13, 0x0

    .line 254
    invoke-static/range {v8 .. v13}, Lo1/y;->d(Lo1/b0;Ljava/lang/Object;ILjava/lang/Object;Ll2/o;I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 258
    .line 259
    .line 260
    goto :goto_8

    .line 261
    :cond_9
    const v1, -0x633657e2

    .line 262
    .line 263
    .line 264
    invoke-virtual {v12, v1}, Ll2/t;->Y(I)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v12, v7}, Ll2/t;->q(Z)V

    .line 268
    .line 269
    .line 270
    :goto_8
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 271
    .line 272
    .line 273
    move-result v1

    .line 274
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    if-nez v1, :cond_a

    .line 279
    .line 280
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 281
    .line 282
    if-ne v3, v1, :cond_b

    .line 283
    .line 284
    :cond_a
    new-instance v3, Lla/p;

    .line 285
    .line 286
    const/16 v1, 0x17

    .line 287
    .line 288
    invoke-direct {v3, v0, v1}, Lla/p;-><init>(Ljava/lang/Object;I)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    :cond_b
    check-cast v3, Lay0/k;

    .line 295
    .line 296
    invoke-static {v2, v3, v12}, Ll2/l0;->a(Ljava/lang/Object;Lay0/k;Ll2/o;)V

    .line 297
    .line 298
    .line 299
    goto :goto_9

    .line 300
    :cond_c
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 301
    .line 302
    .line 303
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 304
    .line 305
    return-object v0

    .line 306
    :pswitch_2
    move-object/from16 v1, p1

    .line 307
    .line 308
    check-cast v1, Ll2/o;

    .line 309
    .line 310
    move-object/from16 v2, p2

    .line 311
    .line 312
    check-cast v2, Ljava/lang/Number;

    .line 313
    .line 314
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 315
    .line 316
    .line 317
    move-result v2

    .line 318
    and-int/lit8 v3, v2, 0x3

    .line 319
    .line 320
    const/4 v4, 0x2

    .line 321
    const/4 v5, 0x0

    .line 322
    const/4 v6, 0x1

    .line 323
    if-eq v3, v4, :cond_d

    .line 324
    .line 325
    move v3, v6

    .line 326
    goto :goto_a

    .line 327
    :cond_d
    move v3, v5

    .line 328
    :goto_a
    and-int/2addr v2, v6

    .line 329
    check-cast v1, Ll2/t;

    .line 330
    .line 331
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 332
    .line 333
    .line 334
    move-result v2

    .line 335
    if-eqz v2, :cond_e

    .line 336
    .line 337
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v2, Lt2/b;

    .line 340
    .line 341
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Landroidx/compose/foundation/layout/c;

    .line 344
    .line 345
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 346
    .line 347
    .line 348
    move-result-object v3

    .line 349
    invoke-virtual {v2, v0, v1, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    goto :goto_b

    .line 353
    :cond_e
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 354
    .line 355
    .line 356
    :goto_b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 357
    .line 358
    return-object v0

    .line 359
    :pswitch_3
    move-object/from16 v1, p1

    .line 360
    .line 361
    check-cast v1, Ll2/o;

    .line 362
    .line 363
    move-object/from16 v2, p2

    .line 364
    .line 365
    check-cast v2, Ljava/lang/Number;

    .line 366
    .line 367
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 368
    .line 369
    .line 370
    move-result v2

    .line 371
    and-int/lit8 v3, v2, 0x3

    .line 372
    .line 373
    const/4 v4, 0x2

    .line 374
    const/4 v5, 0x1

    .line 375
    if-eq v3, v4, :cond_f

    .line 376
    .line 377
    move v3, v5

    .line 378
    goto :goto_c

    .line 379
    :cond_f
    const/4 v3, 0x0

    .line 380
    :goto_c
    and-int/2addr v2, v5

    .line 381
    check-cast v1, Ll2/t;

    .line 382
    .line 383
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 384
    .line 385
    .line 386
    move-result v2

    .line 387
    if-eqz v2, :cond_10

    .line 388
    .line 389
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast v2, Lay0/o;

    .line 392
    .line 393
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 394
    .line 395
    check-cast v0, Li2/e1;

    .line 396
    .line 397
    const/4 v3, 0x6

    .line 398
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 399
    .line 400
    .line 401
    move-result-object v3

    .line 402
    invoke-interface {v2, v0, v1, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 403
    .line 404
    .line 405
    goto :goto_d

    .line 406
    :cond_10
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 407
    .line 408
    .line 409
    :goto_d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 410
    .line 411
    return-object v0

    .line 412
    :pswitch_4
    move-object/from16 v1, p1

    .line 413
    .line 414
    check-cast v1, Ll2/o;

    .line 415
    .line 416
    move-object/from16 v2, p2

    .line 417
    .line 418
    check-cast v2, Ljava/lang/Number;

    .line 419
    .line 420
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 421
    .line 422
    .line 423
    move-result v2

    .line 424
    iget-object v3, v0, Laa/p;->e:Ljava/lang/Object;

    .line 425
    .line 426
    check-cast v3, Ljava/lang/String;

    .line 427
    .line 428
    and-int/lit8 v4, v2, 0x3

    .line 429
    .line 430
    const/4 v5, 0x2

    .line 431
    const/4 v6, 0x1

    .line 432
    const/4 v7, 0x0

    .line 433
    if-eq v4, v5, :cond_11

    .line 434
    .line 435
    move v4, v6

    .line 436
    goto :goto_e

    .line 437
    :cond_11
    move v4, v7

    .line 438
    :goto_e
    and-int/2addr v2, v6

    .line 439
    check-cast v1, Ll2/t;

    .line 440
    .line 441
    invoke-virtual {v1, v2, v4}, Ll2/t;->O(IZ)Z

    .line 442
    .line 443
    .line 444
    move-result v2

    .line 445
    if-eqz v2, :cond_17

    .line 446
    .line 447
    invoke-virtual {v1, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v2

    .line 451
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v4

    .line 455
    if-nez v2, :cond_12

    .line 456
    .line 457
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 458
    .line 459
    if-ne v4, v2, :cond_13

    .line 460
    .line 461
    :cond_12
    new-instance v4, Lac0/r;

    .line 462
    .line 463
    const/16 v2, 0x17

    .line 464
    .line 465
    invoke-direct {v4, v3, v2}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 466
    .line 467
    .line 468
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 469
    .line 470
    .line 471
    :cond_13
    check-cast v4, Lay0/k;

    .line 472
    .line 473
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 474
    .line 475
    invoke-static {v2, v7, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 476
    .line 477
    .line 478
    move-result-object v2

    .line 479
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 480
    .line 481
    check-cast v0, Lt2/b;

    .line 482
    .line 483
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 484
    .line 485
    invoke-static {v3, v7}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 486
    .line 487
    .line 488
    move-result-object v3

    .line 489
    iget-wide v4, v1, Ll2/t;->T:J

    .line 490
    .line 491
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 492
    .line 493
    .line 494
    move-result v4

    .line 495
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 496
    .line 497
    .line 498
    move-result-object v5

    .line 499
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 500
    .line 501
    .line 502
    move-result-object v2

    .line 503
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 504
    .line 505
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 506
    .line 507
    .line 508
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 509
    .line 510
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 511
    .line 512
    .line 513
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 514
    .line 515
    if-eqz v9, :cond_14

    .line 516
    .line 517
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 518
    .line 519
    .line 520
    goto :goto_f

    .line 521
    :cond_14
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 522
    .line 523
    .line 524
    :goto_f
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 525
    .line 526
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 527
    .line 528
    .line 529
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 530
    .line 531
    invoke-static {v3, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 532
    .line 533
    .line 534
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 535
    .line 536
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 537
    .line 538
    if-nez v5, :cond_15

    .line 539
    .line 540
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    move-result-object v5

    .line 544
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 545
    .line 546
    .line 547
    move-result-object v8

    .line 548
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 549
    .line 550
    .line 551
    move-result v5

    .line 552
    if-nez v5, :cond_16

    .line 553
    .line 554
    :cond_15
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 555
    .line 556
    .line 557
    :cond_16
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 558
    .line 559
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 560
    .line 561
    .line 562
    invoke-static {v7, v0, v1, v6}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 563
    .line 564
    .line 565
    goto :goto_10

    .line 566
    :cond_17
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 567
    .line 568
    .line 569
    :goto_10
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 570
    .line 571
    return-object v0

    .line 572
    :pswitch_5
    move-object/from16 v1, p1

    .line 573
    .line 574
    check-cast v1, Ll2/o;

    .line 575
    .line 576
    move-object/from16 v2, p2

    .line 577
    .line 578
    check-cast v2, Ljava/lang/Number;

    .line 579
    .line 580
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 581
    .line 582
    .line 583
    move-result v2

    .line 584
    and-int/lit8 v3, v2, 0x3

    .line 585
    .line 586
    const/4 v4, 0x2

    .line 587
    const/4 v5, 0x1

    .line 588
    const/4 v6, 0x0

    .line 589
    if-eq v3, v4, :cond_18

    .line 590
    .line 591
    move v3, v5

    .line 592
    goto :goto_11

    .line 593
    :cond_18
    move v3, v6

    .line 594
    :goto_11
    and-int/2addr v2, v5

    .line 595
    check-cast v1, Ll2/t;

    .line 596
    .line 597
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 598
    .line 599
    .line 600
    move-result v2

    .line 601
    if-eqz v2, :cond_1d

    .line 602
    .line 603
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 604
    .line 605
    check-cast v2, Ll2/b1;

    .line 606
    .line 607
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 608
    .line 609
    .line 610
    move-result-object v3

    .line 611
    sget-object v4, Ll2/n;->a:Ll2/x0;

    .line 612
    .line 613
    if-ne v3, v4, :cond_19

    .line 614
    .line 615
    new-instance v3, La2/g;

    .line 616
    .line 617
    const/16 v4, 0xc

    .line 618
    .line 619
    invoke-direct {v3, v2, v4}, La2/g;-><init>(Ll2/b1;I)V

    .line 620
    .line 621
    .line 622
    invoke-virtual {v1, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 623
    .line 624
    .line 625
    :cond_19
    check-cast v3, Lay0/k;

    .line 626
    .line 627
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 628
    .line 629
    invoke-static {v2, v3}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 630
    .line 631
    .line 632
    move-result-object v2

    .line 633
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 634
    .line 635
    check-cast v0, Lt2/b;

    .line 636
    .line 637
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 638
    .line 639
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 640
    .line 641
    .line 642
    move-result-object v3

    .line 643
    iget-wide v7, v1, Ll2/t;->T:J

    .line 644
    .line 645
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 646
    .line 647
    .line 648
    move-result v4

    .line 649
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 650
    .line 651
    .line 652
    move-result-object v7

    .line 653
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 654
    .line 655
    .line 656
    move-result-object v2

    .line 657
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 658
    .line 659
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 660
    .line 661
    .line 662
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 663
    .line 664
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 665
    .line 666
    .line 667
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 668
    .line 669
    if-eqz v9, :cond_1a

    .line 670
    .line 671
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 672
    .line 673
    .line 674
    goto :goto_12

    .line 675
    :cond_1a
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 676
    .line 677
    .line 678
    :goto_12
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 679
    .line 680
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 681
    .line 682
    .line 683
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 684
    .line 685
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 686
    .line 687
    .line 688
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 689
    .line 690
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 691
    .line 692
    if-nez v7, :cond_1b

    .line 693
    .line 694
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 695
    .line 696
    .line 697
    move-result-object v7

    .line 698
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 699
    .line 700
    .line 701
    move-result-object v8

    .line 702
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 703
    .line 704
    .line 705
    move-result v7

    .line 706
    if-nez v7, :cond_1c

    .line 707
    .line 708
    :cond_1b
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 709
    .line 710
    .line 711
    :cond_1c
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 712
    .line 713
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 714
    .line 715
    .line 716
    invoke-static {v6, v0, v1, v5}, Lia/b;->r(ILt2/b;Ll2/t;Z)V

    .line 717
    .line 718
    .line 719
    goto :goto_13

    .line 720
    :cond_1d
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 721
    .line 722
    .line 723
    :goto_13
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 724
    .line 725
    return-object v0

    .line 726
    :pswitch_6
    move-object/from16 v1, p1

    .line 727
    .line 728
    check-cast v1, Ll2/o;

    .line 729
    .line 730
    move-object/from16 v2, p2

    .line 731
    .line 732
    check-cast v2, Ljava/lang/Number;

    .line 733
    .line 734
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 735
    .line 736
    .line 737
    move-result v2

    .line 738
    and-int/lit8 v3, v2, 0x3

    .line 739
    .line 740
    const/4 v4, 0x2

    .line 741
    const/4 v5, 0x0

    .line 742
    const/4 v6, 0x1

    .line 743
    if-eq v3, v4, :cond_1e

    .line 744
    .line 745
    move v3, v6

    .line 746
    goto :goto_14

    .line 747
    :cond_1e
    move v3, v5

    .line 748
    :goto_14
    and-int/2addr v2, v6

    .line 749
    check-cast v1, Ll2/t;

    .line 750
    .line 751
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 752
    .line 753
    .line 754
    move-result v2

    .line 755
    if-eqz v2, :cond_1f

    .line 756
    .line 757
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 758
    .line 759
    check-cast v2, Lt2/b;

    .line 760
    .line 761
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 762
    .line 763
    check-cast v0, Ljava/util/ArrayList;

    .line 764
    .line 765
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 766
    .line 767
    .line 768
    move-result-object v3

    .line 769
    invoke-virtual {v2, v0, v1, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 770
    .line 771
    .line 772
    goto :goto_15

    .line 773
    :cond_1f
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 774
    .line 775
    .line 776
    :goto_15
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 777
    .line 778
    return-object v0

    .line 779
    :pswitch_7
    move-object/from16 v1, p1

    .line 780
    .line 781
    check-cast v1, Ll2/o;

    .line 782
    .line 783
    move-object/from16 v2, p2

    .line 784
    .line 785
    check-cast v2, Ljava/lang/Number;

    .line 786
    .line 787
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 788
    .line 789
    .line 790
    move-result v2

    .line 791
    and-int/lit8 v3, v2, 0x3

    .line 792
    .line 793
    const/4 v4, 0x2

    .line 794
    const/4 v5, 0x0

    .line 795
    const/4 v6, 0x1

    .line 796
    if-eq v3, v4, :cond_20

    .line 797
    .line 798
    move v3, v6

    .line 799
    goto :goto_16

    .line 800
    :cond_20
    move v3, v5

    .line 801
    :goto_16
    and-int/2addr v2, v6

    .line 802
    check-cast v1, Ll2/t;

    .line 803
    .line 804
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 805
    .line 806
    .line 807
    move-result v2

    .line 808
    if-eqz v2, :cond_21

    .line 809
    .line 810
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 811
    .line 812
    check-cast v2, Lay0/o;

    .line 813
    .line 814
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 815
    .line 816
    check-cast v0, Lh2/t9;

    .line 817
    .line 818
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 819
    .line 820
    .line 821
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 822
    .line 823
    .line 824
    move-result-object v3

    .line 825
    invoke-interface {v2, v0, v1, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 826
    .line 827
    .line 828
    goto :goto_17

    .line 829
    :cond_21
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 830
    .line 831
    .line 832
    :goto_17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 833
    .line 834
    return-object v0

    .line 835
    :pswitch_8
    move-object/from16 v1, p1

    .line 836
    .line 837
    check-cast v1, Ll2/o;

    .line 838
    .line 839
    move-object/from16 v2, p2

    .line 840
    .line 841
    check-cast v2, Ljava/lang/Number;

    .line 842
    .line 843
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 844
    .line 845
    .line 846
    move-result v2

    .line 847
    and-int/lit8 v3, v2, 0x3

    .line 848
    .line 849
    const/4 v4, 0x2

    .line 850
    const/4 v5, 0x0

    .line 851
    const/4 v6, 0x1

    .line 852
    if-eq v3, v4, :cond_22

    .line 853
    .line 854
    move v3, v6

    .line 855
    goto :goto_18

    .line 856
    :cond_22
    move v3, v5

    .line 857
    :goto_18
    and-int/2addr v2, v6

    .line 858
    check-cast v1, Ll2/t;

    .line 859
    .line 860
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 861
    .line 862
    .line 863
    move-result v2

    .line 864
    if-eqz v2, :cond_26

    .line 865
    .line 866
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 867
    .line 868
    check-cast v2, Lay0/o;

    .line 869
    .line 870
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 871
    .line 872
    check-cast v0, Lh2/b8;

    .line 873
    .line 874
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 875
    .line 876
    invoke-static {v3, v5}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 877
    .line 878
    .line 879
    move-result-object v3

    .line 880
    iget-wide v4, v1, Ll2/t;->T:J

    .line 881
    .line 882
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 883
    .line 884
    .line 885
    move-result v4

    .line 886
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 887
    .line 888
    .line 889
    move-result-object v5

    .line 890
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 891
    .line 892
    invoke-static {v1, v7}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 893
    .line 894
    .line 895
    move-result-object v7

    .line 896
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 897
    .line 898
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 899
    .line 900
    .line 901
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 902
    .line 903
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 904
    .line 905
    .line 906
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 907
    .line 908
    if-eqz v9, :cond_23

    .line 909
    .line 910
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 911
    .line 912
    .line 913
    goto :goto_19

    .line 914
    :cond_23
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 915
    .line 916
    .line 917
    :goto_19
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 918
    .line 919
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 920
    .line 921
    .line 922
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 923
    .line 924
    invoke-static {v3, v5, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 925
    .line 926
    .line 927
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 928
    .line 929
    iget-boolean v5, v1, Ll2/t;->S:Z

    .line 930
    .line 931
    if-nez v5, :cond_24

    .line 932
    .line 933
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 934
    .line 935
    .line 936
    move-result-object v5

    .line 937
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 938
    .line 939
    .line 940
    move-result-object v8

    .line 941
    invoke-static {v5, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 942
    .line 943
    .line 944
    move-result v5

    .line 945
    if-nez v5, :cond_25

    .line 946
    .line 947
    :cond_24
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 948
    .line 949
    .line 950
    :cond_25
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 951
    .line 952
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 953
    .line 954
    .line 955
    const/4 v3, 0x6

    .line 956
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 957
    .line 958
    .line 959
    move-result-object v3

    .line 960
    invoke-interface {v2, v0, v1, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 961
    .line 962
    .line 963
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 964
    .line 965
    .line 966
    goto :goto_1a

    .line 967
    :cond_26
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 968
    .line 969
    .line 970
    :goto_1a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 971
    .line 972
    return-object v0

    .line 973
    :pswitch_9
    move-object/from16 v1, p1

    .line 974
    .line 975
    check-cast v1, Ll2/o;

    .line 976
    .line 977
    move-object/from16 v2, p2

    .line 978
    .line 979
    check-cast v2, Ljava/lang/Number;

    .line 980
    .line 981
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 982
    .line 983
    .line 984
    move-result v2

    .line 985
    and-int/lit8 v3, v2, 0x3

    .line 986
    .line 987
    const/4 v4, 0x2

    .line 988
    const/4 v5, 0x0

    .line 989
    const/4 v6, 0x1

    .line 990
    if-eq v3, v4, :cond_27

    .line 991
    .line 992
    move v3, v6

    .line 993
    goto :goto_1b

    .line 994
    :cond_27
    move v3, v5

    .line 995
    :goto_1b
    and-int/2addr v2, v6

    .line 996
    check-cast v1, Ll2/t;

    .line 997
    .line 998
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 999
    .line 1000
    .line 1001
    move-result v2

    .line 1002
    if-eqz v2, :cond_28

    .line 1003
    .line 1004
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1005
    .line 1006
    check-cast v2, Lh2/dc;

    .line 1007
    .line 1008
    iget-object v2, v2, Lh2/dc;->j:Lg4/p0;

    .line 1009
    .line 1010
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1011
    .line 1012
    check-cast v0, Lt2/b;

    .line 1013
    .line 1014
    invoke-static {v2, v0, v1, v5}, Lh2/rb;->a(Lg4/p0;Lay0/n;Ll2/o;I)V

    .line 1015
    .line 1016
    .line 1017
    goto :goto_1c

    .line 1018
    :cond_28
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1019
    .line 1020
    .line 1021
    :goto_1c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1022
    .line 1023
    return-object v0

    .line 1024
    :pswitch_a
    iget-object v1, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1025
    .line 1026
    move-object v2, v1

    .line 1027
    check-cast v2, Ljava/lang/String;

    .line 1028
    .line 1029
    move-object/from16 v1, p1

    .line 1030
    .line 1031
    check-cast v1, Ll2/o;

    .line 1032
    .line 1033
    move-object/from16 v3, p2

    .line 1034
    .line 1035
    check-cast v3, Ljava/lang/Number;

    .line 1036
    .line 1037
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 1038
    .line 1039
    .line 1040
    move-result v3

    .line 1041
    and-int/lit8 v4, v3, 0x3

    .line 1042
    .line 1043
    const/4 v5, 0x2

    .line 1044
    const/4 v6, 0x0

    .line 1045
    const/4 v7, 0x1

    .line 1046
    if-eq v4, v5, :cond_29

    .line 1047
    .line 1048
    move v4, v7

    .line 1049
    goto :goto_1d

    .line 1050
    :cond_29
    move v4, v6

    .line 1051
    :goto_1d
    and-int/2addr v3, v7

    .line 1052
    check-cast v1, Ll2/t;

    .line 1053
    .line 1054
    invoke-virtual {v1, v3, v4}, Ll2/t;->O(IZ)Z

    .line 1055
    .line 1056
    .line 1057
    move-result v3

    .line 1058
    if-eqz v3, :cond_2c

    .line 1059
    .line 1060
    invoke-virtual {v1, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1061
    .line 1062
    .line 1063
    move-result v3

    .line 1064
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 1065
    .line 1066
    .line 1067
    move-result-object v4

    .line 1068
    if-nez v3, :cond_2a

    .line 1069
    .line 1070
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 1071
    .line 1072
    if-ne v4, v3, :cond_2b

    .line 1073
    .line 1074
    :cond_2a
    new-instance v4, Lac0/r;

    .line 1075
    .line 1076
    const/16 v3, 0x11

    .line 1077
    .line 1078
    invoke-direct {v4, v2, v3}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 1079
    .line 1080
    .line 1081
    invoke-virtual {v1, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1082
    .line 1083
    .line 1084
    :cond_2b
    check-cast v4, Lay0/k;

    .line 1085
    .line 1086
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 1087
    .line 1088
    invoke-static {v3, v6, v4}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 1089
    .line 1090
    .line 1091
    move-result-object v3

    .line 1092
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1093
    .line 1094
    check-cast v0, Lh2/z1;

    .line 1095
    .line 1096
    iget-wide v4, v0, Lh2/z1;->f:J

    .line 1097
    .line 1098
    const/16 v23, 0x0

    .line 1099
    .line 1100
    const v24, 0x3fff8

    .line 1101
    .line 1102
    .line 1103
    const-wide/16 v6, 0x0

    .line 1104
    .line 1105
    const/4 v8, 0x0

    .line 1106
    const-wide/16 v9, 0x0

    .line 1107
    .line 1108
    const/4 v11, 0x0

    .line 1109
    const/4 v12, 0x0

    .line 1110
    const-wide/16 v13, 0x0

    .line 1111
    .line 1112
    const/4 v15, 0x0

    .line 1113
    const/16 v16, 0x0

    .line 1114
    .line 1115
    const/16 v17, 0x0

    .line 1116
    .line 1117
    const/16 v18, 0x0

    .line 1118
    .line 1119
    const/16 v19, 0x0

    .line 1120
    .line 1121
    const/16 v20, 0x0

    .line 1122
    .line 1123
    const/16 v22, 0x0

    .line 1124
    .line 1125
    move-object/from16 v21, v1

    .line 1126
    .line 1127
    invoke-static/range {v2 .. v24}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 1128
    .line 1129
    .line 1130
    goto :goto_1e

    .line 1131
    :cond_2c
    move-object/from16 v21, v1

    .line 1132
    .line 1133
    invoke-virtual/range {v21 .. v21}, Ll2/t;->R()V

    .line 1134
    .line 1135
    .line 1136
    :goto_1e
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1137
    .line 1138
    return-object v0

    .line 1139
    :pswitch_b
    move-object/from16 v1, p1

    .line 1140
    .line 1141
    check-cast v1, Ll2/o;

    .line 1142
    .line 1143
    move-object/from16 v2, p2

    .line 1144
    .line 1145
    check-cast v2, Ljava/lang/Number;

    .line 1146
    .line 1147
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1148
    .line 1149
    .line 1150
    move-result v2

    .line 1151
    and-int/lit8 v3, v2, 0x3

    .line 1152
    .line 1153
    const/4 v4, 0x2

    .line 1154
    const/4 v5, 0x1

    .line 1155
    if-eq v3, v4, :cond_2d

    .line 1156
    .line 1157
    move v3, v5

    .line 1158
    goto :goto_1f

    .line 1159
    :cond_2d
    const/4 v3, 0x0

    .line 1160
    :goto_1f
    and-int/2addr v2, v5

    .line 1161
    move-object v9, v1

    .line 1162
    check-cast v9, Ll2/t;

    .line 1163
    .line 1164
    invoke-virtual {v9, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1165
    .line 1166
    .line 1167
    move-result v1

    .line 1168
    if-eqz v1, :cond_2e

    .line 1169
    .line 1170
    iget-object v1, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1171
    .line 1172
    move-object v4, v1

    .line 1173
    check-cast v4, Lj3/f;

    .line 1174
    .line 1175
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1176
    .line 1177
    move-object v5, v0

    .line 1178
    check-cast v5, Ljava/lang/String;

    .line 1179
    .line 1180
    const/4 v10, 0x0

    .line 1181
    const/16 v11, 0xc

    .line 1182
    .line 1183
    const/4 v6, 0x0

    .line 1184
    const-wide/16 v7, 0x0

    .line 1185
    .line 1186
    invoke-static/range {v4 .. v11}, Lh2/f5;->b(Lj3/f;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 1187
    .line 1188
    .line 1189
    goto :goto_20

    .line 1190
    :cond_2e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 1191
    .line 1192
    .line 1193
    :goto_20
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1194
    .line 1195
    return-object v0

    .line 1196
    :pswitch_c
    move-object/from16 v1, p1

    .line 1197
    .line 1198
    check-cast v1, Ll2/o;

    .line 1199
    .line 1200
    move-object/from16 v2, p2

    .line 1201
    .line 1202
    check-cast v2, Ljava/lang/Number;

    .line 1203
    .line 1204
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1205
    .line 1206
    .line 1207
    move-result v2

    .line 1208
    iget-object v3, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1209
    .line 1210
    check-cast v3, Lh2/o3;

    .line 1211
    .line 1212
    and-int/lit8 v4, v2, 0x3

    .line 1213
    .line 1214
    const/4 v5, 0x2

    .line 1215
    const/4 v6, 0x1

    .line 1216
    if-eq v4, v5, :cond_2f

    .line 1217
    .line 1218
    move v4, v6

    .line 1219
    goto :goto_21

    .line 1220
    :cond_2f
    const/4 v4, 0x0

    .line 1221
    :goto_21
    and-int/2addr v2, v6

    .line 1222
    move-object v9, v1

    .line 1223
    check-cast v9, Ll2/t;

    .line 1224
    .line 1225
    invoke-virtual {v9, v2, v4}, Ll2/t;->O(IZ)Z

    .line 1226
    .line 1227
    .line 1228
    move-result v1

    .line 1229
    if-eqz v1, :cond_32

    .line 1230
    .line 1231
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 1232
    .line 1233
    sget-object v2, Lh2/m3;->d:Lk1/a1;

    .line 1234
    .line 1235
    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 1236
    .line 1237
    .line 1238
    move-result-object v5

    .line 1239
    invoke-virtual {v3}, Lh2/o3;->f()I

    .line 1240
    .line 1241
    .line 1242
    move-result v6

    .line 1243
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1244
    .line 1245
    .line 1246
    move-result v1

    .line 1247
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1248
    .line 1249
    .line 1250
    move-result-object v2

    .line 1251
    if-nez v1, :cond_30

    .line 1252
    .line 1253
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 1254
    .line 1255
    if-ne v2, v1, :cond_31

    .line 1256
    .line 1257
    :cond_30
    new-instance v2, Lh2/v2;

    .line 1258
    .line 1259
    const/4 v1, 0x0

    .line 1260
    invoke-direct {v2, v3, v1}, Lh2/v2;-><init>(Lh2/o3;I)V

    .line 1261
    .line 1262
    .line 1263
    invoke-virtual {v9, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1264
    .line 1265
    .line 1266
    :cond_31
    move-object v7, v2

    .line 1267
    check-cast v7, Lay0/k;

    .line 1268
    .line 1269
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1270
    .line 1271
    move-object v8, v0

    .line 1272
    check-cast v8, Lh2/z1;

    .line 1273
    .line 1274
    const/4 v10, 0x6

    .line 1275
    invoke-static/range {v5 .. v10}, Lh2/m3;->f(Lx2/s;ILay0/k;Lh2/z1;Ll2/o;I)V

    .line 1276
    .line 1277
    .line 1278
    goto :goto_22

    .line 1279
    :cond_32
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 1280
    .line 1281
    .line 1282
    :goto_22
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1283
    .line 1284
    return-object v0

    .line 1285
    :pswitch_d
    move-object/from16 v1, p1

    .line 1286
    .line 1287
    check-cast v1, Ll2/o;

    .line 1288
    .line 1289
    move-object/from16 v2, p2

    .line 1290
    .line 1291
    check-cast v2, Ljava/lang/Number;

    .line 1292
    .line 1293
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1294
    .line 1295
    .line 1296
    move-result v2

    .line 1297
    and-int/lit8 v3, v2, 0x3

    .line 1298
    .line 1299
    const/4 v4, 0x2

    .line 1300
    const/4 v5, 0x1

    .line 1301
    const/4 v6, 0x0

    .line 1302
    if-eq v3, v4, :cond_33

    .line 1303
    .line 1304
    move v3, v5

    .line 1305
    goto :goto_23

    .line 1306
    :cond_33
    move v3, v6

    .line 1307
    :goto_23
    and-int/2addr v2, v5

    .line 1308
    move-object v11, v1

    .line 1309
    check-cast v11, Ll2/t;

    .line 1310
    .line 1311
    invoke-virtual {v11, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1312
    .line 1313
    .line 1314
    move-result v1

    .line 1315
    if-eqz v1, :cond_3d

    .line 1316
    .line 1317
    sget-object v1, Lk1/j;->g:Lk1/f;

    .line 1318
    .line 1319
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1320
    .line 1321
    check-cast v2, Lt2/b;

    .line 1322
    .line 1323
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1324
    .line 1325
    check-cast v0, Lt2/b;

    .line 1326
    .line 1327
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 1328
    .line 1329
    const/4 v4, 0x6

    .line 1330
    invoke-static {v1, v3, v11, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 1331
    .line 1332
    .line 1333
    move-result-object v1

    .line 1334
    iget-wide v7, v11, Ll2/t;->T:J

    .line 1335
    .line 1336
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 1337
    .line 1338
    .line 1339
    move-result v3

    .line 1340
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 1341
    .line 1342
    .line 1343
    move-result-object v7

    .line 1344
    sget-object v8, Lx2/p;->b:Lx2/p;

    .line 1345
    .line 1346
    invoke-static {v11, v8}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1347
    .line 1348
    .line 1349
    move-result-object v9

    .line 1350
    sget-object v10, Lv3/k;->m1:Lv3/j;

    .line 1351
    .line 1352
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1353
    .line 1354
    .line 1355
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 1356
    .line 1357
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 1358
    .line 1359
    .line 1360
    iget-boolean v12, v11, Ll2/t;->S:Z

    .line 1361
    .line 1362
    if-eqz v12, :cond_34

    .line 1363
    .line 1364
    invoke-virtual {v11, v10}, Ll2/t;->l(Lay0/a;)V

    .line 1365
    .line 1366
    .line 1367
    goto :goto_24

    .line 1368
    :cond_34
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 1369
    .line 1370
    .line 1371
    :goto_24
    sget-object v12, Lv3/j;->g:Lv3/h;

    .line 1372
    .line 1373
    invoke-static {v12, v1, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1374
    .line 1375
    .line 1376
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 1377
    .line 1378
    invoke-static {v1, v7, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1379
    .line 1380
    .line 1381
    sget-object v7, Lv3/j;->j:Lv3/h;

    .line 1382
    .line 1383
    iget-boolean v13, v11, Ll2/t;->S:Z

    .line 1384
    .line 1385
    if-nez v13, :cond_35

    .line 1386
    .line 1387
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 1388
    .line 1389
    .line 1390
    move-result-object v13

    .line 1391
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1392
    .line 1393
    .line 1394
    move-result-object v14

    .line 1395
    invoke-static {v13, v14}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1396
    .line 1397
    .line 1398
    move-result v13

    .line 1399
    if-nez v13, :cond_36

    .line 1400
    .line 1401
    :cond_35
    invoke-static {v3, v11, v3, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1402
    .line 1403
    .line 1404
    :cond_36
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 1405
    .line 1406
    invoke-static {v3, v9, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1407
    .line 1408
    .line 1409
    sget-object v9, Lk1/t;->a:Lk1/t;

    .line 1410
    .line 1411
    invoke-virtual {v9, v8, v6}, Lk1/t;->b(Lx2/s;Z)Lx2/s;

    .line 1412
    .line 1413
    .line 1414
    move-result-object v13

    .line 1415
    sget-object v14, Lx2/c;->d:Lx2/j;

    .line 1416
    .line 1417
    invoke-static {v14, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1418
    .line 1419
    .line 1420
    move-result-object v15

    .line 1421
    move/from16 p0, v4

    .line 1422
    .line 1423
    iget-wide v4, v11, Ll2/t;->T:J

    .line 1424
    .line 1425
    invoke-static {v4, v5}, Ljava/lang/Long;->hashCode(J)I

    .line 1426
    .line 1427
    .line 1428
    move-result v4

    .line 1429
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 1430
    .line 1431
    .line 1432
    move-result-object v5

    .line 1433
    invoke-static {v11, v13}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1434
    .line 1435
    .line 1436
    move-result-object v13

    .line 1437
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 1438
    .line 1439
    .line 1440
    iget-boolean v6, v11, Ll2/t;->S:Z

    .line 1441
    .line 1442
    if-eqz v6, :cond_37

    .line 1443
    .line 1444
    invoke-virtual {v11, v10}, Ll2/t;->l(Lay0/a;)V

    .line 1445
    .line 1446
    .line 1447
    goto :goto_25

    .line 1448
    :cond_37
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 1449
    .line 1450
    .line 1451
    :goto_25
    invoke-static {v12, v15, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1452
    .line 1453
    .line 1454
    invoke-static {v1, v5, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1455
    .line 1456
    .line 1457
    iget-boolean v5, v11, Ll2/t;->S:Z

    .line 1458
    .line 1459
    if-nez v5, :cond_38

    .line 1460
    .line 1461
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v5

    .line 1465
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1466
    .line 1467
    .line 1468
    move-result-object v6

    .line 1469
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1470
    .line 1471
    .line 1472
    move-result v5

    .line 1473
    if-nez v5, :cond_39

    .line 1474
    .line 1475
    :cond_38
    invoke-static {v4, v11, v4, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1476
    .line 1477
    .line 1478
    :cond_39
    invoke-static {v3, v13, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1479
    .line 1480
    .line 1481
    invoke-static/range {p0 .. p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1482
    .line 1483
    .line 1484
    move-result-object v4

    .line 1485
    invoke-virtual {v2, v9, v11, v4}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1486
    .line 1487
    .line 1488
    const/4 v2, 0x1

    .line 1489
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 1490
    .line 1491
    .line 1492
    sget-object v2, Lx2/c;->r:Lx2/h;

    .line 1493
    .line 1494
    invoke-virtual {v9, v2, v8}, Lk1/t;->a(Lx2/h;Lx2/s;)Lx2/s;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v2

    .line 1498
    sget-object v4, Lh2/f2;->a:Lk1/a1;

    .line 1499
    .line 1500
    invoke-static {v2, v4}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 1501
    .line 1502
    .line 1503
    move-result-object v2

    .line 1504
    const/4 v4, 0x0

    .line 1505
    invoke-static {v14, v4}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v4

    .line 1509
    iget-wide v5, v11, Ll2/t;->T:J

    .line 1510
    .line 1511
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 1512
    .line 1513
    .line 1514
    move-result v5

    .line 1515
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 1516
    .line 1517
    .line 1518
    move-result-object v6

    .line 1519
    invoke-static {v11, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 1520
    .line 1521
    .line 1522
    move-result-object v2

    .line 1523
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 1524
    .line 1525
    .line 1526
    iget-boolean v8, v11, Ll2/t;->S:Z

    .line 1527
    .line 1528
    if-eqz v8, :cond_3a

    .line 1529
    .line 1530
    invoke-virtual {v11, v10}, Ll2/t;->l(Lay0/a;)V

    .line 1531
    .line 1532
    .line 1533
    goto :goto_26

    .line 1534
    :cond_3a
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 1535
    .line 1536
    .line 1537
    :goto_26
    invoke-static {v12, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1538
    .line 1539
    .line 1540
    invoke-static {v1, v6, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1541
    .line 1542
    .line 1543
    iget-boolean v1, v11, Ll2/t;->S:Z

    .line 1544
    .line 1545
    if-nez v1, :cond_3b

    .line 1546
    .line 1547
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 1548
    .line 1549
    .line 1550
    move-result-object v1

    .line 1551
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1552
    .line 1553
    .line 1554
    move-result-object v4

    .line 1555
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1556
    .line 1557
    .line 1558
    move-result v1

    .line 1559
    if-nez v1, :cond_3c

    .line 1560
    .line 1561
    :cond_3b
    invoke-static {v5, v11, v5, v7}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 1562
    .line 1563
    .line 1564
    :cond_3c
    invoke-static {v3, v2, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 1565
    .line 1566
    .line 1567
    sget-object v1, Lk2/n;->a:Lk2/l;

    .line 1568
    .line 1569
    invoke-static {v1, v11}, Lh2/g1;->d(Lk2/l;Ll2/o;)J

    .line 1570
    .line 1571
    .line 1572
    move-result-wide v7

    .line 1573
    sget-object v1, Lk2/n;->b:Lk2/p0;

    .line 1574
    .line 1575
    invoke-static {v1, v11}, Lh2/ec;->a(Lk2/p0;Ll2/o;)Lg4/p0;

    .line 1576
    .line 1577
    .line 1578
    move-result-object v9

    .line 1579
    new-instance v1, Lf2/c0;

    .line 1580
    .line 1581
    const/4 v2, 0x7

    .line 1582
    invoke-direct {v1, v0, v2}, Lf2/c0;-><init>(Lt2/b;I)V

    .line 1583
    .line 1584
    .line 1585
    const v0, -0x41cc98e9

    .line 1586
    .line 1587
    .line 1588
    invoke-static {v0, v11, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 1589
    .line 1590
    .line 1591
    move-result-object v10

    .line 1592
    const/16 v12, 0x180

    .line 1593
    .line 1594
    invoke-static/range {v7 .. v12}, Li2/a1;->d(JLg4/p0;Lay0/n;Ll2/o;I)V

    .line 1595
    .line 1596
    .line 1597
    const/4 v2, 0x1

    .line 1598
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 1599
    .line 1600
    .line 1601
    invoke-virtual {v11, v2}, Ll2/t;->q(Z)V

    .line 1602
    .line 1603
    .line 1604
    goto :goto_27

    .line 1605
    :cond_3d
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 1606
    .line 1607
    .line 1608
    :goto_27
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1609
    .line 1610
    return-object v0

    .line 1611
    :pswitch_e
    move-object/from16 v1, p1

    .line 1612
    .line 1613
    check-cast v1, Ll2/o;

    .line 1614
    .line 1615
    move-object/from16 v2, p2

    .line 1616
    .line 1617
    check-cast v2, Ljava/lang/Number;

    .line 1618
    .line 1619
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1620
    .line 1621
    .line 1622
    move-result v2

    .line 1623
    and-int/lit8 v3, v2, 0x3

    .line 1624
    .line 1625
    const/4 v4, 0x2

    .line 1626
    const/4 v5, 0x0

    .line 1627
    const/4 v6, 0x1

    .line 1628
    if-eq v3, v4, :cond_3e

    .line 1629
    .line 1630
    move v3, v6

    .line 1631
    goto :goto_28

    .line 1632
    :cond_3e
    move v3, v5

    .line 1633
    :goto_28
    and-int/2addr v2, v6

    .line 1634
    check-cast v1, Ll2/t;

    .line 1635
    .line 1636
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 1637
    .line 1638
    .line 1639
    move-result v2

    .line 1640
    if-eqz v2, :cond_3f

    .line 1641
    .line 1642
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1643
    .line 1644
    check-cast v2, Lay0/o;

    .line 1645
    .line 1646
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1647
    .line 1648
    check-cast v0, Lh2/m0;

    .line 1649
    .line 1650
    iget-object v0, v0, Lh2/m0;->b:Lh2/aa;

    .line 1651
    .line 1652
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1653
    .line 1654
    .line 1655
    move-result-object v3

    .line 1656
    invoke-interface {v2, v0, v1, v3}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1657
    .line 1658
    .line 1659
    goto :goto_29

    .line 1660
    :cond_3f
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 1661
    .line 1662
    .line 1663
    :goto_29
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1664
    .line 1665
    return-object v0

    .line 1666
    :pswitch_f
    move-object/from16 v1, p1

    .line 1667
    .line 1668
    check-cast v1, Ll2/o;

    .line 1669
    .line 1670
    move-object/from16 v2, p2

    .line 1671
    .line 1672
    check-cast v2, Ljava/lang/Number;

    .line 1673
    .line 1674
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1675
    .line 1676
    .line 1677
    move-result v2

    .line 1678
    iget-object v3, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1679
    .line 1680
    check-cast v3, Lz9/k;

    .line 1681
    .line 1682
    and-int/lit8 v2, v2, 0x3

    .line 1683
    .line 1684
    const/4 v4, 0x2

    .line 1685
    if-ne v2, v4, :cond_41

    .line 1686
    .line 1687
    move-object v2, v1

    .line 1688
    check-cast v2, Ll2/t;

    .line 1689
    .line 1690
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 1691
    .line 1692
    .line 1693
    move-result v4

    .line 1694
    if-nez v4, :cond_40

    .line 1695
    .line 1696
    goto :goto_2a

    .line 1697
    :cond_40
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 1698
    .line 1699
    .line 1700
    goto :goto_2b

    .line 1701
    :cond_41
    :goto_2a
    iget-object v2, v3, Lz9/k;->e:Lz9/u;

    .line 1702
    .line 1703
    const-string v4, "null cannot be cast to non-null type androidx.navigation.compose.ComposeNavigator.Destination"

    .line 1704
    .line 1705
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1706
    .line 1707
    .line 1708
    check-cast v2, Laa/h;

    .line 1709
    .line 1710
    iget-object v2, v2, Laa/h;->i:Lay0/p;

    .line 1711
    .line 1712
    iget-object v0, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1713
    .line 1714
    check-cast v0, Lb1/n;

    .line 1715
    .line 1716
    const/4 v4, 0x0

    .line 1717
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v4

    .line 1721
    invoke-interface {v2, v0, v3, v1, v4}, Lay0/p;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1722
    .line 1723
    .line 1724
    :goto_2b
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1725
    .line 1726
    return-object v0

    .line 1727
    :pswitch_10
    move-object/from16 v1, p1

    .line 1728
    .line 1729
    check-cast v1, Ll2/o;

    .line 1730
    .line 1731
    move-object/from16 v2, p2

    .line 1732
    .line 1733
    check-cast v2, Ljava/lang/Number;

    .line 1734
    .line 1735
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1736
    .line 1737
    .line 1738
    move-result v2

    .line 1739
    and-int/lit8 v2, v2, 0x3

    .line 1740
    .line 1741
    const/4 v3, 0x2

    .line 1742
    if-ne v2, v3, :cond_43

    .line 1743
    .line 1744
    move-object v2, v1

    .line 1745
    check-cast v2, Ll2/t;

    .line 1746
    .line 1747
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 1748
    .line 1749
    .line 1750
    move-result v3

    .line 1751
    if-nez v3, :cond_42

    .line 1752
    .line 1753
    goto :goto_2c

    .line 1754
    :cond_42
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 1755
    .line 1756
    .line 1757
    goto :goto_2d

    .line 1758
    :cond_43
    :goto_2c
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1759
    .line 1760
    check-cast v2, Lu2/c;

    .line 1761
    .line 1762
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1763
    .line 1764
    check-cast v0, Lt2/b;

    .line 1765
    .line 1766
    const/4 v3, 0x0

    .line 1767
    invoke-static {v2, v0, v1, v3}, Ljp/q0;->b(Lu2/c;Lt2/b;Ll2/o;I)V

    .line 1768
    .line 1769
    .line 1770
    :goto_2d
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1771
    .line 1772
    return-object v0

    .line 1773
    :pswitch_11
    move-object/from16 v1, p1

    .line 1774
    .line 1775
    check-cast v1, Ll2/o;

    .line 1776
    .line 1777
    move-object/from16 v2, p2

    .line 1778
    .line 1779
    check-cast v2, Ljava/lang/Number;

    .line 1780
    .line 1781
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 1782
    .line 1783
    .line 1784
    move-result v2

    .line 1785
    and-int/lit8 v2, v2, 0x3

    .line 1786
    .line 1787
    const/4 v3, 0x2

    .line 1788
    if-ne v2, v3, :cond_45

    .line 1789
    .line 1790
    move-object v2, v1

    .line 1791
    check-cast v2, Ll2/t;

    .line 1792
    .line 1793
    invoke-virtual {v2}, Ll2/t;->A()Z

    .line 1794
    .line 1795
    .line 1796
    move-result v3

    .line 1797
    if-nez v3, :cond_44

    .line 1798
    .line 1799
    goto :goto_2e

    .line 1800
    :cond_44
    invoke-virtual {v2}, Ll2/t;->R()V

    .line 1801
    .line 1802
    .line 1803
    goto :goto_2f

    .line 1804
    :cond_45
    :goto_2e
    iget-object v2, v0, Laa/p;->e:Ljava/lang/Object;

    .line 1805
    .line 1806
    check-cast v2, Laa/u;

    .line 1807
    .line 1808
    iget-object v2, v2, Laa/u;->j:Lt2/b;

    .line 1809
    .line 1810
    iget-object v0, v0, Laa/p;->f:Ljava/lang/Object;

    .line 1811
    .line 1812
    check-cast v0, Lz9/k;

    .line 1813
    .line 1814
    const/4 v3, 0x0

    .line 1815
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v3

    .line 1819
    invoke-virtual {v2, v0, v1, v3}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1820
    .line 1821
    .line 1822
    :goto_2f
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1823
    .line 1824
    return-object v0

    .line 1825
    :pswitch_data_0
    .packed-switch 0x0
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
