.class public final synthetic Ldl/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Ldl/h;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Ldl/h;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ldl/h;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ldl/h;->d:I

    .line 4
    .line 5
    const-string v3, "entry"

    .line 6
    .line 7
    const/4 v4, 0x1

    .line 8
    const/4 v5, 0x2

    .line 9
    const/16 v6, 0x30

    .line 10
    .line 11
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 12
    .line 13
    const/16 v8, 0x8

    .line 14
    .line 15
    const-string v9, "$this$HorizontalPager"

    .line 16
    .line 17
    const-string v10, "it"

    .line 18
    .line 19
    const-string v11, "$this$composable"

    .line 20
    .line 21
    const/4 v12, 0x0

    .line 22
    sget-object v13, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    iget-object v14, v0, Ldl/h;->f:Ljava/lang/Object;

    .line 25
    .line 26
    iget-object v0, v0, Ldl/h;->e:Ljava/lang/Object;

    .line 27
    .line 28
    packed-switch v1, :pswitch_data_0

    .line 29
    .line 30
    .line 31
    check-cast v0, Lt2/b;

    .line 32
    .line 33
    check-cast v14, Lay0/a;

    .line 34
    .line 35
    move-object/from16 v1, p1

    .line 36
    .line 37
    check-cast v1, Lb1/n;

    .line 38
    .line 39
    move-object/from16 v2, p2

    .line 40
    .line 41
    check-cast v2, Lz9/k;

    .line 42
    .line 43
    move-object/from16 v3, p3

    .line 44
    .line 45
    check-cast v3, Ll2/o;

    .line 46
    .line 47
    move-object/from16 v4, p4

    .line 48
    .line 49
    check-cast v4, Ljava/lang/Integer;

    .line 50
    .line 51
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {v0, v14, v3, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return-object v13

    .line 62
    :pswitch_0
    check-cast v0, Lx10/a;

    .line 63
    .line 64
    check-cast v14, Lp1/v;

    .line 65
    .line 66
    move-object/from16 v1, p1

    .line 67
    .line 68
    check-cast v1, Lp1/p;

    .line 69
    .line 70
    move-object/from16 v2, p2

    .line 71
    .line 72
    check-cast v2, Ljava/lang/Integer;

    .line 73
    .line 74
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    move-object/from16 v3, p3

    .line 79
    .line 80
    check-cast v3, Ll2/o;

    .line 81
    .line 82
    move-object/from16 v5, p4

    .line 83
    .line 84
    check-cast v5, Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    check-cast v3, Ll2/t;

    .line 93
    .line 94
    invoke-virtual {v3}, Ll2/t;->L()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    if-ne v1, v7, :cond_0

    .line 99
    .line 100
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    invoke-virtual {v3, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    :cond_0
    check-cast v1, Ll2/b1;

    .line 110
    .line 111
    iget-object v5, v0, Lx10/a;->b:Ljava/util/List;

    .line 112
    .line 113
    new-instance v7, Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 116
    .line 117
    .line 118
    move-result v8

    .line 119
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 120
    .line 121
    .line 122
    move-object v8, v5

    .line 123
    check-cast v8, Ljava/util/Collection;

    .line 124
    .line 125
    invoke-interface {v8}, Ljava/util/Collection;->size()I

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    move v9, v12

    .line 130
    :goto_0
    if-ge v9, v8, :cond_1

    .line 131
    .line 132
    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v10

    .line 136
    check-cast v10, Lx10/e;

    .line 137
    .line 138
    iget-object v10, v10, Lx10/e;->a:Ljava/lang/String;

    .line 139
    .line 140
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    add-int/lit8 v9, v9, 0x1

    .line 144
    .line 145
    goto :goto_0

    .line 146
    :cond_1
    invoke-static {v7, v3, v12}, Lz10/a;->n(Ljava/util/ArrayList;Ll2/o;I)V

    .line 147
    .line 148
    .line 149
    invoke-interface {v1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v7

    .line 153
    check-cast v7, Ljava/lang/Boolean;

    .line 154
    .line 155
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 156
    .line 157
    .line 158
    move-result v7

    .line 159
    if-eqz v7, :cond_2

    .line 160
    .line 161
    const v0, 0x22bcf6e4

    .line 162
    .line 163
    .line 164
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 165
    .line 166
    .line 167
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v0

    .line 171
    check-cast v0, Lx10/e;

    .line 172
    .line 173
    iget-object v0, v0, Lx10/e;->b:Lx10/f;

    .line 174
    .line 175
    const/4 v2, 0x6

    .line 176
    invoke-static {v1, v0, v3, v2}, Lz10/a;->m(Ll2/b1;Lx10/f;Ll2/o;I)V

    .line 177
    .line 178
    .line 179
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 180
    .line 181
    .line 182
    goto :goto_2

    .line 183
    :cond_2
    const v7, 0x22c03215

    .line 184
    .line 185
    .line 186
    invoke-virtual {v3, v7}, Ll2/t;->Y(I)V

    .line 187
    .line 188
    .line 189
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object v7

    .line 193
    check-cast v7, Lx10/e;

    .line 194
    .line 195
    iget-object v7, v7, Lx10/e;->b:Lx10/f;

    .line 196
    .line 197
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 198
    .line 199
    .line 200
    move-result v7

    .line 201
    if-eqz v7, :cond_4

    .line 202
    .line 203
    if-ne v7, v4, :cond_3

    .line 204
    .line 205
    const v1, 0x6437e08a

    .line 206
    .line 207
    .line 208
    invoke-virtual {v3, v1}, Ll2/t;->Y(I)V

    .line 209
    .line 210
    .line 211
    invoke-static {v0, v14, v3, v12}, Lz10/a;->j(Lx10/a;Lp1/v;Ll2/o;I)V

    .line 212
    .line 213
    .line 214
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 215
    .line 216
    .line 217
    goto :goto_1

    .line 218
    :cond_3
    const v0, 0x6437bf8d

    .line 219
    .line 220
    .line 221
    invoke-static {v0, v3, v12}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    throw v0

    .line 226
    :cond_4
    const v0, 0x6437c805

    .line 227
    .line 228
    .line 229
    invoke-virtual {v3, v0}, Ll2/t;->Y(I)V

    .line 230
    .line 231
    .line 232
    invoke-interface {v5, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    check-cast v0, Lx10/e;

    .line 237
    .line 238
    invoke-static {v0, v1, v3, v6}, Lz10/a;->i(Lx10/e;Ll2/b1;Ll2/o;I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 242
    .line 243
    .line 244
    :goto_1
    invoke-virtual {v3, v12}, Ll2/t;->q(Z)V

    .line 245
    .line 246
    .line 247
    :goto_2
    return-object v13

    .line 248
    :pswitch_1
    check-cast v0, Lay0/o;

    .line 249
    .line 250
    check-cast v14, Lyj/b;

    .line 251
    .line 252
    move-object/from16 v1, p1

    .line 253
    .line 254
    check-cast v1, Lb1/n;

    .line 255
    .line 256
    move-object/from16 v2, p2

    .line 257
    .line 258
    check-cast v2, Lz9/k;

    .line 259
    .line 260
    move-object/from16 v3, p3

    .line 261
    .line 262
    check-cast v3, Ll2/o;

    .line 263
    .line 264
    move-object/from16 v4, p4

    .line 265
    .line 266
    check-cast v4, Ljava/lang/Integer;

    .line 267
    .line 268
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 269
    .line 270
    .line 271
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    invoke-interface {v0, v14, v3, v1}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    return-object v13

    .line 279
    :pswitch_2
    check-cast v0, Lzh/j;

    .line 280
    .line 281
    check-cast v14, Lay0/k;

    .line 282
    .line 283
    move-object/from16 v1, p1

    .line 284
    .line 285
    check-cast v1, Lp1/p;

    .line 286
    .line 287
    move-object/from16 v2, p2

    .line 288
    .line 289
    check-cast v2, Ljava/lang/Integer;

    .line 290
    .line 291
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 292
    .line 293
    .line 294
    move-result v2

    .line 295
    move-object/from16 v3, p3

    .line 296
    .line 297
    check-cast v3, Ll2/o;

    .line 298
    .line 299
    move-object/from16 v4, p4

    .line 300
    .line 301
    check-cast v4, Ljava/lang/Integer;

    .line 302
    .line 303
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 304
    .line 305
    .line 306
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    iget-object v0, v0, Lzh/j;->a:Ljava/util/ArrayList;

    .line 310
    .line 311
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    check-cast v0, Lzh/a;

    .line 316
    .line 317
    invoke-static {v0, v14, v3, v8}, Lwk/a;->s(Lzh/a;Lay0/k;Ll2/o;I)V

    .line 318
    .line 319
    .line 320
    return-object v13

    .line 321
    :pswitch_3
    check-cast v0, Lyj/b;

    .line 322
    .line 323
    check-cast v14, Lyj/b;

    .line 324
    .line 325
    move-object/from16 v1, p1

    .line 326
    .line 327
    check-cast v1, Lb1/n;

    .line 328
    .line 329
    move-object/from16 v2, p2

    .line 330
    .line 331
    check-cast v2, Lz9/k;

    .line 332
    .line 333
    move-object/from16 v3, p3

    .line 334
    .line 335
    check-cast v3, Ll2/o;

    .line 336
    .line 337
    move-object/from16 v4, p4

    .line 338
    .line 339
    check-cast v4, Ljava/lang/Integer;

    .line 340
    .line 341
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    invoke-static {v0, v14, v3, v12}, Lrp/d;->a(Lyj/b;Lyj/b;Ll2/o;I)V

    .line 345
    .line 346
    .line 347
    return-object v13

    .line 348
    :pswitch_4
    check-cast v0, Lxh/e;

    .line 349
    .line 350
    check-cast v14, Lxh/e;

    .line 351
    .line 352
    move-object/from16 v1, p1

    .line 353
    .line 354
    check-cast v1, Lb1/n;

    .line 355
    .line 356
    move-object/from16 v2, p2

    .line 357
    .line 358
    check-cast v2, Lz9/k;

    .line 359
    .line 360
    move-object/from16 v4, p3

    .line 361
    .line 362
    check-cast v4, Ll2/o;

    .line 363
    .line 364
    move-object/from16 v5, p4

    .line 365
    .line 366
    check-cast v5, Ljava/lang/Integer;

    .line 367
    .line 368
    invoke-static {v5, v1, v11, v2, v3}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 369
    .line 370
    .line 371
    iget-object v1, v2, Lz9/k;->l:Llx0/q;

    .line 372
    .line 373
    invoke-virtual {v1}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v1

    .line 377
    check-cast v1, Landroidx/lifecycle/s0;

    .line 378
    .line 379
    const-string v2, "navigation_result"

    .line 380
    .line 381
    invoke-virtual {v1, v2}, Landroidx/lifecycle/s0;->b(Ljava/lang/String;)Lyy0/l1;

    .line 382
    .line 383
    .line 384
    move-result-object v1

    .line 385
    invoke-static {v0, v14, v1, v4, v12}, Ljp/y0;->a(Lxh/e;Lxh/e;Lyy0/l1;Ll2/o;I)V

    .line 386
    .line 387
    .line 388
    return-object v13

    .line 389
    :pswitch_5
    check-cast v0, Lsg/o;

    .line 390
    .line 391
    check-cast v14, Lay0/k;

    .line 392
    .line 393
    move-object/from16 v1, p1

    .line 394
    .line 395
    check-cast v1, Lp1/p;

    .line 396
    .line 397
    move-object/from16 v2, p2

    .line 398
    .line 399
    check-cast v2, Ljava/lang/Integer;

    .line 400
    .line 401
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 402
    .line 403
    .line 404
    move-result v2

    .line 405
    move-object/from16 v3, p3

    .line 406
    .line 407
    check-cast v3, Ll2/o;

    .line 408
    .line 409
    move-object/from16 v4, p4

    .line 410
    .line 411
    check-cast v4, Ljava/lang/Integer;

    .line 412
    .line 413
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 417
    .line 418
    .line 419
    iget-object v0, v0, Lsg/o;->a:Ljava/util/ArrayList;

    .line 420
    .line 421
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v0

    .line 425
    check-cast v0, Lsg/f;

    .line 426
    .line 427
    invoke-static {v0, v14, v3, v8}, Luk/a;->b(Lsg/f;Lay0/k;Ll2/o;I)V

    .line 428
    .line 429
    .line 430
    return-object v13

    .line 431
    :pswitch_6
    check-cast v0, Lki/j;

    .line 432
    .line 433
    check-cast v14, Lxh/e;

    .line 434
    .line 435
    move-object/from16 v1, p1

    .line 436
    .line 437
    check-cast v1, Lb1/n;

    .line 438
    .line 439
    move-object/from16 v2, p2

    .line 440
    .line 441
    check-cast v2, Lz9/k;

    .line 442
    .line 443
    move-object/from16 v3, p3

    .line 444
    .line 445
    check-cast v3, Ll2/o;

    .line 446
    .line 447
    move-object/from16 v4, p4

    .line 448
    .line 449
    check-cast v4, Ljava/lang/Integer;

    .line 450
    .line 451
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 452
    .line 453
    .line 454
    sget-object v1, Lki/j;->Companion:Lki/d;

    .line 455
    .line 456
    invoke-static {v0, v14, v3, v8}, Lkp/w9;->a(Lki/j;Lxh/e;Ll2/o;I)V

    .line 457
    .line 458
    .line 459
    return-object v13

    .line 460
    :pswitch_7
    check-cast v0, Lt2/b;

    .line 461
    .line 462
    check-cast v14, Lyj/b;

    .line 463
    .line 464
    move-object/from16 v1, p1

    .line 465
    .line 466
    check-cast v1, Lb1/n;

    .line 467
    .line 468
    move-object/from16 v2, p2

    .line 469
    .line 470
    check-cast v2, Lz9/k;

    .line 471
    .line 472
    move-object/from16 v3, p3

    .line 473
    .line 474
    check-cast v3, Ll2/o;

    .line 475
    .line 476
    move-object/from16 v4, p4

    .line 477
    .line 478
    check-cast v4, Ljava/lang/Integer;

    .line 479
    .line 480
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 481
    .line 482
    .line 483
    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 484
    .line 485
    .line 486
    move-result-object v1

    .line 487
    invoke-virtual {v0, v14, v3, v1}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    return-object v13

    .line 491
    :pswitch_8
    check-cast v0, Lay0/a;

    .line 492
    .line 493
    check-cast v14, Lay0/n;

    .line 494
    .line 495
    move-object/from16 v1, p1

    .line 496
    .line 497
    check-cast v1, Lb1/n;

    .line 498
    .line 499
    move-object/from16 v4, p2

    .line 500
    .line 501
    check-cast v4, Lz9/k;

    .line 502
    .line 503
    move-object/from16 v8, p3

    .line 504
    .line 505
    check-cast v8, Ll2/o;

    .line 506
    .line 507
    move-object/from16 v9, p4

    .line 508
    .line 509
    check-cast v9, Ljava/lang/Integer;

    .line 510
    .line 511
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 512
    .line 513
    .line 514
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 515
    .line 516
    .line 517
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    const-string v1, "id"

    .line 521
    .line 522
    invoke-static {v4, v1}, Lzb/b;->t(Lz9/k;Ljava/lang/String;)Ljava/lang/String;

    .line 523
    .line 524
    .line 525
    move-result-object v1

    .line 526
    sget-object v3, Lw3/q1;->a:Ll2/u2;

    .line 527
    .line 528
    check-cast v8, Ll2/t;

    .line 529
    .line 530
    invoke-virtual {v8, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 531
    .line 532
    .line 533
    move-result-object v3

    .line 534
    check-cast v3, Ljava/lang/Boolean;

    .line 535
    .line 536
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 537
    .line 538
    .line 539
    move-result v3

    .line 540
    if-nez v3, :cond_5

    .line 541
    .line 542
    const v2, 0x671e003

    .line 543
    .line 544
    .line 545
    invoke-virtual {v8, v2}, Ll2/t;->Y(I)V

    .line 546
    .line 547
    .line 548
    sget-object v2, Lzb/x;->a:Ll2/u2;

    .line 549
    .line 550
    invoke-virtual {v8, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object v2

    .line 554
    check-cast v2, Lhi/a;

    .line 555
    .line 556
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 557
    .line 558
    .line 559
    goto :goto_3

    .line 560
    :cond_5
    const v4, -0x3835ad9f

    .line 561
    .line 562
    .line 563
    invoke-virtual {v8, v4}, Ll2/t;->Y(I)V

    .line 564
    .line 565
    .line 566
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 567
    .line 568
    .line 569
    const/4 v2, 0x0

    .line 570
    :goto_3
    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 571
    .line 572
    invoke-virtual {v8, v4}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v4

    .line 576
    check-cast v4, Landroid/content/Context;

    .line 577
    .line 578
    if-nez v3, :cond_b

    .line 579
    .line 580
    if-nez v2, :cond_6

    .line 581
    .line 582
    goto :goto_4

    .line 583
    :cond_6
    const v3, -0x3886f2fa

    .line 584
    .line 585
    .line 586
    invoke-virtual {v8, v3}, Ll2/t;->Y(I)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 590
    .line 591
    .line 592
    invoke-virtual {v8, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 593
    .line 594
    .line 595
    move-result v3

    .line 596
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 597
    .line 598
    .line 599
    move-result-object v5

    .line 600
    if-nez v3, :cond_7

    .line 601
    .line 602
    if-ne v5, v7, :cond_8

    .line 603
    .line 604
    :cond_7
    invoke-interface {v14, v2, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 605
    .line 606
    .line 607
    move-result-object v1

    .line 608
    move-object v5, v1

    .line 609
    check-cast v5, Lay0/k;

    .line 610
    .line 611
    invoke-virtual {v8, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 612
    .line 613
    .line 614
    :cond_8
    check-cast v5, Lay0/k;

    .line 615
    .line 616
    invoke-virtual {v8, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 617
    .line 618
    .line 619
    move-result v1

    .line 620
    invoke-virtual {v8, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 621
    .line 622
    .line 623
    move-result v2

    .line 624
    or-int/2addr v1, v2

    .line 625
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 626
    .line 627
    .line 628
    move-result-object v2

    .line 629
    if-nez v1, :cond_9

    .line 630
    .line 631
    if-ne v2, v7, :cond_a

    .line 632
    .line 633
    :cond_9
    new-instance v2, Lod0/n;

    .line 634
    .line 635
    const/16 v1, 0x9

    .line 636
    .line 637
    invoke-direct {v2, v1, v4, v0}, Lod0/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 638
    .line 639
    .line 640
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 641
    .line 642
    .line 643
    :cond_a
    check-cast v2, Lay0/k;

    .line 644
    .line 645
    invoke-static {v5, v2, v8, v12}, Ljp/kd;->b(Lay0/k;Lay0/k;Ll2/o;I)V

    .line 646
    .line 647
    .line 648
    goto :goto_5

    .line 649
    :cond_b
    :goto_4
    const v0, -0x38340fd7

    .line 650
    .line 651
    .line 652
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 653
    .line 654
    .line 655
    invoke-static {v8}, Lzb/b;->u(Ll2/o;)Lzb/j;

    .line 656
    .line 657
    .line 658
    move-result-object v0

    .line 659
    new-instance v1, Llc/q;

    .line 660
    .line 661
    sget-object v2, Llc/a;->c:Llc/c;

    .line 662
    .line 663
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 664
    .line 665
    .line 666
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object v2

    .line 670
    if-ne v2, v7, :cond_c

    .line 671
    .line 672
    new-instance v2, Lz81/g;

    .line 673
    .line 674
    invoke-direct {v2, v5}, Lz81/g;-><init>(I)V

    .line 675
    .line 676
    .line 677
    invoke-virtual {v8, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 678
    .line 679
    .line 680
    :cond_c
    check-cast v2, Lay0/a;

    .line 681
    .line 682
    invoke-interface {v0, v1, v2, v8, v6}, Lzb/j;->E0(Llc/q;Lay0/a;Ll2/o;I)V

    .line 683
    .line 684
    .line 685
    invoke-virtual {v8, v12}, Ll2/t;->q(Z)V

    .line 686
    .line 687
    .line 688
    :goto_5
    return-object v13

    .line 689
    :pswitch_9
    check-cast v0, Lm70/g0;

    .line 690
    .line 691
    move-object/from16 v20, v14

    .line 692
    .line 693
    check-cast v20, Lay0/k;

    .line 694
    .line 695
    move-object/from16 v1, p1

    .line 696
    .line 697
    check-cast v1, Lp1/p;

    .line 698
    .line 699
    move-object/from16 v2, p2

    .line 700
    .line 701
    check-cast v2, Ljava/lang/Integer;

    .line 702
    .line 703
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 704
    .line 705
    .line 706
    move-result v2

    .line 707
    move-object/from16 v22, p3

    .line 708
    .line 709
    check-cast v22, Ll2/o;

    .line 710
    .line 711
    move-object/from16 v3, p4

    .line 712
    .line 713
    check-cast v3, Ljava/lang/Integer;

    .line 714
    .line 715
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 716
    .line 717
    .line 718
    invoke-static {v1, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    new-instance v1, Ll70/y;

    .line 722
    .line 723
    iget-object v3, v0, Lm70/g0;->s:Ll70/v;

    .line 724
    .line 725
    iget-object v3, v3, Ll70/v;->a:Ll70/w;

    .line 726
    .line 727
    invoke-direct {v1, v3, v2}, Ll70/y;-><init>(Ll70/w;I)V

    .line 728
    .line 729
    .line 730
    new-instance v3, Ll70/y;

    .line 731
    .line 732
    iget-object v4, v0, Lm70/g0;->s:Ll70/v;

    .line 733
    .line 734
    iget-object v4, v4, Ll70/v;->a:Ll70/w;

    .line 735
    .line 736
    invoke-direct {v3, v4, v2}, Ll70/y;-><init>(Ll70/w;I)V

    .line 737
    .line 738
    .line 739
    iget-object v2, v0, Lm70/g0;->b:Ljava/util/Map;

    .line 740
    .line 741
    invoke-interface {v2, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 742
    .line 743
    .line 744
    move-result-object v1

    .line 745
    move-object/from16 v17, v1

    .line 746
    .line 747
    check-cast v17, Lne0/s;

    .line 748
    .line 749
    iget-object v1, v0, Lm70/g0;->f:Ljava/lang/Integer;

    .line 750
    .line 751
    iget-object v2, v0, Lm70/g0;->h:Lm70/f0;

    .line 752
    .line 753
    iget-object v2, v2, Lm70/f0;->c:Ll70/s;

    .line 754
    .line 755
    iget-object v2, v2, Ll70/s;->a:Ll70/q;

    .line 756
    .line 757
    const/high16 v4, 0x3f800000    # 1.0f

    .line 758
    .line 759
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 760
    .line 761
    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 762
    .line 763
    .line 764
    move-result-object v4

    .line 765
    sget-object v6, Lj91/a;->a:Ll2/u2;

    .line 766
    .line 767
    move-object/from16 v7, v22

    .line 768
    .line 769
    check-cast v7, Ll2/t;

    .line 770
    .line 771
    invoke-virtual {v7, v6}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 772
    .line 773
    .line 774
    move-result-object v6

    .line 775
    check-cast v6, Lj91/c;

    .line 776
    .line 777
    iget v6, v6, Lj91/c;->d:F

    .line 778
    .line 779
    const/4 v7, 0x0

    .line 780
    invoke-static {v4, v6, v7, v5}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 781
    .line 782
    .line 783
    move-result-object v15

    .line 784
    iget-boolean v0, v0, Lm70/g0;->i:Z

    .line 785
    .line 786
    const/16 v23, 0x0

    .line 787
    .line 788
    move/from16 v21, v0

    .line 789
    .line 790
    move-object/from16 v18, v1

    .line 791
    .line 792
    move-object/from16 v19, v2

    .line 793
    .line 794
    move-object/from16 v16, v3

    .line 795
    .line 796
    invoke-static/range {v15 .. v23}, Ln70/a;->X(Lx2/s;Ll70/y;Lne0/s;Ljava/lang/Integer;Ll70/q;Lay0/k;ZLl2/o;I)V

    .line 797
    .line 798
    .line 799
    return-object v13

    .line 800
    :pswitch_a
    check-cast v0, Lay0/a;

    .line 801
    .line 802
    check-cast v14, Ll2/b1;

    .line 803
    .line 804
    move-object/from16 v1, p1

    .line 805
    .line 806
    check-cast v1, Lb1/n;

    .line 807
    .line 808
    move-object/from16 v2, p2

    .line 809
    .line 810
    check-cast v2, Lz9/k;

    .line 811
    .line 812
    move-object/from16 v3, p3

    .line 813
    .line 814
    check-cast v3, Ll2/o;

    .line 815
    .line 816
    move-object/from16 v4, p4

    .line 817
    .line 818
    check-cast v4, Ljava/lang/Integer;

    .line 819
    .line 820
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 821
    .line 822
    .line 823
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 824
    .line 825
    .line 826
    move-result-object v1

    .line 827
    check-cast v1, Lpe/b;

    .line 828
    .line 829
    invoke-static {v1, v0, v3, v12}, Ljp/sb;->b(Lpe/b;Lay0/a;Ll2/o;I)V

    .line 830
    .line 831
    .line 832
    return-object v13

    .line 833
    :pswitch_b
    check-cast v0, Lyj/b;

    .line 834
    .line 835
    check-cast v14, Ly1/i;

    .line 836
    .line 837
    move-object/from16 v1, p1

    .line 838
    .line 839
    check-cast v1, Lb1/n;

    .line 840
    .line 841
    move-object/from16 v2, p2

    .line 842
    .line 843
    check-cast v2, Lz9/k;

    .line 844
    .line 845
    move-object/from16 v3, p3

    .line 846
    .line 847
    check-cast v3, Ll2/o;

    .line 848
    .line 849
    move-object/from16 v4, p4

    .line 850
    .line 851
    check-cast v4, Ljava/lang/Integer;

    .line 852
    .line 853
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 854
    .line 855
    .line 856
    invoke-static {v0, v14, v3, v12}, Landroidx/datastore/preferences/protobuf/o1;->c(Lyj/b;Ly1/i;Ll2/o;I)V

    .line 857
    .line 858
    .line 859
    return-object v13

    .line 860
    :pswitch_c
    check-cast v0, Ly1/i;

    .line 861
    .line 862
    check-cast v14, Ll2/b1;

    .line 863
    .line 864
    move-object/from16 v1, p1

    .line 865
    .line 866
    check-cast v1, Lb1/n;

    .line 867
    .line 868
    move-object/from16 v2, p2

    .line 869
    .line 870
    check-cast v2, Lz9/k;

    .line 871
    .line 872
    move-object/from16 v3, p3

    .line 873
    .line 874
    check-cast v3, Ll2/o;

    .line 875
    .line 876
    move-object/from16 v4, p4

    .line 877
    .line 878
    check-cast v4, Ljava/lang/Integer;

    .line 879
    .line 880
    invoke-static {v4, v1, v11, v2, v10}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 881
    .line 882
    .line 883
    invoke-interface {v14}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 884
    .line 885
    .line 886
    move-result-object v1

    .line 887
    check-cast v1, Lzg/h;

    .line 888
    .line 889
    invoke-static {v0, v1, v3, v12}, Ljp/ld;->a(Ly1/i;Lzg/h;Ll2/o;I)V

    .line 890
    .line 891
    .line 892
    return-object v13

    .line 893
    :pswitch_d
    check-cast v0, Lrh/s;

    .line 894
    .line 895
    check-cast v14, Lay0/k;

    .line 896
    .line 897
    move-object/from16 v1, p1

    .line 898
    .line 899
    check-cast v1, Lrh/d;

    .line 900
    .line 901
    move-object/from16 v3, p2

    .line 902
    .line 903
    check-cast v3, Ljava/lang/Integer;

    .line 904
    .line 905
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 906
    .line 907
    .line 908
    move-result v3

    .line 909
    move-object/from16 v9, p3

    .line 910
    .line 911
    check-cast v9, Ll2/o;

    .line 912
    .line 913
    move-object/from16 v10, p4

    .line 914
    .line 915
    check-cast v10, Ljava/lang/Integer;

    .line 916
    .line 917
    invoke-virtual {v10}, Ljava/lang/Integer;->intValue()I

    .line 918
    .line 919
    .line 920
    move-result v10

    .line 921
    const-string v11, "field"

    .line 922
    .line 923
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 924
    .line 925
    .line 926
    and-int/lit8 v11, v10, 0x6

    .line 927
    .line 928
    const/4 v15, 0x4

    .line 929
    if-nez v11, :cond_f

    .line 930
    .line 931
    and-int/lit8 v11, v10, 0x8

    .line 932
    .line 933
    if-nez v11, :cond_d

    .line 934
    .line 935
    move-object v11, v9

    .line 936
    check-cast v11, Ll2/t;

    .line 937
    .line 938
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 939
    .line 940
    .line 941
    move-result v11

    .line 942
    goto :goto_6

    .line 943
    :cond_d
    move-object v11, v9

    .line 944
    check-cast v11, Ll2/t;

    .line 945
    .line 946
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 947
    .line 948
    .line 949
    move-result v11

    .line 950
    :goto_6
    if-eqz v11, :cond_e

    .line 951
    .line 952
    move v5, v15

    .line 953
    :cond_e
    or-int/2addr v5, v10

    .line 954
    goto :goto_7

    .line 955
    :cond_f
    move v5, v10

    .line 956
    :goto_7
    and-int/2addr v6, v10

    .line 957
    if-nez v6, :cond_11

    .line 958
    .line 959
    move-object v6, v9

    .line 960
    check-cast v6, Ll2/t;

    .line 961
    .line 962
    invoke-virtual {v6, v3}, Ll2/t;->e(I)Z

    .line 963
    .line 964
    .line 965
    move-result v6

    .line 966
    if-eqz v6, :cond_10

    .line 967
    .line 968
    const/16 v6, 0x20

    .line 969
    .line 970
    goto :goto_8

    .line 971
    :cond_10
    const/16 v6, 0x10

    .line 972
    .line 973
    :goto_8
    or-int/2addr v5, v6

    .line 974
    :cond_11
    and-int/lit16 v6, v5, 0x93

    .line 975
    .line 976
    const/16 v10, 0x92

    .line 977
    .line 978
    if-eq v6, v10, :cond_12

    .line 979
    .line 980
    move v6, v4

    .line 981
    goto :goto_9

    .line 982
    :cond_12
    move v6, v12

    .line 983
    :goto_9
    and-int/lit8 v10, v5, 0x1

    .line 984
    .line 985
    check-cast v9, Ll2/t;

    .line 986
    .line 987
    invoke-virtual {v9, v10, v6}, Ll2/t;->O(IZ)Z

    .line 988
    .line 989
    .line 990
    move-result v6

    .line 991
    if-eqz v6, :cond_1b

    .line 992
    .line 993
    iget-object v6, v1, Lrh/d;->c:Ljava/lang/String;

    .line 994
    .line 995
    iget-object v10, v1, Lrh/d;->b:Ljava/lang/String;

    .line 996
    .line 997
    iget-object v11, v1, Lrh/d;->f:Ljava/lang/String;

    .line 998
    .line 999
    iget-boolean v2, v1, Lrh/d;->d:Z

    .line 1000
    .line 1001
    if-eqz v2, :cond_13

    .line 1002
    .line 1003
    move-object/from16 v18, v11

    .line 1004
    .line 1005
    goto :goto_a

    .line 1006
    :cond_13
    const/16 v18, 0x0

    .line 1007
    .line 1008
    :goto_a
    iget-object v0, v0, Lrh/s;->a:Ljava/util/List;

    .line 1009
    .line 1010
    invoke-static {v0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 1011
    .line 1012
    .line 1013
    move-result v0

    .line 1014
    if-eq v3, v0, :cond_14

    .line 1015
    .line 1016
    move/from16 v21, v4

    .line 1017
    .line 1018
    goto :goto_b

    .line 1019
    :cond_14
    move/from16 v21, v12

    .line 1020
    .line 1021
    :goto_b
    iget-object v0, v1, Lrh/d;->h:Lrh/c;

    .line 1022
    .line 1023
    instance-of v0, v0, Lrh/b;

    .line 1024
    .line 1025
    const-string v2, "wallbox_onboarding_configuration_component_"

    .line 1026
    .line 1027
    invoke-static {v3, v2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v23

    .line 1031
    invoke-virtual {v9, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1032
    .line 1033
    .line 1034
    move-result v2

    .line 1035
    and-int/lit8 v3, v5, 0xe

    .line 1036
    .line 1037
    if-eq v3, v15, :cond_16

    .line 1038
    .line 1039
    and-int/lit8 v3, v5, 0x8

    .line 1040
    .line 1041
    if-eqz v3, :cond_15

    .line 1042
    .line 1043
    invoke-virtual {v9, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 1044
    .line 1045
    .line 1046
    move-result v3

    .line 1047
    if-eqz v3, :cond_15

    .line 1048
    .line 1049
    goto :goto_c

    .line 1050
    :cond_15
    move v4, v12

    .line 1051
    :cond_16
    :goto_c
    or-int/2addr v2, v4

    .line 1052
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v3

    .line 1056
    if-nez v2, :cond_17

    .line 1057
    .line 1058
    if-ne v3, v7, :cond_18

    .line 1059
    .line 1060
    :cond_17
    new-instance v3, Laa/z;

    .line 1061
    .line 1062
    const/16 v2, 0x15

    .line 1063
    .line 1064
    invoke-direct {v3, v2, v14, v1}, Laa/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1065
    .line 1066
    .line 1067
    invoke-virtual {v9, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1068
    .line 1069
    .line 1070
    :cond_18
    move-object/from16 v19, v3

    .line 1071
    .line 1072
    check-cast v19, Lay0/k;

    .line 1073
    .line 1074
    invoke-virtual {v9, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 1075
    .line 1076
    .line 1077
    move-result v1

    .line 1078
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 1079
    .line 1080
    .line 1081
    move-result-object v2

    .line 1082
    if-nez v1, :cond_19

    .line 1083
    .line 1084
    if-ne v2, v7, :cond_1a

    .line 1085
    .line 1086
    :cond_19
    new-instance v2, Lak/n;

    .line 1087
    .line 1088
    const/16 v1, 0x1c

    .line 1089
    .line 1090
    invoke-direct {v2, v1, v14}, Lak/n;-><init>(ILay0/k;)V

    .line 1091
    .line 1092
    .line 1093
    invoke-virtual {v9, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 1094
    .line 1095
    .line 1096
    :cond_1a
    move-object/from16 v20, v2

    .line 1097
    .line 1098
    check-cast v20, Lay0/a;

    .line 1099
    .line 1100
    const/16 v25, 0x0

    .line 1101
    .line 1102
    move/from16 v22, v0

    .line 1103
    .line 1104
    move-object/from16 v16, v6

    .line 1105
    .line 1106
    move-object/from16 v24, v9

    .line 1107
    .line 1108
    move-object/from16 v17, v10

    .line 1109
    .line 1110
    invoke-static/range {v16 .. v25}, Ldl/a;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;Lay0/a;ZZLjava/lang/String;Ll2/o;I)V

    .line 1111
    .line 1112
    .line 1113
    goto :goto_d

    .line 1114
    :cond_1b
    move-object/from16 v24, v9

    .line 1115
    .line 1116
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 1117
    .line 1118
    .line 1119
    :goto_d
    return-object v13

    .line 1120
    nop

    .line 1121
    :pswitch_data_0
    .packed-switch 0x0
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
