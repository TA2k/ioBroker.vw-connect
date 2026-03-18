.class public final Ltv/j;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Ltv/j;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltv/j;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p2, p0, Ltv/j;->h:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p3, p0, Ltv/j;->i:Ljava/lang/Object;

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 33

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ltv/j;->f:I

    .line 4
    .line 5
    iget-object v3, v0, Ltv/j;->i:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v4, v0, Ltv/j;->h:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v0, v0, Ltv/j;->g:Ljava/lang/Object;

    .line 10
    .line 11
    packed-switch v1, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    check-cast v0, Ljava/util/List;

    .line 15
    .line 16
    check-cast v4, Lz4/m;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    const/4 v6, 0x0

    .line 23
    :goto_0
    if-ge v6, v1, :cond_2

    .line 24
    .line 25
    invoke-interface {v0, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v7

    .line 29
    check-cast v7, Lt3/p0;

    .line 30
    .line 31
    invoke-interface {v7}, Lt3/p0;->l()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v7

    .line 35
    instance-of v8, v7, Lz4/i;

    .line 36
    .line 37
    if-eqz v8, :cond_0

    .line 38
    .line 39
    check-cast v7, Lz4/i;

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_0
    const/4 v7, 0x0

    .line 43
    :goto_1
    if-eqz v7, :cond_1

    .line 44
    .line 45
    iget-object v8, v7, Lz4/i;->d:Lz4/f;

    .line 46
    .line 47
    iget-object v9, v4, Lz4/m;->d:Lz4/k;

    .line 48
    .line 49
    invoke-virtual {v9, v8}, Lz4/k;->a(Lz4/o;)Ld5/f;

    .line 50
    .line 51
    .line 52
    move-result-object v9

    .line 53
    new-instance v10, Lz4/e;

    .line 54
    .line 55
    iget-object v8, v8, Lz4/f;->c:Ljava/lang/Object;

    .line 56
    .line 57
    invoke-direct {v10, v8, v9}, Lz4/e;-><init>(Ljava/lang/Object;Ld5/f;)V

    .line 58
    .line 59
    .line 60
    iget-object v8, v7, Lz4/i;->e:Lay0/k;

    .line 61
    .line 62
    invoke-interface {v8, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    :cond_1
    iget-object v8, v4, Lz4/m;->i:Ljava/util/ArrayList;

    .line 66
    .line 67
    invoke-virtual {v8, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    add-int/lit8 v6, v6, 0x1

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_2
    iget-object v0, v4, Lz4/m;->d:Lz4/k;

    .line 74
    .line 75
    check-cast v3, Lz4/q;

    .line 76
    .line 77
    iget-object v1, v0, Lz4/k;->a:Ld5/f;

    .line 78
    .line 79
    new-instance v4, Le5/f;

    .line 80
    .line 81
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 82
    .line 83
    .line 84
    new-instance v0, Ljava/util/HashMap;

    .line 85
    .line 86
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 87
    .line 88
    .line 89
    iput-object v0, v4, Le5/f;->a:Ljava/util/HashMap;

    .line 90
    .line 91
    new-instance v0, Ljava/util/HashMap;

    .line 92
    .line 93
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 94
    .line 95
    .line 96
    iput-object v0, v4, Le5/f;->b:Ljava/util/HashMap;

    .line 97
    .line 98
    new-instance v0, Ljava/util/HashMap;

    .line 99
    .line 100
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 101
    .line 102
    .line 103
    iput-object v0, v4, Le5/f;->c:Ljava/util/HashMap;

    .line 104
    .line 105
    invoke-virtual {v1}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v6

    .line 113
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-eqz v0, :cond_b1

    .line 118
    .line 119
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    move-object v7, v0

    .line 124
    check-cast v7, Ljava/lang/String;

    .line 125
    .line 126
    invoke-virtual {v1, v7}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v7}, Ljava/lang/String;->hashCode()I

    .line 134
    .line 135
    .line 136
    move-result v8

    .line 137
    sparse-switch v8, :sswitch_data_0

    .line 138
    .line 139
    .line 140
    :goto_3
    const/4 v8, -0x1

    .line 141
    goto :goto_4

    .line 142
    :sswitch_0
    const-string v8, "Variables"

    .line 143
    .line 144
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 145
    .line 146
    .line 147
    move-result v8

    .line 148
    if-nez v8, :cond_3

    .line 149
    .line 150
    goto :goto_3

    .line 151
    :cond_3
    const/4 v8, 0x2

    .line 152
    goto :goto_4

    .line 153
    :sswitch_1
    const-string v8, "Generate"

    .line 154
    .line 155
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    move-result v8

    .line 159
    if-nez v8, :cond_4

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_4
    const/4 v8, 0x1

    .line 163
    goto :goto_4

    .line 164
    :sswitch_2
    const-string v8, "Helpers"

    .line 165
    .line 166
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 167
    .line 168
    .line 169
    move-result v8

    .line 170
    if-nez v8, :cond_5

    .line 171
    .line 172
    goto :goto_3

    .line 173
    :cond_5
    const/4 v8, 0x0

    .line 174
    :goto_4
    const-string v14, ""

    .line 175
    .line 176
    packed-switch v8, :pswitch_data_1

    .line 177
    .line 178
    .line 179
    instance-of v8, v0, Ld5/f;

    .line 180
    .line 181
    if-eqz v8, :cond_96

    .line 182
    .line 183
    move-object v8, v0

    .line 184
    check-cast v8, Ld5/f;

    .line 185
    .line 186
    invoke-virtual {v8}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    :cond_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 195
    .line 196
    .line 197
    move-result v15

    .line 198
    if-eqz v15, :cond_7

    .line 199
    .line 200
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v15

    .line 204
    check-cast v15, Ljava/lang/String;

    .line 205
    .line 206
    const-string v2, "type"

    .line 207
    .line 208
    invoke-virtual {v15, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v15

    .line 212
    if-eqz v15, :cond_6

    .line 213
    .line 214
    invoke-virtual {v8, v2}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    goto :goto_5

    .line 219
    :cond_7
    const/4 v0, 0x0

    .line 220
    :goto_5
    if-eqz v0, :cond_94

    .line 221
    .line 222
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    sparse-switch v2, :sswitch_data_1

    .line 227
    .line 228
    .line 229
    :goto_6
    const/4 v2, -0x1

    .line 230
    goto/16 :goto_7

    .line 231
    .line 232
    :sswitch_3
    const-string v2, "hGuideline"

    .line 233
    .line 234
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v2

    .line 238
    if-nez v2, :cond_8

    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_8
    const/16 v2, 0x9

    .line 242
    .line 243
    goto/16 :goto_7

    .line 244
    .line 245
    :sswitch_4
    const-string v2, "vFlow"

    .line 246
    .line 247
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move-result v2

    .line 251
    if-nez v2, :cond_9

    .line 252
    .line 253
    goto :goto_6

    .line 254
    :cond_9
    const/16 v2, 0x8

    .line 255
    .line 256
    goto/16 :goto_7

    .line 257
    .line 258
    :sswitch_5
    const-string v2, "hFlow"

    .line 259
    .line 260
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 261
    .line 262
    .line 263
    move-result v2

    .line 264
    if-nez v2, :cond_a

    .line 265
    .line 266
    goto :goto_6

    .line 267
    :cond_a
    const/4 v2, 0x7

    .line 268
    goto :goto_7

    .line 269
    :sswitch_6
    const-string v2, "grid"

    .line 270
    .line 271
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 272
    .line 273
    .line 274
    move-result v2

    .line 275
    if-nez v2, :cond_b

    .line 276
    .line 277
    goto :goto_6

    .line 278
    :cond_b
    const/4 v2, 0x6

    .line 279
    goto :goto_7

    .line 280
    :sswitch_7
    const-string v2, "row"

    .line 281
    .line 282
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 283
    .line 284
    .line 285
    move-result v2

    .line 286
    if-nez v2, :cond_c

    .line 287
    .line 288
    goto :goto_6

    .line 289
    :cond_c
    const/4 v2, 0x5

    .line 290
    goto :goto_7

    .line 291
    :sswitch_8
    const-string v2, "barrier"

    .line 292
    .line 293
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 294
    .line 295
    .line 296
    move-result v2

    .line 297
    if-nez v2, :cond_d

    .line 298
    .line 299
    goto :goto_6

    .line 300
    :cond_d
    const/4 v2, 0x4

    .line 301
    goto :goto_7

    .line 302
    :sswitch_9
    const-string v2, "vChain"

    .line 303
    .line 304
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 305
    .line 306
    .line 307
    move-result v2

    .line 308
    if-nez v2, :cond_e

    .line 309
    .line 310
    goto :goto_6

    .line 311
    :cond_e
    const/4 v2, 0x3

    .line 312
    goto :goto_7

    .line 313
    :sswitch_a
    const-string v2, "hChain"

    .line 314
    .line 315
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    move-result v2

    .line 319
    if-nez v2, :cond_f

    .line 320
    .line 321
    goto :goto_6

    .line 322
    :cond_f
    const/4 v2, 0x2

    .line 323
    goto :goto_7

    .line 324
    :sswitch_b
    const-string v2, "column"

    .line 325
    .line 326
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 327
    .line 328
    .line 329
    move-result v2

    .line 330
    if-nez v2, :cond_10

    .line 331
    .line 332
    goto :goto_6

    .line 333
    :cond_10
    const/4 v2, 0x1

    .line 334
    goto :goto_7

    .line 335
    :sswitch_c
    const-string v2, "vGuideline"

    .line 336
    .line 337
    invoke-virtual {v0, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v2

    .line 341
    if-nez v2, :cond_11

    .line 342
    .line 343
    goto :goto_6

    .line 344
    :cond_11
    const/4 v2, 0x0

    .line 345
    :goto_7
    const-string v13, "start"

    .line 346
    .line 347
    const-string v12, "end"

    .line 348
    .line 349
    const-string v11, "top"

    .line 350
    .line 351
    const-string v10, "bottom"

    .line 352
    .line 353
    const-string v15, "contains"

    .line 354
    .line 355
    const-string v9, "\""

    .line 356
    .line 357
    const-string v5, " contains should be an array \""

    .line 358
    .line 359
    const/high16 v24, 0x7fc00000    # Float.NaN

    .line 360
    .line 361
    packed-switch v2, :pswitch_data_2

    .line 362
    .line 363
    .line 364
    :goto_8
    move-object/from16 v27, v1

    .line 365
    .line 366
    move-object v1, v4

    .line 367
    move-object/from16 v29, v6

    .line 368
    .line 369
    goto/16 :goto_48

    .line 370
    .line 371
    :pswitch_0
    const/4 v2, 0x0

    .line 372
    invoke-static {v2, v3, v7, v8}, Lkp/b0;->h(ILz4/q;Ljava/lang/String;Ld5/f;)V

    .line 373
    .line 374
    .line 375
    goto :goto_8

    .line 376
    :pswitch_1
    const/4 v2, 0x0

    .line 377
    const/high16 v25, 0x3f000000    # 0.5f

    .line 378
    .line 379
    invoke-static/range {v25 .. v25}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 380
    .line 381
    .line 382
    move-result-object v26

    .line 383
    invoke-virtual {v0, v2}, Ljava/lang/String;->charAt(I)C

    .line 384
    .line 385
    .line 386
    move-result v0

    .line 387
    const/16 v2, 0x76

    .line 388
    .line 389
    if-ne v0, v2, :cond_12

    .line 390
    .line 391
    const/4 v0, 0x1

    .line 392
    goto :goto_9

    .line 393
    :cond_12
    const/4 v0, 0x0

    .line 394
    :goto_9
    invoke-virtual {v3, v7}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 395
    .line 396
    .line 397
    move-result-object v2

    .line 398
    move/from16 v27, v0

    .line 399
    .line 400
    iget-object v0, v2, Le5/b;->c:Ljava/lang/Object;

    .line 401
    .line 402
    if-eqz v0, :cond_14

    .line 403
    .line 404
    instance-of v0, v0, Lf5/e;

    .line 405
    .line 406
    if-nez v0, :cond_13

    .line 407
    .line 408
    goto :goto_a

    .line 409
    :cond_13
    move-object/from16 v27, v1

    .line 410
    .line 411
    const/4 v1, 0x7

    .line 412
    goto :goto_c

    .line 413
    :cond_14
    :goto_a
    if-eqz v27, :cond_15

    .line 414
    .line 415
    new-instance v0, Lf5/e;

    .line 416
    .line 417
    move-object/from16 v27, v1

    .line 418
    .line 419
    const/16 v1, 0x8

    .line 420
    .line 421
    invoke-direct {v0, v3, v1}, Lf5/e;-><init>(Lz4/q;I)V

    .line 422
    .line 423
    .line 424
    const/4 v1, 0x7

    .line 425
    goto :goto_b

    .line 426
    :cond_15
    move-object/from16 v27, v1

    .line 427
    .line 428
    const/16 v1, 0x8

    .line 429
    .line 430
    new-instance v0, Lf5/e;

    .line 431
    .line 432
    const/4 v1, 0x7

    .line 433
    invoke-direct {v0, v3, v1}, Lf5/e;-><init>(Lz4/q;I)V

    .line 434
    .line 435
    .line 436
    :goto_b
    iput-object v0, v2, Le5/b;->c:Ljava/lang/Object;

    .line 437
    .line 438
    invoke-virtual {v0}, Le5/h;->b()Lh5/d;

    .line 439
    .line 440
    .line 441
    move-result-object v0

    .line 442
    invoke-virtual {v2, v0}, Le5/b;->a(Lh5/d;)V

    .line 443
    .line 444
    .line 445
    :goto_c
    iget-object v0, v2, Le5/b;->c:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast v0, Lf5/e;

    .line 448
    .line 449
    invoke-virtual {v8}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 450
    .line 451
    .line 452
    move-result-object v2

    .line 453
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 454
    .line 455
    .line 456
    move-result-object v2

    .line 457
    :goto_d
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 458
    .line 459
    .line 460
    move-result v22

    .line 461
    if-eqz v22, :cond_4a

    .line 462
    .line 463
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v22

    .line 467
    move-object/from16 v1, v22

    .line 468
    .line 469
    check-cast v1, Ljava/lang/String;

    .line 470
    .line 471
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 472
    .line 473
    .line 474
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 475
    .line 476
    .line 477
    move-result v22

    .line 478
    sparse-switch v22, :sswitch_data_2

    .line 479
    .line 480
    .line 481
    move-object/from16 v22, v2

    .line 482
    .line 483
    :goto_e
    const/4 v2, -0x1

    .line 484
    goto/16 :goto_10

    .line 485
    .line 486
    :sswitch_d
    move-object/from16 v22, v2

    .line 487
    .line 488
    const-string v2, "wrap"

    .line 489
    .line 490
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 491
    .line 492
    .line 493
    move-result v2

    .line 494
    if-nez v2, :cond_16

    .line 495
    .line 496
    goto/16 :goto_f

    .line 497
    .line 498
    :cond_16
    const/16 v2, 0xc

    .line 499
    .line 500
    goto/16 :goto_10

    .line 501
    .line 502
    :sswitch_e
    move-object/from16 v22, v2

    .line 503
    .line 504
    const-string v2, "vGap"

    .line 505
    .line 506
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 507
    .line 508
    .line 509
    move-result v2

    .line 510
    if-nez v2, :cond_17

    .line 511
    .line 512
    goto/16 :goto_f

    .line 513
    .line 514
    :cond_17
    const/16 v2, 0xb

    .line 515
    .line 516
    goto/16 :goto_10

    .line 517
    .line 518
    :sswitch_f
    move-object/from16 v22, v2

    .line 519
    .line 520
    const-string v2, "type"

    .line 521
    .line 522
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 523
    .line 524
    .line 525
    move-result v2

    .line 526
    if-nez v2, :cond_18

    .line 527
    .line 528
    goto/16 :goto_f

    .line 529
    .line 530
    :cond_18
    const/16 v2, 0xa

    .line 531
    .line 532
    goto/16 :goto_10

    .line 533
    .line 534
    :sswitch_10
    move-object/from16 v22, v2

    .line 535
    .line 536
    const-string v2, "hGap"

    .line 537
    .line 538
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 539
    .line 540
    .line 541
    move-result v2

    .line 542
    if-nez v2, :cond_19

    .line 543
    .line 544
    goto/16 :goto_f

    .line 545
    .line 546
    :cond_19
    const/16 v2, 0x9

    .line 547
    .line 548
    goto/16 :goto_10

    .line 549
    .line 550
    :sswitch_11
    move-object/from16 v22, v2

    .line 551
    .line 552
    const-string v2, "maxElement"

    .line 553
    .line 554
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 555
    .line 556
    .line 557
    move-result v2

    .line 558
    if-nez v2, :cond_1a

    .line 559
    .line 560
    goto/16 :goto_f

    .line 561
    .line 562
    :cond_1a
    const/16 v2, 0x8

    .line 563
    .line 564
    goto/16 :goto_10

    .line 565
    .line 566
    :sswitch_12
    move-object/from16 v22, v2

    .line 567
    .line 568
    invoke-virtual {v1, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 569
    .line 570
    .line 571
    move-result v2

    .line 572
    if-nez v2, :cond_1b

    .line 573
    .line 574
    goto/16 :goto_f

    .line 575
    .line 576
    :cond_1b
    const/4 v2, 0x7

    .line 577
    goto/16 :goto_10

    .line 578
    .line 579
    :sswitch_13
    move-object/from16 v22, v2

    .line 580
    .line 581
    const-string v2, "vFlowBias"

    .line 582
    .line 583
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 584
    .line 585
    .line 586
    move-result v2

    .line 587
    if-nez v2, :cond_1c

    .line 588
    .line 589
    goto :goto_f

    .line 590
    :cond_1c
    const/4 v2, 0x6

    .line 591
    goto :goto_10

    .line 592
    :sswitch_14
    move-object/from16 v22, v2

    .line 593
    .line 594
    const-string v2, "padding"

    .line 595
    .line 596
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 597
    .line 598
    .line 599
    move-result v2

    .line 600
    if-nez v2, :cond_1d

    .line 601
    .line 602
    goto :goto_f

    .line 603
    :cond_1d
    const/4 v2, 0x5

    .line 604
    goto :goto_10

    .line 605
    :sswitch_15
    move-object/from16 v22, v2

    .line 606
    .line 607
    const-string v2, "vStyle"

    .line 608
    .line 609
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 610
    .line 611
    .line 612
    move-result v2

    .line 613
    if-nez v2, :cond_1e

    .line 614
    .line 615
    goto :goto_f

    .line 616
    :cond_1e
    const/4 v2, 0x4

    .line 617
    goto :goto_10

    .line 618
    :sswitch_16
    move-object/from16 v22, v2

    .line 619
    .line 620
    const-string v2, "vAlign"

    .line 621
    .line 622
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 623
    .line 624
    .line 625
    move-result v2

    .line 626
    if-nez v2, :cond_1f

    .line 627
    .line 628
    goto :goto_f

    .line 629
    :cond_1f
    const/4 v2, 0x3

    .line 630
    goto :goto_10

    .line 631
    :sswitch_17
    move-object/from16 v22, v2

    .line 632
    .line 633
    const-string v2, "hFlowBias"

    .line 634
    .line 635
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 636
    .line 637
    .line 638
    move-result v2

    .line 639
    if-nez v2, :cond_20

    .line 640
    .line 641
    goto :goto_f

    .line 642
    :cond_20
    const/4 v2, 0x2

    .line 643
    goto :goto_10

    .line 644
    :sswitch_18
    move-object/from16 v22, v2

    .line 645
    .line 646
    const-string v2, "hStyle"

    .line 647
    .line 648
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 649
    .line 650
    .line 651
    move-result v2

    .line 652
    if-nez v2, :cond_21

    .line 653
    .line 654
    goto :goto_f

    .line 655
    :cond_21
    const/4 v2, 0x1

    .line 656
    goto :goto_10

    .line 657
    :sswitch_19
    move-object/from16 v22, v2

    .line 658
    .line 659
    const-string v2, "hAlign"

    .line 660
    .line 661
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 662
    .line 663
    .line 664
    move-result v2

    .line 665
    if-nez v2, :cond_22

    .line 666
    .line 667
    :goto_f
    goto/16 :goto_e

    .line 668
    .line 669
    :cond_22
    const/4 v2, 0x0

    .line 670
    :goto_10
    packed-switch v2, :pswitch_data_3

    .line 671
    .line 672
    .line 673
    invoke-virtual {v3, v7}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 674
    .line 675
    .line 676
    move-result-object v2

    .line 677
    invoke-static {v8, v2, v4, v1, v3}, Lkp/b0;->c(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 678
    .line 679
    .line 680
    :goto_11
    move-object/from16 v31, v4

    .line 681
    .line 682
    move-object/from16 v29, v6

    .line 683
    .line 684
    :catch_0
    :cond_23
    :goto_12
    move-object/from16 v28, v9

    .line 685
    .line 686
    goto/16 :goto_23

    .line 687
    .line 688
    :pswitch_2
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 689
    .line 690
    .line 691
    move-result-object v1

    .line 692
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 693
    .line 694
    .line 695
    move-result-object v1

    .line 696
    sget-object v2, Le5/k;->d:Ljava/util/HashMap;

    .line 697
    .line 698
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 699
    .line 700
    .line 701
    move-result v28

    .line 702
    if-eqz v28, :cond_24

    .line 703
    .line 704
    invoke-virtual {v2, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 705
    .line 706
    .line 707
    move-result-object v1

    .line 708
    check-cast v1, Ljava/lang/Integer;

    .line 709
    .line 710
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 711
    .line 712
    .line 713
    move-result v1

    .line 714
    goto :goto_13

    .line 715
    :cond_24
    const/4 v1, -0x1

    .line 716
    :goto_13
    iput v1, v0, Lf5/e;->r0:I

    .line 717
    .line 718
    goto :goto_11

    .line 719
    :pswitch_3
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 720
    .line 721
    .line 722
    move-result-object v1

    .line 723
    invoke-virtual {v1}, Ld5/c;->k()I

    .line 724
    .line 725
    .line 726
    move-result v1

    .line 727
    iput v1, v0, Lf5/e;->A0:I

    .line 728
    .line 729
    goto :goto_11

    .line 730
    :pswitch_4
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 731
    .line 732
    .line 733
    move-result-object v1

    .line 734
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 735
    .line 736
    .line 737
    move-result-object v1

    .line 738
    const-string v2, "hFlow"

    .line 739
    .line 740
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 741
    .line 742
    .line 743
    move-result v1

    .line 744
    if-eqz v1, :cond_25

    .line 745
    .line 746
    const/4 v2, 0x0

    .line 747
    iput v2, v0, Lf5/e;->H0:I

    .line 748
    .line 749
    goto :goto_11

    .line 750
    :cond_25
    const/4 v1, 0x1

    .line 751
    iput v1, v0, Lf5/e;->H0:I

    .line 752
    .line 753
    goto :goto_11

    .line 754
    :pswitch_5
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 755
    .line 756
    .line 757
    move-result-object v1

    .line 758
    invoke-virtual {v1}, Ld5/c;->k()I

    .line 759
    .line 760
    .line 761
    move-result v1

    .line 762
    iput v1, v0, Lf5/e;->B0:I

    .line 763
    .line 764
    goto :goto_11

    .line 765
    :pswitch_6
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 766
    .line 767
    .line 768
    move-result-object v1

    .line 769
    invoke-virtual {v1}, Ld5/c;->k()I

    .line 770
    .line 771
    .line 772
    move-result v1

    .line 773
    iput v1, v0, Lf5/e;->G0:I

    .line 774
    .line 775
    goto :goto_11

    .line 776
    :pswitch_7
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 777
    .line 778
    .line 779
    move-result-object v1

    .line 780
    instance-of v2, v1, Ld5/a;

    .line 781
    .line 782
    if-eqz v2, :cond_33

    .line 783
    .line 784
    move-object v2, v1

    .line 785
    check-cast v2, Ld5/a;

    .line 786
    .line 787
    move-object/from16 v28, v1

    .line 788
    .line 789
    iget-object v1, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 790
    .line 791
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 792
    .line 793
    .line 794
    move-result v1

    .line 795
    move-object/from16 v29, v6

    .line 796
    .line 797
    const/4 v6, 0x1

    .line 798
    if-ge v1, v6, :cond_26

    .line 799
    .line 800
    :goto_14
    move-object/from16 v31, v4

    .line 801
    .line 802
    goto/16 :goto_19

    .line 803
    .line 804
    :cond_26
    const/4 v1, 0x0

    .line 805
    :goto_15
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 806
    .line 807
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 808
    .line 809
    .line 810
    move-result v6

    .line 811
    if-ge v1, v6, :cond_32

    .line 812
    .line 813
    invoke-virtual {v2, v1}, Ld5/b;->r(I)Ld5/c;

    .line 814
    .line 815
    .line 816
    move-result-object v6

    .line 817
    move/from16 v28, v1

    .line 818
    .line 819
    instance-of v1, v6, Ld5/a;

    .line 820
    .line 821
    if-eqz v1, :cond_30

    .line 822
    .line 823
    check-cast v6, Ld5/a;

    .line 824
    .line 825
    iget-object v1, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 826
    .line 827
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 828
    .line 829
    .line 830
    move-result v1

    .line 831
    if-lez v1, :cond_2f

    .line 832
    .line 833
    const/4 v1, 0x0

    .line 834
    invoke-virtual {v6, v1}, Ld5/b;->r(I)Ld5/c;

    .line 835
    .line 836
    .line 837
    move-result-object v30

    .line 838
    invoke-virtual/range {v30 .. v30}, Ld5/c;->e()Ljava/lang/String;

    .line 839
    .line 840
    .line 841
    move-result-object v1

    .line 842
    move-object/from16 v30, v2

    .line 843
    .line 844
    iget-object v2, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 845
    .line 846
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 847
    .line 848
    .line 849
    move-result v2

    .line 850
    move-object/from16 v31, v4

    .line 851
    .line 852
    const/4 v4, 0x2

    .line 853
    if-eq v2, v4, :cond_29

    .line 854
    .line 855
    const/4 v4, 0x3

    .line 856
    if-eq v2, v4, :cond_28

    .line 857
    .line 858
    const/4 v4, 0x4

    .line 859
    if-eq v2, v4, :cond_27

    .line 860
    .line 861
    move/from16 v4, v24

    .line 862
    .line 863
    move v6, v4

    .line 864
    :goto_16
    move/from16 v32, v6

    .line 865
    .line 866
    goto :goto_17

    .line 867
    :cond_27
    const/4 v2, 0x1

    .line 868
    invoke-virtual {v6, v2}, Ld5/b;->t(I)F

    .line 869
    .line 870
    .line 871
    move-result v4

    .line 872
    move/from16 v20, v4

    .line 873
    .line 874
    const/4 v2, 0x2

    .line 875
    invoke-virtual {v6, v2}, Ld5/b;->t(I)F

    .line 876
    .line 877
    .line 878
    move-result v4

    .line 879
    iget-object v2, v3, Lz4/q;->a:Lrx/b;

    .line 880
    .line 881
    invoke-virtual {v2, v4}, Lrx/b;->e(F)F

    .line 882
    .line 883
    .line 884
    move-result v2

    .line 885
    const/4 v4, 0x3

    .line 886
    invoke-virtual {v6, v4}, Ld5/b;->t(I)F

    .line 887
    .line 888
    .line 889
    move-result v6

    .line 890
    iget-object v4, v3, Lz4/q;->a:Lrx/b;

    .line 891
    .line 892
    invoke-virtual {v4, v6}, Lrx/b;->e(F)F

    .line 893
    .line 894
    .line 895
    move-result v4

    .line 896
    move/from16 v32, v2

    .line 897
    .line 898
    move v6, v4

    .line 899
    move/from16 v4, v20

    .line 900
    .line 901
    goto :goto_17

    .line 902
    :cond_28
    const/4 v2, 0x1

    .line 903
    invoke-virtual {v6, v2}, Ld5/b;->t(I)F

    .line 904
    .line 905
    .line 906
    move-result v4

    .line 907
    const/4 v2, 0x2

    .line 908
    invoke-virtual {v6, v2}, Ld5/b;->t(I)F

    .line 909
    .line 910
    .line 911
    move-result v6

    .line 912
    iget-object v2, v3, Lz4/q;->a:Lrx/b;

    .line 913
    .line 914
    invoke-virtual {v2, v6}, Lrx/b;->e(F)F

    .line 915
    .line 916
    .line 917
    move-result v2

    .line 918
    move v6, v2

    .line 919
    goto :goto_16

    .line 920
    :cond_29
    const/4 v2, 0x1

    .line 921
    invoke-virtual {v6, v2}, Ld5/b;->t(I)F

    .line 922
    .line 923
    .line 924
    move-result v4

    .line 925
    move/from16 v6, v24

    .line 926
    .line 927
    goto :goto_16

    .line 928
    :goto_17
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 929
    .line 930
    .line 931
    move-result-object v2

    .line 932
    invoke-virtual {v0, v2}, Le5/h;->q([Ljava/lang/Object;)V

    .line 933
    .line 934
    .line 935
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 936
    .line 937
    .line 938
    move-result v2

    .line 939
    if-nez v2, :cond_2b

    .line 940
    .line 941
    iget-object v2, v0, Lf5/e;->o0:Ljava/util/HashMap;

    .line 942
    .line 943
    if-nez v2, :cond_2a

    .line 944
    .line 945
    new-instance v2, Ljava/util/HashMap;

    .line 946
    .line 947
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 948
    .line 949
    .line 950
    iput-object v2, v0, Lf5/e;->o0:Ljava/util/HashMap;

    .line 951
    .line 952
    :cond_2a
    iget-object v2, v0, Lf5/e;->o0:Ljava/util/HashMap;

    .line 953
    .line 954
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 955
    .line 956
    .line 957
    move-result-object v4

    .line 958
    invoke-virtual {v2, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 959
    .line 960
    .line 961
    :cond_2b
    invoke-static/range {v32 .. v32}, Ljava/lang/Float;->isNaN(F)Z

    .line 962
    .line 963
    .line 964
    move-result v2

    .line 965
    if-nez v2, :cond_2d

    .line 966
    .line 967
    iget-object v2, v0, Lf5/e;->p0:Ljava/util/HashMap;

    .line 968
    .line 969
    if-nez v2, :cond_2c

    .line 970
    .line 971
    new-instance v2, Ljava/util/HashMap;

    .line 972
    .line 973
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 974
    .line 975
    .line 976
    iput-object v2, v0, Lf5/e;->p0:Ljava/util/HashMap;

    .line 977
    .line 978
    :cond_2c
    iget-object v2, v0, Lf5/e;->p0:Ljava/util/HashMap;

    .line 979
    .line 980
    invoke-static/range {v32 .. v32}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 981
    .line 982
    .line 983
    move-result-object v4

    .line 984
    invoke-virtual {v2, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 985
    .line 986
    .line 987
    :cond_2d
    invoke-static {v6}, Ljava/lang/Float;->isNaN(F)Z

    .line 988
    .line 989
    .line 990
    move-result v2

    .line 991
    if-nez v2, :cond_31

    .line 992
    .line 993
    iget-object v2, v0, Lf5/e;->q0:Ljava/util/HashMap;

    .line 994
    .line 995
    if-nez v2, :cond_2e

    .line 996
    .line 997
    new-instance v2, Ljava/util/HashMap;

    .line 998
    .line 999
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 1000
    .line 1001
    .line 1002
    iput-object v2, v0, Lf5/e;->q0:Ljava/util/HashMap;

    .line 1003
    .line 1004
    :cond_2e
    iget-object v2, v0, Lf5/e;->q0:Ljava/util/HashMap;

    .line 1005
    .line 1006
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1007
    .line 1008
    .line 1009
    move-result-object v4

    .line 1010
    invoke-virtual {v2, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1011
    .line 1012
    .line 1013
    goto :goto_18

    .line 1014
    :cond_2f
    move-object/from16 v30, v2

    .line 1015
    .line 1016
    move-object/from16 v31, v4

    .line 1017
    .line 1018
    goto :goto_18

    .line 1019
    :cond_30
    move-object/from16 v30, v2

    .line 1020
    .line 1021
    move-object/from16 v31, v4

    .line 1022
    .line 1023
    invoke-virtual {v6}, Ld5/c;->e()Ljava/lang/String;

    .line 1024
    .line 1025
    .line 1026
    move-result-object v1

    .line 1027
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v1

    .line 1031
    invoke-virtual {v0, v1}, Le5/h;->q([Ljava/lang/Object;)V

    .line 1032
    .line 1033
    .line 1034
    :cond_31
    :goto_18
    add-int/lit8 v1, v28, 0x1

    .line 1035
    .line 1036
    move-object/from16 v2, v30

    .line 1037
    .line 1038
    move-object/from16 v4, v31

    .line 1039
    .line 1040
    goto/16 :goto_15

    .line 1041
    .line 1042
    :cond_32
    move-object/from16 v31, v4

    .line 1043
    .line 1044
    goto/16 :goto_12

    .line 1045
    .line 1046
    :cond_33
    move-object/from16 v28, v1

    .line 1047
    .line 1048
    move-object/from16 v29, v6

    .line 1049
    .line 1050
    goto/16 :goto_14

    .line 1051
    .line 1052
    :goto_19
    sget-object v0, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 1053
    .line 1054
    invoke-static {v7, v5}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1055
    .line 1056
    .line 1057
    move-result-object v1

    .line 1058
    invoke-virtual/range {v28 .. v28}, Ld5/c;->e()Ljava/lang/String;

    .line 1059
    .line 1060
    .line 1061
    move-result-object v2

    .line 1062
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1063
    .line 1064
    .line 1065
    invoke-virtual {v1, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1066
    .line 1067
    .line 1068
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v1

    .line 1072
    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 1073
    .line 1074
    .line 1075
    goto/16 :goto_38

    .line 1076
    .line 1077
    :pswitch_8
    move-object/from16 v31, v4

    .line 1078
    .line 1079
    move-object/from16 v29, v6

    .line 1080
    .line 1081
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v1

    .line 1085
    instance-of v2, v1, Ld5/a;

    .line 1086
    .line 1087
    if-eqz v2, :cond_35

    .line 1088
    .line 1089
    move-object v2, v1

    .line 1090
    check-cast v2, Ld5/a;

    .line 1091
    .line 1092
    iget-object v4, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1093
    .line 1094
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1095
    .line 1096
    .line 1097
    move-result v4

    .line 1098
    const/4 v6, 0x1

    .line 1099
    if-le v4, v6, :cond_35

    .line 1100
    .line 1101
    const/4 v4, 0x0

    .line 1102
    invoke-virtual {v2, v4}, Ld5/b;->t(I)F

    .line 1103
    .line 1104
    .line 1105
    move-result v1

    .line 1106
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1107
    .line 1108
    .line 1109
    move-result-object v1

    .line 1110
    invoke-virtual {v2, v6}, Ld5/b;->t(I)F

    .line 1111
    .line 1112
    .line 1113
    move-result v4

    .line 1114
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v4

    .line 1118
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1119
    .line 1120
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1121
    .line 1122
    .line 1123
    move-result v6

    .line 1124
    move-object/from16 v28, v1

    .line 1125
    .line 1126
    const/4 v1, 0x2

    .line 1127
    if-le v6, v1, :cond_34

    .line 1128
    .line 1129
    invoke-virtual {v2, v1}, Ld5/b;->t(I)F

    .line 1130
    .line 1131
    .line 1132
    move-result v2

    .line 1133
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1134
    .line 1135
    .line 1136
    move-result-object v1

    .line 1137
    move-object v2, v1

    .line 1138
    :goto_1a
    move-object/from16 v1, v28

    .line 1139
    .line 1140
    goto :goto_1b

    .line 1141
    :cond_34
    move-object/from16 v2, v26

    .line 1142
    .line 1143
    goto :goto_1a

    .line 1144
    :cond_35
    invoke-virtual {v1}, Ld5/c;->i()F

    .line 1145
    .line 1146
    .line 1147
    move-result v1

    .line 1148
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v4

    .line 1152
    move-object/from16 v1, v26

    .line 1153
    .line 1154
    move-object v2, v1

    .line 1155
    :goto_1b
    :try_start_0
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 1156
    .line 1157
    .line 1158
    move-result v4

    .line 1159
    iput v4, v0, Le5/b;->i:F

    .line 1160
    .line 1161
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1162
    .line 1163
    .line 1164
    move-result v4

    .line 1165
    cmpl-float v4, v4, v25

    .line 1166
    .line 1167
    if-eqz v4, :cond_36

    .line 1168
    .line 1169
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1170
    .line 1171
    .line 1172
    move-result v1

    .line 1173
    iput v1, v0, Lf5/e;->I0:F

    .line 1174
    .line 1175
    :cond_36
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 1176
    .line 1177
    .line 1178
    move-result v1

    .line 1179
    cmpl-float v1, v1, v25

    .line 1180
    .line 1181
    if-eqz v1, :cond_23

    .line 1182
    .line 1183
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 1184
    .line 1185
    .line 1186
    move-result v1

    .line 1187
    iput v1, v0, Lf5/e;->J0:F
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 1188
    .line 1189
    goto/16 :goto_12

    .line 1190
    .line 1191
    :pswitch_9
    move-object/from16 v31, v4

    .line 1192
    .line 1193
    move-object/from16 v29, v6

    .line 1194
    .line 1195
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1196
    .line 1197
    .line 1198
    move-result-object v1

    .line 1199
    instance-of v2, v1, Ld5/a;

    .line 1200
    .line 1201
    if-eqz v2, :cond_38

    .line 1202
    .line 1203
    move-object v2, v1

    .line 1204
    check-cast v2, Ld5/a;

    .line 1205
    .line 1206
    iget-object v4, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1207
    .line 1208
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1209
    .line 1210
    .line 1211
    move-result v4

    .line 1212
    const/4 v6, 0x1

    .line 1213
    if-le v4, v6, :cond_38

    .line 1214
    .line 1215
    move-object/from16 v28, v1

    .line 1216
    .line 1217
    const/4 v4, 0x0

    .line 1218
    invoke-virtual {v2, v4}, Ld5/b;->v(I)I

    .line 1219
    .line 1220
    .line 1221
    move-result v1

    .line 1222
    int-to-float v1, v1

    .line 1223
    invoke-virtual {v2, v6}, Ld5/b;->v(I)I

    .line 1224
    .line 1225
    .line 1226
    move-result v4

    .line 1227
    int-to-float v4, v4

    .line 1228
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1229
    .line 1230
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1231
    .line 1232
    .line 1233
    move-result v6

    .line 1234
    move/from16 v30, v1

    .line 1235
    .line 1236
    const/4 v1, 0x2

    .line 1237
    if-le v6, v1, :cond_37

    .line 1238
    .line 1239
    invoke-virtual {v2, v1}, Ld5/b;->v(I)I

    .line 1240
    .line 1241
    .line 1242
    move-result v2

    .line 1243
    int-to-float v1, v2

    .line 1244
    :try_start_1
    move-object/from16 v2, v28

    .line 1245
    .line 1246
    check-cast v2, Ld5/a;

    .line 1247
    .line 1248
    const/4 v6, 0x3

    .line 1249
    invoke-virtual {v2, v6}, Ld5/b;->v(I)I

    .line 1250
    .line 1251
    .line 1252
    move-result v2
    :try_end_1
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_1

    .line 1253
    int-to-float v2, v2

    .line 1254
    move v6, v2

    .line 1255
    move-object/from16 v28, v9

    .line 1256
    .line 1257
    move v2, v1

    .line 1258
    move/from16 v1, v30

    .line 1259
    .line 1260
    goto :goto_1c

    .line 1261
    :catch_1
    move v2, v1

    .line 1262
    move-object/from16 v28, v9

    .line 1263
    .line 1264
    move/from16 v1, v30

    .line 1265
    .line 1266
    const/4 v6, 0x0

    .line 1267
    goto :goto_1c

    .line 1268
    :cond_37
    move v6, v4

    .line 1269
    move-object/from16 v28, v9

    .line 1270
    .line 1271
    move/from16 v1, v30

    .line 1272
    .line 1273
    move v2, v1

    .line 1274
    goto :goto_1c

    .line 1275
    :cond_38
    move-object/from16 v28, v1

    .line 1276
    .line 1277
    invoke-virtual/range {v28 .. v28}, Ld5/c;->k()I

    .line 1278
    .line 1279
    .line 1280
    move-result v1

    .line 1281
    int-to-float v1, v1

    .line 1282
    move v2, v1

    .line 1283
    move v4, v2

    .line 1284
    move v6, v4

    .line 1285
    move-object/from16 v28, v9

    .line 1286
    .line 1287
    :goto_1c
    iget-object v9, v3, Lz4/q;->a:Lrx/b;

    .line 1288
    .line 1289
    invoke-virtual {v9, v1}, Lrx/b;->e(F)F

    .line 1290
    .line 1291
    .line 1292
    move-result v1

    .line 1293
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 1294
    .line 1295
    .line 1296
    move-result v1

    .line 1297
    iput v1, v0, Lf5/e;->C0:I

    .line 1298
    .line 1299
    iget-object v1, v3, Lz4/q;->a:Lrx/b;

    .line 1300
    .line 1301
    invoke-virtual {v1, v4}, Lrx/b;->e(F)F

    .line 1302
    .line 1303
    .line 1304
    move-result v1

    .line 1305
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 1306
    .line 1307
    .line 1308
    move-result v1

    .line 1309
    iput v1, v0, Lf5/e;->E0:I

    .line 1310
    .line 1311
    iget-object v1, v3, Lz4/q;->a:Lrx/b;

    .line 1312
    .line 1313
    invoke-virtual {v1, v2}, Lrx/b;->e(F)F

    .line 1314
    .line 1315
    .line 1316
    move-result v1

    .line 1317
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 1318
    .line 1319
    .line 1320
    move-result v1

    .line 1321
    iput v1, v0, Lf5/e;->D0:I

    .line 1322
    .line 1323
    iget-object v1, v3, Lz4/q;->a:Lrx/b;

    .line 1324
    .line 1325
    invoke-virtual {v1, v6}, Lrx/b;->e(F)F

    .line 1326
    .line 1327
    .line 1328
    move-result v1

    .line 1329
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 1330
    .line 1331
    .line 1332
    move-result v1

    .line 1333
    iput v1, v0, Lf5/e;->F0:I

    .line 1334
    .line 1335
    goto/16 :goto_23

    .line 1336
    .line 1337
    :pswitch_a
    move-object/from16 v31, v4

    .line 1338
    .line 1339
    move-object/from16 v29, v6

    .line 1340
    .line 1341
    move-object/from16 v28, v9

    .line 1342
    .line 1343
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v1

    .line 1347
    instance-of v2, v1, Ld5/a;

    .line 1348
    .line 1349
    if-eqz v2, :cond_3a

    .line 1350
    .line 1351
    move-object v2, v1

    .line 1352
    check-cast v2, Ld5/a;

    .line 1353
    .line 1354
    iget-object v4, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1355
    .line 1356
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1357
    .line 1358
    .line 1359
    move-result v4

    .line 1360
    const/4 v6, 0x1

    .line 1361
    if-le v4, v6, :cond_3a

    .line 1362
    .line 1363
    const/4 v4, 0x0

    .line 1364
    invoke-virtual {v2, v4}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1365
    .line 1366
    .line 1367
    move-result-object v1

    .line 1368
    invoke-virtual {v2, v6}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1369
    .line 1370
    .line 1371
    move-result-object v4

    .line 1372
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1373
    .line 1374
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1375
    .line 1376
    .line 1377
    move-result v6

    .line 1378
    const/4 v9, 0x2

    .line 1379
    if-le v6, v9, :cond_39

    .line 1380
    .line 1381
    invoke-virtual {v2, v9}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1382
    .line 1383
    .line 1384
    move-result-object v2

    .line 1385
    goto :goto_1d

    .line 1386
    :cond_39
    move-object v2, v14

    .line 1387
    goto :goto_1d

    .line 1388
    :cond_3a
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 1389
    .line 1390
    .line 1391
    move-result-object v4

    .line 1392
    move-object v1, v14

    .line 1393
    move-object v2, v1

    .line 1394
    :goto_1d
    invoke-virtual {v4, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1395
    .line 1396
    .line 1397
    move-result v6

    .line 1398
    if-nez v6, :cond_3b

    .line 1399
    .line 1400
    invoke-static {v4}, Le5/j;->a(Ljava/lang/String;)I

    .line 1401
    .line 1402
    .line 1403
    move-result v4

    .line 1404
    iput v4, v0, Lf5/e;->s0:I

    .line 1405
    .line 1406
    :cond_3b
    invoke-virtual {v1, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1407
    .line 1408
    .line 1409
    move-result v4

    .line 1410
    if-nez v4, :cond_3c

    .line 1411
    .line 1412
    invoke-static {v1}, Le5/j;->a(Ljava/lang/String;)I

    .line 1413
    .line 1414
    .line 1415
    move-result v1

    .line 1416
    iput v1, v0, Lf5/e;->t0:I

    .line 1417
    .line 1418
    :cond_3c
    invoke-virtual {v2, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1419
    .line 1420
    .line 1421
    move-result v1

    .line 1422
    if-nez v1, :cond_49

    .line 1423
    .line 1424
    invoke-static {v2}, Le5/j;->a(Ljava/lang/String;)I

    .line 1425
    .line 1426
    .line 1427
    move-result v1

    .line 1428
    iput v1, v0, Lf5/e;->u0:I

    .line 1429
    .line 1430
    goto/16 :goto_23

    .line 1431
    .line 1432
    :pswitch_b
    move-object/from16 v31, v4

    .line 1433
    .line 1434
    move-object/from16 v29, v6

    .line 1435
    .line 1436
    move-object/from16 v28, v9

    .line 1437
    .line 1438
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1439
    .line 1440
    .line 1441
    move-result-object v1

    .line 1442
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 1443
    .line 1444
    .line 1445
    move-result-object v1

    .line 1446
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1447
    .line 1448
    .line 1449
    invoke-virtual {v1}, Ljava/lang/String;->hashCode()I

    .line 1450
    .line 1451
    .line 1452
    move-result v2

    .line 1453
    sparse-switch v2, :sswitch_data_3

    .line 1454
    .line 1455
    .line 1456
    :goto_1e
    const/4 v1, -0x1

    .line 1457
    goto :goto_1f

    .line 1458
    :sswitch_1a
    invoke-virtual {v1, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1459
    .line 1460
    .line 1461
    move-result v1

    .line 1462
    if-nez v1, :cond_3d

    .line 1463
    .line 1464
    goto :goto_1e

    .line 1465
    :cond_3d
    const/4 v1, 0x2

    .line 1466
    goto :goto_1f

    .line 1467
    :sswitch_1b
    invoke-virtual {v1, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1468
    .line 1469
    .line 1470
    move-result v1

    .line 1471
    if-nez v1, :cond_3e

    .line 1472
    .line 1473
    goto :goto_1e

    .line 1474
    :cond_3e
    const/4 v1, 0x1

    .line 1475
    goto :goto_1f

    .line 1476
    :sswitch_1c
    const-string v2, "baseline"

    .line 1477
    .line 1478
    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1479
    .line 1480
    .line 1481
    move-result v1

    .line 1482
    if-nez v1, :cond_3f

    .line 1483
    .line 1484
    goto :goto_1e

    .line 1485
    :cond_3f
    const/4 v1, 0x0

    .line 1486
    :goto_1f
    packed-switch v1, :pswitch_data_4

    .line 1487
    .line 1488
    .line 1489
    const/4 v1, 0x2

    .line 1490
    iput v1, v0, Lf5/e;->y0:I

    .line 1491
    .line 1492
    :goto_20
    const/4 v6, 0x1

    .line 1493
    goto/16 :goto_23

    .line 1494
    .line 1495
    :pswitch_c
    const/4 v4, 0x0

    .line 1496
    iput v4, v0, Lf5/e;->y0:I

    .line 1497
    .line 1498
    goto :goto_20

    .line 1499
    :pswitch_d
    const/4 v6, 0x1

    .line 1500
    iput v6, v0, Lf5/e;->y0:I

    .line 1501
    .line 1502
    goto/16 :goto_23

    .line 1503
    .line 1504
    :pswitch_e
    const/4 v4, 0x3

    .line 1505
    const/4 v6, 0x1

    .line 1506
    iput v4, v0, Lf5/e;->y0:I

    .line 1507
    .line 1508
    goto/16 :goto_23

    .line 1509
    .line 1510
    :pswitch_f
    move-object/from16 v31, v4

    .line 1511
    .line 1512
    move-object/from16 v29, v6

    .line 1513
    .line 1514
    move-object/from16 v28, v9

    .line 1515
    .line 1516
    const/4 v6, 0x1

    .line 1517
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v1

    .line 1521
    instance-of v2, v1, Ld5/a;

    .line 1522
    .line 1523
    if-eqz v2, :cond_41

    .line 1524
    .line 1525
    move-object v2, v1

    .line 1526
    check-cast v2, Ld5/a;

    .line 1527
    .line 1528
    iget-object v4, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1529
    .line 1530
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1531
    .line 1532
    .line 1533
    move-result v4

    .line 1534
    if-le v4, v6, :cond_41

    .line 1535
    .line 1536
    const/4 v4, 0x0

    .line 1537
    invoke-virtual {v2, v4}, Ld5/b;->t(I)F

    .line 1538
    .line 1539
    .line 1540
    move-result v1

    .line 1541
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1542
    .line 1543
    .line 1544
    move-result-object v1

    .line 1545
    invoke-virtual {v2, v6}, Ld5/b;->t(I)F

    .line 1546
    .line 1547
    .line 1548
    move-result v4

    .line 1549
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1550
    .line 1551
    .line 1552
    move-result-object v4

    .line 1553
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1554
    .line 1555
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1556
    .line 1557
    .line 1558
    move-result v6

    .line 1559
    const/4 v9, 0x2

    .line 1560
    if-le v6, v9, :cond_40

    .line 1561
    .line 1562
    invoke-virtual {v2, v9}, Ld5/b;->t(I)F

    .line 1563
    .line 1564
    .line 1565
    move-result v2

    .line 1566
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1567
    .line 1568
    .line 1569
    move-result-object v2

    .line 1570
    goto :goto_21

    .line 1571
    :cond_40
    move-object/from16 v2, v26

    .line 1572
    .line 1573
    goto :goto_21

    .line 1574
    :cond_41
    invoke-virtual {v1}, Ld5/c;->i()F

    .line 1575
    .line 1576
    .line 1577
    move-result v1

    .line 1578
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 1579
    .line 1580
    .line 1581
    move-result-object v4

    .line 1582
    move-object/from16 v1, v26

    .line 1583
    .line 1584
    move-object v2, v1

    .line 1585
    :goto_21
    :try_start_2
    invoke-virtual {v4}, Ljava/lang/Float;->floatValue()F

    .line 1586
    .line 1587
    .line 1588
    move-result v4

    .line 1589
    iput v4, v0, Le5/b;->h:F

    .line 1590
    .line 1591
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1592
    .line 1593
    .line 1594
    move-result v4

    .line 1595
    cmpl-float v4, v4, v25

    .line 1596
    .line 1597
    if-eqz v4, :cond_42

    .line 1598
    .line 1599
    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    .line 1600
    .line 1601
    .line 1602
    move-result v1

    .line 1603
    iput v1, v0, Lf5/e;->K0:F

    .line 1604
    .line 1605
    :cond_42
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 1606
    .line 1607
    .line 1608
    move-result v1

    .line 1609
    cmpl-float v1, v1, v25

    .line 1610
    .line 1611
    if-eqz v1, :cond_49

    .line 1612
    .line 1613
    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    .line 1614
    .line 1615
    .line 1616
    move-result v1

    .line 1617
    iput v1, v0, Lf5/e;->L0:F
    :try_end_2
    .catch Ljava/lang/NumberFormatException; {:try_start_2 .. :try_end_2} :catch_2

    .line 1618
    .line 1619
    goto/16 :goto_23

    .line 1620
    .line 1621
    :pswitch_10
    move-object/from16 v31, v4

    .line 1622
    .line 1623
    move-object/from16 v29, v6

    .line 1624
    .line 1625
    move-object/from16 v28, v9

    .line 1626
    .line 1627
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1628
    .line 1629
    .line 1630
    move-result-object v1

    .line 1631
    instance-of v2, v1, Ld5/a;

    .line 1632
    .line 1633
    if-eqz v2, :cond_44

    .line 1634
    .line 1635
    move-object v2, v1

    .line 1636
    check-cast v2, Ld5/a;

    .line 1637
    .line 1638
    iget-object v4, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1639
    .line 1640
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 1641
    .line 1642
    .line 1643
    move-result v4

    .line 1644
    const/4 v6, 0x1

    .line 1645
    if-le v4, v6, :cond_44

    .line 1646
    .line 1647
    const/4 v4, 0x0

    .line 1648
    invoke-virtual {v2, v4}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1649
    .line 1650
    .line 1651
    move-result-object v1

    .line 1652
    invoke-virtual {v2, v6}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1653
    .line 1654
    .line 1655
    move-result-object v4

    .line 1656
    iget-object v6, v2, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1657
    .line 1658
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1659
    .line 1660
    .line 1661
    move-result v6

    .line 1662
    const/4 v9, 0x2

    .line 1663
    if-le v6, v9, :cond_43

    .line 1664
    .line 1665
    invoke-virtual {v2, v9}, Ld5/b;->y(I)Ljava/lang/String;

    .line 1666
    .line 1667
    .line 1668
    move-result-object v2

    .line 1669
    goto :goto_22

    .line 1670
    :cond_43
    move-object v2, v14

    .line 1671
    goto :goto_22

    .line 1672
    :cond_44
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 1673
    .line 1674
    .line 1675
    move-result-object v4

    .line 1676
    move-object v1, v14

    .line 1677
    move-object v2, v1

    .line 1678
    :goto_22
    invoke-virtual {v4, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1679
    .line 1680
    .line 1681
    move-result v6

    .line 1682
    if-nez v6, :cond_45

    .line 1683
    .line 1684
    invoke-static {v4}, Le5/j;->a(Ljava/lang/String;)I

    .line 1685
    .line 1686
    .line 1687
    move-result v4

    .line 1688
    iput v4, v0, Lf5/e;->v0:I

    .line 1689
    .line 1690
    :cond_45
    invoke-virtual {v1, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1691
    .line 1692
    .line 1693
    move-result v4

    .line 1694
    if-nez v4, :cond_46

    .line 1695
    .line 1696
    invoke-static {v1}, Le5/j;->a(Ljava/lang/String;)I

    .line 1697
    .line 1698
    .line 1699
    move-result v1

    .line 1700
    iput v1, v0, Lf5/e;->w0:I

    .line 1701
    .line 1702
    :cond_46
    invoke-virtual {v2, v14}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1703
    .line 1704
    .line 1705
    move-result v1

    .line 1706
    if-nez v1, :cond_49

    .line 1707
    .line 1708
    invoke-static {v2}, Le5/j;->a(Ljava/lang/String;)I

    .line 1709
    .line 1710
    .line 1711
    move-result v1

    .line 1712
    iput v1, v0, Lf5/e;->x0:I

    .line 1713
    .line 1714
    goto :goto_23

    .line 1715
    :pswitch_11
    move-object/from16 v31, v4

    .line 1716
    .line 1717
    move-object/from16 v29, v6

    .line 1718
    .line 1719
    move-object/from16 v28, v9

    .line 1720
    .line 1721
    invoke-virtual {v8, v1}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 1722
    .line 1723
    .line 1724
    move-result-object v1

    .line 1725
    invoke-virtual {v1}, Ld5/c;->e()Ljava/lang/String;

    .line 1726
    .line 1727
    .line 1728
    move-result-object v1

    .line 1729
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1730
    .line 1731
    .line 1732
    invoke-virtual {v1, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1733
    .line 1734
    .line 1735
    move-result v2

    .line 1736
    if-nez v2, :cond_48

    .line 1737
    .line 1738
    invoke-virtual {v1, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1739
    .line 1740
    .line 1741
    move-result v1

    .line 1742
    if-nez v1, :cond_47

    .line 1743
    .line 1744
    const/4 v1, 0x2

    .line 1745
    iput v1, v0, Lf5/e;->z0:I

    .line 1746
    .line 1747
    goto :goto_23

    .line 1748
    :cond_47
    const/4 v4, 0x0

    .line 1749
    iput v4, v0, Lf5/e;->z0:I

    .line 1750
    .line 1751
    goto :goto_23

    .line 1752
    :cond_48
    const/4 v6, 0x1

    .line 1753
    iput v6, v0, Lf5/e;->z0:I

    .line 1754
    .line 1755
    :catch_2
    :cond_49
    :goto_23
    move-object/from16 v2, v22

    .line 1756
    .line 1757
    move-object/from16 v9, v28

    .line 1758
    .line 1759
    move-object/from16 v6, v29

    .line 1760
    .line 1761
    move-object/from16 v4, v31

    .line 1762
    .line 1763
    const/4 v1, 0x7

    .line 1764
    goto/16 :goto_d

    .line 1765
    .line 1766
    :cond_4a
    move-object/from16 v31, v4

    .line 1767
    .line 1768
    move-object/from16 v29, v6

    .line 1769
    .line 1770
    goto/16 :goto_38

    .line 1771
    .line 1772
    :pswitch_12
    move-object/from16 v27, v1

    .line 1773
    .line 1774
    move-object/from16 v31, v4

    .line 1775
    .line 1776
    move-object/from16 v29, v6

    .line 1777
    .line 1778
    iget-boolean v0, v3, Lz4/q;->b:Z

    .line 1779
    .line 1780
    invoke-virtual {v3, v7}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1781
    .line 1782
    .line 1783
    move-result-object v1

    .line 1784
    iget-object v2, v1, Le5/b;->c:Ljava/lang/Object;

    .line 1785
    .line 1786
    if-eqz v2, :cond_4b

    .line 1787
    .line 1788
    instance-of v2, v2, Lf5/b;

    .line 1789
    .line 1790
    if-nez v2, :cond_4c

    .line 1791
    .line 1792
    :cond_4b
    new-instance v2, Lf5/b;

    .line 1793
    .line 1794
    const/4 v4, 0x5

    .line 1795
    invoke-direct {v2, v3, v4}, Le5/h;-><init>(Lz4/q;I)V

    .line 1796
    .line 1797
    .line 1798
    const/4 v4, 0x4

    .line 1799
    iput v4, v2, Lf5/b;->n0:I

    .line 1800
    .line 1801
    iput-object v2, v1, Le5/b;->c:Ljava/lang/Object;

    .line 1802
    .line 1803
    invoke-virtual {v2}, Le5/h;->b()Lh5/d;

    .line 1804
    .line 1805
    .line 1806
    move-result-object v2

    .line 1807
    invoke-virtual {v1, v2}, Le5/b;->a(Lh5/d;)V

    .line 1808
    .line 1809
    .line 1810
    :cond_4c
    iget-object v1, v1, Le5/b;->c:Ljava/lang/Object;

    .line 1811
    .line 1812
    check-cast v1, Lf5/b;

    .line 1813
    .line 1814
    invoke-virtual {v8}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 1815
    .line 1816
    .line 1817
    move-result-object v2

    .line 1818
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1819
    .line 1820
    .line 1821
    move-result-object v2

    .line 1822
    :cond_4d
    :goto_24
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 1823
    .line 1824
    .line 1825
    move-result v4

    .line 1826
    if-eqz v4, :cond_77

    .line 1827
    .line 1828
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1829
    .line 1830
    .line 1831
    move-result-object v4

    .line 1832
    check-cast v4, Ljava/lang/String;

    .line 1833
    .line 1834
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1835
    .line 1836
    .line 1837
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 1838
    .line 1839
    .line 1840
    move-result v5

    .line 1841
    sparse-switch v5, :sswitch_data_4

    .line 1842
    .line 1843
    .line 1844
    :goto_25
    const/4 v5, -0x1

    .line 1845
    goto :goto_26

    .line 1846
    :sswitch_1d
    invoke-virtual {v4, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1847
    .line 1848
    .line 1849
    move-result v5

    .line 1850
    if-nez v5, :cond_4e

    .line 1851
    .line 1852
    goto :goto_25

    .line 1853
    :cond_4e
    const/4 v5, 0x2

    .line 1854
    goto :goto_26

    .line 1855
    :sswitch_1e
    const-string v5, "direction"

    .line 1856
    .line 1857
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1858
    .line 1859
    .line 1860
    move-result v5

    .line 1861
    if-nez v5, :cond_4f

    .line 1862
    .line 1863
    goto :goto_25

    .line 1864
    :cond_4f
    const/4 v5, 0x1

    .line 1865
    goto :goto_26

    .line 1866
    :sswitch_1f
    const-string v5, "margin"

    .line 1867
    .line 1868
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1869
    .line 1870
    .line 1871
    move-result v5

    .line 1872
    if-nez v5, :cond_50

    .line 1873
    .line 1874
    goto :goto_25

    .line 1875
    :cond_50
    const/4 v5, 0x0

    .line 1876
    :goto_26
    packed-switch v5, :pswitch_data_5

    .line 1877
    .line 1878
    .line 1879
    goto :goto_24

    .line 1880
    :pswitch_13
    invoke-virtual {v8, v4}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 1881
    .line 1882
    .line 1883
    move-result-object v4

    .line 1884
    instance-of v5, v4, Ld5/a;

    .line 1885
    .line 1886
    if-eqz v5, :cond_51

    .line 1887
    .line 1888
    check-cast v4, Ld5/a;

    .line 1889
    .line 1890
    goto :goto_27

    .line 1891
    :cond_51
    const/4 v4, 0x0

    .line 1892
    :goto_27
    if-eqz v4, :cond_4d

    .line 1893
    .line 1894
    const/4 v5, 0x0

    .line 1895
    :goto_28
    iget-object v6, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 1896
    .line 1897
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 1898
    .line 1899
    .line 1900
    move-result v6

    .line 1901
    if-ge v5, v6, :cond_4d

    .line 1902
    .line 1903
    invoke-virtual {v4, v5}, Ld5/b;->r(I)Ld5/c;

    .line 1904
    .line 1905
    .line 1906
    move-result-object v6

    .line 1907
    invoke-virtual {v6}, Ld5/c;->e()Ljava/lang/String;

    .line 1908
    .line 1909
    .line 1910
    move-result-object v6

    .line 1911
    invoke-virtual {v3, v6}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 1912
    .line 1913
    .line 1914
    move-result-object v6

    .line 1915
    filled-new-array {v6}, [Ljava/lang/Object;

    .line 1916
    .line 1917
    .line 1918
    move-result-object v6

    .line 1919
    invoke-virtual {v1, v6}, Le5/h;->q([Ljava/lang/Object;)V

    .line 1920
    .line 1921
    .line 1922
    add-int/lit8 v5, v5, 0x1

    .line 1923
    .line 1924
    goto :goto_28

    .line 1925
    :pswitch_14
    invoke-virtual {v8, v4}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 1926
    .line 1927
    .line 1928
    move-result-object v4

    .line 1929
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1930
    .line 1931
    .line 1932
    invoke-virtual {v4}, Ljava/lang/String;->hashCode()I

    .line 1933
    .line 1934
    .line 1935
    move-result v5

    .line 1936
    sparse-switch v5, :sswitch_data_5

    .line 1937
    .line 1938
    .line 1939
    :goto_29
    const/4 v4, -0x1

    .line 1940
    goto :goto_2a

    .line 1941
    :sswitch_20
    invoke-virtual {v4, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1942
    .line 1943
    .line 1944
    move-result v4

    .line 1945
    if-nez v4, :cond_52

    .line 1946
    .line 1947
    goto :goto_29

    .line 1948
    :cond_52
    const/4 v4, 0x5

    .line 1949
    goto :goto_2a

    .line 1950
    :sswitch_21
    const-string v5, "right"

    .line 1951
    .line 1952
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1953
    .line 1954
    .line 1955
    move-result v4

    .line 1956
    if-nez v4, :cond_53

    .line 1957
    .line 1958
    goto :goto_29

    .line 1959
    :cond_53
    const/4 v4, 0x4

    .line 1960
    goto :goto_2a

    .line 1961
    :sswitch_22
    const-string v5, "left"

    .line 1962
    .line 1963
    invoke-virtual {v4, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1964
    .line 1965
    .line 1966
    move-result v4

    .line 1967
    if-nez v4, :cond_54

    .line 1968
    .line 1969
    goto :goto_29

    .line 1970
    :cond_54
    const/4 v4, 0x3

    .line 1971
    goto :goto_2a

    .line 1972
    :sswitch_23
    invoke-virtual {v4, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1973
    .line 1974
    .line 1975
    move-result v4

    .line 1976
    if-nez v4, :cond_55

    .line 1977
    .line 1978
    goto :goto_29

    .line 1979
    :cond_55
    const/4 v4, 0x2

    .line 1980
    goto :goto_2a

    .line 1981
    :sswitch_24
    invoke-virtual {v4, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1982
    .line 1983
    .line 1984
    move-result v4

    .line 1985
    if-nez v4, :cond_56

    .line 1986
    .line 1987
    goto :goto_29

    .line 1988
    :cond_56
    const/4 v4, 0x1

    .line 1989
    goto :goto_2a

    .line 1990
    :sswitch_25
    invoke-virtual {v4, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 1991
    .line 1992
    .line 1993
    move-result v4

    .line 1994
    if-nez v4, :cond_57

    .line 1995
    .line 1996
    goto :goto_29

    .line 1997
    :cond_57
    const/4 v4, 0x0

    .line 1998
    :goto_2a
    packed-switch v4, :pswitch_data_6

    .line 1999
    .line 2000
    .line 2001
    goto/16 :goto_24

    .line 2002
    .line 2003
    :pswitch_15
    if-eqz v0, :cond_58

    .line 2004
    .line 2005
    const/4 v6, 0x1

    .line 2006
    iput v6, v1, Lf5/b;->n0:I

    .line 2007
    .line 2008
    goto/16 :goto_24

    .line 2009
    .line 2010
    :cond_58
    const/4 v6, 0x1

    .line 2011
    const/4 v9, 0x2

    .line 2012
    iput v9, v1, Lf5/b;->n0:I

    .line 2013
    .line 2014
    goto/16 :goto_24

    .line 2015
    .line 2016
    :pswitch_16
    const/4 v6, 0x1

    .line 2017
    const/4 v9, 0x2

    .line 2018
    iput v9, v1, Lf5/b;->n0:I

    .line 2019
    .line 2020
    goto/16 :goto_24

    .line 2021
    .line 2022
    :pswitch_17
    const/4 v6, 0x1

    .line 2023
    const/4 v9, 0x2

    .line 2024
    iput v6, v1, Lf5/b;->n0:I

    .line 2025
    .line 2026
    goto/16 :goto_24

    .line 2027
    .line 2028
    :pswitch_18
    const/4 v4, 0x5

    .line 2029
    const/4 v6, 0x1

    .line 2030
    const/4 v9, 0x2

    .line 2031
    iput v4, v1, Lf5/b;->n0:I

    .line 2032
    .line 2033
    goto/16 :goto_24

    .line 2034
    .line 2035
    :pswitch_19
    const/4 v6, 0x1

    .line 2036
    const/4 v9, 0x2

    .line 2037
    if-eqz v0, :cond_59

    .line 2038
    .line 2039
    iput v9, v1, Lf5/b;->n0:I

    .line 2040
    .line 2041
    goto/16 :goto_24

    .line 2042
    .line 2043
    :cond_59
    iput v6, v1, Lf5/b;->n0:I

    .line 2044
    .line 2045
    goto/16 :goto_24

    .line 2046
    .line 2047
    :pswitch_1a
    const/4 v4, 0x6

    .line 2048
    iput v4, v1, Lf5/b;->n0:I

    .line 2049
    .line 2050
    goto/16 :goto_24

    .line 2051
    .line 2052
    :pswitch_1b
    invoke-virtual {v8, v4}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 2053
    .line 2054
    .line 2055
    move-result-object v4

    .line 2056
    instance-of v5, v4, Ld5/e;

    .line 2057
    .line 2058
    if-eqz v5, :cond_5a

    .line 2059
    .line 2060
    invoke-virtual {v4}, Ld5/c;->i()F

    .line 2061
    .line 2062
    .line 2063
    move-result v4

    .line 2064
    goto :goto_2b

    .line 2065
    :cond_5a
    move/from16 v4, v24

    .line 2066
    .line 2067
    :goto_2b
    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    .line 2068
    .line 2069
    .line 2070
    move-result v5

    .line 2071
    if-nez v5, :cond_4d

    .line 2072
    .line 2073
    iget-object v5, v3, Lz4/q;->a:Lrx/b;

    .line 2074
    .line 2075
    invoke-virtual {v5, v4}, Lrx/b;->e(F)F

    .line 2076
    .line 2077
    .line 2078
    move-result v4

    .line 2079
    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2080
    .line 2081
    .line 2082
    move-result-object v4

    .line 2083
    invoke-virtual {v1, v4}, Lf5/b;->l(Ljava/lang/Float;)Le5/b;

    .line 2084
    .line 2085
    .line 2086
    goto/16 :goto_24

    .line 2087
    .line 2088
    :pswitch_1c
    move-object/from16 v27, v1

    .line 2089
    .line 2090
    move-object/from16 v31, v4

    .line 2091
    .line 2092
    move-object/from16 v29, v6

    .line 2093
    .line 2094
    move-object/from16 v28, v9

    .line 2095
    .line 2096
    const/4 v4, 0x0

    .line 2097
    invoke-virtual {v0, v4}, Ljava/lang/String;->charAt(I)C

    .line 2098
    .line 2099
    .line 2100
    move-result v0

    .line 2101
    const/16 v1, 0x68

    .line 2102
    .line 2103
    if-ne v0, v1, :cond_5b

    .line 2104
    .line 2105
    const/4 v6, 0x1

    .line 2106
    invoke-virtual {v3, v6}, Lz4/q;->e(I)Le5/h;

    .line 2107
    .line 2108
    .line 2109
    move-result-object v0

    .line 2110
    check-cast v0, Lf5/h;

    .line 2111
    .line 2112
    goto :goto_2c

    .line 2113
    :cond_5b
    const/4 v1, 0x2

    .line 2114
    invoke-virtual {v3, v1}, Lz4/q;->e(I)Le5/h;

    .line 2115
    .line 2116
    .line 2117
    move-result-object v0

    .line 2118
    check-cast v0, Lf5/i;

    .line 2119
    .line 2120
    :goto_2c
    iput-object v7, v0, Le5/b;->a:Ljava/lang/Object;

    .line 2121
    .line 2122
    invoke-virtual {v8}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 2123
    .line 2124
    .line 2125
    move-result-object v1

    .line 2126
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2127
    .line 2128
    .line 2129
    move-result-object v1

    .line 2130
    :goto_2d
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 2131
    .line 2132
    .line 2133
    move-result v2

    .line 2134
    if-eqz v2, :cond_77

    .line 2135
    .line 2136
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2137
    .line 2138
    .line 2139
    move-result-object v2

    .line 2140
    check-cast v2, Ljava/lang/String;

    .line 2141
    .line 2142
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2143
    .line 2144
    .line 2145
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 2146
    .line 2147
    .line 2148
    move-result v4

    .line 2149
    sparse-switch v4, :sswitch_data_6

    .line 2150
    .line 2151
    .line 2152
    :goto_2e
    const/4 v4, -0x1

    .line 2153
    goto :goto_2f

    .line 2154
    :sswitch_26
    const-string v4, "style"

    .line 2155
    .line 2156
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2157
    .line 2158
    .line 2159
    move-result v4

    .line 2160
    if-nez v4, :cond_5c

    .line 2161
    .line 2162
    goto :goto_2e

    .line 2163
    :cond_5c
    const/4 v4, 0x7

    .line 2164
    goto :goto_2f

    .line 2165
    :sswitch_27
    invoke-virtual {v2, v13}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2166
    .line 2167
    .line 2168
    move-result v4

    .line 2169
    if-nez v4, :cond_5d

    .line 2170
    .line 2171
    goto :goto_2e

    .line 2172
    :cond_5d
    const/4 v4, 0x6

    .line 2173
    goto :goto_2f

    .line 2174
    :sswitch_28
    const-string v4, "right"

    .line 2175
    .line 2176
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2177
    .line 2178
    .line 2179
    move-result v4

    .line 2180
    if-nez v4, :cond_5e

    .line 2181
    .line 2182
    goto :goto_2e

    .line 2183
    :cond_5e
    const/4 v4, 0x5

    .line 2184
    goto :goto_2f

    .line 2185
    :sswitch_29
    const-string v4, "left"

    .line 2186
    .line 2187
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2188
    .line 2189
    .line 2190
    move-result v4

    .line 2191
    if-nez v4, :cond_5f

    .line 2192
    .line 2193
    goto :goto_2e

    .line 2194
    :cond_5f
    const/4 v4, 0x4

    .line 2195
    goto :goto_2f

    .line 2196
    :sswitch_2a
    invoke-virtual {v2, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2197
    .line 2198
    .line 2199
    move-result v4

    .line 2200
    if-nez v4, :cond_60

    .line 2201
    .line 2202
    goto :goto_2e

    .line 2203
    :cond_60
    const/4 v4, 0x3

    .line 2204
    goto :goto_2f

    .line 2205
    :sswitch_2b
    invoke-virtual {v2, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2206
    .line 2207
    .line 2208
    move-result v4

    .line 2209
    if-nez v4, :cond_61

    .line 2210
    .line 2211
    goto :goto_2e

    .line 2212
    :cond_61
    const/4 v4, 0x2

    .line 2213
    goto :goto_2f

    .line 2214
    :sswitch_2c
    invoke-virtual {v2, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2215
    .line 2216
    .line 2217
    move-result v4

    .line 2218
    if-nez v4, :cond_62

    .line 2219
    .line 2220
    goto :goto_2e

    .line 2221
    :cond_62
    const/4 v4, 0x1

    .line 2222
    goto :goto_2f

    .line 2223
    :sswitch_2d
    invoke-virtual {v2, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2224
    .line 2225
    .line 2226
    move-result v4

    .line 2227
    if-nez v4, :cond_63

    .line 2228
    .line 2229
    goto :goto_2e

    .line 2230
    :cond_63
    const/4 v4, 0x0

    .line 2231
    :goto_2f
    packed-switch v4, :pswitch_data_7

    .line 2232
    .line 2233
    .line 2234
    :cond_64
    :goto_30
    move-object/from16 v16, v1

    .line 2235
    .line 2236
    move-object/from16 v4, v28

    .line 2237
    .line 2238
    move-object/from16 v1, v31

    .line 2239
    .line 2240
    goto/16 :goto_39

    .line 2241
    .line 2242
    :pswitch_1d
    invoke-virtual {v8, v2}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 2243
    .line 2244
    .line 2245
    move-result-object v2

    .line 2246
    instance-of v4, v2, Ld5/a;

    .line 2247
    .line 2248
    if-eqz v4, :cond_65

    .line 2249
    .line 2250
    move-object v4, v2

    .line 2251
    check-cast v4, Ld5/a;

    .line 2252
    .line 2253
    iget-object v6, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 2254
    .line 2255
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 2256
    .line 2257
    .line 2258
    move-result v6

    .line 2259
    const/4 v9, 0x1

    .line 2260
    if-le v6, v9, :cond_65

    .line 2261
    .line 2262
    const/4 v6, 0x0

    .line 2263
    invoke-virtual {v4, v6}, Ld5/b;->y(I)Ljava/lang/String;

    .line 2264
    .line 2265
    .line 2266
    move-result-object v2

    .line 2267
    invoke-virtual {v4, v9}, Ld5/b;->t(I)F

    .line 2268
    .line 2269
    .line 2270
    move-result v4

    .line 2271
    iput v4, v0, Lf5/c;->n0:F

    .line 2272
    .line 2273
    goto :goto_31

    .line 2274
    :cond_65
    invoke-virtual {v2}, Ld5/c;->e()Ljava/lang/String;

    .line 2275
    .line 2276
    .line 2277
    move-result-object v2

    .line 2278
    :goto_31
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2279
    .line 2280
    .line 2281
    const-string v4, "packed"

    .line 2282
    .line 2283
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2284
    .line 2285
    .line 2286
    move-result v4

    .line 2287
    if-nez v4, :cond_67

    .line 2288
    .line 2289
    const-string v4, "spread_inside"

    .line 2290
    .line 2291
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2292
    .line 2293
    .line 2294
    move-result v2

    .line 2295
    if-nez v2, :cond_66

    .line 2296
    .line 2297
    sget-object v2, Le5/j;->d:Le5/j;

    .line 2298
    .line 2299
    iput-object v2, v0, Lf5/c;->t0:Le5/j;

    .line 2300
    .line 2301
    goto :goto_30

    .line 2302
    :cond_66
    sget-object v2, Le5/j;->e:Le5/j;

    .line 2303
    .line 2304
    iput-object v2, v0, Lf5/c;->t0:Le5/j;

    .line 2305
    .line 2306
    goto :goto_30

    .line 2307
    :cond_67
    sget-object v2, Le5/j;->f:Le5/j;

    .line 2308
    .line 2309
    iput-object v2, v0, Lf5/c;->t0:Le5/j;

    .line 2310
    .line 2311
    goto :goto_30

    .line 2312
    :pswitch_1e
    invoke-virtual {v8, v2}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 2313
    .line 2314
    .line 2315
    move-result-object v2

    .line 2316
    instance-of v4, v2, Ld5/a;

    .line 2317
    .line 2318
    if-eqz v4, :cond_76

    .line 2319
    .line 2320
    move-object v4, v2

    .line 2321
    check-cast v4, Ld5/a;

    .line 2322
    .line 2323
    iget-object v6, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 2324
    .line 2325
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 2326
    .line 2327
    .line 2328
    move-result v6

    .line 2329
    const/4 v9, 0x1

    .line 2330
    if-ge v6, v9, :cond_68

    .line 2331
    .line 2332
    goto/16 :goto_37

    .line 2333
    .line 2334
    :cond_68
    const/4 v2, 0x0

    .line 2335
    :goto_32
    iget-object v6, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 2336
    .line 2337
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 2338
    .line 2339
    .line 2340
    move-result v6

    .line 2341
    if-ge v2, v6, :cond_64

    .line 2342
    .line 2343
    invoke-virtual {v4, v2}, Ld5/b;->r(I)Ld5/c;

    .line 2344
    .line 2345
    .line 2346
    move-result-object v6

    .line 2347
    instance-of v9, v6, Ld5/a;

    .line 2348
    .line 2349
    if-eqz v9, :cond_74

    .line 2350
    .line 2351
    check-cast v6, Ld5/a;

    .line 2352
    .line 2353
    iget-object v9, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 2354
    .line 2355
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 2356
    .line 2357
    .line 2358
    move-result v9

    .line 2359
    if-lez v9, :cond_73

    .line 2360
    .line 2361
    const/4 v9, 0x0

    .line 2362
    invoke-virtual {v6, v9}, Ld5/b;->r(I)Ld5/c;

    .line 2363
    .line 2364
    .line 2365
    move-result-object v14

    .line 2366
    invoke-virtual {v14}, Ld5/c;->e()Ljava/lang/String;

    .line 2367
    .line 2368
    .line 2369
    move-result-object v9

    .line 2370
    iget-object v14, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 2371
    .line 2372
    invoke-virtual {v14}, Ljava/util/ArrayList;->size()I

    .line 2373
    .line 2374
    .line 2375
    move-result v14

    .line 2376
    move-object/from16 v16, v1

    .line 2377
    .line 2378
    const/4 v1, 0x2

    .line 2379
    if-eq v14, v1, :cond_6c

    .line 2380
    .line 2381
    const/4 v1, 0x3

    .line 2382
    if-eq v14, v1, :cond_6b

    .line 2383
    .line 2384
    const/4 v1, 0x4

    .line 2385
    if-eq v14, v1, :cond_6a

    .line 2386
    .line 2387
    const/4 v1, 0x6

    .line 2388
    if-eq v14, v1, :cond_69

    .line 2389
    .line 2390
    move/from16 v6, v24

    .line 2391
    .line 2392
    move v14, v6

    .line 2393
    move/from16 v17, v14

    .line 2394
    .line 2395
    move/from16 v19, v17

    .line 2396
    .line 2397
    move/from16 v22, v19

    .line 2398
    .line 2399
    goto/16 :goto_34

    .line 2400
    .line 2401
    :cond_69
    const/4 v14, 0x1

    .line 2402
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2403
    .line 2404
    .line 2405
    move-result v17

    .line 2406
    const/4 v14, 0x2

    .line 2407
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2408
    .line 2409
    .line 2410
    move-result v1

    .line 2411
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2412
    .line 2413
    invoke-virtual {v14, v1}, Lrx/b;->e(F)F

    .line 2414
    .line 2415
    .line 2416
    move-result v1

    .line 2417
    move/from16 v22, v1

    .line 2418
    .line 2419
    const/4 v14, 0x3

    .line 2420
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2421
    .line 2422
    .line 2423
    move-result v1

    .line 2424
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2425
    .line 2426
    invoke-virtual {v14, v1}, Lrx/b;->e(F)F

    .line 2427
    .line 2428
    .line 2429
    move-result v1

    .line 2430
    move/from16 v19, v1

    .line 2431
    .line 2432
    const/4 v14, 0x4

    .line 2433
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2434
    .line 2435
    .line 2436
    move-result v1

    .line 2437
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2438
    .line 2439
    invoke-virtual {v14, v1}, Lrx/b;->e(F)F

    .line 2440
    .line 2441
    .line 2442
    move-result v1

    .line 2443
    const/4 v14, 0x5

    .line 2444
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2445
    .line 2446
    .line 2447
    move-result v6

    .line 2448
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2449
    .line 2450
    invoke-virtual {v14, v6}, Lrx/b;->e(F)F

    .line 2451
    .line 2452
    .line 2453
    move-result v6

    .line 2454
    move/from16 v14, v17

    .line 2455
    .line 2456
    move/from16 v17, v6

    .line 2457
    .line 2458
    move/from16 v6, v19

    .line 2459
    .line 2460
    move/from16 v19, v14

    .line 2461
    .line 2462
    move v14, v1

    .line 2463
    goto :goto_34

    .line 2464
    :cond_6a
    const/4 v1, 0x1

    .line 2465
    invoke-virtual {v6, v1}, Ld5/b;->t(I)F

    .line 2466
    .line 2467
    .line 2468
    move-result v17

    .line 2469
    const/4 v14, 0x2

    .line 2470
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2471
    .line 2472
    .line 2473
    move-result v1

    .line 2474
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2475
    .line 2476
    invoke-virtual {v14, v1}, Lrx/b;->e(F)F

    .line 2477
    .line 2478
    .line 2479
    move-result v1

    .line 2480
    const/4 v14, 0x3

    .line 2481
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2482
    .line 2483
    .line 2484
    move-result v6

    .line 2485
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2486
    .line 2487
    invoke-virtual {v14, v6}, Lrx/b;->e(F)F

    .line 2488
    .line 2489
    .line 2490
    move-result v6

    .line 2491
    move/from16 v22, v1

    .line 2492
    .line 2493
    :goto_33
    move/from16 v19, v17

    .line 2494
    .line 2495
    move/from16 v14, v24

    .line 2496
    .line 2497
    move/from16 v17, v14

    .line 2498
    .line 2499
    goto :goto_34

    .line 2500
    :cond_6b
    const/4 v1, 0x1

    .line 2501
    invoke-virtual {v6, v1}, Ld5/b;->t(I)F

    .line 2502
    .line 2503
    .line 2504
    move-result v17

    .line 2505
    const/4 v14, 0x2

    .line 2506
    invoke-virtual {v6, v14}, Ld5/b;->t(I)F

    .line 2507
    .line 2508
    .line 2509
    move-result v6

    .line 2510
    iget-object v14, v3, Lz4/q;->a:Lrx/b;

    .line 2511
    .line 2512
    invoke-virtual {v14, v6}, Lrx/b;->e(F)F

    .line 2513
    .line 2514
    .line 2515
    move-result v6

    .line 2516
    move/from16 v22, v6

    .line 2517
    .line 2518
    goto :goto_33

    .line 2519
    :cond_6c
    const/4 v1, 0x1

    .line 2520
    invoke-virtual {v6, v1}, Ld5/b;->t(I)F

    .line 2521
    .line 2522
    .line 2523
    move-result v17

    .line 2524
    move/from16 v19, v17

    .line 2525
    .line 2526
    move/from16 v6, v24

    .line 2527
    .line 2528
    move v14, v6

    .line 2529
    move/from16 v17, v14

    .line 2530
    .line 2531
    move/from16 v22, v17

    .line 2532
    .line 2533
    :goto_34
    filled-new-array {v9}, [Ljava/lang/Object;

    .line 2534
    .line 2535
    .line 2536
    move-result-object v1

    .line 2537
    invoke-virtual {v0, v1}, Le5/h;->q([Ljava/lang/Object;)V

    .line 2538
    .line 2539
    .line 2540
    invoke-virtual {v9}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 2541
    .line 2542
    .line 2543
    move-result-object v1

    .line 2544
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->isNaN(F)Z

    .line 2545
    .line 2546
    .line 2547
    move-result v9

    .line 2548
    if-nez v9, :cond_6d

    .line 2549
    .line 2550
    iget-object v9, v0, Lf5/c;->o0:Ljava/util/HashMap;

    .line 2551
    .line 2552
    move/from16 v23, v2

    .line 2553
    .line 2554
    invoke-static/range {v19 .. v19}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2555
    .line 2556
    .line 2557
    move-result-object v2

    .line 2558
    invoke-virtual {v9, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2559
    .line 2560
    .line 2561
    goto :goto_35

    .line 2562
    :cond_6d
    move/from16 v23, v2

    .line 2563
    .line 2564
    :goto_35
    invoke-static/range {v22 .. v22}, Ljava/lang/Float;->isNaN(F)Z

    .line 2565
    .line 2566
    .line 2567
    move-result v2

    .line 2568
    if-nez v2, :cond_6e

    .line 2569
    .line 2570
    iget-object v2, v0, Lf5/c;->p0:Ljava/util/HashMap;

    .line 2571
    .line 2572
    invoke-static/range {v22 .. v22}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2573
    .line 2574
    .line 2575
    move-result-object v9

    .line 2576
    invoke-virtual {v2, v1, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2577
    .line 2578
    .line 2579
    :cond_6e
    invoke-static {v6}, Ljava/lang/Float;->isNaN(F)Z

    .line 2580
    .line 2581
    .line 2582
    move-result v2

    .line 2583
    if-nez v2, :cond_6f

    .line 2584
    .line 2585
    iget-object v2, v0, Lf5/c;->q0:Ljava/util/HashMap;

    .line 2586
    .line 2587
    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2588
    .line 2589
    .line 2590
    move-result-object v6

    .line 2591
    invoke-virtual {v2, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2592
    .line 2593
    .line 2594
    :cond_6f
    invoke-static {v14}, Ljava/lang/Float;->isNaN(F)Z

    .line 2595
    .line 2596
    .line 2597
    move-result v2

    .line 2598
    if-nez v2, :cond_71

    .line 2599
    .line 2600
    iget-object v2, v0, Lf5/c;->r0:Ljava/util/HashMap;

    .line 2601
    .line 2602
    if-nez v2, :cond_70

    .line 2603
    .line 2604
    new-instance v2, Ljava/util/HashMap;

    .line 2605
    .line 2606
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 2607
    .line 2608
    .line 2609
    iput-object v2, v0, Lf5/c;->r0:Ljava/util/HashMap;

    .line 2610
    .line 2611
    :cond_70
    iget-object v2, v0, Lf5/c;->r0:Ljava/util/HashMap;

    .line 2612
    .line 2613
    invoke-static {v14}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2614
    .line 2615
    .line 2616
    move-result-object v6

    .line 2617
    invoke-virtual {v2, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2618
    .line 2619
    .line 2620
    :cond_71
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->isNaN(F)Z

    .line 2621
    .line 2622
    .line 2623
    move-result v2

    .line 2624
    if-nez v2, :cond_75

    .line 2625
    .line 2626
    iget-object v2, v0, Lf5/c;->s0:Ljava/util/HashMap;

    .line 2627
    .line 2628
    if-nez v2, :cond_72

    .line 2629
    .line 2630
    new-instance v2, Ljava/util/HashMap;

    .line 2631
    .line 2632
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 2633
    .line 2634
    .line 2635
    iput-object v2, v0, Lf5/c;->s0:Ljava/util/HashMap;

    .line 2636
    .line 2637
    :cond_72
    iget-object v2, v0, Lf5/c;->s0:Ljava/util/HashMap;

    .line 2638
    .line 2639
    invoke-static/range {v17 .. v17}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 2640
    .line 2641
    .line 2642
    move-result-object v6

    .line 2643
    invoke-virtual {v2, v1, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2644
    .line 2645
    .line 2646
    goto :goto_36

    .line 2647
    :cond_73
    move-object/from16 v16, v1

    .line 2648
    .line 2649
    move/from16 v23, v2

    .line 2650
    .line 2651
    goto :goto_36

    .line 2652
    :cond_74
    move-object/from16 v16, v1

    .line 2653
    .line 2654
    move/from16 v23, v2

    .line 2655
    .line 2656
    invoke-virtual {v6}, Ld5/c;->e()Ljava/lang/String;

    .line 2657
    .line 2658
    .line 2659
    move-result-object v1

    .line 2660
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 2661
    .line 2662
    .line 2663
    move-result-object v1

    .line 2664
    invoke-virtual {v0, v1}, Le5/h;->q([Ljava/lang/Object;)V

    .line 2665
    .line 2666
    .line 2667
    :cond_75
    :goto_36
    add-int/lit8 v2, v23, 0x1

    .line 2668
    .line 2669
    move-object/from16 v1, v16

    .line 2670
    .line 2671
    goto/16 :goto_32

    .line 2672
    .line 2673
    :cond_76
    :goto_37
    sget-object v0, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 2674
    .line 2675
    invoke-static {v7, v5}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2676
    .line 2677
    .line 2678
    move-result-object v1

    .line 2679
    invoke-virtual {v2}, Ld5/c;->e()Ljava/lang/String;

    .line 2680
    .line 2681
    .line 2682
    move-result-object v2

    .line 2683
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2684
    .line 2685
    .line 2686
    move-object/from16 v4, v28

    .line 2687
    .line 2688
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2689
    .line 2690
    .line 2691
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 2692
    .line 2693
    .line 2694
    move-result-object v1

    .line 2695
    invoke-virtual {v0, v1}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 2696
    .line 2697
    .line 2698
    :cond_77
    :goto_38
    move-object/from16 v1, v31

    .line 2699
    .line 2700
    goto/16 :goto_48

    .line 2701
    .line 2702
    :pswitch_1f
    move-object/from16 v16, v1

    .line 2703
    .line 2704
    move-object/from16 v4, v28

    .line 2705
    .line 2706
    move-object/from16 v1, v31

    .line 2707
    .line 2708
    invoke-static {v8, v0, v1, v2, v3}, Lkp/b0;->e(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 2709
    .line 2710
    .line 2711
    :goto_39
    move-object/from16 v31, v1

    .line 2712
    .line 2713
    move-object/from16 v28, v4

    .line 2714
    .line 2715
    move-object/from16 v1, v16

    .line 2716
    .line 2717
    goto/16 :goto_2d

    .line 2718
    .line 2719
    :pswitch_20
    move-object/from16 v27, v1

    .line 2720
    .line 2721
    move-object v1, v4

    .line 2722
    move-object/from16 v29, v6

    .line 2723
    .line 2724
    const/16 v18, 0x5

    .line 2725
    .line 2726
    const/16 v19, 0x4

    .line 2727
    .line 2728
    invoke-virtual {v3, v7}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 2729
    .line 2730
    .line 2731
    move-result-object v2

    .line 2732
    iget-object v4, v2, Le5/b;->c:Ljava/lang/Object;

    .line 2733
    .line 2734
    if-eqz v4, :cond_78

    .line 2735
    .line 2736
    instance-of v4, v4, Lf5/f;

    .line 2737
    .line 2738
    if-nez v4, :cond_7b

    .line 2739
    .line 2740
    :cond_78
    const/4 v4, 0x0

    .line 2741
    invoke-virtual {v0, v4}, Ljava/lang/String;->charAt(I)C

    .line 2742
    .line 2743
    .line 2744
    move-result v5

    .line 2745
    const/16 v6, 0x72

    .line 2746
    .line 2747
    if-ne v5, v6, :cond_79

    .line 2748
    .line 2749
    const/16 v0, 0xa

    .line 2750
    .line 2751
    goto :goto_3a

    .line 2752
    :cond_79
    invoke-virtual {v0, v4}, Ljava/lang/String;->charAt(I)C

    .line 2753
    .line 2754
    .line 2755
    move-result v0

    .line 2756
    const/16 v4, 0x63

    .line 2757
    .line 2758
    if-ne v0, v4, :cond_7a

    .line 2759
    .line 2760
    const/16 v0, 0xb

    .line 2761
    .line 2762
    goto :goto_3a

    .line 2763
    :cond_7a
    const/16 v0, 0x9

    .line 2764
    .line 2765
    :goto_3a
    new-instance v4, Lf5/f;

    .line 2766
    .line 2767
    invoke-direct {v4, v3, v0}, Lf5/f;-><init>(Lz4/q;I)V

    .line 2768
    .line 2769
    .line 2770
    iput-object v4, v2, Le5/b;->c:Ljava/lang/Object;

    .line 2771
    .line 2772
    invoke-virtual {v4}, Le5/h;->b()Lh5/d;

    .line 2773
    .line 2774
    .line 2775
    move-result-object v0

    .line 2776
    invoke-virtual {v2, v0}, Le5/b;->a(Lh5/d;)V

    .line 2777
    .line 2778
    .line 2779
    :cond_7b
    iget-object v0, v2, Le5/b;->c:Ljava/lang/Object;

    .line 2780
    .line 2781
    move-object v2, v0

    .line 2782
    check-cast v2, Lf5/f;

    .line 2783
    .line 2784
    invoke-virtual {v8}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 2785
    .line 2786
    .line 2787
    move-result-object v0

    .line 2788
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2789
    .line 2790
    .line 2791
    move-result-object v4

    .line 2792
    :goto_3b
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 2793
    .line 2794
    .line 2795
    move-result v0

    .line 2796
    if-eqz v0, :cond_95

    .line 2797
    .line 2798
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2799
    .line 2800
    .line 2801
    move-result-object v0

    .line 2802
    check-cast v0, Ljava/lang/String;

    .line 2803
    .line 2804
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2805
    .line 2806
    .line 2807
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 2808
    .line 2809
    .line 2810
    move-result v5

    .line 2811
    sparse-switch v5, :sswitch_data_7

    .line 2812
    .line 2813
    .line 2814
    :goto_3c
    const/4 v5, -0x1

    .line 2815
    goto/16 :goto_3d

    .line 2816
    .line 2817
    :sswitch_2e
    const-string v5, "columnWeights"

    .line 2818
    .line 2819
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2820
    .line 2821
    .line 2822
    move-result v5

    .line 2823
    if-nez v5, :cond_7c

    .line 2824
    .line 2825
    goto :goto_3c

    .line 2826
    :cond_7c
    const/16 v5, 0xb

    .line 2827
    .line 2828
    goto/16 :goto_3d

    .line 2829
    .line 2830
    :sswitch_2f
    const-string v5, "columns"

    .line 2831
    .line 2832
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2833
    .line 2834
    .line 2835
    move-result v5

    .line 2836
    if-nez v5, :cond_7d

    .line 2837
    .line 2838
    goto :goto_3c

    .line 2839
    :cond_7d
    const/16 v5, 0xa

    .line 2840
    .line 2841
    goto/16 :goto_3d

    .line 2842
    .line 2843
    :sswitch_30
    const-string v5, "rowWeights"

    .line 2844
    .line 2845
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2846
    .line 2847
    .line 2848
    move-result v5

    .line 2849
    if-nez v5, :cond_7e

    .line 2850
    .line 2851
    goto :goto_3c

    .line 2852
    :cond_7e
    const/16 v5, 0x9

    .line 2853
    .line 2854
    goto/16 :goto_3d

    .line 2855
    .line 2856
    :sswitch_31
    const-string v5, "spans"

    .line 2857
    .line 2858
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2859
    .line 2860
    .line 2861
    move-result v5

    .line 2862
    if-nez v5, :cond_7f

    .line 2863
    .line 2864
    goto :goto_3c

    .line 2865
    :cond_7f
    const/16 v5, 0x8

    .line 2866
    .line 2867
    goto/16 :goto_3d

    .line 2868
    .line 2869
    :sswitch_32
    const-string v5, "skips"

    .line 2870
    .line 2871
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2872
    .line 2873
    .line 2874
    move-result v5

    .line 2875
    if-nez v5, :cond_80

    .line 2876
    .line 2877
    goto :goto_3c

    .line 2878
    :cond_80
    const/4 v5, 0x7

    .line 2879
    goto :goto_3d

    .line 2880
    :sswitch_33
    const-string v5, "flags"

    .line 2881
    .line 2882
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2883
    .line 2884
    .line 2885
    move-result v5

    .line 2886
    if-nez v5, :cond_81

    .line 2887
    .line 2888
    goto :goto_3c

    .line 2889
    :cond_81
    const/4 v5, 0x6

    .line 2890
    goto :goto_3d

    .line 2891
    :sswitch_34
    const-string v5, "vGap"

    .line 2892
    .line 2893
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2894
    .line 2895
    .line 2896
    move-result v5

    .line 2897
    if-nez v5, :cond_82

    .line 2898
    .line 2899
    goto :goto_3c

    .line 2900
    :cond_82
    move/from16 v5, v18

    .line 2901
    .line 2902
    goto :goto_3d

    .line 2903
    :sswitch_35
    const-string v5, "rows"

    .line 2904
    .line 2905
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2906
    .line 2907
    .line 2908
    move-result v5

    .line 2909
    if-nez v5, :cond_83

    .line 2910
    .line 2911
    goto :goto_3c

    .line 2912
    :cond_83
    move/from16 v5, v19

    .line 2913
    .line 2914
    goto :goto_3d

    .line 2915
    :sswitch_36
    const-string v5, "hGap"

    .line 2916
    .line 2917
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2918
    .line 2919
    .line 2920
    move-result v5

    .line 2921
    if-nez v5, :cond_84

    .line 2922
    .line 2923
    goto :goto_3c

    .line 2924
    :cond_84
    const/4 v5, 0x3

    .line 2925
    goto :goto_3d

    .line 2926
    :sswitch_37
    invoke-virtual {v0, v15}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2927
    .line 2928
    .line 2929
    move-result v5

    .line 2930
    if-nez v5, :cond_85

    .line 2931
    .line 2932
    goto :goto_3c

    .line 2933
    :cond_85
    const/4 v5, 0x2

    .line 2934
    goto :goto_3d

    .line 2935
    :sswitch_38
    const-string v5, "padding"

    .line 2936
    .line 2937
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2938
    .line 2939
    .line 2940
    move-result v5

    .line 2941
    if-nez v5, :cond_86

    .line 2942
    .line 2943
    goto/16 :goto_3c

    .line 2944
    .line 2945
    :cond_86
    const/4 v5, 0x1

    .line 2946
    goto :goto_3d

    .line 2947
    :sswitch_39
    const-string v5, "orientation"

    .line 2948
    .line 2949
    invoke-virtual {v0, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2950
    .line 2951
    .line 2952
    move-result v5

    .line 2953
    if-nez v5, :cond_87

    .line 2954
    .line 2955
    goto/16 :goto_3c

    .line 2956
    .line 2957
    :cond_87
    const/4 v5, 0x0

    .line 2958
    :goto_3d
    const-string v6, ":"

    .line 2959
    .line 2960
    const-string v9, ","

    .line 2961
    .line 2962
    packed-switch v5, :pswitch_data_8

    .line 2963
    .line 2964
    .line 2965
    invoke-virtual {v3, v7}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 2966
    .line 2967
    .line 2968
    move-result-object v5

    .line 2969
    invoke-static {v8, v5, v1, v0, v3}, Lkp/b0;->c(Ld5/f;Le5/b;Le5/f;Ljava/lang/String;Lz4/q;)V

    .line 2970
    .line 2971
    .line 2972
    :cond_88
    :goto_3e
    const/16 v10, 0xa

    .line 2973
    .line 2974
    :cond_89
    :goto_3f
    const/4 v12, 0x3

    .line 2975
    const/4 v13, 0x2

    .line 2976
    goto/16 :goto_3b

    .line 2977
    .line 2978
    :pswitch_21
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 2979
    .line 2980
    .line 2981
    move-result-object v0

    .line 2982
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 2983
    .line 2984
    .line 2985
    move-result-object v0

    .line 2986
    if-eqz v0, :cond_88

    .line 2987
    .line 2988
    invoke-virtual {v0, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 2989
    .line 2990
    .line 2991
    move-result v5

    .line 2992
    if-eqz v5, :cond_88

    .line 2993
    .line 2994
    iput-object v0, v2, Lf5/f;->y0:Ljava/lang/String;

    .line 2995
    .line 2996
    goto :goto_3e

    .line 2997
    :pswitch_22
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 2998
    .line 2999
    .line 3000
    move-result-object v0

    .line 3001
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3002
    .line 3003
    .line 3004
    move-result v0

    .line 3005
    if-lez v0, :cond_88

    .line 3006
    .line 3007
    iget v5, v2, Le5/h;->l0:I

    .line 3008
    .line 3009
    const/16 v10, 0xa

    .line 3010
    .line 3011
    if-ne v5, v10, :cond_8a

    .line 3012
    .line 3013
    goto :goto_3f

    .line 3014
    :cond_8a
    iput v0, v2, Lf5/f;->u0:I

    .line 3015
    .line 3016
    goto :goto_3f

    .line 3017
    :pswitch_23
    const/16 v10, 0xa

    .line 3018
    .line 3019
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3020
    .line 3021
    .line 3022
    move-result-object v0

    .line 3023
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 3024
    .line 3025
    .line 3026
    move-result-object v0

    .line 3027
    if-eqz v0, :cond_89

    .line 3028
    .line 3029
    invoke-virtual {v0, v9}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 3030
    .line 3031
    .line 3032
    move-result v5

    .line 3033
    if-eqz v5, :cond_89

    .line 3034
    .line 3035
    iput-object v0, v2, Lf5/f;->x0:Ljava/lang/String;

    .line 3036
    .line 3037
    goto :goto_3f

    .line 3038
    :pswitch_24
    const/16 v10, 0xa

    .line 3039
    .line 3040
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3041
    .line 3042
    .line 3043
    move-result-object v0

    .line 3044
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 3045
    .line 3046
    .line 3047
    move-result-object v0

    .line 3048
    if-eqz v0, :cond_89

    .line 3049
    .line 3050
    invoke-virtual {v0, v6}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 3051
    .line 3052
    .line 3053
    move-result v5

    .line 3054
    if-eqz v5, :cond_89

    .line 3055
    .line 3056
    iput-object v0, v2, Lf5/f;->z0:Ljava/lang/String;

    .line 3057
    .line 3058
    goto :goto_3f

    .line 3059
    :pswitch_25
    const/16 v10, 0xa

    .line 3060
    .line 3061
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3062
    .line 3063
    .line 3064
    move-result-object v0

    .line 3065
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 3066
    .line 3067
    .line 3068
    move-result-object v0

    .line 3069
    if-eqz v0, :cond_89

    .line 3070
    .line 3071
    invoke-virtual {v0, v6}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 3072
    .line 3073
    .line 3074
    move-result v5

    .line 3075
    if-eqz v5, :cond_89

    .line 3076
    .line 3077
    iput-object v0, v2, Lf5/f;->A0:Ljava/lang/String;

    .line 3078
    .line 3079
    goto :goto_3f

    .line 3080
    :pswitch_26
    const/16 v10, 0xa

    .line 3081
    .line 3082
    :try_start_3
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3083
    .line 3084
    .line 3085
    move-result-object v0

    .line 3086
    instance-of v5, v0, Ld5/e;

    .line 3087
    .line 3088
    if-eqz v5, :cond_8b

    .line 3089
    .line 3090
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3091
    .line 3092
    .line 3093
    move-result v0

    .line 3094
    move v5, v0

    .line 3095
    move-object v0, v14

    .line 3096
    goto :goto_42

    .line 3097
    :catch_3
    move-exception v0

    .line 3098
    goto :goto_40

    .line 3099
    :cond_8b
    invoke-virtual {v0}, Ld5/c;->e()Ljava/lang/String;

    .line 3100
    .line 3101
    .line 3102
    move-result-object v0
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 3103
    goto :goto_41

    .line 3104
    :goto_40
    sget-object v5, Ljava/lang/System;->err:Ljava/io/PrintStream;

    .line 3105
    .line 3106
    new-instance v6, Ljava/lang/StringBuilder;

    .line 3107
    .line 3108
    const-string v9, "Error parsing grid flags "

    .line 3109
    .line 3110
    invoke-direct {v6, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3111
    .line 3112
    .line 3113
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 3114
    .line 3115
    .line 3116
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3117
    .line 3118
    .line 3119
    move-result-object v0

    .line 3120
    invoke-virtual {v5, v0}, Ljava/io/PrintStream;->println(Ljava/lang/String;)V

    .line 3121
    .line 3122
    .line 3123
    move-object v0, v14

    .line 3124
    :goto_41
    const/4 v5, 0x0

    .line 3125
    :goto_42
    if-eqz v0, :cond_8f

    .line 3126
    .line 3127
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 3128
    .line 3129
    .line 3130
    move-result v6

    .line 3131
    if-nez v6, :cond_8f

    .line 3132
    .line 3133
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3134
    .line 3135
    .line 3136
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 3137
    .line 3138
    .line 3139
    move-result v5

    .line 3140
    if-eqz v5, :cond_8c

    .line 3141
    .line 3142
    goto/16 :goto_3f

    .line 3143
    .line 3144
    :cond_8c
    const-string v5, "\\|"

    .line 3145
    .line 3146
    invoke-virtual {v0, v5}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 3147
    .line 3148
    .line 3149
    move-result-object v0

    .line 3150
    const/4 v6, 0x0

    .line 3151
    iput v6, v2, Lf5/f;->B0:I

    .line 3152
    .line 3153
    array-length v5, v0

    .line 3154
    const/4 v6, 0x0

    .line 3155
    :goto_43
    if-ge v6, v5, :cond_89

    .line 3156
    .line 3157
    aget-object v9, v0, v6

    .line 3158
    .line 3159
    invoke-virtual {v9}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    .line 3160
    .line 3161
    .line 3162
    move-result-object v9

    .line 3163
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3164
    .line 3165
    .line 3166
    const-string v11, "subgridbycolrow"

    .line 3167
    .line 3168
    invoke-virtual {v9, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 3169
    .line 3170
    .line 3171
    move-result v11

    .line 3172
    if-nez v11, :cond_8e

    .line 3173
    .line 3174
    const-string v11, "spansrespectwidgetorder"

    .line 3175
    .line 3176
    invoke-virtual {v9, v11}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 3177
    .line 3178
    .line 3179
    move-result v9

    .line 3180
    if-nez v9, :cond_8d

    .line 3181
    .line 3182
    goto :goto_44

    .line 3183
    :cond_8d
    iget v9, v2, Lf5/f;->B0:I

    .line 3184
    .line 3185
    const/16 v20, 0x2

    .line 3186
    .line 3187
    or-int/lit8 v9, v9, 0x2

    .line 3188
    .line 3189
    iput v9, v2, Lf5/f;->B0:I

    .line 3190
    .line 3191
    goto :goto_44

    .line 3192
    :cond_8e
    iget v9, v2, Lf5/f;->B0:I

    .line 3193
    .line 3194
    const/16 v21, 0x1

    .line 3195
    .line 3196
    or-int/lit8 v9, v9, 0x1

    .line 3197
    .line 3198
    iput v9, v2, Lf5/f;->B0:I

    .line 3199
    .line 3200
    :goto_44
    add-int/lit8 v6, v6, 0x1

    .line 3201
    .line 3202
    goto :goto_43

    .line 3203
    :cond_8f
    iput v5, v2, Lf5/f;->B0:I

    .line 3204
    .line 3205
    goto/16 :goto_3f

    .line 3206
    .line 3207
    :pswitch_27
    const/16 v10, 0xa

    .line 3208
    .line 3209
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3210
    .line 3211
    .line 3212
    move-result-object v0

    .line 3213
    invoke-virtual {v0}, Ld5/c;->i()F

    .line 3214
    .line 3215
    .line 3216
    move-result v0

    .line 3217
    iget-object v5, v3, Lz4/q;->a:Lrx/b;

    .line 3218
    .line 3219
    invoke-virtual {v5, v0}, Lrx/b;->e(F)F

    .line 3220
    .line 3221
    .line 3222
    move-result v0

    .line 3223
    iput v0, v2, Lf5/f;->w0:F

    .line 3224
    .line 3225
    goto/16 :goto_3f

    .line 3226
    .line 3227
    :pswitch_28
    const/16 v10, 0xa

    .line 3228
    .line 3229
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3230
    .line 3231
    .line 3232
    move-result-object v0

    .line 3233
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3234
    .line 3235
    .line 3236
    move-result v0

    .line 3237
    if-lez v0, :cond_89

    .line 3238
    .line 3239
    iget v5, v2, Le5/h;->l0:I

    .line 3240
    .line 3241
    const/16 v6, 0xb

    .line 3242
    .line 3243
    if-ne v5, v6, :cond_90

    .line 3244
    .line 3245
    goto/16 :goto_3f

    .line 3246
    .line 3247
    :cond_90
    iput v0, v2, Lf5/f;->t0:I

    .line 3248
    .line 3249
    goto/16 :goto_3f

    .line 3250
    .line 3251
    :pswitch_29
    const/16 v6, 0xb

    .line 3252
    .line 3253
    const/16 v10, 0xa

    .line 3254
    .line 3255
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3256
    .line 3257
    .line 3258
    move-result-object v0

    .line 3259
    invoke-virtual {v0}, Ld5/c;->i()F

    .line 3260
    .line 3261
    .line 3262
    move-result v0

    .line 3263
    iget-object v5, v3, Lz4/q;->a:Lrx/b;

    .line 3264
    .line 3265
    invoke-virtual {v5, v0}, Lrx/b;->e(F)F

    .line 3266
    .line 3267
    .line 3268
    move-result v0

    .line 3269
    iput v0, v2, Lf5/f;->v0:F

    .line 3270
    .line 3271
    goto/16 :goto_3f

    .line 3272
    .line 3273
    :pswitch_2a
    const/16 v6, 0xb

    .line 3274
    .line 3275
    const/16 v10, 0xa

    .line 3276
    .line 3277
    invoke-virtual {v8, v0}, Ld5/b;->x(Ljava/lang/String;)Ld5/c;

    .line 3278
    .line 3279
    .line 3280
    move-result-object v0

    .line 3281
    instance-of v5, v0, Ld5/a;

    .line 3282
    .line 3283
    if-eqz v5, :cond_91

    .line 3284
    .line 3285
    check-cast v0, Ld5/a;

    .line 3286
    .line 3287
    goto :goto_45

    .line 3288
    :cond_91
    const/4 v0, 0x0

    .line 3289
    :goto_45
    if-eqz v0, :cond_89

    .line 3290
    .line 3291
    const/4 v5, 0x0

    .line 3292
    :goto_46
    iget-object v9, v0, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3293
    .line 3294
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 3295
    .line 3296
    .line 3297
    move-result v9

    .line 3298
    if-ge v5, v9, :cond_89

    .line 3299
    .line 3300
    invoke-virtual {v0, v5}, Ld5/b;->r(I)Ld5/c;

    .line 3301
    .line 3302
    .line 3303
    move-result-object v9

    .line 3304
    invoke-virtual {v9}, Ld5/c;->e()Ljava/lang/String;

    .line 3305
    .line 3306
    .line 3307
    move-result-object v9

    .line 3308
    invoke-virtual {v3, v9}, Lz4/q;->b(Ljava/lang/Object;)Le5/b;

    .line 3309
    .line 3310
    .line 3311
    move-result-object v9

    .line 3312
    filled-new-array {v9}, [Ljava/lang/Object;

    .line 3313
    .line 3314
    .line 3315
    move-result-object v9

    .line 3316
    invoke-virtual {v2, v9}, Le5/h;->q([Ljava/lang/Object;)V

    .line 3317
    .line 3318
    .line 3319
    add-int/lit8 v5, v5, 0x1

    .line 3320
    .line 3321
    goto :goto_46

    .line 3322
    :pswitch_2b
    const/16 v6, 0xb

    .line 3323
    .line 3324
    const/16 v10, 0xa

    .line 3325
    .line 3326
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3327
    .line 3328
    .line 3329
    move-result-object v0

    .line 3330
    instance-of v5, v0, Ld5/a;

    .line 3331
    .line 3332
    if-eqz v5, :cond_93

    .line 3333
    .line 3334
    move-object v5, v0

    .line 3335
    check-cast v5, Ld5/a;

    .line 3336
    .line 3337
    iget-object v9, v5, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3338
    .line 3339
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 3340
    .line 3341
    .line 3342
    move-result v9

    .line 3343
    const/4 v11, 0x1

    .line 3344
    if-le v9, v11, :cond_93

    .line 3345
    .line 3346
    const/4 v9, 0x0

    .line 3347
    invoke-virtual {v5, v9}, Ld5/b;->v(I)I

    .line 3348
    .line 3349
    .line 3350
    move-result v12

    .line 3351
    int-to-float v9, v12

    .line 3352
    invoke-virtual {v5, v11}, Ld5/b;->v(I)I

    .line 3353
    .line 3354
    .line 3355
    move-result v12

    .line 3356
    int-to-float v11, v12

    .line 3357
    iget-object v12, v5, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3358
    .line 3359
    invoke-virtual {v12}, Ljava/util/ArrayList;->size()I

    .line 3360
    .line 3361
    .line 3362
    move-result v12

    .line 3363
    const/4 v13, 0x2

    .line 3364
    if-le v12, v13, :cond_92

    .line 3365
    .line 3366
    invoke-virtual {v5, v13}, Ld5/b;->v(I)I

    .line 3367
    .line 3368
    .line 3369
    move-result v5

    .line 3370
    int-to-float v5, v5

    .line 3371
    :try_start_4
    check-cast v0, Ld5/a;
    :try_end_4
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_4 .. :try_end_4} :catch_4

    .line 3372
    .line 3373
    const/4 v12, 0x3

    .line 3374
    :try_start_5
    invoke-virtual {v0, v12}, Ld5/b;->v(I)I

    .line 3375
    .line 3376
    .line 3377
    move-result v0
    :try_end_5
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_5 .. :try_end_5} :catch_5

    .line 3378
    int-to-float v0, v0

    .line 3379
    goto :goto_47

    .line 3380
    :catch_4
    const/4 v12, 0x3

    .line 3381
    :catch_5
    const/4 v0, 0x0

    .line 3382
    goto :goto_47

    .line 3383
    :cond_92
    const/4 v12, 0x3

    .line 3384
    move v5, v9

    .line 3385
    move v0, v11

    .line 3386
    goto :goto_47

    .line 3387
    :cond_93
    const/4 v12, 0x3

    .line 3388
    const/4 v13, 0x2

    .line 3389
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3390
    .line 3391
    .line 3392
    move-result v0

    .line 3393
    int-to-float v9, v0

    .line 3394
    move v0, v9

    .line 3395
    move v5, v0

    .line 3396
    move v11, v5

    .line 3397
    :goto_47
    iget-object v6, v3, Lz4/q;->a:Lrx/b;

    .line 3398
    .line 3399
    invoke-virtual {v6, v9}, Lrx/b;->e(F)F

    .line 3400
    .line 3401
    .line 3402
    move-result v6

    .line 3403
    invoke-static {v6}, Ljava/lang/Math;->round(F)I

    .line 3404
    .line 3405
    .line 3406
    move-result v6

    .line 3407
    iput v6, v2, Lf5/f;->o0:I

    .line 3408
    .line 3409
    iget-object v6, v3, Lz4/q;->a:Lrx/b;

    .line 3410
    .line 3411
    invoke-virtual {v6, v11}, Lrx/b;->e(F)F

    .line 3412
    .line 3413
    .line 3414
    move-result v6

    .line 3415
    invoke-static {v6}, Ljava/lang/Math;->round(F)I

    .line 3416
    .line 3417
    .line 3418
    move-result v6

    .line 3419
    iput v6, v2, Lf5/f;->q0:I

    .line 3420
    .line 3421
    iget-object v6, v3, Lz4/q;->a:Lrx/b;

    .line 3422
    .line 3423
    invoke-virtual {v6, v5}, Lrx/b;->e(F)F

    .line 3424
    .line 3425
    .line 3426
    move-result v5

    .line 3427
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 3428
    .line 3429
    .line 3430
    move-result v5

    .line 3431
    iput v5, v2, Lf5/f;->p0:I

    .line 3432
    .line 3433
    iget-object v5, v3, Lz4/q;->a:Lrx/b;

    .line 3434
    .line 3435
    invoke-virtual {v5, v0}, Lrx/b;->e(F)F

    .line 3436
    .line 3437
    .line 3438
    move-result v0

    .line 3439
    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    .line 3440
    .line 3441
    .line 3442
    move-result v0

    .line 3443
    iput v0, v2, Lf5/f;->r0:I

    .line 3444
    .line 3445
    goto/16 :goto_3b

    .line 3446
    .line 3447
    :pswitch_2c
    const/16 v10, 0xa

    .line 3448
    .line 3449
    const/4 v12, 0x3

    .line 3450
    const/4 v13, 0x2

    .line 3451
    invoke-virtual {v8, v0}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3452
    .line 3453
    .line 3454
    move-result-object v0

    .line 3455
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3456
    .line 3457
    .line 3458
    move-result v0

    .line 3459
    iput v0, v2, Lf5/f;->s0:I

    .line 3460
    .line 3461
    goto/16 :goto_3b

    .line 3462
    .line 3463
    :pswitch_2d
    move-object/from16 v27, v1

    .line 3464
    .line 3465
    move-object v1, v4

    .line 3466
    move-object/from16 v29, v6

    .line 3467
    .line 3468
    const/4 v6, 0x1

    .line 3469
    invoke-static {v6, v3, v7, v8}, Lkp/b0;->h(ILz4/q;Ljava/lang/String;Ld5/f;)V

    .line 3470
    .line 3471
    .line 3472
    goto :goto_48

    .line 3473
    :cond_94
    move-object/from16 v27, v1

    .line 3474
    .line 3475
    move-object v1, v4

    .line 3476
    move-object/from16 v29, v6

    .line 3477
    .line 3478
    invoke-static {v3, v1, v7, v8}, Lkp/b0;->i(Lz4/q;Le5/f;Ljava/lang/String;Ld5/f;)V

    .line 3479
    .line 3480
    .line 3481
    :cond_95
    :goto_48
    const/4 v9, 0x0

    .line 3482
    goto/16 :goto_56

    .line 3483
    .line 3484
    :cond_96
    move-object/from16 v27, v1

    .line 3485
    .line 3486
    move-object v1, v4

    .line 3487
    move-object/from16 v29, v6

    .line 3488
    .line 3489
    instance-of v2, v0, Ld5/e;

    .line 3490
    .line 3491
    if-eqz v2, :cond_95

    .line 3492
    .line 3493
    invoke-virtual {v0}, Ld5/c;->k()I

    .line 3494
    .line 3495
    .line 3496
    move-result v0

    .line 3497
    iget-object v2, v1, Le5/f;->a:Ljava/util/HashMap;

    .line 3498
    .line 3499
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3500
    .line 3501
    .line 3502
    move-result-object v0

    .line 3503
    invoke-virtual {v2, v7, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3504
    .line 3505
    .line 3506
    goto :goto_48

    .line 3507
    :pswitch_2e
    move-object/from16 v27, v1

    .line 3508
    .line 3509
    move-object v1, v4

    .line 3510
    move-object/from16 v29, v6

    .line 3511
    .line 3512
    instance-of v2, v0, Ld5/f;

    .line 3513
    .line 3514
    if-eqz v2, :cond_95

    .line 3515
    .line 3516
    check-cast v0, Ld5/f;

    .line 3517
    .line 3518
    invoke-virtual {v0}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 3519
    .line 3520
    .line 3521
    move-result-object v2

    .line 3522
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 3523
    .line 3524
    .line 3525
    move-result-object v2

    .line 3526
    :cond_97
    :goto_49
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 3527
    .line 3528
    .line 3529
    move-result v4

    .line 3530
    if-eqz v4, :cond_95

    .line 3531
    .line 3532
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 3533
    .line 3534
    .line 3535
    move-result-object v4

    .line 3536
    check-cast v4, Ljava/lang/String;

    .line 3537
    .line 3538
    invoke-virtual {v0, v4}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3539
    .line 3540
    .line 3541
    move-result-object v5

    .line 3542
    instance-of v6, v5, Ld5/e;

    .line 3543
    .line 3544
    if-eqz v6, :cond_99

    .line 3545
    .line 3546
    invoke-virtual {v5}, Ld5/c;->k()I

    .line 3547
    .line 3548
    .line 3549
    move-result v5

    .line 3550
    iget-object v6, v1, Le5/f;->a:Ljava/util/HashMap;

    .line 3551
    .line 3552
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3553
    .line 3554
    .line 3555
    move-result-object v5

    .line 3556
    invoke-virtual {v6, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3557
    .line 3558
    .line 3559
    :cond_98
    const/4 v11, 0x0

    .line 3560
    goto :goto_49

    .line 3561
    :cond_99
    instance-of v6, v5, Ld5/f;

    .line 3562
    .line 3563
    if-eqz v6, :cond_98

    .line 3564
    .line 3565
    check-cast v5, Ld5/f;

    .line 3566
    .line 3567
    const-string v6, "from"

    .line 3568
    .line 3569
    invoke-virtual {v5, v6}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3570
    .line 3571
    .line 3572
    move-result v7

    .line 3573
    if-eqz v7, :cond_9e

    .line 3574
    .line 3575
    const-string v7, "to"

    .line 3576
    .line 3577
    invoke-virtual {v5, v7}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3578
    .line 3579
    .line 3580
    move-result v8

    .line 3581
    if-eqz v8, :cond_9e

    .line 3582
    .line 3583
    invoke-virtual {v5, v6}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3584
    .line 3585
    .line 3586
    move-result-object v6

    .line 3587
    invoke-virtual {v1, v6}, Le5/f;->a(Ld5/c;)F

    .line 3588
    .line 3589
    .line 3590
    move-result v6

    .line 3591
    invoke-virtual {v5, v7}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3592
    .line 3593
    .line 3594
    move-result-object v7

    .line 3595
    invoke-virtual {v1, v7}, Le5/f;->a(Ld5/c;)F

    .line 3596
    .line 3597
    .line 3598
    move-result v7

    .line 3599
    const-string v8, "prefix"

    .line 3600
    .line 3601
    invoke-virtual {v5, v8}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 3602
    .line 3603
    .line 3604
    move-result-object v8

    .line 3605
    const-string v9, "postfix"

    .line 3606
    .line 3607
    invoke-virtual {v5, v9}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 3608
    .line 3609
    .line 3610
    move-result-object v5

    .line 3611
    iget-object v9, v1, Le5/f;->b:Ljava/util/HashMap;

    .line 3612
    .line 3613
    invoke-virtual {v9, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 3614
    .line 3615
    .line 3616
    move-result v10

    .line 3617
    if-eqz v10, :cond_9a

    .line 3618
    .line 3619
    invoke-virtual {v9, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3620
    .line 3621
    .line 3622
    :cond_9a
    new-instance v10, Le5/c;

    .line 3623
    .line 3624
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 3625
    .line 3626
    .line 3627
    const/4 v11, 0x0

    .line 3628
    iput-boolean v11, v10, Le5/c;->a:Z

    .line 3629
    .line 3630
    const/4 v11, 0x0

    .line 3631
    iput v11, v10, Le5/c;->d:F

    .line 3632
    .line 3633
    if-nez v8, :cond_9b

    .line 3634
    .line 3635
    move-object v8, v14

    .line 3636
    :cond_9b
    iput-object v8, v10, Le5/c;->b:Ljava/lang/String;

    .line 3637
    .line 3638
    if-nez v5, :cond_9c

    .line 3639
    .line 3640
    move-object v5, v14

    .line 3641
    :cond_9c
    iput-object v5, v10, Le5/c;->c:Ljava/lang/String;

    .line 3642
    .line 3643
    iput v7, v10, Le5/c;->e:F

    .line 3644
    .line 3645
    invoke-virtual {v9, v4, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3646
    .line 3647
    .line 3648
    iget-object v5, v1, Le5/f;->c:Ljava/util/HashMap;

    .line 3649
    .line 3650
    new-instance v8, Ljava/util/ArrayList;

    .line 3651
    .line 3652
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 3653
    .line 3654
    .line 3655
    float-to-int v6, v6

    .line 3656
    float-to-int v7, v7

    .line 3657
    move v9, v6

    .line 3658
    :goto_4a
    if-gt v6, v7, :cond_9d

    .line 3659
    .line 3660
    new-instance v12, Ljava/lang/StringBuilder;

    .line 3661
    .line 3662
    invoke-direct {v12}, Ljava/lang/StringBuilder;-><init>()V

    .line 3663
    .line 3664
    .line 3665
    iget-object v13, v10, Le5/c;->b:Ljava/lang/String;

    .line 3666
    .line 3667
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3668
    .line 3669
    .line 3670
    invoke-virtual {v12, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 3671
    .line 3672
    .line 3673
    iget-object v13, v10, Le5/c;->c:Ljava/lang/String;

    .line 3674
    .line 3675
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3676
    .line 3677
    .line 3678
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3679
    .line 3680
    .line 3681
    move-result-object v12

    .line 3682
    invoke-virtual {v8, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 3683
    .line 3684
    .line 3685
    const/high16 v12, 0x3f800000    # 1.0f

    .line 3686
    .line 3687
    float-to-int v12, v12

    .line 3688
    add-int/2addr v9, v12

    .line 3689
    add-int/lit8 v6, v6, 0x1

    .line 3690
    .line 3691
    goto :goto_4a

    .line 3692
    :cond_9d
    invoke-virtual {v5, v4, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3693
    .line 3694
    .line 3695
    goto/16 :goto_49

    .line 3696
    .line 3697
    :cond_9e
    const/4 v11, 0x0

    .line 3698
    invoke-virtual {v5, v6}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3699
    .line 3700
    .line 3701
    move-result v7

    .line 3702
    if-eqz v7, :cond_a0

    .line 3703
    .line 3704
    const-string v7, "step"

    .line 3705
    .line 3706
    invoke-virtual {v5, v7}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3707
    .line 3708
    .line 3709
    move-result v8

    .line 3710
    if-eqz v8, :cond_a0

    .line 3711
    .line 3712
    invoke-virtual {v5, v6}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3713
    .line 3714
    .line 3715
    move-result-object v6

    .line 3716
    invoke-virtual {v1, v6}, Le5/f;->a(Ld5/c;)F

    .line 3717
    .line 3718
    .line 3719
    move-result v6

    .line 3720
    invoke-virtual {v5, v7}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3721
    .line 3722
    .line 3723
    move-result-object v5

    .line 3724
    invoke-virtual {v1, v5}, Le5/f;->a(Ld5/c;)F

    .line 3725
    .line 3726
    .line 3727
    move-result v5

    .line 3728
    iget-object v7, v1, Le5/f;->b:Ljava/util/HashMap;

    .line 3729
    .line 3730
    invoke-virtual {v7, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 3731
    .line 3732
    .line 3733
    move-result v8

    .line 3734
    if-eqz v8, :cond_9f

    .line 3735
    .line 3736
    invoke-virtual {v7, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3737
    .line 3738
    .line 3739
    :cond_9f
    new-instance v8, Le5/e;

    .line 3740
    .line 3741
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 3742
    .line 3743
    .line 3744
    iput v5, v8, Le5/e;->a:F

    .line 3745
    .line 3746
    iput v6, v8, Le5/e;->b:F

    .line 3747
    .line 3748
    invoke-virtual {v7, v4, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3749
    .line 3750
    .line 3751
    goto/16 :goto_49

    .line 3752
    .line 3753
    :cond_a0
    const-string v6, "ids"

    .line 3754
    .line 3755
    invoke-virtual {v5, v6}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3756
    .line 3757
    .line 3758
    move-result v7

    .line 3759
    if-eqz v7, :cond_a3

    .line 3760
    .line 3761
    invoke-virtual {v5, v6}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3762
    .line 3763
    .line 3764
    move-result-object v6

    .line 3765
    instance-of v7, v6, Ld5/a;

    .line 3766
    .line 3767
    if-eqz v7, :cond_a2

    .line 3768
    .line 3769
    check-cast v6, Ld5/a;

    .line 3770
    .line 3771
    new-instance v5, Ljava/util/ArrayList;

    .line 3772
    .line 3773
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 3774
    .line 3775
    .line 3776
    const/4 v7, 0x0

    .line 3777
    :goto_4b
    iget-object v8, v6, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3778
    .line 3779
    invoke-virtual {v8}, Ljava/util/ArrayList;->size()I

    .line 3780
    .line 3781
    .line 3782
    move-result v8

    .line 3783
    if-ge v7, v8, :cond_a1

    .line 3784
    .line 3785
    invoke-virtual {v6, v7}, Ld5/b;->y(I)Ljava/lang/String;

    .line 3786
    .line 3787
    .line 3788
    move-result-object v8

    .line 3789
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 3790
    .line 3791
    .line 3792
    add-int/lit8 v7, v7, 0x1

    .line 3793
    .line 3794
    goto :goto_4b

    .line 3795
    :cond_a1
    iget-object v6, v1, Le5/f;->c:Ljava/util/HashMap;

    .line 3796
    .line 3797
    invoke-virtual {v6, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3798
    .line 3799
    .line 3800
    goto/16 :goto_49

    .line 3801
    .line 3802
    :cond_a2
    new-instance v0, Ld5/g;

    .line 3803
    .line 3804
    new-instance v1, Ljava/lang/StringBuilder;

    .line 3805
    .line 3806
    const-string v2, "no array found for key <ids>, found ["

    .line 3807
    .line 3808
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 3809
    .line 3810
    .line 3811
    invoke-virtual {v6}, Ld5/c;->m()Ljava/lang/String;

    .line 3812
    .line 3813
    .line 3814
    move-result-object v2

    .line 3815
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3816
    .line 3817
    .line 3818
    const-string v2, "] : "

    .line 3819
    .line 3820
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 3821
    .line 3822
    .line 3823
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 3824
    .line 3825
    .line 3826
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 3827
    .line 3828
    .line 3829
    move-result-object v1

    .line 3830
    invoke-direct {v0, v1, v5}, Ld5/g;-><init>(Ljava/lang/String;Ld5/c;)V

    .line 3831
    .line 3832
    .line 3833
    throw v0

    .line 3834
    :cond_a3
    const-string v6, "tag"

    .line 3835
    .line 3836
    invoke-virtual {v5, v6}, Ld5/b;->B(Ljava/lang/String;)Z

    .line 3837
    .line 3838
    .line 3839
    move-result v7

    .line 3840
    if-eqz v7, :cond_97

    .line 3841
    .line 3842
    invoke-virtual {v5, v6}, Ld5/b;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 3843
    .line 3844
    .line 3845
    move-result-object v5

    .line 3846
    iget-object v6, v3, Lz4/q;->e:Ljava/util/HashMap;

    .line 3847
    .line 3848
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 3849
    .line 3850
    .line 3851
    move-result v7

    .line 3852
    if-eqz v7, :cond_a4

    .line 3853
    .line 3854
    invoke-virtual {v6, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3855
    .line 3856
    .line 3857
    move-result-object v5

    .line 3858
    check-cast v5, Ljava/util/ArrayList;

    .line 3859
    .line 3860
    goto :goto_4c

    .line 3861
    :cond_a4
    const/4 v5, 0x0

    .line 3862
    :goto_4c
    iget-object v6, v1, Le5/f;->c:Ljava/util/HashMap;

    .line 3863
    .line 3864
    invoke-virtual {v6, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 3865
    .line 3866
    .line 3867
    goto/16 :goto_49

    .line 3868
    .line 3869
    :pswitch_2f
    move-object/from16 v27, v1

    .line 3870
    .line 3871
    move-object v1, v4

    .line 3872
    move-object/from16 v29, v6

    .line 3873
    .line 3874
    instance-of v2, v0, Ld5/f;

    .line 3875
    .line 3876
    if-eqz v2, :cond_95

    .line 3877
    .line 3878
    check-cast v0, Ld5/f;

    .line 3879
    .line 3880
    invoke-virtual {v0}, Ld5/b;->C()Ljava/util/ArrayList;

    .line 3881
    .line 3882
    .line 3883
    move-result-object v2

    .line 3884
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 3885
    .line 3886
    .line 3887
    move-result-object v2

    .line 3888
    :cond_a5
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 3889
    .line 3890
    .line 3891
    move-result v4

    .line 3892
    if-eqz v4, :cond_95

    .line 3893
    .line 3894
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 3895
    .line 3896
    .line 3897
    move-result-object v4

    .line 3898
    check-cast v4, Ljava/lang/String;

    .line 3899
    .line 3900
    invoke-virtual {v0, v4}, Ld5/b;->s(Ljava/lang/String;)Ld5/c;

    .line 3901
    .line 3902
    .line 3903
    move-result-object v5

    .line 3904
    iget-object v6, v1, Le5/f;->c:Ljava/util/HashMap;

    .line 3905
    .line 3906
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 3907
    .line 3908
    .line 3909
    move-result v7

    .line 3910
    if-eqz v7, :cond_a6

    .line 3911
    .line 3912
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 3913
    .line 3914
    .line 3915
    move-result-object v4

    .line 3916
    check-cast v4, Ljava/util/ArrayList;

    .line 3917
    .line 3918
    goto :goto_4d

    .line 3919
    :cond_a6
    const/4 v4, 0x0

    .line 3920
    :goto_4d
    if-eqz v4, :cond_a5

    .line 3921
    .line 3922
    instance-of v6, v5, Ld5/f;

    .line 3923
    .line 3924
    if-eqz v6, :cond_a5

    .line 3925
    .line 3926
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 3927
    .line 3928
    .line 3929
    move-result-object v4

    .line 3930
    :goto_4e
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 3931
    .line 3932
    .line 3933
    move-result v6

    .line 3934
    if-eqz v6, :cond_a5

    .line 3935
    .line 3936
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 3937
    .line 3938
    .line 3939
    move-result-object v6

    .line 3940
    check-cast v6, Ljava/lang/String;

    .line 3941
    .line 3942
    move-object v7, v5

    .line 3943
    check-cast v7, Ld5/f;

    .line 3944
    .line 3945
    invoke-static {v3, v1, v6, v7}, Lkp/b0;->i(Lz4/q;Le5/f;Ljava/lang/String;Ld5/f;)V

    .line 3946
    .line 3947
    .line 3948
    goto :goto_4e

    .line 3949
    :pswitch_30
    move-object/from16 v27, v1

    .line 3950
    .line 3951
    move-object v1, v4

    .line 3952
    move-object/from16 v29, v6

    .line 3953
    .line 3954
    const/4 v12, 0x3

    .line 3955
    const/4 v13, 0x2

    .line 3956
    instance-of v2, v0, Ld5/a;

    .line 3957
    .line 3958
    if-eqz v2, :cond_95

    .line 3959
    .line 3960
    check-cast v0, Ld5/a;

    .line 3961
    .line 3962
    const/4 v2, 0x0

    .line 3963
    :goto_4f
    iget-object v4, v0, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3964
    .line 3965
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 3966
    .line 3967
    .line 3968
    move-result v4

    .line 3969
    if-ge v2, v4, :cond_95

    .line 3970
    .line 3971
    invoke-virtual {v0, v2}, Ld5/b;->r(I)Ld5/c;

    .line 3972
    .line 3973
    .line 3974
    move-result-object v4

    .line 3975
    instance-of v5, v4, Ld5/a;

    .line 3976
    .line 3977
    if-eqz v5, :cond_ab

    .line 3978
    .line 3979
    check-cast v4, Ld5/a;

    .line 3980
    .line 3981
    iget-object v5, v4, Ld5/b;->h:Ljava/util/ArrayList;

    .line 3982
    .line 3983
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 3984
    .line 3985
    .line 3986
    move-result v5

    .line 3987
    const/4 v6, 0x1

    .line 3988
    if-le v5, v6, :cond_b0

    .line 3989
    .line 3990
    const/4 v6, 0x0

    .line 3991
    invoke-virtual {v4, v6}, Ld5/b;->y(I)Ljava/lang/String;

    .line 3992
    .line 3993
    .line 3994
    move-result-object v5

    .line 3995
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 3996
    .line 3997
    .line 3998
    invoke-virtual {v5}, Ljava/lang/String;->hashCode()I

    .line 3999
    .line 4000
    .line 4001
    move-result v6

    .line 4002
    sparse-switch v6, :sswitch_data_8

    .line 4003
    .line 4004
    .line 4005
    :goto_50
    const/4 v5, -0x1

    .line 4006
    goto :goto_51

    .line 4007
    :sswitch_3a
    const-string v6, "hGuideline"

    .line 4008
    .line 4009
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4010
    .line 4011
    .line 4012
    move-result v5

    .line 4013
    if-nez v5, :cond_a7

    .line 4014
    .line 4015
    goto :goto_50

    .line 4016
    :cond_a7
    move v5, v12

    .line 4017
    goto :goto_51

    .line 4018
    :sswitch_3b
    const-string v6, "vChain"

    .line 4019
    .line 4020
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4021
    .line 4022
    .line 4023
    move-result v5

    .line 4024
    if-nez v5, :cond_a8

    .line 4025
    .line 4026
    goto :goto_50

    .line 4027
    :cond_a8
    move v5, v13

    .line 4028
    goto :goto_51

    .line 4029
    :sswitch_3c
    const-string v6, "hChain"

    .line 4030
    .line 4031
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4032
    .line 4033
    .line 4034
    move-result v5

    .line 4035
    if-nez v5, :cond_a9

    .line 4036
    .line 4037
    goto :goto_50

    .line 4038
    :cond_a9
    const/4 v5, 0x1

    .line 4039
    goto :goto_51

    .line 4040
    :sswitch_3d
    const-string v6, "vGuideline"

    .line 4041
    .line 4042
    invoke-virtual {v5, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 4043
    .line 4044
    .line 4045
    move-result v5

    .line 4046
    if-nez v5, :cond_aa

    .line 4047
    .line 4048
    goto :goto_50

    .line 4049
    :cond_aa
    const/4 v5, 0x0

    .line 4050
    :goto_51
    const-string v6, "id"

    .line 4051
    .line 4052
    packed-switch v5, :pswitch_data_9

    .line 4053
    .line 4054
    .line 4055
    :cond_ab
    :goto_52
    const/4 v9, 0x0

    .line 4056
    :goto_53
    const/4 v11, 0x1

    .line 4057
    goto :goto_55

    .line 4058
    :pswitch_31
    const/4 v9, 0x1

    .line 4059
    invoke-virtual {v4, v9}, Ld5/b;->r(I)Ld5/c;

    .line 4060
    .line 4061
    .line 4062
    move-result-object v4

    .line 4063
    instance-of v5, v4, Ld5/f;

    .line 4064
    .line 4065
    if-nez v5, :cond_ac

    .line 4066
    .line 4067
    goto :goto_54

    .line 4068
    :cond_ac
    check-cast v4, Ld5/f;

    .line 4069
    .line 4070
    invoke-virtual {v4, v6}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 4071
    .line 4072
    .line 4073
    move-result-object v5

    .line 4074
    if-nez v5, :cond_ad

    .line 4075
    .line 4076
    :goto_54
    goto :goto_52

    .line 4077
    :cond_ad
    const/4 v9, 0x0

    .line 4078
    invoke-static {v9, v3, v5, v4}, Lkp/b0;->h(ILz4/q;Ljava/lang/String;Ld5/f;)V

    .line 4079
    .line 4080
    .line 4081
    goto :goto_53

    .line 4082
    :pswitch_32
    const/4 v9, 0x0

    .line 4083
    const/4 v11, 0x1

    .line 4084
    invoke-static {v11, v3, v1, v4}, Lkp/b0;->d(ILz4/q;Le5/f;Ld5/a;)V

    .line 4085
    .line 4086
    .line 4087
    goto :goto_55

    .line 4088
    :pswitch_33
    const/4 v9, 0x0

    .line 4089
    const/4 v11, 0x1

    .line 4090
    invoke-static {v9, v3, v1, v4}, Lkp/b0;->d(ILz4/q;Le5/f;Ld5/a;)V

    .line 4091
    .line 4092
    .line 4093
    goto :goto_55

    .line 4094
    :pswitch_34
    const/4 v9, 0x0

    .line 4095
    const/4 v11, 0x1

    .line 4096
    invoke-virtual {v4, v11}, Ld5/b;->r(I)Ld5/c;

    .line 4097
    .line 4098
    .line 4099
    move-result-object v4

    .line 4100
    instance-of v5, v4, Ld5/f;

    .line 4101
    .line 4102
    if-nez v5, :cond_ae

    .line 4103
    .line 4104
    goto :goto_55

    .line 4105
    :cond_ae
    check-cast v4, Ld5/f;

    .line 4106
    .line 4107
    invoke-virtual {v4, v6}, Ld5/b;->A(Ljava/lang/String;)Ljava/lang/String;

    .line 4108
    .line 4109
    .line 4110
    move-result-object v5

    .line 4111
    if-nez v5, :cond_af

    .line 4112
    .line 4113
    goto :goto_55

    .line 4114
    :cond_af
    invoke-static {v11, v3, v5, v4}, Lkp/b0;->h(ILz4/q;Ljava/lang/String;Ld5/f;)V

    .line 4115
    .line 4116
    .line 4117
    goto :goto_55

    .line 4118
    :cond_b0
    move v11, v6

    .line 4119
    const/4 v9, 0x0

    .line 4120
    :goto_55
    add-int/lit8 v2, v2, 0x1

    .line 4121
    .line 4122
    goto/16 :goto_4f

    .line 4123
    .line 4124
    :goto_56
    move-object v4, v1

    .line 4125
    move-object/from16 v1, v27

    .line 4126
    .line 4127
    move-object/from16 v6, v29

    .line 4128
    .line 4129
    goto/16 :goto_2

    .line 4130
    .line 4131
    :cond_b1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4132
    .line 4133
    return-object v0

    .line 4134
    :pswitch_35
    check-cast v0, Lw3/a;

    .line 4135
    .line 4136
    check-cast v4, Le3/d;

    .line 4137
    .line 4138
    invoke-virtual {v0, v4}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 4139
    .line 4140
    .line 4141
    check-cast v3, Lw3/f2;

    .line 4142
    .line 4143
    const-string v1, "listener"

    .line 4144
    .line 4145
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4146
    .line 4147
    .line 4148
    invoke-static {v0}, Llp/w9;->b(Landroid/view/View;)Li6/a;

    .line 4149
    .line 4150
    .line 4151
    move-result-object v0

    .line 4152
    iget-object v0, v0, Li6/a;->a:Ljava/util/ArrayList;

    .line 4153
    .line 4154
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 4155
    .line 4156
    .line 4157
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 4158
    .line 4159
    return-object v0

    .line 4160
    :pswitch_36
    check-cast v4, Landroidx/compose/foundation/layout/c;

    .line 4161
    .line 4162
    check-cast v0, Ljl/h;

    .line 4163
    .line 4164
    iget-object v0, v0, Ljl/h;->t:Ll2/j1;

    .line 4165
    .line 4166
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4167
    .line 4168
    .line 4169
    move-result-object v0

    .line 4170
    check-cast v0, Ljl/f;

    .line 4171
    .line 4172
    invoke-virtual {v0}, Ljl/f;->a()Li3/c;

    .line 4173
    .line 4174
    .line 4175
    move-result-object v0

    .line 4176
    if-eqz v0, :cond_b2

    .line 4177
    .line 4178
    invoke-virtual {v0}, Li3/c;->g()J

    .line 4179
    .line 4180
    .line 4181
    move-result-wide v0

    .line 4182
    new-instance v2, Ld3/e;

    .line 4183
    .line 4184
    invoke-direct {v2, v0, v1}, Ld3/e;-><init>(J)V

    .line 4185
    .line 4186
    .line 4187
    goto :goto_57

    .line 4188
    :cond_b2
    const/4 v2, 0x0

    .line 4189
    :goto_57
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 4190
    .line 4191
    if-eqz v2, :cond_b6

    .line 4192
    .line 4193
    iget-wide v1, v2, Ld3/e;->a:J

    .line 4194
    .line 4195
    const-wide v5, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 4196
    .line 4197
    .line 4198
    .line 4199
    .line 4200
    cmp-long v5, v1, v5

    .line 4201
    .line 4202
    if-eqz v5, :cond_b6

    .line 4203
    .line 4204
    invoke-static {v1, v2}, Ld3/e;->d(J)F

    .line 4205
    .line 4206
    .line 4207
    move-result v5

    .line 4208
    const/high16 v6, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 4209
    .line 4210
    cmpg-float v5, v5, v6

    .line 4211
    .line 4212
    if-nez v5, :cond_b3

    .line 4213
    .line 4214
    goto :goto_59

    .line 4215
    :cond_b3
    invoke-static {v1, v2}, Ld3/e;->b(J)F

    .line 4216
    .line 4217
    .line 4218
    move-result v5

    .line 4219
    cmpg-float v5, v5, v6

    .line 4220
    .line 4221
    if-nez v5, :cond_b4

    .line 4222
    .line 4223
    goto :goto_59

    .line 4224
    :cond_b4
    invoke-static {v1, v2}, Ld3/e;->d(J)F

    .line 4225
    .line 4226
    .line 4227
    move-result v5

    .line 4228
    invoke-static {v1, v2}, Ld3/e;->b(J)F

    .line 4229
    .line 4230
    .line 4231
    move-result v1

    .line 4232
    iget-wide v6, v4, Landroidx/compose/foundation/layout/c;->b:J

    .line 4233
    .line 4234
    invoke-static {v6, v7}, Lt4/a;->h(J)I

    .line 4235
    .line 4236
    .line 4237
    move-result v2

    .line 4238
    int-to-float v2, v2

    .line 4239
    cmpl-float v2, v5, v2

    .line 4240
    .line 4241
    if-lez v2, :cond_b5

    .line 4242
    .line 4243
    iget-wide v6, v4, Landroidx/compose/foundation/layout/c;->b:J

    .line 4244
    .line 4245
    invoke-static {v6, v7}, Lt4/a;->h(J)I

    .line 4246
    .line 4247
    .line 4248
    move-result v2

    .line 4249
    int-to-float v2, v2

    .line 4250
    div-float/2addr v2, v5

    .line 4251
    goto :goto_58

    .line 4252
    :cond_b5
    const/high16 v2, 0x3f800000    # 1.0f

    .line 4253
    .line 4254
    :goto_58
    check-cast v3, Lt4/c;

    .line 4255
    .line 4256
    mul-float/2addr v5, v2

    .line 4257
    invoke-interface {v3, v5}, Lt4/c;->o0(F)F

    .line 4258
    .line 4259
    .line 4260
    move-result v4

    .line 4261
    mul-float/2addr v1, v2

    .line 4262
    invoke-interface {v3, v1}, Lt4/c;->o0(F)F

    .line 4263
    .line 4264
    .line 4265
    move-result v1

    .line 4266
    invoke-static {v0, v4, v1}, Landroidx/compose/foundation/layout/d;->o(Lx2/s;FF)Lx2/s;

    .line 4267
    .line 4268
    .line 4269
    move-result-object v0

    .line 4270
    goto :goto_5a

    .line 4271
    :cond_b6
    :goto_59
    sget v1, Ltv/l;->a:F

    .line 4272
    .line 4273
    invoke-static {v0, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 4274
    .line 4275
    .line 4276
    move-result-object v0

    .line 4277
    :goto_5a
    return-object v0

    .line 4278
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_36
        :pswitch_35
    .end packed-switch

    :sswitch_data_0
    .sparse-switch
        -0x6cbf819b -> :sswitch_2
        0x6fc27995 -> :sswitch_1
        0x72879d57 -> :sswitch_0
    .end sparse-switch

    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_30
        :pswitch_2f
        :pswitch_2e
    .end packed-switch

    :sswitch_data_1
    .sparse-switch
        -0x6a6caee6 -> :sswitch_c
        -0x50c12caa -> :sswitch_b
        -0x4aa718c7 -> :sswitch_a
        -0x32c34015 -> :sswitch_9
        -0x13db5c49 -> :sswitch_8
        0x1b9da -> :sswitch_7
        0x308b46 -> :sswitch_6
        0x5db01b6 -> :sswitch_5
        0x6a04ac4 -> :sswitch_4
        0x398f2168 -> :sswitch_3
    .end sparse-switch

    :pswitch_data_2
    .packed-switch 0x0
        :pswitch_2d
        :pswitch_20
        :pswitch_1c
        :pswitch_1c
        :pswitch_12
        :pswitch_20
        :pswitch_20
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch

    :sswitch_data_2
    .sparse-switch
        -0x4ac15883 -> :sswitch_19
        -0x49bfd1d7 -> :sswitch_18
        -0x47693271 -> :sswitch_17
        -0x32dd7fd1 -> :sswitch_16
        -0x31dbf925 -> :sswitch_15
        -0x300fc3ef -> :sswitch_14
        -0x2bab2063 -> :sswitch_13
        -0x21d289e1 -> :sswitch_12
        -0x1d240708 -> :sswitch_11
        0x305d4e -> :sswitch_10
        0x368f3a -> :sswitch_f
        0x36ba80 -> :sswitch_e
        0x37d04a -> :sswitch_d
    .end sparse-switch

    :pswitch_data_3
    .packed-switch 0x0
        :pswitch_11
        :pswitch_10
        :pswitch_f
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
    .end packed-switch

    :sswitch_data_3
    .sparse-switch
        -0x669119bb -> :sswitch_1c
        -0x527265d5 -> :sswitch_1b
        0x1c155 -> :sswitch_1a
    .end sparse-switch

    :pswitch_data_4
    .packed-switch 0x0
        :pswitch_e
        :pswitch_d
        :pswitch_c
    .end packed-switch

    :sswitch_data_4
    .sparse-switch
        -0x40737a52 -> :sswitch_1f
        -0x395ff881 -> :sswitch_1e
        -0x21d289e1 -> :sswitch_1d
    .end sparse-switch

    :pswitch_data_5
    .packed-switch 0x0
        :pswitch_1b
        :pswitch_14
        :pswitch_13
    .end packed-switch

    :sswitch_data_5
    .sparse-switch
        -0x527265d5 -> :sswitch_25
        0x188db -> :sswitch_24
        0x1c155 -> :sswitch_23
        0x32a007 -> :sswitch_22
        0x677c21c -> :sswitch_21
        0x68ac462 -> :sswitch_20
    .end sparse-switch

    :pswitch_data_6
    .packed-switch 0x0
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
    .end packed-switch

    :sswitch_data_6
    .sparse-switch
        -0x527265d5 -> :sswitch_2d
        -0x21d289e1 -> :sswitch_2c
        0x188db -> :sswitch_2b
        0x1c155 -> :sswitch_2a
        0x32a007 -> :sswitch_29
        0x677c21c -> :sswitch_28
        0x68ac462 -> :sswitch_27
        0x68b1db1 -> :sswitch_26
    .end sparse-switch

    :pswitch_data_7
    .packed-switch 0x0
        :pswitch_1f
        :pswitch_1e
        :pswitch_1f
        :pswitch_1f
        :pswitch_1f
        :pswitch_1f
        :pswitch_1f
        :pswitch_1d
    .end packed-switch

    :sswitch_data_7
    .sparse-switch
        -0x55cd0a30 -> :sswitch_39
        -0x300fc3ef -> :sswitch_38
        -0x21d289e1 -> :sswitch_37
        0x305d4e -> :sswitch_36
        0x3581d9 -> :sswitch_35
        0x36ba80 -> :sswitch_34
        0x5cfee87 -> :sswitch_33
        0x686cad4 -> :sswitch_32
        0x688f269 -> :sswitch_31
        0x89c01c1 -> :sswitch_30
        0x389b97dd -> :sswitch_2f
        0x793284c5 -> :sswitch_2e
    .end sparse-switch

    :pswitch_data_8
    .packed-switch 0x0
        :pswitch_2c
        :pswitch_2b
        :pswitch_2a
        :pswitch_29
        :pswitch_28
        :pswitch_27
        :pswitch_26
        :pswitch_25
        :pswitch_24
        :pswitch_23
        :pswitch_22
        :pswitch_21
    .end packed-switch

    :sswitch_data_8
    .sparse-switch
        -0x6a6caee6 -> :sswitch_3d
        -0x4aa718c7 -> :sswitch_3c
        -0x32c34015 -> :sswitch_3b
        0x398f2168 -> :sswitch_3a
    .end sparse-switch

    :pswitch_data_9
    .packed-switch 0x0
        :pswitch_34
        :pswitch_33
        :pswitch_32
        :pswitch_31
    .end packed-switch
.end method
