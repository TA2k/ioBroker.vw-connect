.class public abstract Len/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lb81/c;

.field public static final b:Lb81/c;

.field public static final c:Lb81/c;

.field public static final d:Lb81/c;


# direct methods
.method static constructor <clinit>()V
    .locals 11

    .line 1
    const-string v9, "chars"

    .line 2
    .line 3
    const-string v10, "markers"

    .line 4
    .line 5
    const-string v0, "w"

    .line 6
    .line 7
    const-string v1, "h"

    .line 8
    .line 9
    const-string v2, "ip"

    .line 10
    .line 11
    const-string v3, "op"

    .line 12
    .line 13
    const-string v4, "fr"

    .line 14
    .line 15
    const-string v5, "v"

    .line 16
    .line 17
    const-string v6, "layers"

    .line 18
    .line 19
    const-string v7, "assets"

    .line 20
    .line 21
    const-string v8, "fonts"

    .line 22
    .line 23
    filled-new-array/range {v0 .. v10}, [Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Len/r;->a:Lb81/c;

    .line 32
    .line 33
    const-string v5, "p"

    .line 34
    .line 35
    const-string v6, "u"

    .line 36
    .line 37
    const-string v1, "id"

    .line 38
    .line 39
    const-string v2, "layers"

    .line 40
    .line 41
    const-string v3, "w"

    .line 42
    .line 43
    const-string v4, "h"

    .line 44
    .line 45
    filled-new-array/range {v1 .. v6}, [Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    sput-object v0, Len/r;->b:Lb81/c;

    .line 54
    .line 55
    const-string v0, "list"

    .line 56
    .line 57
    filled-new-array {v0}, [Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v0

    .line 61
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sput-object v0, Len/r;->c:Lb81/c;

    .line 66
    .line 67
    const-string v0, "tm"

    .line 68
    .line 69
    const-string v1, "dr"

    .line 70
    .line 71
    const-string v2, "cm"

    .line 72
    .line 73
    filled-new-array {v2, v0, v1}, [Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    invoke-static {v0}, Lb81/c;->u([Ljava/lang/String;)Lb81/c;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    sput-object v0, Len/r;->d:Lb81/c;

    .line 82
    .line 83
    return-void
.end method

.method public static a(Lfn/b;)Lum/a;
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static {}, Lgn/h;->c()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    new-instance v2, Landroidx/collection/u;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    invoke-direct {v2, v3}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    new-instance v4, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    new-instance v5, Ljava/util/HashMap;

    .line 19
    .line 20
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    new-instance v6, Ljava/util/HashMap;

    .line 24
    .line 25
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 26
    .line 27
    .line 28
    new-instance v7, Ljava/util/HashMap;

    .line 29
    .line 30
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 31
    .line 32
    .line 33
    new-instance v8, Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 36
    .line 37
    .line 38
    new-instance v9, Landroidx/collection/b1;

    .line 39
    .line 40
    const/4 v10, 0x0

    .line 41
    invoke-direct {v9, v10}, Landroidx/collection/b1;-><init>(I)V

    .line 42
    .line 43
    .line 44
    new-instance v11, Lum/a;

    .line 45
    .line 46
    invoke-direct {v11}, Lum/a;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 50
    .line 51
    .line 52
    move v13, v10

    .line 53
    move v14, v13

    .line 54
    const/4 v12, 0x0

    .line 55
    const/4 v15, 0x0

    .line 56
    const/16 v16, 0x0

    .line 57
    .line 58
    :goto_0
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 59
    .line 60
    .line 61
    move-result v17

    .line 62
    if-eqz v17, :cond_2a

    .line 63
    .line 64
    sget-object v3, Len/r;->a:Lb81/c;

    .line 65
    .line 66
    invoke-virtual {v0, v3}, Lfn/b;->H(Lb81/c;)I

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    packed-switch v3, :pswitch_data_0

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 77
    .line 78
    .line 79
    move/from16 v23, v1

    .line 80
    .line 81
    move-object v3, v11

    .line 82
    move/from16 v21, v14

    .line 83
    .line 84
    move/from16 v24, v15

    .line 85
    .line 86
    goto/16 :goto_16

    .line 87
    .line 88
    :pswitch_0
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 89
    .line 90
    .line 91
    :goto_1
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    if-eqz v3, :cond_4

    .line 96
    .line 97
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 98
    .line 99
    .line 100
    const/4 v3, 0x0

    .line 101
    const/16 v21, 0x0

    .line 102
    .line 103
    :goto_2
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 104
    .line 105
    .line 106
    move-result v19

    .line 107
    if-eqz v19, :cond_3

    .line 108
    .line 109
    sget-object v10, Len/r;->d:Lb81/c;

    .line 110
    .line 111
    invoke-virtual {v0, v10}, Lfn/b;->H(Lb81/c;)I

    .line 112
    .line 113
    .line 114
    move-result v10

    .line 115
    if-eqz v10, :cond_2

    .line 116
    .line 117
    move/from16 v23, v1

    .line 118
    .line 119
    const/4 v1, 0x1

    .line 120
    if-eq v10, v1, :cond_1

    .line 121
    .line 122
    const/4 v1, 0x2

    .line 123
    if-eq v10, v1, :cond_0

    .line 124
    .line 125
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 129
    .line 130
    .line 131
    :goto_3
    move/from16 v1, v23

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_0
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 135
    .line 136
    .line 137
    goto :goto_3

    .line 138
    :cond_1
    move v1, v14

    .line 139
    move v10, v15

    .line 140
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 141
    .line 142
    .line 143
    move-result-wide v14

    .line 144
    double-to-float v14, v14

    .line 145
    move v15, v10

    .line 146
    move/from16 v21, v14

    .line 147
    .line 148
    move v14, v1

    .line 149
    goto :goto_3

    .line 150
    :cond_2
    move/from16 v23, v1

    .line 151
    .line 152
    move v1, v14

    .line 153
    move v10, v15

    .line 154
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    goto :goto_3

    .line 159
    :cond_3
    move/from16 v23, v1

    .line 160
    .line 161
    move v1, v14

    .line 162
    move v10, v15

    .line 163
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 164
    .line 165
    .line 166
    new-instance v14, Lan/f;

    .line 167
    .line 168
    move/from16 v15, v21

    .line 169
    .line 170
    invoke-direct {v14, v3, v15}, Lan/f;-><init>(Ljava/lang/String;F)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {v8, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move v14, v1

    .line 177
    move v15, v10

    .line 178
    move/from16 v1, v23

    .line 179
    .line 180
    goto :goto_1

    .line 181
    :cond_4
    move/from16 v23, v1

    .line 182
    .line 183
    move v1, v14

    .line 184
    move v10, v15

    .line 185
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 186
    .line 187
    .line 188
    :goto_4
    move/from16 v21, v1

    .line 189
    .line 190
    move/from16 v24, v10

    .line 191
    .line 192
    :goto_5
    move-object v3, v11

    .line 193
    goto/16 :goto_16

    .line 194
    .line 195
    :pswitch_1
    move/from16 v23, v1

    .line 196
    .line 197
    move v1, v14

    .line 198
    move v10, v15

    .line 199
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 200
    .line 201
    .line 202
    :goto_6
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 203
    .line 204
    .line 205
    move-result v3

    .line 206
    if-eqz v3, :cond_f

    .line 207
    .line 208
    sget-object v3, Len/j;->a:Lb81/c;

    .line 209
    .line 210
    new-instance v3, Ljava/util/ArrayList;

    .line 211
    .line 212
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 213
    .line 214
    .line 215
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 216
    .line 217
    .line 218
    const-wide/16 v14, 0x0

    .line 219
    .line 220
    move-wide/from16 v27, v14

    .line 221
    .line 222
    const/16 v26, 0x0

    .line 223
    .line 224
    const/16 v29, 0x0

    .line 225
    .line 226
    const/16 v30, 0x0

    .line 227
    .line 228
    :goto_7
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 229
    .line 230
    .line 231
    move-result v14

    .line 232
    if-eqz v14, :cond_e

    .line 233
    .line 234
    sget-object v14, Len/j;->a:Lb81/c;

    .line 235
    .line 236
    invoke-virtual {v0, v14}, Lfn/b;->H(Lb81/c;)I

    .line 237
    .line 238
    .line 239
    move-result v14

    .line 240
    if-eqz v14, :cond_d

    .line 241
    .line 242
    const/4 v15, 0x1

    .line 243
    if-eq v14, v15, :cond_c

    .line 244
    .line 245
    const/4 v15, 0x2

    .line 246
    if-eq v14, v15, :cond_b

    .line 247
    .line 248
    const/4 v15, 0x3

    .line 249
    if-eq v14, v15, :cond_a

    .line 250
    .line 251
    const/4 v15, 0x4

    .line 252
    if-eq v14, v15, :cond_9

    .line 253
    .line 254
    const/4 v15, 0x5

    .line 255
    if-eq v14, v15, :cond_5

    .line 256
    .line 257
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 261
    .line 262
    .line 263
    goto :goto_7

    .line 264
    :cond_5
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 265
    .line 266
    .line 267
    :goto_8
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 268
    .line 269
    .line 270
    move-result v14

    .line 271
    if-eqz v14, :cond_8

    .line 272
    .line 273
    sget-object v14, Len/j;->b:Lb81/c;

    .line 274
    .line 275
    invoke-virtual {v0, v14}, Lfn/b;->H(Lb81/c;)I

    .line 276
    .line 277
    .line 278
    move-result v14

    .line 279
    if-eqz v14, :cond_6

    .line 280
    .line 281
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 285
    .line 286
    .line 287
    goto :goto_8

    .line 288
    :cond_6
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 289
    .line 290
    .line 291
    :goto_9
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 292
    .line 293
    .line 294
    move-result v14

    .line 295
    if-eqz v14, :cond_7

    .line 296
    .line 297
    invoke-static {v0, v11}, Len/g;->a(Lfn/b;Lum/a;)Lcn/b;

    .line 298
    .line 299
    .line 300
    move-result-object v14

    .line 301
    check-cast v14, Lcn/m;

    .line 302
    .line 303
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    goto :goto_9

    .line 307
    :cond_7
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 308
    .line 309
    .line 310
    goto :goto_8

    .line 311
    :cond_8
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 312
    .line 313
    .line 314
    goto :goto_7

    .line 315
    :cond_9
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v30

    .line 319
    goto :goto_7

    .line 320
    :cond_a
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 321
    .line 322
    .line 323
    move-result-object v29

    .line 324
    goto :goto_7

    .line 325
    :cond_b
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 326
    .line 327
    .line 328
    move-result-wide v27

    .line 329
    goto :goto_7

    .line 330
    :cond_c
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 331
    .line 332
    .line 333
    goto :goto_7

    .line 334
    :cond_d
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v14

    .line 338
    const/4 v15, 0x0

    .line 339
    invoke-virtual {v14, v15}, Ljava/lang/String;->charAt(I)C

    .line 340
    .line 341
    .line 342
    move-result v26

    .line 343
    goto :goto_7

    .line 344
    :cond_e
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 345
    .line 346
    .line 347
    new-instance v24, Lan/d;

    .line 348
    .line 349
    move-object/from16 v25, v3

    .line 350
    .line 351
    invoke-direct/range {v24 .. v30}, Lan/d;-><init>(Ljava/util/ArrayList;CDLjava/lang/String;Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    move-object/from16 v3, v24

    .line 355
    .line 356
    invoke-virtual {v3}, Lan/d;->hashCode()I

    .line 357
    .line 358
    .line 359
    move-result v14

    .line 360
    invoke-virtual {v9, v14, v3}, Landroidx/collection/b1;->e(ILjava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    goto/16 :goto_6

    .line 364
    .line 365
    :cond_f
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 366
    .line 367
    .line 368
    goto/16 :goto_4

    .line 369
    .line 370
    :pswitch_2
    move/from16 v23, v1

    .line 371
    .line 372
    move v1, v14

    .line 373
    move v10, v15

    .line 374
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 375
    .line 376
    .line 377
    :goto_a
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 378
    .line 379
    .line 380
    move-result v3

    .line 381
    if-eqz v3, :cond_17

    .line 382
    .line 383
    sget-object v3, Len/r;->c:Lb81/c;

    .line 384
    .line 385
    invoke-virtual {v0, v3}, Lfn/b;->H(Lb81/c;)I

    .line 386
    .line 387
    .line 388
    move-result v3

    .line 389
    if-eqz v3, :cond_10

    .line 390
    .line 391
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 392
    .line 393
    .line 394
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 395
    .line 396
    .line 397
    goto :goto_a

    .line 398
    :cond_10
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 399
    .line 400
    .line 401
    :goto_b
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 402
    .line 403
    .line 404
    move-result v3

    .line 405
    if-eqz v3, :cond_16

    .line 406
    .line 407
    sget-object v3, Len/k;->a:Lb81/c;

    .line 408
    .line 409
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 410
    .line 411
    .line 412
    const/4 v3, 0x0

    .line 413
    const/4 v14, 0x0

    .line 414
    const/4 v15, 0x0

    .line 415
    :goto_c
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 416
    .line 417
    .line 418
    move-result v19

    .line 419
    if-eqz v19, :cond_15

    .line 420
    .line 421
    move/from16 v21, v1

    .line 422
    .line 423
    sget-object v1, Len/k;->a:Lb81/c;

    .line 424
    .line 425
    invoke-virtual {v0, v1}, Lfn/b;->H(Lb81/c;)I

    .line 426
    .line 427
    .line 428
    move-result v1

    .line 429
    if-eqz v1, :cond_14

    .line 430
    .line 431
    move/from16 v24, v10

    .line 432
    .line 433
    const/4 v10, 0x1

    .line 434
    if-eq v1, v10, :cond_13

    .line 435
    .line 436
    const/4 v10, 0x2

    .line 437
    if-eq v1, v10, :cond_12

    .line 438
    .line 439
    const/4 v10, 0x3

    .line 440
    if-eq v1, v10, :cond_11

    .line 441
    .line 442
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 443
    .line 444
    .line 445
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 446
    .line 447
    .line 448
    :goto_d
    move/from16 v1, v21

    .line 449
    .line 450
    move/from16 v10, v24

    .line 451
    .line 452
    goto :goto_c

    .line 453
    :cond_11
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 454
    .line 455
    .line 456
    goto :goto_d

    .line 457
    :cond_12
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 458
    .line 459
    .line 460
    move-result-object v15

    .line 461
    goto :goto_d

    .line 462
    :cond_13
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 463
    .line 464
    .line 465
    move-result-object v14

    .line 466
    goto :goto_d

    .line 467
    :cond_14
    move/from16 v24, v10

    .line 468
    .line 469
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 470
    .line 471
    .line 472
    move-result-object v3

    .line 473
    move/from16 v1, v21

    .line 474
    .line 475
    goto :goto_c

    .line 476
    :cond_15
    move/from16 v21, v1

    .line 477
    .line 478
    move/from16 v24, v10

    .line 479
    .line 480
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 481
    .line 482
    .line 483
    new-instance v1, Lan/c;

    .line 484
    .line 485
    invoke-direct {v1, v3, v14, v15}, Lan/c;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v7, v14, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move/from16 v1, v21

    .line 492
    .line 493
    goto :goto_b

    .line 494
    :cond_16
    move/from16 v21, v1

    .line 495
    .line 496
    move/from16 v24, v10

    .line 497
    .line 498
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 499
    .line 500
    .line 501
    goto :goto_a

    .line 502
    :cond_17
    move/from16 v21, v1

    .line 503
    .line 504
    move/from16 v24, v10

    .line 505
    .line 506
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 507
    .line 508
    .line 509
    goto/16 :goto_5

    .line 510
    .line 511
    :pswitch_3
    move/from16 v23, v1

    .line 512
    .line 513
    move/from16 v21, v14

    .line 514
    .line 515
    move/from16 v24, v15

    .line 516
    .line 517
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 518
    .line 519
    .line 520
    :goto_e
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 521
    .line 522
    .line 523
    move-result v1

    .line 524
    if-eqz v1, :cond_21

    .line 525
    .line 526
    new-instance v1, Ljava/util/ArrayList;

    .line 527
    .line 528
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 529
    .line 530
    .line 531
    new-instance v3, Landroidx/collection/u;

    .line 532
    .line 533
    const/4 v10, 0x0

    .line 534
    invoke-direct {v3, v10}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 535
    .line 536
    .line 537
    invoke-virtual {v0}, Lfn/b;->b()V

    .line 538
    .line 539
    .line 540
    move-object/from16 v28, v10

    .line 541
    .line 542
    move-object/from16 v29, v28

    .line 543
    .line 544
    move-object/from16 v30, v29

    .line 545
    .line 546
    const/16 v26, 0x0

    .line 547
    .line 548
    const/16 v27, 0x0

    .line 549
    .line 550
    :goto_f
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 551
    .line 552
    .line 553
    move-result v14

    .line 554
    if-eqz v14, :cond_1f

    .line 555
    .line 556
    sget-object v14, Len/r;->b:Lb81/c;

    .line 557
    .line 558
    invoke-virtual {v0, v14}, Lfn/b;->H(Lb81/c;)I

    .line 559
    .line 560
    .line 561
    move-result v14

    .line 562
    if-eqz v14, :cond_1e

    .line 563
    .line 564
    const/4 v15, 0x1

    .line 565
    if-eq v14, v15, :cond_1c

    .line 566
    .line 567
    const/4 v15, 0x2

    .line 568
    if-eq v14, v15, :cond_1b

    .line 569
    .line 570
    const/4 v15, 0x3

    .line 571
    if-eq v14, v15, :cond_1a

    .line 572
    .line 573
    const/4 v15, 0x4

    .line 574
    if-eq v14, v15, :cond_19

    .line 575
    .line 576
    const/4 v15, 0x5

    .line 577
    if-eq v14, v15, :cond_18

    .line 578
    .line 579
    invoke-virtual {v0}, Lfn/b;->M()V

    .line 580
    .line 581
    .line 582
    invoke-virtual {v0}, Lfn/b;->T()V

    .line 583
    .line 584
    .line 585
    move-object/from16 v17, v11

    .line 586
    .line 587
    goto :goto_11

    .line 588
    :cond_18
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 589
    .line 590
    .line 591
    move-result-object v30

    .line 592
    goto :goto_f

    .line 593
    :cond_19
    const/4 v15, 0x5

    .line 594
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 595
    .line 596
    .line 597
    move-result-object v29

    .line 598
    goto :goto_f

    .line 599
    :cond_1a
    const/4 v15, 0x5

    .line 600
    invoke-virtual {v0}, Lfn/b;->l()I

    .line 601
    .line 602
    .line 603
    move-result v27

    .line 604
    goto :goto_f

    .line 605
    :cond_1b
    const/4 v15, 0x5

    .line 606
    invoke-virtual {v0}, Lfn/b;->l()I

    .line 607
    .line 608
    .line 609
    move-result v26

    .line 610
    goto :goto_f

    .line 611
    :cond_1c
    const/4 v15, 0x5

    .line 612
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 613
    .line 614
    .line 615
    :goto_10
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 616
    .line 617
    .line 618
    move-result v14

    .line 619
    if-eqz v14, :cond_1d

    .line 620
    .line 621
    invoke-static {v0, v11}, Len/q;->a(Lfn/b;Lum/a;)Ldn/e;

    .line 622
    .line 623
    .line 624
    move-result-object v14

    .line 625
    move-object/from16 v17, v11

    .line 626
    .line 627
    iget-wide v10, v14, Ldn/e;->d:J

    .line 628
    .line 629
    invoke-virtual {v3, v10, v11, v14}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 630
    .line 631
    .line 632
    invoke-virtual {v1, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 633
    .line 634
    .line 635
    move-object/from16 v11, v17

    .line 636
    .line 637
    const/4 v10, 0x0

    .line 638
    goto :goto_10

    .line 639
    :cond_1d
    move-object/from16 v17, v11

    .line 640
    .line 641
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 642
    .line 643
    .line 644
    :goto_11
    move-object/from16 v11, v17

    .line 645
    .line 646
    :goto_12
    const/4 v10, 0x0

    .line 647
    goto :goto_f

    .line 648
    :cond_1e
    move-object/from16 v17, v11

    .line 649
    .line 650
    const/4 v15, 0x5

    .line 651
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v28

    .line 655
    goto :goto_12

    .line 656
    :cond_1f
    move-object/from16 v17, v11

    .line 657
    .line 658
    const/4 v15, 0x5

    .line 659
    invoke-virtual {v0}, Lfn/b;->f()V

    .line 660
    .line 661
    .line 662
    if-eqz v29, :cond_20

    .line 663
    .line 664
    new-instance v25, Lum/l;

    .line 665
    .line 666
    invoke-direct/range {v25 .. v30}, Lum/l;-><init>(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 667
    .line 668
    .line 669
    move-object/from16 v1, v25

    .line 670
    .line 671
    move-object/from16 v10, v28

    .line 672
    .line 673
    invoke-virtual {v6, v10, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 674
    .line 675
    .line 676
    goto :goto_13

    .line 677
    :cond_20
    move-object/from16 v10, v28

    .line 678
    .line 679
    invoke-virtual {v5, v10, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 680
    .line 681
    .line 682
    :goto_13
    move-object/from16 v11, v17

    .line 683
    .line 684
    goto/16 :goto_e

    .line 685
    .line 686
    :cond_21
    move-object/from16 v17, v11

    .line 687
    .line 688
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 689
    .line 690
    .line 691
    move-object/from16 v3, v17

    .line 692
    .line 693
    goto/16 :goto_16

    .line 694
    .line 695
    :pswitch_4
    move/from16 v23, v1

    .line 696
    .line 697
    move-object/from16 v17, v11

    .line 698
    .line 699
    move/from16 v21, v14

    .line 700
    .line 701
    move/from16 v24, v15

    .line 702
    .line 703
    invoke-virtual {v0}, Lfn/b;->a()V

    .line 704
    .line 705
    .line 706
    const/4 v1, 0x0

    .line 707
    :goto_14
    invoke-virtual {v0}, Lfn/b;->h()Z

    .line 708
    .line 709
    .line 710
    move-result v3

    .line 711
    if-eqz v3, :cond_24

    .line 712
    .line 713
    move-object/from16 v3, v17

    .line 714
    .line 715
    invoke-static {v0, v3}, Len/q;->a(Lfn/b;Lum/a;)Ldn/e;

    .line 716
    .line 717
    .line 718
    move-result-object v10

    .line 719
    iget v11, v10, Ldn/e;->e:I

    .line 720
    .line 721
    const/4 v15, 0x3

    .line 722
    if-ne v11, v15, :cond_22

    .line 723
    .line 724
    add-int/lit8 v1, v1, 0x1

    .line 725
    .line 726
    :cond_22
    invoke-virtual {v4, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 727
    .line 728
    .line 729
    iget-wide v14, v10, Ldn/e;->d:J

    .line 730
    .line 731
    invoke-virtual {v2, v14, v15, v10}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 732
    .line 733
    .line 734
    const/4 v15, 0x4

    .line 735
    if-le v1, v15, :cond_23

    .line 736
    .line 737
    new-instance v10, Ljava/lang/StringBuilder;

    .line 738
    .line 739
    const-string v11, "You have "

    .line 740
    .line 741
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    invoke-virtual {v10, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 745
    .line 746
    .line 747
    const-string v11, " images. Lottie should primarily be used with shapes. If you are using Adobe Illustrator, convert the Illustrator layers to shape layers."

    .line 748
    .line 749
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 750
    .line 751
    .line 752
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 753
    .line 754
    .line 755
    move-result-object v10

    .line 756
    invoke-static {v10}, Lgn/c;->a(Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    :cond_23
    move-object/from16 v17, v3

    .line 760
    .line 761
    goto :goto_14

    .line 762
    :cond_24
    move-object/from16 v3, v17

    .line 763
    .line 764
    invoke-virtual {v0}, Lfn/b;->d()V

    .line 765
    .line 766
    .line 767
    goto :goto_16

    .line 768
    :pswitch_5
    move/from16 v23, v1

    .line 769
    .line 770
    move-object v3, v11

    .line 771
    move/from16 v21, v14

    .line 772
    .line 773
    move/from16 v24, v15

    .line 774
    .line 775
    invoke-virtual {v0}, Lfn/b;->q()Ljava/lang/String;

    .line 776
    .line 777
    .line 778
    move-result-object v1

    .line 779
    const-string v10, "\\."

    .line 780
    .line 781
    invoke-virtual {v1, v10}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    .line 782
    .line 783
    .line 784
    move-result-object v1

    .line 785
    const/16 v18, 0x0

    .line 786
    .line 787
    aget-object v10, v1, v18

    .line 788
    .line 789
    invoke-static {v10}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 790
    .line 791
    .line 792
    move-result v10

    .line 793
    const/16 v22, 0x1

    .line 794
    .line 795
    aget-object v11, v1, v22

    .line 796
    .line 797
    invoke-static {v11}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 798
    .line 799
    .line 800
    move-result v11

    .line 801
    const/16 v20, 0x2

    .line 802
    .line 803
    aget-object v1, v1, v20

    .line 804
    .line 805
    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 806
    .line 807
    .line 808
    move-result v1

    .line 809
    const/4 v15, 0x4

    .line 810
    if-ge v10, v15, :cond_25

    .line 811
    .line 812
    goto :goto_15

    .line 813
    :cond_25
    if-le v10, v15, :cond_26

    .line 814
    .line 815
    goto :goto_16

    .line 816
    :cond_26
    if-ge v11, v15, :cond_27

    .line 817
    .line 818
    goto :goto_15

    .line 819
    :cond_27
    if-le v11, v15, :cond_28

    .line 820
    .line 821
    goto :goto_16

    .line 822
    :cond_28
    if-ltz v1, :cond_29

    .line 823
    .line 824
    goto :goto_16

    .line 825
    :cond_29
    :goto_15
    const-string v1, "Lottie only supports bodymovin >= 4.4.0"

    .line 826
    .line 827
    invoke-virtual {v3, v1}, Lum/a;->a(Ljava/lang/String;)V

    .line 828
    .line 829
    .line 830
    :goto_16
    move-object v11, v3

    .line 831
    move/from16 v14, v21

    .line 832
    .line 833
    move/from16 v1, v23

    .line 834
    .line 835
    move/from16 v15, v24

    .line 836
    .line 837
    :goto_17
    const/4 v3, 0x0

    .line 838
    const/4 v10, 0x0

    .line 839
    goto/16 :goto_0

    .line 840
    .line 841
    :pswitch_6
    move/from16 v23, v1

    .line 842
    .line 843
    move-object v3, v11

    .line 844
    move/from16 v21, v14

    .line 845
    .line 846
    move/from16 v24, v15

    .line 847
    .line 848
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 849
    .line 850
    .line 851
    move-result-wide v10

    .line 852
    double-to-float v1, v10

    .line 853
    move/from16 v16, v1

    .line 854
    .line 855
    :goto_18
    move-object v11, v3

    .line 856
    move/from16 v1, v23

    .line 857
    .line 858
    goto :goto_17

    .line 859
    :pswitch_7
    move/from16 v23, v1

    .line 860
    .line 861
    move-object v3, v11

    .line 862
    move/from16 v21, v14

    .line 863
    .line 864
    move/from16 v24, v15

    .line 865
    .line 866
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 867
    .line 868
    .line 869
    move-result-wide v10

    .line 870
    double-to-float v1, v10

    .line 871
    const v10, 0x3c23d70a    # 0.01f

    .line 872
    .line 873
    .line 874
    sub-float v12, v1, v10

    .line 875
    .line 876
    goto :goto_18

    .line 877
    :pswitch_8
    move/from16 v23, v1

    .line 878
    .line 879
    move-object v3, v11

    .line 880
    move/from16 v21, v14

    .line 881
    .line 882
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 883
    .line 884
    .line 885
    move-result-wide v10

    .line 886
    double-to-float v15, v10

    .line 887
    :goto_19
    move-object v11, v3

    .line 888
    goto :goto_17

    .line 889
    :pswitch_9
    move/from16 v23, v1

    .line 890
    .line 891
    move-object v3, v11

    .line 892
    move/from16 v24, v15

    .line 893
    .line 894
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 895
    .line 896
    .line 897
    move-result-wide v10

    .line 898
    double-to-int v14, v10

    .line 899
    goto :goto_19

    .line 900
    :pswitch_a
    move/from16 v23, v1

    .line 901
    .line 902
    move-object v3, v11

    .line 903
    move/from16 v21, v14

    .line 904
    .line 905
    move/from16 v24, v15

    .line 906
    .line 907
    invoke-virtual {v0}, Lfn/b;->k()D

    .line 908
    .line 909
    .line 910
    move-result-wide v10

    .line 911
    double-to-int v13, v10

    .line 912
    goto :goto_19

    .line 913
    :cond_2a
    move/from16 v23, v1

    .line 914
    .line 915
    move-object v3, v11

    .line 916
    move/from16 v21, v14

    .line 917
    .line 918
    move/from16 v24, v15

    .line 919
    .line 920
    int-to-float v0, v13

    .line 921
    mul-float v0, v0, v23

    .line 922
    .line 923
    float-to-int v0, v0

    .line 924
    move/from16 v1, v21

    .line 925
    .line 926
    int-to-float v1, v1

    .line 927
    mul-float v1, v1, v23

    .line 928
    .line 929
    float-to-int v1, v1

    .line 930
    new-instance v10, Landroid/graphics/Rect;

    .line 931
    .line 932
    const/4 v15, 0x0

    .line 933
    invoke-direct {v10, v15, v15, v0, v1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 934
    .line 935
    .line 936
    invoke-static {}, Lgn/h;->c()F

    .line 937
    .line 938
    .line 939
    move-result v0

    .line 940
    iput-object v10, v3, Lum/a;->k:Landroid/graphics/Rect;

    .line 941
    .line 942
    move/from16 v10, v24

    .line 943
    .line 944
    iput v10, v3, Lum/a;->l:F

    .line 945
    .line 946
    iput v12, v3, Lum/a;->m:F

    .line 947
    .line 948
    move/from16 v1, v16

    .line 949
    .line 950
    iput v1, v3, Lum/a;->n:F

    .line 951
    .line 952
    iput-object v4, v3, Lum/a;->j:Ljava/util/ArrayList;

    .line 953
    .line 954
    iput-object v2, v3, Lum/a;->i:Landroidx/collection/u;

    .line 955
    .line 956
    iput-object v5, v3, Lum/a;->c:Ljava/util/HashMap;

    .line 957
    .line 958
    iput-object v6, v3, Lum/a;->d:Ljava/util/HashMap;

    .line 959
    .line 960
    iput v0, v3, Lum/a;->e:F

    .line 961
    .line 962
    iput-object v9, v3, Lum/a;->h:Landroidx/collection/b1;

    .line 963
    .line 964
    iput-object v7, v3, Lum/a;->f:Ljava/util/HashMap;

    .line 965
    .line 966
    iput-object v8, v3, Lum/a;->g:Ljava/util/ArrayList;

    .line 967
    .line 968
    return-object v3

    .line 969
    :pswitch_data_0
    .packed-switch 0x0
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
