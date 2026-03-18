.class public final Lt3/t1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:Lt3/t1;

.field public static final b:Lt3/v1;

.field public static final c:Lt3/v1;

.field public static final d:Lt3/v1;

.field public static final e:Lt3/v1;

.field public static final f:Lt3/v1;

.field public static final g:Lt3/v1;

.field public static final h:Lt3/v1;

.field public static final i:Lt3/v1;

.field public static final j:Lt3/v1;


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    new-instance v0, Lt3/t1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt3/t1;->a:Lt3/t1;

    .line 7
    .line 8
    new-instance v0, Lt3/v1;

    .line 9
    .line 10
    const-string v1, "caption bar"

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lt3/t1;->b:Lt3/v1;

    .line 16
    .line 17
    new-instance v1, Lt3/v1;

    .line 18
    .line 19
    const-string v2, "display cutout"

    .line 20
    .line 21
    invoke-direct {v1, v2}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    sput-object v1, Lt3/t1;->c:Lt3/v1;

    .line 25
    .line 26
    new-instance v2, Lt3/v1;

    .line 27
    .line 28
    const-string v3, "ime"

    .line 29
    .line 30
    invoke-direct {v2, v3}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v2, Lt3/t1;->d:Lt3/v1;

    .line 34
    .line 35
    new-instance v3, Lt3/v1;

    .line 36
    .line 37
    const-string v4, "mandatory system gestures"

    .line 38
    .line 39
    invoke-direct {v3, v4}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sput-object v3, Lt3/t1;->e:Lt3/v1;

    .line 43
    .line 44
    new-instance v4, Lt3/v1;

    .line 45
    .line 46
    const-string v5, "navigation bars"

    .line 47
    .line 48
    invoke-direct {v4, v5}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    sput-object v4, Lt3/t1;->f:Lt3/v1;

    .line 52
    .line 53
    new-instance v5, Lt3/v1;

    .line 54
    .line 55
    const-string v6, "status bars"

    .line 56
    .line 57
    invoke-direct {v5, v6}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    sput-object v5, Lt3/t1;->g:Lt3/v1;

    .line 61
    .line 62
    const/4 v6, 0x3

    .line 63
    new-array v7, v6, [Lt3/u1;

    .line 64
    .line 65
    const/4 v8, 0x0

    .line 66
    aput-object v5, v7, v8

    .line 67
    .line 68
    const/4 v9, 0x1

    .line 69
    aput-object v4, v7, v9

    .line 70
    .line 71
    const/4 v10, 0x2

    .line 72
    aput-object v0, v7, v10

    .line 73
    .line 74
    new-instance v11, Ljava/util/ArrayList;

    .line 75
    .line 76
    invoke-direct {v11, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 77
    .line 78
    .line 79
    move v12, v8

    .line 80
    :goto_0
    if-ge v12, v6, :cond_0

    .line 81
    .line 82
    aget-object v13, v7, v12

    .line 83
    .line 84
    check-cast v13, Lt3/v1;

    .line 85
    .line 86
    iget-object v13, v13, Lt3/v1;->c:Lt3/r;

    .line 87
    .line 88
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    add-int/lit8 v12, v12, 0x1

    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_0
    new-array v12, v8, [Lt3/r;

    .line 95
    .line 96
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v11

    .line 100
    check-cast v11, [Lt3/r;

    .line 101
    .line 102
    array-length v12, v11

    .line 103
    invoke-static {v11, v12}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v11

    .line 107
    check-cast v11, [Lt3/r;

    .line 108
    .line 109
    new-instance v12, Lt3/r;

    .line 110
    .line 111
    invoke-direct {v12, v11}, Lt3/r;-><init>([Lt3/r;)V

    .line 112
    .line 113
    .line 114
    new-instance v11, Ljava/util/ArrayList;

    .line 115
    .line 116
    invoke-direct {v11, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 117
    .line 118
    .line 119
    move v12, v8

    .line 120
    :goto_1
    if-ge v12, v6, :cond_1

    .line 121
    .line 122
    aget-object v13, v7, v12

    .line 123
    .line 124
    check-cast v13, Lt3/v1;

    .line 125
    .line 126
    iget-object v13, v13, Lt3/v1;->d:Lt3/r;

    .line 127
    .line 128
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    add-int/lit8 v12, v12, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_1
    new-array v7, v8, [Lt3/r;

    .line 135
    .line 136
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v7

    .line 140
    check-cast v7, [Lt3/r;

    .line 141
    .line 142
    array-length v11, v7

    .line 143
    invoke-static {v7, v11}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v7

    .line 147
    check-cast v7, [Lt3/r;

    .line 148
    .line 149
    new-instance v11, Lt3/r;

    .line 150
    .line 151
    invoke-direct {v11, v7}, Lt3/r;-><init>([Lt3/r;)V

    .line 152
    .line 153
    .line 154
    new-instance v7, Lt3/v1;

    .line 155
    .line 156
    const-string v11, "system gestures"

    .line 157
    .line 158
    invoke-direct {v7, v11}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    sput-object v7, Lt3/t1;->h:Lt3/v1;

    .line 162
    .line 163
    new-instance v11, Lt3/v1;

    .line 164
    .line 165
    const-string v12, "tappable element"

    .line 166
    .line 167
    invoke-direct {v11, v12}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    sput-object v11, Lt3/t1;->i:Lt3/v1;

    .line 171
    .line 172
    new-instance v12, Lt3/v1;

    .line 173
    .line 174
    const-string v13, "waterfall"

    .line 175
    .line 176
    invoke-direct {v12, v13}, Lt3/v1;-><init>(Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    sput-object v12, Lt3/t1;->j:Lt3/v1;

    .line 180
    .line 181
    const/4 v13, 0x6

    .line 182
    new-array v14, v13, [Lt3/u1;

    .line 183
    .line 184
    aput-object v5, v14, v8

    .line 185
    .line 186
    aput-object v4, v14, v9

    .line 187
    .line 188
    aput-object v0, v14, v10

    .line 189
    .line 190
    aput-object v1, v14, v6

    .line 191
    .line 192
    const/4 v15, 0x4

    .line 193
    aput-object v2, v14, v15

    .line 194
    .line 195
    const/16 v16, 0x5

    .line 196
    .line 197
    aput-object v11, v14, v16

    .line 198
    .line 199
    move/from16 v17, v6

    .line 200
    .line 201
    new-instance v6, Ljava/util/ArrayList;

    .line 202
    .line 203
    invoke-direct {v6, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 204
    .line 205
    .line 206
    move/from16 v18, v9

    .line 207
    .line 208
    move v9, v8

    .line 209
    :goto_2
    if-ge v9, v13, :cond_2

    .line 210
    .line 211
    aget-object v19, v14, v9

    .line 212
    .line 213
    move/from16 v20, v10

    .line 214
    .line 215
    move-object/from16 v10, v19

    .line 216
    .line 217
    check-cast v10, Lt3/v1;

    .line 218
    .line 219
    iget-object v10, v10, Lt3/v1;->c:Lt3/r;

    .line 220
    .line 221
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    add-int/lit8 v9, v9, 0x1

    .line 225
    .line 226
    move/from16 v10, v20

    .line 227
    .line 228
    goto :goto_2

    .line 229
    :cond_2
    move/from16 v20, v10

    .line 230
    .line 231
    new-array v9, v8, [Lt3/r;

    .line 232
    .line 233
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 234
    .line 235
    .line 236
    move-result-object v6

    .line 237
    check-cast v6, [Lt3/r;

    .line 238
    .line 239
    array-length v9, v6

    .line 240
    invoke-static {v6, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    check-cast v6, [Lt3/r;

    .line 245
    .line 246
    new-instance v9, Lt3/r;

    .line 247
    .line 248
    invoke-direct {v9, v6}, Lt3/r;-><init>([Lt3/r;)V

    .line 249
    .line 250
    .line 251
    new-instance v6, Ljava/util/ArrayList;

    .line 252
    .line 253
    invoke-direct {v6, v13}, Ljava/util/ArrayList;-><init>(I)V

    .line 254
    .line 255
    .line 256
    move v9, v8

    .line 257
    :goto_3
    if-ge v9, v13, :cond_3

    .line 258
    .line 259
    aget-object v10, v14, v9

    .line 260
    .line 261
    check-cast v10, Lt3/v1;

    .line 262
    .line 263
    iget-object v10, v10, Lt3/v1;->d:Lt3/r;

    .line 264
    .line 265
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 266
    .line 267
    .line 268
    add-int/lit8 v9, v9, 0x1

    .line 269
    .line 270
    goto :goto_3

    .line 271
    :cond_3
    new-array v9, v8, [Lt3/r;

    .line 272
    .line 273
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v6

    .line 277
    check-cast v6, [Lt3/r;

    .line 278
    .line 279
    array-length v9, v6

    .line 280
    invoke-static {v6, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    check-cast v6, [Lt3/r;

    .line 285
    .line 286
    new-instance v9, Lt3/r;

    .line 287
    .line 288
    invoke-direct {v9, v6}, Lt3/r;-><init>([Lt3/r;)V

    .line 289
    .line 290
    .line 291
    new-array v6, v15, [Lt3/u1;

    .line 292
    .line 293
    aput-object v3, v6, v8

    .line 294
    .line 295
    aput-object v7, v6, v18

    .line 296
    .line 297
    aput-object v11, v6, v20

    .line 298
    .line 299
    aput-object v12, v6, v17

    .line 300
    .line 301
    new-instance v9, Ljava/util/ArrayList;

    .line 302
    .line 303
    invoke-direct {v9, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 304
    .line 305
    .line 306
    move v10, v8

    .line 307
    :goto_4
    if-ge v10, v15, :cond_4

    .line 308
    .line 309
    aget-object v14, v6, v10

    .line 310
    .line 311
    check-cast v14, Lt3/v1;

    .line 312
    .line 313
    iget-object v14, v14, Lt3/v1;->c:Lt3/r;

    .line 314
    .line 315
    invoke-virtual {v9, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    add-int/lit8 v10, v10, 0x1

    .line 319
    .line 320
    goto :goto_4

    .line 321
    :cond_4
    new-array v10, v8, [Lt3/r;

    .line 322
    .line 323
    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v9

    .line 327
    check-cast v9, [Lt3/r;

    .line 328
    .line 329
    array-length v10, v9

    .line 330
    invoke-static {v9, v10}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v9

    .line 334
    check-cast v9, [Lt3/r;

    .line 335
    .line 336
    new-instance v10, Lt3/r;

    .line 337
    .line 338
    invoke-direct {v10, v9}, Lt3/r;-><init>([Lt3/r;)V

    .line 339
    .line 340
    .line 341
    new-instance v9, Ljava/util/ArrayList;

    .line 342
    .line 343
    invoke-direct {v9, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 344
    .line 345
    .line 346
    move v10, v8

    .line 347
    :goto_5
    if-ge v10, v15, :cond_5

    .line 348
    .line 349
    aget-object v14, v6, v10

    .line 350
    .line 351
    check-cast v14, Lt3/v1;

    .line 352
    .line 353
    iget-object v14, v14, Lt3/v1;->d:Lt3/r;

    .line 354
    .line 355
    invoke-virtual {v9, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 356
    .line 357
    .line 358
    add-int/lit8 v10, v10, 0x1

    .line 359
    .line 360
    goto :goto_5

    .line 361
    :cond_5
    new-array v6, v8, [Lt3/r;

    .line 362
    .line 363
    invoke-virtual {v9, v6}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v6

    .line 367
    check-cast v6, [Lt3/r;

    .line 368
    .line 369
    array-length v9, v6

    .line 370
    invoke-static {v6, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v6

    .line 374
    check-cast v6, [Lt3/r;

    .line 375
    .line 376
    new-instance v9, Lt3/r;

    .line 377
    .line 378
    invoke-direct {v9, v6}, Lt3/r;-><init>([Lt3/r;)V

    .line 379
    .line 380
    .line 381
    const/16 v6, 0x9

    .line 382
    .line 383
    new-array v9, v6, [Lt3/u1;

    .line 384
    .line 385
    aput-object v5, v9, v8

    .line 386
    .line 387
    aput-object v4, v9, v18

    .line 388
    .line 389
    aput-object v0, v9, v20

    .line 390
    .line 391
    aput-object v2, v9, v17

    .line 392
    .line 393
    aput-object v7, v9, v15

    .line 394
    .line 395
    aput-object v3, v9, v16

    .line 396
    .line 397
    aput-object v11, v9, v13

    .line 398
    .line 399
    const/4 v0, 0x7

    .line 400
    aput-object v1, v9, v0

    .line 401
    .line 402
    const/16 v0, 0x8

    .line 403
    .line 404
    aput-object v12, v9, v0

    .line 405
    .line 406
    new-instance v0, Ljava/util/ArrayList;

    .line 407
    .line 408
    invoke-direct {v0, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 409
    .line 410
    .line 411
    move v1, v8

    .line 412
    :goto_6
    if-ge v1, v6, :cond_6

    .line 413
    .line 414
    aget-object v2, v9, v1

    .line 415
    .line 416
    check-cast v2, Lt3/v1;

    .line 417
    .line 418
    iget-object v2, v2, Lt3/v1;->c:Lt3/r;

    .line 419
    .line 420
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 421
    .line 422
    .line 423
    add-int/lit8 v1, v1, 0x1

    .line 424
    .line 425
    goto :goto_6

    .line 426
    :cond_6
    new-array v1, v8, [Lt3/r;

    .line 427
    .line 428
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    check-cast v0, [Lt3/r;

    .line 433
    .line 434
    array-length v1, v0

    .line 435
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    check-cast v0, [Lt3/r;

    .line 440
    .line 441
    new-instance v1, Lt3/r;

    .line 442
    .line 443
    invoke-direct {v1, v0}, Lt3/r;-><init>([Lt3/r;)V

    .line 444
    .line 445
    .line 446
    new-instance v0, Ljava/util/ArrayList;

    .line 447
    .line 448
    invoke-direct {v0, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 449
    .line 450
    .line 451
    move v1, v8

    .line 452
    :goto_7
    if-ge v1, v6, :cond_7

    .line 453
    .line 454
    aget-object v2, v9, v1

    .line 455
    .line 456
    check-cast v2, Lt3/v1;

    .line 457
    .line 458
    iget-object v2, v2, Lt3/v1;->d:Lt3/r;

    .line 459
    .line 460
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    add-int/lit8 v1, v1, 0x1

    .line 464
    .line 465
    goto :goto_7

    .line 466
    :cond_7
    new-array v1, v8, [Lt3/r;

    .line 467
    .line 468
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 469
    .line 470
    .line 471
    move-result-object v0

    .line 472
    check-cast v0, [Lt3/r;

    .line 473
    .line 474
    array-length v1, v0

    .line 475
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 476
    .line 477
    .line 478
    move-result-object v0

    .line 479
    check-cast v0, [Lt3/r;

    .line 480
    .line 481
    new-instance v1, Lt3/r;

    .line 482
    .line 483
    invoke-direct {v1, v0}, Lt3/r;-><init>([Lt3/r;)V

    .line 484
    .line 485
    .line 486
    return-void
.end method
