.class public final Le9/c;
.super Llp/je;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lw7/p;

.field public final b:Lm9/f;

.field public c:Lw7/u;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lw7/p;

    .line 5
    .line 6
    invoke-direct {v0}, Lw7/p;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Le9/c;->a:Lw7/p;

    .line 10
    .line 11
    new-instance v0, Lm9/f;

    .line 12
    .line 13
    invoke-direct {v0}, Lm9/f;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Le9/c;->b:Lm9/f;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final b(Lx8/a;Ljava/nio/ByteBuffer;)Lt7/c0;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Le9/c;->a:Lw7/p;

    .line 6
    .line 7
    iget-object v3, v0, Le9/c;->b:Lm9/f;

    .line 8
    .line 9
    iget-object v4, v0, Le9/c;->c:Lw7/u;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    iget-wide v5, v1, Lx8/a;->m:J

    .line 14
    .line 15
    monitor-enter v4

    .line 16
    :try_start_0
    iget-wide v7, v4, Lw7/u;->b:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    .line 18
    monitor-exit v4

    .line 19
    cmp-long v4, v5, v7

    .line 20
    .line 21
    if-eqz v4, :cond_1

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :catchall_0
    move-exception v0

    .line 25
    :try_start_1
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw v0

    .line 27
    :cond_0
    :goto_0
    new-instance v4, Lw7/u;

    .line 28
    .line 29
    iget-wide v5, v1, Lz7/e;->j:J

    .line 30
    .line 31
    invoke-direct {v4, v5, v6}, Lw7/u;-><init>(J)V

    .line 32
    .line 33
    .line 34
    iput-object v4, v0, Le9/c;->c:Lw7/u;

    .line 35
    .line 36
    iget-wide v5, v1, Lz7/e;->j:J

    .line 37
    .line 38
    iget-wide v7, v1, Lx8/a;->m:J

    .line 39
    .line 40
    sub-long/2addr v5, v7

    .line 41
    invoke-virtual {v4, v5, v6}, Lw7/u;->a(J)J

    .line 42
    .line 43
    .line 44
    :cond_1
    invoke-virtual/range {p2 .. p2}, Ljava/nio/ByteBuffer;->array()[B

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    invoke-virtual/range {p2 .. p2}, Ljava/nio/Buffer;->limit()I

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    invoke-virtual {v2, v4, v1}, Lw7/p;->G(I[B)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v3, v4, v1}, Lm9/f;->o(I[B)V

    .line 56
    .line 57
    .line 58
    const/16 v1, 0x27

    .line 59
    .line 60
    invoke-virtual {v3, v1}, Lm9/f;->t(I)V

    .line 61
    .line 62
    .line 63
    const/4 v1, 0x1

    .line 64
    invoke-virtual {v3, v1}, Lm9/f;->i(I)I

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    int-to-long v4, v4

    .line 69
    const/16 v6, 0x20

    .line 70
    .line 71
    shl-long/2addr v4, v6

    .line 72
    invoke-virtual {v3, v6}, Lm9/f;->i(I)I

    .line 73
    .line 74
    .line 75
    move-result v6

    .line 76
    int-to-long v6, v6

    .line 77
    or-long v12, v4, v6

    .line 78
    .line 79
    const/16 v4, 0x14

    .line 80
    .line 81
    invoke-virtual {v3, v4}, Lm9/f;->t(I)V

    .line 82
    .line 83
    .line 84
    const/16 v4, 0xc

    .line 85
    .line 86
    invoke-virtual {v3, v4}, Lm9/f;->i(I)I

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    const/16 v5, 0x8

    .line 91
    .line 92
    invoke-virtual {v3, v5}, Lm9/f;->i(I)I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    const/16 v5, 0xe

    .line 97
    .line 98
    invoke-virtual {v2, v5}, Lw7/p;->J(I)V

    .line 99
    .line 100
    .line 101
    const/4 v5, 0x0

    .line 102
    if-eqz v3, :cond_19

    .line 103
    .line 104
    const/16 v6, 0xff

    .line 105
    .line 106
    const/4 v7, 0x4

    .line 107
    if-eq v3, v6, :cond_18

    .line 108
    .line 109
    if-eq v3, v7, :cond_e

    .line 110
    .line 111
    const/4 v4, 0x5

    .line 112
    if-eq v3, v4, :cond_3

    .line 113
    .line 114
    const/4 v4, 0x6

    .line 115
    if-eq v3, v4, :cond_2

    .line 116
    .line 117
    const/4 v0, 0x0

    .line 118
    goto/16 :goto_f

    .line 119
    .line 120
    :cond_2
    iget-object v0, v0, Le9/c;->c:Lw7/u;

    .line 121
    .line 122
    invoke-static {v12, v13, v2}, Le9/a;->d(JLw7/p;)J

    .line 123
    .line 124
    .line 125
    move-result-wide v8

    .line 126
    invoke-virtual {v0, v8, v9}, Lw7/u;->b(J)J

    .line 127
    .line 128
    .line 129
    move-result-wide v10

    .line 130
    new-instance v6, Le9/a;

    .line 131
    .line 132
    const/4 v7, 0x1

    .line 133
    invoke-direct/range {v6 .. v11}, Le9/a;-><init>(IJJ)V

    .line 134
    .line 135
    .line 136
    move-object v0, v6

    .line 137
    goto/16 :goto_f

    .line 138
    .line 139
    :cond_3
    iget-object v0, v0, Le9/c;->c:Lw7/u;

    .line 140
    .line 141
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 142
    .line 143
    .line 144
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 145
    .line 146
    .line 147
    move-result v3

    .line 148
    and-int/lit16 v3, v3, 0x80

    .line 149
    .line 150
    if-eqz v3, :cond_4

    .line 151
    .line 152
    move v3, v1

    .line 153
    goto :goto_1

    .line 154
    :cond_4
    move v3, v5

    .line 155
    :goto_1
    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 156
    .line 157
    if-nez v3, :cond_d

    .line 158
    .line 159
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    and-int/lit8 v6, v3, 0x40

    .line 164
    .line 165
    if-eqz v6, :cond_5

    .line 166
    .line 167
    move v6, v1

    .line 168
    goto :goto_2

    .line 169
    :cond_5
    move v6, v5

    .line 170
    :goto_2
    and-int/lit8 v10, v3, 0x20

    .line 171
    .line 172
    if-eqz v10, :cond_6

    .line 173
    .line 174
    move v10, v1

    .line 175
    goto :goto_3

    .line 176
    :cond_6
    move v10, v5

    .line 177
    :goto_3
    and-int/lit8 v3, v3, 0x10

    .line 178
    .line 179
    if-eqz v3, :cond_7

    .line 180
    .line 181
    move v3, v1

    .line 182
    goto :goto_4

    .line 183
    :cond_7
    move v3, v5

    .line 184
    :goto_4
    if-eqz v6, :cond_8

    .line 185
    .line 186
    if-nez v3, :cond_8

    .line 187
    .line 188
    invoke-static {v12, v13, v2}, Le9/a;->d(JLw7/p;)J

    .line 189
    .line 190
    .line 191
    move-result-wide v14

    .line 192
    goto :goto_5

    .line 193
    :cond_8
    const-wide v14, -0x7fffffffffffffffL    # -4.9E-324

    .line 194
    .line 195
    .line 196
    .line 197
    .line 198
    :goto_5
    if-nez v6, :cond_b

    .line 199
    .line 200
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    new-instance v6, Ljava/util/ArrayList;

    .line 205
    .line 206
    invoke-direct {v6, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 207
    .line 208
    .line 209
    move v11, v5

    .line 210
    :goto_6
    if-ge v11, v4, :cond_a

    .line 211
    .line 212
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 213
    .line 214
    .line 215
    if-nez v3, :cond_9

    .line 216
    .line 217
    invoke-static {v12, v13, v2}, Le9/a;->d(JLw7/p;)J

    .line 218
    .line 219
    .line 220
    move-result-wide v16

    .line 221
    move-wide/from16 v8, v16

    .line 222
    .line 223
    goto :goto_7

    .line 224
    :cond_9
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 225
    .line 226
    .line 227
    .line 228
    .line 229
    :goto_7
    new-instance v1, Lrb0/a;

    .line 230
    .line 231
    invoke-virtual {v0, v8, v9}, Lw7/u;->b(J)J

    .line 232
    .line 233
    .line 234
    invoke-direct {v1, v7}, Lrb0/a;-><init>(I)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {v6, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    add-int/lit8 v11, v11, 0x1

    .line 241
    .line 242
    const/4 v1, 0x1

    .line 243
    goto :goto_6

    .line 244
    :cond_a
    move-object v4, v6

    .line 245
    :cond_b
    if-eqz v10, :cond_c

    .line 246
    .line 247
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 248
    .line 249
    .line 250
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 251
    .line 252
    .line 253
    :cond_c
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 254
    .line 255
    .line 256
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 257
    .line 258
    .line 259
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 260
    .line 261
    .line 262
    move-wide v8, v14

    .line 263
    :goto_8
    move-object/from16 v21, v4

    .line 264
    .line 265
    goto :goto_9

    .line 266
    :cond_d
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 267
    .line 268
    .line 269
    .line 270
    .line 271
    goto :goto_8

    .line 272
    :goto_9
    new-instance v16, Le9/d;

    .line 273
    .line 274
    invoke-virtual {v0, v8, v9}, Lw7/u;->b(J)J

    .line 275
    .line 276
    .line 277
    move-result-wide v19

    .line 278
    move-wide/from16 v17, v8

    .line 279
    .line 280
    invoke-direct/range {v16 .. v21}, Le9/d;-><init>(JJLjava/util/List;)V

    .line 281
    .line 282
    .line 283
    move-object/from16 v0, v16

    .line 284
    .line 285
    goto/16 :goto_f

    .line 286
    .line 287
    :cond_e
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 288
    .line 289
    .line 290
    move-result v0

    .line 291
    new-instance v1, Ljava/util/ArrayList;

    .line 292
    .line 293
    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 294
    .line 295
    .line 296
    move v3, v5

    .line 297
    :goto_a
    if-ge v3, v0, :cond_17

    .line 298
    .line 299
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 300
    .line 301
    .line 302
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 303
    .line 304
    .line 305
    move-result v4

    .line 306
    and-int/lit16 v4, v4, 0x80

    .line 307
    .line 308
    if-eqz v4, :cond_f

    .line 309
    .line 310
    const/4 v4, 0x1

    .line 311
    goto :goto_b

    .line 312
    :cond_f
    move v4, v5

    .line 313
    :goto_b
    new-instance v6, Ljava/util/ArrayList;

    .line 314
    .line 315
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 316
    .line 317
    .line 318
    if-nez v4, :cond_16

    .line 319
    .line 320
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 321
    .line 322
    .line 323
    move-result v4

    .line 324
    and-int/lit8 v8, v4, 0x40

    .line 325
    .line 326
    if-eqz v8, :cond_10

    .line 327
    .line 328
    const/4 v8, 0x1

    .line 329
    goto :goto_c

    .line 330
    :cond_10
    move v8, v5

    .line 331
    :goto_c
    and-int/lit8 v4, v4, 0x20

    .line 332
    .line 333
    if-eqz v4, :cond_11

    .line 334
    .line 335
    const/4 v4, 0x1

    .line 336
    goto :goto_d

    .line 337
    :cond_11
    move v4, v5

    .line 338
    :goto_d
    if-eqz v8, :cond_12

    .line 339
    .line 340
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 341
    .line 342
    .line 343
    :cond_12
    if-nez v8, :cond_14

    .line 344
    .line 345
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    new-instance v8, Ljava/util/ArrayList;

    .line 350
    .line 351
    invoke-direct {v8, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 352
    .line 353
    .line 354
    move v9, v5

    .line 355
    :goto_e
    if-ge v9, v6, :cond_13

    .line 356
    .line 357
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 358
    .line 359
    .line 360
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 361
    .line 362
    .line 363
    new-instance v10, Lst/b;

    .line 364
    .line 365
    invoke-direct {v10, v7}, Lst/b;-><init>(I)V

    .line 366
    .line 367
    .line 368
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 369
    .line 370
    .line 371
    add-int/lit8 v9, v9, 0x1

    .line 372
    .line 373
    goto :goto_e

    .line 374
    :cond_13
    move-object v6, v8

    .line 375
    :cond_14
    if-eqz v4, :cond_15

    .line 376
    .line 377
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 378
    .line 379
    .line 380
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 381
    .line 382
    .line 383
    :cond_15
    invoke-virtual {v2}, Lw7/p;->C()I

    .line 384
    .line 385
    .line 386
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 387
    .line 388
    .line 389
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 390
    .line 391
    .line 392
    :cond_16
    new-instance v4, La0/j;

    .line 393
    .line 394
    invoke-direct {v4, v6}, La0/j;-><init>(Ljava/util/ArrayList;)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 398
    .line 399
    .line 400
    add-int/lit8 v3, v3, 0x1

    .line 401
    .line 402
    goto :goto_a

    .line 403
    :cond_17
    new-instance v0, Le9/f;

    .line 404
    .line 405
    invoke-direct {v0, v1}, Le9/f;-><init>(Ljava/util/ArrayList;)V

    .line 406
    .line 407
    .line 408
    goto :goto_f

    .line 409
    :cond_18
    invoke-virtual {v2}, Lw7/p;->y()J

    .line 410
    .line 411
    .line 412
    move-result-wide v10

    .line 413
    sub-int/2addr v4, v7

    .line 414
    new-array v0, v4, [B

    .line 415
    .line 416
    invoke-virtual {v2, v0, v5, v4}, Lw7/p;->h([BII)V

    .line 417
    .line 418
    .line 419
    new-instance v8, Le9/a;

    .line 420
    .line 421
    const/4 v9, 0x0

    .line 422
    invoke-direct/range {v8 .. v13}, Le9/a;-><init>(IJJ)V

    .line 423
    .line 424
    .line 425
    move-object v0, v8

    .line 426
    goto :goto_f

    .line 427
    :cond_19
    new-instance v0, Le9/e;

    .line 428
    .line 429
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 430
    .line 431
    .line 432
    :goto_f
    if-nez v0, :cond_1a

    .line 433
    .line 434
    new-instance v0, Lt7/c0;

    .line 435
    .line 436
    new-array v1, v5, [Lt7/b0;

    .line 437
    .line 438
    invoke-direct {v0, v1}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 439
    .line 440
    .line 441
    return-object v0

    .line 442
    :cond_1a
    new-instance v1, Lt7/c0;

    .line 443
    .line 444
    const/4 v2, 0x1

    .line 445
    new-array v2, v2, [Lt7/b0;

    .line 446
    .line 447
    aput-object v0, v2, v5

    .line 448
    .line 449
    invoke-direct {v1, v2}, Lt7/c0;-><init>([Lt7/b0;)V

    .line 450
    .line 451
    .line 452
    return-object v1
.end method
