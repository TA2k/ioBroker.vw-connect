.class public final Lmv/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public volatile a:Landroid/graphics/Bitmap;

.field public volatile b:Lhu/q;

.field public final c:I

.field public final d:I

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(Landroid/graphics/Bitmap;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object p1, p0, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 2
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v0

    iput v0, p0, Lmv/a;->c:I

    .line 3
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    move-result p1

    iput p1, p0, Lmv/a;->d:I

    const/4 p1, 0x0

    .line 4
    invoke-static {p1}, Lmv/a;->c(I)V

    iput p1, p0, Lmv/a;->e:I

    const/4 p1, -0x1

    iput p1, p0, Lmv/a;->f:I

    return-void
.end method

.method public constructor <init>(Landroid/media/Image;III)V
    .locals 2

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Lhu/q;

    const/16 v1, 0x17

    invoke-direct {v0, p1, v1}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Lmv/a;->b:Lhu/q;

    iput p2, p0, Lmv/a;->c:I

    iput p3, p0, Lmv/a;->d:I

    .line 6
    invoke-static {p4}, Lmv/a;->c(I)V

    iput p4, p0, Lmv/a;->e:I

    const/16 p1, 0x23

    iput p1, p0, Lmv/a;->f:I

    return-void
.end method

.method public static a(Landroid/media/Image;I)Lmv/a;
    .locals 18

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v0}, Lmv/a;->c(I)V

    .line 8
    .line 9
    .line 10
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getFormat()I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    const/16 v4, 0x23

    .line 15
    .line 16
    const/4 v5, 0x1

    .line 17
    const/4 v6, 0x0

    .line 18
    const/16 v7, 0x100

    .line 19
    .line 20
    if-eq v3, v7, :cond_0

    .line 21
    .line 22
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getFormat()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ne v3, v4, :cond_1

    .line 27
    .line 28
    :cond_0
    move v3, v5

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    move v3, v6

    .line 31
    :goto_0
    const-string v8, "Only JPEG and YUV_420_888 are supported now"

    .line 32
    .line 33
    invoke-static {v3, v8}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getFormat()I

    .line 41
    .line 42
    .line 43
    move-result v8

    .line 44
    const/4 v9, 0x3

    .line 45
    if-ne v8, v7, :cond_4

    .line 46
    .line 47
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    aget-object v3, v3, v6

    .line 52
    .line 53
    invoke-virtual {v3}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-virtual {v3}, Ljava/nio/Buffer;->limit()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    new-instance v8, Lmv/a;

    .line 62
    .line 63
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getFormat()I

    .line 64
    .line 65
    .line 66
    move-result v10

    .line 67
    if-ne v10, v7, :cond_2

    .line 68
    .line 69
    move v7, v5

    .line 70
    goto :goto_1

    .line 71
    :cond_2
    move v7, v6

    .line 72
    :goto_1
    const-string v10, "Only JPEG is supported now"

    .line 73
    .line 74
    invoke-static {v7, v10}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    if-eqz v7, :cond_3

    .line 82
    .line 83
    array-length v10, v7

    .line 84
    if-ne v10, v5, :cond_3

    .line 85
    .line 86
    aget-object v7, v7, v6

    .line 87
    .line 88
    invoke-virtual {v7}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 89
    .line 90
    .line 91
    move-result-object v7

    .line 92
    invoke-virtual {v7}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v7}, Ljava/nio/Buffer;->remaining()I

    .line 96
    .line 97
    .line 98
    move-result v10

    .line 99
    new-array v11, v10, [B

    .line 100
    .line 101
    invoke-virtual {v7, v11}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 102
    .line 103
    .line 104
    invoke-static {v11, v6, v10}, Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;

    .line 105
    .line 106
    .line 107
    move-result-object v6

    .line 108
    invoke-virtual {v6}, Landroid/graphics/Bitmap;->getWidth()I

    .line 109
    .line 110
    .line 111
    move-result v7

    .line 112
    invoke-virtual {v6}, Landroid/graphics/Bitmap;->getHeight()I

    .line 113
    .line 114
    .line 115
    move-result v10

    .line 116
    invoke-static {v6, v0, v7, v10}, Ljp/ya;->d(Landroid/graphics/Bitmap;III)Landroid/graphics/Bitmap;

    .line 117
    .line 118
    .line 119
    move-result-object v6

    .line 120
    invoke-direct {v8, v6}, Lmv/a;-><init>(Landroid/graphics/Bitmap;)V

    .line 121
    .line 122
    .line 123
    move-object/from16 v10, p0

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 127
    .line 128
    const-string v1, "Unexpected image format, JPEG should have exactly 1 image plane"

    .line 129
    .line 130
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw v0

    .line 134
    :cond_4
    array-length v7, v3

    .line 135
    move v8, v6

    .line 136
    :goto_2
    if-ge v8, v7, :cond_6

    .line 137
    .line 138
    aget-object v10, v3, v8

    .line 139
    .line 140
    invoke-virtual {v10}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 141
    .line 142
    .line 143
    move-result-object v11

    .line 144
    if-eqz v11, :cond_5

    .line 145
    .line 146
    invoke-virtual {v10}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 147
    .line 148
    .line 149
    move-result-object v10

    .line 150
    invoke-virtual {v10}, Ljava/nio/ByteBuffer;->rewind()Ljava/nio/Buffer;

    .line 151
    .line 152
    .line 153
    :cond_5
    add-int/lit8 v8, v8, 0x1

    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_6
    new-instance v8, Lmv/a;

    .line 157
    .line 158
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getWidth()I

    .line 159
    .line 160
    .line 161
    move-result v3

    .line 162
    invoke-virtual/range {p0 .. p0}, Landroid/media/Image;->getHeight()I

    .line 163
    .line 164
    .line 165
    move-result v7

    .line 166
    move-object/from16 v10, p0

    .line 167
    .line 168
    invoke-direct {v8, v10, v3, v7, v0}, Lmv/a;-><init>(Landroid/media/Image;III)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v10}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 172
    .line 173
    .line 174
    move-result-object v3

    .line 175
    aget-object v3, v3, v6

    .line 176
    .line 177
    invoke-virtual {v3}, Landroid/media/Image$Plane;->getBuffer()Ljava/nio/ByteBuffer;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    invoke-virtual {v3}, Ljava/nio/Buffer;->limit()I

    .line 182
    .line 183
    .line 184
    move-result v3

    .line 185
    mul-int/2addr v3, v9

    .line 186
    div-int/lit8 v3, v3, 0x2

    .line 187
    .line 188
    :goto_3
    invoke-virtual {v10}, Landroid/media/Image;->getFormat()I

    .line 189
    .line 190
    .line 191
    move-result v6

    .line 192
    invoke-virtual {v10}, Landroid/media/Image;->getHeight()I

    .line 193
    .line 194
    .line 195
    move-result v7

    .line 196
    invoke-virtual {v10}, Landroid/media/Image;->getWidth()I

    .line 197
    .line 198
    .line 199
    move-result v10

    .line 200
    const-class v11, Lkp/na;

    .line 201
    .line 202
    monitor-enter v11

    .line 203
    int-to-byte v5, v5

    .line 204
    or-int/lit8 v5, v5, 0x2

    .line 205
    .line 206
    int-to-byte v5, v5

    .line 207
    if-ne v5, v9, :cond_10

    .line 208
    .line 209
    :try_start_0
    new-instance v5, Lkp/ia;

    .line 210
    .line 211
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 212
    .line 213
    .line 214
    const-class v9, Lkp/na;

    .line 215
    .line 216
    monitor-enter v9
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 217
    :try_start_1
    sget-object v12, Lkp/na;->a:Lip/s;

    .line 218
    .line 219
    if-nez v12, :cond_7

    .line 220
    .line 221
    new-instance v12, Lip/s;

    .line 222
    .line 223
    const/4 v13, 0x2

    .line 224
    invoke-direct {v12, v13}, Lip/s;-><init>(I)V

    .line 225
    .line 226
    .line 227
    sput-object v12, Lkp/na;->a:Lip/s;

    .line 228
    .line 229
    goto :goto_4

    .line 230
    :catchall_0
    move-exception v0

    .line 231
    goto/16 :goto_8

    .line 232
    .line 233
    :cond_7
    :goto_4
    sget-object v12, Lkp/na;->a:Lip/s;

    .line 234
    .line 235
    invoke-virtual {v12, v5}, Lap0/o;->y(Ljava/lang/Object;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object v5

    .line 239
    check-cast v5, Lkp/la;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 240
    .line 241
    :try_start_2
    monitor-exit v9
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 242
    monitor-exit v11

    .line 243
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 244
    .line 245
    .line 246
    move-result-wide v11

    .line 247
    sub-long/2addr v11, v1

    .line 248
    sget-object v1, Lkp/k7;->e:Lkp/k7;

    .line 249
    .line 250
    iget-object v2, v5, Lkp/la;->e:Laq/t;

    .line 251
    .line 252
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 253
    .line 254
    .line 255
    move-result-wide v13

    .line 256
    iget-object v9, v5, Lkp/la;->i:Ljava/util/HashMap;

    .line 257
    .line 258
    invoke-virtual {v9, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v15

    .line 262
    if-nez v15, :cond_8

    .line 263
    .line 264
    move-object/from16 p0, v2

    .line 265
    .line 266
    move/from16 v17, v3

    .line 267
    .line 268
    goto :goto_5

    .line 269
    :cond_8
    invoke-virtual {v9, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v15

    .line 273
    check-cast v15, Ljava/lang/Long;

    .line 274
    .line 275
    invoke-virtual {v15}, Ljava/lang/Long;->longValue()J

    .line 276
    .line 277
    .line 278
    move-result-wide v15

    .line 279
    sub-long v15, v13, v15

    .line 280
    .line 281
    sget-object v4, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 282
    .line 283
    move-object/from16 p0, v2

    .line 284
    .line 285
    move/from16 v17, v3

    .line 286
    .line 287
    const-wide/16 v2, 0x1e

    .line 288
    .line 289
    invoke-virtual {v4, v2, v3}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 290
    .line 291
    .line 292
    move-result-wide v2

    .line 293
    cmp-long v2, v15, v2

    .line 294
    .line 295
    if-gtz v2, :cond_9

    .line 296
    .line 297
    return-object v8

    .line 298
    :cond_9
    :goto_5
    invoke-static {v13, v14}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    invoke-virtual {v9, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    new-instance v1, Lss/b;

    .line 306
    .line 307
    const/4 v2, 0x6

    .line 308
    invoke-direct {v1, v2}, Lss/b;-><init>(I)V

    .line 309
    .line 310
    .line 311
    const/4 v2, -0x1

    .line 312
    if-eq v6, v2, :cond_e

    .line 313
    .line 314
    const/16 v2, 0x23

    .line 315
    .line 316
    if-eq v6, v2, :cond_d

    .line 317
    .line 318
    const v2, 0x32315659

    .line 319
    .line 320
    .line 321
    if-eq v6, v2, :cond_c

    .line 322
    .line 323
    const/16 v2, 0x10

    .line 324
    .line 325
    if-eq v6, v2, :cond_b

    .line 326
    .line 327
    const/16 v2, 0x11

    .line 328
    .line 329
    if-eq v6, v2, :cond_a

    .line 330
    .line 331
    sget-object v2, Lkp/z6;->e:Lkp/z6;

    .line 332
    .line 333
    goto :goto_6

    .line 334
    :cond_a
    sget-object v2, Lkp/z6;->g:Lkp/z6;

    .line 335
    .line 336
    goto :goto_6

    .line 337
    :cond_b
    sget-object v2, Lkp/z6;->f:Lkp/z6;

    .line 338
    .line 339
    goto :goto_6

    .line 340
    :cond_c
    sget-object v2, Lkp/z6;->h:Lkp/z6;

    .line 341
    .line 342
    goto :goto_6

    .line 343
    :cond_d
    sget-object v2, Lkp/z6;->i:Lkp/z6;

    .line 344
    .line 345
    goto :goto_6

    .line 346
    :cond_e
    sget-object v2, Lkp/z6;->j:Lkp/z6;

    .line 347
    .line 348
    :goto_6
    iput-object v2, v1, Lss/b;->g:Ljava/lang/Object;

    .line 349
    .line 350
    sget-object v2, Lkp/e7;->e:Lkp/e7;

    .line 351
    .line 352
    iput-object v2, v1, Lss/b;->f:Ljava/lang/Object;

    .line 353
    .line 354
    const v2, 0x7fffffff

    .line 355
    .line 356
    .line 357
    and-int v3, v17, v2

    .line 358
    .line 359
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 360
    .line 361
    .line 362
    move-result-object v3

    .line 363
    iput-object v3, v1, Lss/b;->h:Ljava/lang/Object;

    .line 364
    .line 365
    and-int v3, v7, v2

    .line 366
    .line 367
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 368
    .line 369
    .line 370
    move-result-object v3

    .line 371
    iput-object v3, v1, Lss/b;->j:Ljava/lang/Object;

    .line 372
    .line 373
    and-int v3, v10, v2

    .line 374
    .line 375
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 376
    .line 377
    .line 378
    move-result-object v3

    .line 379
    iput-object v3, v1, Lss/b;->i:Ljava/lang/Object;

    .line 380
    .line 381
    const-wide v3, 0x7fffffffffffffffL

    .line 382
    .line 383
    .line 384
    .line 385
    .line 386
    and-long/2addr v3, v11

    .line 387
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 388
    .line 389
    .line 390
    move-result-object v3

    .line 391
    iput-object v3, v1, Lss/b;->e:Ljava/lang/Object;

    .line 392
    .line 393
    and-int/2addr v0, v2

    .line 394
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 395
    .line 396
    .line 397
    move-result-object v0

    .line 398
    iput-object v0, v1, Lss/b;->k:Ljava/lang/Object;

    .line 399
    .line 400
    new-instance v0, Lkp/f7;

    .line 401
    .line 402
    invoke-direct {v0, v1}, Lkp/f7;-><init>(Lss/b;)V

    .line 403
    .line 404
    .line 405
    new-instance v1, Lil/g;

    .line 406
    .line 407
    const/4 v2, 0x7

    .line 408
    const/4 v3, 0x0

    .line 409
    invoke-direct {v1, v2, v3}, Lil/g;-><init>(IZ)V

    .line 410
    .line 411
    .line 412
    iput-object v0, v1, Lil/g;->g:Ljava/lang/Object;

    .line 413
    .line 414
    new-instance v0, Lvp/y1;

    .line 415
    .line 416
    invoke-direct {v0, v1}, Lvp/y1;-><init>(Lil/g;)V

    .line 417
    .line 418
    .line 419
    invoke-virtual/range {p0 .. p0}, Laq/t;->i()Z

    .line 420
    .line 421
    .line 422
    move-result v1

    .line 423
    if-eqz v1, :cond_f

    .line 424
    .line 425
    invoke-virtual/range {p0 .. p0}, Laq/t;->g()Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    move-result-object v1

    .line 429
    check-cast v1, Ljava/lang/String;

    .line 430
    .line 431
    goto :goto_7

    .line 432
    :cond_f
    sget-object v1, Lno/k;->c:Lno/k;

    .line 433
    .line 434
    iget-object v2, v5, Lkp/la;->g:Ljava/lang/String;

    .line 435
    .line 436
    invoke-virtual {v1, v2}, Lno/k;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    :goto_7
    sget-object v2, Lfv/l;->d:Lfv/l;

    .line 441
    .line 442
    new-instance v3, Lio/i;

    .line 443
    .line 444
    invoke-direct {v3, v5, v0, v1}, Lio/i;-><init>(Lkp/la;Lvp/y1;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    invoke-virtual {v2, v3}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 448
    .line 449
    .line 450
    return-object v8

    .line 451
    :goto_8
    :try_start_3
    monitor-exit v9
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 452
    :try_start_4
    throw v0

    .line 453
    :cond_10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 454
    .line 455
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 456
    .line 457
    .line 458
    and-int/lit8 v1, v5, 0x1

    .line 459
    .line 460
    if-nez v1, :cond_11

    .line 461
    .line 462
    const-string v1, " enableFirelog"

    .line 463
    .line 464
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 465
    .line 466
    .line 467
    :cond_11
    and-int/lit8 v1, v5, 0x2

    .line 468
    .line 469
    if-nez v1, :cond_12

    .line 470
    .line 471
    const-string v1, " firelogEventType"

    .line 472
    .line 473
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 474
    .line 475
    .line 476
    :cond_12
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 477
    .line 478
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 479
    .line 480
    .line 481
    move-result-object v0

    .line 482
    const-string v2, "Missing required properties:"

    .line 483
    .line 484
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    throw v1

    .line 492
    :goto_9
    monitor-exit v11
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 493
    throw v0

    .line 494
    :catchall_1
    move-exception v0

    .line 495
    goto :goto_9
.end method

.method public static c(I)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p0, :cond_1

    .line 3
    .line 4
    const/16 v1, 0x5a

    .line 5
    .line 6
    if-eq p0, v1, :cond_1

    .line 7
    .line 8
    const/16 v1, 0xb4

    .line 9
    .line 10
    if-eq p0, v1, :cond_1

    .line 11
    .line 12
    const/16 v1, 0x10e

    .line 13
    .line 14
    if-ne p0, v1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    :cond_1
    :goto_0
    const-string p0, "Invalid rotation. Only 0, 90, 180, 270 are supported currently."

    .line 19
    .line 20
    invoke-static {v0, p0}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final b()[Landroid/media/Image$Plane;
    .locals 1

    .line 1
    iget-object v0, p0, Lmv/a;->b:Lhu/q;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return-object p0

    .line 7
    :cond_0
    iget-object p0, p0, Lmv/a;->b:Lhu/q;

    .line 8
    .line 9
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Landroid/media/Image;

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/media/Image;->getPlanes()[Landroid/media/Image$Plane;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method
