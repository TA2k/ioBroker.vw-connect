.class public final Lv9/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv9/h;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:I

.field public final c:Lw7/p;

.field public final d:Lm9/f;

.field public e:Lo8/i0;

.field public f:Ljava/lang/String;

.field public g:Lt7/o;

.field public h:I

.field public i:I

.field public j:I

.field public k:I

.field public l:J

.field public m:Z

.field public n:I

.field public o:I

.field public p:I

.field public q:Z

.field public r:J

.field public s:I

.field public t:J

.field public u:I

.field public v:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lv9/s;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput p2, p0, Lv9/s;->b:I

    .line 7
    .line 8
    new-instance p1, Lw7/p;

    .line 9
    .line 10
    const/16 p2, 0x400

    .line 11
    .line 12
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lv9/s;->c:Lw7/p;

    .line 16
    .line 17
    new-instance p2, Lm9/f;

    .line 18
    .line 19
    iget-object p1, p1, Lw7/p;->a:[B

    .line 20
    .line 21
    array-length v0, p1

    .line 22
    invoke-direct {p2, v0, p1}, Lm9/f;-><init>(I[B)V

    .line 23
    .line 24
    .line 25
    iput-object p2, p0, Lv9/s;->d:Lm9/f;

    .line 26
    .line 27
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 28
    .line 29
    .line 30
    .line 31
    .line 32
    iput-wide p1, p0, Lv9/s;->l:J

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final b(Lw7/p;)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lv9/s;->e:Lo8/i0;

    .line 4
    .line 5
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    :goto_0
    invoke-virtual/range {p1 .. p1}, Lw7/p;->a()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-lez v1, :cond_1e

    .line 13
    .line 14
    iget v1, v0, Lv9/s;->h:I

    .line 15
    .line 16
    const/16 v2, 0x56

    .line 17
    .line 18
    const/4 v3, 0x1

    .line 19
    if-eqz v1, :cond_1d

    .line 20
    .line 21
    const/4 v4, 0x2

    .line 22
    const/4 v5, 0x0

    .line 23
    if-eq v1, v3, :cond_1b

    .line 24
    .line 25
    iget-object v2, v0, Lv9/s;->c:Lw7/p;

    .line 26
    .line 27
    const/16 v6, 0x8

    .line 28
    .line 29
    const/4 v7, 0x3

    .line 30
    iget-object v8, v0, Lv9/s;->d:Lm9/f;

    .line 31
    .line 32
    if-eq v1, v4, :cond_19

    .line 33
    .line 34
    if-ne v1, v7, :cond_18

    .line 35
    .line 36
    invoke-virtual/range {p1 .. p1}, Lw7/p;->a()I

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    iget v9, v0, Lv9/s;->j:I

    .line 41
    .line 42
    iget v10, v0, Lv9/s;->i:I

    .line 43
    .line 44
    sub-int/2addr v9, v10

    .line 45
    invoke-static {v1, v9}, Ljava/lang/Math;->min(II)I

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    iget-object v9, v8, Lm9/f;->b:[B

    .line 50
    .line 51
    iget v10, v0, Lv9/s;->i:I

    .line 52
    .line 53
    move-object/from16 v11, p1

    .line 54
    .line 55
    invoke-virtual {v11, v9, v10, v1}, Lw7/p;->h([BII)V

    .line 56
    .line 57
    .line 58
    iget v9, v0, Lv9/s;->i:I

    .line 59
    .line 60
    add-int/2addr v9, v1

    .line 61
    iput v9, v0, Lv9/s;->i:I

    .line 62
    .line 63
    iget v1, v0, Lv9/s;->j:I

    .line 64
    .line 65
    if-ne v9, v1, :cond_0

    .line 66
    .line 67
    invoke-virtual {v8, v5}, Lm9/f;->q(I)V

    .line 68
    .line 69
    .line 70
    invoke-virtual {v8}, Lm9/f;->h()Z

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    const/4 v9, 0x0

    .line 75
    if-nez v1, :cond_f

    .line 76
    .line 77
    iput-boolean v3, v0, Lv9/s;->m:Z

    .line 78
    .line 79
    invoke-virtual {v8, v3}, Lm9/f;->i(I)I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-ne v1, v3, :cond_1

    .line 84
    .line 85
    invoke-virtual {v8, v3}, Lm9/f;->i(I)I

    .line 86
    .line 87
    .line 88
    move-result v10

    .line 89
    goto :goto_1

    .line 90
    :cond_1
    move v10, v5

    .line 91
    :goto_1
    iput v10, v0, Lv9/s;->n:I

    .line 92
    .line 93
    if-nez v10, :cond_e

    .line 94
    .line 95
    if-ne v1, v3, :cond_2

    .line 96
    .line 97
    invoke-virtual {v8, v4}, Lm9/f;->i(I)I

    .line 98
    .line 99
    .line 100
    move-result v10

    .line 101
    add-int/2addr v10, v3

    .line 102
    mul-int/2addr v10, v6

    .line 103
    invoke-virtual {v8, v10}, Lm9/f;->i(I)I

    .line 104
    .line 105
    .line 106
    :cond_2
    invoke-virtual {v8}, Lm9/f;->h()Z

    .line 107
    .line 108
    .line 109
    move-result v10

    .line 110
    if-eqz v10, :cond_d

    .line 111
    .line 112
    const/4 v10, 0x6

    .line 113
    invoke-virtual {v8, v10}, Lm9/f;->i(I)I

    .line 114
    .line 115
    .line 116
    move-result v12

    .line 117
    iput v12, v0, Lv9/s;->o:I

    .line 118
    .line 119
    const/4 v12, 0x4

    .line 120
    invoke-virtual {v8, v12}, Lm9/f;->i(I)I

    .line 121
    .line 122
    .line 123
    move-result v13

    .line 124
    invoke-virtual {v8, v7}, Lm9/f;->i(I)I

    .line 125
    .line 126
    .line 127
    move-result v14

    .line 128
    if-nez v13, :cond_c

    .line 129
    .line 130
    if-nez v14, :cond_c

    .line 131
    .line 132
    if-nez v1, :cond_3

    .line 133
    .line 134
    invoke-virtual {v8}, Lm9/f;->g()I

    .line 135
    .line 136
    .line 137
    move-result v13

    .line 138
    invoke-virtual {v8}, Lm9/f;->b()I

    .line 139
    .line 140
    .line 141
    move-result v14

    .line 142
    invoke-static {v8, v3}, Lo8/b;->n(Lm9/f;Z)Lo8/a;

    .line 143
    .line 144
    .line 145
    move-result-object v15

    .line 146
    iget-object v5, v15, Lo8/a;->a:Ljava/lang/String;

    .line 147
    .line 148
    iput-object v5, v0, Lv9/s;->v:Ljava/lang/String;

    .line 149
    .line 150
    iget v5, v15, Lo8/a;->b:I

    .line 151
    .line 152
    iput v5, v0, Lv9/s;->s:I

    .line 153
    .line 154
    iget v5, v15, Lo8/a;->c:I

    .line 155
    .line 156
    iput v5, v0, Lv9/s;->u:I

    .line 157
    .line 158
    invoke-virtual {v8}, Lm9/f;->b()I

    .line 159
    .line 160
    .line 161
    move-result v5

    .line 162
    sub-int/2addr v14, v5

    .line 163
    invoke-virtual {v8, v13}, Lm9/f;->q(I)V

    .line 164
    .line 165
    .line 166
    add-int/lit8 v5, v14, 0x7

    .line 167
    .line 168
    div-int/2addr v5, v6

    .line 169
    new-array v5, v5, [B

    .line 170
    .line 171
    invoke-virtual {v8, v14, v5}, Lm9/f;->j(I[B)V

    .line 172
    .line 173
    .line 174
    new-instance v13, Lt7/n;

    .line 175
    .line 176
    invoke-direct {v13}, Lt7/n;-><init>()V

    .line 177
    .line 178
    .line 179
    iget-object v14, v0, Lv9/s;->f:Ljava/lang/String;

    .line 180
    .line 181
    iput-object v14, v13, Lt7/n;->a:Ljava/lang/String;

    .line 182
    .line 183
    const-string v14, "video/mp2t"

    .line 184
    .line 185
    invoke-static {v14}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 186
    .line 187
    .line 188
    move-result-object v14

    .line 189
    iput-object v14, v13, Lt7/n;->l:Ljava/lang/String;

    .line 190
    .line 191
    const-string v14, "audio/mp4a-latm"

    .line 192
    .line 193
    invoke-static {v14}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object v14

    .line 197
    iput-object v14, v13, Lt7/n;->m:Ljava/lang/String;

    .line 198
    .line 199
    iget-object v14, v0, Lv9/s;->v:Ljava/lang/String;

    .line 200
    .line 201
    iput-object v14, v13, Lt7/n;->j:Ljava/lang/String;

    .line 202
    .line 203
    iget v14, v0, Lv9/s;->u:I

    .line 204
    .line 205
    iput v14, v13, Lt7/n;->E:I

    .line 206
    .line 207
    iget v14, v0, Lv9/s;->s:I

    .line 208
    .line 209
    iput v14, v13, Lt7/n;->F:I

    .line 210
    .line 211
    invoke-static {v5}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 212
    .line 213
    .line 214
    move-result-object v5

    .line 215
    iput-object v5, v13, Lt7/n;->p:Ljava/util/List;

    .line 216
    .line 217
    iget-object v5, v0, Lv9/s;->a:Ljava/lang/String;

    .line 218
    .line 219
    iput-object v5, v13, Lt7/n;->d:Ljava/lang/String;

    .line 220
    .line 221
    iget v5, v0, Lv9/s;->b:I

    .line 222
    .line 223
    iput v5, v13, Lt7/n;->f:I

    .line 224
    .line 225
    new-instance v5, Lt7/o;

    .line 226
    .line 227
    invoke-direct {v5, v13}, Lt7/o;-><init>(Lt7/n;)V

    .line 228
    .line 229
    .line 230
    iget-object v13, v0, Lv9/s;->g:Lt7/o;

    .line 231
    .line 232
    invoke-virtual {v5, v13}, Lt7/o;->equals(Ljava/lang/Object;)Z

    .line 233
    .line 234
    .line 235
    move-result v13

    .line 236
    if-nez v13, :cond_4

    .line 237
    .line 238
    iput-object v5, v0, Lv9/s;->g:Lt7/o;

    .line 239
    .line 240
    iget v13, v5, Lt7/o;->G:I

    .line 241
    .line 242
    int-to-long v13, v13

    .line 243
    const-wide/32 v16, 0x3d090000

    .line 244
    .line 245
    .line 246
    div-long v13, v16, v13

    .line 247
    .line 248
    iput-wide v13, v0, Lv9/s;->t:J

    .line 249
    .line 250
    iget-object v13, v0, Lv9/s;->e:Lo8/i0;

    .line 251
    .line 252
    invoke-interface {v13, v5}, Lo8/i0;->c(Lt7/o;)V

    .line 253
    .line 254
    .line 255
    goto :goto_2

    .line 256
    :cond_3
    invoke-virtual {v8, v4}, Lm9/f;->i(I)I

    .line 257
    .line 258
    .line 259
    move-result v5

    .line 260
    add-int/2addr v5, v3

    .line 261
    mul-int/2addr v5, v6

    .line 262
    invoke-virtual {v8, v5}, Lm9/f;->i(I)I

    .line 263
    .line 264
    .line 265
    move-result v5

    .line 266
    int-to-long v13, v5

    .line 267
    long-to-int v5, v13

    .line 268
    invoke-virtual {v8}, Lm9/f;->b()I

    .line 269
    .line 270
    .line 271
    move-result v13

    .line 272
    invoke-static {v8, v3}, Lo8/b;->n(Lm9/f;Z)Lo8/a;

    .line 273
    .line 274
    .line 275
    move-result-object v14

    .line 276
    iget-object v15, v14, Lo8/a;->a:Ljava/lang/String;

    .line 277
    .line 278
    iput-object v15, v0, Lv9/s;->v:Ljava/lang/String;

    .line 279
    .line 280
    iget v15, v14, Lo8/a;->b:I

    .line 281
    .line 282
    iput v15, v0, Lv9/s;->s:I

    .line 283
    .line 284
    iget v14, v14, Lo8/a;->c:I

    .line 285
    .line 286
    iput v14, v0, Lv9/s;->u:I

    .line 287
    .line 288
    invoke-virtual {v8}, Lm9/f;->b()I

    .line 289
    .line 290
    .line 291
    move-result v14

    .line 292
    sub-int/2addr v13, v14

    .line 293
    sub-int/2addr v5, v13

    .line 294
    invoke-virtual {v8, v5}, Lm9/f;->t(I)V

    .line 295
    .line 296
    .line 297
    :cond_4
    :goto_2
    invoke-virtual {v8, v7}, Lm9/f;->i(I)I

    .line 298
    .line 299
    .line 300
    move-result v5

    .line 301
    iput v5, v0, Lv9/s;->p:I

    .line 302
    .line 303
    if-eqz v5, :cond_9

    .line 304
    .line 305
    if-eq v5, v3, :cond_8

    .line 306
    .line 307
    if-eq v5, v7, :cond_7

    .line 308
    .line 309
    if-eq v5, v12, :cond_7

    .line 310
    .line 311
    const/4 v7, 0x5

    .line 312
    if-eq v5, v7, :cond_7

    .line 313
    .line 314
    if-eq v5, v10, :cond_6

    .line 315
    .line 316
    const/4 v7, 0x7

    .line 317
    if-ne v5, v7, :cond_5

    .line 318
    .line 319
    goto :goto_3

    .line 320
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 321
    .line 322
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 323
    .line 324
    .line 325
    throw v0

    .line 326
    :cond_6
    :goto_3
    invoke-virtual {v8, v3}, Lm9/f;->t(I)V

    .line 327
    .line 328
    .line 329
    goto :goto_4

    .line 330
    :cond_7
    invoke-virtual {v8, v10}, Lm9/f;->t(I)V

    .line 331
    .line 332
    .line 333
    goto :goto_4

    .line 334
    :cond_8
    const/16 v5, 0x9

    .line 335
    .line 336
    invoke-virtual {v8, v5}, Lm9/f;->t(I)V

    .line 337
    .line 338
    .line 339
    goto :goto_4

    .line 340
    :cond_9
    invoke-virtual {v8, v6}, Lm9/f;->t(I)V

    .line 341
    .line 342
    .line 343
    :goto_4
    invoke-virtual {v8}, Lm9/f;->h()Z

    .line 344
    .line 345
    .line 346
    move-result v5

    .line 347
    iput-boolean v5, v0, Lv9/s;->q:Z

    .line 348
    .line 349
    const-wide/16 v12, 0x0

    .line 350
    .line 351
    iput-wide v12, v0, Lv9/s;->r:J

    .line 352
    .line 353
    if-eqz v5, :cond_b

    .line 354
    .line 355
    if-ne v1, v3, :cond_a

    .line 356
    .line 357
    invoke-virtual {v8, v4}, Lm9/f;->i(I)I

    .line 358
    .line 359
    .line 360
    move-result v1

    .line 361
    add-int/2addr v1, v3

    .line 362
    mul-int/2addr v1, v6

    .line 363
    invoke-virtual {v8, v1}, Lm9/f;->i(I)I

    .line 364
    .line 365
    .line 366
    move-result v1

    .line 367
    int-to-long v4, v1

    .line 368
    iput-wide v4, v0, Lv9/s;->r:J

    .line 369
    .line 370
    goto :goto_5

    .line 371
    :cond_a
    invoke-virtual {v8}, Lm9/f;->h()Z

    .line 372
    .line 373
    .line 374
    move-result v1

    .line 375
    iget-wide v4, v0, Lv9/s;->r:J

    .line 376
    .line 377
    shl-long/2addr v4, v6

    .line 378
    invoke-virtual {v8, v6}, Lm9/f;->i(I)I

    .line 379
    .line 380
    .line 381
    move-result v7

    .line 382
    int-to-long v12, v7

    .line 383
    add-long/2addr v4, v12

    .line 384
    iput-wide v4, v0, Lv9/s;->r:J

    .line 385
    .line 386
    if-nez v1, :cond_a

    .line 387
    .line 388
    :cond_b
    :goto_5
    invoke-virtual {v8}, Lm9/f;->h()Z

    .line 389
    .line 390
    .line 391
    move-result v1

    .line 392
    if-eqz v1, :cond_10

    .line 393
    .line 394
    invoke-virtual {v8, v6}, Lm9/f;->t(I)V

    .line 395
    .line 396
    .line 397
    goto :goto_6

    .line 398
    :cond_c
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    throw v0

    .line 403
    :cond_d
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 404
    .line 405
    .line 406
    move-result-object v0

    .line 407
    throw v0

    .line 408
    :cond_e
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 409
    .line 410
    .line 411
    move-result-object v0

    .line 412
    throw v0

    .line 413
    :cond_f
    iget-boolean v1, v0, Lv9/s;->m:Z

    .line 414
    .line 415
    if-nez v1, :cond_10

    .line 416
    .line 417
    goto :goto_a

    .line 418
    :cond_10
    :goto_6
    iget v1, v0, Lv9/s;->n:I

    .line 419
    .line 420
    if-nez v1, :cond_17

    .line 421
    .line 422
    iget v1, v0, Lv9/s;->o:I

    .line 423
    .line 424
    if-nez v1, :cond_16

    .line 425
    .line 426
    iget v1, v0, Lv9/s;->p:I

    .line 427
    .line 428
    if-nez v1, :cond_15

    .line 429
    .line 430
    const/4 v1, 0x0

    .line 431
    :goto_7
    invoke-virtual {v8, v6}, Lm9/f;->i(I)I

    .line 432
    .line 433
    .line 434
    move-result v4

    .line 435
    add-int/2addr v1, v4

    .line 436
    const/16 v5, 0xff

    .line 437
    .line 438
    if-eq v4, v5, :cond_14

    .line 439
    .line 440
    invoke-virtual {v8}, Lm9/f;->g()I

    .line 441
    .line 442
    .line 443
    move-result v4

    .line 444
    and-int/lit8 v5, v4, 0x7

    .line 445
    .line 446
    if-nez v5, :cond_11

    .line 447
    .line 448
    shr-int/lit8 v4, v4, 0x3

    .line 449
    .line 450
    invoke-virtual {v2, v4}, Lw7/p;->I(I)V

    .line 451
    .line 452
    .line 453
    const/4 v4, 0x0

    .line 454
    goto :goto_8

    .line 455
    :cond_11
    iget-object v4, v2, Lw7/p;->a:[B

    .line 456
    .line 457
    mul-int/lit8 v5, v1, 0x8

    .line 458
    .line 459
    invoke-virtual {v8, v5, v4}, Lm9/f;->j(I[B)V

    .line 460
    .line 461
    .line 462
    const/4 v4, 0x0

    .line 463
    invoke-virtual {v2, v4}, Lw7/p;->I(I)V

    .line 464
    .line 465
    .line 466
    :goto_8
    iget-object v5, v0, Lv9/s;->e:Lo8/i0;

    .line 467
    .line 468
    invoke-interface {v5, v2, v1, v4}, Lo8/i0;->a(Lw7/p;II)V

    .line 469
    .line 470
    .line 471
    iget-wide v4, v0, Lv9/s;->l:J

    .line 472
    .line 473
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 474
    .line 475
    .line 476
    .line 477
    .line 478
    cmp-long v2, v4, v6

    .line 479
    .line 480
    if-eqz v2, :cond_12

    .line 481
    .line 482
    goto :goto_9

    .line 483
    :cond_12
    const/4 v3, 0x0

    .line 484
    :goto_9
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 485
    .line 486
    .line 487
    iget-object v2, v0, Lv9/s;->e:Lo8/i0;

    .line 488
    .line 489
    iget-wide v3, v0, Lv9/s;->l:J

    .line 490
    .line 491
    const/16 v21, 0x0

    .line 492
    .line 493
    const/16 v22, 0x0

    .line 494
    .line 495
    const/16 v19, 0x1

    .line 496
    .line 497
    move/from16 v20, v1

    .line 498
    .line 499
    move-object/from16 v16, v2

    .line 500
    .line 501
    move-wide/from16 v17, v3

    .line 502
    .line 503
    invoke-interface/range {v16 .. v22}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 504
    .line 505
    .line 506
    iget-wide v1, v0, Lv9/s;->l:J

    .line 507
    .line 508
    iget-wide v3, v0, Lv9/s;->t:J

    .line 509
    .line 510
    add-long/2addr v1, v3

    .line 511
    iput-wide v1, v0, Lv9/s;->l:J

    .line 512
    .line 513
    iget-boolean v1, v0, Lv9/s;->q:Z

    .line 514
    .line 515
    if-eqz v1, :cond_13

    .line 516
    .line 517
    iget-wide v1, v0, Lv9/s;->r:J

    .line 518
    .line 519
    long-to-int v1, v1

    .line 520
    invoke-virtual {v8, v1}, Lm9/f;->t(I)V

    .line 521
    .line 522
    .line 523
    :cond_13
    :goto_a
    const/4 v4, 0x0

    .line 524
    iput v4, v0, Lv9/s;->h:I

    .line 525
    .line 526
    goto/16 :goto_0

    .line 527
    .line 528
    :cond_14
    move/from16 v20, v1

    .line 529
    .line 530
    goto :goto_7

    .line 531
    :cond_15
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 532
    .line 533
    .line 534
    move-result-object v0

    .line 535
    throw v0

    .line 536
    :cond_16
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    throw v0

    .line 541
    :cond_17
    invoke-static {v9, v9}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 542
    .line 543
    .line 544
    move-result-object v0

    .line 545
    throw v0

    .line 546
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 547
    .line 548
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 549
    .line 550
    .line 551
    throw v0

    .line 552
    :cond_19
    move-object/from16 v11, p1

    .line 553
    .line 554
    iget v1, v0, Lv9/s;->k:I

    .line 555
    .line 556
    and-int/lit16 v1, v1, -0xe1

    .line 557
    .line 558
    shl-int/2addr v1, v6

    .line 559
    invoke-virtual {v11}, Lw7/p;->w()I

    .line 560
    .line 561
    .line 562
    move-result v3

    .line 563
    or-int/2addr v1, v3

    .line 564
    iput v1, v0, Lv9/s;->j:I

    .line 565
    .line 566
    iget-object v3, v2, Lw7/p;->a:[B

    .line 567
    .line 568
    array-length v3, v3

    .line 569
    if-le v1, v3, :cond_1a

    .line 570
    .line 571
    invoke-virtual {v2, v1}, Lw7/p;->F(I)V

    .line 572
    .line 573
    .line 574
    iget-object v1, v2, Lw7/p;->a:[B

    .line 575
    .line 576
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 577
    .line 578
    .line 579
    array-length v2, v1

    .line 580
    invoke-virtual {v8, v2, v1}, Lm9/f;->o(I[B)V

    .line 581
    .line 582
    .line 583
    :cond_1a
    const/4 v4, 0x0

    .line 584
    iput v4, v0, Lv9/s;->i:I

    .line 585
    .line 586
    iput v7, v0, Lv9/s;->h:I

    .line 587
    .line 588
    goto/16 :goto_0

    .line 589
    .line 590
    :cond_1b
    move-object/from16 v11, p1

    .line 591
    .line 592
    invoke-virtual {v11}, Lw7/p;->w()I

    .line 593
    .line 594
    .line 595
    move-result v1

    .line 596
    and-int/lit16 v3, v1, 0xe0

    .line 597
    .line 598
    const/16 v5, 0xe0

    .line 599
    .line 600
    if-ne v3, v5, :cond_1c

    .line 601
    .line 602
    iput v1, v0, Lv9/s;->k:I

    .line 603
    .line 604
    iput v4, v0, Lv9/s;->h:I

    .line 605
    .line 606
    goto/16 :goto_0

    .line 607
    .line 608
    :cond_1c
    if-eq v1, v2, :cond_0

    .line 609
    .line 610
    const/4 v4, 0x0

    .line 611
    iput v4, v0, Lv9/s;->h:I

    .line 612
    .line 613
    goto/16 :goto_0

    .line 614
    .line 615
    :cond_1d
    move-object/from16 v11, p1

    .line 616
    .line 617
    invoke-virtual {v11}, Lw7/p;->w()I

    .line 618
    .line 619
    .line 620
    move-result v1

    .line 621
    if-ne v1, v2, :cond_0

    .line 622
    .line 623
    iput v3, v0, Lv9/s;->h:I

    .line 624
    .line 625
    goto/16 :goto_0

    .line 626
    .line 627
    :cond_1e
    return-void
.end method

.method public final c()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lv9/s;->h:I

    .line 3
    .line 4
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 5
    .line 6
    .line 7
    .line 8
    .line 9
    iput-wide v1, p0, Lv9/s;->l:J

    .line 10
    .line 11
    iput-boolean v0, p0, Lv9/s;->m:Z

    .line 12
    .line 13
    return-void
.end method

.method public final d(Lo8/q;Lh11/h;)V
    .locals 2

    .line 1
    invoke-virtual {p2}, Lh11/h;->d()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 5
    .line 6
    .line 7
    iget v0, p2, Lh11/h;->f:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lv9/s;->e:Lo8/i0;

    .line 15
    .line 16
    invoke-virtual {p2}, Lh11/h;->i()V

    .line 17
    .line 18
    .line 19
    iget-object p1, p2, Lh11/h;->h:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p1, Ljava/lang/String;

    .line 22
    .line 23
    iput-object p1, p0, Lv9/s;->f:Ljava/lang/String;

    .line 24
    .line 25
    return-void
.end method

.method public final e(Z)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(IJ)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lv9/s;->l:J

    .line 2
    .line 3
    return-void
.end method
