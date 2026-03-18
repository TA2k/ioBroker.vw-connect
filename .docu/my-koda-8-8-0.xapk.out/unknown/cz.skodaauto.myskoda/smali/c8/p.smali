.class public final Lc8/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Z

.field public B:J

.field public C:J

.field public D:Z

.field public E:J

.field public F:Lw7/r;

.field public final a:Lbu/c;

.field public final b:[J

.field public c:Landroid/media/AudioTrack;

.field public d:I

.field public e:Lc8/o;

.field public f:I

.field public g:J

.field public h:F

.field public i:Z

.field public j:J

.field public k:I

.field public l:J

.field public m:J

.field public n:Ljava/lang/reflect/Method;

.field public o:J

.field public p:Z

.field public q:J

.field public r:J

.field public s:J

.field public t:J

.field public u:I

.field public v:I

.field public w:J

.field public x:J

.field public y:J

.field public z:J


# direct methods
.method public constructor <init>(Lbu/c;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lc8/p;->a:Lbu/c;

    .line 5
    .line 6
    :try_start_0
    const-class p1, Landroid/media/AudioTrack;

    .line 7
    .line 8
    const-string v0, "getLatency"

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-virtual {p1, v0, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    iput-object p1, p0, Lc8/p;->n:Ljava/lang/reflect/Method;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    .line 17
    :catch_0
    const/16 p1, 0xa

    .line 18
    .line 19
    new-array p1, p1, [J

    .line 20
    .line 21
    iput-object p1, p0, Lc8/p;->b:[J

    .line 22
    .line 23
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    iput-wide v0, p0, Lc8/p;->C:J

    .line 29
    .line 30
    iput-wide v0, p0, Lc8/p;->B:J

    .line 31
    .line 32
    sget-object p1, Lw7/r;->a:Lw7/r;

    .line 33
    .line 34
    iput-object p1, p0, Lc8/p;->F:Lw7/r;

    .line 35
    .line 36
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 31

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 4
    .line 5
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Landroid/media/AudioTrack;->getPlayState()I

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const-wide/16 v4, 0x3e8

    .line 13
    .line 14
    const-wide/16 v6, 0x0

    .line 15
    .line 16
    const/4 v9, 0x1

    .line 17
    const/4 v10, 0x3

    .line 18
    if-ne v2, v10, :cond_19

    .line 19
    .line 20
    iget-object v2, v0, Lc8/p;->F:Lw7/r;

    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 26
    .line 27
    .line 28
    move-result-wide v11

    .line 29
    div-long/2addr v11, v4

    .line 30
    iget-wide v13, v0, Lc8/p;->m:J

    .line 31
    .line 32
    sub-long v13, v11, v13

    .line 33
    .line 34
    const-wide/16 v15, 0x7530

    .line 35
    .line 36
    cmp-long v2, v13, v15

    .line 37
    .line 38
    if-ltz v2, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Lc8/p;->b()J

    .line 41
    .line 42
    .line 43
    move-result-wide v13

    .line 44
    iget v2, v0, Lc8/p;->f:I

    .line 45
    .line 46
    invoke-static {v2, v13, v14}, Lw7/w;->H(IJ)J

    .line 47
    .line 48
    .line 49
    move-result-wide v13

    .line 50
    cmp-long v2, v13, v6

    .line 51
    .line 52
    if-nez v2, :cond_0

    .line 53
    .line 54
    move-object/from16 v26, v1

    .line 55
    .line 56
    move-wide/from16 v16, v4

    .line 57
    .line 58
    move-wide/from16 v22, v6

    .line 59
    .line 60
    goto/16 :goto_8

    .line 61
    .line 62
    :cond_0
    iget v2, v0, Lc8/p;->u:I

    .line 63
    .line 64
    iget v15, v0, Lc8/p;->h:F

    .line 65
    .line 66
    invoke-static {v13, v14, v15}, Lw7/w;->t(JF)J

    .line 67
    .line 68
    .line 69
    move-result-wide v13

    .line 70
    sub-long/2addr v13, v11

    .line 71
    iget-object v15, v0, Lc8/p;->b:[J

    .line 72
    .line 73
    aput-wide v13, v15, v2

    .line 74
    .line 75
    iget v2, v0, Lc8/p;->u:I

    .line 76
    .line 77
    add-int/2addr v2, v9

    .line 78
    const/16 v13, 0xa

    .line 79
    .line 80
    rem-int/2addr v2, v13

    .line 81
    iput v2, v0, Lc8/p;->u:I

    .line 82
    .line 83
    iget v2, v0, Lc8/p;->v:I

    .line 84
    .line 85
    if-ge v2, v13, :cond_1

    .line 86
    .line 87
    add-int/2addr v2, v9

    .line 88
    iput v2, v0, Lc8/p;->v:I

    .line 89
    .line 90
    :cond_1
    iput-wide v11, v0, Lc8/p;->m:J

    .line 91
    .line 92
    iput-wide v6, v0, Lc8/p;->l:J

    .line 93
    .line 94
    const/4 v2, 0x0

    .line 95
    :goto_0
    iget v13, v0, Lc8/p;->v:I

    .line 96
    .line 97
    if-ge v2, v13, :cond_2

    .line 98
    .line 99
    move-wide/from16 v16, v4

    .line 100
    .line 101
    iget-wide v4, v0, Lc8/p;->l:J

    .line 102
    .line 103
    aget-wide v18, v15, v2

    .line 104
    .line 105
    int-to-long v13, v13

    .line 106
    div-long v18, v18, v13

    .line 107
    .line 108
    add-long v4, v18, v4

    .line 109
    .line 110
    iput-wide v4, v0, Lc8/p;->l:J

    .line 111
    .line 112
    add-int/lit8 v2, v2, 0x1

    .line 113
    .line 114
    move-wide/from16 v4, v16

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_2
    move-wide/from16 v16, v4

    .line 118
    .line 119
    iget-boolean v2, v0, Lc8/p;->p:Z

    .line 120
    .line 121
    const-string v4, "DefaultAudioSink"

    .line 122
    .line 123
    const-wide/32 v18, 0x7a120

    .line 124
    .line 125
    .line 126
    if-eqz v2, :cond_4

    .line 127
    .line 128
    iget-object v2, v0, Lc8/p;->n:Ljava/lang/reflect/Method;

    .line 129
    .line 130
    if-eqz v2, :cond_4

    .line 131
    .line 132
    const-wide/32 v20, 0x4c4b40

    .line 133
    .line 134
    .line 135
    iget-wide v13, v0, Lc8/p;->q:J

    .line 136
    .line 137
    sub-long v13, v11, v13

    .line 138
    .line 139
    cmp-long v5, v13, v18

    .line 140
    .line 141
    if-ltz v5, :cond_5

    .line 142
    .line 143
    const/4 v5, 0x0

    .line 144
    :try_start_0
    iget-object v13, v0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 145
    .line 146
    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 147
    .line 148
    .line 149
    invoke-virtual {v2, v13, v5}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    check-cast v2, Ljava/lang/Integer;

    .line 154
    .line 155
    sget-object v13, Lw7/w;->a:Ljava/lang/String;

    .line 156
    .line 157
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    int-to-long v13, v2

    .line 162
    mul-long v13, v13, v16

    .line 163
    .line 164
    iget-wide v9, v0, Lc8/p;->g:J

    .line 165
    .line 166
    sub-long/2addr v13, v9

    .line 167
    iput-wide v13, v0, Lc8/p;->o:J

    .line 168
    .line 169
    invoke-static {v13, v14, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 170
    .line 171
    .line 172
    move-result-wide v9

    .line 173
    iput-wide v9, v0, Lc8/p;->o:J

    .line 174
    .line 175
    cmp-long v13, v9, v20

    .line 176
    .line 177
    if-lez v13, :cond_3

    .line 178
    .line 179
    new-instance v13, Ljava/lang/StringBuilder;

    .line 180
    .line 181
    const-string v14, "Ignoring impossibly large audio latency: "

    .line 182
    .line 183
    invoke-direct {v13, v14}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v13, v9, v10}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 187
    .line 188
    .line 189
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 190
    .line 191
    .line 192
    move-result-object v9

    .line 193
    invoke-static {v4, v9}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    iput-wide v6, v0, Lc8/p;->o:J
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 197
    .line 198
    goto :goto_1

    .line 199
    :catch_0
    iput-object v5, v0, Lc8/p;->n:Ljava/lang/reflect/Method;

    .line 200
    .line 201
    :cond_3
    :goto_1
    iput-wide v11, v0, Lc8/p;->q:J

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_4
    const-wide/32 v20, 0x4c4b40

    .line 205
    .line 206
    .line 207
    :cond_5
    :goto_2
    iget-object v5, v0, Lc8/p;->e:Lc8/o;

    .line 208
    .line 209
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 210
    .line 211
    .line 212
    iget v9, v5, Lc8/o;->b:I

    .line 213
    .line 214
    iget-object v10, v5, Lc8/o;->a:Lc8/n;

    .line 215
    .line 216
    iget v13, v0, Lc8/p;->h:F

    .line 217
    .line 218
    move-wide/from16 v22, v6

    .line 219
    .line 220
    invoke-virtual {v0, v11, v12}, Lc8/p;->c(J)J

    .line 221
    .line 222
    .line 223
    move-result-wide v6

    .line 224
    iget-wide v2, v5, Lc8/o;->g:J

    .line 225
    .line 226
    sub-long v2, v11, v2

    .line 227
    .line 228
    iget-wide v14, v5, Lc8/o;->f:J

    .line 229
    .line 230
    cmp-long v2, v2, v14

    .line 231
    .line 232
    if-gez v2, :cond_6

    .line 233
    .line 234
    move-object/from16 v26, v1

    .line 235
    .line 236
    goto/16 :goto_8

    .line 237
    .line 238
    :cond_6
    iput-wide v11, v5, Lc8/o;->g:J

    .line 239
    .line 240
    iget-object v2, v10, Lc8/n;->a:Landroid/media/AudioTrack;

    .line 241
    .line 242
    iget-object v3, v10, Lc8/n;->b:Landroid/media/AudioTimestamp;

    .line 243
    .line 244
    invoke-virtual {v2, v3}, Landroid/media/AudioTrack;->getTimestamp(Landroid/media/AudioTimestamp;)Z

    .line 245
    .line 246
    .line 247
    move-result v24

    .line 248
    if-eqz v24, :cond_9

    .line 249
    .line 250
    iget-wide v14, v3, Landroid/media/AudioTimestamp;->framePosition:J

    .line 251
    .line 252
    move/from16 v25, v9

    .line 253
    .line 254
    iget-wide v8, v10, Lc8/n;->d:J

    .line 255
    .line 256
    cmp-long v2, v8, v14

    .line 257
    .line 258
    if-lez v2, :cond_8

    .line 259
    .line 260
    iget-boolean v2, v10, Lc8/n;->f:Z

    .line 261
    .line 262
    if-eqz v2, :cond_7

    .line 263
    .line 264
    move-object/from16 v26, v1

    .line 265
    .line 266
    iget-wide v1, v10, Lc8/n;->g:J

    .line 267
    .line 268
    add-long/2addr v1, v8

    .line 269
    iput-wide v1, v10, Lc8/n;->g:J

    .line 270
    .line 271
    const/4 v1, 0x0

    .line 272
    iput-boolean v1, v10, Lc8/n;->f:Z

    .line 273
    .line 274
    goto :goto_3

    .line 275
    :cond_7
    move-object/from16 v26, v1

    .line 276
    .line 277
    iget-wide v1, v10, Lc8/n;->c:J

    .line 278
    .line 279
    const-wide/16 v8, 0x1

    .line 280
    .line 281
    add-long/2addr v1, v8

    .line 282
    iput-wide v1, v10, Lc8/n;->c:J

    .line 283
    .line 284
    goto :goto_3

    .line 285
    :cond_8
    move-object/from16 v26, v1

    .line 286
    .line 287
    :goto_3
    iput-wide v14, v10, Lc8/n;->d:J

    .line 288
    .line 289
    iget-wide v1, v10, Lc8/n;->g:J

    .line 290
    .line 291
    add-long/2addr v14, v1

    .line 292
    iget-wide v1, v10, Lc8/n;->c:J

    .line 293
    .line 294
    const/16 v8, 0x20

    .line 295
    .line 296
    shl-long/2addr v1, v8

    .line 297
    add-long/2addr v14, v1

    .line 298
    iput-wide v14, v10, Lc8/n;->e:J

    .line 299
    .line 300
    goto :goto_4

    .line 301
    :cond_9
    move-object/from16 v26, v1

    .line 302
    .line 303
    move/from16 v25, v9

    .line 304
    .line 305
    :goto_4
    if-eqz v24, :cond_c

    .line 306
    .line 307
    iget-object v2, v5, Lc8/o;->c:Lbu/c;

    .line 308
    .line 309
    iget-wide v8, v3, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 310
    .line 311
    div-long v8, v8, v16

    .line 312
    .line 313
    iget-wide v14, v10, Lc8/n;->e:J

    .line 314
    .line 315
    iget-object v1, v10, Lc8/n;->b:Landroid/media/AudioTimestamp;

    .line 316
    .line 317
    iget-wide v0, v1, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 318
    .line 319
    div-long v0, v0, v16

    .line 320
    .line 321
    move-wide/from16 v27, v0

    .line 322
    .line 323
    move/from16 v0, v25

    .line 324
    .line 325
    invoke-static {v0, v14, v15}, Lw7/w;->H(IJ)J

    .line 326
    .line 327
    .line 328
    move-result-wide v14

    .line 329
    move-wide/from16 v29, v14

    .line 330
    .line 331
    sub-long v14, v11, v27

    .line 332
    .line 333
    invoke-static {v14, v15, v13}, Lw7/w;->r(JF)J

    .line 334
    .line 335
    .line 336
    move-result-wide v14

    .line 337
    add-long v14, v14, v29

    .line 338
    .line 339
    sub-long v27, v8, v11

    .line 340
    .line 341
    invoke-static/range {v27 .. v28}, Ljava/lang/Math;->abs(J)J

    .line 342
    .line 343
    .line 344
    move-result-wide v27

    .line 345
    cmp-long v1, v27, v20

    .line 346
    .line 347
    move/from16 v25, v1

    .line 348
    .line 349
    const-string v1, ", "

    .line 350
    .line 351
    if-lez v25, :cond_a

    .line 352
    .line 353
    iget-wide v14, v10, Lc8/n;->e:J

    .line 354
    .line 355
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 356
    .line 357
    .line 358
    move-object/from16 v25, v3

    .line 359
    .line 360
    new-instance v3, Ljava/lang/StringBuilder;

    .line 361
    .line 362
    move/from16 v27, v13

    .line 363
    .line 364
    const-string v13, "Spurious audio timestamp (system clock mismatch): "

    .line 365
    .line 366
    invoke-direct {v3, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    invoke-virtual {v3, v14, v15}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 370
    .line 371
    .line 372
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 373
    .line 374
    .line 375
    invoke-virtual {v3, v8, v9}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 376
    .line 377
    .line 378
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 379
    .line 380
    .line 381
    invoke-virtual {v3, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 382
    .line 383
    .line 384
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {v3, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 388
    .line 389
    .line 390
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 391
    .line 392
    .line 393
    iget-object v2, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 394
    .line 395
    check-cast v2, Lc8/y;

    .line 396
    .line 397
    invoke-virtual {v2}, Lc8/y;->j()J

    .line 398
    .line 399
    .line 400
    move-result-wide v6

    .line 401
    invoke-virtual {v3, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 402
    .line 403
    .line 404
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 405
    .line 406
    .line 407
    invoke-virtual {v2}, Lc8/y;->k()J

    .line 408
    .line 409
    .line 410
    move-result-wide v1

    .line 411
    invoke-virtual {v3, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 412
    .line 413
    .line 414
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 415
    .line 416
    .line 417
    move-result-object v1

    .line 418
    invoke-static {v4, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    const/4 v1, 0x4

    .line 422
    invoke-virtual {v5, v1}, Lc8/o;->a(I)V

    .line 423
    .line 424
    .line 425
    goto :goto_5

    .line 426
    :cond_a
    move-object/from16 v25, v3

    .line 427
    .line 428
    move/from16 v27, v13

    .line 429
    .line 430
    sub-long/2addr v14, v6

    .line 431
    invoke-static {v14, v15}, Ljava/lang/Math;->abs(J)J

    .line 432
    .line 433
    .line 434
    move-result-wide v13

    .line 435
    cmp-long v3, v13, v20

    .line 436
    .line 437
    if-lez v3, :cond_b

    .line 438
    .line 439
    iget-wide v13, v10, Lc8/n;->e:J

    .line 440
    .line 441
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 442
    .line 443
    .line 444
    new-instance v3, Ljava/lang/StringBuilder;

    .line 445
    .line 446
    const-string v15, "Spurious audio timestamp (frame position mismatch): "

    .line 447
    .line 448
    invoke-direct {v3, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    invoke-virtual {v3, v13, v14}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 452
    .line 453
    .line 454
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 455
    .line 456
    .line 457
    invoke-virtual {v3, v8, v9}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 458
    .line 459
    .line 460
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 461
    .line 462
    .line 463
    invoke-virtual {v3, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 464
    .line 465
    .line 466
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 467
    .line 468
    .line 469
    invoke-virtual {v3, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 470
    .line 471
    .line 472
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 473
    .line 474
    .line 475
    iget-object v2, v2, Lbu/c;->e:Ljava/lang/Object;

    .line 476
    .line 477
    check-cast v2, Lc8/y;

    .line 478
    .line 479
    invoke-virtual {v2}, Lc8/y;->j()J

    .line 480
    .line 481
    .line 482
    move-result-wide v6

    .line 483
    invoke-virtual {v3, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 484
    .line 485
    .line 486
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 487
    .line 488
    .line 489
    invoke-virtual {v2}, Lc8/y;->k()J

    .line 490
    .line 491
    .line 492
    move-result-wide v1

    .line 493
    invoke-virtual {v3, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 494
    .line 495
    .line 496
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 497
    .line 498
    .line 499
    move-result-object v1

    .line 500
    invoke-static {v4, v1}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 501
    .line 502
    .line 503
    const/4 v1, 0x4

    .line 504
    invoke-virtual {v5, v1}, Lc8/o;->a(I)V

    .line 505
    .line 506
    .line 507
    goto :goto_5

    .line 508
    :cond_b
    const/4 v1, 0x4

    .line 509
    iget v2, v5, Lc8/o;->d:I

    .line 510
    .line 511
    if-ne v2, v1, :cond_d

    .line 512
    .line 513
    const/4 v2, 0x0

    .line 514
    invoke-virtual {v5, v2}, Lc8/o;->a(I)V

    .line 515
    .line 516
    .line 517
    goto :goto_5

    .line 518
    :cond_c
    move/from16 v27, v13

    .line 519
    .line 520
    move/from16 v0, v25

    .line 521
    .line 522
    const/4 v1, 0x4

    .line 523
    move-object/from16 v25, v3

    .line 524
    .line 525
    :cond_d
    :goto_5
    iget v3, v5, Lc8/o;->d:I

    .line 526
    .line 527
    if-eqz v3, :cond_16

    .line 528
    .line 529
    const/4 v2, 0x1

    .line 530
    if-eq v3, v2, :cond_11

    .line 531
    .line 532
    const/4 v14, 0x2

    .line 533
    if-eq v3, v14, :cond_10

    .line 534
    .line 535
    const/4 v15, 0x3

    .line 536
    if-eq v3, v15, :cond_f

    .line 537
    .line 538
    if-ne v3, v1, :cond_e

    .line 539
    .line 540
    goto/16 :goto_8

    .line 541
    .line 542
    :cond_e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 543
    .line 544
    invoke-direct {v0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 545
    .line 546
    .line 547
    throw v0

    .line 548
    :cond_f
    if-eqz v24, :cond_1a

    .line 549
    .line 550
    const/4 v1, 0x0

    .line 551
    invoke-virtual {v5, v1}, Lc8/o;->a(I)V

    .line 552
    .line 553
    .line 554
    goto/16 :goto_7

    .line 555
    .line 556
    :cond_10
    const/4 v1, 0x0

    .line 557
    if-nez v24, :cond_18

    .line 558
    .line 559
    invoke-virtual {v5, v1}, Lc8/o;->a(I)V

    .line 560
    .line 561
    .line 562
    goto/16 :goto_7

    .line 563
    .line 564
    :cond_11
    if-eqz v24, :cond_15

    .line 565
    .line 566
    iget-wide v3, v10, Lc8/n;->e:J

    .line 567
    .line 568
    iget-wide v6, v5, Lc8/o;->h:J

    .line 569
    .line 570
    cmp-long v1, v3, v6

    .line 571
    .line 572
    if-gtz v1, :cond_12

    .line 573
    .line 574
    goto :goto_6

    .line 575
    :cond_12
    iget-wide v3, v5, Lc8/o;->i:J

    .line 576
    .line 577
    invoke-static {v0, v6, v7}, Lw7/w;->H(IJ)J

    .line 578
    .line 579
    .line 580
    move-result-wide v6

    .line 581
    sub-long v3, v11, v3

    .line 582
    .line 583
    move/from16 v1, v27

    .line 584
    .line 585
    invoke-static {v3, v4, v1}, Lw7/w;->r(JF)J

    .line 586
    .line 587
    .line 588
    move-result-wide v3

    .line 589
    add-long/2addr v3, v6

    .line 590
    iget-wide v6, v10, Lc8/n;->e:J

    .line 591
    .line 592
    iget-object v8, v10, Lc8/n;->b:Landroid/media/AudioTimestamp;

    .line 593
    .line 594
    iget-wide v8, v8, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 595
    .line 596
    div-long v8, v8, v16

    .line 597
    .line 598
    invoke-static {v0, v6, v7}, Lw7/w;->H(IJ)J

    .line 599
    .line 600
    .line 601
    move-result-wide v6

    .line 602
    sub-long v8, v11, v8

    .line 603
    .line 604
    invoke-static {v8, v9, v1}, Lw7/w;->r(JF)J

    .line 605
    .line 606
    .line 607
    move-result-wide v0

    .line 608
    add-long/2addr v0, v6

    .line 609
    sub-long/2addr v0, v3

    .line 610
    invoke-static {v0, v1}, Ljava/lang/Math;->abs(J)J

    .line 611
    .line 612
    .line 613
    move-result-wide v0

    .line 614
    cmp-long v0, v0, v16

    .line 615
    .line 616
    if-gez v0, :cond_13

    .line 617
    .line 618
    const/4 v14, 0x2

    .line 619
    invoke-virtual {v5, v14}, Lc8/o;->a(I)V

    .line 620
    .line 621
    .line 622
    goto :goto_8

    .line 623
    :cond_13
    :goto_6
    iget-wide v0, v5, Lc8/o;->e:J

    .line 624
    .line 625
    sub-long/2addr v11, v0

    .line 626
    const-wide/32 v0, 0x1e8480

    .line 627
    .line 628
    .line 629
    cmp-long v0, v11, v0

    .line 630
    .line 631
    if-lez v0, :cond_14

    .line 632
    .line 633
    const/4 v15, 0x3

    .line 634
    invoke-virtual {v5, v15}, Lc8/o;->a(I)V

    .line 635
    .line 636
    .line 637
    goto :goto_8

    .line 638
    :cond_14
    iget-wide v0, v10, Lc8/n;->e:J

    .line 639
    .line 640
    iput-wide v0, v5, Lc8/o;->h:J

    .line 641
    .line 642
    move-object/from16 v0, v25

    .line 643
    .line 644
    iget-wide v0, v0, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 645
    .line 646
    div-long v0, v0, v16

    .line 647
    .line 648
    iput-wide v0, v5, Lc8/o;->i:J

    .line 649
    .line 650
    goto :goto_8

    .line 651
    :cond_15
    const/4 v1, 0x0

    .line 652
    invoke-virtual {v5, v1}, Lc8/o;->a(I)V

    .line 653
    .line 654
    .line 655
    goto :goto_7

    .line 656
    :cond_16
    move-object/from16 v0, v25

    .line 657
    .line 658
    const/4 v1, 0x0

    .line 659
    if-eqz v24, :cond_17

    .line 660
    .line 661
    iget-wide v3, v0, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 662
    .line 663
    div-long v6, v3, v16

    .line 664
    .line 665
    iget-wide v8, v5, Lc8/o;->e:J

    .line 666
    .line 667
    cmp-long v0, v6, v8

    .line 668
    .line 669
    if-ltz v0, :cond_18

    .line 670
    .line 671
    iget-wide v6, v10, Lc8/n;->e:J

    .line 672
    .line 673
    iput-wide v6, v5, Lc8/o;->h:J

    .line 674
    .line 675
    div-long v3, v3, v16

    .line 676
    .line 677
    iput-wide v3, v5, Lc8/o;->i:J

    .line 678
    .line 679
    const/4 v2, 0x1

    .line 680
    invoke-virtual {v5, v2}, Lc8/o;->a(I)V

    .line 681
    .line 682
    .line 683
    goto :goto_7

    .line 684
    :cond_17
    iget-wide v3, v5, Lc8/o;->e:J

    .line 685
    .line 686
    sub-long/2addr v11, v3

    .line 687
    cmp-long v0, v11, v18

    .line 688
    .line 689
    if-lez v0, :cond_18

    .line 690
    .line 691
    const/4 v15, 0x3

    .line 692
    invoke-virtual {v5, v15}, Lc8/o;->a(I)V

    .line 693
    .line 694
    .line 695
    :cond_18
    :goto_7
    move-object/from16 v0, p0

    .line 696
    .line 697
    goto :goto_9

    .line 698
    :cond_19
    move-object/from16 v26, v1

    .line 699
    .line 700
    move-wide/from16 v16, v4

    .line 701
    .line 702
    move-wide/from16 v22, v6

    .line 703
    .line 704
    :cond_1a
    :goto_8
    const/4 v1, 0x0

    .line 705
    goto :goto_7

    .line 706
    :goto_9
    iget-object v3, v0, Lc8/p;->F:Lw7/r;

    .line 707
    .line 708
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 709
    .line 710
    .line 711
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 712
    .line 713
    .line 714
    move-result-wide v3

    .line 715
    div-long v3, v3, v16

    .line 716
    .line 717
    iget-object v5, v0, Lc8/p;->e:Lc8/o;

    .line 718
    .line 719
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 720
    .line 721
    .line 722
    iget v6, v5, Lc8/o;->d:I

    .line 723
    .line 724
    const/4 v14, 0x2

    .line 725
    if-ne v6, v14, :cond_1b

    .line 726
    .line 727
    const/4 v8, 0x1

    .line 728
    goto :goto_a

    .line 729
    :cond_1b
    move v8, v1

    .line 730
    :goto_a
    if-eqz v8, :cond_1c

    .line 731
    .line 732
    iget v1, v0, Lc8/p;->h:F

    .line 733
    .line 734
    iget-object v6, v5, Lc8/o;->a:Lc8/n;

    .line 735
    .line 736
    iget-wide v9, v6, Lc8/n;->e:J

    .line 737
    .line 738
    iget-object v6, v6, Lc8/n;->b:Landroid/media/AudioTimestamp;

    .line 739
    .line 740
    iget-wide v6, v6, Landroid/media/AudioTimestamp;->nanoTime:J

    .line 741
    .line 742
    div-long v6, v6, v16

    .line 743
    .line 744
    iget v11, v5, Lc8/o;->b:I

    .line 745
    .line 746
    invoke-static {v11, v9, v10}, Lw7/w;->H(IJ)J

    .line 747
    .line 748
    .line 749
    move-result-wide v9

    .line 750
    sub-long v6, v3, v6

    .line 751
    .line 752
    invoke-static {v6, v7, v1}, Lw7/w;->r(JF)J

    .line 753
    .line 754
    .line 755
    move-result-wide v6

    .line 756
    add-long/2addr v6, v9

    .line 757
    :goto_b
    move-wide v9, v6

    .line 758
    goto :goto_c

    .line 759
    :cond_1c
    invoke-virtual {v0, v3, v4}, Lc8/p;->c(J)J

    .line 760
    .line 761
    .line 762
    move-result-wide v6

    .line 763
    goto :goto_b

    .line 764
    :goto_c
    invoke-virtual/range {v26 .. v26}, Landroid/media/AudioTrack;->getPlayState()I

    .line 765
    .line 766
    .line 767
    move-result v1

    .line 768
    const/4 v15, 0x3

    .line 769
    if-ne v1, v15, :cond_21

    .line 770
    .line 771
    if-nez v8, :cond_1d

    .line 772
    .line 773
    iget v1, v5, Lc8/o;->d:I

    .line 774
    .line 775
    if-eqz v1, :cond_1e

    .line 776
    .line 777
    const/4 v2, 0x1

    .line 778
    if-ne v1, v2, :cond_1d

    .line 779
    .line 780
    goto :goto_d

    .line 781
    :cond_1d
    invoke-virtual {v0, v9, v10}, Lc8/p;->e(J)V

    .line 782
    .line 783
    .line 784
    :cond_1e
    :goto_d
    iget-wide v5, v0, Lc8/p;->C:J

    .line 785
    .line 786
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 787
    .line 788
    .line 789
    .line 790
    .line 791
    cmp-long v1, v5, v7

    .line 792
    .line 793
    if-eqz v1, :cond_1f

    .line 794
    .line 795
    sub-long v5, v3, v5

    .line 796
    .line 797
    iget-wide v11, v0, Lc8/p;->B:J

    .line 798
    .line 799
    sub-long v11, v9, v11

    .line 800
    .line 801
    iget v1, v0, Lc8/p;->h:F

    .line 802
    .line 803
    invoke-static {v5, v6, v1}, Lw7/w;->r(JF)J

    .line 804
    .line 805
    .line 806
    move-result-wide v5

    .line 807
    iget-wide v13, v0, Lc8/p;->B:J

    .line 808
    .line 809
    add-long/2addr v13, v5

    .line 810
    sub-long v15, v13, v9

    .line 811
    .line 812
    invoke-static/range {v15 .. v16}, Ljava/lang/Math;->abs(J)J

    .line 813
    .line 814
    .line 815
    move-result-wide v15

    .line 816
    cmp-long v1, v11, v22

    .line 817
    .line 818
    if-eqz v1, :cond_1f

    .line 819
    .line 820
    const-wide/32 v11, 0xf4240

    .line 821
    .line 822
    .line 823
    cmp-long v1, v15, v11

    .line 824
    .line 825
    if-gez v1, :cond_1f

    .line 826
    .line 827
    const-wide/16 v11, 0xa

    .line 828
    .line 829
    mul-long/2addr v5, v11

    .line 830
    const-wide/16 v11, 0x64

    .line 831
    .line 832
    div-long/2addr v5, v11

    .line 833
    sub-long v11, v13, v5

    .line 834
    .line 835
    add-long/2addr v13, v5

    .line 836
    invoke-static/range {v9 .. v14}, Lw7/w;->h(JJJ)J

    .line 837
    .line 838
    .line 839
    move-result-wide v9

    .line 840
    :cond_1f
    iget-boolean v1, v0, Lc8/p;->A:Z

    .line 841
    .line 842
    if-nez v1, :cond_20

    .line 843
    .line 844
    iget-boolean v1, v0, Lc8/p;->i:Z

    .line 845
    .line 846
    if-nez v1, :cond_20

    .line 847
    .line 848
    iget-wide v5, v0, Lc8/p;->B:J

    .line 849
    .line 850
    cmp-long v1, v5, v7

    .line 851
    .line 852
    if-eqz v1, :cond_20

    .line 853
    .line 854
    cmp-long v1, v9, v5

    .line 855
    .line 856
    if-lez v1, :cond_20

    .line 857
    .line 858
    const/4 v2, 0x1

    .line 859
    iput-boolean v2, v0, Lc8/p;->i:Z

    .line 860
    .line 861
    sub-long v1, v9, v5

    .line 862
    .line 863
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 864
    .line 865
    .line 866
    move-result-wide v1

    .line 867
    iget v5, v0, Lc8/p;->h:F

    .line 868
    .line 869
    invoke-static {v1, v2, v5}, Lw7/w;->t(JF)J

    .line 870
    .line 871
    .line 872
    move-result-wide v1

    .line 873
    iget-object v5, v0, Lc8/p;->F:Lw7/r;

    .line 874
    .line 875
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 876
    .line 877
    .line 878
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 879
    .line 880
    .line 881
    move-result-wide v5

    .line 882
    invoke-static {v1, v2}, Lw7/w;->N(J)J

    .line 883
    .line 884
    .line 885
    move-result-wide v1

    .line 886
    sub-long/2addr v5, v1

    .line 887
    iget-object v1, v0, Lc8/p;->a:Lbu/c;

    .line 888
    .line 889
    iget-object v1, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 890
    .line 891
    check-cast v1, Lc8/y;

    .line 892
    .line 893
    iget-object v1, v1, Lc8/y;->s:Laq/a;

    .line 894
    .line 895
    if-eqz v1, :cond_20

    .line 896
    .line 897
    iget-object v1, v1, Laq/a;->e:Ljava/lang/Object;

    .line 898
    .line 899
    check-cast v1, Lc8/a0;

    .line 900
    .line 901
    iget-object v1, v1, Lc8/a0;->Q1:Lb81/d;

    .line 902
    .line 903
    iget-object v2, v1, Lb81/d;->e:Ljava/lang/Object;

    .line 904
    .line 905
    check-cast v2, Landroid/os/Handler;

    .line 906
    .line 907
    if-eqz v2, :cond_20

    .line 908
    .line 909
    new-instance v7, Lc8/i;

    .line 910
    .line 911
    invoke-direct {v7, v1, v5, v6}, Lc8/i;-><init>(Lb81/d;J)V

    .line 912
    .line 913
    .line 914
    invoke-virtual {v2, v7}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 915
    .line 916
    .line 917
    :cond_20
    iput-wide v3, v0, Lc8/p;->C:J

    .line 918
    .line 919
    iput-wide v9, v0, Lc8/p;->B:J

    .line 920
    .line 921
    goto :goto_e

    .line 922
    :cond_21
    const/4 v2, 0x1

    .line 923
    if-ne v1, v2, :cond_22

    .line 924
    .line 925
    invoke-virtual {v0, v9, v10}, Lc8/p;->e(J)V

    .line 926
    .line 927
    .line 928
    :cond_22
    :goto_e
    return-wide v9
.end method

.method public final b()J
    .locals 12

    .line 1
    iget-wide v0, p0, Lc8/p;->w:J

    .line 2
    .line 3
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    cmp-long v0, v0, v2

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lc8/p;->d()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iget-wide v2, p0, Lc8/p;->z:J

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    return-wide v0

    .line 23
    :cond_0
    iget-object v0, p0, Lc8/p;->F:Lw7/r;

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 29
    .line 30
    .line 31
    move-result-wide v0

    .line 32
    iget-wide v4, p0, Lc8/p;->r:J

    .line 33
    .line 34
    sub-long v4, v0, v4

    .line 35
    .line 36
    const-wide/16 v6, 0x5

    .line 37
    .line 38
    cmp-long v4, v4, v6

    .line 39
    .line 40
    if-ltz v4, :cond_7

    .line 41
    .line 42
    iget-object v4, p0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 43
    .line 44
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v4}, Landroid/media/AudioTrack;->getPlayState()I

    .line 48
    .line 49
    .line 50
    move-result v5

    .line 51
    const/4 v6, 0x1

    .line 52
    if-ne v5, v6, :cond_1

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_1
    invoke-virtual {v4}, Landroid/media/AudioTrack;->getPlaybackHeadPosition()I

    .line 56
    .line 57
    .line 58
    move-result v4

    .line 59
    int-to-long v6, v4

    .line 60
    const-wide v8, 0xffffffffL

    .line 61
    .line 62
    .line 63
    .line 64
    .line 65
    and-long/2addr v6, v8

    .line 66
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 67
    .line 68
    const/16 v8, 0x1d

    .line 69
    .line 70
    if-gt v4, v8, :cond_3

    .line 71
    .line 72
    const-wide/16 v8, 0x0

    .line 73
    .line 74
    cmp-long v4, v6, v8

    .line 75
    .line 76
    if-nez v4, :cond_2

    .line 77
    .line 78
    iget-wide v10, p0, Lc8/p;->s:J

    .line 79
    .line 80
    cmp-long v4, v10, v8

    .line 81
    .line 82
    if-lez v4, :cond_2

    .line 83
    .line 84
    const/4 v4, 0x3

    .line 85
    if-ne v5, v4, :cond_2

    .line 86
    .line 87
    iget-wide v4, p0, Lc8/p;->x:J

    .line 88
    .line 89
    cmp-long v2, v4, v2

    .line 90
    .line 91
    if-nez v2, :cond_6

    .line 92
    .line 93
    iput-wide v0, p0, Lc8/p;->x:J

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    iput-wide v2, p0, Lc8/p;->x:J

    .line 97
    .line 98
    :cond_3
    iget-wide v2, p0, Lc8/p;->s:J

    .line 99
    .line 100
    cmp-long v4, v2, v6

    .line 101
    .line 102
    if-lez v4, :cond_5

    .line 103
    .line 104
    iget-boolean v4, p0, Lc8/p;->D:Z

    .line 105
    .line 106
    if-eqz v4, :cond_4

    .line 107
    .line 108
    iget-wide v4, p0, Lc8/p;->E:J

    .line 109
    .line 110
    add-long/2addr v4, v2

    .line 111
    iput-wide v4, p0, Lc8/p;->E:J

    .line 112
    .line 113
    const/4 v2, 0x0

    .line 114
    iput-boolean v2, p0, Lc8/p;->D:Z

    .line 115
    .line 116
    goto :goto_0

    .line 117
    :cond_4
    iget-wide v2, p0, Lc8/p;->t:J

    .line 118
    .line 119
    const-wide/16 v4, 0x1

    .line 120
    .line 121
    add-long/2addr v2, v4

    .line 122
    iput-wide v2, p0, Lc8/p;->t:J

    .line 123
    .line 124
    :cond_5
    :goto_0
    iput-wide v6, p0, Lc8/p;->s:J

    .line 125
    .line 126
    :cond_6
    :goto_1
    iput-wide v0, p0, Lc8/p;->r:J

    .line 127
    .line 128
    :cond_7
    iget-wide v0, p0, Lc8/p;->s:J

    .line 129
    .line 130
    iget-wide v2, p0, Lc8/p;->E:J

    .line 131
    .line 132
    add-long/2addr v0, v2

    .line 133
    iget-wide v2, p0, Lc8/p;->t:J

    .line 134
    .line 135
    const/16 p0, 0x20

    .line 136
    .line 137
    shl-long/2addr v2, p0

    .line 138
    add-long/2addr v0, v2

    .line 139
    return-wide v0
.end method

.method public final c(J)J
    .locals 5

    .line 1
    iget v0, p0, Lc8/p;->v:I

    .line 2
    .line 3
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    iget-wide p1, p0, Lc8/p;->w:J

    .line 11
    .line 12
    cmp-long p1, p1, v1

    .line 13
    .line 14
    if-eqz p1, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Lc8/p;->d()J

    .line 17
    .line 18
    .line 19
    move-result-wide p1

    .line 20
    iget v0, p0, Lc8/p;->f:I

    .line 21
    .line 22
    invoke-static {v0, p1, p2}, Lw7/w;->H(IJ)J

    .line 23
    .line 24
    .line 25
    move-result-wide p1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p0}, Lc8/p;->b()J

    .line 28
    .line 29
    .line 30
    move-result-wide p1

    .line 31
    iget v0, p0, Lc8/p;->f:I

    .line 32
    .line 33
    invoke-static {v0, p1, p2}, Lw7/w;->H(IJ)J

    .line 34
    .line 35
    .line 36
    move-result-wide p1

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    iget-wide v3, p0, Lc8/p;->l:J

    .line 39
    .line 40
    add-long/2addr p1, v3

    .line 41
    iget v0, p0, Lc8/p;->h:F

    .line 42
    .line 43
    invoke-static {p1, p2, v0}, Lw7/w;->r(JF)J

    .line 44
    .line 45
    .line 46
    move-result-wide p1

    .line 47
    :goto_0
    iget-wide v3, p0, Lc8/p;->o:J

    .line 48
    .line 49
    sub-long/2addr p1, v3

    .line 50
    const-wide/16 v3, 0x0

    .line 51
    .line 52
    invoke-static {v3, v4, p1, p2}, Ljava/lang/Math;->max(JJ)J

    .line 53
    .line 54
    .line 55
    move-result-wide p1

    .line 56
    iget-wide v3, p0, Lc8/p;->w:J

    .line 57
    .line 58
    cmp-long v0, v3, v1

    .line 59
    .line 60
    if-eqz v0, :cond_2

    .line 61
    .line 62
    iget-wide v0, p0, Lc8/p;->z:J

    .line 63
    .line 64
    iget p0, p0, Lc8/p;->f:I

    .line 65
    .line 66
    invoke-static {p0, v0, v1}, Lw7/w;->H(IJ)J

    .line 67
    .line 68
    .line 69
    move-result-wide v0

    .line 70
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->min(JJ)J

    .line 71
    .line 72
    .line 73
    move-result-wide p0

    .line 74
    return-wide p0

    .line 75
    :cond_2
    return-wide p1
.end method

.method public final d()J
    .locals 10

    .line 1
    iget-object v0, p0, Lc8/p;->c:Landroid/media/AudioTrack;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Landroid/media/AudioTrack;->getPlayState()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x2

    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    iget-wide v0, p0, Lc8/p;->y:J

    .line 14
    .line 15
    return-wide v0

    .line 16
    :cond_0
    iget-object v0, p0, Lc8/p;->F:Lw7/r;

    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    invoke-static {v0, v1}, Lw7/w;->D(J)J

    .line 26
    .line 27
    .line 28
    move-result-wide v0

    .line 29
    iget-wide v2, p0, Lc8/p;->w:J

    .line 30
    .line 31
    sub-long/2addr v0, v2

    .line 32
    iget v2, p0, Lc8/p;->h:F

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Lw7/w;->r(JF)J

    .line 35
    .line 36
    .line 37
    move-result-wide v3

    .line 38
    iget v0, p0, Lc8/p;->f:I

    .line 39
    .line 40
    int-to-long v5, v0

    .line 41
    const-wide/32 v7, 0xf4240

    .line 42
    .line 43
    .line 44
    sget-object v9, Ljava/math/RoundingMode;->UP:Ljava/math/RoundingMode;

    .line 45
    .line 46
    invoke-static/range {v3 .. v9}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 47
    .line 48
    .line 49
    move-result-wide v0

    .line 50
    iget-wide v2, p0, Lc8/p;->y:J

    .line 51
    .line 52
    add-long/2addr v2, v0

    .line 53
    return-wide v2
.end method

.method public final e(J)V
    .locals 5

    .line 1
    iget-boolean v0, p0, Lc8/p;->A:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    iget-wide v0, p0, Lc8/p;->j:J

    .line 6
    .line 7
    const-wide v2, -0x7fffffffffffffffL    # -4.9E-324

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    cmp-long v4, v0, v2

    .line 13
    .line 14
    if-eqz v4, :cond_1

    .line 15
    .line 16
    cmp-long v4, p1, v0

    .line 17
    .line 18
    if-gez v4, :cond_0

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    sub-long/2addr p1, v0

    .line 22
    iget v0, p0, Lc8/p;->h:F

    .line 23
    .line 24
    invoke-static {p1, p2, v0}, Lw7/w;->t(JF)J

    .line 25
    .line 26
    .line 27
    move-result-wide p1

    .line 28
    iget-object v0, p0, Lc8/p;->F:Lw7/r;

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    invoke-static {p1, p2}, Lw7/w;->N(J)J

    .line 38
    .line 39
    .line 40
    move-result-wide p1

    .line 41
    sub-long/2addr v0, p1

    .line 42
    iput-wide v2, p0, Lc8/p;->j:J

    .line 43
    .line 44
    iget-object p0, p0, Lc8/p;->a:Lbu/c;

    .line 45
    .line 46
    iget-object p0, p0, Lbu/c;->e:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lc8/y;

    .line 49
    .line 50
    iget-object p0, p0, Lc8/y;->s:Laq/a;

    .line 51
    .line 52
    if-eqz p0, :cond_1

    .line 53
    .line 54
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Lc8/a0;

    .line 57
    .line 58
    iget-object p0, p0, Lc8/a0;->Q1:Lb81/d;

    .line 59
    .line 60
    iget-object p1, p0, Lb81/d;->e:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p1, Landroid/os/Handler;

    .line 63
    .line 64
    if-eqz p1, :cond_1

    .line 65
    .line 66
    new-instance p2, Lc8/i;

    .line 67
    .line 68
    invoke-direct {p2, p0, v0, v1}, Lc8/i;-><init>(Lb81/d;J)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {p1, p2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 72
    .line 73
    .line 74
    :cond_1
    :goto_0
    return-void
.end method

.method public final f()V
    .locals 3

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lc8/p;->l:J

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iput v2, p0, Lc8/p;->v:I

    .line 7
    .line 8
    iput v2, p0, Lc8/p;->u:I

    .line 9
    .line 10
    iput-wide v0, p0, Lc8/p;->m:J

    .line 11
    .line 12
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    iput-wide v0, p0, Lc8/p;->B:J

    .line 18
    .line 19
    iput-wide v0, p0, Lc8/p;->C:J

    .line 20
    .line 21
    iput-boolean v2, p0, Lc8/p;->i:Z

    .line 22
    .line 23
    return-void
.end method
