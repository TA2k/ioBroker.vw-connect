.class public final Lt01/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# instance fields
.field public final a:Lt01/b;

.field public volatile b:Lt01/a;


# direct methods
.method public constructor <init>(Lt01/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt01/c;->a:Lt01/b;

    .line 5
    .line 6
    sget-object p1, Lt01/a;->d:Lt01/a;

    .line 7
    .line 8
    iput-object p1, p0, Lt01/c;->b:Lt01/a;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ld01/y;I)V
    .locals 2

    .line 1
    invoke-virtual {p1, p2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1, p2}, Ld01/y;->k(I)Ljava/lang/String;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1, p2}, Ld01/y;->e(I)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string p1, ": "

    .line 21
    .line 22
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-object p0, p0, Lt01/c;->a:Lt01/b;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Lt01/b;->f(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lt01/c;->b:Lt01/a;

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    check-cast v2, Li01/f;

    .line 8
    .line 9
    iget-object v3, v2, Li01/f;->e:Ld01/k0;

    .line 10
    .line 11
    sget-object v4, Lt01/a;->d:Lt01/a;

    .line 12
    .line 13
    if-ne v0, v4, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2, v3}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    return-object v0

    .line 20
    :cond_0
    sget-object v4, Lt01/a;->f:Lt01/a;

    .line 21
    .line 22
    const/4 v6, 0x1

    .line 23
    if-ne v0, v4, :cond_1

    .line 24
    .line 25
    move v4, v6

    .line 26
    goto :goto_0

    .line 27
    :cond_1
    const/4 v4, 0x0

    .line 28
    :goto_0
    if-nez v4, :cond_3

    .line 29
    .line 30
    sget-object v7, Lt01/a;->e:Lt01/a;

    .line 31
    .line 32
    if-ne v0, v7, :cond_2

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_2
    const/4 v6, 0x0

    .line 36
    :cond_3
    :goto_1
    iget-object v0, v3, Ld01/k0;->d:Ld01/r0;

    .line 37
    .line 38
    iget-object v7, v2, Li01/f;->d:Lh01/g;

    .line 39
    .line 40
    if-eqz v7, :cond_4

    .line 41
    .line 42
    invoke-virtual {v7}, Lh01/g;->c()Lh01/p;

    .line 43
    .line 44
    .line 45
    move-result-object v7

    .line 46
    goto :goto_2

    .line 47
    :cond_4
    const/4 v7, 0x0

    .line 48
    :goto_2
    new-instance v9, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v10, "--> "

    .line 51
    .line 52
    invoke-direct {v9, v10}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object v10, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const/16 v10, 0x20

    .line 61
    .line 62
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v10, v3, Ld01/k0;->a:Ld01/a0;

    .line 66
    .line 67
    const-string v11, "url"

    .line 68
    .line 69
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    iget-object v10, v10, Ld01/a0;->i:Ljava/lang/String;

    .line 73
    .line 74
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    const-string v10, ""

    .line 78
    .line 79
    const-string v12, " "

    .line 80
    .line 81
    if-eqz v7, :cond_5

    .line 82
    .line 83
    new-instance v13, Ljava/lang/StringBuilder;

    .line 84
    .line 85
    invoke-direct {v13, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v7, v7, Lh01/p;->g:Ld01/i0;

    .line 89
    .line 90
    invoke-virtual {v13, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object v7

    .line 97
    goto :goto_3

    .line 98
    :cond_5
    move-object v7, v10

    .line 99
    :goto_3
    invoke-virtual {v9, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object v7

    .line 106
    const-string v9, "-byte body)"

    .line 107
    .line 108
    const-string v13, " ("

    .line 109
    .line 110
    if-nez v6, :cond_6

    .line 111
    .line 112
    if-eqz v0, :cond_6

    .line 113
    .line 114
    invoke-static {v7, v13}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 119
    .line 120
    .line 121
    move-result-wide v14

    .line 122
    invoke-virtual {v7, v14, v15}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    :cond_6
    iget-object v14, v1, Lt01/c;->a:Lt01/b;

    .line 133
    .line 134
    invoke-interface {v14, v7}, Lt01/b;->f(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    const-string v7, "identity"

    .line 138
    .line 139
    const-string v14, "-byte body omitted)"

    .line 140
    .line 141
    const-string v15, "Content-Encoding"

    .line 142
    .line 143
    const-string v5, "gzip"

    .line 144
    .line 145
    const-wide/16 v16, -0x1

    .line 146
    .line 147
    if-eqz v6, :cond_16

    .line 148
    .line 149
    iget-object v8, v3, Ld01/k0;->c:Ld01/y;

    .line 150
    .line 151
    move/from16 v18, v4

    .line 152
    .line 153
    if-eqz v0, :cond_8

    .line 154
    .line 155
    invoke-virtual {v0}, Ld01/r0;->contentType()Ld01/d0;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    move/from16 v19, v6

    .line 160
    .line 161
    if-eqz v4, :cond_7

    .line 162
    .line 163
    const-string v6, "Content-Type"

    .line 164
    .line 165
    invoke-virtual {v8, v6}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v6

    .line 169
    if-nez v6, :cond_7

    .line 170
    .line 171
    iget-object v6, v1, Lt01/c;->a:Lt01/b;

    .line 172
    .line 173
    move-object/from16 v20, v11

    .line 174
    .line 175
    new-instance v11, Ljava/lang/StringBuilder;

    .line 176
    .line 177
    move-object/from16 v21, v12

    .line 178
    .line 179
    const-string v12, "Content-Type: "

    .line 180
    .line 181
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v11, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v4

    .line 191
    invoke-interface {v6, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    goto :goto_4

    .line 195
    :cond_7
    move-object/from16 v20, v11

    .line 196
    .line 197
    move-object/from16 v21, v12

    .line 198
    .line 199
    :goto_4
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 200
    .line 201
    .line 202
    move-result-wide v11

    .line 203
    cmp-long v4, v11, v16

    .line 204
    .line 205
    if-eqz v4, :cond_9

    .line 206
    .line 207
    const-string v4, "Content-Length"

    .line 208
    .line 209
    invoke-virtual {v8, v4}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v4

    .line 213
    if-nez v4, :cond_9

    .line 214
    .line 215
    iget-object v4, v1, Lt01/c;->a:Lt01/b;

    .line 216
    .line 217
    new-instance v6, Ljava/lang/StringBuilder;

    .line 218
    .line 219
    const-string v11, "Content-Length: "

    .line 220
    .line 221
    invoke-direct {v6, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 225
    .line 226
    .line 227
    move-result-wide v11

    .line 228
    invoke-virtual {v6, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v6

    .line 235
    invoke-interface {v4, v6}, Lt01/b;->f(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    goto :goto_5

    .line 239
    :cond_8
    move/from16 v19, v6

    .line 240
    .line 241
    move-object/from16 v20, v11

    .line 242
    .line 243
    move-object/from16 v21, v12

    .line 244
    .line 245
    :cond_9
    :goto_5
    invoke-virtual {v8}, Ld01/y;->size()I

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    const/4 v6, 0x0

    .line 250
    :goto_6
    if-ge v6, v4, :cond_a

    .line 251
    .line 252
    invoke-virtual {v1, v8, v6}, Lt01/c;->a(Ld01/y;I)V

    .line 253
    .line 254
    .line 255
    add-int/lit8 v6, v6, 0x1

    .line 256
    .line 257
    goto :goto_6

    .line 258
    :cond_a
    const-string v4, "--> END "

    .line 259
    .line 260
    if-eqz v18, :cond_15

    .line 261
    .line 262
    if-nez v0, :cond_b

    .line 263
    .line 264
    goto/16 :goto_9

    .line 265
    .line 266
    :cond_b
    iget-object v6, v3, Ld01/k0;->c:Ld01/y;

    .line 267
    .line 268
    invoke-virtual {v6, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object v6

    .line 272
    if-nez v6, :cond_c

    .line 273
    .line 274
    goto :goto_7

    .line 275
    :cond_c
    invoke-virtual {v6, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 276
    .line 277
    .line 278
    move-result v11

    .line 279
    if-nez v11, :cond_d

    .line 280
    .line 281
    invoke-virtual {v6, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 282
    .line 283
    .line 284
    move-result v6

    .line 285
    if-nez v6, :cond_d

    .line 286
    .line 287
    iget-object v0, v1, Lt01/c;->a:Lt01/b;

    .line 288
    .line 289
    new-instance v6, Ljava/lang/StringBuilder;

    .line 290
    .line 291
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 295
    .line 296
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 297
    .line 298
    .line 299
    const-string v4, " (encoded body omitted)"

    .line 300
    .line 301
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 302
    .line 303
    .line 304
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 305
    .line 306
    .line 307
    move-result-object v4

    .line 308
    invoke-interface {v0, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 309
    .line 310
    .line 311
    goto/16 :goto_a

    .line 312
    .line 313
    :cond_d
    :goto_7
    invoke-virtual {v0}, Ld01/r0;->isDuplex()Z

    .line 314
    .line 315
    .line 316
    move-result v6

    .line 317
    if-eqz v6, :cond_e

    .line 318
    .line 319
    iget-object v0, v1, Lt01/c;->a:Lt01/b;

    .line 320
    .line 321
    new-instance v6, Ljava/lang/StringBuilder;

    .line 322
    .line 323
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 327
    .line 328
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    const-string v4, " (duplex request body omitted)"

    .line 332
    .line 333
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 337
    .line 338
    .line 339
    move-result-object v4

    .line 340
    invoke-interface {v0, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    goto/16 :goto_a

    .line 344
    .line 345
    :cond_e
    invoke-virtual {v0}, Ld01/r0;->isOneShot()Z

    .line 346
    .line 347
    .line 348
    move-result v6

    .line 349
    if-eqz v6, :cond_f

    .line 350
    .line 351
    iget-object v0, v1, Lt01/c;->a:Lt01/b;

    .line 352
    .line 353
    new-instance v6, Ljava/lang/StringBuilder;

    .line 354
    .line 355
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 356
    .line 357
    .line 358
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 359
    .line 360
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 361
    .line 362
    .line 363
    const-string v4, " (one-shot body omitted)"

    .line 364
    .line 365
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 366
    .line 367
    .line 368
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v4

    .line 372
    invoke-interface {v0, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    goto/16 :goto_a

    .line 376
    .line 377
    :cond_f
    new-instance v6, Lu01/f;

    .line 378
    .line 379
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v0, v6}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v8, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 386
    .line 387
    .line 388
    move-result-object v8

    .line 389
    invoke-virtual {v5, v8}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 390
    .line 391
    .line 392
    move-result v8

    .line 393
    if-eqz v8, :cond_10

    .line 394
    .line 395
    iget-wide v11, v6, Lu01/f;->e:J

    .line 396
    .line 397
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 398
    .line 399
    .line 400
    move-result-object v8

    .line 401
    new-instance v11, Lu01/p;

    .line 402
    .line 403
    invoke-direct {v11, v6}, Lu01/p;-><init>(Lu01/h;)V

    .line 404
    .line 405
    .line 406
    :try_start_0
    new-instance v6, Lu01/f;

    .line 407
    .line 408
    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    .line 409
    .line 410
    .line 411
    invoke-virtual {v6, v11}, Lu01/f;->P(Lu01/h0;)J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 412
    .line 413
    .line 414
    invoke-virtual {v11}, Lu01/p;->close()V

    .line 415
    .line 416
    .line 417
    goto :goto_8

    .line 418
    :catchall_0
    move-exception v0

    .line 419
    move-object v1, v0

    .line 420
    :try_start_1
    throw v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 421
    :catchall_1
    move-exception v0

    .line 422
    invoke-static {v11, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 423
    .line 424
    .line 425
    throw v0

    .line 426
    :cond_10
    const/4 v8, 0x0

    .line 427
    :goto_8
    invoke-virtual {v0}, Ld01/r0;->contentType()Ld01/d0;

    .line 428
    .line 429
    .line 430
    move-result-object v11

    .line 431
    if-eqz v11, :cond_11

    .line 432
    .line 433
    sget-object v12, Ld01/d0;->e:Lly0/n;

    .line 434
    .line 435
    const/4 v12, 0x0

    .line 436
    invoke-virtual {v11, v12}, Ld01/d0;->a(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 437
    .line 438
    .line 439
    move-result-object v11

    .line 440
    if-nez v11, :cond_12

    .line 441
    .line 442
    :cond_11
    sget-object v11, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 443
    .line 444
    :cond_12
    iget-object v12, v1, Lt01/c;->a:Lt01/b;

    .line 445
    .line 446
    invoke-interface {v12, v10}, Lt01/b;->f(Ljava/lang/String;)V

    .line 447
    .line 448
    .line 449
    invoke-static {v6}, Ljp/mg;->a(Lu01/f;)Z

    .line 450
    .line 451
    .line 452
    move-result v12

    .line 453
    if-nez v12, :cond_13

    .line 454
    .line 455
    iget-object v6, v1, Lt01/c;->a:Lt01/b;

    .line 456
    .line 457
    new-instance v8, Ljava/lang/StringBuilder;

    .line 458
    .line 459
    invoke-direct {v8, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 460
    .line 461
    .line 462
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 463
    .line 464
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 465
    .line 466
    .line 467
    const-string v4, " (binary "

    .line 468
    .line 469
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 470
    .line 471
    .line 472
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 473
    .line 474
    .line 475
    move-result-wide v11

    .line 476
    invoke-virtual {v8, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 477
    .line 478
    .line 479
    invoke-virtual {v8, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 480
    .line 481
    .line 482
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 483
    .line 484
    .line 485
    move-result-object v0

    .line 486
    invoke-interface {v6, v0}, Lt01/b;->f(Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    goto/16 :goto_a

    .line 490
    .line 491
    :cond_13
    if-eqz v8, :cond_14

    .line 492
    .line 493
    iget-object v0, v1, Lt01/c;->a:Lt01/b;

    .line 494
    .line 495
    new-instance v9, Ljava/lang/StringBuilder;

    .line 496
    .line 497
    invoke-direct {v9, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 501
    .line 502
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 503
    .line 504
    .line 505
    invoke-virtual {v9, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 506
    .line 507
    .line 508
    iget-wide v11, v6, Lu01/f;->e:J

    .line 509
    .line 510
    invoke-virtual {v9, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 511
    .line 512
    .line 513
    const-string v4, "-byte, "

    .line 514
    .line 515
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 516
    .line 517
    .line 518
    invoke-virtual {v8}, Ljava/lang/Long;->longValue()J

    .line 519
    .line 520
    .line 521
    move-result-wide v11

    .line 522
    invoke-virtual {v9, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 523
    .line 524
    .line 525
    const-string v4, "-gzipped-byte body)"

    .line 526
    .line 527
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 528
    .line 529
    .line 530
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 531
    .line 532
    .line 533
    move-result-object v4

    .line 534
    invoke-interface {v0, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 535
    .line 536
    .line 537
    goto :goto_a

    .line 538
    :cond_14
    iget-object v8, v1, Lt01/c;->a:Lt01/b;

    .line 539
    .line 540
    invoke-virtual {v6, v11}, Lu01/f;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 541
    .line 542
    .line 543
    move-result-object v6

    .line 544
    invoke-interface {v8, v6}, Lt01/b;->f(Ljava/lang/String;)V

    .line 545
    .line 546
    .line 547
    iget-object v6, v1, Lt01/c;->a:Lt01/b;

    .line 548
    .line 549
    new-instance v8, Ljava/lang/StringBuilder;

    .line 550
    .line 551
    invoke-direct {v8, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 552
    .line 553
    .line 554
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 555
    .line 556
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 557
    .line 558
    .line 559
    invoke-virtual {v8, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 560
    .line 561
    .line 562
    invoke-virtual {v0}, Ld01/r0;->contentLength()J

    .line 563
    .line 564
    .line 565
    move-result-wide v11

    .line 566
    invoke-virtual {v8, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 567
    .line 568
    .line 569
    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 570
    .line 571
    .line 572
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 573
    .line 574
    .line 575
    move-result-object v0

    .line 576
    invoke-interface {v6, v0}, Lt01/b;->f(Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    goto :goto_a

    .line 580
    :cond_15
    :goto_9
    iget-object v0, v1, Lt01/c;->a:Lt01/b;

    .line 581
    .line 582
    new-instance v6, Ljava/lang/StringBuilder;

    .line 583
    .line 584
    invoke-direct {v6, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 585
    .line 586
    .line 587
    iget-object v4, v3, Ld01/k0;->b:Ljava/lang/String;

    .line 588
    .line 589
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 590
    .line 591
    .line 592
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object v4

    .line 596
    invoke-interface {v0, v4}, Lt01/b;->f(Ljava/lang/String;)V

    .line 597
    .line 598
    .line 599
    goto :goto_a

    .line 600
    :cond_16
    move/from16 v18, v4

    .line 601
    .line 602
    move/from16 v19, v6

    .line 603
    .line 604
    move-object/from16 v20, v11

    .line 605
    .line 606
    move-object/from16 v21, v12

    .line 607
    .line 608
    :goto_a
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 609
    .line 610
    .line 611
    move-result-wide v8

    .line 612
    :try_start_2
    invoke-virtual {v2, v3}, Li01/f;->b(Ld01/k0;)Ld01/t0;

    .line 613
    .line 614
    .line 615
    move-result-object v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 616
    sget-object v2, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 617
    .line 618
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 619
    .line 620
    .line 621
    move-result-wide v3

    .line 622
    sub-long/2addr v3, v8

    .line 623
    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 624
    .line 625
    .line 626
    move-result-wide v2

    .line 627
    iget-object v4, v0, Ld01/t0;->j:Ld01/v0;

    .line 628
    .line 629
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 630
    .line 631
    .line 632
    invoke-virtual {v4}, Ld01/v0;->b()J

    .line 633
    .line 634
    .line 635
    move-result-wide v11

    .line 636
    cmp-long v6, v11, v16

    .line 637
    .line 638
    move-object/from16 v16, v4

    .line 639
    .line 640
    const-string v4, "-byte"

    .line 641
    .line 642
    if-eqz v6, :cond_17

    .line 643
    .line 644
    new-instance v6, Ljava/lang/StringBuilder;

    .line 645
    .line 646
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 647
    .line 648
    .line 649
    invoke-virtual {v6, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 650
    .line 651
    .line 652
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 653
    .line 654
    .line 655
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 656
    .line 657
    .line 658
    move-result-object v6

    .line 659
    :goto_b
    move-wide/from16 v22, v8

    .line 660
    .line 661
    goto :goto_c

    .line 662
    :cond_17
    const-string v6, "unknown-length"

    .line 663
    .line 664
    goto :goto_b

    .line 665
    :goto_c
    iget-object v8, v1, Lt01/c;->a:Lt01/b;

    .line 666
    .line 667
    new-instance v9, Ljava/lang/StringBuilder;

    .line 668
    .line 669
    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    .line 670
    .line 671
    .line 672
    move-wide/from16 v24, v11

    .line 673
    .line 674
    new-instance v11, Ljava/lang/StringBuilder;

    .line 675
    .line 676
    const-string v12, "<-- "

    .line 677
    .line 678
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 679
    .line 680
    .line 681
    iget v12, v0, Ld01/t0;->g:I

    .line 682
    .line 683
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 684
    .line 685
    .line 686
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 687
    .line 688
    .line 689
    move-result-object v11

    .line 690
    invoke-virtual {v9, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 691
    .line 692
    .line 693
    iget-object v11, v0, Ld01/t0;->f:Ljava/lang/String;

    .line 694
    .line 695
    invoke-virtual {v11}, Ljava/lang/String;->length()I

    .line 696
    .line 697
    .line 698
    move-result v11

    .line 699
    if-lez v11, :cond_18

    .line 700
    .line 701
    new-instance v11, Ljava/lang/StringBuilder;

    .line 702
    .line 703
    move-object/from16 v12, v21

    .line 704
    .line 705
    invoke-direct {v11, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 706
    .line 707
    .line 708
    move-object/from16 v17, v4

    .line 709
    .line 710
    iget-object v4, v0, Ld01/t0;->f:Ljava/lang/String;

    .line 711
    .line 712
    invoke-virtual {v11, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 713
    .line 714
    .line 715
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 716
    .line 717
    .line 718
    move-result-object v4

    .line 719
    invoke-virtual {v9, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 720
    .line 721
    .line 722
    goto :goto_d

    .line 723
    :cond_18
    move-object/from16 v17, v4

    .line 724
    .line 725
    move-object/from16 v12, v21

    .line 726
    .line 727
    :goto_d
    new-instance v4, Ljava/lang/StringBuilder;

    .line 728
    .line 729
    invoke-direct {v4, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 730
    .line 731
    .line 732
    iget-object v11, v0, Ld01/t0;->d:Ld01/k0;

    .line 733
    .line 734
    iget-object v11, v11, Ld01/k0;->a:Ld01/a0;

    .line 735
    .line 736
    move-object/from16 v12, v20

    .line 737
    .line 738
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 739
    .line 740
    .line 741
    iget-object v11, v11, Ld01/a0;->i:Ljava/lang/String;

    .line 742
    .line 743
    invoke-virtual {v4, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 744
    .line 745
    .line 746
    invoke-virtual {v4, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 747
    .line 748
    .line 749
    invoke-virtual {v4, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 750
    .line 751
    .line 752
    const-string v2, "ms"

    .line 753
    .line 754
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 755
    .line 756
    .line 757
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 758
    .line 759
    .line 760
    move-result-object v2

    .line 761
    invoke-virtual {v9, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 762
    .line 763
    .line 764
    const-string v2, ", "

    .line 765
    .line 766
    if-nez v19, :cond_19

    .line 767
    .line 768
    new-instance v3, Ljava/lang/StringBuilder;

    .line 769
    .line 770
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 771
    .line 772
    .line 773
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 774
    .line 775
    .line 776
    const-string v4, " body"

    .line 777
    .line 778
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 779
    .line 780
    .line 781
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 782
    .line 783
    .line 784
    move-result-object v3

    .line 785
    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 786
    .line 787
    .line 788
    :cond_19
    const-string v3, ")"

    .line 789
    .line 790
    invoke-virtual {v9, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 791
    .line 792
    .line 793
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 794
    .line 795
    .line 796
    move-result-object v3

    .line 797
    invoke-interface {v8, v3}, Lt01/b;->f(Ljava/lang/String;)V

    .line 798
    .line 799
    .line 800
    if-eqz v19, :cond_26

    .line 801
    .line 802
    iget-object v3, v0, Ld01/t0;->i:Ld01/y;

    .line 803
    .line 804
    invoke-virtual {v3}, Ld01/y;->size()I

    .line 805
    .line 806
    .line 807
    move-result v4

    .line 808
    const/4 v6, 0x0

    .line 809
    :goto_e
    if-ge v6, v4, :cond_1a

    .line 810
    .line 811
    invoke-virtual {v1, v3, v6}, Lt01/c;->a(Ld01/y;I)V

    .line 812
    .line 813
    .line 814
    add-int/lit8 v6, v6, 0x1

    .line 815
    .line 816
    goto :goto_e

    .line 817
    :cond_1a
    if-eqz v18, :cond_25

    .line 818
    .line 819
    invoke-static {v0}, Li01/e;->a(Ld01/t0;)Z

    .line 820
    .line 821
    .line 822
    move-result v4

    .line 823
    if-nez v4, :cond_1b

    .line 824
    .line 825
    goto/16 :goto_11

    .line 826
    .line 827
    :cond_1b
    iget-object v4, v0, Ld01/t0;->i:Ld01/y;

    .line 828
    .line 829
    invoke-virtual {v4, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 830
    .line 831
    .line 832
    move-result-object v4

    .line 833
    if-nez v4, :cond_1c

    .line 834
    .line 835
    goto :goto_f

    .line 836
    :cond_1c
    invoke-virtual {v4, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 837
    .line 838
    .line 839
    move-result v6

    .line 840
    if-nez v6, :cond_1d

    .line 841
    .line 842
    invoke-virtual {v4, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 843
    .line 844
    .line 845
    move-result v4

    .line 846
    if-nez v4, :cond_1d

    .line 847
    .line 848
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 849
    .line 850
    const-string v2, "<-- END HTTP (encoded body omitted)"

    .line 851
    .line 852
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 853
    .line 854
    .line 855
    return-object v0

    .line 856
    :cond_1d
    :goto_f
    iget-object v4, v0, Ld01/t0;->j:Ld01/v0;

    .line 857
    .line 858
    invoke-virtual {v4}, Ld01/v0;->d()Ld01/d0;

    .line 859
    .line 860
    .line 861
    move-result-object v4

    .line 862
    if-eqz v4, :cond_1e

    .line 863
    .line 864
    iget-object v6, v4, Ld01/d0;->b:Ljava/lang/String;

    .line 865
    .line 866
    const-string v7, "text"

    .line 867
    .line 868
    invoke-virtual {v6, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 869
    .line 870
    .line 871
    move-result v6

    .line 872
    if-eqz v6, :cond_1e

    .line 873
    .line 874
    iget-object v4, v4, Ld01/d0;->c:Ljava/lang/String;

    .line 875
    .line 876
    const-string v6, "event-stream"

    .line 877
    .line 878
    invoke-virtual {v4, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 879
    .line 880
    .line 881
    move-result v4

    .line 882
    if-eqz v4, :cond_1e

    .line 883
    .line 884
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 885
    .line 886
    const-string v2, "<-- END HTTP (streaming)"

    .line 887
    .line 888
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 889
    .line 890
    .line 891
    return-object v0

    .line 892
    :cond_1e
    invoke-virtual/range {v16 .. v16}, Ld01/v0;->p0()Lu01/h;

    .line 893
    .line 894
    .line 895
    move-result-object v4

    .line 896
    const-wide v6, 0x7fffffffffffffffL

    .line 897
    .line 898
    .line 899
    .line 900
    .line 901
    invoke-interface {v4, v6, v7}, Lu01/h;->c(J)Z

    .line 902
    .line 903
    .line 904
    sget-object v6, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 905
    .line 906
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 907
    .line 908
    .line 909
    move-result-wide v7

    .line 910
    sub-long v7, v7, v22

    .line 911
    .line 912
    invoke-virtual {v6, v7, v8}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 913
    .line 914
    .line 915
    move-result-wide v6

    .line 916
    invoke-interface {v4}, Lu01/h;->n()Lu01/f;

    .line 917
    .line 918
    .line 919
    move-result-object v4

    .line 920
    invoke-virtual {v3, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 921
    .line 922
    .line 923
    move-result-object v3

    .line 924
    invoke-virtual {v5, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 925
    .line 926
    .line 927
    move-result v3

    .line 928
    if-eqz v3, :cond_1f

    .line 929
    .line 930
    iget-wide v8, v4, Lu01/f;->e:J

    .line 931
    .line 932
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 933
    .line 934
    .line 935
    move-result-object v12

    .line 936
    new-instance v3, Lu01/p;

    .line 937
    .line 938
    invoke-virtual {v4}, Lu01/f;->b()Lu01/f;

    .line 939
    .line 940
    .line 941
    move-result-object v4

    .line 942
    invoke-direct {v3, v4}, Lu01/p;-><init>(Lu01/h;)V

    .line 943
    .line 944
    .line 945
    :try_start_3
    new-instance v4, Lu01/f;

    .line 946
    .line 947
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 948
    .line 949
    .line 950
    invoke-virtual {v4, v3}, Lu01/f;->P(Lu01/h0;)J
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 951
    .line 952
    .line 953
    invoke-virtual {v3}, Lu01/p;->close()V

    .line 954
    .line 955
    .line 956
    goto :goto_10

    .line 957
    :catchall_2
    move-exception v0

    .line 958
    move-object v1, v0

    .line 959
    :try_start_4
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    .line 960
    :catchall_3
    move-exception v0

    .line 961
    invoke-static {v3, v1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 962
    .line 963
    .line 964
    throw v0

    .line 965
    :cond_1f
    const/4 v12, 0x0

    .line 966
    :goto_10
    invoke-virtual/range {v16 .. v16}, Ld01/v0;->d()Ld01/d0;

    .line 967
    .line 968
    .line 969
    move-result-object v3

    .line 970
    if-eqz v3, :cond_20

    .line 971
    .line 972
    sget-object v5, Ld01/d0;->e:Lly0/n;

    .line 973
    .line 974
    const/4 v5, 0x0

    .line 975
    invoke-virtual {v3, v5}, Ld01/d0;->a(Ljava/nio/charset/Charset;)Ljava/nio/charset/Charset;

    .line 976
    .line 977
    .line 978
    move-result-object v3

    .line 979
    if-nez v3, :cond_21

    .line 980
    .line 981
    :cond_20
    sget-object v3, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 982
    .line 983
    :cond_21
    invoke-static {v4}, Ljp/mg;->a(Lu01/f;)Z

    .line 984
    .line 985
    .line 986
    move-result v5

    .line 987
    const-string v8, "<-- END HTTP ("

    .line 988
    .line 989
    if-nez v5, :cond_22

    .line 990
    .line 991
    iget-object v2, v1, Lt01/c;->a:Lt01/b;

    .line 992
    .line 993
    invoke-interface {v2, v10}, Lt01/b;->f(Ljava/lang/String;)V

    .line 994
    .line 995
    .line 996
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 997
    .line 998
    const-string v2, "ms, binary "

    .line 999
    .line 1000
    invoke-static {v6, v7, v8, v2}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v2

    .line 1004
    iget-wide v3, v4, Lu01/f;->e:J

    .line 1005
    .line 1006
    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 1007
    .line 1008
    .line 1009
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1010
    .line 1011
    .line 1012
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v2

    .line 1016
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1017
    .line 1018
    .line 1019
    return-object v0

    .line 1020
    :cond_22
    const-wide/16 v13, 0x0

    .line 1021
    .line 1022
    cmp-long v5, v24, v13

    .line 1023
    .line 1024
    if-eqz v5, :cond_23

    .line 1025
    .line 1026
    iget-object v5, v1, Lt01/c;->a:Lt01/b;

    .line 1027
    .line 1028
    invoke-interface {v5, v10}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1029
    .line 1030
    .line 1031
    iget-object v5, v1, Lt01/c;->a:Lt01/b;

    .line 1032
    .line 1033
    invoke-virtual {v4}, Lu01/f;->b()Lu01/f;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v9

    .line 1037
    invoke-virtual {v9, v3}, Lu01/f;->f0(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v3

    .line 1041
    invoke-interface {v5, v3}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1042
    .line 1043
    .line 1044
    :cond_23
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 1045
    .line 1046
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1047
    .line 1048
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 1049
    .line 1050
    .line 1051
    const-string v5, "ms, "

    .line 1052
    .line 1053
    invoke-static {v6, v7, v8, v5}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v5

    .line 1057
    iget-wide v6, v4, Lu01/f;->e:J

    .line 1058
    .line 1059
    invoke-virtual {v5, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 1060
    .line 1061
    .line 1062
    move-object/from16 v4, v17

    .line 1063
    .line 1064
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1065
    .line 1066
    .line 1067
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1068
    .line 1069
    .line 1070
    move-result-object v4

    .line 1071
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1072
    .line 1073
    .line 1074
    if-eqz v12, :cond_24

    .line 1075
    .line 1076
    new-instance v4, Ljava/lang/StringBuilder;

    .line 1077
    .line 1078
    invoke-direct {v4, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1079
    .line 1080
    .line 1081
    invoke-virtual {v12}, Ljava/lang/Number;->longValue()J

    .line 1082
    .line 1083
    .line 1084
    move-result-wide v5

    .line 1085
    invoke-virtual {v4, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 1086
    .line 1087
    .line 1088
    const-string v2, "-gzipped-byte"

    .line 1089
    .line 1090
    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1091
    .line 1092
    .line 1093
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1094
    .line 1095
    .line 1096
    move-result-object v2

    .line 1097
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1098
    .line 1099
    .line 1100
    :cond_24
    const-string v2, " body)"

    .line 1101
    .line 1102
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1103
    .line 1104
    .line 1105
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v2

    .line 1109
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1110
    .line 1111
    .line 1112
    return-object v0

    .line 1113
    :cond_25
    :goto_11
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 1114
    .line 1115
    const-string v2, "<-- END HTTP"

    .line 1116
    .line 1117
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1118
    .line 1119
    .line 1120
    :cond_26
    return-object v0

    .line 1121
    :catch_0
    move-exception v0

    .line 1122
    move-wide/from16 v22, v8

    .line 1123
    .line 1124
    move-object/from16 v2, v20

    .line 1125
    .line 1126
    move-object/from16 v12, v21

    .line 1127
    .line 1128
    sget-object v4, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 1129
    .line 1130
    invoke-static {}, Ljava/lang/System;->nanoTime()J

    .line 1131
    .line 1132
    .line 1133
    move-result-wide v5

    .line 1134
    sub-long v5, v5, v22

    .line 1135
    .line 1136
    invoke-virtual {v4, v5, v6}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 1137
    .line 1138
    .line 1139
    move-result-wide v4

    .line 1140
    iget-object v1, v1, Lt01/c;->a:Lt01/b;

    .line 1141
    .line 1142
    new-instance v6, Ljava/lang/StringBuilder;

    .line 1143
    .line 1144
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 1145
    .line 1146
    .line 1147
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1148
    .line 1149
    const-string v8, "<-- HTTP FAILED: "

    .line 1150
    .line 1151
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1152
    .line 1153
    .line 1154
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1155
    .line 1156
    .line 1157
    const/16 v8, 0x2e

    .line 1158
    .line 1159
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 1160
    .line 1161
    .line 1162
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v7

    .line 1166
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1167
    .line 1168
    .line 1169
    new-instance v7, Ljava/lang/StringBuilder;

    .line 1170
    .line 1171
    invoke-direct {v7, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1172
    .line 1173
    .line 1174
    iget-object v3, v3, Ld01/k0;->a:Ld01/a0;

    .line 1175
    .line 1176
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1177
    .line 1178
    .line 1179
    iget-object v2, v3, Ld01/a0;->i:Ljava/lang/String;

    .line 1180
    .line 1181
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1182
    .line 1183
    .line 1184
    invoke-virtual {v7, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1185
    .line 1186
    .line 1187
    invoke-virtual {v7, v4, v5}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 1188
    .line 1189
    .line 1190
    const-string v2, "ms)"

    .line 1191
    .line 1192
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1193
    .line 1194
    .line 1195
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1196
    .line 1197
    .line 1198
    move-result-object v2

    .line 1199
    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1200
    .line 1201
    .line 1202
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1203
    .line 1204
    .line 1205
    move-result-object v2

    .line 1206
    invoke-interface {v1, v2}, Lt01/b;->f(Ljava/lang/String;)V

    .line 1207
    .line 1208
    .line 1209
    throw v0
.end method
