.class public final Li01/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ld01/c0;


# static fields
.field public static final a:Li01/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Li01/a;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Li01/a;->a:Li01/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final intercept(Ld01/b0;)Ld01/t0;
    .locals 20

    .line 1
    const-string v1, "close"

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    check-cast v0, Li01/f;

    .line 6
    .line 7
    iget-object v3, v0, Li01/f;->d:Lh01/g;

    .line 8
    .line 9
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object v2, v3, Lh01/g;->a:Lh01/o;

    .line 13
    .line 14
    iget-object v9, v3, Lh01/g;->c:Li01/d;

    .line 15
    .line 16
    iget-object v10, v0, Li01/f;->e:Ld01/k0;

    .line 17
    .line 18
    iget-object v0, v10, Ld01/k0;->d:Ld01/r0;

    .line 19
    .line 20
    iget-object v4, v10, Ld01/k0;->c:Ld01/y;

    .line 21
    .line 22
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 23
    .line 24
    .line 25
    move-result-wide v11

    .line 26
    iget-object v5, v10, Ld01/k0;->b:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v5}, Llp/l1;->c(Ljava/lang/String;)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    const/4 v13, 0x0

    .line 33
    const/4 v14, 0x1

    .line 34
    if-eqz v5, :cond_0

    .line 35
    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    move v5, v14

    .line 39
    goto :goto_0

    .line 40
    :cond_0
    move v5, v13

    .line 41
    :goto_0
    const-string v15, "Connection"

    .line 42
    .line 43
    invoke-virtual {v4, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    const-string v7, "upgrade"

    .line 48
    .line 49
    invoke-virtual {v7, v6}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 50
    .line 51
    .line 52
    move-result v16

    .line 53
    const/16 v17, 0x0

    .line 54
    .line 55
    :try_start_0
    invoke-interface {v9, v10}, Li01/d;->k(Ld01/k0;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_7

    .line 56
    .line 57
    .line 58
    if-eqz v5, :cond_5

    .line 59
    .line 60
    :try_start_1
    const-string v5, "100-continue"

    .line 61
    .line 62
    const-string v6, "Expect"

    .line 63
    .line 64
    invoke-virtual {v4, v6}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-virtual {v5, v4}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result v4
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0

    .line 72
    if-eqz v4, :cond_1

    .line 73
    .line 74
    :try_start_2
    invoke-interface {v9}, Li01/d;->g()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1

    .line 75
    .line 76
    .line 77
    :try_start_3
    invoke-virtual {v3, v14}, Lh01/g;->d(Z)Ld01/s0;

    .line 78
    .line 79
    .line 80
    move-result-object v4

    .line 81
    move-object/from16 v18, v4

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :catch_0
    move-exception v0

    .line 85
    move-object v14, v7

    .line 86
    goto/16 :goto_6

    .line 87
    .line 88
    :catch_1
    move-exception v0

    .line 89
    invoke-virtual {v3, v0}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 90
    .line 91
    .line 92
    throw v0
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0

    .line 93
    :cond_1
    move-object/from16 v18, v17

    .line 94
    .line 95
    :goto_1
    if-nez v18, :cond_3

    .line 96
    .line 97
    :try_start_4
    invoke-virtual {v0}, Ld01/r0;->isDuplex()Z

    .line 98
    .line 99
    .line 100
    move-result v2
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_2

    .line 101
    if-eqz v2, :cond_2

    .line 102
    .line 103
    :try_start_5
    invoke-interface {v9}, Li01/d;->g()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_3

    .line 104
    .line 105
    .line 106
    :try_start_6
    invoke-virtual {v3, v10, v14}, Lh01/g;->b(Ld01/k0;Z)Lh01/e;

    .line 107
    .line 108
    .line 109
    move-result-object v2

    .line 110
    invoke-static {v2}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    invoke-virtual {v0, v2}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 115
    .line 116
    .line 117
    :goto_2
    move-object v14, v7

    .line 118
    goto :goto_5

    .line 119
    :catch_2
    move-exception v0

    .line 120
    move-object v14, v7

    .line 121
    :goto_3
    move-object/from16 v17, v18

    .line 122
    .line 123
    goto/16 :goto_6

    .line 124
    .line 125
    :catch_3
    move-exception v0

    .line 126
    invoke-virtual {v3, v0}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 127
    .line 128
    .line 129
    throw v0

    .line 130
    :cond_2
    invoke-virtual {v3, v10, v13}, Lh01/g;->b(Ld01/k0;Z)Lh01/e;

    .line 131
    .line 132
    .line 133
    move-result-object v2

    .line 134
    invoke-static {v2}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    invoke-virtual {v0, v2}, Ld01/r0;->writeTo(Lu01/g;)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2}, Lu01/a0;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_2

    .line 142
    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_3
    const/4 v6, 0x0

    .line 146
    move-object v4, v7

    .line 147
    const/4 v7, 0x0

    .line 148
    const/4 v8, 0x0

    .line 149
    move-object v5, v4

    .line 150
    const/4 v4, 0x1

    .line 151
    move-object/from16 v19, v5

    .line 152
    .line 153
    const/4 v5, 0x0

    .line 154
    move-object/from16 v14, v19

    .line 155
    .line 156
    :try_start_7
    invoke-virtual/range {v2 .. v8}, Lh01/o;->f(Lh01/g;ZZZZLjava/io/IOException;)Ljava/io/IOException;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v3}, Lh01/g;->c()Lh01/p;

    .line 160
    .line 161
    .line 162
    move-result-object v2

    .line 163
    iget-object v2, v2, Lh01/p;->i:Lk01/p;

    .line 164
    .line 165
    if-eqz v2, :cond_4

    .line 166
    .line 167
    const/4 v2, 0x1

    .line 168
    goto :goto_4

    .line 169
    :cond_4
    move v2, v13

    .line 170
    :goto_4
    if-nez v2, :cond_6

    .line 171
    .line 172
    invoke-interface {v9}, Li01/d;->i()Li01/c;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    invoke-interface {v2}, Li01/c;->c()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_4

    .line 177
    .line 178
    .line 179
    goto :goto_5

    .line 180
    :catch_4
    move-exception v0

    .line 181
    goto :goto_3

    .line 182
    :cond_5
    move-object v14, v7

    .line 183
    const/4 v6, 0x0

    .line 184
    const/4 v7, 0x0

    .line 185
    const/4 v8, 0x0

    .line 186
    const/4 v4, 0x1

    .line 187
    const/4 v5, 0x0

    .line 188
    :try_start_8
    invoke-virtual/range {v2 .. v8}, Lh01/o;->f(Lh01/g;ZZZZLjava/io/IOException;)Ljava/io/IOException;
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_6

    .line 189
    .line 190
    .line 191
    move-object/from16 v18, v17

    .line 192
    .line 193
    :cond_6
    :goto_5
    if-eqz v0, :cond_7

    .line 194
    .line 195
    :try_start_9
    invoke-virtual {v0}, Ld01/r0;->isDuplex()Z

    .line 196
    .line 197
    .line 198
    move-result v0
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_4

    .line 199
    if-nez v0, :cond_8

    .line 200
    .line 201
    :cond_7
    :try_start_a
    invoke-interface {v9}, Li01/d;->a()V
    :try_end_a
    .catch Ljava/io/IOException; {:try_start_a .. :try_end_a} :catch_5

    .line 202
    .line 203
    .line 204
    :cond_8
    move-object/from16 v8, v17

    .line 205
    .line 206
    goto :goto_7

    .line 207
    :catch_5
    move-exception v0

    .line 208
    :try_start_b
    invoke-virtual {v3, v0}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 209
    .line 210
    .line 211
    throw v0
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_4

    .line 212
    :catch_6
    move-exception v0

    .line 213
    goto :goto_6

    .line 214
    :catch_7
    move-exception v0

    .line 215
    move-object v14, v7

    .line 216
    :try_start_c
    invoke-virtual {v3, v0}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 217
    .line 218
    .line 219
    throw v0
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_6

    .line 220
    :goto_6
    instance-of v2, v0, Lk01/a;

    .line 221
    .line 222
    if-nez v2, :cond_19

    .line 223
    .line 224
    iget-boolean v2, v3, Lh01/g;->e:Z

    .line 225
    .line 226
    if-eqz v2, :cond_18

    .line 227
    .line 228
    move-object v8, v0

    .line 229
    move-object/from16 v18, v17

    .line 230
    .line 231
    :goto_7
    if-nez v18, :cond_9

    .line 232
    .line 233
    :try_start_d
    invoke-virtual {v3, v13}, Lh01/g;->d(Z)Ld01/s0;

    .line 234
    .line 235
    .line 236
    move-result-object v18

    .line 237
    invoke-static/range {v18 .. v18}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    :cond_9
    move-object/from16 v0, v18

    .line 241
    .line 242
    goto :goto_8

    .line 243
    :catch_8
    move-exception v0

    .line 244
    goto/16 :goto_f

    .line 245
    .line 246
    :goto_8
    iput-object v10, v0, Ld01/s0;->a:Ld01/k0;

    .line 247
    .line 248
    invoke-virtual {v3}, Lh01/g;->c()Lh01/p;

    .line 249
    .line 250
    .line 251
    move-result-object v2

    .line 252
    iget-object v2, v2, Lh01/p;->f:Ld01/w;

    .line 253
    .line 254
    iput-object v2, v0, Ld01/s0;->e:Ld01/w;

    .line 255
    .line 256
    iput-wide v11, v0, Ld01/s0;->l:J

    .line 257
    .line 258
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 259
    .line 260
    .line 261
    move-result-wide v4

    .line 262
    iput-wide v4, v0, Ld01/s0;->m:J

    .line 263
    .line 264
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    iget v2, v0, Ld01/t0;->g:I
    :try_end_d
    .catch Ljava/io/IOException; {:try_start_d .. :try_end_d} :catch_8

    .line 269
    .line 270
    :goto_9
    iget-object v4, v0, Ld01/t0;->j:Ld01/v0;

    .line 271
    .line 272
    const/16 v5, 0x64

    .line 273
    .line 274
    if-ne v2, v5, :cond_a

    .line 275
    .line 276
    goto :goto_a

    .line 277
    :cond_a
    const/16 v5, 0x66

    .line 278
    .line 279
    if-gt v5, v2, :cond_b

    .line 280
    .line 281
    const/16 v5, 0xc8

    .line 282
    .line 283
    if-ge v2, v5, :cond_b

    .line 284
    .line 285
    :goto_a
    :try_start_e
    invoke-virtual {v3, v13}, Lh01/g;->d(Z)Ld01/s0;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    iput-object v10, v0, Ld01/s0;->a:Ld01/k0;

    .line 293
    .line 294
    invoke-virtual {v3}, Lh01/g;->c()Lh01/p;

    .line 295
    .line 296
    .line 297
    move-result-object v2

    .line 298
    iget-object v2, v2, Lh01/p;->f:Ld01/w;

    .line 299
    .line 300
    iput-object v2, v0, Ld01/s0;->e:Ld01/w;

    .line 301
    .line 302
    iput-wide v11, v0, Ld01/s0;->l:J

    .line 303
    .line 304
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 305
    .line 306
    .line 307
    move-result-wide v4

    .line 308
    iput-wide v4, v0, Ld01/s0;->m:J

    .line 309
    .line 310
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    iget v2, v0, Ld01/t0;->g:I

    .line 315
    .line 316
    goto :goto_9

    .line 317
    :cond_b
    const/16 v5, 0x65

    .line 318
    .line 319
    if-ne v2, v5, :cond_c

    .line 320
    .line 321
    const/4 v5, 0x1

    .line 322
    goto :goto_b

    .line 323
    :cond_c
    move v5, v13

    .line 324
    :goto_b
    if-eqz v5, :cond_f

    .line 325
    .line 326
    invoke-virtual {v3}, Lh01/g;->c()Lh01/p;

    .line 327
    .line 328
    .line 329
    move-result-object v6

    .line 330
    iget-object v6, v6, Lh01/p;->i:Lk01/p;

    .line 331
    .line 332
    if-eqz v6, :cond_d

    .line 333
    .line 334
    const/4 v6, 0x1

    .line 335
    goto :goto_c

    .line 336
    :cond_d
    move v6, v13

    .line 337
    :goto_c
    if-nez v6, :cond_e

    .line 338
    .line 339
    goto :goto_d

    .line 340
    :cond_e
    new-instance v0, Ljava/net/ProtocolException;

    .line 341
    .line 342
    const-string v1, "Unexpected 101 code on HTTP/2 connection"

    .line 343
    .line 344
    invoke-direct {v0, v1}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    throw v0

    .line 348
    :cond_f
    :goto_d
    if-eqz v5, :cond_10

    .line 349
    .line 350
    invoke-static {v0, v15}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 351
    .line 352
    .line 353
    move-result-object v5

    .line 354
    invoke-virtual {v14, v5}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 355
    .line 356
    .line 357
    move-result v5

    .line 358
    if-eqz v5, :cond_10

    .line 359
    .line 360
    const/4 v13, 0x1

    .line 361
    :cond_10
    if-eqz v16, :cond_11

    .line 362
    .line 363
    if-eqz v13, :cond_11

    .line 364
    .line 365
    invoke-virtual {v0}, Ld01/t0;->d()Ld01/s0;

    .line 366
    .line 367
    .line 368
    move-result-object v0

    .line 369
    new-instance v5, Le01/c;

    .line 370
    .line 371
    invoke-virtual {v4}, Ld01/v0;->d()Ld01/d0;

    .line 372
    .line 373
    .line 374
    move-result-object v6

    .line 375
    invoke-virtual {v4}, Ld01/v0;->b()J

    .line 376
    .line 377
    .line 378
    move-result-wide v10

    .line 379
    invoke-direct {v5, v6, v10, v11}, Le01/c;-><init>(Ld01/d0;J)V

    .line 380
    .line 381
    .line 382
    iput-object v5, v0, Ld01/s0;->g:Ld01/v0;

    .line 383
    .line 384
    invoke-virtual {v3}, Lh01/g;->f()Lgw0/c;

    .line 385
    .line 386
    .line 387
    move-result-object v3

    .line 388
    iput-object v3, v0, Ld01/s0;->h:Lu01/g0;

    .line 389
    .line 390
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 391
    .line 392
    .line 393
    move-result-object v0
    :try_end_e
    .catch Ljava/io/IOException; {:try_start_e .. :try_end_e} :catch_8

    .line 394
    move v11, v2

    .line 395
    goto :goto_e

    .line 396
    :cond_11
    :try_start_f
    const-string v4, "Content-Type"

    .line 397
    .line 398
    invoke-static {v0, v4}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 399
    .line 400
    .line 401
    move-result-object v10

    .line 402
    invoke-interface {v9, v0}, Li01/d;->b(Ld01/t0;)J

    .line 403
    .line 404
    .line 405
    move-result-wide v5

    .line 406
    invoke-interface {v9, v0}, Li01/d;->c(Ld01/t0;)Lu01/h0;

    .line 407
    .line 408
    .line 409
    move-result-object v4

    .line 410
    move v7, v2

    .line 411
    new-instance v2, Lh01/f;

    .line 412
    .line 413
    move v11, v7

    .line 414
    const/4 v7, 0x0

    .line 415
    invoke-direct/range {v2 .. v7}, Lh01/f;-><init>(Lh01/g;Lu01/h0;JZ)V

    .line 416
    .line 417
    .line 418
    new-instance v4, Li01/g;

    .line 419
    .line 420
    invoke-static {v2}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 421
    .line 422
    .line 423
    move-result-object v2

    .line 424
    invoke-direct {v4, v10, v5, v6, v2}, Li01/g;-><init>(Ljava/lang/String;JLu01/b0;)V
    :try_end_f
    .catch Ljava/io/IOException; {:try_start_f .. :try_end_f} :catch_9

    .line 425
    .line 426
    .line 427
    :try_start_10
    invoke-virtual {v0}, Ld01/t0;->d()Ld01/s0;

    .line 428
    .line 429
    .line 430
    move-result-object v0

    .line 431
    iput-object v4, v0, Ld01/s0;->g:Ld01/v0;

    .line 432
    .line 433
    new-instance v2, Lvp/y1;

    .line 434
    .line 435
    const/16 v5, 0x9

    .line 436
    .line 437
    const/4 v6, 0x0

    .line 438
    invoke-direct {v2, v3, v4, v6, v5}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 439
    .line 440
    .line 441
    iput-object v2, v0, Ld01/s0;->o:Ld01/y0;

    .line 442
    .line 443
    invoke-virtual {v0}, Ld01/s0;->a()Ld01/t0;

    .line 444
    .line 445
    .line 446
    move-result-object v0

    .line 447
    :goto_e
    iget-object v2, v0, Ld01/t0;->d:Ld01/k0;

    .line 448
    .line 449
    iget-object v2, v2, Ld01/k0;->c:Ld01/y;

    .line 450
    .line 451
    invoke-virtual {v2, v15}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v2

    .line 455
    invoke-virtual {v1, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 456
    .line 457
    .line 458
    move-result v2

    .line 459
    if-nez v2, :cond_12

    .line 460
    .line 461
    invoke-static {v0, v15}, Ld01/t0;->b(Ld01/t0;Ljava/lang/String;)Ljava/lang/String;

    .line 462
    .line 463
    .line 464
    move-result-object v2

    .line 465
    invoke-virtual {v1, v2}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 466
    .line 467
    .line 468
    move-result v1

    .line 469
    if-eqz v1, :cond_13

    .line 470
    .line 471
    :cond_12
    invoke-interface {v9}, Li01/d;->i()Li01/c;

    .line 472
    .line 473
    .line 474
    move-result-object v1

    .line 475
    invoke-interface {v1}, Li01/c;->c()V

    .line 476
    .line 477
    .line 478
    :cond_13
    const/16 v1, 0xcc

    .line 479
    .line 480
    if-eq v11, v1, :cond_14

    .line 481
    .line 482
    const/16 v1, 0xcd

    .line 483
    .line 484
    if-ne v11, v1, :cond_15

    .line 485
    .line 486
    :cond_14
    iget-object v1, v0, Ld01/t0;->j:Ld01/v0;

    .line 487
    .line 488
    invoke-virtual {v1}, Ld01/v0;->b()J

    .line 489
    .line 490
    .line 491
    move-result-wide v1

    .line 492
    const-wide/16 v3, 0x0

    .line 493
    .line 494
    cmp-long v1, v1, v3

    .line 495
    .line 496
    if-gtz v1, :cond_16

    .line 497
    .line 498
    :cond_15
    return-object v0

    .line 499
    :cond_16
    new-instance v1, Ljava/net/ProtocolException;

    .line 500
    .line 501
    new-instance v2, Ljava/lang/StringBuilder;

    .line 502
    .line 503
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 504
    .line 505
    .line 506
    const-string v3, "HTTP "

    .line 507
    .line 508
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 509
    .line 510
    .line 511
    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 512
    .line 513
    .line 514
    const-string v3, " had non-zero Content-Length: "

    .line 515
    .line 516
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 517
    .line 518
    .line 519
    iget-object v0, v0, Ld01/t0;->j:Ld01/v0;

    .line 520
    .line 521
    invoke-virtual {v0}, Ld01/v0;->b()J

    .line 522
    .line 523
    .line 524
    move-result-wide v3

    .line 525
    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 526
    .line 527
    .line 528
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    invoke-direct {v1, v0}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 533
    .line 534
    .line 535
    throw v1

    .line 536
    :catch_9
    move-exception v0

    .line 537
    invoke-virtual {v3, v0}, Lh01/g;->e(Ljava/io/IOException;)V

    .line 538
    .line 539
    .line 540
    throw v0
    :try_end_10
    .catch Ljava/io/IOException; {:try_start_10 .. :try_end_10} :catch_8

    .line 541
    :goto_f
    if-eqz v8, :cond_17

    .line 542
    .line 543
    invoke-static {v8, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 544
    .line 545
    .line 546
    throw v8

    .line 547
    :cond_17
    throw v0

    .line 548
    :cond_18
    throw v0

    .line 549
    :cond_19
    throw v0
.end method
