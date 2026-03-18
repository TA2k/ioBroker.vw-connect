.class public abstract synthetic Lla/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lg40/d0;Lij0/a;)Lh40/m3;
    .locals 24

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    const-string v0, "<this>"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v3, v1, Lg40/d0;->k:Ljava/time/LocalDate;

    .line 11
    .line 12
    iget-object v4, v1, Lg40/d0;->l:Ljava/time/LocalDate;

    .line 13
    .line 14
    iget-object v5, v1, Lg40/d0;->m:Ljava/time/LocalDate;

    .line 15
    .line 16
    iget-object v14, v1, Lg40/d0;->h:Lg40/g0;

    .line 17
    .line 18
    const-string v0, "stringResource"

    .line 19
    .line 20
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v7, v1, Lg40/d0;->a:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v8, v1, Lg40/d0;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v9, v1, Lg40/d0;->c:Ljava/lang/String;

    .line 28
    .line 29
    iget-object v10, v1, Lg40/d0;->d:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v0, v1, Lg40/d0;->e:Ljava/util/List;

    .line 32
    .line 33
    check-cast v0, Ljava/lang/Iterable;

    .line 34
    .line 35
    new-instance v11, Ljava/util/ArrayList;

    .line 36
    .line 37
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    const/4 v12, 0x0

    .line 49
    if-eqz v0, :cond_3

    .line 50
    .line 51
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    check-cast v0, Ljava/lang/String;

    .line 56
    .line 57
    :try_start_0
    new-instance v13, Ljava/net/URL;

    .line 58
    .line 59
    invoke-direct {v13, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :catchall_0
    move-exception v0

    .line 64
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 65
    .line 66
    .line 67
    move-result-object v13

    .line 68
    :goto_1
    invoke-static {v13}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    if-eqz v0, :cond_0

    .line 73
    .line 74
    new-instance v15, Lbp0/e;

    .line 75
    .line 76
    const/4 v2, 0x1

    .line 77
    invoke-direct {v15, v0, v2}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 78
    .line 79
    .line 80
    invoke-static {v12, v1, v15}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 81
    .line 82
    .line 83
    :cond_0
    instance-of v0, v13, Llx0/n;

    .line 84
    .line 85
    if-eqz v0, :cond_1

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_1
    move-object v12, v13

    .line 89
    :goto_2
    check-cast v12, Ljava/net/URL;

    .line 90
    .line 91
    if-eqz v12, :cond_2

    .line 92
    .line 93
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    :cond_2
    move-object/from16 v2, p1

    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_3
    iget-boolean v0, v1, Lg40/d0;->f:Z

    .line 100
    .line 101
    iget-boolean v13, v1, Lg40/d0;->g:Z

    .line 102
    .line 103
    iget-object v15, v1, Lg40/d0;->i:Ljava/lang/String;

    .line 104
    .line 105
    const v2, 0x7f080321

    .line 106
    .line 107
    .line 108
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 113
    .line 114
    .line 115
    move-result v6

    .line 116
    const/4 v12, 0x1

    .line 117
    if-eqz v6, :cond_7

    .line 118
    .line 119
    if-eq v6, v12, :cond_6

    .line 120
    .line 121
    const/4 v12, 0x2

    .line 122
    if-eq v6, v12, :cond_8

    .line 123
    .line 124
    const/4 v12, 0x3

    .line 125
    if-eq v6, v12, :cond_5

    .line 126
    .line 127
    const/4 v12, 0x4

    .line 128
    if-eq v6, v12, :cond_8

    .line 129
    .line 130
    const/4 v12, 0x5

    .line 131
    if-ne v6, v12, :cond_4

    .line 132
    .line 133
    const/4 v2, 0x0

    .line 134
    goto :goto_3

    .line 135
    :cond_4
    new-instance v0, La8/r0;

    .line 136
    .line 137
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 138
    .line 139
    .line 140
    throw v0

    .line 141
    :cond_5
    const v2, 0x7f0804ae

    .line 142
    .line 143
    .line 144
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    goto :goto_3

    .line 149
    :cond_6
    const v2, 0x7f0802d3

    .line 150
    .line 151
    .line 152
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    goto :goto_3

    .line 157
    :cond_7
    const v2, 0x7f080357

    .line 158
    .line 159
    .line 160
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    :cond_8
    :goto_3
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 165
    .line 166
    .line 167
    move-result v6

    .line 168
    if-eqz v6, :cond_e

    .line 169
    .line 170
    const/4 v12, 0x1

    .line 171
    if-eq v6, v12, :cond_d

    .line 172
    .line 173
    const/4 v12, 0x2

    .line 174
    if-eq v6, v12, :cond_c

    .line 175
    .line 176
    const/4 v12, 0x3

    .line 177
    if-eq v6, v12, :cond_b

    .line 178
    .line 179
    const/4 v12, 0x4

    .line 180
    if-eq v6, v12, :cond_a

    .line 181
    .line 182
    const/4 v12, 0x5

    .line 183
    if-ne v6, v12, :cond_9

    .line 184
    .line 185
    move/from16 v23, v0

    .line 186
    .line 187
    const/4 v0, 0x0

    .line 188
    goto :goto_4

    .line 189
    :cond_9
    new-instance v0, La8/r0;

    .line 190
    .line 191
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 192
    .line 193
    .line 194
    throw v0

    .line 195
    :cond_a
    const/4 v6, 0x0

    .line 196
    new-array v12, v6, [Ljava/lang/Object;

    .line 197
    .line 198
    move-object/from16 v6, p1

    .line 199
    .line 200
    check-cast v6, Ljj0/f;

    .line 201
    .line 202
    move/from16 v23, v0

    .line 203
    .line 204
    const v0, 0x7f120cd4

    .line 205
    .line 206
    .line 207
    invoke-virtual {v6, v0, v12}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    goto :goto_4

    .line 212
    :cond_b
    move/from16 v23, v0

    .line 213
    .line 214
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 215
    .line 216
    .line 217
    move-result-object v0

    .line 218
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v0

    .line 222
    move-object/from16 v6, p1

    .line 223
    .line 224
    check-cast v6, Ljj0/f;

    .line 225
    .line 226
    const v12, 0x7f120cd0

    .line 227
    .line 228
    .line 229
    invoke-virtual {v6, v12, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    goto :goto_4

    .line 234
    :cond_c
    move/from16 v23, v0

    .line 235
    .line 236
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    move-object/from16 v6, p1

    .line 245
    .line 246
    check-cast v6, Ljj0/f;

    .line 247
    .line 248
    const v12, 0x7f120ccf

    .line 249
    .line 250
    .line 251
    invoke-virtual {v6, v12, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    goto :goto_4

    .line 256
    :cond_d
    move/from16 v23, v0

    .line 257
    .line 258
    invoke-static {v4}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object v0

    .line 266
    move-object/from16 v6, p1

    .line 267
    .line 268
    check-cast v6, Ljj0/f;

    .line 269
    .line 270
    const v12, 0x7f120cd2

    .line 271
    .line 272
    .line 273
    invoke-virtual {v6, v12, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    goto :goto_4

    .line 278
    :cond_e
    move/from16 v23, v0

    .line 279
    .line 280
    invoke-static {v3}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 281
    .line 282
    .line 283
    move-result-object v0

    .line 284
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    move-object/from16 v6, p1

    .line 289
    .line 290
    check-cast v6, Ljj0/f;

    .line 291
    .line 292
    const v12, 0x7f120cd1

    .line 293
    .line 294
    .line 295
    invoke-virtual {v6, v12, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    :goto_4
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 300
    .line 301
    .line 302
    move-result v6

    .line 303
    if-eqz v6, :cond_14

    .line 304
    .line 305
    const/4 v12, 0x1

    .line 306
    if-eq v6, v12, :cond_13

    .line 307
    .line 308
    const/4 v12, 0x2

    .line 309
    if-eq v6, v12, :cond_12

    .line 310
    .line 311
    const/4 v12, 0x3

    .line 312
    if-eq v6, v12, :cond_11

    .line 313
    .line 314
    const/4 v12, 0x4

    .line 315
    if-eq v6, v12, :cond_10

    .line 316
    .line 317
    const/4 v12, 0x5

    .line 318
    if-ne v6, v12, :cond_f

    .line 319
    .line 320
    const/16 v18, 0x0

    .line 321
    .line 322
    goto :goto_6

    .line 323
    :cond_f
    new-instance v0, La8/r0;

    .line 324
    .line 325
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 326
    .line 327
    .line 328
    throw v0

    .line 329
    :cond_10
    const/4 v6, 0x0

    .line 330
    new-array v3, v6, [Ljava/lang/Object;

    .line 331
    .line 332
    move-object/from16 v4, p1

    .line 333
    .line 334
    check-cast v4, Ljj0/f;

    .line 335
    .line 336
    const v6, 0x7f120cba

    .line 337
    .line 338
    .line 339
    invoke-virtual {v4, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v12

    .line 343
    :goto_5
    move-object/from16 v18, v12

    .line 344
    .line 345
    goto :goto_6

    .line 346
    :cond_11
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object v3

    .line 350
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    move-result-object v3

    .line 354
    move-object/from16 v4, p1

    .line 355
    .line 356
    check-cast v4, Ljj0/f;

    .line 357
    .line 358
    const v6, 0x7f120ca8

    .line 359
    .line 360
    .line 361
    invoke-virtual {v4, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object v12

    .line 365
    goto :goto_5

    .line 366
    :cond_12
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v3

    .line 370
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 371
    .line 372
    .line 373
    move-result-object v3

    .line 374
    move-object/from16 v4, p1

    .line 375
    .line 376
    check-cast v4, Ljj0/f;

    .line 377
    .line 378
    const v6, 0x7f120ca9

    .line 379
    .line 380
    .line 381
    invoke-virtual {v4, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 382
    .line 383
    .line 384
    move-result-object v12

    .line 385
    goto :goto_5

    .line 386
    :cond_13
    invoke-static {v4}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 387
    .line 388
    .line 389
    move-result-object v3

    .line 390
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 391
    .line 392
    .line 393
    move-result-object v3

    .line 394
    move-object/from16 v4, p1

    .line 395
    .line 396
    check-cast v4, Ljj0/f;

    .line 397
    .line 398
    const v6, 0x7f120cb9

    .line 399
    .line 400
    .line 401
    invoke-virtual {v4, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v12

    .line 405
    goto :goto_5

    .line 406
    :cond_14
    invoke-static {v3}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v3

    .line 410
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object v3

    .line 414
    move-object/from16 v4, p1

    .line 415
    .line 416
    check-cast v4, Ljj0/f;

    .line 417
    .line 418
    const v6, 0x7f120cb8

    .line 419
    .line 420
    .line 421
    invoke-virtual {v4, v6, v3}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 422
    .line 423
    .line 424
    move-result-object v12

    .line 425
    goto :goto_5

    .line 426
    :goto_6
    iget-object v3, v1, Lg40/d0;->n:Lg40/e0;

    .line 427
    .line 428
    invoke-static {v5}, Lu7/b;->c(Ljava/time/LocalDate;)Ljava/lang/String;

    .line 429
    .line 430
    .line 431
    move-result-object v4

    .line 432
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v4

    .line 436
    move-object/from16 v5, p1

    .line 437
    .line 438
    check-cast v5, Ljj0/f;

    .line 439
    .line 440
    const v6, 0x7f120ca8

    .line 441
    .line 442
    .line 443
    invoke-virtual {v5, v6, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 444
    .line 445
    .line 446
    move-result-object v20

    .line 447
    iget-object v4, v1, Lg40/d0;->o:Ljava/lang/String;

    .line 448
    .line 449
    iget-object v1, v1, Lg40/d0;->p:Ljava/lang/String;

    .line 450
    .line 451
    new-instance v6, Lh40/m3;

    .line 452
    .line 453
    move-object/from16 v17, v0

    .line 454
    .line 455
    move-object/from16 v22, v1

    .line 456
    .line 457
    move-object/from16 v16, v2

    .line 458
    .line 459
    move-object/from16 v19, v3

    .line 460
    .line 461
    move-object/from16 v21, v4

    .line 462
    .line 463
    move/from16 v12, v23

    .line 464
    .line 465
    invoke-direct/range {v6 .. v22}, Lh40/m3;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZZLg40/g0;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Lg40/e0;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 466
    .line 467
    .line 468
    return-object v6
.end method
