.class public abstract Llp/jc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Landroid/content/Context;Lvv0/c;Ljava/lang/String;)Lvv0/b;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-virtual {v0, v2, v3}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 9
    .line 10
    .line 11
    move-result-object v4

    .line 12
    const-string v5, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 13
    .line 14
    invoke-interface {v4, v5, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    const/4 v6, 0x2

    .line 19
    const/4 v7, 0x1

    .line 20
    if-lt v5, v7, :cond_1

    .line 21
    .line 22
    if-lt v5, v6, :cond_0

    .line 23
    .line 24
    const-string v5, "com.wultra.PowerAuthKeychain.EncryptionMode"

    .line 25
    .line 26
    invoke-interface {v4, v5, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eq v5, v7, :cond_1

    .line 31
    .line 32
    :cond_0
    move v5, v7

    .line 33
    goto :goto_0

    .line 34
    :cond_1
    move v5, v3

    .line 35
    :goto_0
    invoke-virtual {v1, v0}, Lvv0/c;->b(Landroid/content/Context;)I

    .line 36
    .line 37
    .line 38
    move-result v8

    .line 39
    if-ne v8, v7, :cond_2

    .line 40
    .line 41
    if-eqz v5, :cond_23

    .line 42
    .line 43
    :cond_2
    invoke-virtual {v1, v0}, Lvv0/c;->c(Landroid/content/Context;)Lvv0/d;

    .line 44
    .line 45
    .line 46
    move-result-object v8

    .line 47
    invoke-virtual {v1, v0}, Lvv0/c;->a(Landroid/content/Context;)Lvv0/d;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    if-eqz v8, :cond_23

    .line 52
    .line 53
    new-instance v9, Lwv0/a;

    .line 54
    .line 55
    invoke-direct {v9, v0, v2, v8, v1}, Lwv0/a;-><init>(Landroid/content/Context;Ljava/lang/String;Lvv0/d;Lvv0/d;)V

    .line 56
    .line 57
    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v11, 0x3

    .line 60
    if-eqz v5, :cond_12

    .line 61
    .line 62
    iget v5, v9, Lwv0/a;->d:I

    .line 63
    .line 64
    const-string v12, "EncryptedKeychain: "

    .line 65
    .line 66
    const-string v13, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 67
    .line 68
    invoke-interface {v4, v13, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 69
    .line 70
    .line 71
    move-result v13

    .line 72
    if-nez v13, :cond_3

    .line 73
    .line 74
    :goto_1
    move v1, v3

    .line 75
    goto/16 :goto_a

    .line 76
    .line 77
    :cond_3
    const-string v14, "com.wultra.PowerAuthKeychain.EncryptionMode"

    .line 78
    .line 79
    invoke-interface {v4, v14, v3}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 80
    .line 81
    .line 82
    move-result v14

    .line 83
    if-ne v13, v6, :cond_4

    .line 84
    .line 85
    if-ne v5, v14, :cond_4

    .line 86
    .line 87
    :goto_2
    move v1, v7

    .line 88
    goto/16 :goto_a

    .line 89
    .line 90
    :cond_4
    if-eq v5, v7, :cond_5

    .line 91
    .line 92
    move v14, v7

    .line 93
    goto :goto_3

    .line 94
    :cond_5
    move v14, v3

    .line 95
    :goto_3
    if-eq v5, v11, :cond_6

    .line 96
    .line 97
    if-eqz v14, :cond_6

    .line 98
    .line 99
    move v11, v7

    .line 100
    goto :goto_4

    .line 101
    :cond_6
    move v11, v3

    .line 102
    :goto_4
    if-ne v5, v6, :cond_7

    .line 103
    .line 104
    move v5, v7

    .line 105
    goto :goto_5

    .line 106
    :cond_7
    move v5, v3

    .line 107
    :goto_5
    if-ne v13, v7, :cond_8

    .line 108
    .line 109
    if-eqz v14, :cond_9

    .line 110
    .line 111
    if-eqz v11, :cond_10

    .line 112
    .line 113
    if-nez v5, :cond_10

    .line 114
    .line 115
    goto :goto_6

    .line 116
    :cond_8
    if-ne v13, v6, :cond_10

    .line 117
    .line 118
    :cond_9
    :goto_6
    if-eqz v14, :cond_d

    .line 119
    .line 120
    if-eqz v1, :cond_c

    .line 121
    .line 122
    if-eqz v5, :cond_a

    .line 123
    .line 124
    invoke-virtual {v1}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    invoke-virtual {v8}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    goto :goto_7

    .line 133
    :cond_a
    invoke-virtual {v8}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 134
    .line 135
    .line 136
    move-result-object v5

    .line 137
    invoke-virtual {v1}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    move-object/from16 v21, v5

    .line 142
    .line 143
    move-object v5, v1

    .line 144
    move-object/from16 v1, v21

    .line 145
    .line 146
    :goto_7
    if-eqz v1, :cond_b

    .line 147
    .line 148
    if-eqz v5, :cond_b

    .line 149
    .line 150
    invoke-virtual {v9, v4, v1, v5}, Lwv0/a;->e(Landroid/content/SharedPreferences;Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    goto :goto_9

    .line 155
    :cond_b
    const-string v1, ": Unable to get source or destination encryption key."

    .line 156
    .line 157
    invoke-static {v12, v2, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    new-array v5, v3, [Ljava/lang/Object;

    .line 162
    .line 163
    invoke-static {v1, v5}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 164
    .line 165
    .line 166
    goto :goto_8

    .line 167
    :cond_c
    const-string v1, ": Internal error: Backup provider is not set."

    .line 168
    .line 169
    invoke-static {v12, v2, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    new-array v5, v3, [Ljava/lang/Object;

    .line 174
    .line 175
    invoke-static {v1, v5}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 176
    .line 177
    .line 178
    :goto_8
    move v1, v3

    .line 179
    goto :goto_9

    .line 180
    :cond_d
    invoke-virtual {v8}, Lvv0/d;->g()Ljavax/crypto/SecretKey;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    if-eqz v1, :cond_e

    .line 185
    .line 186
    invoke-virtual {v9, v4, v1, v10}, Lwv0/a;->e(Landroid/content/SharedPreferences;Ljavax/crypto/SecretKey;Ljavax/crypto/SecretKey;)Z

    .line 187
    .line 188
    .line 189
    move-result v1

    .line 190
    if-eqz v1, :cond_f

    .line 191
    .line 192
    goto :goto_1

    .line 193
    :cond_e
    const-string v1, ": Unable to get source encryption key."

    .line 194
    .line 195
    invoke-static {v12, v2, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object v1

    .line 199
    new-array v5, v3, [Ljava/lang/Object;

    .line 200
    .line 201
    invoke-static {v1, v5}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    goto :goto_8

    .line 205
    :cond_f
    :goto_9
    if-nez v1, :cond_11

    .line 206
    .line 207
    const-string v5, ": Data migration failed. Removing all remaining content."

    .line 208
    .line 209
    invoke-static {v12, v2, v5}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v5

    .line 213
    new-array v8, v3, [Ljava/lang/Object;

    .line 214
    .line 215
    invoke-static {v5, v8}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    invoke-interface {v4}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    invoke-interface {v5}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    .line 223
    .line 224
    .line 225
    move-result-object v5

    .line 226
    invoke-interface {v5}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 227
    .line 228
    .line 229
    goto :goto_a

    .line 230
    :cond_10
    invoke-interface {v4}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 231
    .line 232
    .line 233
    move-result-object v1

    .line 234
    invoke-virtual {v9, v1}, Lwv0/a;->d(Landroid/content/SharedPreferences$Editor;)V

    .line 235
    .line 236
    .line 237
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 238
    .line 239
    .line 240
    goto/16 :goto_2

    .line 241
    .line 242
    :cond_11
    :goto_a
    if-eqz v1, :cond_23

    .line 243
    .line 244
    goto/16 :goto_16

    .line 245
    .line 246
    :cond_12
    const-string v1, "EncryptedKeychain: "

    .line 247
    .line 248
    invoke-virtual {v9}, Lwv0/a;->c()Ljavax/crypto/SecretKey;

    .line 249
    .line 250
    .line 251
    move-result-object v5

    .line 252
    if-nez v5, :cond_13

    .line 253
    .line 254
    move v6, v3

    .line 255
    goto/16 :goto_15

    .line 256
    .line 257
    :cond_13
    new-instance v8, Ljava/util/HashMap;

    .line 258
    .line 259
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 260
    .line 261
    .line 262
    new-instance v12, Ljava/util/HashSet;

    .line 263
    .line 264
    invoke-direct {v12}, Ljava/util/HashSet;-><init>()V

    .line 265
    .line 266
    .line 267
    invoke-interface {v4}, Landroid/content/SharedPreferences;->getAll()Ljava/util/Map;

    .line 268
    .line 269
    .line 270
    move-result-object v13

    .line 271
    invoke-interface {v13}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 272
    .line 273
    .line 274
    move-result-object v13

    .line 275
    invoke-interface {v13}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 276
    .line 277
    .line 278
    move-result-object v13

    .line 279
    :goto_b
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 280
    .line 281
    .line 282
    move-result v14

    .line 283
    if-eqz v14, :cond_20

    .line 284
    .line 285
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v14

    .line 289
    check-cast v14, Ljava/util/Map$Entry;

    .line 290
    .line 291
    invoke-interface {v14}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v15

    .line 295
    check-cast v15, Ljava/lang/String;

    .line 296
    .line 297
    invoke-static {v15}, Llp/rd;->c(Ljava/lang/String;)Z

    .line 298
    .line 299
    .line 300
    move-result v16

    .line 301
    if-eqz v16, :cond_14

    .line 302
    .line 303
    goto :goto_b

    .line 304
    :cond_14
    invoke-interface {v14}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    move-result-object v14

    .line 308
    instance-of v10, v14, Ljava/lang/String;

    .line 309
    .line 310
    if-eqz v10, :cond_18

    .line 311
    .line 312
    check-cast v14, Ljava/lang/String;

    .line 313
    .line 314
    invoke-virtual {v14}, Ljava/lang/String;->isEmpty()Z

    .line 315
    .line 316
    .line 317
    move-result v10

    .line 318
    if-eqz v10, :cond_15

    .line 319
    .line 320
    invoke-virtual {v12, v15}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    :goto_c
    const/4 v10, 0x0

    .line 324
    goto :goto_b

    .line 325
    :cond_15
    :try_start_0
    invoke-static {v14, v3}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 326
    .line 327
    .line 328
    move-result-object v10

    .line 329
    invoke-static {v10, v3}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v16
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_2

    .line 333
    move/from16 v17, v11

    .line 334
    .line 335
    :try_start_1
    invoke-virtual/range {v16 .. v16}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 336
    .line 337
    .line 338
    move-result-object v11
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 339
    move/from16 v16, v6

    .line 340
    .line 341
    :try_start_2
    invoke-virtual {v14}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 342
    .line 343
    .line 344
    move-result-object v6

    .line 345
    invoke-virtual {v11, v6}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 346
    .line 347
    .line 348
    move-result v6
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_0

    .line 349
    if-eqz v6, :cond_16

    .line 350
    .line 351
    goto :goto_e

    .line 352
    :catch_0
    :cond_16
    :goto_d
    const/4 v10, 0x0

    .line 353
    goto :goto_e

    .line 354
    :catch_1
    move/from16 v16, v6

    .line 355
    .line 356
    goto :goto_d

    .line 357
    :catch_2
    move/from16 v16, v6

    .line 358
    .line 359
    move/from16 v17, v11

    .line 360
    .line 361
    goto :goto_d

    .line 362
    :goto_e
    if-eqz v10, :cond_17

    .line 363
    .line 364
    array-length v6, v10

    .line 365
    add-int/2addr v6, v7

    .line 366
    new-array v6, v6, [B

    .line 367
    .line 368
    aput-byte v7, v6, v3

    .line 369
    .line 370
    array-length v11, v10

    .line 371
    invoke-static {v10, v3, v6, v7, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 372
    .line 373
    .line 374
    goto/16 :goto_11

    .line 375
    .line 376
    :cond_17
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 377
    .line 378
    .line 379
    move-result-object v6

    .line 380
    invoke-virtual {v14, v6}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 381
    .line 382
    .line 383
    move-result-object v6

    .line 384
    array-length v10, v6

    .line 385
    add-int/2addr v10, v7

    .line 386
    new-array v10, v10, [B

    .line 387
    .line 388
    aput-byte v16, v10, v3

    .line 389
    .line 390
    array-length v11, v6

    .line 391
    invoke-static {v6, v3, v10, v7, v11}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 392
    .line 393
    .line 394
    move-object v6, v10

    .line 395
    goto/16 :goto_11

    .line 396
    .line 397
    :cond_18
    move/from16 v16, v6

    .line 398
    .line 399
    move/from16 v17, v11

    .line 400
    .line 401
    instance-of v6, v14, Ljava/lang/Boolean;

    .line 402
    .line 403
    if-eqz v6, :cond_19

    .line 404
    .line 405
    check-cast v14, Ljava/lang/Boolean;

    .line 406
    .line 407
    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    .line 408
    .line 409
    .line 410
    move-result v6

    .line 411
    move/from16 v10, v16

    .line 412
    .line 413
    new-array v11, v10, [B

    .line 414
    .line 415
    aput-byte v17, v11, v3

    .line 416
    .line 417
    aput-byte v6, v11, v7

    .line 418
    .line 419
    move-object v6, v11

    .line 420
    goto/16 :goto_11

    .line 421
    .line 422
    :cond_19
    instance-of v6, v14, Ljava/lang/Long;

    .line 423
    .line 424
    if-eqz v6, :cond_1a

    .line 425
    .line 426
    check-cast v14, Ljava/lang/Long;

    .line 427
    .line 428
    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    .line 429
    .line 430
    .line 431
    move-result-wide v10

    .line 432
    const/16 v6, 0x9

    .line 433
    .line 434
    invoke-static {v6}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 435
    .line 436
    .line 437
    move-result-object v6

    .line 438
    const/4 v14, 0x4

    .line 439
    invoke-virtual {v6, v14}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 440
    .line 441
    .line 442
    invoke-virtual {v6, v10, v11}, Ljava/nio/ByteBuffer;->putLong(J)Ljava/nio/ByteBuffer;

    .line 443
    .line 444
    .line 445
    invoke-virtual {v6}, Ljava/nio/ByteBuffer;->array()[B

    .line 446
    .line 447
    .line 448
    move-result-object v6

    .line 449
    goto/16 :goto_11

    .line 450
    .line 451
    :cond_1a
    instance-of v6, v14, Ljava/lang/Float;

    .line 452
    .line 453
    const/4 v10, 0x5

    .line 454
    if-eqz v6, :cond_1b

    .line 455
    .line 456
    check-cast v14, Ljava/lang/Float;

    .line 457
    .line 458
    invoke-virtual {v14}, Ljava/lang/Float;->floatValue()F

    .line 459
    .line 460
    .line 461
    move-result v6

    .line 462
    invoke-static {v10}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 463
    .line 464
    .line 465
    move-result-object v11

    .line 466
    invoke-virtual {v11, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 467
    .line 468
    .line 469
    invoke-virtual {v11, v6}, Ljava/nio/ByteBuffer;->putFloat(F)Ljava/nio/ByteBuffer;

    .line 470
    .line 471
    .line 472
    invoke-virtual {v11}, Ljava/nio/ByteBuffer;->array()[B

    .line 473
    .line 474
    .line 475
    move-result-object v6

    .line 476
    goto :goto_11

    .line 477
    :cond_1b
    instance-of v6, v14, Ljava/util/Set;

    .line 478
    .line 479
    if-eqz v6, :cond_1f

    .line 480
    .line 481
    check-cast v14, Ljava/util/Set;

    .line 482
    .line 483
    invoke-interface {v14}, Ljava/util/Set;->size()I

    .line 484
    .line 485
    .line 486
    move-result v6

    .line 487
    new-instance v11, Ljava/util/ArrayList;

    .line 488
    .line 489
    invoke-direct {v11, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 490
    .line 491
    .line 492
    invoke-interface {v14}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 493
    .line 494
    .line 495
    move-result-object v14

    .line 496
    move/from16 v18, v3

    .line 497
    .line 498
    :goto_f
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 499
    .line 500
    .line 501
    move-result v19

    .line 502
    if-eqz v19, :cond_1c

    .line 503
    .line 504
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v19

    .line 508
    move/from16 v20, v10

    .line 509
    .line 510
    move-object/from16 v10, v19

    .line 511
    .line 512
    check-cast v10, Ljava/lang/String;

    .line 513
    .line 514
    invoke-static {}, Ljava/nio/charset/Charset;->defaultCharset()Ljava/nio/charset/Charset;

    .line 515
    .line 516
    .line 517
    move-result-object v7

    .line 518
    invoke-virtual {v10, v7}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 519
    .line 520
    .line 521
    move-result-object v7

    .line 522
    invoke-virtual {v11, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 523
    .line 524
    .line 525
    array-length v7, v7

    .line 526
    add-int v18, v18, v7

    .line 527
    .line 528
    move/from16 v10, v20

    .line 529
    .line 530
    const/4 v7, 0x1

    .line 531
    goto :goto_f

    .line 532
    :cond_1c
    move/from16 v20, v10

    .line 533
    .line 534
    mul-int/lit8 v7, v6, 0x4

    .line 535
    .line 536
    add-int/lit8 v7, v7, 0x5

    .line 537
    .line 538
    add-int v7, v7, v18

    .line 539
    .line 540
    invoke-static {v7}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 541
    .line 542
    .line 543
    move-result-object v7

    .line 544
    const/4 v10, 0x6

    .line 545
    invoke-virtual {v7, v10}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 546
    .line 547
    .line 548
    invoke-virtual {v7, v6}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 549
    .line 550
    .line 551
    move v10, v3

    .line 552
    :goto_10
    if-ge v10, v6, :cond_1d

    .line 553
    .line 554
    invoke-virtual {v11, v10}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 555
    .line 556
    .line 557
    move-result-object v14

    .line 558
    check-cast v14, [B

    .line 559
    .line 560
    array-length v3, v14

    .line 561
    invoke-virtual {v7, v3}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 562
    .line 563
    .line 564
    invoke-virtual {v7, v14}, Ljava/nio/ByteBuffer;->put([B)Ljava/nio/ByteBuffer;

    .line 565
    .line 566
    .line 567
    add-int/lit8 v10, v10, 0x1

    .line 568
    .line 569
    const/4 v3, 0x0

    .line 570
    goto :goto_10

    .line 571
    :cond_1d
    invoke-virtual {v7}, Ljava/nio/ByteBuffer;->array()[B

    .line 572
    .line 573
    .line 574
    move-result-object v6

    .line 575
    :goto_11
    invoke-static {v6, v5, v2}, Llp/qd;->b([BLjavax/crypto/SecretKey;Ljava/lang/String;)[B

    .line 576
    .line 577
    .line 578
    move-result-object v3

    .line 579
    if-nez v3, :cond_1e

    .line 580
    .line 581
    const-string v3, ": Failed to import value from key: "

    .line 582
    .line 583
    invoke-static {v1, v2, v3, v15}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 584
    .line 585
    .line 586
    move-result-object v1

    .line 587
    const/4 v6, 0x0

    .line 588
    new-array v3, v6, [Ljava/lang/Object;

    .line 589
    .line 590
    invoke-static {v1, v3}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 591
    .line 592
    .line 593
    goto :goto_15

    .line 594
    :cond_1e
    const/4 v6, 0x0

    .line 595
    const/4 v10, 0x2

    .line 596
    invoke-static {v3, v10}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 597
    .line 598
    .line 599
    move-result-object v3

    .line 600
    invoke-virtual {v8, v15, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    :goto_12
    move v3, v6

    .line 604
    move/from16 v11, v17

    .line 605
    .line 606
    const/4 v6, 0x2

    .line 607
    const/4 v7, 0x1

    .line 608
    goto/16 :goto_c

    .line 609
    .line 610
    :cond_1f
    move v6, v3

    .line 611
    const-string v3, ": Removing unsupported value from key: "

    .line 612
    .line 613
    invoke-static {v1, v2, v3, v15}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 614
    .line 615
    .line 616
    move-result-object v3

    .line 617
    new-array v7, v6, [Ljava/lang/Object;

    .line 618
    .line 619
    invoke-static {v3, v7}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 620
    .line 621
    .line 622
    invoke-virtual {v12, v15}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 623
    .line 624
    .line 625
    goto :goto_12

    .line 626
    :cond_20
    move v6, v3

    .line 627
    iget-object v1, v9, Lwv0/a;->b:Landroid/content/Context;

    .line 628
    .line 629
    iget-object v3, v9, Lwv0/a;->a:Ljava/lang/String;

    .line 630
    .line 631
    invoke-virtual {v1, v3, v6}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 632
    .line 633
    .line 634
    move-result-object v1

    .line 635
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 636
    .line 637
    .line 638
    move-result-object v1

    .line 639
    invoke-virtual {v8}, Ljava/util/HashMap;->entrySet()Ljava/util/Set;

    .line 640
    .line 641
    .line 642
    move-result-object v3

    .line 643
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 644
    .line 645
    .line 646
    move-result-object v3

    .line 647
    :goto_13
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 648
    .line 649
    .line 650
    move-result v5

    .line 651
    if-eqz v5, :cond_21

    .line 652
    .line 653
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    move-result-object v5

    .line 657
    check-cast v5, Ljava/util/Map$Entry;

    .line 658
    .line 659
    invoke-interface {v5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 660
    .line 661
    .line 662
    move-result-object v6

    .line 663
    check-cast v6, Ljava/lang/String;

    .line 664
    .line 665
    invoke-interface {v5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 666
    .line 667
    .line 668
    move-result-object v5

    .line 669
    check-cast v5, Ljava/lang/String;

    .line 670
    .line 671
    invoke-interface {v1, v6, v5}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 672
    .line 673
    .line 674
    goto :goto_13

    .line 675
    :cond_21
    invoke-virtual {v12}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 676
    .line 677
    .line 678
    move-result-object v3

    .line 679
    :goto_14
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 680
    .line 681
    .line 682
    move-result v5

    .line 683
    if-eqz v5, :cond_22

    .line 684
    .line 685
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 686
    .line 687
    .line 688
    move-result-object v5

    .line 689
    check-cast v5, Ljava/lang/String;

    .line 690
    .line 691
    invoke-interface {v1, v5}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 692
    .line 693
    .line 694
    goto :goto_14

    .line 695
    :cond_22
    invoke-virtual {v9, v1}, Lwv0/a;->d(Landroid/content/SharedPreferences$Editor;)V

    .line 696
    .line 697
    .line 698
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 699
    .line 700
    .line 701
    const/4 v6, 0x1

    .line 702
    :goto_15
    if-eqz v6, :cond_23

    .line 703
    .line 704
    :goto_16
    return-object v9

    .line 705
    :cond_23
    new-instance v1, Lwv0/b;

    .line 706
    .line 707
    invoke-direct {v1, v0, v2}, Lwv0/b;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 708
    .line 709
    .line 710
    const-string v3, "com.wultra.PowerAuthKeychain.IsEncrypted"

    .line 711
    .line 712
    const/4 v6, 0x0

    .line 713
    invoke-interface {v4, v3, v6}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 714
    .line 715
    .line 716
    move-result v3

    .line 717
    const/4 v5, 0x1

    .line 718
    if-lt v3, v5, :cond_25

    .line 719
    .line 720
    const/4 v10, 0x2

    .line 721
    if-lt v3, v10, :cond_24

    .line 722
    .line 723
    const-string v3, "com.wultra.PowerAuthKeychain.EncryptionMode"

    .line 724
    .line 725
    invoke-interface {v4, v3, v6}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    .line 726
    .line 727
    .line 728
    move-result v3

    .line 729
    if-eq v3, v5, :cond_25

    .line 730
    .line 731
    :cond_24
    move v7, v5

    .line 732
    goto :goto_17

    .line 733
    :cond_25
    move v7, v6

    .line 734
    :goto_17
    if-eqz v7, :cond_26

    .line 735
    .line 736
    const-string v3, "KeychainFactory: "

    .line 737
    .line 738
    const-string v4, ": The content was previously encrypted but the encryption is no longer available."

    .line 739
    .line 740
    invoke-static {v3, v2, v4}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 741
    .line 742
    .line 743
    move-result-object v3

    .line 744
    new-array v4, v6, [Ljava/lang/Object;

    .line 745
    .line 746
    invoke-static {v3, v4}, Llp/gf;->b(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 747
    .line 748
    .line 749
    monitor-enter v1

    .line 750
    :try_start_3
    invoke-virtual {v0, v2, v6}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 751
    .line 752
    .line 753
    move-result-object v0

    .line 754
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 755
    .line 756
    .line 757
    move-result-object v0

    .line 758
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    .line 759
    .line 760
    .line 761
    move-result-object v0

    .line 762
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 763
    .line 764
    .line 765
    monitor-exit v1

    .line 766
    goto :goto_18

    .line 767
    :catchall_0
    move-exception v0

    .line 768
    :try_start_4
    monitor-exit v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 769
    throw v0

    .line 770
    :cond_26
    :goto_18
    return-object v1
.end method

.method public static varargs b(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 10

    .line 1
    const/4 v1, 0x0

    .line 2
    move v2, v1

    .line 3
    :goto_0
    array-length v0, p1

    .line 4
    if-ge v2, v0, :cond_1

    .line 5
    .line 6
    aget-object v3, p1, v2

    .line 7
    .line 8
    if-nez v3, :cond_0

    .line 9
    .line 10
    const-string v0, "null"

    .line 11
    .line 12
    goto :goto_1

    .line 13
    :cond_0
    :try_start_0
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    goto :goto_1

    .line 18
    :catch_0
    move-exception v0

    .line 19
    move-object v8, v0

    .line 20
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-static {v3}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    invoke-static {v3}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    const-string v4, "@"

    .line 37
    .line 38
    invoke-static {v0, v4, v3}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    const-string v3, "com.google.common.base.Strings"

    .line 43
    .line 44
    invoke-static {v3}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    sget-object v4, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    .line 49
    .line 50
    const-string v6, "lenientToString"

    .line 51
    .line 52
    const-string v5, "Exception during lenientFormat for "

    .line 53
    .line 54
    invoke-virtual {v5, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    const-string v5, "com.google.common.base.Strings"

    .line 59
    .line 60
    invoke-virtual/range {v3 .. v8}, Ljava/util/logging/Logger;->logp(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    const-string v4, " threw "

    .line 72
    .line 73
    const-string v5, ">"

    .line 74
    .line 75
    const-string v6, "<"

    .line 76
    .line 77
    invoke-static {v6, v0, v4, v3, v5}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    :goto_1
    aput-object v0, p1, v2

    .line 82
    .line 83
    add-int/lit8 v2, v2, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    mul-int/lit8 v0, v0, 0x10

    .line 91
    .line 92
    new-instance v3, Ljava/lang/StringBuilder;

    .line 93
    .line 94
    add-int/2addr v2, v0

    .line 95
    invoke-direct {v3, v2}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 96
    .line 97
    .line 98
    move v0, v1

    .line 99
    :goto_2
    array-length v2, p1

    .line 100
    if-ge v1, v2, :cond_3

    .line 101
    .line 102
    const-string v4, "%s"

    .line 103
    .line 104
    invoke-virtual {p0, v4, v0}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    .line 105
    .line 106
    .line 107
    move-result v4

    .line 108
    const/4 v5, -0x1

    .line 109
    if-ne v4, v5, :cond_2

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_2
    invoke-virtual {v3, p0, v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    add-int/lit8 v0, v1, 0x1

    .line 116
    .line 117
    aget-object v1, p1, v1

    .line 118
    .line 119
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    add-int/lit8 v1, v4, 0x2

    .line 123
    .line 124
    move v9, v1

    .line 125
    move v1, v0

    .line 126
    move v0, v9

    .line 127
    goto :goto_2

    .line 128
    :cond_3
    :goto_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 129
    .line 130
    .line 131
    move-result v4

    .line 132
    invoke-virtual {v3, p0, v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    if-ge v1, v2, :cond_5

    .line 136
    .line 137
    const-string p0, " ["

    .line 138
    .line 139
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    add-int/lit8 p0, v1, 0x1

    .line 143
    .line 144
    aget-object v0, p1, v1

    .line 145
    .line 146
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 147
    .line 148
    .line 149
    :goto_4
    array-length v0, p1

    .line 150
    if-ge p0, v0, :cond_4

    .line 151
    .line 152
    const-string v0, ", "

    .line 153
    .line 154
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    add-int/lit8 v0, p0, 0x1

    .line 158
    .line 159
    aget-object p0, p1, p0

    .line 160
    .line 161
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 162
    .line 163
    .line 164
    move p0, v0

    .line 165
    goto :goto_4

    .line 166
    :cond_4
    const/16 p0, 0x5d

    .line 167
    .line 168
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 169
    .line 170
    .line 171
    :cond_5
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0
.end method
