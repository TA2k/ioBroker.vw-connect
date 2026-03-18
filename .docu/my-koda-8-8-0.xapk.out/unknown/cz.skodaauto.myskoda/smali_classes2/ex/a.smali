.class public final Lex/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljavax/net/ssl/X509TrustManager;


# instance fields
.field public final a:Ldx/i;


# direct methods
.method public constructor <init>(Ldx/i;)V
    .locals 1

    .line 1
    const-string v0, "certStore"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lex/a;->a:Ldx/i;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0

    .line 1
    const-string p0, "chain"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "authType"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    const-string v1, "chain"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v1, "authType"

    .line 9
    .line 10
    move-object/from16 v2, p2

    .line 11
    .line 12
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    move-object/from16 v1, p0

    .line 16
    .line 17
    iget-object v1, v1, Lex/a;->a:Ldx/i;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    aget-object v0, v0, v2

    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    const-string v3, "certificate"

    .line 26
    .line 27
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/security/cert/Certificate;->getEncoded()[B

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    const-string v4, "key"

    .line 35
    .line 36
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v3}, Lio/getlime/security/powerauth/core/CryptoUtils;->hashSha256([B)[B

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    const-string v4, "hashSha256(data)"

    .line 44
    .line 45
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v4, "Malformed DN: "

    .line 49
    .line 50
    const-string v5, "Unexpected end of DN: "

    .line 51
    .line 52
    new-instance v6, Lix/a;

    .line 53
    .line 54
    invoke-virtual {v0}, Ljava/security/cert/X509Certificate;->getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    invoke-direct {v6, v0}, Lix/a;-><init>(Ljavax/security/auth/x500/X500Principal;)V

    .line 59
    .line 60
    .line 61
    const-string v0, "CN"

    .line 62
    .line 63
    iget v7, v6, Lix/a;->b:I

    .line 64
    .line 65
    iput v2, v6, Lix/a;->c:I

    .line 66
    .line 67
    iput v2, v6, Lix/a;->d:I

    .line 68
    .line 69
    iput v2, v6, Lix/a;->e:I

    .line 70
    .line 71
    iput v2, v6, Lix/a;->f:I

    .line 72
    .line 73
    iget-object v8, v6, Lix/a;->a:Ljava/lang/String;

    .line 74
    .line 75
    invoke-virtual {v8}, Ljava/lang/String;->toCharArray()[C

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    iput-object v9, v6, Lix/a;->g:[C

    .line 80
    .line 81
    invoke-virtual {v6}, Lix/a;->c()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v9

    .line 85
    if-nez v9, :cond_0

    .line 86
    .line 87
    :goto_0
    const/4 v10, 0x0

    .line 88
    goto/16 :goto_e

    .line 89
    .line 90
    :cond_0
    :goto_1
    const-string v11, ""

    .line 91
    .line 92
    iget v12, v6, Lix/a;->c:I

    .line 93
    .line 94
    if-ne v12, v7, :cond_1

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_1
    iget-object v13, v6, Lix/a;->g:[C

    .line 98
    .line 99
    aget-char v13, v13, v12

    .line 100
    .line 101
    const/16 v15, 0x22

    .line 102
    .line 103
    const/16 v10, 0x3b

    .line 104
    .line 105
    const/16 v14, 0x2c

    .line 106
    .line 107
    const/16 v2, 0x2b

    .line 108
    .line 109
    if-eq v13, v15, :cond_12

    .line 110
    .line 111
    const/16 v15, 0x23

    .line 112
    .line 113
    if-eq v13, v15, :cond_9

    .line 114
    .line 115
    if-eq v13, v2, :cond_14

    .line 116
    .line 117
    if-eq v13, v14, :cond_14

    .line 118
    .line 119
    if-eq v13, v10, :cond_14

    .line 120
    .line 121
    iput v12, v6, Lix/a;->d:I

    .line 122
    .line 123
    iput v12, v6, Lix/a;->e:I

    .line 124
    .line 125
    :goto_2
    iget v11, v6, Lix/a;->c:I

    .line 126
    .line 127
    if-lt v11, v7, :cond_2

    .line 128
    .line 129
    new-instance v11, Ljava/lang/String;

    .line 130
    .line 131
    iget-object v12, v6, Lix/a;->g:[C

    .line 132
    .line 133
    iget v13, v6, Lix/a;->d:I

    .line 134
    .line 135
    iget v15, v6, Lix/a;->e:I

    .line 136
    .line 137
    sub-int/2addr v15, v13

    .line 138
    invoke-direct {v11, v12, v13, v15}, Ljava/lang/String;-><init>([CII)V

    .line 139
    .line 140
    .line 141
    goto/16 :goto_d

    .line 142
    .line 143
    :cond_2
    iget-object v12, v6, Lix/a;->g:[C

    .line 144
    .line 145
    aget-char v13, v12, v11

    .line 146
    .line 147
    const/16 v15, 0x20

    .line 148
    .line 149
    if-eq v13, v15, :cond_5

    .line 150
    .line 151
    if-eq v13, v10, :cond_4

    .line 152
    .line 153
    const/16 v15, 0x5c

    .line 154
    .line 155
    if-eq v13, v15, :cond_3

    .line 156
    .line 157
    if-eq v13, v2, :cond_4

    .line 158
    .line 159
    if-eq v13, v14, :cond_4

    .line 160
    .line 161
    iget v15, v6, Lix/a;->e:I

    .line 162
    .line 163
    add-int/lit8 v10, v15, 0x1

    .line 164
    .line 165
    iput v10, v6, Lix/a;->e:I

    .line 166
    .line 167
    aput-char v13, v12, v15

    .line 168
    .line 169
    add-int/lit8 v11, v11, 0x1

    .line 170
    .line 171
    iput v11, v6, Lix/a;->c:I

    .line 172
    .line 173
    :goto_3
    const/16 v10, 0x3b

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_3
    iget v10, v6, Lix/a;->e:I

    .line 177
    .line 178
    add-int/lit8 v11, v10, 0x1

    .line 179
    .line 180
    iput v11, v6, Lix/a;->e:I

    .line 181
    .line 182
    invoke-virtual {v6}, Lix/a;->b()C

    .line 183
    .line 184
    .line 185
    move-result v11

    .line 186
    aput-char v11, v12, v10

    .line 187
    .line 188
    iget v10, v6, Lix/a;->c:I

    .line 189
    .line 190
    add-int/lit8 v10, v10, 0x1

    .line 191
    .line 192
    iput v10, v6, Lix/a;->c:I

    .line 193
    .line 194
    goto :goto_3

    .line 195
    :cond_4
    new-instance v10, Ljava/lang/String;

    .line 196
    .line 197
    iget v11, v6, Lix/a;->d:I

    .line 198
    .line 199
    iget v13, v6, Lix/a;->e:I

    .line 200
    .line 201
    sub-int/2addr v13, v11

    .line 202
    invoke-direct {v10, v12, v11, v13}, Ljava/lang/String;-><init>([CII)V

    .line 203
    .line 204
    .line 205
    :goto_4
    move-object v11, v10

    .line 206
    goto/16 :goto_d

    .line 207
    .line 208
    :cond_5
    iget v10, v6, Lix/a;->e:I

    .line 209
    .line 210
    iput v10, v6, Lix/a;->f:I

    .line 211
    .line 212
    add-int/lit8 v11, v11, 0x1

    .line 213
    .line 214
    iput v11, v6, Lix/a;->c:I

    .line 215
    .line 216
    add-int/lit8 v11, v10, 0x1

    .line 217
    .line 218
    iput v11, v6, Lix/a;->e:I

    .line 219
    .line 220
    const/16 v15, 0x20

    .line 221
    .line 222
    aput-char v15, v12, v10

    .line 223
    .line 224
    :goto_5
    iget v10, v6, Lix/a;->c:I

    .line 225
    .line 226
    if-ge v10, v7, :cond_6

    .line 227
    .line 228
    iget-object v11, v6, Lix/a;->g:[C

    .line 229
    .line 230
    aget-char v12, v11, v10

    .line 231
    .line 232
    if-ne v12, v15, :cond_6

    .line 233
    .line 234
    iget v12, v6, Lix/a;->e:I

    .line 235
    .line 236
    add-int/lit8 v13, v12, 0x1

    .line 237
    .line 238
    iput v13, v6, Lix/a;->e:I

    .line 239
    .line 240
    aput-char v15, v11, v12

    .line 241
    .line 242
    add-int/lit8 v10, v10, 0x1

    .line 243
    .line 244
    iput v10, v6, Lix/a;->c:I

    .line 245
    .line 246
    const/16 v15, 0x20

    .line 247
    .line 248
    goto :goto_5

    .line 249
    :cond_6
    if-eq v10, v7, :cond_8

    .line 250
    .line 251
    iget-object v11, v6, Lix/a;->g:[C

    .line 252
    .line 253
    aget-char v10, v11, v10

    .line 254
    .line 255
    if-eq v10, v14, :cond_8

    .line 256
    .line 257
    if-eq v10, v2, :cond_8

    .line 258
    .line 259
    const/16 v11, 0x3b

    .line 260
    .line 261
    if-ne v10, v11, :cond_7

    .line 262
    .line 263
    goto :goto_6

    .line 264
    :cond_7
    move v10, v11

    .line 265
    goto/16 :goto_2

    .line 266
    .line 267
    :cond_8
    :goto_6
    new-instance v10, Ljava/lang/String;

    .line 268
    .line 269
    iget-object v11, v6, Lix/a;->g:[C

    .line 270
    .line 271
    iget v12, v6, Lix/a;->d:I

    .line 272
    .line 273
    iget v13, v6, Lix/a;->f:I

    .line 274
    .line 275
    sub-int/2addr v13, v12

    .line 276
    invoke-direct {v10, v11, v12, v13}, Ljava/lang/String;-><init>([CII)V

    .line 277
    .line 278
    .line 279
    goto :goto_4

    .line 280
    :cond_9
    add-int/lit8 v10, v12, 0x4

    .line 281
    .line 282
    if-ge v10, v7, :cond_11

    .line 283
    .line 284
    iput v12, v6, Lix/a;->d:I

    .line 285
    .line 286
    add-int/lit8 v12, v12, 0x1

    .line 287
    .line 288
    iput v12, v6, Lix/a;->c:I

    .line 289
    .line 290
    :goto_7
    iget v10, v6, Lix/a;->c:I

    .line 291
    .line 292
    if-eq v10, v7, :cond_d

    .line 293
    .line 294
    iget-object v11, v6, Lix/a;->g:[C

    .line 295
    .line 296
    aget-char v12, v11, v10

    .line 297
    .line 298
    if-eq v12, v2, :cond_d

    .line 299
    .line 300
    if-eq v12, v14, :cond_d

    .line 301
    .line 302
    const/16 v13, 0x3b

    .line 303
    .line 304
    if-ne v12, v13, :cond_a

    .line 305
    .line 306
    goto :goto_9

    .line 307
    :cond_a
    const/16 v15, 0x20

    .line 308
    .line 309
    if-ne v12, v15, :cond_b

    .line 310
    .line 311
    iput v10, v6, Lix/a;->e:I

    .line 312
    .line 313
    add-int/lit8 v10, v10, 0x1

    .line 314
    .line 315
    iput v10, v6, Lix/a;->c:I

    .line 316
    .line 317
    :goto_8
    iget v10, v6, Lix/a;->c:I

    .line 318
    .line 319
    if-ge v10, v7, :cond_e

    .line 320
    .line 321
    iget-object v11, v6, Lix/a;->g:[C

    .line 322
    .line 323
    aget-char v11, v11, v10

    .line 324
    .line 325
    if-ne v11, v15, :cond_e

    .line 326
    .line 327
    add-int/lit8 v10, v10, 0x1

    .line 328
    .line 329
    iput v10, v6, Lix/a;->c:I

    .line 330
    .line 331
    const/16 v15, 0x20

    .line 332
    .line 333
    goto :goto_8

    .line 334
    :cond_b
    const/16 v13, 0x41

    .line 335
    .line 336
    if-lt v12, v13, :cond_c

    .line 337
    .line 338
    const/16 v13, 0x46

    .line 339
    .line 340
    if-gt v12, v13, :cond_c

    .line 341
    .line 342
    add-int/lit8 v12, v12, 0x20

    .line 343
    .line 344
    int-to-char v12, v12

    .line 345
    aput-char v12, v11, v10

    .line 346
    .line 347
    :cond_c
    add-int/lit8 v10, v10, 0x1

    .line 348
    .line 349
    iput v10, v6, Lix/a;->c:I

    .line 350
    .line 351
    goto :goto_7

    .line 352
    :cond_d
    :goto_9
    iput v10, v6, Lix/a;->e:I

    .line 353
    .line 354
    :cond_e
    iget v10, v6, Lix/a;->e:I

    .line 355
    .line 356
    iget v11, v6, Lix/a;->d:I

    .line 357
    .line 358
    sub-int/2addr v10, v11

    .line 359
    const/4 v12, 0x5

    .line 360
    if-lt v10, v12, :cond_10

    .line 361
    .line 362
    and-int/lit8 v12, v10, 0x1

    .line 363
    .line 364
    if-eqz v12, :cond_10

    .line 365
    .line 366
    div-int/lit8 v12, v10, 0x2

    .line 367
    .line 368
    new-array v13, v12, [B

    .line 369
    .line 370
    add-int/lit8 v11, v11, 0x1

    .line 371
    .line 372
    const/4 v15, 0x0

    .line 373
    :goto_a
    if-ge v15, v12, :cond_f

    .line 374
    .line 375
    invoke-virtual {v6, v11}, Lix/a;->a(I)I

    .line 376
    .line 377
    .line 378
    move-result v2

    .line 379
    int-to-byte v2, v2

    .line 380
    aput-byte v2, v13, v15

    .line 381
    .line 382
    add-int/lit8 v11, v11, 0x2

    .line 383
    .line 384
    add-int/lit8 v15, v15, 0x1

    .line 385
    .line 386
    const/16 v2, 0x2b

    .line 387
    .line 388
    goto :goto_a

    .line 389
    :cond_f
    new-instance v11, Ljava/lang/String;

    .line 390
    .line 391
    iget-object v2, v6, Lix/a;->g:[C

    .line 392
    .line 393
    iget v12, v6, Lix/a;->d:I

    .line 394
    .line 395
    invoke-direct {v11, v2, v12, v10}, Ljava/lang/String;-><init>([CII)V

    .line 396
    .line 397
    .line 398
    goto :goto_d

    .line 399
    :cond_10
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 400
    .line 401
    invoke-virtual {v5, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 402
    .line 403
    .line 404
    move-result-object v1

    .line 405
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 406
    .line 407
    .line 408
    throw v0

    .line 409
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 410
    .line 411
    invoke-virtual {v5, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 412
    .line 413
    .line 414
    move-result-object v1

    .line 415
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 416
    .line 417
    .line 418
    throw v0

    .line 419
    :cond_12
    add-int/lit8 v12, v12, 0x1

    .line 420
    .line 421
    iput v12, v6, Lix/a;->c:I

    .line 422
    .line 423
    iput v12, v6, Lix/a;->d:I

    .line 424
    .line 425
    iput v12, v6, Lix/a;->e:I

    .line 426
    .line 427
    :goto_b
    iget v2, v6, Lix/a;->c:I

    .line 428
    .line 429
    if-eq v2, v7, :cond_24

    .line 430
    .line 431
    iget-object v10, v6, Lix/a;->g:[C

    .line 432
    .line 433
    aget-char v11, v10, v2

    .line 434
    .line 435
    if-ne v11, v15, :cond_22

    .line 436
    .line 437
    add-int/lit8 v2, v2, 0x1

    .line 438
    .line 439
    iput v2, v6, Lix/a;->c:I

    .line 440
    .line 441
    :goto_c
    iget v2, v6, Lix/a;->c:I

    .line 442
    .line 443
    if-ge v2, v7, :cond_13

    .line 444
    .line 445
    iget-object v10, v6, Lix/a;->g:[C

    .line 446
    .line 447
    aget-char v10, v10, v2

    .line 448
    .line 449
    const/16 v12, 0x20

    .line 450
    .line 451
    if-ne v10, v12, :cond_13

    .line 452
    .line 453
    add-int/lit8 v2, v2, 0x1

    .line 454
    .line 455
    iput v2, v6, Lix/a;->c:I

    .line 456
    .line 457
    goto :goto_c

    .line 458
    :cond_13
    new-instance v11, Ljava/lang/String;

    .line 459
    .line 460
    iget-object v2, v6, Lix/a;->g:[C

    .line 461
    .line 462
    iget v10, v6, Lix/a;->d:I

    .line 463
    .line 464
    iget v12, v6, Lix/a;->e:I

    .line 465
    .line 466
    sub-int/2addr v12, v10

    .line 467
    invoke-direct {v11, v2, v10, v12}, Ljava/lang/String;-><init>([CII)V

    .line 468
    .line 469
    .line 470
    :cond_14
    :goto_d
    invoke-virtual {v0, v9}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 471
    .line 472
    .line 473
    move-result v2

    .line 474
    if-eqz v2, :cond_15

    .line 475
    .line 476
    move-object v10, v11

    .line 477
    goto :goto_e

    .line 478
    :cond_15
    iget v2, v6, Lix/a;->c:I

    .line 479
    .line 480
    if-lt v2, v7, :cond_1d

    .line 481
    .line 482
    goto/16 :goto_0

    .line 483
    .line 484
    :goto_e
    const-string v0, "dnParser.findMostSpecific(\"CN\")"

    .line 485
    .line 486
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 487
    .line 488
    .line 489
    monitor-enter v1

    .line 490
    :try_start_0
    invoke-virtual {v1}, Ldx/i;->b()V

    .line 491
    .line 492
    .line 493
    iget-object v0, v1, Ldx/i;->f:Lcom/wultra/android/sslpinning/model/CachedData;

    .line 494
    .line 495
    if-eqz v0, :cond_16

    .line 496
    .line 497
    invoke-virtual {v0}, Lcom/wultra/android/sslpinning/model/CachedData;->getCertificates()[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 498
    .line 499
    .line 500
    move-result-object v0

    .line 501
    iget-object v2, v1, Ldx/i;->g:[Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 502
    .line 503
    invoke-static {v0, v2}, Lmx0/n;->O([Ljava/lang/Object;[Ljava/lang/Object;)[Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    check-cast v0, [Lcom/wultra/android/sslpinning/model/CertificateInfo;

    .line 508
    .line 509
    goto :goto_f

    .line 510
    :catchall_0
    move-exception v0

    .line 511
    goto :goto_13

    .line 512
    :cond_16
    iget-object v0, v1, Ldx/i;->g:[Lcom/wultra/android/sslpinning/model/CertificateInfo;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 513
    .line 514
    :goto_f
    monitor-exit v1

    .line 515
    array-length v2, v0

    .line 516
    if-eqz v2, :cond_1c

    .line 517
    .line 518
    new-instance v2, Ljava/util/Date;

    .line 519
    .line 520
    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    .line 521
    .line 522
    .line 523
    array-length v4, v0

    .line 524
    const/4 v5, 0x0

    .line 525
    const/4 v6, 0x0

    .line 526
    :goto_10
    if-ge v5, v4, :cond_1a

    .line 527
    .line 528
    aget-object v7, v0, v5

    .line 529
    .line 530
    invoke-virtual {v7, v2}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->isExpired$library_release(Ljava/util/Date;)Z

    .line 531
    .line 532
    .line 533
    move-result v8

    .line 534
    if-eqz v8, :cond_17

    .line 535
    .line 536
    goto :goto_11

    .line 537
    :cond_17
    invoke-virtual {v7}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->getCommonName()Ljava/lang/String;

    .line 538
    .line 539
    .line 540
    move-result-object v8

    .line 541
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 542
    .line 543
    .line 544
    move-result v8

    .line 545
    if-eqz v8, :cond_19

    .line 546
    .line 547
    invoke-virtual {v7}, Lcom/wultra/android/sslpinning/model/CertificateInfo;->getFingerprint()[B

    .line 548
    .line 549
    .line 550
    move-result-object v7

    .line 551
    invoke-static {v7, v3}, Ljava/util/Arrays;->equals([B[B)Z

    .line 552
    .line 553
    .line 554
    move-result v7

    .line 555
    if-eqz v7, :cond_18

    .line 556
    .line 557
    sget-object v0, Ldx/f;->d:Ldx/f;

    .line 558
    .line 559
    invoke-virtual {v1, v0, v10}, Ldx/i;->a(Lay0/n;Ljava/lang/String;)V

    .line 560
    .line 561
    .line 562
    return-void

    .line 563
    :cond_18
    add-int/lit8 v6, v6, 0x1

    .line 564
    .line 565
    :cond_19
    :goto_11
    add-int/lit8 v5, v5, 0x1

    .line 566
    .line 567
    goto :goto_10

    .line 568
    :cond_1a
    if-lez v6, :cond_1b

    .line 569
    .line 570
    sget-object v0, Ldx/g;->d:Ldx/g;

    .line 571
    .line 572
    invoke-virtual {v1, v0, v10}, Ldx/i;->a(Lay0/n;Ljava/lang/String;)V

    .line 573
    .line 574
    .line 575
    goto :goto_12

    .line 576
    :cond_1b
    sget-object v0, Ldx/h;->d:Ldx/h;

    .line 577
    .line 578
    invoke-virtual {v1, v0, v10}, Ldx/i;->a(Lay0/n;Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    goto :goto_12

    .line 582
    :cond_1c
    sget-object v0, Ldx/e;->d:Ldx/e;

    .line 583
    .line 584
    invoke-virtual {v1, v0, v10}, Ldx/i;->a(Lay0/n;Ljava/lang/String;)V

    .line 585
    .line 586
    .line 587
    :goto_12
    new-instance v0, Ljava/security/cert/CertificateException;

    .line 588
    .line 589
    const-string v1, "WultraSSLpinning doesn\'t trust the server certificate"

    .line 590
    .line 591
    invoke-direct {v0, v1}, Ljava/security/cert/CertificateException;-><init>(Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    throw v0

    .line 595
    :goto_13
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 596
    throw v0

    .line 597
    :cond_1d
    iget-object v9, v6, Lix/a;->g:[C

    .line 598
    .line 599
    aget-char v9, v9, v2

    .line 600
    .line 601
    if-eq v9, v14, :cond_20

    .line 602
    .line 603
    const/16 v13, 0x3b

    .line 604
    .line 605
    if-ne v9, v13, :cond_1e

    .line 606
    .line 607
    goto :goto_14

    .line 608
    :cond_1e
    const/16 v10, 0x2b

    .line 609
    .line 610
    if-ne v9, v10, :cond_1f

    .line 611
    .line 612
    goto :goto_14

    .line 613
    :cond_1f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 614
    .line 615
    invoke-virtual {v4, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 616
    .line 617
    .line 618
    move-result-object v1

    .line 619
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 620
    .line 621
    .line 622
    throw v0

    .line 623
    :cond_20
    :goto_14
    add-int/lit8 v2, v2, 0x1

    .line 624
    .line 625
    iput v2, v6, Lix/a;->c:I

    .line 626
    .line 627
    invoke-virtual {v6}, Lix/a;->c()Ljava/lang/String;

    .line 628
    .line 629
    .line 630
    move-result-object v9

    .line 631
    if-eqz v9, :cond_21

    .line 632
    .line 633
    const/4 v2, 0x0

    .line 634
    goto/16 :goto_1

    .line 635
    .line 636
    :cond_21
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 637
    .line 638
    invoke-virtual {v4, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 639
    .line 640
    .line 641
    move-result-object v1

    .line 642
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 643
    .line 644
    .line 645
    throw v0

    .line 646
    :cond_22
    const/16 v2, 0x5c

    .line 647
    .line 648
    const/16 v12, 0x20

    .line 649
    .line 650
    const/16 v13, 0x3b

    .line 651
    .line 652
    const/16 v17, 0x2b

    .line 653
    .line 654
    if-ne v11, v2, :cond_23

    .line 655
    .line 656
    iget v11, v6, Lix/a;->e:I

    .line 657
    .line 658
    invoke-virtual {v6}, Lix/a;->b()C

    .line 659
    .line 660
    .line 661
    move-result v16

    .line 662
    aput-char v16, v10, v11

    .line 663
    .line 664
    goto :goto_15

    .line 665
    :cond_23
    iget v2, v6, Lix/a;->e:I

    .line 666
    .line 667
    aput-char v11, v10, v2

    .line 668
    .line 669
    :goto_15
    iget v2, v6, Lix/a;->c:I

    .line 670
    .line 671
    add-int/lit8 v2, v2, 0x1

    .line 672
    .line 673
    iput v2, v6, Lix/a;->c:I

    .line 674
    .line 675
    iget v2, v6, Lix/a;->e:I

    .line 676
    .line 677
    add-int/lit8 v2, v2, 0x1

    .line 678
    .line 679
    iput v2, v6, Lix/a;->e:I

    .line 680
    .line 681
    goto/16 :goto_b

    .line 682
    .line 683
    :cond_24
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 684
    .line 685
    invoke-virtual {v5, v8}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 686
    .line 687
    .line 688
    move-result-object v1

    .line 689
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 690
    .line 691
    .line 692
    throw v0
.end method

.method public final getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    new-array p0, p0, [Ljava/security/cert/X509Certificate;

    .line 3
    .line 4
    return-object p0
.end method
