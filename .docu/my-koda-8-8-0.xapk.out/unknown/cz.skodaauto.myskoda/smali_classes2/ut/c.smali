.class public final Lut/c;
.super Lut/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lst/a;


# instance fields
.field public final b:Lau/r;

.field public final c:Landroid/content/Context;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lut/c;->d:Lst/a;

    .line 6
    .line 7
    return-void
.end method

.method public constructor <init>(Lau/r;Landroid/content/Context;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lut/c;->c:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p1, p0, Lut/c;->b:Lau/r;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 9

    .line 1
    iget-object v0, p0, Lut/c;->b:Lau/r;

    .line 2
    .line 3
    invoke-virtual {v0}, Lau/r;->P()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    move v1, v2

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    :goto_0
    const/4 v3, 0x0

    .line 21
    sget-object v4, Lut/c;->d:Lst/a;

    .line 22
    .line 23
    if-eqz v1, :cond_1

    .line 24
    .line 25
    new-instance p0, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v1, "URL is missing:"

    .line 28
    .line 29
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v0}, Lau/r;->P()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    return v3

    .line 47
    :cond_1
    invoke-virtual {v0}, Lau/r;->P()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    const/4 v5, 0x0

    .line 52
    if-nez v1, :cond_2

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    :try_start_0
    invoke-static {v1}, Ljava/net/URI;->create(Ljava/lang/String;)Ljava/net/URI;

    .line 56
    .line 57
    .line 58
    move-result-object v5
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 59
    goto :goto_1

    .line 60
    :catch_0
    move-exception v1

    .line 61
    invoke-virtual {v1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    const-string v6, "getResultUrl throws exception %s"

    .line 70
    .line 71
    invoke-virtual {v4, v6, v1}, Lst/a;->g(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :goto_1
    if-nez v5, :cond_3

    .line 75
    .line 76
    const-string p0, "URL cannot be parsed"

    .line 77
    .line 78
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    return v3

    .line 82
    :cond_3
    iget-object p0, p0, Lut/c;->c:Landroid/content/Context;

    .line 83
    .line 84
    invoke-virtual {p0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    const-string v6, "array"

    .line 89
    .line 90
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    const-string v7, "firebase_performance_whitelisted_domains"

    .line 95
    .line 96
    invoke-virtual {v1, v7, v6, p0}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 97
    .line 98
    .line 99
    move-result p0

    .line 100
    if-nez p0, :cond_4

    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_4
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 104
    .line 105
    .line 106
    move-result-object v6

    .line 107
    const-string v7, "Detected domain allowlist, only allowlisted domains will be measured."

    .line 108
    .line 109
    invoke-virtual {v6, v7}, Lst/a;->a(Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    sget-object v6, Ljp/l1;->a:[Ljava/lang/String;

    .line 113
    .line 114
    if-nez v6, :cond_5

    .line 115
    .line 116
    invoke-virtual {v1, p0}, Landroid/content/res/Resources;->getStringArray(I)[Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    sput-object p0, Ljp/l1;->a:[Ljava/lang/String;

    .line 121
    .line 122
    :cond_5
    invoke-virtual {v5}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    if-nez p0, :cond_6

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_6
    sget-object v1, Ljp/l1;->a:[Ljava/lang/String;

    .line 130
    .line 131
    array-length v6, v1

    .line 132
    move v7, v3

    .line 133
    :goto_2
    if-ge v7, v6, :cond_20

    .line 134
    .line 135
    aget-object v8, v1, v7

    .line 136
    .line 137
    invoke-virtual {p0, v8}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 138
    .line 139
    .line 140
    move-result v8

    .line 141
    if-eqz v8, :cond_1f

    .line 142
    .line 143
    :goto_3
    invoke-virtual {v5}, Ljava/net/URI;->getHost()Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    if-eqz p0, :cond_1e

    .line 148
    .line 149
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 154
    .line 155
    .line 156
    move-result v1

    .line 157
    if-nez v1, :cond_1e

    .line 158
    .line 159
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 160
    .line 161
    .line 162
    move-result p0

    .line 163
    const/16 v1, 0xff

    .line 164
    .line 165
    if-gt p0, v1, :cond_1e

    .line 166
    .line 167
    invoke-virtual {v5}, Ljava/net/URI;->getScheme()Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    if-nez p0, :cond_7

    .line 172
    .line 173
    goto :goto_4

    .line 174
    :cond_7
    const-string v1, "http"

    .line 175
    .line 176
    invoke-virtual {v1, p0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    if-nez v1, :cond_9

    .line 181
    .line 182
    const-string v1, "https"

    .line 183
    .line 184
    invoke-virtual {v1, p0}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 185
    .line 186
    .line 187
    move-result p0

    .line 188
    if-eqz p0, :cond_8

    .line 189
    .line 190
    goto :goto_5

    .line 191
    :cond_8
    :goto_4
    const-string p0, "URL scheme is null or invalid"

    .line 192
    .line 193
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    return v3

    .line 197
    :cond_9
    :goto_5
    invoke-virtual {v5}, Ljava/net/URI;->getUserInfo()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object p0

    .line 201
    if-nez p0, :cond_1d

    .line 202
    .line 203
    invoke-virtual {v5}, Ljava/net/URI;->getPort()I

    .line 204
    .line 205
    .line 206
    move-result p0

    .line 207
    const/4 v1, -0x1

    .line 208
    if-eq p0, v1, :cond_b

    .line 209
    .line 210
    if-lez p0, :cond_a

    .line 211
    .line 212
    goto :goto_6

    .line 213
    :cond_a
    const-string p0, "URL port is less than or equal to 0"

    .line 214
    .line 215
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    return v3

    .line 219
    :cond_b
    :goto_6
    invoke-virtual {v0}, Lau/r;->R()Z

    .line 220
    .line 221
    .line 222
    move-result p0

    .line 223
    if-eqz p0, :cond_c

    .line 224
    .line 225
    invoke-virtual {v0}, Lau/r;->H()I

    .line 226
    .line 227
    .line 228
    move-result p0

    .line 229
    goto :goto_7

    .line 230
    :cond_c
    move p0, v3

    .line 231
    :goto_7
    if-eqz p0, :cond_1c

    .line 232
    .line 233
    if-eq p0, v2, :cond_1c

    .line 234
    .line 235
    invoke-virtual {v0}, Lau/r;->S()Z

    .line 236
    .line 237
    .line 238
    move-result p0

    .line 239
    if-eqz p0, :cond_e

    .line 240
    .line 241
    invoke-virtual {v0}, Lau/r;->I()I

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    if-lez p0, :cond_d

    .line 246
    .line 247
    goto :goto_8

    .line 248
    :cond_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 249
    .line 250
    const-string v1, "HTTP ResponseCode is a negative value:"

    .line 251
    .line 252
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v0}, Lau/r;->I()I

    .line 256
    .line 257
    .line 258
    move-result v0

    .line 259
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 260
    .line 261
    .line 262
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    return v3

    .line 270
    :cond_e
    :goto_8
    invoke-virtual {v0}, Lau/r;->T()Z

    .line 271
    .line 272
    .line 273
    move-result p0

    .line 274
    const-wide/16 v5, 0x0

    .line 275
    .line 276
    if-eqz p0, :cond_10

    .line 277
    .line 278
    invoke-virtual {v0}, Lau/r;->K()J

    .line 279
    .line 280
    .line 281
    move-result-wide v7

    .line 282
    cmp-long p0, v7, v5

    .line 283
    .line 284
    if-ltz p0, :cond_f

    .line 285
    .line 286
    move p0, v2

    .line 287
    goto :goto_9

    .line 288
    :cond_f
    move p0, v3

    .line 289
    :goto_9
    if-nez p0, :cond_10

    .line 290
    .line 291
    new-instance p0, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    const-string v1, "Request Payload is a negative value:"

    .line 294
    .line 295
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v0}, Lau/r;->K()J

    .line 299
    .line 300
    .line 301
    move-result-wide v0

    .line 302
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    return v3

    .line 313
    :cond_10
    invoke-virtual {v0}, Lau/r;->U()Z

    .line 314
    .line 315
    .line 316
    move-result p0

    .line 317
    if-eqz p0, :cond_12

    .line 318
    .line 319
    invoke-virtual {v0}, Lau/r;->L()J

    .line 320
    .line 321
    .line 322
    move-result-wide v7

    .line 323
    cmp-long p0, v7, v5

    .line 324
    .line 325
    if-ltz p0, :cond_11

    .line 326
    .line 327
    move p0, v2

    .line 328
    goto :goto_a

    .line 329
    :cond_11
    move p0, v3

    .line 330
    :goto_a
    if-nez p0, :cond_12

    .line 331
    .line 332
    new-instance p0, Ljava/lang/StringBuilder;

    .line 333
    .line 334
    const-string v1, "Response Payload is a negative value:"

    .line 335
    .line 336
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {v0}, Lau/r;->L()J

    .line 340
    .line 341
    .line 342
    move-result-wide v0

    .line 343
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 344
    .line 345
    .line 346
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 351
    .line 352
    .line 353
    return v3

    .line 354
    :cond_12
    invoke-virtual {v0}, Lau/r;->Q()Z

    .line 355
    .line 356
    .line 357
    move-result p0

    .line 358
    if-eqz p0, :cond_1b

    .line 359
    .line 360
    invoke-virtual {v0}, Lau/r;->F()J

    .line 361
    .line 362
    .line 363
    move-result-wide v7

    .line 364
    cmp-long p0, v7, v5

    .line 365
    .line 366
    if-gtz p0, :cond_13

    .line 367
    .line 368
    goto/16 :goto_e

    .line 369
    .line 370
    :cond_13
    invoke-virtual {v0}, Lau/r;->V()Z

    .line 371
    .line 372
    .line 373
    move-result p0

    .line 374
    if-eqz p0, :cond_15

    .line 375
    .line 376
    invoke-virtual {v0}, Lau/r;->M()J

    .line 377
    .line 378
    .line 379
    move-result-wide v7

    .line 380
    cmp-long p0, v7, v5

    .line 381
    .line 382
    if-ltz p0, :cond_14

    .line 383
    .line 384
    move p0, v2

    .line 385
    goto :goto_b

    .line 386
    :cond_14
    move p0, v3

    .line 387
    :goto_b
    if-nez p0, :cond_15

    .line 388
    .line 389
    new-instance p0, Ljava/lang/StringBuilder;

    .line 390
    .line 391
    const-string v1, "Time to complete the request is a negative value:"

    .line 392
    .line 393
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    invoke-virtual {v0}, Lau/r;->M()J

    .line 397
    .line 398
    .line 399
    move-result-wide v0

    .line 400
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 401
    .line 402
    .line 403
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 404
    .line 405
    .line 406
    move-result-object p0

    .line 407
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 408
    .line 409
    .line 410
    return v3

    .line 411
    :cond_15
    invoke-virtual {v0}, Lau/r;->X()Z

    .line 412
    .line 413
    .line 414
    move-result p0

    .line 415
    if-eqz p0, :cond_17

    .line 416
    .line 417
    invoke-virtual {v0}, Lau/r;->O()J

    .line 418
    .line 419
    .line 420
    move-result-wide v7

    .line 421
    cmp-long p0, v7, v5

    .line 422
    .line 423
    if-ltz p0, :cond_16

    .line 424
    .line 425
    move p0, v2

    .line 426
    goto :goto_c

    .line 427
    :cond_16
    move p0, v3

    .line 428
    :goto_c
    if-nez p0, :cond_17

    .line 429
    .line 430
    new-instance p0, Ljava/lang/StringBuilder;

    .line 431
    .line 432
    const-string v1, "Time from the start of the request to the start of the response is null or a negative value:"

    .line 433
    .line 434
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 435
    .line 436
    .line 437
    invoke-virtual {v0}, Lau/r;->O()J

    .line 438
    .line 439
    .line 440
    move-result-wide v0

    .line 441
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 442
    .line 443
    .line 444
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 445
    .line 446
    .line 447
    move-result-object p0

    .line 448
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 449
    .line 450
    .line 451
    return v3

    .line 452
    :cond_17
    invoke-virtual {v0}, Lau/r;->W()Z

    .line 453
    .line 454
    .line 455
    move-result p0

    .line 456
    if-eqz p0, :cond_1a

    .line 457
    .line 458
    invoke-virtual {v0}, Lau/r;->N()J

    .line 459
    .line 460
    .line 461
    move-result-wide v7

    .line 462
    cmp-long p0, v7, v5

    .line 463
    .line 464
    if-gtz p0, :cond_18

    .line 465
    .line 466
    goto :goto_d

    .line 467
    :cond_18
    invoke-virtual {v0}, Lau/r;->S()Z

    .line 468
    .line 469
    .line 470
    move-result p0

    .line 471
    if-nez p0, :cond_19

    .line 472
    .line 473
    const-string p0, "Did not receive a HTTP Response Code"

    .line 474
    .line 475
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 476
    .line 477
    .line 478
    return v3

    .line 479
    :cond_19
    return v2

    .line 480
    :cond_1a
    :goto_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 481
    .line 482
    const-string v1, "Time from the start of the request to the end of the response is null, negative or zero:"

    .line 483
    .line 484
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    invoke-virtual {v0}, Lau/r;->N()J

    .line 488
    .line 489
    .line 490
    move-result-wide v0

    .line 491
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 492
    .line 493
    .line 494
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 495
    .line 496
    .line 497
    move-result-object p0

    .line 498
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 499
    .line 500
    .line 501
    return v3

    .line 502
    :cond_1b
    :goto_e
    new-instance p0, Ljava/lang/StringBuilder;

    .line 503
    .line 504
    const-string v1, "Start time of the request is null, or zero, or a negative value:"

    .line 505
    .line 506
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 507
    .line 508
    .line 509
    invoke-virtual {v0}, Lau/r;->F()J

    .line 510
    .line 511
    .line 512
    move-result-wide v0

    .line 513
    invoke-virtual {p0, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 514
    .line 515
    .line 516
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 517
    .line 518
    .line 519
    move-result-object p0

    .line 520
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 521
    .line 522
    .line 523
    return v3

    .line 524
    :cond_1c
    invoke-virtual {v0}, Lau/r;->H()I

    .line 525
    .line 526
    .line 527
    move-result p0

    .line 528
    packed-switch p0, :pswitch_data_0

    .line 529
    .line 530
    .line 531
    const-string p0, "null"

    .line 532
    .line 533
    goto :goto_f

    .line 534
    :pswitch_0
    const-string p0, "CONNECT"

    .line 535
    .line 536
    goto :goto_f

    .line 537
    :pswitch_1
    const-string p0, "TRACE"

    .line 538
    .line 539
    goto :goto_f

    .line 540
    :pswitch_2
    const-string p0, "OPTIONS"

    .line 541
    .line 542
    goto :goto_f

    .line 543
    :pswitch_3
    const-string p0, "PATCH"

    .line 544
    .line 545
    goto :goto_f

    .line 546
    :pswitch_4
    const-string p0, "HEAD"

    .line 547
    .line 548
    goto :goto_f

    .line 549
    :pswitch_5
    const-string p0, "DELETE"

    .line 550
    .line 551
    goto :goto_f

    .line 552
    :pswitch_6
    const-string p0, "POST"

    .line 553
    .line 554
    goto :goto_f

    .line 555
    :pswitch_7
    const-string p0, "PUT"

    .line 556
    .line 557
    goto :goto_f

    .line 558
    :pswitch_8
    const-string p0, "GET"

    .line 559
    .line 560
    goto :goto_f

    .line 561
    :pswitch_9
    const-string p0, "HTTP_METHOD_UNKNOWN"

    .line 562
    .line 563
    :goto_f
    const-string v0, "HTTP Method is null or invalid: "

    .line 564
    .line 565
    invoke-virtual {v0, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 566
    .line 567
    .line 568
    move-result-object p0

    .line 569
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 570
    .line 571
    .line 572
    return v3

    .line 573
    :cond_1d
    const-string p0, "URL user info is null"

    .line 574
    .line 575
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 576
    .line 577
    .line 578
    return v3

    .line 579
    :cond_1e
    const-string p0, "URL host is null or invalid"

    .line 580
    .line 581
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 582
    .line 583
    .line 584
    return v3

    .line 585
    :cond_1f
    add-int/lit8 v7, v7, 0x1

    .line 586
    .line 587
    goto/16 :goto_2

    .line 588
    .line 589
    :cond_20
    new-instance p0, Ljava/lang/StringBuilder;

    .line 590
    .line 591
    const-string v0, "URL fails allowlist rule: "

    .line 592
    .line 593
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {p0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 597
    .line 598
    .line 599
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 600
    .line 601
    .line 602
    move-result-object p0

    .line 603
    invoke-virtual {v4, p0}, Lst/a;->f(Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    return v3

    .line 607
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
