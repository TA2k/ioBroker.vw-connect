.class public abstract Lnu/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/TimeZone;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "UTC"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/TimeZone;->getTimeZone(Ljava/lang/String;)Ljava/util/TimeZone;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lnu/a;->a:Ljava/util/TimeZone;

    .line 8
    .line 9
    return-void
.end method

.method public static a(Ljava/lang/String;IC)Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-ne p0, p2, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x1

    .line 14
    return p0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public static b(Ljava/lang/String;Ljava/text/ParsePosition;)Ljava/util/Date;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {v2}, Ljava/text/ParsePosition;->getIndex()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    add-int/lit8 v3, v0, 0x4

    .line 10
    .line 11
    invoke-static {v0, v3, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 12
    .line 13
    .line 14
    move-result v4

    .line 15
    const/16 v5, 0x2d

    .line 16
    .line 17
    invoke-static {v1, v3, v5}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 18
    .line 19
    .line 20
    move-result v6

    .line 21
    const/4 v7, 0x5

    .line 22
    if-eqz v6, :cond_0

    .line 23
    .line 24
    add-int/lit8 v3, v0, 0x5

    .line 25
    .line 26
    :cond_0
    add-int/lit8 v0, v3, 0x2

    .line 27
    .line 28
    invoke-static {v3, v0, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    invoke-static {v1, v0, v5}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 33
    .line 34
    .line 35
    move-result v8

    .line 36
    if-eqz v8, :cond_1

    .line 37
    .line 38
    add-int/lit8 v0, v3, 0x3

    .line 39
    .line 40
    :cond_1
    add-int/lit8 v3, v0, 0x2

    .line 41
    .line 42
    invoke-static {v0, v3, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 43
    .line 44
    .line 45
    move-result v8

    .line 46
    const/16 v9, 0x54

    .line 47
    .line 48
    invoke-static {v1, v3, v9}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 49
    .line 50
    .line 51
    move-result v9

    .line 52
    const/4 v10, 0x1

    .line 53
    const/4 v11, 0x0

    .line 54
    if-nez v9, :cond_2

    .line 55
    .line 56
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 57
    .line 58
    .line 59
    move-result v12

    .line 60
    if-gt v12, v3, :cond_2

    .line 61
    .line 62
    new-instance v0, Ljava/util/GregorianCalendar;

    .line 63
    .line 64
    sub-int/2addr v6, v10

    .line 65
    invoke-direct {v0, v4, v6, v8}, Ljava/util/GregorianCalendar;-><init>(III)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v11}, Ljava/util/Calendar;->setLenient(Z)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v2, v3}, Ljava/text/ParsePosition;->setIndex(I)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    return-object v0

    .line 79
    :catch_0
    move-exception v0

    .line 80
    goto/16 :goto_9

    .line 81
    .line 82
    :cond_2
    const/16 v12, 0x2b

    .line 83
    .line 84
    const/16 v13, 0x5a

    .line 85
    .line 86
    const/4 v14, 0x2

    .line 87
    if-eqz v9, :cond_d

    .line 88
    .line 89
    add-int/lit8 v3, v0, 0x3

    .line 90
    .line 91
    add-int/lit8 v9, v0, 0x5

    .line 92
    .line 93
    invoke-static {v3, v9, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    const/16 v15, 0x3a

    .line 98
    .line 99
    invoke-static {v1, v9, v15}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 100
    .line 101
    .line 102
    move-result v16

    .line 103
    if-eqz v16, :cond_3

    .line 104
    .line 105
    add-int/lit8 v9, v0, 0x6

    .line 106
    .line 107
    :cond_3
    add-int/lit8 v0, v9, 0x2

    .line 108
    .line 109
    invoke-static {v9, v0, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 110
    .line 111
    .line 112
    move-result v16

    .line 113
    invoke-static {v1, v0, v15}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 114
    .line 115
    .line 116
    move-result v15

    .line 117
    if-eqz v15, :cond_4

    .line 118
    .line 119
    add-int/lit8 v9, v9, 0x3

    .line 120
    .line 121
    move v0, v9

    .line 122
    :cond_4
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 123
    .line 124
    .line 125
    move-result v9

    .line 126
    if-le v9, v0, :cond_c

    .line 127
    .line 128
    invoke-virtual {v1, v0}, Ljava/lang/String;->charAt(I)C

    .line 129
    .line 130
    .line 131
    move-result v9

    .line 132
    if-eq v9, v13, :cond_c

    .line 133
    .line 134
    if-eq v9, v12, :cond_c

    .line 135
    .line 136
    if-eq v9, v5, :cond_c

    .line 137
    .line 138
    add-int/lit8 v9, v0, 0x2

    .line 139
    .line 140
    invoke-static {v0, v9, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 141
    .line 142
    .line 143
    move-result v15

    .line 144
    const/16 v11, 0x3b

    .line 145
    .line 146
    if-le v15, v11, :cond_5

    .line 147
    .line 148
    const/16 v11, 0x3f

    .line 149
    .line 150
    if-ge v15, v11, :cond_5

    .line 151
    .line 152
    const/16 v15, 0x3b

    .line 153
    .line 154
    :cond_5
    const/16 v11, 0x2e

    .line 155
    .line 156
    invoke-static {v1, v9, v11}, Lnu/a;->a(Ljava/lang/String;IC)Z

    .line 157
    .line 158
    .line 159
    move-result v11

    .line 160
    if-eqz v11, :cond_b

    .line 161
    .line 162
    add-int/lit8 v9, v0, 0x3

    .line 163
    .line 164
    add-int/lit8 v11, v0, 0x4

    .line 165
    .line 166
    :goto_0
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    if-ge v11, v7, :cond_8

    .line 171
    .line 172
    invoke-virtual {v1, v11}, Ljava/lang/String;->charAt(I)C

    .line 173
    .line 174
    .line 175
    move-result v7

    .line 176
    const/16 v5, 0x30

    .line 177
    .line 178
    if-lt v7, v5, :cond_7

    .line 179
    .line 180
    const/16 v5, 0x39

    .line 181
    .line 182
    if-le v7, v5, :cond_6

    .line 183
    .line 184
    goto :goto_1

    .line 185
    :cond_6
    add-int/lit8 v11, v11, 0x1

    .line 186
    .line 187
    const/16 v5, 0x2d

    .line 188
    .line 189
    goto :goto_0

    .line 190
    :cond_7
    :goto_1
    move v5, v11

    .line 191
    goto :goto_2

    .line 192
    :cond_8
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 193
    .line 194
    .line 195
    move-result v5

    .line 196
    :goto_2
    add-int/lit8 v0, v0, 0x6

    .line 197
    .line 198
    invoke-static {v5, v0}, Ljava/lang/Math;->min(II)I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    invoke-static {v9, v0, v1}, Lnu/a;->c(IILjava/lang/String;)I

    .line 203
    .line 204
    .line 205
    move-result v7

    .line 206
    sub-int/2addr v0, v9

    .line 207
    if-eq v0, v10, :cond_a

    .line 208
    .line 209
    if-eq v0, v14, :cond_9

    .line 210
    .line 211
    goto :goto_3

    .line 212
    :cond_9
    mul-int/lit8 v7, v7, 0xa

    .line 213
    .line 214
    goto :goto_3

    .line 215
    :cond_a
    mul-int/lit8 v7, v7, 0x64

    .line 216
    .line 217
    :goto_3
    move v0, v3

    .line 218
    move v3, v5

    .line 219
    move/from16 v5, v16

    .line 220
    .line 221
    goto :goto_5

    .line 222
    :cond_b
    move v0, v3

    .line 223
    move v3, v9

    .line 224
    move/from16 v5, v16

    .line 225
    .line 226
    const/4 v7, 0x0

    .line 227
    goto :goto_5

    .line 228
    :cond_c
    move v5, v3

    .line 229
    move v3, v0

    .line 230
    move v0, v5

    .line 231
    move/from16 v5, v16

    .line 232
    .line 233
    :goto_4
    const/4 v7, 0x0

    .line 234
    const/4 v15, 0x0

    .line 235
    goto :goto_5

    .line 236
    :cond_d
    const/4 v0, 0x0

    .line 237
    const/4 v5, 0x0

    .line 238
    goto :goto_4

    .line 239
    :goto_5
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 240
    .line 241
    .line 242
    move-result v9

    .line 243
    if-le v9, v3, :cond_15

    .line 244
    .line 245
    invoke-virtual {v1, v3}, Ljava/lang/String;->charAt(I)C

    .line 246
    .line 247
    .line 248
    move-result v9
    :try_end_0
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 249
    sget-object v11, Lnu/a;->a:Ljava/util/TimeZone;

    .line 250
    .line 251
    if-ne v9, v13, :cond_e

    .line 252
    .line 253
    add-int/2addr v3, v10

    .line 254
    goto/16 :goto_8

    .line 255
    .line 256
    :cond_e
    if-eq v9, v12, :cond_10

    .line 257
    .line 258
    const/16 v12, 0x2d

    .line 259
    .line 260
    if-ne v9, v12, :cond_f

    .line 261
    .line 262
    goto :goto_6

    .line 263
    :cond_f
    :try_start_1
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 264
    .line 265
    new-instance v3, Ljava/lang/StringBuilder;

    .line 266
    .line 267
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 268
    .line 269
    .line 270
    const-string v4, "Invalid time zone indicator \'"

    .line 271
    .line 272
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v3, v9}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    const-string v4, "\'"

    .line 279
    .line 280
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 284
    .line 285
    .line 286
    move-result-object v3

    .line 287
    invoke-direct {v0, v3}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 288
    .line 289
    .line 290
    throw v0

    .line 291
    :cond_10
    :goto_6
    invoke-virtual {v1, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v9

    .line 295
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 296
    .line 297
    .line 298
    move-result v12

    .line 299
    const/4 v13, 0x5

    .line 300
    if-lt v12, v13, :cond_11

    .line 301
    .line 302
    goto :goto_7

    .line 303
    :cond_11
    new-instance v12, Ljava/lang/StringBuilder;

    .line 304
    .line 305
    invoke-direct {v12}, Ljava/lang/StringBuilder;-><init>()V

    .line 306
    .line 307
    .line 308
    invoke-virtual {v12, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 309
    .line 310
    .line 311
    const-string v9, "00"

    .line 312
    .line 313
    invoke-virtual {v12, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 314
    .line 315
    .line 316
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v9

    .line 320
    :goto_7
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 321
    .line 322
    .line 323
    move-result v12

    .line 324
    add-int/2addr v3, v12

    .line 325
    const-string v12, "+0000"

    .line 326
    .line 327
    invoke-virtual {v9, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 328
    .line 329
    .line 330
    move-result v12

    .line 331
    if-nez v12, :cond_14

    .line 332
    .line 333
    const-string v12, "+00:00"

    .line 334
    .line 335
    invoke-virtual {v9, v12}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    move-result v12

    .line 339
    if-eqz v12, :cond_12

    .line 340
    .line 341
    goto :goto_8

    .line 342
    :cond_12
    new-instance v11, Ljava/lang/StringBuilder;

    .line 343
    .line 344
    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    .line 345
    .line 346
    .line 347
    const-string v12, "GMT"

    .line 348
    .line 349
    invoke-virtual {v11, v12}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 350
    .line 351
    .line 352
    invoke-virtual {v11, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 353
    .line 354
    .line 355
    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 356
    .line 357
    .line 358
    move-result-object v9

    .line 359
    invoke-static {v9}, Ljava/util/TimeZone;->getTimeZone(Ljava/lang/String;)Ljava/util/TimeZone;

    .line 360
    .line 361
    .line 362
    move-result-object v11

    .line 363
    invoke-virtual {v11}, Ljava/util/TimeZone;->getID()Ljava/lang/String;

    .line 364
    .line 365
    .line 366
    move-result-object v12

    .line 367
    invoke-virtual {v12, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 368
    .line 369
    .line 370
    move-result v13

    .line 371
    if-nez v13, :cond_14

    .line 372
    .line 373
    const-string v13, ":"

    .line 374
    .line 375
    const-string v14, ""

    .line 376
    .line 377
    invoke-virtual {v12, v13, v14}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v12

    .line 381
    invoke-virtual {v12, v9}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 382
    .line 383
    .line 384
    move-result v12

    .line 385
    if-eqz v12, :cond_13

    .line 386
    .line 387
    goto :goto_8

    .line 388
    :cond_13
    new-instance v0, Ljava/lang/IndexOutOfBoundsException;

    .line 389
    .line 390
    new-instance v3, Ljava/lang/StringBuilder;

    .line 391
    .line 392
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 393
    .line 394
    .line 395
    const-string v4, "Mismatching time zone indicator: "

    .line 396
    .line 397
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 398
    .line 399
    .line 400
    invoke-virtual {v3, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 401
    .line 402
    .line 403
    const-string v4, " given, resolves to "

    .line 404
    .line 405
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 406
    .line 407
    .line 408
    invoke-virtual {v11}, Ljava/util/TimeZone;->getID()Ljava/lang/String;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 413
    .line 414
    .line 415
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 416
    .line 417
    .line 418
    move-result-object v3

    .line 419
    invoke-direct {v0, v3}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    throw v0

    .line 423
    :cond_14
    :goto_8
    new-instance v9, Ljava/util/GregorianCalendar;

    .line 424
    .line 425
    invoke-direct {v9, v11}, Ljava/util/GregorianCalendar;-><init>(Ljava/util/TimeZone;)V

    .line 426
    .line 427
    .line 428
    const/4 v11, 0x0

    .line 429
    invoke-virtual {v9, v11}, Ljava/util/Calendar;->setLenient(Z)V

    .line 430
    .line 431
    .line 432
    invoke-virtual {v9, v10, v4}, Ljava/util/Calendar;->set(II)V

    .line 433
    .line 434
    .line 435
    sub-int/2addr v6, v10

    .line 436
    const/4 v4, 0x2

    .line 437
    invoke-virtual {v9, v4, v6}, Ljava/util/Calendar;->set(II)V

    .line 438
    .line 439
    .line 440
    const/4 v13, 0x5

    .line 441
    invoke-virtual {v9, v13, v8}, Ljava/util/Calendar;->set(II)V

    .line 442
    .line 443
    .line 444
    const/16 v4, 0xb

    .line 445
    .line 446
    invoke-virtual {v9, v4, v0}, Ljava/util/Calendar;->set(II)V

    .line 447
    .line 448
    .line 449
    const/16 v0, 0xc

    .line 450
    .line 451
    invoke-virtual {v9, v0, v5}, Ljava/util/Calendar;->set(II)V

    .line 452
    .line 453
    .line 454
    const/16 v0, 0xd

    .line 455
    .line 456
    invoke-virtual {v9, v0, v15}, Ljava/util/Calendar;->set(II)V

    .line 457
    .line 458
    .line 459
    const/16 v0, 0xe

    .line 460
    .line 461
    invoke-virtual {v9, v0, v7}, Ljava/util/Calendar;->set(II)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {v2, v3}, Ljava/text/ParsePosition;->setIndex(I)V

    .line 465
    .line 466
    .line 467
    invoke-virtual {v9}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    return-object v0

    .line 472
    :cond_15
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 473
    .line 474
    const-string v3, "No time zone indicator"

    .line 475
    .line 476
    invoke-direct {v0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 477
    .line 478
    .line 479
    throw v0
    :try_end_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 480
    :goto_9
    if-nez v1, :cond_16

    .line 481
    .line 482
    const/4 v1, 0x0

    .line 483
    goto :goto_a

    .line 484
    :cond_16
    const-string v3, "\""

    .line 485
    .line 486
    const/16 v4, 0x22

    .line 487
    .line 488
    invoke-static {v4, v3, v1}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 489
    .line 490
    .line 491
    move-result-object v1

    .line 492
    :goto_a
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 493
    .line 494
    .line 495
    move-result-object v3

    .line 496
    if-eqz v3, :cond_17

    .line 497
    .line 498
    invoke-virtual {v3}, Ljava/lang/String;->isEmpty()Z

    .line 499
    .line 500
    .line 501
    move-result v4

    .line 502
    if-eqz v4, :cond_18

    .line 503
    .line 504
    :cond_17
    new-instance v3, Ljava/lang/StringBuilder;

    .line 505
    .line 506
    const-string v4, "("

    .line 507
    .line 508
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 512
    .line 513
    .line 514
    move-result-object v4

    .line 515
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 516
    .line 517
    .line 518
    move-result-object v4

    .line 519
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 520
    .line 521
    .line 522
    const-string v4, ")"

    .line 523
    .line 524
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 525
    .line 526
    .line 527
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 528
    .line 529
    .line 530
    move-result-object v3

    .line 531
    :cond_18
    new-instance v4, Ljava/text/ParseException;

    .line 532
    .line 533
    const-string v5, "Failed to parse date ["

    .line 534
    .line 535
    const-string v6, "]: "

    .line 536
    .line 537
    invoke-static {v5, v1, v6, v3}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 538
    .line 539
    .line 540
    move-result-object v1

    .line 541
    invoke-virtual {v2}, Ljava/text/ParsePosition;->getIndex()I

    .line 542
    .line 543
    .line 544
    move-result v2

    .line 545
    invoke-direct {v4, v1, v2}, Ljava/text/ParseException;-><init>(Ljava/lang/String;I)V

    .line 546
    .line 547
    .line 548
    invoke-virtual {v4, v0}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    .line 549
    .line 550
    .line 551
    throw v4
.end method

.method public static c(IILjava/lang/String;)I
    .locals 5

    .line 1
    if-ltz p0, :cond_4

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-gt p1, v0, :cond_4

    .line 8
    .line 9
    if-gt p0, p1, :cond_4

    .line 10
    .line 11
    const-string v0, "Invalid number: "

    .line 12
    .line 13
    const/16 v1, 0xa

    .line 14
    .line 15
    if-ge p0, p1, :cond_1

    .line 16
    .line 17
    add-int/lit8 v2, p0, 0x1

    .line 18
    .line 19
    invoke-virtual {p2, p0}, Ljava/lang/String;->charAt(I)C

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    invoke-static {v3, v1}, Ljava/lang/Character;->digit(CI)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-ltz v3, :cond_0

    .line 28
    .line 29
    neg-int v3, v3

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 32
    .line 33
    new-instance v2, Ljava/lang/StringBuilder;

    .line 34
    .line 35
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p2, p0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v1, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v1

    .line 53
    :cond_1
    const/4 v3, 0x0

    .line 54
    move v2, p0

    .line 55
    :goto_0
    if-ge v2, p1, :cond_3

    .line 56
    .line 57
    add-int/lit8 v4, v2, 0x1

    .line 58
    .line 59
    invoke-virtual {p2, v2}, Ljava/lang/String;->charAt(I)C

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    invoke-static {v2, v1}, Ljava/lang/Character;->digit(CI)I

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-ltz v2, :cond_2

    .line 68
    .line 69
    mul-int/lit8 v3, v3, 0xa

    .line 70
    .line 71
    sub-int/2addr v3, v2

    .line 72
    move v2, v4

    .line 73
    goto :goto_0

    .line 74
    :cond_2
    new-instance v1, Ljava/lang/NumberFormatException;

    .line 75
    .line 76
    new-instance v2, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {p2, p0, p1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-direct {v1, p0}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    throw v1

    .line 96
    :cond_3
    neg-int p0, v3

    .line 97
    return p0

    .line 98
    :cond_4
    new-instance p0, Ljava/lang/NumberFormatException;

    .line 99
    .line 100
    invoke-direct {p0, p2}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    throw p0
.end method
