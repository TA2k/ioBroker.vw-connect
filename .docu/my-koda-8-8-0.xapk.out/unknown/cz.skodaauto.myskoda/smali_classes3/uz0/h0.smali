.class public final Luz0/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Luz0/h0;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Luz0/h0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luz0/h0;->a:Luz0/h0;

    .line 7
    .line 8
    new-instance v0, Luz0/h1;

    .line 9
    .line 10
    const-string v1, "kotlin.time.Instant"

    .line 11
    .line 12
    sget-object v2, Lsz0/e;->j:Lsz0/e;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2}, Luz0/h1;-><init>(Ljava/lang/String;Lsz0/f;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Luz0/h0;->b:Luz0/h1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 23

    .line 1
    sget-object v0, Lmy0/f;->f:Lmy0/f;

    .line 2
    .line 3
    invoke-interface/range {p1 .. p1}, Ltz0/c;->x()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "input"

    .line 8
    .line 9
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    new-instance v1, Lc2/k;

    .line 19
    .line 20
    const-string v2, "An empty string is not a valid Instant"

    .line 21
    .line 22
    invoke-direct {v1, v2, v0}, Lc2/k;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    goto/16 :goto_16

    .line 26
    .line 27
    :cond_0
    const/4 v1, 0x0

    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    const/16 v3, 0x20

    .line 33
    .line 34
    const/16 v4, 0x2b

    .line 35
    .line 36
    const/16 v5, 0x2d

    .line 37
    .line 38
    const/4 v6, 0x1

    .line 39
    if-eq v2, v4, :cond_1

    .line 40
    .line 41
    if-eq v2, v5, :cond_1

    .line 42
    .line 43
    move v7, v1

    .line 44
    move v2, v3

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    move v7, v6

    .line 47
    :goto_0
    move v9, v1

    .line 48
    move v8, v7

    .line 49
    :goto_1
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 50
    .line 51
    .line 52
    move-result v10

    .line 53
    const/16 v11, 0x3a

    .line 54
    .line 55
    const/16 v12, 0x30

    .line 56
    .line 57
    if-ge v8, v10, :cond_2

    .line 58
    .line 59
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 60
    .line 61
    .line 62
    move-result v10

    .line 63
    if-gt v12, v10, :cond_2

    .line 64
    .line 65
    if-ge v10, v11, :cond_2

    .line 66
    .line 67
    mul-int/lit8 v9, v9, 0xa

    .line 68
    .line 69
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 70
    .line 71
    .line 72
    move-result v10

    .line 73
    sub-int/2addr v10, v12

    .line 74
    add-int/2addr v9, v10

    .line 75
    add-int/lit8 v8, v8, 0x1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    sub-int v10, v8, v7

    .line 79
    .line 80
    const-string v13, " digits"

    .line 81
    .line 82
    const/16 v14, 0xa

    .line 83
    .line 84
    if-le v10, v14, :cond_3

    .line 85
    .line 86
    new-instance v1, Ljava/lang/StringBuilder;

    .line 87
    .line 88
    const-string v2, "Expected at most 10 digits for the year number, got "

    .line 89
    .line 90
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v1

    .line 103
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    goto/16 :goto_16

    .line 108
    .line 109
    :cond_3
    if-ne v10, v14, :cond_4

    .line 110
    .line 111
    invoke-virtual {v0, v7}, Ljava/lang/String;->charAt(I)C

    .line 112
    .line 113
    .line 114
    move-result v7

    .line 115
    const/16 v15, 0x32

    .line 116
    .line 117
    invoke-static {v7, v15}, Lkotlin/jvm/internal/m;->g(II)I

    .line 118
    .line 119
    .line 120
    move-result v7

    .line 121
    if-ltz v7, :cond_4

    .line 122
    .line 123
    new-instance v1, Ljava/lang/StringBuilder;

    .line 124
    .line 125
    const-string v2, "Expected at most 9 digits for the year number or year 1000000000, got "

    .line 126
    .line 127
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    goto/16 :goto_16

    .line 145
    .line 146
    :cond_4
    const/4 v7, 0x4

    .line 147
    if-ge v10, v7, :cond_5

    .line 148
    .line 149
    new-instance v1, Ljava/lang/StringBuilder;

    .line 150
    .line 151
    const-string v2, "The year number must be padded to 4 digits, got "

    .line 152
    .line 153
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 160
    .line 161
    .line 162
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    goto/16 :goto_16

    .line 171
    .line 172
    :cond_5
    if-ne v2, v4, :cond_6

    .line 173
    .line 174
    if-ne v10, v7, :cond_6

    .line 175
    .line 176
    const-string v1, "The \'+\' sign at the start is only valid for year numbers longer than 4 digits"

    .line 177
    .line 178
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    goto/16 :goto_16

    .line 183
    .line 184
    :cond_6
    if-ne v2, v3, :cond_7

    .line 185
    .line 186
    if-eq v10, v7, :cond_7

    .line 187
    .line 188
    const-string v1, "A \'+\' or \'-\' sign is required for year numbers longer than 4 digits"

    .line 189
    .line 190
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    goto/16 :goto_16

    .line 195
    .line 196
    :cond_7
    if-ne v2, v5, :cond_8

    .line 197
    .line 198
    neg-int v9, v9

    .line 199
    :cond_8
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    add-int/lit8 v3, v8, 0x10

    .line 204
    .line 205
    if-ge v2, v3, :cond_9

    .line 206
    .line 207
    const-string v1, "The input string is too short"

    .line 208
    .line 209
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    goto/16 :goto_16

    .line 214
    .line 215
    :cond_9
    new-instance v2, Lmj/g;

    .line 216
    .line 217
    const/4 v10, 0x7

    .line 218
    invoke-direct {v2, v10}, Lmj/g;-><init>(I)V

    .line 219
    .line 220
    .line 221
    const-string v10, "\'-\'"

    .line 222
    .line 223
    invoke-static {v0, v10, v8, v2}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    if-eqz v2, :cond_a

    .line 228
    .line 229
    :goto_2
    move-object v1, v2

    .line 230
    goto/16 :goto_16

    .line 231
    .line 232
    :cond_a
    add-int/lit8 v2, v8, 0x3

    .line 233
    .line 234
    new-instance v15, Lmj/g;

    .line 235
    .line 236
    const/16 v1, 0x8

    .line 237
    .line 238
    invoke-direct {v15, v1}, Lmj/g;-><init>(I)V

    .line 239
    .line 240
    .line 241
    invoke-static {v0, v10, v2, v15}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    if-eqz v1, :cond_b

    .line 246
    .line 247
    goto/16 :goto_16

    .line 248
    .line 249
    :cond_b
    add-int/lit8 v1, v8, 0x6

    .line 250
    .line 251
    new-instance v2, Lmj/g;

    .line 252
    .line 253
    const/16 v10, 0x9

    .line 254
    .line 255
    invoke-direct {v2, v10}, Lmj/g;-><init>(I)V

    .line 256
    .line 257
    .line 258
    const-string v15, "\'T\' or \'t\'"

    .line 259
    .line 260
    invoke-static {v0, v15, v1, v2}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 261
    .line 262
    .line 263
    move-result-object v1

    .line 264
    if-eqz v1, :cond_c

    .line 265
    .line 266
    goto/16 :goto_16

    .line 267
    .line 268
    :cond_c
    add-int/lit8 v1, v8, 0x9

    .line 269
    .line 270
    new-instance v2, Lmj/g;

    .line 271
    .line 272
    invoke-direct {v2, v14}, Lmj/g;-><init>(I)V

    .line 273
    .line 274
    .line 275
    const-string v15, "\':\'"

    .line 276
    .line 277
    invoke-static {v0, v15, v1, v2}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 278
    .line 279
    .line 280
    move-result-object v1

    .line 281
    if-eqz v1, :cond_d

    .line 282
    .line 283
    goto/16 :goto_16

    .line 284
    .line 285
    :cond_d
    add-int/lit8 v1, v8, 0xc

    .line 286
    .line 287
    new-instance v2, Lmj/g;

    .line 288
    .line 289
    const/16 v7, 0xb

    .line 290
    .line 291
    invoke-direct {v2, v7}, Lmj/g;-><init>(I)V

    .line 292
    .line 293
    .line 294
    invoke-static {v0, v15, v1, v2}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    if-eqz v1, :cond_e

    .line 299
    .line 300
    goto/16 :goto_16

    .line 301
    .line 302
    :cond_e
    const/4 v1, 0x0

    .line 303
    :goto_3
    const/16 v2, 0xc

    .line 304
    .line 305
    if-ge v1, v14, :cond_10

    .line 306
    .line 307
    sget-object v15, Lmy0/h;->b:[I

    .line 308
    .line 309
    aget v15, v15, v1

    .line 310
    .line 311
    add-int/2addr v15, v8

    .line 312
    new-instance v7, Lmj/g;

    .line 313
    .line 314
    invoke-direct {v7, v2}, Lmj/g;-><init>(I)V

    .line 315
    .line 316
    .line 317
    const-string v2, "an ASCII digit"

    .line 318
    .line 319
    invoke-static {v0, v2, v15, v7}, Lmy0/h;->l(Ljava/lang/String;Ljava/lang/String;ILay0/k;)Lc2/k;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    if-eqz v2, :cond_f

    .line 324
    .line 325
    goto :goto_2

    .line 326
    :cond_f
    add-int/lit8 v1, v1, 0x1

    .line 327
    .line 328
    const/16 v7, 0xb

    .line 329
    .line 330
    goto :goto_3

    .line 331
    :cond_10
    add-int/lit8 v1, v8, 0x1

    .line 332
    .line 333
    invoke-static {v1, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 334
    .line 335
    .line 336
    move-result v1

    .line 337
    add-int/lit8 v7, v8, 0x4

    .line 338
    .line 339
    invoke-static {v7, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 340
    .line 341
    .line 342
    move-result v7

    .line 343
    add-int/lit8 v15, v8, 0x7

    .line 344
    .line 345
    invoke-static {v15, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 346
    .line 347
    .line 348
    move-result v15

    .line 349
    move/from16 v17, v2

    .line 350
    .line 351
    add-int/lit8 v2, v8, 0xa

    .line 352
    .line 353
    invoke-static {v2, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 354
    .line 355
    .line 356
    move-result v2

    .line 357
    move/from16 v18, v10

    .line 358
    .line 359
    add-int/lit8 v10, v8, 0xd

    .line 360
    .line 361
    invoke-static {v10, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 362
    .line 363
    .line 364
    move-result v10

    .line 365
    add-int/lit8 v8, v8, 0xf

    .line 366
    .line 367
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 368
    .line 369
    .line 370
    move-result v5

    .line 371
    const/16 v4, 0x2e

    .line 372
    .line 373
    if-ne v5, v4, :cond_13

    .line 374
    .line 375
    move v8, v3

    .line 376
    const/4 v4, 0x0

    .line 377
    :goto_4
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 378
    .line 379
    .line 380
    move-result v5

    .line 381
    if-ge v8, v5, :cond_11

    .line 382
    .line 383
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 384
    .line 385
    .line 386
    move-result v5

    .line 387
    if-gt v12, v5, :cond_11

    .line 388
    .line 389
    if-ge v5, v11, :cond_11

    .line 390
    .line 391
    mul-int/lit8 v4, v4, 0xa

    .line 392
    .line 393
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 394
    .line 395
    .line 396
    move-result v5

    .line 397
    sub-int/2addr v5, v12

    .line 398
    add-int/2addr v4, v5

    .line 399
    add-int/lit8 v8, v8, 0x1

    .line 400
    .line 401
    goto :goto_4

    .line 402
    :cond_11
    sub-int v3, v8, v3

    .line 403
    .line 404
    if-gt v6, v3, :cond_12

    .line 405
    .line 406
    if-ge v3, v14, :cond_12

    .line 407
    .line 408
    sget-object v5, Lmy0/h;->a:[I

    .line 409
    .line 410
    rsub-int/lit8 v3, v3, 0x9

    .line 411
    .line 412
    aget v3, v5, v3

    .line 413
    .line 414
    mul-int/2addr v4, v3

    .line 415
    goto :goto_5

    .line 416
    :cond_12
    new-instance v1, Ljava/lang/StringBuilder;

    .line 417
    .line 418
    const-string v2, "1..9 digits are supported for the fraction of the second, got "

    .line 419
    .line 420
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 424
    .line 425
    .line 426
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 427
    .line 428
    .line 429
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v1

    .line 433
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    goto/16 :goto_16

    .line 438
    .line 439
    :cond_13
    const/4 v4, 0x0

    .line 440
    :goto_5
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 441
    .line 442
    .line 443
    move-result v3

    .line 444
    if-lt v8, v3, :cond_14

    .line 445
    .line 446
    const-string v1, "The UTC offset at the end of the string is missing"

    .line 447
    .line 448
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 449
    .line 450
    .line 451
    move-result-object v1

    .line 452
    goto/16 :goto_16

    .line 453
    .line 454
    :cond_14
    invoke-virtual {v0, v8}, Ljava/lang/String;->charAt(I)C

    .line 455
    .line 456
    .line 457
    move-result v3

    .line 458
    const/4 v5, 0x2

    .line 459
    const/16 v13, 0x27

    .line 460
    .line 461
    const-string v14, ", got \'"

    .line 462
    .line 463
    move/from16 v20, v6

    .line 464
    .line 465
    const/16 v12, 0x2b

    .line 466
    .line 467
    if-eq v3, v12, :cond_17

    .line 468
    .line 469
    const/16 v12, 0x2d

    .line 470
    .line 471
    if-eq v3, v12, :cond_17

    .line 472
    .line 473
    const/16 v11, 0x5a

    .line 474
    .line 475
    if-eq v3, v11, :cond_15

    .line 476
    .line 477
    const/16 v11, 0x7a

    .line 478
    .line 479
    if-eq v3, v11, :cond_15

    .line 480
    .line 481
    new-instance v1, Ljava/lang/StringBuilder;

    .line 482
    .line 483
    const-string v2, "Expected the UTC offset at position "

    .line 484
    .line 485
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 486
    .line 487
    .line 488
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 489
    .line 490
    .line 491
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 492
    .line 493
    .line 494
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 495
    .line 496
    .line 497
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 498
    .line 499
    .line 500
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 505
    .line 506
    .line 507
    move-result-object v1

    .line 508
    goto/16 :goto_16

    .line 509
    .line 510
    :cond_15
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 511
    .line 512
    .line 513
    move-result v3

    .line 514
    add-int/lit8 v8, v8, 0x1

    .line 515
    .line 516
    if-ne v3, v8, :cond_16

    .line 517
    .line 518
    const/4 v6, 0x0

    .line 519
    :goto_6
    move/from16 v3, v20

    .line 520
    .line 521
    goto/16 :goto_10

    .line 522
    .line 523
    :cond_16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 524
    .line 525
    const-string v2, "Extra text after the instant at position "

    .line 526
    .line 527
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 528
    .line 529
    .line 530
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 531
    .line 532
    .line 533
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 534
    .line 535
    .line 536
    move-result-object v1

    .line 537
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 538
    .line 539
    .line 540
    move-result-object v1

    .line 541
    goto/16 :goto_16

    .line 542
    .line 543
    :cond_17
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 544
    .line 545
    .line 546
    move-result v12

    .line 547
    sub-int/2addr v12, v8

    .line 548
    move/from16 v6, v18

    .line 549
    .line 550
    if-le v12, v6, :cond_18

    .line 551
    .line 552
    new-instance v1, Ljava/lang/StringBuilder;

    .line 553
    .line 554
    const-string v2, "The UTC offset string \""

    .line 555
    .line 556
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 557
    .line 558
    .line 559
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 560
    .line 561
    .line 562
    move-result v2

    .line 563
    invoke-virtual {v0, v8, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 564
    .line 565
    .line 566
    move-result-object v2

    .line 567
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 568
    .line 569
    .line 570
    move-result-object v2

    .line 571
    const/16 v3, 0x10

    .line 572
    .line 573
    invoke-static {v3, v2}, Lmy0/h;->u(ILjava/lang/String;)Ljava/lang/String;

    .line 574
    .line 575
    .line 576
    move-result-object v2

    .line 577
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 578
    .line 579
    .line 580
    const-string v2, "\" is too long"

    .line 581
    .line 582
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 583
    .line 584
    .line 585
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 586
    .line 587
    .line 588
    move-result-object v1

    .line 589
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 590
    .line 591
    .line 592
    move-result-object v1

    .line 593
    goto/16 :goto_16

    .line 594
    .line 595
    :cond_18
    rem-int/lit8 v6, v12, 0x3

    .line 596
    .line 597
    if-eqz v6, :cond_19

    .line 598
    .line 599
    new-instance v1, Ljava/lang/StringBuilder;

    .line 600
    .line 601
    const-string v2, "Invalid UTC offset string \""

    .line 602
    .line 603
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 604
    .line 605
    .line 606
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 607
    .line 608
    .line 609
    move-result v2

    .line 610
    invoke-virtual {v0, v8, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 611
    .line 612
    .line 613
    move-result-object v2

    .line 614
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 615
    .line 616
    .line 617
    move-result-object v2

    .line 618
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 619
    .line 620
    .line 621
    const/16 v2, 0x22

    .line 622
    .line 623
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 624
    .line 625
    .line 626
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 627
    .line 628
    .line 629
    move-result-object v1

    .line 630
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 631
    .line 632
    .line 633
    move-result-object v1

    .line 634
    goto/16 :goto_16

    .line 635
    .line 636
    :cond_19
    const/4 v6, 0x0

    .line 637
    :goto_7
    if-ge v6, v5, :cond_1c

    .line 638
    .line 639
    sget-object v21, Lmy0/h;->c:[I

    .line 640
    .line 641
    aget v21, v21, v6

    .line 642
    .line 643
    add-int v5, v8, v21

    .line 644
    .line 645
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 646
    .line 647
    .line 648
    move-result v13

    .line 649
    if-lt v5, v13, :cond_1a

    .line 650
    .line 651
    goto :goto_8

    .line 652
    :cond_1a
    invoke-virtual {v0, v5}, Ljava/lang/String;->charAt(I)C

    .line 653
    .line 654
    .line 655
    move-result v13

    .line 656
    if-eq v13, v11, :cond_1b

    .line 657
    .line 658
    const-string v1, "Expected \':\' at index "

    .line 659
    .line 660
    invoke-static {v1, v5, v14}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 661
    .line 662
    .line 663
    move-result-object v1

    .line 664
    invoke-virtual {v0, v5}, Ljava/lang/String;->charAt(I)C

    .line 665
    .line 666
    .line 667
    move-result v2

    .line 668
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 669
    .line 670
    .line 671
    const/16 v2, 0x27

    .line 672
    .line 673
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 674
    .line 675
    .line 676
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 677
    .line 678
    .line 679
    move-result-object v1

    .line 680
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 681
    .line 682
    .line 683
    move-result-object v1

    .line 684
    goto/16 :goto_16

    .line 685
    .line 686
    :cond_1b
    add-int/lit8 v6, v6, 0x1

    .line 687
    .line 688
    const/4 v5, 0x2

    .line 689
    const/16 v13, 0x27

    .line 690
    .line 691
    goto :goto_7

    .line 692
    :cond_1c
    :goto_8
    const/4 v5, 0x0

    .line 693
    :goto_9
    const/4 v6, 0x6

    .line 694
    if-ge v5, v6, :cond_1f

    .line 695
    .line 696
    sget-object v6, Lmy0/h;->d:[I

    .line 697
    .line 698
    aget v6, v6, v5

    .line 699
    .line 700
    add-int/2addr v6, v8

    .line 701
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 702
    .line 703
    .line 704
    move-result v13

    .line 705
    if-lt v6, v13, :cond_1d

    .line 706
    .line 707
    goto :goto_a

    .line 708
    :cond_1d
    invoke-virtual {v0, v6}, Ljava/lang/String;->charAt(I)C

    .line 709
    .line 710
    .line 711
    move-result v13

    .line 712
    move/from16 v22, v5

    .line 713
    .line 714
    const/16 v5, 0x30

    .line 715
    .line 716
    if-gt v5, v13, :cond_1e

    .line 717
    .line 718
    if-ge v13, v11, :cond_1e

    .line 719
    .line 720
    add-int/lit8 v6, v22, 0x1

    .line 721
    .line 722
    move v5, v6

    .line 723
    goto :goto_9

    .line 724
    :cond_1e
    const-string v1, "Expected an ASCII digit at index "

    .line 725
    .line 726
    invoke-static {v1, v6, v14}, Lp3/m;->p(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/StringBuilder;

    .line 727
    .line 728
    .line 729
    move-result-object v1

    .line 730
    invoke-virtual {v0, v6}, Ljava/lang/String;->charAt(I)C

    .line 731
    .line 732
    .line 733
    move-result v2

    .line 734
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 735
    .line 736
    .line 737
    const/16 v2, 0x27

    .line 738
    .line 739
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 740
    .line 741
    .line 742
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 747
    .line 748
    .line 749
    move-result-object v1

    .line 750
    goto/16 :goto_16

    .line 751
    .line 752
    :cond_1f
    :goto_a
    add-int/lit8 v5, v8, 0x1

    .line 753
    .line 754
    invoke-static {v5, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 755
    .line 756
    .line 757
    move-result v5

    .line 758
    const/4 v6, 0x3

    .line 759
    if-le v12, v6, :cond_20

    .line 760
    .line 761
    add-int/lit8 v6, v8, 0x4

    .line 762
    .line 763
    invoke-static {v6, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 764
    .line 765
    .line 766
    move-result v6

    .line 767
    :goto_b
    const/4 v11, 0x6

    .line 768
    goto :goto_c

    .line 769
    :cond_20
    const/4 v6, 0x0

    .line 770
    goto :goto_b

    .line 771
    :goto_c
    if-le v12, v11, :cond_21

    .line 772
    .line 773
    add-int/lit8 v11, v8, 0x7

    .line 774
    .line 775
    invoke-static {v11, v0}, Lmy0/h;->n(ILjava/lang/String;)I

    .line 776
    .line 777
    .line 778
    move-result v11

    .line 779
    :goto_d
    const/16 v12, 0x3b

    .line 780
    .line 781
    goto :goto_e

    .line 782
    :cond_21
    const/4 v11, 0x0

    .line 783
    goto :goto_d

    .line 784
    :goto_e
    if-le v6, v12, :cond_22

    .line 785
    .line 786
    new-instance v1, Ljava/lang/StringBuilder;

    .line 787
    .line 788
    const-string v2, "Expected offset-minute-of-hour in 0..59, got "

    .line 789
    .line 790
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 791
    .line 792
    .line 793
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 794
    .line 795
    .line 796
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 797
    .line 798
    .line 799
    move-result-object v1

    .line 800
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 801
    .line 802
    .line 803
    move-result-object v1

    .line 804
    goto/16 :goto_16

    .line 805
    .line 806
    :cond_22
    if-le v11, v12, :cond_23

    .line 807
    .line 808
    new-instance v1, Ljava/lang/StringBuilder;

    .line 809
    .line 810
    const-string v2, "Expected offset-second-of-minute in 0..59, got "

    .line 811
    .line 812
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 813
    .line 814
    .line 815
    invoke-virtual {v1, v11}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 816
    .line 817
    .line 818
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 819
    .line 820
    .line 821
    move-result-object v1

    .line 822
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 823
    .line 824
    .line 825
    move-result-object v1

    .line 826
    goto/16 :goto_16

    .line 827
    .line 828
    :cond_23
    const/16 v12, 0x11

    .line 829
    .line 830
    if-le v5, v12, :cond_25

    .line 831
    .line 832
    const/16 v12, 0x12

    .line 833
    .line 834
    if-ne v5, v12, :cond_24

    .line 835
    .line 836
    if-nez v6, :cond_24

    .line 837
    .line 838
    if-eqz v11, :cond_25

    .line 839
    .line 840
    :cond_24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 841
    .line 842
    const-string v2, "Expected an offset in -18:00..+18:00, got "

    .line 843
    .line 844
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 845
    .line 846
    .line 847
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 848
    .line 849
    .line 850
    move-result v2

    .line 851
    invoke-virtual {v0, v8, v2}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 852
    .line 853
    .line 854
    move-result-object v2

    .line 855
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 856
    .line 857
    .line 858
    move-result-object v2

    .line 859
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 860
    .line 861
    .line 862
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 863
    .line 864
    .line 865
    move-result-object v1

    .line 866
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 867
    .line 868
    .line 869
    move-result-object v1

    .line 870
    goto/16 :goto_16

    .line 871
    .line 872
    :cond_25
    mul-int/lit16 v5, v5, 0xe10

    .line 873
    .line 874
    mul-int/lit8 v6, v6, 0x3c

    .line 875
    .line 876
    add-int/2addr v6, v5

    .line 877
    add-int/2addr v6, v11

    .line 878
    const/16 v12, 0x2d

    .line 879
    .line 880
    if-ne v3, v12, :cond_26

    .line 881
    .line 882
    const/4 v3, -0x1

    .line 883
    goto :goto_f

    .line 884
    :cond_26
    move/from16 v3, v20

    .line 885
    .line 886
    :goto_f
    mul-int/2addr v6, v3

    .line 887
    goto/16 :goto_6

    .line 888
    .line 889
    :goto_10
    if-gt v3, v1, :cond_34

    .line 890
    .line 891
    const/16 v5, 0xd

    .line 892
    .line 893
    if-ge v1, v5, :cond_34

    .line 894
    .line 895
    if-gt v3, v7, :cond_33

    .line 896
    .line 897
    and-int/lit8 v3, v9, 0x3

    .line 898
    .line 899
    if-nez v3, :cond_28

    .line 900
    .line 901
    rem-int/lit8 v5, v9, 0x64

    .line 902
    .line 903
    if-nez v5, :cond_27

    .line 904
    .line 905
    rem-int/lit16 v5, v9, 0x190

    .line 906
    .line 907
    if-nez v5, :cond_28

    .line 908
    .line 909
    :cond_27
    const/4 v5, 0x1

    .line 910
    :goto_11
    const/4 v8, 0x2

    .line 911
    goto :goto_12

    .line 912
    :cond_28
    const/4 v5, 0x0

    .line 913
    goto :goto_11

    .line 914
    :goto_12
    if-eq v1, v8, :cond_2a

    .line 915
    .line 916
    const/4 v8, 0x4

    .line 917
    if-eq v1, v8, :cond_29

    .line 918
    .line 919
    const/4 v11, 0x6

    .line 920
    if-eq v1, v11, :cond_29

    .line 921
    .line 922
    const/16 v5, 0x9

    .line 923
    .line 924
    if-eq v1, v5, :cond_29

    .line 925
    .line 926
    const/16 v5, 0xb

    .line 927
    .line 928
    if-eq v1, v5, :cond_29

    .line 929
    .line 930
    const/16 v5, 0x1f

    .line 931
    .line 932
    goto :goto_13

    .line 933
    :cond_29
    const/16 v5, 0x1e

    .line 934
    .line 935
    goto :goto_13

    .line 936
    :cond_2a
    if-eqz v5, :cond_2b

    .line 937
    .line 938
    const/16 v5, 0x1d

    .line 939
    .line 940
    goto :goto_13

    .line 941
    :cond_2b
    const/16 v5, 0x1c

    .line 942
    .line 943
    :goto_13
    if-gt v7, v5, :cond_33

    .line 944
    .line 945
    const/16 v5, 0x17

    .line 946
    .line 947
    if-le v15, v5, :cond_2c

    .line 948
    .line 949
    new-instance v1, Ljava/lang/StringBuilder;

    .line 950
    .line 951
    const-string v2, "Expected hour in 0..23, got "

    .line 952
    .line 953
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 954
    .line 955
    .line 956
    invoke-virtual {v1, v15}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 957
    .line 958
    .line 959
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 960
    .line 961
    .line 962
    move-result-object v1

    .line 963
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 964
    .line 965
    .line 966
    move-result-object v1

    .line 967
    goto/16 :goto_16

    .line 968
    .line 969
    :cond_2c
    const/16 v12, 0x3b

    .line 970
    .line 971
    if-le v2, v12, :cond_2d

    .line 972
    .line 973
    new-instance v1, Ljava/lang/StringBuilder;

    .line 974
    .line 975
    const-string v3, "Expected minute-of-hour in 0..59, got "

    .line 976
    .line 977
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 978
    .line 979
    .line 980
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 981
    .line 982
    .line 983
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 984
    .line 985
    .line 986
    move-result-object v1

    .line 987
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 988
    .line 989
    .line 990
    move-result-object v1

    .line 991
    goto/16 :goto_16

    .line 992
    .line 993
    :cond_2d
    if-le v10, v12, :cond_2e

    .line 994
    .line 995
    new-instance v1, Ljava/lang/StringBuilder;

    .line 996
    .line 997
    const-string v2, "Expected second-of-minute in 0..59, got "

    .line 998
    .line 999
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1000
    .line 1001
    .line 1002
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1003
    .line 1004
    .line 1005
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v1

    .line 1009
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v1

    .line 1013
    goto/16 :goto_16

    .line 1014
    .line 1015
    :cond_2e
    int-to-long v11, v9

    .line 1016
    const/16 v0, 0x16d

    .line 1017
    .line 1018
    int-to-long v13, v0

    .line 1019
    mul-long/2addr v13, v11

    .line 1020
    const-wide/16 v18, 0x0

    .line 1021
    .line 1022
    cmp-long v0, v11, v18

    .line 1023
    .line 1024
    if-ltz v0, :cond_2f

    .line 1025
    .line 1026
    move v8, v6

    .line 1027
    const/4 v0, 0x3

    .line 1028
    int-to-long v5, v0

    .line 1029
    add-long/2addr v5, v11

    .line 1030
    move/from16 v16, v2

    .line 1031
    .line 1032
    move/from16 p1, v3

    .line 1033
    .line 1034
    const/4 v0, 0x4

    .line 1035
    int-to-long v2, v0

    .line 1036
    div-long/2addr v5, v2

    .line 1037
    const/16 v0, 0x63

    .line 1038
    .line 1039
    int-to-long v2, v0

    .line 1040
    add-long/2addr v2, v11

    .line 1041
    const/16 v0, 0x64

    .line 1042
    .line 1043
    move-wide/from16 v18, v2

    .line 1044
    .line 1045
    int-to-long v2, v0

    .line 1046
    div-long v2, v18, v2

    .line 1047
    .line 1048
    sub-long/2addr v5, v2

    .line 1049
    const/16 v0, 0x18f

    .line 1050
    .line 1051
    int-to-long v2, v0

    .line 1052
    add-long/2addr v11, v2

    .line 1053
    const/16 v0, 0x190

    .line 1054
    .line 1055
    int-to-long v2, v0

    .line 1056
    div-long/2addr v11, v2

    .line 1057
    add-long/2addr v11, v5

    .line 1058
    add-long/2addr v11, v13

    .line 1059
    goto :goto_14

    .line 1060
    :cond_2f
    move/from16 v16, v2

    .line 1061
    .line 1062
    move/from16 p1, v3

    .line 1063
    .line 1064
    move v8, v6

    .line 1065
    const/4 v0, -0x4

    .line 1066
    int-to-long v2, v0

    .line 1067
    div-long v2, v11, v2

    .line 1068
    .line 1069
    const/16 v0, -0x64

    .line 1070
    .line 1071
    int-to-long v5, v0

    .line 1072
    div-long v5, v11, v5

    .line 1073
    .line 1074
    sub-long/2addr v2, v5

    .line 1075
    const/16 v0, -0x190

    .line 1076
    .line 1077
    int-to-long v5, v0

    .line 1078
    div-long/2addr v11, v5

    .line 1079
    add-long/2addr v11, v2

    .line 1080
    sub-long v11, v13, v11

    .line 1081
    .line 1082
    :goto_14
    mul-int/lit16 v0, v1, 0x16f

    .line 1083
    .line 1084
    add-int/lit16 v0, v0, -0x16a

    .line 1085
    .line 1086
    div-int/lit8 v0, v0, 0xc

    .line 1087
    .line 1088
    int-to-long v2, v0

    .line 1089
    add-long/2addr v11, v2

    .line 1090
    const/16 v20, 0x1

    .line 1091
    .line 1092
    add-int/lit8 v7, v7, -0x1

    .line 1093
    .line 1094
    int-to-long v2, v7

    .line 1095
    add-long/2addr v11, v2

    .line 1096
    const/4 v0, 0x2

    .line 1097
    if-le v1, v0, :cond_32

    .line 1098
    .line 1099
    const-wide/16 v0, -0x1

    .line 1100
    .line 1101
    add-long/2addr v0, v11

    .line 1102
    if-nez p1, :cond_31

    .line 1103
    .line 1104
    rem-int/lit8 v2, v9, 0x64

    .line 1105
    .line 1106
    if-nez v2, :cond_30

    .line 1107
    .line 1108
    const/16 v2, 0x190

    .line 1109
    .line 1110
    rem-int/2addr v9, v2

    .line 1111
    if-nez v9, :cond_31

    .line 1112
    .line 1113
    :cond_30
    move-wide v11, v0

    .line 1114
    goto :goto_15

    .line 1115
    :cond_31
    const-wide/16 v0, -0x2

    .line 1116
    .line 1117
    add-long/2addr v11, v0

    .line 1118
    :cond_32
    :goto_15
    const v0, 0xafaa8

    .line 1119
    .line 1120
    .line 1121
    int-to-long v0, v0

    .line 1122
    sub-long/2addr v11, v0

    .line 1123
    mul-int/lit16 v15, v15, 0xe10

    .line 1124
    .line 1125
    mul-int/lit8 v2, v16, 0x3c

    .line 1126
    .line 1127
    add-int/2addr v2, v15

    .line 1128
    add-int/2addr v2, v10

    .line 1129
    const v0, 0x15180

    .line 1130
    .line 1131
    .line 1132
    int-to-long v0, v0

    .line 1133
    mul-long/2addr v11, v0

    .line 1134
    int-to-long v0, v2

    .line 1135
    add-long/2addr v11, v0

    .line 1136
    int-to-long v0, v8

    .line 1137
    sub-long/2addr v11, v0

    .line 1138
    new-instance v1, Lin/p;

    .line 1139
    .line 1140
    invoke-direct {v1, v11, v12, v4}, Lin/p;-><init>(JI)V

    .line 1141
    .line 1142
    .line 1143
    goto :goto_16

    .line 1144
    :cond_33
    const-string v2, " of year "

    .line 1145
    .line 1146
    const-string v3, ", got "

    .line 1147
    .line 1148
    const-string v4, "Expected a valid day-of-month for month "

    .line 1149
    .line 1150
    invoke-static {v1, v9, v4, v2, v3}, Lu/w;->j(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v1

    .line 1154
    invoke-virtual {v1, v7}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1155
    .line 1156
    .line 1157
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v1

    .line 1161
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 1162
    .line 1163
    .line 1164
    move-result-object v1

    .line 1165
    goto :goto_16

    .line 1166
    :cond_34
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1167
    .line 1168
    const-string v3, "Expected a month number in 1..12, got "

    .line 1169
    .line 1170
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1171
    .line 1172
    .line 1173
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1174
    .line 1175
    .line 1176
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1177
    .line 1178
    .line 1179
    move-result-object v1

    .line 1180
    invoke-static {v0, v1}, Lmy0/h;->m(Ljava/lang/String;Ljava/lang/String;)Lc2/k;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v1

    .line 1184
    :goto_16
    invoke-interface {v1}, Lmy0/i;->toInstant()Lmy0/f;

    .line 1185
    .line 1186
    .line 1187
    move-result-object v0

    .line 1188
    return-object v0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Luz0/h0;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lmy0/f;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p2}, Lmy0/f;->toString()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p1, p0}, Ltz0/d;->E(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method
