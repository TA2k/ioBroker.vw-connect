.class public final Ld4/o;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Ld4/o;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ld4/o;->g:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 42

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld4/o;->f:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v0, v0, Ld4/o;->g:Ljava/lang/String;

    .line 8
    .line 9
    packed-switch v1, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    move-object/from16 v1, p1

    .line 13
    .line 14
    check-cast v1, Lg4/d;

    .line 15
    .line 16
    const-string v3, "$this$withAnnotatedString"

    .line 17
    .line 18
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    sget-wide v3, Le3/s;->g:J

    .line 22
    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x0

    .line 25
    invoke-static {v0, v5, v6, v6}, Landroid/text/Html;->fromHtml(Ljava/lang/String;ILandroid/text/Html$ImageGetter;Landroid/text/Html$TagHandler;)Landroid/text/Spanned;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v7, "fromHtml(\n        this,\n\u2026        tagHandler,\n    )"

    .line 30
    .line 31
    invoke-static {v0, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 35
    .line 36
    .line 37
    move-result v7

    .line 38
    const-class v8, Landroid/text/style/LeadingMarginSpan;

    .line 39
    .line 40
    invoke-interface {v0, v5, v7, v8}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v7

    .line 44
    check-cast v7, [Landroid/text/style/LeadingMarginSpan;

    .line 45
    .line 46
    const-string v8, "spans"

    .line 47
    .line 48
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    array-length v8, v7

    .line 52
    const/4 v9, 0x1

    .line 53
    if-le v8, v9, :cond_0

    .line 54
    .line 55
    new-instance v8, Ld4/b0;

    .line 56
    .line 57
    const/4 v10, 0x5

    .line 58
    invoke-direct {v8, v0, v10}, Ld4/b0;-><init>(Ljava/lang/Object;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v7, v8}, Lmx0/n;->S([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 62
    .line 63
    .line 64
    :cond_0
    array-length v8, v7

    .line 65
    const-string v10, "span"

    .line 66
    .line 67
    if-nez v8, :cond_2

    .line 68
    .line 69
    :cond_1
    move-object/from16 v20, v2

    .line 70
    .line 71
    move/from16 p1, v9

    .line 72
    .line 73
    goto/16 :goto_15

    .line 74
    .line 75
    :cond_2
    instance-of v8, v0, Landroid/text/SpannableStringBuilder;

    .line 76
    .line 77
    if-eqz v8, :cond_3

    .line 78
    .line 79
    check-cast v0, Landroid/text/SpannableStringBuilder;

    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_3
    new-instance v8, Landroid/text/SpannableStringBuilder;

    .line 83
    .line 84
    invoke-direct {v8, v0}, Landroid/text/SpannableStringBuilder;-><init>(Ljava/lang/CharSequence;)V

    .line 85
    .line 86
    .line 87
    move-object v0, v8

    .line 88
    :goto_0
    array-length v8, v7

    .line 89
    move v11, v5

    .line 90
    :goto_1
    const/16 v12, 0x21

    .line 91
    .line 92
    if-ge v11, v8, :cond_4

    .line 93
    .line 94
    aget-object v13, v7, v11

    .line 95
    .line 96
    invoke-virtual {v0, v13}, Landroid/text/SpannableStringBuilder;->getSpanStart(Ljava/lang/Object;)I

    .line 97
    .line 98
    .line 99
    move-result v14

    .line 100
    invoke-virtual {v0, v13}, Landroid/text/SpannableStringBuilder;->getSpanEnd(Ljava/lang/Object;)I

    .line 101
    .line 102
    .line 103
    move-result v15

    .line 104
    invoke-virtual {v0, v13, v14, v15, v12}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 105
    .line 106
    .line 107
    add-int/lit8 v11, v11, 0x1

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_4
    array-length v8, v7

    .line 111
    move v13, v5

    .line 112
    const/4 v14, -0x1

    .line 113
    :goto_2
    if-ge v13, v8, :cond_1

    .line 114
    .line 115
    aget-object v15, v7, v13

    .line 116
    .line 117
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->getSpanStart(Ljava/lang/Object;)I

    .line 118
    .line 119
    .line 120
    move-result v6

    .line 121
    if-ge v6, v14, :cond_5

    .line 122
    .line 123
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->removeSpan(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    move-object/from16 v20, v2

    .line 127
    .line 128
    move-object/from16 v21, v7

    .line 129
    .line 130
    move/from16 p1, v9

    .line 131
    .line 132
    move v9, v12

    .line 133
    const/4 v5, -0x1

    .line 134
    goto/16 :goto_14

    .line 135
    .line 136
    :cond_5
    invoke-static {v15, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-static {v15}, Lkp/ea;->c(Landroid/text/style/LeadingMarginSpan;)Z

    .line 140
    .line 141
    .line 142
    move-result v16

    .line 143
    move/from16 p1, v9

    .line 144
    .line 145
    const/16 v9, 0xa

    .line 146
    .line 147
    if-nez v16, :cond_7

    .line 148
    .line 149
    :cond_6
    const/4 v5, -0x1

    .line 150
    goto :goto_4

    .line 151
    :cond_7
    if-nez v6, :cond_8

    .line 152
    .line 153
    goto :goto_4

    .line 154
    :cond_8
    if-ne v6, v14, :cond_9

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_9
    add-int/lit8 v5, v6, -0x1

    .line 158
    .line 159
    invoke-virtual {v0, v5}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 160
    .line 161
    .line 162
    move-result v12

    .line 163
    if-ne v12, v9, :cond_a

    .line 164
    .line 165
    add-int/lit8 v12, v14, 0x1

    .line 166
    .line 167
    if-ne v6, v12, :cond_a

    .line 168
    .line 169
    const-string v12, "\r\n"

    .line 170
    .line 171
    invoke-virtual {v0, v5, v6, v12}, Landroid/text/SpannableStringBuilder;->replace(IILjava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 172
    .line 173
    .line 174
    add-int/lit8 v6, v6, 0x1

    .line 175
    .line 176
    :goto_3
    move/from16 v5, p1

    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_a
    invoke-virtual {v0, v5}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 180
    .line 181
    .line 182
    move-result v5

    .line 183
    if-ne v5, v9, :cond_6

    .line 184
    .line 185
    goto :goto_3

    .line 186
    :goto_4
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->getSpanEnd(Ljava/lang/Object;)I

    .line 187
    .line 188
    .line 189
    move-result v12

    .line 190
    add-int/lit8 v11, v12, -0x1

    .line 191
    .line 192
    if-ltz v11, :cond_b

    .line 193
    .line 194
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 195
    .line 196
    .line 197
    move-result v9

    .line 198
    if-ge v11, v9, :cond_b

    .line 199
    .line 200
    invoke-interface {v0, v11}, Ljava/lang/CharSequence;->charAt(I)C

    .line 201
    .line 202
    .line 203
    move-result v9

    .line 204
    invoke-static {v9}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 205
    .line 206
    .line 207
    move-result-object v9

    .line 208
    goto :goto_5

    .line 209
    :cond_b
    const/4 v9, 0x0

    .line 210
    :goto_5
    if-nez v9, :cond_c

    .line 211
    .line 212
    const/16 v11, 0xa

    .line 213
    .line 214
    goto :goto_6

    .line 215
    :cond_c
    invoke-virtual {v9}, Ljava/lang/Character;->charValue()C

    .line 216
    .line 217
    .line 218
    move-result v9

    .line 219
    const/16 v11, 0xa

    .line 220
    .line 221
    if-eq v9, v11, :cond_10

    .line 222
    .line 223
    :goto_6
    invoke-virtual {v0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 224
    .line 225
    .line 226
    move-result v9

    .line 227
    invoke-virtual {v0, v12, v9}, Landroid/text/SpannableStringBuilder;->subSequence(II)Ljava/lang/CharSequence;

    .line 228
    .line 229
    .line 230
    move-result-object v9

    .line 231
    const-string v11, "subSequence(end, length)"

    .line 232
    .line 233
    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    invoke-interface {v9}, Ljava/lang/CharSequence;->length()I

    .line 237
    .line 238
    .line 239
    move-result v11

    .line 240
    move-object/from16 v20, v2

    .line 241
    .line 242
    const/4 v2, 0x0

    .line 243
    :goto_7
    if-ge v2, v11, :cond_e

    .line 244
    .line 245
    move-object/from16 v21, v7

    .line 246
    .line 247
    invoke-interface {v9, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 248
    .line 249
    .line 250
    move-result v7

    .line 251
    move/from16 v22, v2

    .line 252
    .line 253
    const/16 v2, 0xa

    .line 254
    .line 255
    if-ne v7, v2, :cond_d

    .line 256
    .line 257
    move/from16 v2, v22

    .line 258
    .line 259
    :goto_8
    const/4 v7, -0x1

    .line 260
    goto :goto_9

    .line 261
    :cond_d
    add-int/lit8 v2, v22, 0x1

    .line 262
    .line 263
    move-object/from16 v7, v21

    .line 264
    .line 265
    goto :goto_7

    .line 266
    :cond_e
    move-object/from16 v21, v7

    .line 267
    .line 268
    const/4 v2, -0x1

    .line 269
    goto :goto_8

    .line 270
    :goto_9
    if-ne v2, v7, :cond_f

    .line 271
    .line 272
    invoke-virtual {v0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 273
    .line 274
    .line 275
    move-result v2

    .line 276
    move v12, v2

    .line 277
    :goto_a
    const/16 v2, 0x21

    .line 278
    .line 279
    goto :goto_b

    .line 280
    :cond_f
    add-int/2addr v12, v2

    .line 281
    add-int/lit8 v12, v12, 0x1

    .line 282
    .line 283
    goto :goto_a

    .line 284
    :goto_b
    invoke-virtual {v0, v15, v6, v12, v2}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 285
    .line 286
    .line 287
    goto :goto_c

    .line 288
    :cond_10
    move-object/from16 v20, v2

    .line 289
    .line 290
    move-object/from16 v21, v7

    .line 291
    .line 292
    const/4 v7, -0x1

    .line 293
    :goto_c
    const-string v2, ""

    .line 294
    .line 295
    if-ne v5, v7, :cond_15

    .line 296
    .line 297
    invoke-static {v15}, Lkp/ea;->c(Landroid/text/style/LeadingMarginSpan;)Z

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    if-eqz v7, :cond_14

    .line 302
    .line 303
    instance-of v7, v15, Landroid/text/style/BulletSpan;

    .line 304
    .line 305
    if-nez v7, :cond_14

    .line 306
    .line 307
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->removeSpan(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    add-int/lit8 v7, v12, -0x1

    .line 311
    .line 312
    invoke-virtual {v0, v6, v7}, Landroid/text/SpannableStringBuilder;->subSequence(II)Ljava/lang/CharSequence;

    .line 313
    .line 314
    .line 315
    move-result-object v7

    .line 316
    const-string v9, "subSequence(start, end - 1)"

    .line 317
    .line 318
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 322
    .line 323
    .line 324
    move-result v9

    .line 325
    const/4 v11, 0x0

    .line 326
    :goto_d
    if-ge v11, v9, :cond_12

    .line 327
    .line 328
    move/from16 v22, v5

    .line 329
    .line 330
    invoke-interface {v7, v11}, Ljava/lang/CharSequence;->charAt(I)C

    .line 331
    .line 332
    .line 333
    move-result v5

    .line 334
    move-object/from16 v23, v7

    .line 335
    .line 336
    const/16 v7, 0xa

    .line 337
    .line 338
    if-ne v5, v7, :cond_11

    .line 339
    .line 340
    move v7, v11

    .line 341
    :goto_e
    const/4 v5, -0x1

    .line 342
    goto :goto_f

    .line 343
    :cond_11
    add-int/lit8 v11, v11, 0x1

    .line 344
    .line 345
    move/from16 v5, v22

    .line 346
    .line 347
    move-object/from16 v7, v23

    .line 348
    .line 349
    goto :goto_d

    .line 350
    :cond_12
    move/from16 v22, v5

    .line 351
    .line 352
    const/4 v7, -0x1

    .line 353
    goto :goto_e

    .line 354
    :goto_f
    if-eq v7, v5, :cond_13

    .line 355
    .line 356
    add-int/2addr v7, v6

    .line 357
    add-int/lit8 v6, v7, 0x1

    .line 358
    .line 359
    const/16 v9, 0x21

    .line 360
    .line 361
    invoke-virtual {v0, v15, v6, v12, v9}, Landroid/text/SpannableStringBuilder;->setSpan(Ljava/lang/Object;III)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {v0, v7, v6, v2}, Landroid/text/SpannableStringBuilder;->replace(IILjava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 365
    .line 366
    .line 367
    :goto_10
    const/16 v22, 0x0

    .line 368
    .line 369
    goto :goto_11

    .line 370
    :cond_13
    const/16 v9, 0x21

    .line 371
    .line 372
    goto :goto_11

    .line 373
    :cond_14
    move/from16 v22, v5

    .line 374
    .line 375
    const/4 v5, -0x1

    .line 376
    const/16 v9, 0x21

    .line 377
    .line 378
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->removeSpan(Ljava/lang/Object;)V

    .line 379
    .line 380
    .line 381
    goto :goto_11

    .line 382
    :cond_15
    move/from16 v22, v5

    .line 383
    .line 384
    move v5, v7

    .line 385
    const/16 v9, 0x21

    .line 386
    .line 387
    if-lez v22, :cond_16

    .line 388
    .line 389
    sub-int v7, v6, v22

    .line 390
    .line 391
    invoke-virtual {v0, v7, v6, v2}, Landroid/text/SpannableStringBuilder;->replace(IILjava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 392
    .line 393
    .line 394
    goto :goto_10

    .line 395
    :cond_16
    :goto_11
    if-nez v22, :cond_1a

    .line 396
    .line 397
    invoke-virtual {v0, v15}, Landroid/text/SpannableStringBuilder;->getSpanEnd(Ljava/lang/Object;)I

    .line 398
    .line 399
    .line 400
    move-result v6

    .line 401
    add-int/lit8 v7, v6, -0x1

    .line 402
    .line 403
    if-ltz v7, :cond_17

    .line 404
    .line 405
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 406
    .line 407
    .line 408
    move-result v11

    .line 409
    if-ge v7, v11, :cond_17

    .line 410
    .line 411
    invoke-interface {v0, v7}, Ljava/lang/CharSequence;->charAt(I)C

    .line 412
    .line 413
    .line 414
    move-result v11

    .line 415
    invoke-static {v11}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 416
    .line 417
    .line 418
    move-result-object v11

    .line 419
    goto :goto_12

    .line 420
    :cond_17
    const/4 v11, 0x0

    .line 421
    :goto_12
    if-nez v11, :cond_18

    .line 422
    .line 423
    goto :goto_13

    .line 424
    :cond_18
    invoke-virtual {v11}, Ljava/lang/Character;->charValue()C

    .line 425
    .line 426
    .line 427
    move-result v11

    .line 428
    const/16 v12, 0xa

    .line 429
    .line 430
    if-ne v11, v12, :cond_19

    .line 431
    .line 432
    invoke-virtual {v0}, Landroid/text/SpannableStringBuilder;->length()I

    .line 433
    .line 434
    .line 435
    move-result v11

    .line 436
    if-eq v11, v6, :cond_19

    .line 437
    .line 438
    invoke-virtual {v0, v7, v6, v2}, Landroid/text/SpannableStringBuilder;->replace(IILjava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 439
    .line 440
    .line 441
    add-int/lit8 v6, v6, -0x1

    .line 442
    .line 443
    :cond_19
    :goto_13
    move v14, v6

    .line 444
    :cond_1a
    :goto_14
    add-int/lit8 v13, v13, 0x1

    .line 445
    .line 446
    move v12, v9

    .line 447
    move-object/from16 v2, v20

    .line 448
    .line 449
    move-object/from16 v7, v21

    .line 450
    .line 451
    const/4 v5, 0x0

    .line 452
    const/4 v6, 0x0

    .line 453
    move/from16 v9, p1

    .line 454
    .line 455
    goto/16 :goto_2

    .line 456
    .line 457
    :goto_15
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 458
    .line 459
    const-class v5, Landroid/text/style/AbsoluteSizeSpan;

    .line 460
    .line 461
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 462
    .line 463
    .line 464
    move-result-object v5

    .line 465
    sget-object v6, Ltm/i;->g:Ltm/i;

    .line 466
    .line 467
    new-instance v7, Llx0/l;

    .line 468
    .line 469
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 470
    .line 471
    .line 472
    const-class v5, Landroid/text/style/RelativeSizeSpan;

    .line 473
    .line 474
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 475
    .line 476
    .line 477
    move-result-object v5

    .line 478
    sget-object v6, Ltm/i;->k:Ltm/i;

    .line 479
    .line 480
    new-instance v8, Llx0/l;

    .line 481
    .line 482
    invoke-direct {v8, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 483
    .line 484
    .line 485
    const-class v5, Landroid/text/style/BackgroundColorSpan;

    .line 486
    .line 487
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 488
    .line 489
    .line 490
    move-result-object v5

    .line 491
    sget-object v6, Ltm/i;->h:Ltm/i;

    .line 492
    .line 493
    new-instance v9, Llx0/l;

    .line 494
    .line 495
    invoke-direct {v9, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 496
    .line 497
    .line 498
    const-class v5, Landroid/text/style/ForegroundColorSpan;

    .line 499
    .line 500
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 501
    .line 502
    .line 503
    move-result-object v5

    .line 504
    sget-object v6, Ltm/i;->i:Ltm/i;

    .line 505
    .line 506
    new-instance v11, Llx0/l;

    .line 507
    .line 508
    invoke-direct {v11, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 509
    .line 510
    .line 511
    const-class v5, Landroid/text/style/StrikethroughSpan;

    .line 512
    .line 513
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 514
    .line 515
    .line 516
    move-result-object v5

    .line 517
    sget-object v6, Ltm/i;->n:Ltm/i;

    .line 518
    .line 519
    new-instance v12, Llx0/l;

    .line 520
    .line 521
    invoke-direct {v12, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 522
    .line 523
    .line 524
    const-class v5, Landroid/text/style/UnderlineSpan;

    .line 525
    .line 526
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 527
    .line 528
    .line 529
    move-result-object v5

    .line 530
    sget-object v6, Ltm/i;->t:Ltm/i;

    .line 531
    .line 532
    new-instance v13, Llx0/l;

    .line 533
    .line 534
    invoke-direct {v13, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 535
    .line 536
    .line 537
    const-class v5, Landroid/text/style/StyleSpan;

    .line 538
    .line 539
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 540
    .line 541
    .line 542
    move-result-object v5

    .line 543
    sget-object v6, Ltm/i;->o:Ltm/i;

    .line 544
    .line 545
    new-instance v14, Llx0/l;

    .line 546
    .line 547
    invoke-direct {v14, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 548
    .line 549
    .line 550
    const-class v5, Landroid/text/style/SubscriptSpan;

    .line 551
    .line 552
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 553
    .line 554
    .line 555
    move-result-object v5

    .line 556
    sget-object v6, Ltm/i;->p:Ltm/i;

    .line 557
    .line 558
    new-instance v15, Llx0/l;

    .line 559
    .line 560
    invoke-direct {v15, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 561
    .line 562
    .line 563
    const-class v5, Landroid/text/style/SuperscriptSpan;

    .line 564
    .line 565
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 566
    .line 567
    .line 568
    move-result-object v5

    .line 569
    sget-object v6, Ltm/i;->q:Ltm/i;

    .line 570
    .line 571
    move-object/from16 v21, v7

    .line 572
    .line 573
    new-instance v7, Llx0/l;

    .line 574
    .line 575
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 576
    .line 577
    .line 578
    const-class v5, Landroid/text/style/ScaleXSpan;

    .line 579
    .line 580
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 581
    .line 582
    .line 583
    move-result-object v5

    .line 584
    sget-object v6, Ltm/i;->l:Ltm/i;

    .line 585
    .line 586
    move-object/from16 v29, v7

    .line 587
    .line 588
    new-instance v7, Llx0/l;

    .line 589
    .line 590
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 591
    .line 592
    .line 593
    const-class v5, Ltm/h;

    .line 594
    .line 595
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 596
    .line 597
    .line 598
    move-result-object v5

    .line 599
    sget-object v6, Ltm/i;->m:Ltm/i;

    .line 600
    .line 601
    move-object/from16 v30, v7

    .line 602
    .line 603
    new-instance v7, Llx0/l;

    .line 604
    .line 605
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 606
    .line 607
    .line 608
    const-class v5, Landroid/text/style/LocaleSpan;

    .line 609
    .line 610
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 611
    .line 612
    .line 613
    move-result-object v5

    .line 614
    sget-object v6, Ltm/i;->j:Ltm/i;

    .line 615
    .line 616
    move-object/from16 v31, v7

    .line 617
    .line 618
    new-instance v7, Llx0/l;

    .line 619
    .line 620
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 621
    .line 622
    .line 623
    const-class v5, Landroid/text/style/TextAppearanceSpan;

    .line 624
    .line 625
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 626
    .line 627
    .line 628
    move-result-object v5

    .line 629
    sget-object v6, Ltm/i;->r:Ltm/i;

    .line 630
    .line 631
    move-object/from16 v32, v7

    .line 632
    .line 633
    new-instance v7, Llx0/l;

    .line 634
    .line 635
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 636
    .line 637
    .line 638
    const-class v5, Landroid/text/style/TypefaceSpan;

    .line 639
    .line 640
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 641
    .line 642
    .line 643
    move-result-object v5

    .line 644
    sget-object v6, Ltm/i;->s:Ltm/i;

    .line 645
    .line 646
    move-object/from16 v33, v7

    .line 647
    .line 648
    new-instance v7, Llx0/l;

    .line 649
    .line 650
    invoke-direct {v7, v5, v6}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 651
    .line 652
    .line 653
    const-class v5, Landroid/text/style/URLSpan;

    .line 654
    .line 655
    invoke-virtual {v2, v5}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 656
    .line 657
    .line 658
    move-result-object v2

    .line 659
    sget-object v5, Ltm/i;->u:Ltm/i;

    .line 660
    .line 661
    new-instance v6, Llx0/l;

    .line 662
    .line 663
    invoke-direct {v6, v2, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 664
    .line 665
    .line 666
    move-object/from16 v35, v6

    .line 667
    .line 668
    move-object/from16 v34, v7

    .line 669
    .line 670
    move-object/from16 v22, v8

    .line 671
    .line 672
    move-object/from16 v23, v9

    .line 673
    .line 674
    move-object/from16 v24, v11

    .line 675
    .line 676
    move-object/from16 v25, v12

    .line 677
    .line 678
    move-object/from16 v26, v13

    .line 679
    .line 680
    move-object/from16 v27, v14

    .line 681
    .line 682
    move-object/from16 v28, v15

    .line 683
    .line 684
    filled-new-array/range {v21 .. v35}, [Llx0/l;

    .line 685
    .line 686
    .line 687
    move-result-object v2

    .line 688
    invoke-static {v2}, Lmx0/x;->n([Llx0/l;)Ljava/util/LinkedHashMap;

    .line 689
    .line 690
    .line 691
    move-result-object v2

    .line 692
    new-instance v5, Lkotlin/jvm/internal/b0;

    .line 693
    .line 694
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 695
    .line 696
    .line 697
    new-instance v6, Ljava/util/ArrayList;

    .line 698
    .line 699
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 700
    .line 701
    .line 702
    new-instance v7, Ljava/util/ArrayList;

    .line 703
    .line 704
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 705
    .line 706
    .line 707
    new-instance v8, Lg4/d;

    .line 708
    .line 709
    invoke-direct {v8}, Lg4/d;-><init>()V

    .line 710
    .line 711
    .line 712
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 713
    .line 714
    .line 715
    move-result-object v9

    .line 716
    invoke-virtual {v8, v9}, Lg4/d;->d(Ljava/lang/String;)V

    .line 717
    .line 718
    .line 719
    new-instance v9, Ljava/util/LinkedHashMap;

    .line 720
    .line 721
    invoke-direct {v9}, Ljava/util/LinkedHashMap;-><init>()V

    .line 722
    .line 723
    .line 724
    invoke-interface {v0}, Ljava/lang/CharSequence;->length()I

    .line 725
    .line 726
    .line 727
    move-result v11

    .line 728
    const-class v12, Ljava/lang/Object;

    .line 729
    .line 730
    const/4 v13, 0x0

    .line 731
    invoke-interface {v0, v13, v11, v12}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v11

    .line 735
    const-string v12, "getSpans(0, length, Any::class.java)"

    .line 736
    .line 737
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 738
    .line 739
    .line 740
    array-length v12, v11

    .line 741
    const/4 v13, 0x0

    .line 742
    :goto_16
    if-ge v13, v12, :cond_1c

    .line 743
    .line 744
    aget-object v14, v11, v13

    .line 745
    .line 746
    new-instance v15, Lgy0/j;

    .line 747
    .line 748
    move-object/from16 v17, v11

    .line 749
    .line 750
    invoke-interface {v0, v14}, Landroid/text/Spanned;->getSpanStart(Ljava/lang/Object;)I

    .line 751
    .line 752
    .line 753
    move-result v11

    .line 754
    move/from16 v18, v12

    .line 755
    .line 756
    invoke-interface {v0, v14}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    .line 757
    .line 758
    .line 759
    move-result v12

    .line 760
    move-object/from16 v19, v0

    .line 761
    .line 762
    move/from16 v0, p1

    .line 763
    .line 764
    invoke-direct {v15, v11, v12, v0}, Lgy0/h;-><init>(III)V

    .line 765
    .line 766
    .line 767
    invoke-virtual {v9, v15}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 768
    .line 769
    .line 770
    move-result-object v0

    .line 771
    if-nez v0, :cond_1b

    .line 772
    .line 773
    new-instance v0, Ljava/util/ArrayList;

    .line 774
    .line 775
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 776
    .line 777
    .line 778
    invoke-interface {v9, v15, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 779
    .line 780
    .line 781
    :cond_1b
    check-cast v0, Ljava/util/List;

    .line 782
    .line 783
    invoke-static {v14, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 784
    .line 785
    .line 786
    invoke-interface {v0, v14}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 787
    .line 788
    .line 789
    add-int/lit8 v13, v13, 0x1

    .line 790
    .line 791
    move-object/from16 v11, v17

    .line 792
    .line 793
    move/from16 v12, v18

    .line 794
    .line 795
    move-object/from16 v0, v19

    .line 796
    .line 797
    const/16 p1, 0x1

    .line 798
    .line 799
    goto :goto_16

    .line 800
    :cond_1c
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 801
    .line 802
    const/16 v11, 0x16

    .line 803
    .line 804
    invoke-direct {v0, v11}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 805
    .line 806
    .line 807
    new-instance v11, Ljava/util/TreeMap;

    .line 808
    .line 809
    invoke-direct {v11, v0}, Ljava/util/TreeMap;-><init>(Ljava/util/Comparator;)V

    .line 810
    .line 811
    .line 812
    invoke-virtual {v11, v9}, Ljava/util/TreeMap;->putAll(Ljava/util/Map;)V

    .line 813
    .line 814
    .line 815
    invoke-virtual {v11}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 816
    .line 817
    .line 818
    move-result-object v0

    .line 819
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 820
    .line 821
    .line 822
    move-result-object v0

    .line 823
    :goto_17
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 824
    .line 825
    .line 826
    move-result v9

    .line 827
    if-eqz v9, :cond_35

    .line 828
    .line 829
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 830
    .line 831
    .line 832
    move-result-object v9

    .line 833
    check-cast v9, Ljava/util/Map$Entry;

    .line 834
    .line 835
    invoke-interface {v9}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 836
    .line 837
    .line 838
    move-result-object v11

    .line 839
    check-cast v11, Lgy0/j;

    .line 840
    .line 841
    invoke-interface {v9}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 842
    .line 843
    .line 844
    move-result-object v9

    .line 845
    check-cast v9, Ljava/util/List;

    .line 846
    .line 847
    new-instance v12, La3/g;

    .line 848
    .line 849
    const/4 v13, 0x6

    .line 850
    invoke-direct {v12, v5, v8, v11, v13}, La3/g;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 851
    .line 852
    .line 853
    new-instance v13, Ltm/j;

    .line 854
    .line 855
    const/4 v14, 0x0

    .line 856
    invoke-direct {v13, v6, v8, v14}, Ltm/j;-><init>(Ljava/util/ArrayList;Lg4/d;I)V

    .line 857
    .line 858
    .line 859
    new-instance v15, Ltm/j;

    .line 860
    .line 861
    const/4 v14, 0x1

    .line 862
    invoke-direct {v15, v7, v8, v14}, Ltm/j;-><init>(Ljava/util/ArrayList;Lg4/d;I)V

    .line 863
    .line 864
    .line 865
    new-instance v14, Ltm/d;

    .line 866
    .line 867
    move-object/from16 v17, v5

    .line 868
    .line 869
    move-object/from16 v18, v6

    .line 870
    .line 871
    sget-wide v5, Le3/s;->i:J

    .line 872
    .line 873
    move-object/from16 v21, v0

    .line 874
    .line 875
    move-object/from16 v19, v1

    .line 876
    .line 877
    sget-wide v0, Lt4/o;->c:J

    .line 878
    .line 879
    invoke-direct {v14}, Ljava/lang/Object;-><init>()V

    .line 880
    .line 881
    .line 882
    iput-wide v3, v14, Ltm/d;->a:J

    .line 883
    .line 884
    iput-wide v5, v14, Ltm/d;->b:J

    .line 885
    .line 886
    iput-wide v0, v14, Ltm/d;->c:J

    .line 887
    .line 888
    move-wide/from16 v22, v3

    .line 889
    .line 890
    const/4 v3, 0x0

    .line 891
    iput-object v3, v14, Ltm/d;->d:Lk4/x;

    .line 892
    .line 893
    iput-object v3, v14, Ltm/d;->e:Lk4/t;

    .line 894
    .line 895
    iput-object v3, v14, Ltm/d;->f:Lk4/n;

    .line 896
    .line 897
    iput-wide v0, v14, Ltm/d;->g:J

    .line 898
    .line 899
    iput-object v3, v14, Ltm/d;->h:Lr4/a;

    .line 900
    .line 901
    iput-wide v5, v14, Ltm/d;->i:J

    .line 902
    .line 903
    iput-object v3, v14, Ltm/d;->j:Lr4/l;

    .line 904
    .line 905
    iput-object v3, v14, Ltm/d;->k:Lr4/p;

    .line 906
    .line 907
    iput-object v3, v14, Ltm/d;->l:Ln4/b;

    .line 908
    .line 909
    iput-object v3, v14, Ltm/d;->m:Lg4/g0;

    .line 910
    .line 911
    check-cast v9, Ljava/lang/Iterable;

    .line 912
    .line 913
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 914
    .line 915
    .line 916
    move-result-object v0

    .line 917
    :goto_18
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 918
    .line 919
    .line 920
    move-result v1

    .line 921
    if-eqz v1, :cond_33

    .line 922
    .line 923
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 924
    .line 925
    .line 926
    move-result-object v1

    .line 927
    instance-of v4, v1, Landroid/text/style/ImageSpan;

    .line 928
    .line 929
    const-string v5, "range"

    .line 930
    .line 931
    if-eqz v4, :cond_1e

    .line 932
    .line 933
    move-object/from16 v25, v1

    .line 934
    .line 935
    check-cast v25, Landroid/text/style/ImageSpan;

    .line 936
    .line 937
    invoke-static {v11, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 938
    .line 939
    .line 940
    new-instance v24, Ltm/c;

    .line 941
    .line 942
    new-instance v4, Ljava/lang/StringBuilder;

    .line 943
    .line 944
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 945
    .line 946
    .line 947
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 948
    .line 949
    .line 950
    move-result-wide v5

    .line 951
    invoke-virtual {v4, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 952
    .line 953
    .line 954
    invoke-virtual/range {v25 .. v25}, Ljava/lang/Object;->hashCode()I

    .line 955
    .line 956
    .line 957
    move-result v5

    .line 958
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 959
    .line 960
    .line 961
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 962
    .line 963
    .line 964
    move-result-object v26

    .line 965
    iget v4, v11, Lgy0/h;->d:I

    .line 966
    .line 967
    iget v5, v11, Lgy0/h;->e:I

    .line 968
    .line 969
    new-instance v29, Ltm/f;

    .line 970
    .line 971
    invoke-direct/range {v29 .. v29}, Ljava/lang/Object;-><init>()V

    .line 972
    .line 973
    .line 974
    move/from16 v27, v4

    .line 975
    .line 976
    move/from16 v28, v5

    .line 977
    .line 978
    invoke-direct/range {v24 .. v29}, Ltm/c;-><init>(Landroid/text/style/ImageSpan;Ljava/lang/String;IILtm/f;)V

    .line 979
    .line 980
    .line 981
    move-object/from16 v4, v24

    .line 982
    .line 983
    invoke-virtual {v13, v4}, Ltm/j;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 984
    .line 985
    .line 986
    :cond_1d
    :goto_19
    move-object/from16 v24, v0

    .line 987
    .line 988
    goto/16 :goto_24

    .line 989
    .line 990
    :cond_1e
    instance-of v4, v1, Landroid/text/style/URLSpan;

    .line 991
    .line 992
    if-eqz v4, :cond_1f

    .line 993
    .line 994
    move-object v4, v1

    .line 995
    check-cast v4, Landroid/text/style/URLSpan;

    .line 996
    .line 997
    iput-object v4, v14, Ltm/d;->n:Landroid/text/style/URLSpan;

    .line 998
    .line 999
    invoke-virtual {v12, v1}, La3/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1000
    .line 1001
    .line 1002
    goto :goto_19

    .line 1003
    :cond_1f
    instance-of v4, v1, Landroid/text/style/LeadingMarginSpan;

    .line 1004
    .line 1005
    if-eqz v4, :cond_1d

    .line 1006
    .line 1007
    move-object v4, v1

    .line 1008
    check-cast v4, Landroid/text/style/LeadingMarginSpan;

    .line 1009
    .line 1010
    invoke-static {v4}, Lkp/ea;->c(Landroid/text/style/LeadingMarginSpan;)Z

    .line 1011
    .line 1012
    .line 1013
    move-result v4

    .line 1014
    if-eqz v4, :cond_1d

    .line 1015
    .line 1016
    invoke-static {v11, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1017
    .line 1018
    .line 1019
    instance-of v4, v1, Landroid/text/style/BulletSpan;

    .line 1020
    .line 1021
    if-eqz v4, :cond_24

    .line 1022
    .line 1023
    move-object v4, v1

    .line 1024
    check-cast v4, Landroid/text/style/BulletSpan;

    .line 1025
    .line 1026
    instance-of v5, v4, Ltm/b;

    .line 1027
    .line 1028
    if-eqz v5, :cond_22

    .line 1029
    .line 1030
    new-instance v5, Ltm/f;

    .line 1031
    .line 1032
    move-object v6, v4

    .line 1033
    check-cast v6, Ltm/b;

    .line 1034
    .line 1035
    iget v6, v6, Ltm/b;->d:I

    .line 1036
    .line 1037
    if-eqz v6, :cond_20

    .line 1038
    .line 1039
    const/4 v9, 0x1

    .line 1040
    goto :goto_1a

    .line 1041
    :cond_20
    const/4 v9, 0x0

    .line 1042
    :goto_1a
    if-eqz v9, :cond_21

    .line 1043
    .line 1044
    invoke-static {v6}, Le3/j0;->c(I)J

    .line 1045
    .line 1046
    .line 1047
    goto :goto_1b

    .line 1048
    :cond_21
    sget v6, Le3/s;->j:I

    .line 1049
    .line 1050
    :goto_1b
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1051
    .line 1052
    .line 1053
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v4

    .line 1057
    :goto_1c
    move-object/from16 v24, v0

    .line 1058
    .line 1059
    goto/16 :goto_23

    .line 1060
    .line 1061
    :cond_22
    new-instance v5, Ltm/f;

    .line 1062
    .line 1063
    invoke-virtual {v4}, Landroid/text/style/BulletSpan;->getColor()I

    .line 1064
    .line 1065
    .line 1066
    move-result v6

    .line 1067
    if-eqz v6, :cond_23

    .line 1068
    .line 1069
    invoke-virtual {v4}, Landroid/text/style/BulletSpan;->getColor()I

    .line 1070
    .line 1071
    .line 1072
    move-result v6

    .line 1073
    invoke-static {v6}, Le3/j0;->c(I)J

    .line 1074
    .line 1075
    .line 1076
    goto :goto_1d

    .line 1077
    :cond_23
    sget v6, Le3/s;->j:I

    .line 1078
    .line 1079
    :goto_1d
    invoke-virtual {v4}, Landroid/text/style/BulletSpan;->getBulletRadius()I

    .line 1080
    .line 1081
    .line 1082
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1083
    .line 1084
    .line 1085
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1086
    .line 1087
    .line 1088
    move-result-object v4

    .line 1089
    goto :goto_1c

    .line 1090
    :cond_24
    instance-of v4, v1, Landroid/text/style/QuoteSpan;

    .line 1091
    .line 1092
    if-eqz v4, :cond_26

    .line 1093
    .line 1094
    move-object v4, v1

    .line 1095
    check-cast v4, Landroid/text/style/QuoteSpan;

    .line 1096
    .line 1097
    instance-of v5, v4, Ltm/g;

    .line 1098
    .line 1099
    if-eqz v5, :cond_25

    .line 1100
    .line 1101
    new-instance v5, Ltm/f;

    .line 1102
    .line 1103
    move-object v6, v4

    .line 1104
    check-cast v6, Ltm/g;

    .line 1105
    .line 1106
    iget v6, v6, Ltm/g;->d:I

    .line 1107
    .line 1108
    invoke-static {v6}, Le3/j0;->c(I)J

    .line 1109
    .line 1110
    .line 1111
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1112
    .line 1113
    .line 1114
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1115
    .line 1116
    .line 1117
    move-result-object v4

    .line 1118
    goto :goto_1c

    .line 1119
    :cond_25
    new-instance v5, Ltm/f;

    .line 1120
    .line 1121
    invoke-virtual {v4}, Landroid/text/style/QuoteSpan;->getColor()I

    .line 1122
    .line 1123
    .line 1124
    move-result v6

    .line 1125
    invoke-static {v6}, Le3/j0;->c(I)J

    .line 1126
    .line 1127
    .line 1128
    invoke-virtual {v4}, Landroid/text/style/QuoteSpan;->getStripeWidth()I

    .line 1129
    .line 1130
    .line 1131
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1132
    .line 1133
    .line 1134
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1135
    .line 1136
    .line 1137
    move-result-object v4

    .line 1138
    goto :goto_1c

    .line 1139
    :cond_26
    instance-of v4, v1, Landroid/text/style/IconMarginSpan;

    .line 1140
    .line 1141
    if-eqz v4, :cond_27

    .line 1142
    .line 1143
    move-object v4, v1

    .line 1144
    check-cast v4, Landroid/text/style/IconMarginSpan;

    .line 1145
    .line 1146
    new-instance v5, Ltm/f;

    .line 1147
    .line 1148
    :try_start_0
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1149
    .line 1150
    .line 1151
    move-result-object v6

    .line 1152
    const-string v9, "mBitmap"

    .line 1153
    .line 1154
    invoke-virtual {v6, v9}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v6

    .line 1158
    const/4 v9, 0x1

    .line 1159
    invoke-virtual {v6, v9}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 1160
    .line 1161
    .line 1162
    invoke-virtual {v6, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 1163
    .line 1164
    .line 1165
    :catch_0
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1166
    .line 1167
    .line 1168
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1169
    .line 1170
    .line 1171
    move-result-object v4

    .line 1172
    goto :goto_1c

    .line 1173
    :cond_27
    instance-of v4, v1, Landroid/text/style/DrawableMarginSpan;

    .line 1174
    .line 1175
    if-eqz v4, :cond_2c

    .line 1176
    .line 1177
    move-object v4, v1

    .line 1178
    check-cast v4, Landroid/text/style/DrawableMarginSpan;

    .line 1179
    .line 1180
    new-instance v5, Ltm/f;

    .line 1181
    .line 1182
    :try_start_1
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v6

    .line 1186
    const-string v9, "mDrawable"

    .line 1187
    .line 1188
    invoke-virtual {v6, v9}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 1189
    .line 1190
    .line 1191
    move-result-object v6

    .line 1192
    const/4 v9, 0x1

    .line 1193
    invoke-virtual {v6, v9}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 1194
    .line 1195
    .line 1196
    invoke-virtual {v6, v4}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v6

    .line 1200
    instance-of v9, v6, Landroid/graphics/drawable/Drawable;

    .line 1201
    .line 1202
    if-eqz v9, :cond_28

    .line 1203
    .line 1204
    check-cast v6, Landroid/graphics/drawable/Drawable;

    .line 1205
    .line 1206
    goto :goto_1e

    .line 1207
    :cond_28
    move-object v6, v3

    .line 1208
    :goto_1e
    if-eqz v6, :cond_2b

    .line 1209
    .line 1210
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getMinimumWidth()I

    .line 1211
    .line 1212
    .line 1213
    move-result v9

    .line 1214
    if-lez v9, :cond_29

    .line 1215
    .line 1216
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getMinimumWidth()I

    .line 1217
    .line 1218
    .line 1219
    move-result v9

    .line 1220
    goto :goto_1f

    .line 1221
    :cond_29
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 1222
    .line 1223
    .line 1224
    move-result-object v9

    .line 1225
    invoke-virtual {v9}, Landroid/graphics/Rect;->width()I

    .line 1226
    .line 1227
    .line 1228
    move-result v9

    .line 1229
    invoke-static {v9}, Ljava/lang/Math;->abs(I)I

    .line 1230
    .line 1231
    .line 1232
    move-result v9

    .line 1233
    :goto_1f
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getMinimumHeight()I

    .line 1234
    .line 1235
    .line 1236
    move-result v24

    .line 1237
    if-lez v24, :cond_2a

    .line 1238
    .line 1239
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getMinimumHeight()I

    .line 1240
    .line 1241
    .line 1242
    move-result v24

    .line 1243
    :goto_20
    move/from16 v3, v24

    .line 1244
    .line 1245
    move-object/from16 v24, v0

    .line 1246
    .line 1247
    goto :goto_21

    .line 1248
    :cond_2a
    invoke-virtual {v6}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 1249
    .line 1250
    .line 1251
    move-result-object v24

    .line 1252
    invoke-virtual/range {v24 .. v24}, Landroid/graphics/Rect;->height()I

    .line 1253
    .line 1254
    .line 1255
    move-result v24

    .line 1256
    invoke-static/range {v24 .. v24}, Ljava/lang/Math;->abs(I)I

    .line 1257
    .line 1258
    .line 1259
    move-result v24
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 1260
    goto :goto_20

    .line 1261
    :goto_21
    const/4 v0, 0x4

    .line 1262
    :try_start_2
    invoke-static {v6, v9, v3, v0}, Lkp/m9;->b(Landroid/graphics/drawable/Drawable;III)Landroid/graphics/Bitmap;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    .line 1263
    .line 1264
    .line 1265
    goto :goto_22

    .line 1266
    :catch_1
    :cond_2b
    move-object/from16 v24, v0

    .line 1267
    .line 1268
    :catch_2
    :goto_22
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 1269
    .line 1270
    .line 1271
    invoke-static {v4, v11, v5}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1272
    .line 1273
    .line 1274
    move-result-object v0

    .line 1275
    move-object v4, v0

    .line 1276
    goto :goto_23

    .line 1277
    :cond_2c
    move-object/from16 v24, v0

    .line 1278
    .line 1279
    instance-of v0, v1, Landroid/text/style/LeadingMarginSpan$Standard;

    .line 1280
    .line 1281
    if-eqz v0, :cond_2d

    .line 1282
    .line 1283
    move-object v0, v1

    .line 1284
    check-cast v0, Landroid/text/style/LeadingMarginSpan$Standard;

    .line 1285
    .line 1286
    sget-object v3, Ltm/f;->a:Ltm/f;

    .line 1287
    .line 1288
    invoke-static {v0, v11, v3}, Lkp/fa;->a(Landroid/text/style/LeadingMarginSpan;Lgy0/j;Ltm/f;)Ltm/e;

    .line 1289
    .line 1290
    .line 1291
    move-result-object v4

    .line 1292
    :goto_23
    invoke-virtual {v15, v4}, Ltm/j;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1293
    .line 1294
    .line 1295
    goto :goto_24

    .line 1296
    :cond_2d
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1297
    .line 1298
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1299
    .line 1300
    .line 1301
    move-result-object v1

    .line 1302
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v1

    .line 1306
    const-string v2, " is not supported!"

    .line 1307
    .line 1308
    invoke-virtual {v1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v1

    .line 1312
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1313
    .line 1314
    .line 1315
    throw v0

    .line 1316
    :goto_24
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1317
    .line 1318
    .line 1319
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v0

    .line 1323
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 1324
    .line 1325
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1326
    .line 1327
    .line 1328
    move-result-object v0

    .line 1329
    invoke-interface {v2, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 1330
    .line 1331
    .line 1332
    move-result v0

    .line 1333
    const/4 v4, 0x2

    .line 1334
    if-eqz v0, :cond_2f

    .line 1335
    .line 1336
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1337
    .line 1338
    .line 1339
    move-result-object v0

    .line 1340
    invoke-virtual {v3, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 1341
    .line 1342
    .line 1343
    move-result-object v0

    .line 1344
    invoke-virtual {v2, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1345
    .line 1346
    .line 1347
    move-result-object v0

    .line 1348
    invoke-static {v4, v0}, Lkotlin/jvm/internal/j0;->g(ILjava/lang/Object;)Z

    .line 1349
    .line 1350
    .line 1351
    move-result v3

    .line 1352
    if-eqz v3, :cond_2e

    .line 1353
    .line 1354
    check-cast v0, Lay0/n;

    .line 1355
    .line 1356
    goto :goto_26

    .line 1357
    :cond_2e
    const/4 v0, 0x0

    .line 1358
    goto :goto_26

    .line 1359
    :cond_2f
    invoke-virtual {v2}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 1360
    .line 1361
    .line 1362
    move-result-object v0

    .line 1363
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v0

    .line 1367
    :cond_30
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1368
    .line 1369
    .line 1370
    move-result v3

    .line 1371
    if-eqz v3, :cond_31

    .line 1372
    .line 1373
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1374
    .line 1375
    .line 1376
    move-result-object v3

    .line 1377
    check-cast v3, Ljava/util/Map$Entry;

    .line 1378
    .line 1379
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1380
    .line 1381
    .line 1382
    move-result-object v5

    .line 1383
    if-eqz v5, :cond_30

    .line 1384
    .line 1385
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 1386
    .line 1387
    .line 1388
    move-result-object v5

    .line 1389
    check-cast v5, Lhy0/d;

    .line 1390
    .line 1391
    invoke-interface {v5, v1}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 1392
    .line 1393
    .line 1394
    move-result v5

    .line 1395
    if-eqz v5, :cond_30

    .line 1396
    .line 1397
    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 1398
    .line 1399
    .line 1400
    move-result-object v0

    .line 1401
    goto :goto_25

    .line 1402
    :cond_31
    const/4 v0, 0x0

    .line 1403
    :goto_25
    invoke-static {v4, v0}, Lkotlin/jvm/internal/j0;->g(ILjava/lang/Object;)Z

    .line 1404
    .line 1405
    .line 1406
    move-result v3

    .line 1407
    if-eqz v3, :cond_2e

    .line 1408
    .line 1409
    check-cast v0, Lay0/n;

    .line 1410
    .line 1411
    :goto_26
    if-eqz v0, :cond_32

    .line 1412
    .line 1413
    invoke-interface {v0, v14, v1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1414
    .line 1415
    .line 1416
    :cond_32
    move-object/from16 v0, v24

    .line 1417
    .line 1418
    const/4 v3, 0x0

    .line 1419
    goto/16 :goto_18

    .line 1420
    .line 1421
    :cond_33
    iget-object v0, v14, Ltm/d;->n:Landroid/text/style/URLSpan;

    .line 1422
    .line 1423
    if-eqz v0, :cond_34

    .line 1424
    .line 1425
    iget-wide v0, v14, Ltm/d;->b:J

    .line 1426
    .line 1427
    sget-wide v3, Le3/s;->i:J

    .line 1428
    .line 1429
    cmp-long v0, v0, v3

    .line 1430
    .line 1431
    if-nez v0, :cond_34

    .line 1432
    .line 1433
    iget-wide v0, v14, Ltm/d;->a:J

    .line 1434
    .line 1435
    :goto_27
    move-wide/from16 v25, v0

    .line 1436
    .line 1437
    goto :goto_28

    .line 1438
    :cond_34
    iget-wide v0, v14, Ltm/d;->b:J

    .line 1439
    .line 1440
    goto :goto_27

    .line 1441
    :goto_28
    iget-wide v0, v14, Ltm/d;->c:J

    .line 1442
    .line 1443
    iget-object v3, v14, Ltm/d;->d:Lk4/x;

    .line 1444
    .line 1445
    iget-object v4, v14, Ltm/d;->e:Lk4/t;

    .line 1446
    .line 1447
    iget-object v5, v14, Ltm/d;->f:Lk4/n;

    .line 1448
    .line 1449
    iget-wide v12, v14, Ltm/d;->g:J

    .line 1450
    .line 1451
    iget-object v6, v14, Ltm/d;->h:Lr4/a;

    .line 1452
    .line 1453
    move-wide/from16 v27, v0

    .line 1454
    .line 1455
    iget-wide v0, v14, Ltm/d;->i:J

    .line 1456
    .line 1457
    iget-object v9, v14, Ltm/d;->j:Lr4/l;

    .line 1458
    .line 1459
    iget-object v15, v14, Ltm/d;->l:Ln4/b;

    .line 1460
    .line 1461
    move-wide/from16 v38, v0

    .line 1462
    .line 1463
    iget-object v0, v14, Ltm/d;->k:Lr4/p;

    .line 1464
    .line 1465
    new-instance v24, Lg4/g0;

    .line 1466
    .line 1467
    const/16 v32, 0x0

    .line 1468
    .line 1469
    const/16 v41, 0x0

    .line 1470
    .line 1471
    move-object/from16 v36, v0

    .line 1472
    .line 1473
    move-object/from16 v29, v3

    .line 1474
    .line 1475
    move-object/from16 v30, v4

    .line 1476
    .line 1477
    move-object/from16 v31, v5

    .line 1478
    .line 1479
    move-object/from16 v35, v6

    .line 1480
    .line 1481
    move-object/from16 v40, v9

    .line 1482
    .line 1483
    move-wide/from16 v33, v12

    .line 1484
    .line 1485
    move-object/from16 v37, v15

    .line 1486
    .line 1487
    invoke-direct/range {v24 .. v41}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;)V

    .line 1488
    .line 1489
    .line 1490
    move-object/from16 v0, v24

    .line 1491
    .line 1492
    iget-object v1, v14, Ltm/d;->m:Lg4/g0;

    .line 1493
    .line 1494
    invoke-virtual {v0, v1}, Lg4/g0;->d(Lg4/g0;)Lg4/g0;

    .line 1495
    .line 1496
    .line 1497
    move-result-object v0

    .line 1498
    iget v1, v11, Lgy0/h;->d:I

    .line 1499
    .line 1500
    iget v3, v11, Lgy0/h;->e:I

    .line 1501
    .line 1502
    invoke-virtual {v8, v0, v1, v3}, Lg4/d;->b(Lg4/g0;II)V

    .line 1503
    .line 1504
    .line 1505
    move-object/from16 v5, v17

    .line 1506
    .line 1507
    move-object/from16 v6, v18

    .line 1508
    .line 1509
    move-object/from16 v1, v19

    .line 1510
    .line 1511
    move-object/from16 v0, v21

    .line 1512
    .line 1513
    move-wide/from16 v3, v22

    .line 1514
    .line 1515
    goto/16 :goto_17

    .line 1516
    .line 1517
    :cond_35
    move-object/from16 v19, v1

    .line 1518
    .line 1519
    move-object/from16 v18, v6

    .line 1520
    .line 1521
    invoke-virtual {v8}, Lg4/d;->j()Lg4/g;

    .line 1522
    .line 1523
    .line 1524
    move-result-object v0

    .line 1525
    invoke-virtual/range {v18 .. v18}, Ljava/util/ArrayList;->size()I

    .line 1526
    .line 1527
    .line 1528
    move-result v1

    .line 1529
    const/4 v9, 0x1

    .line 1530
    if-gt v1, v9, :cond_36

    .line 1531
    .line 1532
    invoke-static/range {v18 .. v18}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 1533
    .line 1534
    .line 1535
    :cond_36
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 1536
    .line 1537
    .line 1538
    move-result v1

    .line 1539
    if-gt v1, v9, :cond_37

    .line 1540
    .line 1541
    invoke-static {v7}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 1542
    .line 1543
    .line 1544
    :cond_37
    move-object/from16 v1, v19

    .line 1545
    .line 1546
    invoke-virtual {v1, v0}, Lg4/d;->c(Lg4/g;)V

    .line 1547
    .line 1548
    .line 1549
    return-object v20

    .line 1550
    :pswitch_0
    move-object/from16 v20, v2

    .line 1551
    .line 1552
    move-object/from16 v1, p1

    .line 1553
    .line 1554
    check-cast v1, Ld4/l;

    .line 1555
    .line 1556
    invoke-static {v1, v0}, Ld4/x;->d(Ld4/l;Ljava/lang/String;)V

    .line 1557
    .line 1558
    .line 1559
    return-object v20

    .line 1560
    nop

    .line 1561
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
