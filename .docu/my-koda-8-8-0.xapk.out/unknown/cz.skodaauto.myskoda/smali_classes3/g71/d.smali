.class public final Lg71/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le3/n0;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lg71/d;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lg71/d;->b:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(JLt4/m;Lt4/c;)Le3/g0;
    .locals 15

    .line 1
    move-object/from16 v1, p3

    .line 2
    .line 3
    move-object/from16 v2, p4

    .line 4
    .line 5
    iget v3, p0, Lg71/d;->a:I

    .line 6
    .line 7
    packed-switch v3, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    const-string v3, "layoutDirection"

    .line 11
    .line 12
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v1, "density"

    .line 16
    .line 17
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance v1, Le3/d0;

    .line 21
    .line 22
    const/16 v2, 0x20

    .line 23
    .line 24
    shr-long v2, p1, v2

    .line 25
    .line 26
    long-to-int v2, v2

    .line 27
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    const/high16 v3, 0x430c0000    # 140.0f

    .line 32
    .line 33
    div-float/2addr v2, v3

    .line 34
    const-wide v3, 0xffffffffL

    .line 35
    .line 36
    .line 37
    .line 38
    .line 39
    and-long v3, p1, v3

    .line 40
    .line 41
    long-to-int v3, v3

    .line 42
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    const/high16 v4, 0x425c0000    # 55.0f

    .line 47
    .line 48
    div-float/2addr v3, v4

    .line 49
    const-string v4, "[0-9]+[.]?([0-9]+)?"

    .line 50
    .line 51
    invoke-static {v4}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    iget-object v0, p0, Lg71/d;->b:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {v4, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    new-instance v4, Ljava/lang/StringBuffer;

    .line 64
    .line 65
    invoke-direct {v4}, Ljava/lang/StringBuffer;-><init>()V

    .line 66
    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    :goto_0
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->find()Z

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    if-eqz v6, :cond_1

    .line 74
    .line 75
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->group()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    const-string v7, "group(...)"

    .line 80
    .line 81
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v6}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    rem-int/lit8 v7, v5, 0x2

    .line 89
    .line 90
    if-nez v7, :cond_0

    .line 91
    .line 92
    mul-float/2addr v6, v2

    .line 93
    goto :goto_1

    .line 94
    :cond_0
    mul-float/2addr v6, v3

    .line 95
    :goto_1
    invoke-static {v6}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object v6

    .line 99
    invoke-virtual {v0, v4, v6}, Ljava/util/regex/Matcher;->appendReplacement(Ljava/lang/StringBuffer;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 100
    .line 101
    .line 102
    add-int/lit8 v5, v5, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_1
    invoke-virtual {v4}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    const-string v2, "toString(...)"

    .line 110
    .line 111
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    invoke-static {v0}, Lkp/c7;->d(Ljava/lang/String;)Landroid/graphics/Path;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    new-instance v2, Le3/i;

    .line 119
    .line 120
    invoke-direct {v2, v0}, Le3/i;-><init>(Landroid/graphics/Path;)V

    .line 121
    .line 122
    .line 123
    invoke-direct {v1, v2}, Le3/d0;-><init>(Le3/i;)V

    .line 124
    .line 125
    .line 126
    return-object v1

    .line 127
    :pswitch_0
    new-instance v1, Le3/d0;

    .line 128
    .line 129
    iget-object v0, p0, Lg71/d;->b:Ljava/lang/Object;

    .line 130
    .line 131
    check-cast v0, Le3/i;

    .line 132
    .line 133
    invoke-direct {v1, v0}, Le3/d0;-><init>(Le3/i;)V

    .line 134
    .line 135
    .line 136
    return-object v1

    .line 137
    :pswitch_1
    const-string v3, "layoutDirection"

    .line 138
    .line 139
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    const-string v1, "density"

    .line 143
    .line 144
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    sget-object v1, Llp/q0;->a:Lh71/n;

    .line 148
    .line 149
    const-string v3, "SkodaRPAPlugin"

    .line 150
    .line 151
    const/4 v4, 0x0

    .line 152
    if-nez v1, :cond_2

    .line 153
    .line 154
    new-instance v1, Lf2/h0;

    .line 155
    .line 156
    const/16 v2, 0x11

    .line 157
    .line 158
    invoke-direct {v1, v2}, Lf2/h0;-><init>(I)V

    .line 159
    .line 160
    .line 161
    invoke-static {p0, v3, v4, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 162
    .line 163
    .line 164
    new-instance v0, Le3/d0;

    .line 165
    .line 166
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    invoke-direct {v0, v1}, Le3/d0;-><init>(Le3/i;)V

    .line 171
    .line 172
    .line 173
    goto/16 :goto_3

    .line 174
    .line 175
    :cond_2
    sget-object v5, Llp/q0;->b:Lh71/t;

    .line 176
    .line 177
    if-nez v5, :cond_3

    .line 178
    .line 179
    new-instance v1, Lf2/h0;

    .line 180
    .line 181
    const/16 v2, 0x12

    .line 182
    .line 183
    invoke-direct {v1, v2}, Lf2/h0;-><init>(I)V

    .line 184
    .line 185
    .line 186
    invoke-static {p0, v3, v4, v1}, Ltechnology/cariad/cat/lcclog/LogFunctionsKt;->logWarn(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 187
    .line 188
    .line 189
    new-instance v0, Le3/d0;

    .line 190
    .line 191
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    invoke-direct {v0, v1}, Le3/d0;-><init>(Le3/i;)V

    .line 196
    .line 197
    .line 198
    goto/16 :goto_3

    .line 199
    .line 200
    :cond_3
    iget v3, v1, Lh71/n;->o:F

    .line 201
    .line 202
    invoke-interface {v2, v3}, Lt4/c;->w0(F)F

    .line 203
    .line 204
    .line 205
    move-result v3

    .line 206
    iget v4, v1, Lh71/n;->p:F

    .line 207
    .line 208
    invoke-interface {v2, v4}, Lt4/c;->w0(F)F

    .line 209
    .line 210
    .line 211
    move-result v4

    .line 212
    iget v5, v5, Lh71/t;->b:F

    .line 213
    .line 214
    invoke-interface {v2, v5}, Lt4/c;->w0(F)F

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    iget v1, v1, Lh71/n;->q:F

    .line 219
    .line 220
    invoke-interface {v2, v1}, Lt4/c;->w0(F)F

    .line 221
    .line 222
    .line 223
    move-result v1

    .line 224
    iget-object v0, p0, Lg71/d;->b:Ljava/lang/Object;

    .line 225
    .line 226
    check-cast v0, Lg71/a;

    .line 227
    .line 228
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    const/high16 v2, 0x40000000    # 2.0f

    .line 233
    .line 234
    const/16 v6, 0x20

    .line 235
    .line 236
    if-eqz v0, :cond_5

    .line 237
    .line 238
    const/4 v1, 0x1

    .line 239
    if-ne v0, v1, :cond_4

    .line 240
    .line 241
    shr-long v0, p1, v6

    .line 242
    .line 243
    long-to-int v0, v0

    .line 244
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 245
    .line 246
    .line 247
    move-result v0

    .line 248
    div-float/2addr v0, v2

    .line 249
    div-float v1, v3, v2

    .line 250
    .line 251
    add-float/2addr v1, v0

    .line 252
    goto :goto_2

    .line 253
    :cond_4
    new-instance v0, La8/r0;

    .line 254
    .line 255
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 256
    .line 257
    .line 258
    throw v0

    .line 259
    :cond_5
    add-float/2addr v1, v3

    .line 260
    :goto_2
    div-float v0, v3, v2

    .line 261
    .line 262
    sub-float v0, v1, v0

    .line 263
    .line 264
    sub-float v2, v1, v3

    .line 265
    .line 266
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 267
    .line 268
    .line 269
    move-result-object v3

    .line 270
    const/4 v7, 0x0

    .line 271
    invoke-virtual {v3, v5, v7}, Le3/i;->h(FF)V

    .line 272
    .line 273
    .line 274
    shr-long v8, p1, v6

    .line 275
    .line 276
    long-to-int v8, v8

    .line 277
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 278
    .line 279
    .line 280
    move-result v9

    .line 281
    sub-float/2addr v9, v5

    .line 282
    invoke-virtual {v3, v9, v7}, Le3/i;->g(FF)V

    .line 283
    .line 284
    .line 285
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 286
    .line 287
    .line 288
    move-result v9

    .line 289
    sub-float/2addr v9, v5

    .line 290
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 291
    .line 292
    .line 293
    move-result v9

    .line 294
    int-to-long v9, v9

    .line 295
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 296
    .line 297
    .line 298
    move-result v11

    .line 299
    int-to-long v11, v11

    .line 300
    shl-long/2addr v9, v6

    .line 301
    const-wide v13, 0xffffffffL

    .line 302
    .line 303
    .line 304
    .line 305
    .line 306
    and-long/2addr v11, v13

    .line 307
    or-long/2addr v9, v11

    .line 308
    invoke-static {v9, v10, v5}, Ljp/cf;->b(JF)Ld3/c;

    .line 309
    .line 310
    .line 311
    move-result-object v9

    .line 312
    const/high16 v10, 0x43870000    # 270.0f

    .line 313
    .line 314
    const/high16 v11, 0x42b40000    # 90.0f

    .line 315
    .line 316
    invoke-virtual {v3, v9, v10, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 317
    .line 318
    .line 319
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 320
    .line 321
    .line 322
    move-result v9

    .line 323
    move-wide/from16 p3, v13

    .line 324
    .line 325
    and-long v13, p1, p3

    .line 326
    .line 327
    long-to-int v10, v13

    .line 328
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 329
    .line 330
    .line 331
    move-result v12

    .line 332
    sub-float/2addr v12, v4

    .line 333
    sub-float/2addr v12, v5

    .line 334
    invoke-virtual {v3, v9, v12}, Le3/i;->g(FF)V

    .line 335
    .line 336
    .line 337
    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 338
    .line 339
    .line 340
    move-result v8

    .line 341
    sub-float/2addr v8, v5

    .line 342
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 343
    .line 344
    .line 345
    move-result v9

    .line 346
    sub-float/2addr v9, v4

    .line 347
    sub-float/2addr v9, v5

    .line 348
    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 349
    .line 350
    .line 351
    move-result v8

    .line 352
    int-to-long v12, v8

    .line 353
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 354
    .line 355
    .line 356
    move-result v8

    .line 357
    int-to-long v8, v8

    .line 358
    shl-long/2addr v12, v6

    .line 359
    and-long v8, v8, p3

    .line 360
    .line 361
    or-long/2addr v8, v12

    .line 362
    invoke-static {v8, v9, v5}, Ljp/cf;->b(JF)Ld3/c;

    .line 363
    .line 364
    .line 365
    move-result-object v8

    .line 366
    invoke-virtual {v3, v8, v7, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 367
    .line 368
    .line 369
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 370
    .line 371
    .line 372
    move-result v8

    .line 373
    sub-float/2addr v8, v4

    .line 374
    invoke-virtual {v3, v1, v8}, Le3/i;->g(FF)V

    .line 375
    .line 376
    .line 377
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 378
    .line 379
    .line 380
    move-result v1

    .line 381
    invoke-virtual {v3, v0, v1}, Le3/i;->g(FF)V

    .line 382
    .line 383
    .line 384
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 385
    .line 386
    .line 387
    move-result v0

    .line 388
    sub-float/2addr v0, v4

    .line 389
    invoke-virtual {v3, v2, v0}, Le3/i;->g(FF)V

    .line 390
    .line 391
    .line 392
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 393
    .line 394
    .line 395
    move-result v0

    .line 396
    sub-float/2addr v0, v4

    .line 397
    sub-float/2addr v0, v5

    .line 398
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 399
    .line 400
    .line 401
    move-result v1

    .line 402
    int-to-long v1, v1

    .line 403
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 404
    .line 405
    .line 406
    move-result v0

    .line 407
    int-to-long v8, v0

    .line 408
    shl-long v0, v1, v6

    .line 409
    .line 410
    and-long v8, v8, p3

    .line 411
    .line 412
    or-long/2addr v0, v8

    .line 413
    invoke-static {v0, v1, v5}, Ljp/cf;->b(JF)Ld3/c;

    .line 414
    .line 415
    .line 416
    move-result-object v0

    .line 417
    invoke-virtual {v3, v0, v11, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 418
    .line 419
    .line 420
    invoke-virtual {v3, v7, v5}, Le3/i;->g(FF)V

    .line 421
    .line 422
    .line 423
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 424
    .line 425
    .line 426
    move-result v0

    .line 427
    int-to-long v0, v0

    .line 428
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 429
    .line 430
    .line 431
    move-result v2

    .line 432
    int-to-long v7, v2

    .line 433
    shl-long/2addr v0, v6

    .line 434
    and-long v6, v7, p3

    .line 435
    .line 436
    or-long/2addr v0, v6

    .line 437
    invoke-static {v0, v1, v5}, Ljp/cf;->b(JF)Ld3/c;

    .line 438
    .line 439
    .line 440
    move-result-object v0

    .line 441
    const/high16 v1, 0x43340000    # 180.0f

    .line 442
    .line 443
    invoke-virtual {v3, v0, v1, v11}, Le3/i;->d(Ld3/c;FF)V

    .line 444
    .line 445
    .line 446
    new-instance v0, Le3/d0;

    .line 447
    .line 448
    invoke-direct {v0, v3}, Le3/d0;-><init>(Le3/i;)V

    .line 449
    .line 450
    .line 451
    :goto_3
    return-object v0

    .line 452
    nop

    .line 453
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
