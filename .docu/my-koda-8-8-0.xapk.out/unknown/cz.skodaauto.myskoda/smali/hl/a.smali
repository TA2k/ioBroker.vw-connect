.class public abstract Lhl/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/u2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lh50/p;

    .line 2
    .line 3
    const/16 v1, 0x1a

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lh50/p;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/u2;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/s1;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lhl/a;->a:Ll2/u2;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Lx2/s;Ll2/b1;Lay0/k;)Lx2/s;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "layoutResult"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "onClick"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Le2/y;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, v1, p1, p2}, Le2/y;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0, p2, v0}, Lp3/f0;->b(Lx2/s;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lx2/s;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method

.method public static final b(Lgl/h;Lg4/g0;Ll2/o;)Lg4/g;
    .locals 36

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p2

    .line 9
    .line 10
    check-cast v1, Ll2/t;

    .line 11
    .line 12
    sget-object v2, Lhl/a;->a:Ll2/u2;

    .line 13
    .line 14
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    check-cast v2, Landroid/content/res/Resources;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    if-nez v2, :cond_0

    .line 22
    .line 23
    const v2, 0x50c60e4

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 27
    .line 28
    .line 29
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Landroid/content/Context;

    .line 36
    .line 37
    invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    :goto_0
    invoke-virtual {v1, v3}, Ll2/t;->q(Z)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_0
    const v4, 0x50c5a5a

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1, v4}, Ll2/t;->Y(I)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :goto_1
    const-string v1, "getResources(...)"

    .line 53
    .line 54
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    invoke-static {v2, v0}, Lkp/a9;->d(Landroid/content/res/Resources;Lgl/h;)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-virtual {v0}, Lgl/h;->h()Z

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    const/4 v2, 0x0

    .line 66
    if-eqz v0, :cond_1

    .line 67
    .line 68
    invoke-static {v1, v3, v2, v2}, Landroid/text/Html;->fromHtml(Ljava/lang/String;ILandroid/text/Html$ImageGetter;Landroid/text/Html$TagHandler;)Landroid/text/Spanned;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    :cond_1
    instance-of v0, v1, Landroid/text/Spanned;

    .line 73
    .line 74
    if-eqz v0, :cond_1d

    .line 75
    .line 76
    check-cast v1, Landroid/text/Spanned;

    .line 77
    .line 78
    new-instance v0, Lg4/d;

    .line 79
    .line 80
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    invoke-direct {v0, v4}, Lg4/d;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    if-nez p1, :cond_2

    .line 88
    .line 89
    new-instance v5, Lg4/g0;

    .line 90
    .line 91
    sget-object v10, Lk4/x;->n:Lk4/x;

    .line 92
    .line 93
    const/16 v23, 0x0

    .line 94
    .line 95
    const v24, 0xfffb

    .line 96
    .line 97
    .line 98
    const-wide/16 v6, 0x0

    .line 99
    .line 100
    const-wide/16 v8, 0x0

    .line 101
    .line 102
    const/4 v11, 0x0

    .line 103
    const/4 v12, 0x0

    .line 104
    const/4 v13, 0x0

    .line 105
    const/4 v14, 0x0

    .line 106
    const-wide/16 v15, 0x0

    .line 107
    .line 108
    const/16 v17, 0x0

    .line 109
    .line 110
    const/16 v18, 0x0

    .line 111
    .line 112
    const/16 v19, 0x0

    .line 113
    .line 114
    const-wide/16 v20, 0x0

    .line 115
    .line 116
    const/16 v22, 0x0

    .line 117
    .line 118
    invoke-direct/range {v5 .. v24}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_2
    move-object/from16 v5, p1

    .line 123
    .line 124
    :goto_2
    move v4, v3

    .line 125
    :goto_3
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-ge v4, v6, :cond_1c

    .line 130
    .line 131
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 132
    .line 133
    .line 134
    move-result v6

    .line 135
    const-class v7, Ljava/lang/Object;

    .line 136
    .line 137
    invoke-interface {v1, v4, v6, v7}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    .line 138
    .line 139
    .line 140
    move-result v6

    .line 141
    invoke-interface {v1, v4, v6, v7}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v7

    .line 145
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    array-length v8, v7

    .line 149
    move v9, v3

    .line 150
    :goto_4
    if-ge v9, v8, :cond_1b

    .line 151
    .line 152
    aget-object v10, v7, v9

    .line 153
    .line 154
    instance-of v11, v10, Landroid/text/style/StyleSpan;

    .line 155
    .line 156
    const-string v12, "Kt"

    .line 157
    .line 158
    const/16 v13, 0x2e

    .line 159
    .line 160
    const/16 v14, 0x24

    .line 161
    .line 162
    if-eqz v11, :cond_7

    .line 163
    .line 164
    check-cast v10, Landroid/text/style/StyleSpan;

    .line 165
    .line 166
    invoke-virtual {v10}, Landroid/text/style/StyleSpan;->getStyle()I

    .line 167
    .line 168
    .line 169
    move-result v11

    .line 170
    const/4 v15, 0x1

    .line 171
    if-eq v11, v15, :cond_6

    .line 172
    .line 173
    const/4 v3, 0x2

    .line 174
    if-eq v11, v3, :cond_5

    .line 175
    .line 176
    const/4 v3, 0x3

    .line 177
    if-eq v11, v3, :cond_4

    .line 178
    .line 179
    sget-object v3, Lgi/b;->g:Lgi/b;

    .line 180
    .line 181
    new-instance v11, Le81/w;

    .line 182
    .line 183
    const/16 v15, 0x17

    .line 184
    .line 185
    invoke-direct {v11, v10, v15}, Le81/w;-><init>(Ljava/lang/Object;I)V

    .line 186
    .line 187
    .line 188
    sget-object v15, Lgi/a;->e:Lgi/a;

    .line 189
    .line 190
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    move-result-object v10

    .line 194
    invoke-virtual {v10}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v10

    .line 198
    invoke-static {v10, v14}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object v14

    .line 202
    invoke-static {v13, v14, v14}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v13

    .line 206
    invoke-virtual {v13}, Ljava/lang/String;->length()I

    .line 207
    .line 208
    .line 209
    move-result v14

    .line 210
    if-nez v14, :cond_3

    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_3
    invoke-static {v13, v12}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 214
    .line 215
    .line 216
    move-result-object v10

    .line 217
    :goto_5
    invoke-static {v10, v15, v3, v2, v11}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 218
    .line 219
    .line 220
    goto/16 :goto_a

    .line 221
    .line 222
    :cond_4
    new-instance v16, Lg4/g0;

    .line 223
    .line 224
    new-instance v3, Lk4/t;

    .line 225
    .line 226
    invoke-direct {v3, v15}, Lk4/t;-><init>(I)V

    .line 227
    .line 228
    .line 229
    const/16 v34, 0x0

    .line 230
    .line 231
    const v35, 0xfff7

    .line 232
    .line 233
    .line 234
    const-wide/16 v17, 0x0

    .line 235
    .line 236
    const-wide/16 v19, 0x0

    .line 237
    .line 238
    const/16 v21, 0x0

    .line 239
    .line 240
    const/16 v23, 0x0

    .line 241
    .line 242
    const/16 v24, 0x0

    .line 243
    .line 244
    const/16 v25, 0x0

    .line 245
    .line 246
    const-wide/16 v26, 0x0

    .line 247
    .line 248
    const/16 v28, 0x0

    .line 249
    .line 250
    const/16 v29, 0x0

    .line 251
    .line 252
    const/16 v30, 0x0

    .line 253
    .line 254
    const-wide/16 v31, 0x0

    .line 255
    .line 256
    const/16 v33, 0x0

    .line 257
    .line 258
    move-object/from16 v22, v3

    .line 259
    .line 260
    invoke-direct/range {v16 .. v35}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 261
    .line 262
    .line 263
    move-object/from16 v3, v16

    .line 264
    .line 265
    invoke-virtual {v0, v3, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 266
    .line 267
    .line 268
    new-instance v10, Lg4/g0;

    .line 269
    .line 270
    sget-object v15, Lk4/x;->n:Lk4/x;

    .line 271
    .line 272
    const v29, 0xfffb

    .line 273
    .line 274
    .line 275
    const-wide/16 v11, 0x0

    .line 276
    .line 277
    const-wide/16 v13, 0x0

    .line 278
    .line 279
    const/16 v16, 0x0

    .line 280
    .line 281
    const/16 v17, 0x0

    .line 282
    .line 283
    const/16 v18, 0x0

    .line 284
    .line 285
    const/16 v19, 0x0

    .line 286
    .line 287
    const-wide/16 v20, 0x0

    .line 288
    .line 289
    const/16 v22, 0x0

    .line 290
    .line 291
    const-wide/16 v25, 0x0

    .line 292
    .line 293
    const/16 v27, 0x0

    .line 294
    .line 295
    invoke-direct/range {v10 .. v29}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v0, v10, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 299
    .line 300
    .line 301
    goto/16 :goto_a

    .line 302
    .line 303
    :cond_5
    new-instance v11, Lg4/g0;

    .line 304
    .line 305
    new-instance v3, Lk4/t;

    .line 306
    .line 307
    invoke-direct {v3, v15}, Lk4/t;-><init>(I)V

    .line 308
    .line 309
    .line 310
    const/16 v29, 0x0

    .line 311
    .line 312
    const v30, 0xfff7

    .line 313
    .line 314
    .line 315
    const-wide/16 v12, 0x0

    .line 316
    .line 317
    const-wide/16 v14, 0x0

    .line 318
    .line 319
    const/16 v16, 0x0

    .line 320
    .line 321
    const/16 v18, 0x0

    .line 322
    .line 323
    const/16 v19, 0x0

    .line 324
    .line 325
    const/16 v20, 0x0

    .line 326
    .line 327
    const-wide/16 v21, 0x0

    .line 328
    .line 329
    const/16 v23, 0x0

    .line 330
    .line 331
    const/16 v24, 0x0

    .line 332
    .line 333
    const/16 v25, 0x0

    .line 334
    .line 335
    const-wide/16 v26, 0x0

    .line 336
    .line 337
    const/16 v28, 0x0

    .line 338
    .line 339
    move-object/from16 v17, v3

    .line 340
    .line 341
    invoke-direct/range {v11 .. v30}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 342
    .line 343
    .line 344
    invoke-virtual {v0, v11, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 345
    .line 346
    .line 347
    goto/16 :goto_a

    .line 348
    .line 349
    :cond_6
    new-instance v12, Lg4/g0;

    .line 350
    .line 351
    sget-object v17, Lk4/x;->n:Lk4/x;

    .line 352
    .line 353
    const/16 v30, 0x0

    .line 354
    .line 355
    const v31, 0xfffb

    .line 356
    .line 357
    .line 358
    const-wide/16 v13, 0x0

    .line 359
    .line 360
    const-wide/16 v15, 0x0

    .line 361
    .line 362
    const/16 v18, 0x0

    .line 363
    .line 364
    const/16 v19, 0x0

    .line 365
    .line 366
    const/16 v20, 0x0

    .line 367
    .line 368
    const/16 v21, 0x0

    .line 369
    .line 370
    const-wide/16 v22, 0x0

    .line 371
    .line 372
    const/16 v24, 0x0

    .line 373
    .line 374
    const/16 v25, 0x0

    .line 375
    .line 376
    const/16 v26, 0x0

    .line 377
    .line 378
    const-wide/16 v27, 0x0

    .line 379
    .line 380
    const/16 v29, 0x0

    .line 381
    .line 382
    invoke-direct/range {v12 .. v31}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 383
    .line 384
    .line 385
    invoke-virtual {v0, v12, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 386
    .line 387
    .line 388
    goto/16 :goto_a

    .line 389
    .line 390
    :cond_7
    instance-of v3, v10, Landroid/text/style/ForegroundColorSpan;

    .line 391
    .line 392
    if-eqz v3, :cond_8

    .line 393
    .line 394
    check-cast v10, Landroid/text/style/ForegroundColorSpan;

    .line 395
    .line 396
    new-instance v11, Lg4/g0;

    .line 397
    .line 398
    invoke-virtual {v10}, Landroid/text/style/ForegroundColorSpan;->getForegroundColor()I

    .line 399
    .line 400
    .line 401
    move-result v3

    .line 402
    invoke-static {v3}, Le3/j0;->c(I)J

    .line 403
    .line 404
    .line 405
    move-result-wide v12

    .line 406
    const/16 v29, 0x0

    .line 407
    .line 408
    const v30, 0xfffe

    .line 409
    .line 410
    .line 411
    const-wide/16 v14, 0x0

    .line 412
    .line 413
    const/16 v16, 0x0

    .line 414
    .line 415
    const/16 v17, 0x0

    .line 416
    .line 417
    const/16 v18, 0x0

    .line 418
    .line 419
    const/16 v19, 0x0

    .line 420
    .line 421
    const/16 v20, 0x0

    .line 422
    .line 423
    const-wide/16 v21, 0x0

    .line 424
    .line 425
    const/16 v23, 0x0

    .line 426
    .line 427
    const/16 v24, 0x0

    .line 428
    .line 429
    const/16 v25, 0x0

    .line 430
    .line 431
    const-wide/16 v26, 0x0

    .line 432
    .line 433
    const/16 v28, 0x0

    .line 434
    .line 435
    invoke-direct/range {v11 .. v30}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v0, v11, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 439
    .line 440
    .line 441
    goto/16 :goto_a

    .line 442
    .line 443
    :cond_8
    instance-of v3, v10, Landroid/text/style/BackgroundColorSpan;

    .line 444
    .line 445
    if-eqz v3, :cond_9

    .line 446
    .line 447
    check-cast v10, Landroid/text/style/BackgroundColorSpan;

    .line 448
    .line 449
    new-instance v11, Lg4/g0;

    .line 450
    .line 451
    invoke-virtual {v10}, Landroid/text/style/BackgroundColorSpan;->getBackgroundColor()I

    .line 452
    .line 453
    .line 454
    move-result v3

    .line 455
    invoke-static {v3}, Le3/j0;->c(I)J

    .line 456
    .line 457
    .line 458
    move-result-wide v26

    .line 459
    const/16 v29, 0x0

    .line 460
    .line 461
    const v30, 0xf7ff

    .line 462
    .line 463
    .line 464
    const-wide/16 v12, 0x0

    .line 465
    .line 466
    const-wide/16 v14, 0x0

    .line 467
    .line 468
    const/16 v16, 0x0

    .line 469
    .line 470
    const/16 v17, 0x0

    .line 471
    .line 472
    const/16 v18, 0x0

    .line 473
    .line 474
    const/16 v19, 0x0

    .line 475
    .line 476
    const/16 v20, 0x0

    .line 477
    .line 478
    const-wide/16 v21, 0x0

    .line 479
    .line 480
    const/16 v23, 0x0

    .line 481
    .line 482
    const/16 v24, 0x0

    .line 483
    .line 484
    const/16 v25, 0x0

    .line 485
    .line 486
    const/16 v28, 0x0

    .line 487
    .line 488
    invoke-direct/range {v11 .. v30}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 489
    .line 490
    .line 491
    invoke-virtual {v0, v11, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 492
    .line 493
    .line 494
    goto/16 :goto_a

    .line 495
    .line 496
    :cond_9
    instance-of v3, v10, Landroid/text/style/UnderlineSpan;

    .line 497
    .line 498
    if-eqz v3, :cond_a

    .line 499
    .line 500
    new-instance v15, Lg4/g0;

    .line 501
    .line 502
    const/16 v33, 0x0

    .line 503
    .line 504
    const v34, 0xefff

    .line 505
    .line 506
    .line 507
    const-wide/16 v16, 0x0

    .line 508
    .line 509
    const-wide/16 v18, 0x0

    .line 510
    .line 511
    const/16 v20, 0x0

    .line 512
    .line 513
    const/16 v21, 0x0

    .line 514
    .line 515
    const/16 v22, 0x0

    .line 516
    .line 517
    const/16 v23, 0x0

    .line 518
    .line 519
    const/16 v24, 0x0

    .line 520
    .line 521
    const-wide/16 v25, 0x0

    .line 522
    .line 523
    const/16 v27, 0x0

    .line 524
    .line 525
    const/16 v28, 0x0

    .line 526
    .line 527
    const/16 v29, 0x0

    .line 528
    .line 529
    const-wide/16 v30, 0x0

    .line 530
    .line 531
    sget-object v32, Lr4/l;->c:Lr4/l;

    .line 532
    .line 533
    invoke-direct/range {v15 .. v34}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v0, v15, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 537
    .line 538
    .line 539
    goto/16 :goto_a

    .line 540
    .line 541
    :cond_a
    instance-of v3, v10, Landroid/text/style/StrikethroughSpan;

    .line 542
    .line 543
    if-eqz v3, :cond_b

    .line 544
    .line 545
    new-instance v15, Lg4/g0;

    .line 546
    .line 547
    const/16 v33, 0x0

    .line 548
    .line 549
    const v34, 0xefff

    .line 550
    .line 551
    .line 552
    const-wide/16 v16, 0x0

    .line 553
    .line 554
    const-wide/16 v18, 0x0

    .line 555
    .line 556
    const/16 v20, 0x0

    .line 557
    .line 558
    const/16 v21, 0x0

    .line 559
    .line 560
    const/16 v22, 0x0

    .line 561
    .line 562
    const/16 v23, 0x0

    .line 563
    .line 564
    const/16 v24, 0x0

    .line 565
    .line 566
    const-wide/16 v25, 0x0

    .line 567
    .line 568
    const/16 v27, 0x0

    .line 569
    .line 570
    const/16 v28, 0x0

    .line 571
    .line 572
    const/16 v29, 0x0

    .line 573
    .line 574
    const-wide/16 v30, 0x0

    .line 575
    .line 576
    sget-object v32, Lr4/l;->d:Lr4/l;

    .line 577
    .line 578
    invoke-direct/range {v15 .. v34}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 579
    .line 580
    .line 581
    invoke-virtual {v0, v15, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 582
    .line 583
    .line 584
    goto/16 :goto_a

    .line 585
    .line 586
    :cond_b
    instance-of v3, v10, Landroid/text/style/SuperscriptSpan;

    .line 587
    .line 588
    if-eqz v3, :cond_c

    .line 589
    .line 590
    new-instance v15, Lg4/g0;

    .line 591
    .line 592
    new-instance v3, Lr4/a;

    .line 593
    .line 594
    const/high16 v10, 0x3f000000    # 0.5f

    .line 595
    .line 596
    invoke-direct {v3, v10}, Lr4/a;-><init>(F)V

    .line 597
    .line 598
    .line 599
    const/16 v33, 0x0

    .line 600
    .line 601
    const v34, 0xfeff

    .line 602
    .line 603
    .line 604
    const-wide/16 v16, 0x0

    .line 605
    .line 606
    const-wide/16 v18, 0x0

    .line 607
    .line 608
    const/16 v20, 0x0

    .line 609
    .line 610
    const/16 v21, 0x0

    .line 611
    .line 612
    const/16 v22, 0x0

    .line 613
    .line 614
    const/16 v23, 0x0

    .line 615
    .line 616
    const/16 v24, 0x0

    .line 617
    .line 618
    const-wide/16 v25, 0x0

    .line 619
    .line 620
    const/16 v28, 0x0

    .line 621
    .line 622
    const/16 v29, 0x0

    .line 623
    .line 624
    const-wide/16 v30, 0x0

    .line 625
    .line 626
    const/16 v32, 0x0

    .line 627
    .line 628
    move-object/from16 v27, v3

    .line 629
    .line 630
    invoke-direct/range {v15 .. v34}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 631
    .line 632
    .line 633
    invoke-virtual {v0, v15, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 634
    .line 635
    .line 636
    goto/16 :goto_a

    .line 637
    .line 638
    :cond_c
    instance-of v3, v10, Landroid/text/style/SubscriptSpan;

    .line 639
    .line 640
    if-eqz v3, :cond_d

    .line 641
    .line 642
    new-instance v15, Lg4/g0;

    .line 643
    .line 644
    new-instance v3, Lr4/a;

    .line 645
    .line 646
    const/high16 v10, -0x41000000    # -0.5f

    .line 647
    .line 648
    invoke-direct {v3, v10}, Lr4/a;-><init>(F)V

    .line 649
    .line 650
    .line 651
    const/16 v33, 0x0

    .line 652
    .line 653
    const v34, 0xfeff

    .line 654
    .line 655
    .line 656
    const-wide/16 v16, 0x0

    .line 657
    .line 658
    const-wide/16 v18, 0x0

    .line 659
    .line 660
    const/16 v20, 0x0

    .line 661
    .line 662
    const/16 v21, 0x0

    .line 663
    .line 664
    const/16 v22, 0x0

    .line 665
    .line 666
    const/16 v23, 0x0

    .line 667
    .line 668
    const/16 v24, 0x0

    .line 669
    .line 670
    const-wide/16 v25, 0x0

    .line 671
    .line 672
    const/16 v28, 0x0

    .line 673
    .line 674
    const/16 v29, 0x0

    .line 675
    .line 676
    const-wide/16 v30, 0x0

    .line 677
    .line 678
    const/16 v32, 0x0

    .line 679
    .line 680
    move-object/from16 v27, v3

    .line 681
    .line 682
    invoke-direct/range {v15 .. v34}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 683
    .line 684
    .line 685
    invoke-virtual {v0, v15, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 686
    .line 687
    .line 688
    goto/16 :goto_a

    .line 689
    .line 690
    :cond_d
    instance-of v3, v10, Landroid/text/style/RelativeSizeSpan;

    .line 691
    .line 692
    if-eqz v3, :cond_e

    .line 693
    .line 694
    check-cast v10, Landroid/text/style/RelativeSizeSpan;

    .line 695
    .line 696
    new-instance v11, Lg4/g0;

    .line 697
    .line 698
    invoke-virtual {v10}, Landroid/text/style/RelativeSizeSpan;->getSizeChange()F

    .line 699
    .line 700
    .line 701
    move-result v3

    .line 702
    const-wide v12, 0x200000000L

    .line 703
    .line 704
    .line 705
    .line 706
    .line 707
    invoke-static {v12, v13, v3}, Lgq/b;->e(JF)J

    .line 708
    .line 709
    .line 710
    move-result-wide v14

    .line 711
    const/16 v29, 0x0

    .line 712
    .line 713
    const v30, 0xfffd

    .line 714
    .line 715
    .line 716
    const-wide/16 v12, 0x0

    .line 717
    .line 718
    const/16 v16, 0x0

    .line 719
    .line 720
    const/16 v17, 0x0

    .line 721
    .line 722
    const/16 v18, 0x0

    .line 723
    .line 724
    const/16 v19, 0x0

    .line 725
    .line 726
    const/16 v20, 0x0

    .line 727
    .line 728
    const-wide/16 v21, 0x0

    .line 729
    .line 730
    const/16 v23, 0x0

    .line 731
    .line 732
    const/16 v24, 0x0

    .line 733
    .line 734
    const/16 v25, 0x0

    .line 735
    .line 736
    const-wide/16 v26, 0x0

    .line 737
    .line 738
    const/16 v28, 0x0

    .line 739
    .line 740
    invoke-direct/range {v11 .. v30}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 741
    .line 742
    .line 743
    invoke-virtual {v0, v11, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 744
    .line 745
    .line 746
    goto/16 :goto_a

    .line 747
    .line 748
    :cond_e
    instance-of v3, v10, Landroid/text/style/TypefaceSpan;

    .line 749
    .line 750
    if-eqz v3, :cond_16

    .line 751
    .line 752
    check-cast v10, Landroid/text/style/TypefaceSpan;

    .line 753
    .line 754
    invoke-virtual {v10}, Landroid/text/style/TypefaceSpan;->getFamily()Ljava/lang/String;

    .line 755
    .line 756
    .line 757
    move-result-object v3

    .line 758
    if-eqz v3, :cond_f

    .line 759
    .line 760
    const-string v10, "\""

    .line 761
    .line 762
    const-string v11, ""

    .line 763
    .line 764
    const/4 v15, 0x0

    .line 765
    invoke-static {v15, v3, v10, v11}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 766
    .line 767
    .line 768
    move-result-object v3

    .line 769
    const-string v10, "\u201c"

    .line 770
    .line 771
    invoke-static {v15, v3, v10, v11}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 772
    .line 773
    .line 774
    move-result-object v3

    .line 775
    goto :goto_6

    .line 776
    :cond_f
    const/4 v15, 0x0

    .line 777
    move-object v3, v2

    .line 778
    :goto_6
    if-eqz v3, :cond_1a

    .line 779
    .line 780
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 781
    .line 782
    .line 783
    move-result v10

    .line 784
    const v11, -0x5b97f43d

    .line 785
    .line 786
    .line 787
    if-eq v10, v11, :cond_14

    .line 788
    .line 789
    const v11, -0x5559f3fd

    .line 790
    .line 791
    .line 792
    if-eq v10, v11, :cond_12

    .line 793
    .line 794
    const v11, 0x684317d

    .line 795
    .line 796
    .line 797
    if-eq v10, v11, :cond_10

    .line 798
    .line 799
    goto/16 :goto_a

    .line 800
    .line 801
    :cond_10
    const-string v10, "serif"

    .line 802
    .line 803
    invoke-virtual {v3, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 804
    .line 805
    .line 806
    move-result v3

    .line 807
    if-nez v3, :cond_11

    .line 808
    .line 809
    goto/16 :goto_a

    .line 810
    .line 811
    :cond_11
    new-instance v16, Lg4/g0;

    .line 812
    .line 813
    const/16 v34, 0x0

    .line 814
    .line 815
    const v35, 0xffdf

    .line 816
    .line 817
    .line 818
    const-wide/16 v17, 0x0

    .line 819
    .line 820
    const-wide/16 v19, 0x0

    .line 821
    .line 822
    const/16 v21, 0x0

    .line 823
    .line 824
    const/16 v22, 0x0

    .line 825
    .line 826
    const/16 v23, 0x0

    .line 827
    .line 828
    sget-object v24, Lk4/n;->f:Lk4/z;

    .line 829
    .line 830
    const/16 v25, 0x0

    .line 831
    .line 832
    const-wide/16 v26, 0x0

    .line 833
    .line 834
    const/16 v28, 0x0

    .line 835
    .line 836
    const/16 v29, 0x0

    .line 837
    .line 838
    const/16 v30, 0x0

    .line 839
    .line 840
    const-wide/16 v31, 0x0

    .line 841
    .line 842
    const/16 v33, 0x0

    .line 843
    .line 844
    invoke-direct/range {v16 .. v35}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 845
    .line 846
    .line 847
    move-object/from16 v3, v16

    .line 848
    .line 849
    invoke-virtual {v0, v3, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 850
    .line 851
    .line 852
    goto/16 :goto_a

    .line 853
    .line 854
    :cond_12
    const-string v10, "monospace"

    .line 855
    .line 856
    invoke-virtual {v3, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 857
    .line 858
    .line 859
    move-result v3

    .line 860
    if-nez v3, :cond_13

    .line 861
    .line 862
    goto/16 :goto_a

    .line 863
    .line 864
    :cond_13
    new-instance v16, Lg4/g0;

    .line 865
    .line 866
    const/16 v34, 0x0

    .line 867
    .line 868
    const v35, 0xffdf

    .line 869
    .line 870
    .line 871
    const-wide/16 v17, 0x0

    .line 872
    .line 873
    const-wide/16 v19, 0x0

    .line 874
    .line 875
    const/16 v21, 0x0

    .line 876
    .line 877
    const/16 v22, 0x0

    .line 878
    .line 879
    const/16 v23, 0x0

    .line 880
    .line 881
    sget-object v24, Lk4/n;->g:Lk4/z;

    .line 882
    .line 883
    const/16 v25, 0x0

    .line 884
    .line 885
    const-wide/16 v26, 0x0

    .line 886
    .line 887
    const/16 v28, 0x0

    .line 888
    .line 889
    const/16 v29, 0x0

    .line 890
    .line 891
    const/16 v30, 0x0

    .line 892
    .line 893
    const-wide/16 v31, 0x0

    .line 894
    .line 895
    const/16 v33, 0x0

    .line 896
    .line 897
    invoke-direct/range {v16 .. v35}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 898
    .line 899
    .line 900
    move-object/from16 v3, v16

    .line 901
    .line 902
    invoke-virtual {v0, v3, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 903
    .line 904
    .line 905
    goto/16 :goto_a

    .line 906
    .line 907
    :cond_14
    const-string v10, "sans-serif"

    .line 908
    .line 909
    invoke-virtual {v3, v10}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 910
    .line 911
    .line 912
    move-result v3

    .line 913
    if-nez v3, :cond_15

    .line 914
    .line 915
    goto/16 :goto_a

    .line 916
    .line 917
    :cond_15
    new-instance v16, Lg4/g0;

    .line 918
    .line 919
    const/16 v34, 0x0

    .line 920
    .line 921
    const v35, 0xffdf

    .line 922
    .line 923
    .line 924
    const-wide/16 v17, 0x0

    .line 925
    .line 926
    const-wide/16 v19, 0x0

    .line 927
    .line 928
    const/16 v21, 0x0

    .line 929
    .line 930
    const/16 v22, 0x0

    .line 931
    .line 932
    const/16 v23, 0x0

    .line 933
    .line 934
    sget-object v24, Lk4/n;->e:Lk4/z;

    .line 935
    .line 936
    const/16 v25, 0x0

    .line 937
    .line 938
    const-wide/16 v26, 0x0

    .line 939
    .line 940
    const/16 v28, 0x0

    .line 941
    .line 942
    const/16 v29, 0x0

    .line 943
    .line 944
    const/16 v30, 0x0

    .line 945
    .line 946
    const-wide/16 v31, 0x0

    .line 947
    .line 948
    const/16 v33, 0x0

    .line 949
    .line 950
    invoke-direct/range {v16 .. v35}, Lg4/g0;-><init>(JJLk4/x;Lk4/t;Lk4/u;Lk4/n;Ljava/lang/String;JLr4/a;Lr4/p;Ln4/b;JLr4/l;Le3/m0;I)V

    .line 951
    .line 952
    .line 953
    move-object/from16 v3, v16

    .line 954
    .line 955
    invoke-virtual {v0, v3, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 956
    .line 957
    .line 958
    goto :goto_a

    .line 959
    :cond_16
    const/4 v15, 0x0

    .line 960
    instance-of v3, v10, Landroid/text/style/URLSpan;

    .line 961
    .line 962
    if-eqz v3, :cond_17

    .line 963
    .line 964
    check-cast v10, Landroid/text/style/URLSpan;

    .line 965
    .line 966
    invoke-virtual {v10}, Landroid/text/style/URLSpan;->getURL()Ljava/lang/String;

    .line 967
    .line 968
    .line 969
    move-result-object v3

    .line 970
    const-string v10, "getURL(...)"

    .line 971
    .line 972
    invoke-static {v3, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 973
    .line 974
    .line 975
    invoke-virtual {v0, v5, v4, v6}, Lg4/d;->b(Lg4/g0;II)V

    .line 976
    .line 977
    .line 978
    const-string v10, "URL_RESOURCE"

    .line 979
    .line 980
    invoke-virtual {v0, v10, v3, v4, v6}, Lg4/d;->a(Ljava/lang/String;Ljava/lang/String;II)V

    .line 981
    .line 982
    .line 983
    goto :goto_a

    .line 984
    :cond_17
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 985
    .line 986
    .line 987
    sget-object v3, Lgi/b;->g:Lgi/b;

    .line 988
    .line 989
    new-instance v11, Lca/k;

    .line 990
    .line 991
    const/4 v15, 0x1

    .line 992
    invoke-direct {v11, v10, v15}, Lca/k;-><init>(Ljava/lang/Object;I)V

    .line 993
    .line 994
    .line 995
    sget-object v15, Lgi/a;->e:Lgi/a;

    .line 996
    .line 997
    instance-of v2, v10, Ljava/lang/String;

    .line 998
    .line 999
    if-eqz v2, :cond_18

    .line 1000
    .line 1001
    check-cast v10, Ljava/lang/String;

    .line 1002
    .line 1003
    :goto_7
    const/4 v2, 0x0

    .line 1004
    goto :goto_9

    .line 1005
    :cond_18
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1006
    .line 1007
    .line 1008
    move-result-object v2

    .line 1009
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 1010
    .line 1011
    .line 1012
    move-result-object v2

    .line 1013
    invoke-static {v2, v14}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v10

    .line 1017
    invoke-static {v13, v10, v10}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1018
    .line 1019
    .line 1020
    move-result-object v10

    .line 1021
    invoke-virtual {v10}, Ljava/lang/String;->length()I

    .line 1022
    .line 1023
    .line 1024
    move-result v13

    .line 1025
    if-nez v13, :cond_19

    .line 1026
    .line 1027
    :goto_8
    move-object v10, v2

    .line 1028
    goto :goto_7

    .line 1029
    :cond_19
    invoke-static {v10, v12}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1030
    .line 1031
    .line 1032
    move-result-object v2

    .line 1033
    goto :goto_8

    .line 1034
    :goto_9
    invoke-static {v10, v15, v3, v2, v11}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 1035
    .line 1036
    .line 1037
    :cond_1a
    :goto_a
    add-int/lit8 v9, v9, 0x1

    .line 1038
    .line 1039
    const/4 v3, 0x0

    .line 1040
    goto/16 :goto_4

    .line 1041
    .line 1042
    :cond_1b
    move v4, v6

    .line 1043
    goto/16 :goto_3

    .line 1044
    .line 1045
    :cond_1c
    invoke-virtual {v0}, Lg4/d;->j()Lg4/g;

    .line 1046
    .line 1047
    .line 1048
    move-result-object v0

    .line 1049
    return-object v0

    .line 1050
    :cond_1d
    new-instance v0, Lg4/g;

    .line 1051
    .line 1052
    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v1

    .line 1056
    invoke-direct {v0, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 1057
    .line 1058
    .line 1059
    return-object v0
.end method
