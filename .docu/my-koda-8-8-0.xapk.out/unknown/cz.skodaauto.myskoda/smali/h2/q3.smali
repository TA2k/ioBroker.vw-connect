.class public abstract Lh2/q3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x8

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Lh2/q3;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Ljava/lang/Long;Ljava/lang/Long;Lay0/n;Li2/z;Lgy0/j;Lh2/g2;Lh2/e8;Lh2/z1;Lc3/q;Ll2/o;I)V
    .locals 31

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v15, p1

    .line 4
    .line 5
    move-object/from16 v0, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v12, p9

    .line 10
    .line 11
    check-cast v12, Ll2/t;

    .line 12
    .line 13
    const v2, 0x51d1f196

    .line 14
    .line 15
    .line 16
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    const/4 v2, 0x4

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v2, 0x2

    .line 28
    :goto_0
    or-int v2, p10, v2

    .line 29
    .line 30
    invoke-virtual {v12, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v6

    .line 34
    if-eqz v6, :cond_1

    .line 35
    .line 36
    const/16 v6, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v6, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v2, v6

    .line 42
    invoke-virtual {v12, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v6

    .line 46
    if-eqz v6, :cond_2

    .line 47
    .line 48
    const/16 v6, 0x100

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/16 v6, 0x80

    .line 52
    .line 53
    :goto_2
    or-int/2addr v2, v6

    .line 54
    invoke-virtual {v12, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    if-eqz v6, :cond_3

    .line 59
    .line 60
    const/16 v6, 0x800

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v6, 0x400

    .line 64
    .line 65
    :goto_3
    or-int/2addr v2, v6

    .line 66
    move-object/from16 v6, p4

    .line 67
    .line 68
    invoke-virtual {v12, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v9

    .line 72
    if-eqz v9, :cond_4

    .line 73
    .line 74
    const/16 v9, 0x4000

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    const/16 v9, 0x2000

    .line 78
    .line 79
    :goto_4
    or-int/2addr v2, v9

    .line 80
    move-object/from16 v9, p5

    .line 81
    .line 82
    invoke-virtual {v12, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v10

    .line 86
    if-eqz v10, :cond_5

    .line 87
    .line 88
    const/high16 v10, 0x20000

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_5
    const/high16 v10, 0x10000

    .line 92
    .line 93
    :goto_5
    or-int/2addr v2, v10

    .line 94
    move-object/from16 v10, p6

    .line 95
    .line 96
    invoke-virtual {v12, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v13

    .line 100
    if-eqz v13, :cond_6

    .line 101
    .line 102
    const/high16 v13, 0x100000

    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_6
    const/high16 v13, 0x80000

    .line 106
    .line 107
    :goto_6
    or-int/2addr v2, v13

    .line 108
    move-object/from16 v13, p7

    .line 109
    .line 110
    invoke-virtual {v12, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v14

    .line 114
    if-eqz v14, :cond_7

    .line 115
    .line 116
    const/high16 v14, 0x800000

    .line 117
    .line 118
    goto :goto_7

    .line 119
    :cond_7
    const/high16 v14, 0x400000

    .line 120
    .line 121
    :goto_7
    or-int/2addr v2, v14

    .line 122
    move-object/from16 v14, p8

    .line 123
    .line 124
    invoke-virtual {v12, v14}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v16

    .line 128
    if-eqz v16, :cond_8

    .line 129
    .line 130
    const/high16 v16, 0x4000000

    .line 131
    .line 132
    goto :goto_8

    .line 133
    :cond_8
    const/high16 v16, 0x2000000

    .line 134
    .line 135
    :goto_8
    or-int v2, v2, v16

    .line 136
    .line 137
    const v16, 0x2492493

    .line 138
    .line 139
    .line 140
    and-int v5, v2, v16

    .line 141
    .line 142
    const v4, 0x2492492

    .line 143
    .line 144
    .line 145
    if-eq v5, v4, :cond_9

    .line 146
    .line 147
    const/4 v4, 0x1

    .line 148
    goto :goto_9

    .line 149
    :cond_9
    const/4 v4, 0x0

    .line 150
    :goto_9
    and-int/lit8 v5, v2, 0x1

    .line 151
    .line 152
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    if-eqz v4, :cond_1e

    .line 157
    .line 158
    iget-object v4, v3, Li2/z;->a:Ljava/util/Locale;

    .line 159
    .line 160
    invoke-virtual {v12, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v4

    .line 164
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    sget-object v8, Ll2/n;->a:Ll2/x0;

    .line 169
    .line 170
    if-nez v4, :cond_a

    .line 171
    .line 172
    if-ne v5, v8, :cond_b

    .line 173
    .line 174
    :cond_a
    iget-object v4, v3, Li2/z;->a:Ljava/util/Locale;

    .line 175
    .line 176
    sget-object v5, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 177
    .line 178
    const/4 v6, 0x0

    .line 179
    invoke-static {v4}, Ljava/time/chrono/Chronology;->ofLocale(Ljava/util/Locale;)Ljava/time/chrono/Chronology;

    .line 180
    .line 181
    .line 182
    move-result-object v11

    .line 183
    invoke-static {v5, v6, v11, v4}, Ljava/time/format/DateTimeFormatterBuilder;->getLocalizedDateTimePattern(Ljava/time/format/FormatStyle;Ljava/time/format/FormatStyle;Ljava/time/chrono/Chronology;Ljava/util/Locale;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    const-string v5, "[^dMy/\\-.]"

    .line 188
    .line 189
    invoke-static {v5}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 190
    .line 191
    .line 192
    move-result-object v5

    .line 193
    const-string v6, "compile(...)"

    .line 194
    .line 195
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    const-string v11, "input"

    .line 199
    .line 200
    invoke-static {v4, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v5, v4}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 204
    .line 205
    .line 206
    move-result-object v4

    .line 207
    const-string v5, ""

    .line 208
    .line 209
    invoke-virtual {v4, v5}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v4

    .line 213
    const-string v5, "dd"

    .line 214
    .line 215
    const-string v11, "replaceAll(...)"

    .line 216
    .line 217
    const-string v7, "d{1,2}"

    .line 218
    .line 219
    invoke-static {v4, v11, v7, v6, v4}, Lf2/m0;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 220
    .line 221
    .line 222
    move-result-object v4

    .line 223
    invoke-virtual {v4, v5}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object v4

    .line 227
    const-string v5, "MM"

    .line 228
    .line 229
    const-string v7, "M{1,2}"

    .line 230
    .line 231
    invoke-static {v4, v11, v7, v6, v4}, Lf2/m0;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 232
    .line 233
    .line 234
    move-result-object v4

    .line 235
    invoke-virtual {v4, v5}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    const-string v5, "yyyy"

    .line 240
    .line 241
    const-string v7, "y{1,4}"

    .line 242
    .line 243
    invoke-static {v4, v11, v7, v6, v4}, Lf2/m0;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/util/regex/Matcher;

    .line 244
    .line 245
    .line 246
    move-result-object v4

    .line 247
    invoke-virtual {v4, v5}, Ljava/util/regex/Matcher;->replaceAll(Ljava/lang/String;)Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    invoke-static {v4, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    const-string v5, "My"

    .line 255
    .line 256
    const-string v7, "M/y"

    .line 257
    .line 258
    const/4 v11, 0x0

    .line 259
    invoke-static {v11, v4, v5, v7}, Lly0/w;->t(ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 260
    .line 261
    .line 262
    move-result-object v4

    .line 263
    const-string v5, "."

    .line 264
    .line 265
    invoke-static {v4, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 266
    .line 267
    .line 268
    move-result-object v4

    .line 269
    const-string v5, "[/\\-.]"

    .line 270
    .line 271
    invoke-static {v5}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    .line 272
    .line 273
    .line 274
    move-result-object v5

    .line 275
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v5, v4}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 279
    .line 280
    .line 281
    move-result-object v5

    .line 282
    const-string v6, "matcher(...)"

    .line 283
    .line 284
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    invoke-static {v5, v11, v4}, Ltm0/d;->c(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Lly0/l;

    .line 288
    .line 289
    .line 290
    move-result-object v5

    .line 291
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    iget-object v5, v5, Lly0/l;->c:Lly0/k;

    .line 295
    .line 296
    invoke-virtual {v5, v11}, Lly0/k;->e(I)Lly0/i;

    .line 297
    .line 298
    .line 299
    move-result-object v5

    .line 300
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iget-object v5, v5, Lly0/i;->a:Ljava/lang/String;

    .line 304
    .line 305
    new-instance v6, Li2/e0;

    .line 306
    .line 307
    invoke-virtual {v5, v11}, Ljava/lang/String;->charAt(I)C

    .line 308
    .line 309
    .line 310
    move-result v5

    .line 311
    invoke-direct {v6, v4, v5}, Li2/e0;-><init>(Ljava/lang/String;C)V

    .line 312
    .line 313
    .line 314
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 315
    .line 316
    .line 317
    move-object v5, v6

    .line 318
    :cond_b
    check-cast v5, Li2/e0;

    .line 319
    .line 320
    const v4, 0x7f120595

    .line 321
    .line 322
    .line 323
    invoke-static {v12, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 324
    .line 325
    .line 326
    move-result-object v21

    .line 327
    const v4, 0x7f120597

    .line 328
    .line 329
    .line 330
    invoke-static {v12, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 331
    .line 332
    .line 333
    move-result-object v22

    .line 334
    const v4, 0x7f120596

    .line 335
    .line 336
    .line 337
    invoke-static {v12, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 338
    .line 339
    .line 340
    move-result-object v23

    .line 341
    const v4, 0x7f1205aa

    .line 342
    .line 343
    .line 344
    invoke-static {v12, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 345
    .line 346
    .line 347
    move-result-object v24

    .line 348
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 349
    .line 350
    .line 351
    move-result v4

    .line 352
    const/high16 v6, 0x70000

    .line 353
    .line 354
    and-int/2addr v6, v2

    .line 355
    const/high16 v7, 0x20000

    .line 356
    .line 357
    if-eq v6, v7, :cond_c

    .line 358
    .line 359
    const/4 v6, 0x0

    .line 360
    goto :goto_a

    .line 361
    :cond_c
    const/4 v6, 0x1

    .line 362
    :goto_a
    or-int/2addr v4, v6

    .line 363
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v6

    .line 367
    if-nez v4, :cond_d

    .line 368
    .line 369
    if-ne v6, v8, :cond_e

    .line 370
    .line 371
    :cond_d
    new-instance v16, Lh2/y1;

    .line 372
    .line 373
    move-object/from16 v17, p4

    .line 374
    .line 375
    move-object/from16 v19, v5

    .line 376
    .line 377
    move-object/from16 v20, v9

    .line 378
    .line 379
    move-object/from16 v18, v10

    .line 380
    .line 381
    invoke-direct/range {v16 .. v24}, Lh2/y1;-><init>(Lgy0/j;Lh2/e8;Li2/e0;Lh2/g2;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    move-object/from16 v6, v16

    .line 385
    .line 386
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 387
    .line 388
    .line 389
    :cond_e
    move-object v7, v6

    .line 390
    check-cast v7, Lh2/y1;

    .line 391
    .line 392
    iput-object v1, v7, Lh2/y1;->i:Ljava/lang/Long;

    .line 393
    .line 394
    iput-object v15, v7, Lh2/y1;->j:Ljava/lang/Long;

    .line 395
    .line 396
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 397
    .line 398
    sget-object v6, Lh2/x1;->a:Lk1/a1;

    .line 399
    .line 400
    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/a;->l(Lx2/s;Lk1/z0;)Lx2/s;

    .line 401
    .line 402
    .line 403
    move-result-object v4

    .line 404
    sget-object v6, Lk1/j;->a:Lk1/c;

    .line 405
    .line 406
    sget v6, Lh2/q3;->a:F

    .line 407
    .line 408
    invoke-static {v6}, Lk1/j;->g(F)Lk1/h;

    .line 409
    .line 410
    .line 411
    move-result-object v6

    .line 412
    sget-object v9, Lx2/c;->m:Lx2/i;

    .line 413
    .line 414
    const/4 v10, 0x6

    .line 415
    invoke-static {v6, v9, v12, v10}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 416
    .line 417
    .line 418
    move-result-object v6

    .line 419
    iget-wide v9, v12, Ll2/t;->T:J

    .line 420
    .line 421
    invoke-static {v9, v10}, Ljava/lang/Long;->hashCode(J)I

    .line 422
    .line 423
    .line 424
    move-result v9

    .line 425
    invoke-virtual {v12}, Ll2/t;->m()Ll2/p1;

    .line 426
    .line 427
    .line 428
    move-result-object v10

    .line 429
    invoke-static {v12, v4}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 430
    .line 431
    .line 432
    move-result-object v4

    .line 433
    sget-object v11, Lv3/k;->m1:Lv3/j;

    .line 434
    .line 435
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 436
    .line 437
    .line 438
    sget-object v11, Lv3/j;->b:Lv3/i;

    .line 439
    .line 440
    invoke-virtual {v12}, Ll2/t;->c0()V

    .line 441
    .line 442
    .line 443
    iget-boolean v1, v12, Ll2/t;->S:Z

    .line 444
    .line 445
    if-eqz v1, :cond_f

    .line 446
    .line 447
    invoke-virtual {v12, v11}, Ll2/t;->l(Lay0/a;)V

    .line 448
    .line 449
    .line 450
    goto :goto_b

    .line 451
    :cond_f
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 452
    .line 453
    .line 454
    :goto_b
    sget-object v1, Lv3/j;->g:Lv3/h;

    .line 455
    .line 456
    invoke-static {v1, v6, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 457
    .line 458
    .line 459
    sget-object v1, Lv3/j;->f:Lv3/h;

    .line 460
    .line 461
    invoke-static {v1, v10, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 462
    .line 463
    .line 464
    sget-object v1, Lv3/j;->j:Lv3/h;

    .line 465
    .line 466
    iget-boolean v6, v12, Ll2/t;->S:Z

    .line 467
    .line 468
    if-nez v6, :cond_10

    .line 469
    .line 470
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 471
    .line 472
    .line 473
    move-result-object v6

    .line 474
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 475
    .line 476
    .line 477
    move-result-object v10

    .line 478
    invoke-static {v6, v10}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 479
    .line 480
    .line 481
    move-result v6

    .line 482
    if-nez v6, :cond_11

    .line 483
    .line 484
    :cond_10
    invoke-static {v9, v12, v9, v1}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 485
    .line 486
    .line 487
    :cond_11
    sget-object v1, Lv3/j;->d:Lv3/h;

    .line 488
    .line 489
    invoke-static {v1, v4, v12}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 490
    .line 491
    .line 492
    iget-object v1, v5, Li2/e0;->a:Ljava/lang/String;

    .line 493
    .line 494
    sget-object v4, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 495
    .line 496
    invoke-virtual {v1, v4}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 497
    .line 498
    .line 499
    move-result-object v1

    .line 500
    const-string v4, "toUpperCase(...)"

    .line 501
    .line 502
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 503
    .line 504
    .line 505
    const v4, 0x7f1205b0

    .line 506
    .line 507
    .line 508
    invoke-static {v12, v4}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 509
    .line 510
    .line 511
    move-result-object v4

    .line 512
    const/high16 v6, 0x3f000000    # 0.5f

    .line 513
    .line 514
    float-to-double v9, v6

    .line 515
    const-wide/16 v16, 0x0

    .line 516
    .line 517
    cmpl-double v9, v9, v16

    .line 518
    .line 519
    const-string v18, "invalid weight; must be greater than zero"

    .line 520
    .line 521
    if-lez v9, :cond_12

    .line 522
    .line 523
    goto :goto_c

    .line 524
    :cond_12
    invoke-static/range {v18 .. v18}, Ll1/a;->a(Ljava/lang/String;)V

    .line 525
    .line 526
    .line 527
    :goto_c
    new-instance v9, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 528
    .line 529
    const v19, 0x7f7fffff    # Float.MAX_VALUE

    .line 530
    .line 531
    .line 532
    cmpl-float v10, v6, v19

    .line 533
    .line 534
    if-lez v10, :cond_13

    .line 535
    .line 536
    move/from16 v10, v19

    .line 537
    .line 538
    :goto_d
    const/4 v11, 0x1

    .line 539
    goto :goto_e

    .line 540
    :cond_13
    move v10, v6

    .line 541
    goto :goto_d

    .line 542
    :goto_e
    invoke-direct {v9, v10, v11}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 543
    .line 544
    .line 545
    move-object v10, v9

    .line 546
    iget-object v9, v3, Li2/z;->a:Ljava/util/Locale;

    .line 547
    .line 548
    and-int/lit16 v11, v2, 0x380

    .line 549
    .line 550
    const/16 v6, 0x100

    .line 551
    .line 552
    if-ne v11, v6, :cond_14

    .line 553
    .line 554
    const/16 v21, 0x1

    .line 555
    .line 556
    goto :goto_f

    .line 557
    :cond_14
    const/16 v21, 0x0

    .line 558
    .line 559
    :goto_f
    and-int/lit8 v6, v2, 0x70

    .line 560
    .line 561
    const/16 v3, 0x20

    .line 562
    .line 563
    if-ne v6, v3, :cond_15

    .line 564
    .line 565
    const/4 v3, 0x1

    .line 566
    goto :goto_10

    .line 567
    :cond_15
    const/4 v3, 0x0

    .line 568
    :goto_10
    or-int v3, v21, v3

    .line 569
    .line 570
    move/from16 v21, v3

    .line 571
    .line 572
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 573
    .line 574
    .line 575
    move-result-object v3

    .line 576
    if-nez v21, :cond_17

    .line 577
    .line 578
    if-ne v3, v8, :cond_16

    .line 579
    .line 580
    goto :goto_11

    .line 581
    :cond_16
    move-object/from16 v21, v5

    .line 582
    .line 583
    const/4 v5, 0x0

    .line 584
    goto :goto_12

    .line 585
    :cond_17
    :goto_11
    new-instance v3, Lh2/p3;

    .line 586
    .line 587
    move-object/from16 v21, v5

    .line 588
    .line 589
    const/4 v5, 0x0

    .line 590
    invoke-direct {v3, v0, v15, v5}, Lh2/p3;-><init>(Lay0/n;Ljava/lang/Long;I)V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v12, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 594
    .line 595
    .line 596
    :goto_12
    check-cast v3, Lay0/k;

    .line 597
    .line 598
    new-instance v5, Lh2/t1;

    .line 599
    .line 600
    const/4 v0, 0x1

    .line 601
    invoke-direct {v5, v4, v1, v0}, Lh2/t1;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 602
    .line 603
    .line 604
    const v4, 0x67be837c

    .line 605
    .line 606
    .line 607
    invoke-static {v4, v12, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 608
    .line 609
    .line 610
    move-result-object v4

    .line 611
    new-instance v5, Lh2/u1;

    .line 612
    .line 613
    const/4 v0, 0x2

    .line 614
    invoke-direct {v5, v1, v0}, Lh2/u1;-><init>(Ljava/lang/String;I)V

    .line 615
    .line 616
    .line 617
    const v0, 0x4949163d

    .line 618
    .line 619
    .line 620
    invoke-static {v0, v12, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 621
    .line 622
    .line 623
    move-result-object v5

    .line 624
    shl-int/lit8 v0, v2, 0x3

    .line 625
    .line 626
    and-int/lit8 v0, v0, 0x70

    .line 627
    .line 628
    const v22, 0x1b6000

    .line 629
    .line 630
    .line 631
    or-int v0, v0, v22

    .line 632
    .line 633
    move/from16 v23, v6

    .line 634
    .line 635
    and-int/lit16 v6, v2, 0x1c00

    .line 636
    .line 637
    or-int/2addr v0, v6

    .line 638
    shr-int/lit8 v24, v2, 0x15

    .line 639
    .line 640
    and-int/lit8 v25, v24, 0xe

    .line 641
    .line 642
    and-int/lit8 v24, v24, 0x7e

    .line 643
    .line 644
    move/from16 v27, v6

    .line 645
    .line 646
    const/4 v6, 0x1

    .line 647
    move-object v15, v13

    .line 648
    move v13, v0

    .line 649
    move-object v0, v10

    .line 650
    move-object v10, v15

    .line 651
    move-object/from16 v28, v1

    .line 652
    .line 653
    move/from16 v20, v2

    .line 654
    .line 655
    move-object v2, v3

    .line 656
    move-object/from16 v30, v8

    .line 657
    .line 658
    move/from16 v29, v11

    .line 659
    .line 660
    move-object v11, v14

    .line 661
    move-object/from16 v8, v21

    .line 662
    .line 663
    move/from16 v14, v24

    .line 664
    .line 665
    const/high16 v15, 0x3f000000    # 0.5f

    .line 666
    .line 667
    const/16 v26, 0x0

    .line 668
    .line 669
    move-object/from16 v1, p0

    .line 670
    .line 671
    move-object/from16 v3, p3

    .line 672
    .line 673
    invoke-static/range {v0 .. v14}, Lh2/x1;->b(Lx2/s;Ljava/lang/Long;Lay0/k;Li2/z;Lt2/b;Lt2/b;ILh2/y1;Li2/e0;Ljava/util/Locale;Lh2/z1;Lc3/q;Ll2/o;II)V

    .line 674
    .line 675
    .line 676
    move-object v0, v1

    .line 677
    const v1, 0x7f1205ad

    .line 678
    .line 679
    .line 680
    invoke-static {v12, v1}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 681
    .line 682
    .line 683
    move-result-object v1

    .line 684
    float-to-double v4, v15

    .line 685
    cmpl-double v2, v4, v16

    .line 686
    .line 687
    if-lez v2, :cond_18

    .line 688
    .line 689
    goto :goto_13

    .line 690
    :cond_18
    invoke-static/range {v18 .. v18}, Ll1/a;->a(Ljava/lang/String;)V

    .line 691
    .line 692
    .line 693
    :goto_13
    new-instance v2, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 694
    .line 695
    cmpl-float v4, v15, v19

    .line 696
    .line 697
    if-lez v4, :cond_19

    .line 698
    .line 699
    move/from16 v6, v19

    .line 700
    .line 701
    :goto_14
    const/4 v15, 0x1

    .line 702
    goto :goto_15

    .line 703
    :cond_19
    move v6, v15

    .line 704
    goto :goto_14

    .line 705
    :goto_15
    invoke-direct {v2, v6, v15}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 706
    .line 707
    .line 708
    iget-object v9, v3, Li2/z;->a:Ljava/util/Locale;

    .line 709
    .line 710
    move/from16 v4, v29

    .line 711
    .line 712
    const/16 v6, 0x100

    .line 713
    .line 714
    if-ne v4, v6, :cond_1a

    .line 715
    .line 716
    move v6, v15

    .line 717
    goto :goto_16

    .line 718
    :cond_1a
    move/from16 v6, v26

    .line 719
    .line 720
    :goto_16
    and-int/lit8 v4, v20, 0xe

    .line 721
    .line 722
    const/4 v5, 0x4

    .line 723
    if-ne v4, v5, :cond_1b

    .line 724
    .line 725
    move/from16 v26, v15

    .line 726
    .line 727
    :cond_1b
    or-int v4, v6, v26

    .line 728
    .line 729
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 730
    .line 731
    .line 732
    move-result-object v5

    .line 733
    if-nez v4, :cond_1d

    .line 734
    .line 735
    move-object/from16 v4, v30

    .line 736
    .line 737
    if-ne v5, v4, :cond_1c

    .line 738
    .line 739
    goto :goto_17

    .line 740
    :cond_1c
    move-object/from16 v4, p2

    .line 741
    .line 742
    goto :goto_18

    .line 743
    :cond_1d
    :goto_17
    new-instance v5, Lh2/p3;

    .line 744
    .line 745
    move-object/from16 v4, p2

    .line 746
    .line 747
    invoke-direct {v5, v4, v0, v15}, Lh2/p3;-><init>(Lay0/n;Ljava/lang/Long;I)V

    .line 748
    .line 749
    .line 750
    invoke-virtual {v12, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 751
    .line 752
    .line 753
    :goto_18
    check-cast v5, Lay0/k;

    .line 754
    .line 755
    new-instance v6, Lh2/t1;

    .line 756
    .line 757
    move-object/from16 v10, v28

    .line 758
    .line 759
    const/4 v11, 0x2

    .line 760
    invoke-direct {v6, v1, v10, v11}, Lh2/t1;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    .line 761
    .line 762
    .line 763
    const v1, -0x3497e94d    # -1.5210163E7f

    .line 764
    .line 765
    .line 766
    invoke-static {v1, v12, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 767
    .line 768
    .line 769
    move-result-object v1

    .line 770
    new-instance v6, Lh2/u1;

    .line 771
    .line 772
    const/4 v11, 0x3

    .line 773
    invoke-direct {v6, v10, v11}, Lh2/u1;-><init>(Ljava/lang/String;I)V

    .line 774
    .line 775
    .line 776
    const v10, 0x7498fd34

    .line 777
    .line 778
    .line 779
    invoke-static {v10, v12, v6}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 780
    .line 781
    .line 782
    move-result-object v6

    .line 783
    or-int v10, v23, v22

    .line 784
    .line 785
    or-int v13, v10, v27

    .line 786
    .line 787
    or-int/lit8 v14, v25, 0x30

    .line 788
    .line 789
    move-object v0, v2

    .line 790
    move-object v2, v5

    .line 791
    move-object v5, v6

    .line 792
    const/4 v6, 0x2

    .line 793
    const/4 v11, 0x0

    .line 794
    move-object/from16 v10, p7

    .line 795
    .line 796
    move-object v4, v1

    .line 797
    move-object/from16 v1, p1

    .line 798
    .line 799
    invoke-static/range {v0 .. v14}, Lh2/x1;->b(Lx2/s;Ljava/lang/Long;Lay0/k;Li2/z;Lt2/b;Lt2/b;ILh2/y1;Li2/e0;Ljava/util/Locale;Lh2/z1;Lc3/q;Ll2/o;II)V

    .line 800
    .line 801
    .line 802
    invoke-virtual {v12, v15}, Ll2/t;->q(Z)V

    .line 803
    .line 804
    .line 805
    goto :goto_19

    .line 806
    :cond_1e
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 807
    .line 808
    .line 809
    :goto_19
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 810
    .line 811
    .line 812
    move-result-object v12

    .line 813
    if-eqz v12, :cond_1f

    .line 814
    .line 815
    new-instance v0, Lco0/j;

    .line 816
    .line 817
    const/4 v11, 0x2

    .line 818
    move-object/from16 v1, p0

    .line 819
    .line 820
    move-object/from16 v2, p1

    .line 821
    .line 822
    move-object/from16 v3, p2

    .line 823
    .line 824
    move-object/from16 v4, p3

    .line 825
    .line 826
    move-object/from16 v5, p4

    .line 827
    .line 828
    move-object/from16 v6, p5

    .line 829
    .line 830
    move-object/from16 v7, p6

    .line 831
    .line 832
    move-object/from16 v8, p7

    .line 833
    .line 834
    move-object/from16 v9, p8

    .line 835
    .line 836
    move/from16 v10, p10

    .line 837
    .line 838
    invoke-direct/range {v0 .. v11}, Lco0/j;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llx0/e;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 839
    .line 840
    .line 841
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 842
    .line 843
    :cond_1f
    return-void
.end method
