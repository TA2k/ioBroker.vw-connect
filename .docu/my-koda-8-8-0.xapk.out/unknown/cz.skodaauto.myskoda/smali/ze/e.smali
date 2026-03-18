.class public final Lze/e;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lqe/a;

.field public final e:Lqe/d;

.field public final f:Ljava/util/List;

.field public final g:Lne/b;

.field public final h:Lay0/k;

.field public final i:Lxc/b;

.field public final j:Lay0/k;

.field public final k:Lay0/a;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/l1;


# direct methods
.method public constructor <init>(Lgf/a;ZLqe/a;Lqe/d;Ljava/util/List;Lne/b;Lay0/k;Lxc/b;Lay0/k;Lay0/a;)V
    .locals 12

    .line 1
    move-object/from16 v1, p4

    .line 2
    .line 3
    move-object/from16 v2, p5

    .line 4
    .line 5
    move-object/from16 v3, p7

    .line 6
    .line 7
    move-object/from16 v4, p9

    .line 8
    .line 9
    move-object/from16 v5, p10

    .line 10
    .line 11
    const-string v6, "slotsPerDay"

    .line 12
    .line 13
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v6, "season"

    .line 17
    .line 18
    invoke-static {p3, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v7, "wizardData"

    .line 22
    .line 23
    invoke-static {v1, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v7, "selectedDays"

    .line 27
    .line 28
    invoke-static {v2, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v7, "goToIntermediaryDaySuccess"

    .line 32
    .line 33
    invoke-static {v3, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v7, "goToSeasonSuccess"

    .line 37
    .line 38
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v7, "goToSuccess"

    .line 42
    .line 43
    invoke-static {v5, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 47
    .line 48
    .line 49
    iput-object p3, p0, Lze/e;->d:Lqe/a;

    .line 50
    .line 51
    iput-object v1, p0, Lze/e;->e:Lqe/d;

    .line 52
    .line 53
    iput-object v2, p0, Lze/e;->f:Ljava/util/List;

    .line 54
    .line 55
    move-object/from16 v0, p6

    .line 56
    .line 57
    iput-object v0, p0, Lze/e;->g:Lne/b;

    .line 58
    .line 59
    iput-object v3, p0, Lze/e;->h:Lay0/k;

    .line 60
    .line 61
    move-object/from16 v0, p8

    .line 62
    .line 63
    iput-object v0, p0, Lze/e;->i:Lxc/b;

    .line 64
    .line 65
    iput-object v4, p0, Lze/e;->j:Lay0/k;

    .line 66
    .line 67
    iput-object v5, p0, Lze/e;->k:Lay0/a;

    .line 68
    .line 69
    iget-object v0, v1, Lqe/d;->b:Lje/r;

    .line 70
    .line 71
    invoke-static {v0}, Ljp/kf;->d(Lje/r;)Lje/r;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    iget-object v0, v0, Lje/r;->c:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    const/16 v1, 0x12

    .line 82
    .line 83
    const/4 v2, 0x0

    .line 84
    const/4 v3, 0x1

    .line 85
    if-eqz p1, :cond_4

    .line 86
    .line 87
    const/16 v4, 0x14

    .line 88
    .line 89
    const/16 v5, 0x16

    .line 90
    .line 91
    if-eq p1, v3, :cond_3

    .line 92
    .line 93
    const/4 v7, 0x2

    .line 94
    if-eq p1, v7, :cond_2

    .line 95
    .line 96
    const/4 v7, 0x3

    .line 97
    if-eq p1, v7, :cond_1

    .line 98
    .line 99
    const/4 v4, 0x4

    .line 100
    if-ne p1, v4, :cond_0

    .line 101
    .line 102
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 103
    .line 104
    goto/16 :goto_0

    .line 105
    .line 106
    :cond_0
    new-instance p0, La8/r0;

    .line 107
    .line 108
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_1
    new-instance p1, Lze/g;

    .line 113
    .line 114
    sget-object v7, Lze/f;->d:Lze/f;

    .line 115
    .line 116
    invoke-direct {p1, v7, v3, v3, v4}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 117
    .line 118
    .line 119
    new-instance v4, Lze/g;

    .line 120
    .line 121
    sget-object v8, Lze/f;->e:Lze/f;

    .line 122
    .line 123
    invoke-direct {v4, v8, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 124
    .line 125
    .line 126
    new-instance v8, Lze/g;

    .line 127
    .line 128
    sget-object v9, Lze/f;->f:Lze/f;

    .line 129
    .line 130
    invoke-direct {v8, v9, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 131
    .line 132
    .line 133
    new-instance v9, Lze/g;

    .line 134
    .line 135
    sget-object v10, Lze/f;->g:Lze/f;

    .line 136
    .line 137
    invoke-direct {v9, v10, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 138
    .line 139
    .line 140
    new-instance v5, Lze/g;

    .line 141
    .line 142
    invoke-direct {v5, v7, v2, v2, v1}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 143
    .line 144
    .line 145
    filled-new-array {p1, v4, v8, v9, v5}, [Lze/g;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    goto :goto_0

    .line 154
    :cond_2
    new-instance p1, Lze/g;

    .line 155
    .line 156
    sget-object v7, Lze/f;->d:Lze/f;

    .line 157
    .line 158
    invoke-direct {p1, v7, v3, v3, v4}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 159
    .line 160
    .line 161
    new-instance v4, Lze/g;

    .line 162
    .line 163
    sget-object v8, Lze/f;->e:Lze/f;

    .line 164
    .line 165
    invoke-direct {v4, v8, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 166
    .line 167
    .line 168
    new-instance v8, Lze/g;

    .line 169
    .line 170
    sget-object v9, Lze/f;->f:Lze/f;

    .line 171
    .line 172
    invoke-direct {v8, v9, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 173
    .line 174
    .line 175
    new-instance v5, Lze/g;

    .line 176
    .line 177
    invoke-direct {v5, v7, v2, v2, v1}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 178
    .line 179
    .line 180
    filled-new-array {p1, v4, v8, v5}, [Lze/g;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    goto :goto_0

    .line 189
    :cond_3
    new-instance p1, Lze/g;

    .line 190
    .line 191
    sget-object v7, Lze/f;->d:Lze/f;

    .line 192
    .line 193
    invoke-direct {p1, v7, v3, v3, v4}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 194
    .line 195
    .line 196
    new-instance v4, Lze/g;

    .line 197
    .line 198
    sget-object v8, Lze/f;->e:Lze/f;

    .line 199
    .line 200
    invoke-direct {v4, v8, v3, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 201
    .line 202
    .line 203
    new-instance v5, Lze/g;

    .line 204
    .line 205
    invoke-direct {v5, v7, v2, v2, v1}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 206
    .line 207
    .line 208
    filled-new-array {p1, v4, v5}, [Lze/g;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-static {p1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    goto :goto_0

    .line 217
    :cond_4
    new-instance p1, Lze/g;

    .line 218
    .line 219
    sget-object v4, Lze/f;->d:Lze/f;

    .line 220
    .line 221
    const/16 v5, 0x10

    .line 222
    .line 223
    invoke-direct {p1, v4, v2, v3, v5}, Lze/g;-><init>(Lze/f;ZZI)V

    .line 224
    .line 225
    .line 226
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    :goto_0
    new-instance v4, Ljava/util/ArrayList;

    .line 231
    .line 232
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 233
    .line 234
    .line 235
    if-eqz p2, :cond_5

    .line 236
    .line 237
    new-instance v5, Ljava/text/SimpleDateFormat;

    .line 238
    .line 239
    const-string v7, "HH:mm"

    .line 240
    .line 241
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 242
    .line 243
    .line 244
    move-result-object v8

    .line 245
    invoke-direct {v5, v7, v8}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 246
    .line 247
    .line 248
    goto :goto_1

    .line 249
    :cond_5
    new-instance v5, Ljava/text/SimpleDateFormat;

    .line 250
    .line 251
    const-string v7, "hh:mm a"

    .line 252
    .line 253
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 254
    .line 255
    .line 256
    move-result-object v8

    .line 257
    invoke-direct {v5, v7, v8}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;Ljava/util/Locale;)V

    .line 258
    .line 259
    .line 260
    :goto_1
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 261
    .line 262
    .line 263
    move-result-object v7

    .line 264
    const/4 v8, 0x6

    .line 265
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 266
    .line 267
    .line 268
    move-result-object v8

    .line 269
    const/16 v9, 0xc

    .line 270
    .line 271
    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 272
    .line 273
    .line 274
    move-result-object v10

    .line 275
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 276
    .line 277
    .line 278
    move-result-object v1

    .line 279
    const/16 v11, 0x18

    .line 280
    .line 281
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 282
    .line 283
    .line 284
    move-result-object v11

    .line 285
    filled-new-array {v7, v8, v10, v1, v11}, [Ljava/lang/Integer;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 294
    .line 295
    .line 296
    move-result-object v1

    .line 297
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 298
    .line 299
    .line 300
    move-result v7

    .line 301
    if-eqz v7, :cond_6

    .line 302
    .line 303
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v7

    .line 307
    check-cast v7, Ljava/lang/Number;

    .line 308
    .line 309
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 310
    .line 311
    .line 312
    move-result v7

    .line 313
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    .line 314
    .line 315
    .line 316
    move-result-object v8

    .line 317
    const/16 v10, 0xb

    .line 318
    .line 319
    invoke-virtual {v8, v10, v7}, Ljava/util/Calendar;->set(II)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {v8, v9, v2}, Ljava/util/Calendar;->set(II)V

    .line 323
    .line 324
    .line 325
    invoke-virtual {v8}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    .line 326
    .line 327
    .line 328
    move-result-object v7

    .line 329
    invoke-virtual {v5, v7}, Ljava/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v7

    .line 333
    const-string v8, "format(...)"

    .line 334
    .line 335
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 336
    .line 337
    .line 338
    sget-object v8, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 339
    .line 340
    invoke-virtual {v7, v8}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 341
    .line 342
    .line 343
    move-result-object v7

    .line 344
    const-string v8, "toUpperCase(...)"

    .line 345
    .line 346
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 347
    .line 348
    .line 349
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    goto :goto_2

    .line 353
    :cond_6
    iget-object v1, p0, Lze/e;->d:Lqe/a;

    .line 354
    .line 355
    iget-object v5, p0, Lze/e;->f:Ljava/util/List;

    .line 356
    .line 357
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 358
    .line 359
    .line 360
    move-result v7

    .line 361
    const/4 v8, 0x7

    .line 362
    if-ne v7, v8, :cond_7

    .line 363
    .line 364
    move v2, v3

    .line 365
    :cond_7
    const-string v3, "currencySymbol"

    .line 366
    .line 367
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    new-instance v3, Lze/d;

    .line 374
    .line 375
    const/4 v6, 0x0

    .line 376
    const/4 v7, 0x0

    .line 377
    const/4 v8, 0x0

    .line 378
    move-object/from16 p4, p1

    .line 379
    .line 380
    move-object p2, v0

    .line 381
    move-object/from16 p7, v1

    .line 382
    .line 383
    move/from16 p9, v2

    .line 384
    .line 385
    move-object p1, v3

    .line 386
    move-object p3, v4

    .line 387
    move-object/from16 p8, v5

    .line 388
    .line 389
    move/from16 p6, v6

    .line 390
    .line 391
    move-object/from16 p10, v7

    .line 392
    .line 393
    move/from16 p5, v8

    .line 394
    .line 395
    invoke-direct/range {p1 .. p10}, Lze/d;-><init>(Ljava/lang/String;Ljava/util/List;Ljava/util/List;ZZLqe/a;Ljava/util/List;ZLlc/l;)V

    .line 396
    .line 397
    .line 398
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 399
    .line 400
    .line 401
    move-result-object p1

    .line 402
    iput-object p1, p0, Lze/e;->l:Lyy0/c2;

    .line 403
    .line 404
    new-instance v0, Lyy0/l1;

    .line 405
    .line 406
    invoke-direct {v0, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 407
    .line 408
    .line 409
    iput-object v0, p0, Lze/e;->m:Lyy0/l1;

    .line 410
    .line 411
    return-void
.end method

.method public static final a(Lze/e;Lqe/a;)Lje/t0;
    .locals 4

    .line 1
    iget-object p0, p0, Lze/e;->e:Lqe/d;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lqe/d;->b(Lqe/a;)Lqe/e;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p1, p0, Lqe/e;->b:Ljava/util/List;

    .line 8
    .line 9
    iget-object p0, p0, Lqe/e;->c:Ljava/util/Map;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-eqz v1, :cond_0

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    check-cast v1, Ljava/util/Map$Entry;

    .line 39
    .line 40
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v2

    .line 44
    check-cast v2, Ljava/util/List;

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    check-cast v1, Ljava/util/List;

    .line 51
    .line 52
    new-instance v3, Lje/c0;

    .line 53
    .line 54
    invoke-direct {v3, v2, v1}, Lje/c0;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_0
    new-instance p0, Lje/t0;

    .line 62
    .line 63
    invoke-direct {p0, p1, v0}, Lje/t0;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 64
    .line 65
    .line 66
    return-object p0
.end method

.method public static final b(Lze/e;Ljava/util/List;)Z
    .locals 0

    .line 1
    check-cast p1, Ljava/util/Collection;

    .line 2
    .line 3
    iget-object p0, p0, Lze/e;->f:Ljava/util/List;

    .line 4
    .line 5
    check-cast p0, Ljava/lang/Iterable;

    .line 6
    .line 7
    invoke-static {p0, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lmx0/q;->C(Ljava/lang/Iterable;)Ljava/util/List;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    const/4 p1, 0x7

    .line 20
    if-ne p0, p1, :cond_0

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    return p0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    return p0
.end method
