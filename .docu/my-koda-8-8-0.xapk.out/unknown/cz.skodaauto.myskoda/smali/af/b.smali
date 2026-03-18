.class public final synthetic Laf/b;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Laf/b;->d:I

    .line 2
    .line 3
    move-object v0, p4

    .line 4
    move-object p4, p2

    .line 5
    move p2, p6

    .line 6
    move-object p6, p5

    .line 7
    move-object p5, v0

    .line 8
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/j;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Laf/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lbz/i;

    .line 7
    .line 8
    const-string v0, "p0"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lbz/n;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    new-instance v0, Lay/b;

    .line 21
    .line 22
    const/16 v1, 0x12

    .line 23
    .line 24
    invoke-direct {v0, v1}, Lay/b;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    iget-object v0, p0, Lbz/n;->k:Lzy/q;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-virtual {v0, v1}, Lzy/q;->a(Z)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    if-eqz p1, :cond_1

    .line 41
    .line 42
    if-ne p1, v1, :cond_0

    .line 43
    .line 44
    const/4 p1, 0x0

    .line 45
    invoke-virtual {v0, p1}, Lzy/q;->a(Z)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lbz/n;->p:Ltr0/b;

    .line 49
    .line 50
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    new-instance p0, La8/r0;

    .line 55
    .line 56
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_1
    iget-object p0, p0, Lbz/n;->l:Lzy/z;

    .line 61
    .line 62
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_0
    check-cast p1, Laz/a;

    .line 69
    .line 70
    const-string v0, "p0"

    .line 71
    .line 72
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Lbz/e;

    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    check-cast v0, Lbz/d;

    .line 87
    .line 88
    iget-object v0, v0, Lbz/d;->c:Ljava/util/List;

    .line 89
    .line 90
    check-cast v0, Ljava/util/Collection;

    .line 91
    .line 92
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_2

    .line 101
    .line 102
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_2
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    :goto_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    check-cast p1, Lbz/d;

    .line 114
    .line 115
    const/4 v1, 0x0

    .line 116
    const/4 v2, 0x3

    .line 117
    const/4 v3, 0x0

    .line 118
    invoke-static {p1, v3, v1, v0, v2}, Lbz/d;->a(Lbz/d;Ljava/util/ArrayList;ZLjava/util/ArrayList;I)Lbz/d;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 123
    .line 124
    .line 125
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 126
    .line 127
    return-object p0

    .line 128
    :pswitch_1
    check-cast p1, Laz/c;

    .line 129
    .line 130
    const-string v0, "p0"

    .line 131
    .line 132
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, Lbz/e;

    .line 138
    .line 139
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 140
    .line 141
    .line 142
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    check-cast v0, Lbz/d;

    .line 147
    .line 148
    iget-object v0, v0, Lbz/d;->a:Ljava/util/List;

    .line 149
    .line 150
    check-cast v0, Ljava/util/Collection;

    .line 151
    .line 152
    invoke-static {v0}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    new-instance v1, Lbz/a;

    .line 157
    .line 158
    invoke-direct {v1, p1}, Lbz/a;-><init>(Laz/c;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->replaceAll(Ljava/util/function/UnaryOperator;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    check-cast p1, Lbz/d;

    .line 169
    .line 170
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    const/4 v2, 0x0

    .line 175
    const/4 v3, 0x0

    .line 176
    if-eqz v1, :cond_3

    .line 177
    .line 178
    move v4, v3

    .line 179
    goto :goto_3

    .line 180
    :cond_3
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    move v4, v3

    .line 185
    :cond_4
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 186
    .line 187
    .line 188
    move-result v5

    .line 189
    if-eqz v5, :cond_6

    .line 190
    .line 191
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    move-result-object v5

    .line 195
    check-cast v5, Lbz/c;

    .line 196
    .line 197
    iget-boolean v5, v5, Lbz/c;->d:Z

    .line 198
    .line 199
    if-eqz v5, :cond_4

    .line 200
    .line 201
    add-int/lit8 v4, v4, 0x1

    .line 202
    .line 203
    if-ltz v4, :cond_5

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_5
    invoke-static {}, Ljp/k1;->q()V

    .line 207
    .line 208
    .line 209
    throw v2

    .line 210
    :cond_6
    :goto_3
    const/4 v1, 0x3

    .line 211
    if-ge v4, v1, :cond_7

    .line 212
    .line 213
    const/4 v3, 0x1

    .line 214
    :cond_7
    const/4 v1, 0x4

    .line 215
    invoke-static {p1, v0, v3, v2, v1}, Lbz/d;->a(Lbz/d;Ljava/util/ArrayList;ZLjava/util/ArrayList;I)Lbz/d;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 220
    .line 221
    .line 222
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    return-object p0

    .line 225
    :pswitch_2
    check-cast p1, Ljava/lang/Number;

    .line 226
    .line 227
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 228
    .line 229
    .line 230
    move-result v8

    .line 231
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 232
    .line 233
    check-cast p0, Lbv0/e;

    .line 234
    .line 235
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 236
    .line 237
    .line 238
    move-result-object p1

    .line 239
    move-object v0, p1

    .line 240
    check-cast v0, Lbv0/c;

    .line 241
    .line 242
    const/4 v10, 0x0

    .line 243
    const/16 v11, 0x6ff

    .line 244
    .line 245
    const/4 v1, 0x0

    .line 246
    const/4 v2, 0x0

    .line 247
    const/4 v3, 0x0

    .line 248
    const/4 v4, 0x0

    .line 249
    const/4 v5, 0x0

    .line 250
    const/4 v6, 0x0

    .line 251
    const/4 v7, 0x0

    .line 252
    const/4 v9, 0x0

    .line 253
    invoke-static/range {v0 .. v11}, Lbv0/c;->a(Lbv0/c;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;ZLjava/lang/String;ZZIZLql0/g;I)Lbv0/c;

    .line 254
    .line 255
    .line 256
    move-result-object p1

    .line 257
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 258
    .line 259
    .line 260
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 261
    .line 262
    return-object p0

    .line 263
    :pswitch_3
    check-cast p1, Ljava/lang/Number;

    .line 264
    .line 265
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 266
    .line 267
    .line 268
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast p0, Lbv0/e;

    .line 271
    .line 272
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 276
    .line 277
    .line 278
    move-result-object p1

    .line 279
    new-instance v0, Lbv0/a;

    .line 280
    .line 281
    const/4 v1, 0x2

    .line 282
    const/4 v2, 0x0

    .line 283
    invoke-direct {v0, p0, v2, v1}, Lbv0/a;-><init>(Lbv0/e;Lkotlin/coroutines/Continuation;I)V

    .line 284
    .line 285
    .line 286
    const/4 p0, 0x3

    .line 287
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 288
    .line 289
    .line 290
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 291
    .line 292
    return-object p0

    .line 293
    :pswitch_4
    check-cast p1, Ljava/lang/Boolean;

    .line 294
    .line 295
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 296
    .line 297
    .line 298
    move-result v5

    .line 299
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 300
    .line 301
    check-cast p0, Lbo0/r;

    .line 302
    .line 303
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 304
    .line 305
    .line 306
    move-result-object p1

    .line 307
    move-object v0, p1

    .line 308
    check-cast v0, Lbo0/q;

    .line 309
    .line 310
    const/4 v11, 0x0

    .line 311
    const/16 v12, 0x7ef

    .line 312
    .line 313
    const/4 v1, 0x0

    .line 314
    const/4 v2, 0x0

    .line 315
    const/4 v3, 0x0

    .line 316
    const/4 v4, 0x0

    .line 317
    const/4 v6, 0x0

    .line 318
    const/4 v7, 0x0

    .line 319
    const/4 v8, 0x0

    .line 320
    const/4 v9, 0x0

    .line 321
    const/4 v10, 0x0

    .line 322
    invoke-static/range {v0 .. v12}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 323
    .line 324
    .line 325
    move-result-object p1

    .line 326
    invoke-virtual {p0, p1}, Lbo0/r;->h(Lbo0/q;)Lbo0/q;

    .line 327
    .line 328
    .line 329
    move-result-object p1

    .line 330
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 331
    .line 332
    .line 333
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 334
    .line 335
    return-object p0

    .line 336
    :pswitch_5
    move-object v11, p1

    .line 337
    check-cast v11, Ljava/time/LocalTime;

    .line 338
    .line 339
    const-string p1, "p0"

    .line 340
    .line 341
    invoke-static {v11, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast p0, Lbo0/r;

    .line 347
    .line 348
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 349
    .line 350
    .line 351
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 352
    .line 353
    .line 354
    move-result-object p1

    .line 355
    move-object v0, p1

    .line 356
    check-cast v0, Lbo0/q;

    .line 357
    .line 358
    const/4 v10, 0x0

    .line 359
    const/16 v12, 0x3fd

    .line 360
    .line 361
    const/4 v1, 0x0

    .line 362
    const/4 v2, 0x0

    .line 363
    const/4 v3, 0x0

    .line 364
    const/4 v4, 0x0

    .line 365
    const/4 v5, 0x0

    .line 366
    const/4 v6, 0x0

    .line 367
    const/4 v7, 0x0

    .line 368
    const/4 v8, 0x0

    .line 369
    const/4 v9, 0x0

    .line 370
    invoke-static/range {v0 .. v12}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 371
    .line 372
    .line 373
    move-result-object p1

    .line 374
    invoke-virtual {p0, p1}, Lbo0/r;->h(Lbo0/q;)Lbo0/q;

    .line 375
    .line 376
    .line 377
    move-result-object p1

    .line 378
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 379
    .line 380
    .line 381
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 382
    .line 383
    return-object p0

    .line 384
    :pswitch_6
    move-object v4, p1

    .line 385
    check-cast v4, Lbo0/p;

    .line 386
    .line 387
    const-string p1, "p0"

    .line 388
    .line 389
    invoke-static {v4, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 390
    .line 391
    .line 392
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast p0, Lbo0/r;

    .line 395
    .line 396
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 397
    .line 398
    .line 399
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 400
    .line 401
    .line 402
    move-result-object p1

    .line 403
    check-cast p1, Lbo0/q;

    .line 404
    .line 405
    iget-object p1, p1, Lbo0/q;->d:Lbo0/p;

    .line 406
    .line 407
    if-ne v4, p1, :cond_8

    .line 408
    .line 409
    goto :goto_5

    .line 410
    :cond_8
    new-instance p1, Laa/k;

    .line 411
    .line 412
    const/16 v0, 0x8

    .line 413
    .line 414
    invoke-direct {p1, v0, v4, p0}, Laa/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 415
    .line 416
    .line 417
    invoke-static {p0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 418
    .line 419
    .line 420
    new-instance p1, Lnx0/i;

    .line 421
    .line 422
    invoke-direct {p1}, Lnx0/i;-><init>()V

    .line 423
    .line 424
    .line 425
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 426
    .line 427
    .line 428
    move-result-object v0

    .line 429
    check-cast v0, Lbo0/q;

    .line 430
    .line 431
    iget-object v0, v0, Lbo0/q;->k:Ljava/time/LocalTime;

    .line 432
    .line 433
    invoke-static {}, Ljava/time/OffsetDateTime;->now()Ljava/time/OffsetDateTime;

    .line 434
    .line 435
    .line 436
    move-result-object v1

    .line 437
    invoke-virtual {v1}, Ljava/time/OffsetDateTime;->toLocalTime()Ljava/time/LocalTime;

    .line 438
    .line 439
    .line 440
    move-result-object v2

    .line 441
    invoke-virtual {v0, v2}, Ljava/time/LocalTime;->compareTo(Ljava/time/LocalTime;)I

    .line 442
    .line 443
    .line 444
    move-result v0

    .line 445
    if-gez v0, :cond_9

    .line 446
    .line 447
    invoke-virtual {v1}, Ljava/time/OffsetDateTime;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 448
    .line 449
    .line 450
    move-result-object v0

    .line 451
    const-wide/16 v1, 0x1

    .line 452
    .line 453
    invoke-virtual {v0, v1, v2}, Ljava/time/DayOfWeek;->plus(J)Ljava/time/DayOfWeek;

    .line 454
    .line 455
    .line 456
    move-result-object v0

    .line 457
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 458
    .line 459
    .line 460
    goto :goto_4

    .line 461
    :cond_9
    invoke-virtual {v1}, Ljava/time/OffsetDateTime;->getDayOfWeek()Ljava/time/DayOfWeek;

    .line 462
    .line 463
    .line 464
    move-result-object v0

    .line 465
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 466
    .line 467
    .line 468
    :goto_4
    invoke-virtual {p1, v0}, Lnx0/i;->add(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    invoke-static {p1}, Ljp/m1;->c(Lnx0/i;)Lnx0/i;

    .line 472
    .line 473
    .line 474
    move-result-object v3

    .line 475
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 476
    .line 477
    .line 478
    move-result-object p1

    .line 479
    move-object v0, p1

    .line 480
    check-cast v0, Lbo0/q;

    .line 481
    .line 482
    const/4 v11, 0x0

    .line 483
    const/16 v12, 0x7f3

    .line 484
    .line 485
    const/4 v1, 0x0

    .line 486
    const/4 v2, 0x0

    .line 487
    const/4 v5, 0x0

    .line 488
    const/4 v6, 0x0

    .line 489
    const/4 v7, 0x0

    .line 490
    const/4 v8, 0x0

    .line 491
    const/4 v9, 0x0

    .line 492
    const/4 v10, 0x0

    .line 493
    invoke-static/range {v0 .. v12}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 494
    .line 495
    .line 496
    move-result-object p1

    .line 497
    invoke-virtual {p0, p1}, Lbo0/r;->h(Lbo0/q;)Lbo0/q;

    .line 498
    .line 499
    .line 500
    move-result-object p1

    .line 501
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 502
    .line 503
    .line 504
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 505
    .line 506
    return-object p0

    .line 507
    :pswitch_7
    check-cast p1, Ljava/time/DayOfWeek;

    .line 508
    .line 509
    const-string v0, "p0"

    .line 510
    .line 511
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 512
    .line 513
    .line 514
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 515
    .line 516
    check-cast p0, Lbo0/r;

    .line 517
    .line 518
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 519
    .line 520
    .line 521
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 522
    .line 523
    .line 524
    move-result-object v0

    .line 525
    check-cast v0, Lbo0/q;

    .line 526
    .line 527
    iget-object v0, v0, Lbo0/q;->c:Ljava/util/Set;

    .line 528
    .line 529
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    check-cast v1, Lbo0/q;

    .line 534
    .line 535
    iget-object v1, v1, Lbo0/q;->d:Lbo0/p;

    .line 536
    .line 537
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 538
    .line 539
    .line 540
    move-result v1

    .line 541
    if-eqz v1, :cond_f

    .line 542
    .line 543
    const/4 v2, 0x1

    .line 544
    if-eq v1, v2, :cond_d

    .line 545
    .line 546
    const/4 v2, 0x2

    .line 547
    if-ne v1, v2, :cond_c

    .line 548
    .line 549
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 550
    .line 551
    .line 552
    move-result v1

    .line 553
    if-eqz v1, :cond_b

    .line 554
    .line 555
    invoke-static {v0, p1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 556
    .line 557
    .line 558
    move-result-object v0

    .line 559
    :cond_a
    :goto_6
    move-object v4, v0

    .line 560
    goto :goto_7

    .line 561
    :cond_b
    invoke-static {p1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 562
    .line 563
    .line 564
    move-result-object v0

    .line 565
    goto :goto_6

    .line 566
    :cond_c
    new-instance p0, La8/r0;

    .line 567
    .line 568
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 569
    .line 570
    .line 571
    throw p0

    .line 572
    :cond_d
    invoke-interface {v0, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 573
    .line 574
    .line 575
    move-result v1

    .line 576
    if-nez v1, :cond_e

    .line 577
    .line 578
    invoke-static {v0, p1}, Ljp/m1;->i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 579
    .line 580
    .line 581
    move-result-object v0

    .line 582
    goto :goto_6

    .line 583
    :cond_e
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 584
    .line 585
    .line 586
    move-result v1

    .line 587
    if-le v1, v2, :cond_a

    .line 588
    .line 589
    invoke-static {v0, p1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    goto :goto_6

    .line 594
    :cond_f
    invoke-static {p1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 595
    .line 596
    .line 597
    move-result-object v0

    .line 598
    goto :goto_6

    .line 599
    :goto_7
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 600
    .line 601
    .line 602
    move-result-object p1

    .line 603
    move-object v1, p1

    .line 604
    check-cast v1, Lbo0/q;

    .line 605
    .line 606
    const/4 v12, 0x0

    .line 607
    const/16 v13, 0x7fb

    .line 608
    .line 609
    const/4 v2, 0x0

    .line 610
    const/4 v3, 0x0

    .line 611
    const/4 v5, 0x0

    .line 612
    const/4 v6, 0x0

    .line 613
    const/4 v7, 0x0

    .line 614
    const/4 v8, 0x0

    .line 615
    const/4 v9, 0x0

    .line 616
    const/4 v10, 0x0

    .line 617
    const/4 v11, 0x0

    .line 618
    invoke-static/range {v1 .. v13}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 619
    .line 620
    .line 621
    move-result-object p1

    .line 622
    invoke-virtual {p0, p1}, Lbo0/r;->h(Lbo0/q;)Lbo0/q;

    .line 623
    .line 624
    .line 625
    move-result-object p1

    .line 626
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 627
    .line 628
    .line 629
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 630
    .line 631
    return-object p0

    .line 632
    :pswitch_8
    move-object v2, p1

    .line 633
    check-cast v2, Ljava/time/LocalTime;

    .line 634
    .line 635
    const-string p1, "p0"

    .line 636
    .line 637
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 638
    .line 639
    .line 640
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 641
    .line 642
    check-cast p0, Lbo0/d;

    .line 643
    .line 644
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 645
    .line 646
    .line 647
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 648
    .line 649
    .line 650
    move-result-object p1

    .line 651
    move-object v0, p1

    .line 652
    check-cast v0, Lbo0/c;

    .line 653
    .line 654
    const/4 v4, 0x0

    .line 655
    const/4 v5, 0x5

    .line 656
    const/4 v1, 0x0

    .line 657
    const/4 v3, 0x0

    .line 658
    invoke-static/range {v0 .. v5}, Lbo0/c;->a(Lbo0/c;Ljava/time/LocalTime;Ljava/time/LocalTime;ZZI)Lbo0/c;

    .line 659
    .line 660
    .line 661
    move-result-object p1

    .line 662
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 663
    .line 664
    .line 665
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 666
    .line 667
    return-object p0

    .line 668
    :pswitch_9
    move-object v1, p1

    .line 669
    check-cast v1, Ljava/time/LocalTime;

    .line 670
    .line 671
    const-string p1, "p0"

    .line 672
    .line 673
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 674
    .line 675
    .line 676
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 677
    .line 678
    check-cast p0, Lbo0/d;

    .line 679
    .line 680
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 681
    .line 682
    .line 683
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 684
    .line 685
    .line 686
    move-result-object p1

    .line 687
    move-object v0, p1

    .line 688
    check-cast v0, Lbo0/c;

    .line 689
    .line 690
    const/4 v4, 0x0

    .line 691
    const/16 v5, 0xa

    .line 692
    .line 693
    const/4 v2, 0x0

    .line 694
    const/4 v3, 0x0

    .line 695
    invoke-static/range {v0 .. v5}, Lbo0/c;->a(Lbo0/c;Ljava/time/LocalTime;Ljava/time/LocalTime;ZZI)Lbo0/c;

    .line 696
    .line 697
    .line 698
    move-result-object p1

    .line 699
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 700
    .line 701
    .line 702
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 703
    .line 704
    return-object p0

    .line 705
    :pswitch_a
    check-cast p1, Lci/b;

    .line 706
    .line 707
    const-string v0, "p0"

    .line 708
    .line 709
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 710
    .line 711
    .line 712
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 713
    .line 714
    check-cast p0, Lci/e;

    .line 715
    .line 716
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 717
    .line 718
    .line 719
    sget-object v0, Lci/b;->a:Lci/b;

    .line 720
    .line 721
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 722
    .line 723
    .line 724
    move-result p1

    .line 725
    if-eqz p1, :cond_10

    .line 726
    .line 727
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 728
    .line 729
    .line 730
    move-result-object p1

    .line 731
    new-instance v0, Lc80/l;

    .line 732
    .line 733
    const/16 v1, 0x9

    .line 734
    .line 735
    const/4 v2, 0x0

    .line 736
    invoke-direct {v0, p0, v2, v1}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 737
    .line 738
    .line 739
    const/4 p0, 0x3

    .line 740
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 741
    .line 742
    .line 743
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 744
    .line 745
    return-object p0

    .line 746
    :cond_10
    new-instance p0, La8/r0;

    .line 747
    .line 748
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 749
    .line 750
    .line 751
    throw p0

    .line 752
    :pswitch_b
    check-cast p1, Lcf/c;

    .line 753
    .line 754
    const-string v0, "p0"

    .line 755
    .line 756
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 757
    .line 758
    .line 759
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 760
    .line 761
    check-cast p0, Lcf/e;

    .line 762
    .line 763
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 764
    .line 765
    .line 766
    iget-object v0, p0, Lcf/e;->e:Llx0/q;

    .line 767
    .line 768
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 769
    .line 770
    .line 771
    move-result-object v0

    .line 772
    check-cast v0, Lzb/k0;

    .line 773
    .line 774
    new-instance v1, La60/f;

    .line 775
    .line 776
    const/4 v2, 0x0

    .line 777
    const/16 v3, 0x18

    .line 778
    .line 779
    invoke-direct {v1, v3, p1, p0, v2}, La60/f;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 780
    .line 781
    .line 782
    invoke-static {v0, v1}, Lzb/k0;->b(Lzb/k0;Lay0/n;)V

    .line 783
    .line 784
    .line 785
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 786
    .line 787
    return-object p0

    .line 788
    :pswitch_c
    if-nez p1, :cond_11

    .line 789
    .line 790
    const-string p0, "p0"

    .line 791
    .line 792
    const/4 p1, 0x0

    .line 793
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 794
    .line 795
    .line 796
    throw p1

    .line 797
    :cond_11
    new-instance p0, Ljava/lang/ClassCastException;

    .line 798
    .line 799
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 800
    .line 801
    .line 802
    throw p0

    .line 803
    :pswitch_d
    if-nez p1, :cond_12

    .line 804
    .line 805
    const-string p0, "p0"

    .line 806
    .line 807
    const/4 p1, 0x0

    .line 808
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 809
    .line 810
    .line 811
    throw p1

    .line 812
    :cond_12
    new-instance p0, Ljava/lang/ClassCastException;

    .line 813
    .line 814
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 815
    .line 816
    .line 817
    throw p0

    .line 818
    :pswitch_e
    check-cast p1, Ljava/lang/String;

    .line 819
    .line 820
    const-string v0, "p0"

    .line 821
    .line 822
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 823
    .line 824
    .line 825
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 826
    .line 827
    check-cast p0, Lba0/v;

    .line 828
    .line 829
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 830
    .line 831
    .line 832
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    check-cast v0, Lba0/u;

    .line 837
    .line 838
    iget-object v0, v0, Lba0/u;->c:Laa0/c;

    .line 839
    .line 840
    if-nez v0, :cond_13

    .line 841
    .line 842
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 843
    .line 844
    .line 845
    move-result-object v0

    .line 846
    new-instance v1, La50/c;

    .line 847
    .line 848
    const/16 v2, 0xb

    .line 849
    .line 850
    const/4 v3, 0x0

    .line 851
    invoke-direct {v1, v2, p0, p1, v3}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 852
    .line 853
    .line 854
    const/4 p0, 0x3

    .line 855
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 856
    .line 857
    .line 858
    :cond_13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 859
    .line 860
    return-object p0

    .line 861
    :pswitch_f
    check-cast p1, Ljava/lang/String;

    .line 862
    .line 863
    const-string v0, "p0"

    .line 864
    .line 865
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 866
    .line 867
    .line 868
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 869
    .line 870
    check-cast p0, Lba0/q;

    .line 871
    .line 872
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 873
    .line 874
    .line 875
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 876
    .line 877
    .line 878
    move-result-object v0

    .line 879
    new-instance v1, Lba0/p;

    .line 880
    .line 881
    const/4 v2, 0x1

    .line 882
    const/4 v3, 0x0

    .line 883
    invoke-direct {v1, p0, p1, v3, v2}, Lba0/p;-><init>(Lba0/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 884
    .line 885
    .line 886
    const/4 p0, 0x3

    .line 887
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 888
    .line 889
    .line 890
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 891
    .line 892
    return-object p0

    .line 893
    :pswitch_10
    check-cast p1, Laa0/e;

    .line 894
    .line 895
    const-string v0, "p0"

    .line 896
    .line 897
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 898
    .line 899
    .line 900
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 901
    .line 902
    check-cast p0, Lba0/q;

    .line 903
    .line 904
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 905
    .line 906
    .line 907
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 908
    .line 909
    .line 910
    move-result v0

    .line 911
    if-eqz v0, :cond_15

    .line 912
    .line 913
    const/4 v1, 0x1

    .line 914
    if-ne v0, v1, :cond_14

    .line 915
    .line 916
    const v0, 0x7f121534

    .line 917
    .line 918
    .line 919
    goto :goto_8

    .line 920
    :cond_14
    new-instance p0, La8/r0;

    .line 921
    .line 922
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 923
    .line 924
    .line 925
    throw p0

    .line 926
    :cond_15
    const v0, 0x7f121532

    .line 927
    .line 928
    .line 929
    :goto_8
    new-instance v1, Lba0/h;

    .line 930
    .line 931
    const/4 v2, 0x0

    .line 932
    invoke-direct {v1, p0, v0, v2}, Lba0/h;-><init>(Ljava/lang/Object;II)V

    .line 933
    .line 934
    .line 935
    invoke-static {p1, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 936
    .line 937
    .line 938
    iget-object p0, p0, Lba0/q;->k:Lz90/t;

    .line 939
    .line 940
    invoke-virtual {p0, p1}, Lz90/t;->a(Laa0/e;)V

    .line 941
    .line 942
    .line 943
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 944
    .line 945
    return-object p0

    .line 946
    :pswitch_11
    check-cast p1, Ljava/lang/String;

    .line 947
    .line 948
    const-string v0, "p0"

    .line 949
    .line 950
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 951
    .line 952
    .line 953
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 954
    .line 955
    check-cast p0, Lba0/q;

    .line 956
    .line 957
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 958
    .line 959
    .line 960
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 961
    .line 962
    .line 963
    move-result-object v0

    .line 964
    new-instance v1, Lba0/p;

    .line 965
    .line 966
    const/4 v2, 0x0

    .line 967
    const/4 v3, 0x0

    .line 968
    invoke-direct {v1, p0, p1, v3, v2}, Lba0/p;-><init>(Lba0/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 969
    .line 970
    .line 971
    const/4 p0, 0x3

    .line 972
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 973
    .line 974
    .line 975
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 976
    .line 977
    return-object p0

    .line 978
    :pswitch_12
    check-cast p1, Ljava/lang/String;

    .line 979
    .line 980
    const-string v0, "p0"

    .line 981
    .line 982
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 983
    .line 984
    .line 985
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 986
    .line 987
    check-cast p0, Lba0/g;

    .line 988
    .line 989
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 990
    .line 991
    .line 992
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 993
    .line 994
    .line 995
    move-result-object v0

    .line 996
    new-instance v1, La50/c;

    .line 997
    .line 998
    const/16 v2, 0xa

    .line 999
    .line 1000
    const/4 v3, 0x0

    .line 1001
    invoke-direct {v1, v2, p0, p1, v3}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1002
    .line 1003
    .line 1004
    const/4 p0, 0x3

    .line 1005
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1006
    .line 1007
    .line 1008
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1009
    .line 1010
    return-object p0

    .line 1011
    :pswitch_13
    move-object v1, p1

    .line 1012
    check-cast v1, Ljava/lang/String;

    .line 1013
    .line 1014
    const-string p1, "p0"

    .line 1015
    .line 1016
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1017
    .line 1018
    .line 1019
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1020
    .line 1021
    check-cast p0, Lba0/g;

    .line 1022
    .line 1023
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1024
    .line 1025
    .line 1026
    iget-object p1, p0, Lba0/g;->j:Lz90/m;

    .line 1027
    .line 1028
    invoke-virtual {p1, v1}, Lz90/m;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 1029
    .line 1030
    .line 1031
    move-result-object p1

    .line 1032
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1033
    .line 1034
    .line 1035
    move-result p1

    .line 1036
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 1037
    .line 1038
    .line 1039
    move-result-object v0

    .line 1040
    check-cast v0, Lba0/f;

    .line 1041
    .line 1042
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 1043
    .line 1044
    .line 1045
    move-result v2

    .line 1046
    const/4 v3, 0x1

    .line 1047
    if-lez v2, :cond_16

    .line 1048
    .line 1049
    if-eqz p1, :cond_16

    .line 1050
    .line 1051
    move v2, v3

    .line 1052
    goto :goto_9

    .line 1053
    :cond_16
    const/4 v2, 0x0

    .line 1054
    :goto_9
    xor-int/lit8 v4, p1, 0x1

    .line 1055
    .line 1056
    const/4 v5, 0x0

    .line 1057
    const/16 v6, 0x32

    .line 1058
    .line 1059
    move v3, v2

    .line 1060
    const/4 v2, 0x0

    .line 1061
    invoke-static/range {v0 .. v6}, Lba0/f;->a(Lba0/f;Ljava/lang/String;Ljava/lang/String;ZZLql0/g;I)Lba0/f;

    .line 1062
    .line 1063
    .line 1064
    move-result-object p1

    .line 1065
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 1066
    .line 1067
    .line 1068
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1069
    .line 1070
    return-object p0

    .line 1071
    :pswitch_14
    move-object v0, p1

    .line 1072
    check-cast v0, Lbi/e;

    .line 1073
    .line 1074
    const-string p1, "p0"

    .line 1075
    .line 1076
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1077
    .line 1078
    .line 1079
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1080
    .line 1081
    move-object v1, p0

    .line 1082
    check-cast v1, Lbi/g;

    .line 1083
    .line 1084
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1085
    .line 1086
    .line 1087
    iget-object v2, v1, Lbi/g;->i:Lyy0/c2;

    .line 1088
    .line 1089
    :cond_17
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 1090
    .line 1091
    .line 1092
    move-result-object p0

    .line 1093
    move-object p1, p0

    .line 1094
    check-cast p1, Lbi/f;

    .line 1095
    .line 1096
    iget-object v4, p1, Lbi/f;->a:Lzg/h;

    .line 1097
    .line 1098
    iget-boolean v5, p1, Lbi/f;->b:Z

    .line 1099
    .line 1100
    iget-object v6, p1, Lbi/f;->c:Lai/a;

    .line 1101
    .line 1102
    iget-boolean v7, p1, Lbi/f;->d:Z

    .line 1103
    .line 1104
    new-instance v3, Lbi/f;

    .line 1105
    .line 1106
    const/4 v8, 0x0

    .line 1107
    invoke-direct/range {v3 .. v8}, Lbi/f;-><init>(Lzg/h;ZLai/a;ZZ)V

    .line 1108
    .line 1109
    .line 1110
    invoke-virtual {v2, p0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 1111
    .line 1112
    .line 1113
    move-result p0

    .line 1114
    if-eqz p0, :cond_17

    .line 1115
    .line 1116
    sget-object p0, Lbi/d;->a:Lbi/d;

    .line 1117
    .line 1118
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1119
    .line 1120
    .line 1121
    move-result p0

    .line 1122
    if-eqz p0, :cond_18

    .line 1123
    .line 1124
    iget-object p0, v1, Lbi/g;->g:Lbi/b;

    .line 1125
    .line 1126
    iget-object p1, v1, Lbi/g;->d:Lzg/h;

    .line 1127
    .line 1128
    invoke-virtual {p0, p1}, Lbi/b;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1129
    .line 1130
    .line 1131
    goto :goto_b

    .line 1132
    :cond_18
    sget-object p0, Lbi/c;->a:Lbi/c;

    .line 1133
    .line 1134
    invoke-virtual {v0, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1135
    .line 1136
    .line 1137
    move-result p0

    .line 1138
    if-eqz p0, :cond_1a

    .line 1139
    .line 1140
    iget-object p0, v1, Lbi/g;->h:Lzb/d;

    .line 1141
    .line 1142
    iget-object p1, v1, Lbi/g;->f:Lzg/c1;

    .line 1143
    .line 1144
    iget-object v0, v1, Lbi/g;->e:Lai/a;

    .line 1145
    .line 1146
    if-eqz v0, :cond_19

    .line 1147
    .line 1148
    iget-object v0, v0, Lai/a;->b:Lai/b;

    .line 1149
    .line 1150
    goto :goto_a

    .line 1151
    :cond_19
    const/4 v0, 0x0

    .line 1152
    :goto_a
    invoke-virtual {p0, p1, v0}, Lzb/d;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1153
    .line 1154
    .line 1155
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1156
    .line 1157
    return-object p0

    .line 1158
    :cond_1a
    new-instance p0, La8/r0;

    .line 1159
    .line 1160
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1161
    .line 1162
    .line 1163
    throw p0

    .line 1164
    :pswitch_15
    check-cast p1, Lbf/c;

    .line 1165
    .line 1166
    const-string v0, "p0"

    .line 1167
    .line 1168
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1169
    .line 1170
    .line 1171
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1172
    .line 1173
    check-cast p0, Lbf/d;

    .line 1174
    .line 1175
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1176
    .line 1177
    .line 1178
    sget-object v0, Lbf/c;->a:Lbf/c;

    .line 1179
    .line 1180
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1181
    .line 1182
    .line 1183
    move-result p1

    .line 1184
    if-eqz p1, :cond_1b

    .line 1185
    .line 1186
    iget-object p0, p0, Lbf/d;->e:Lay0/a;

    .line 1187
    .line 1188
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 1189
    .line 1190
    .line 1191
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1192
    .line 1193
    return-object p0

    .line 1194
    :cond_1b
    new-instance p0, La8/r0;

    .line 1195
    .line 1196
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1197
    .line 1198
    .line 1199
    throw p0

    .line 1200
    :pswitch_16
    check-cast p1, Ljava/lang/String;

    .line 1201
    .line 1202
    const-string v0, "p0"

    .line 1203
    .line 1204
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1205
    .line 1206
    .line 1207
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1208
    .line 1209
    check-cast p0, La60/j;

    .line 1210
    .line 1211
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1212
    .line 1213
    .line 1214
    const-string v0, "https"

    .line 1215
    .line 1216
    const/4 v1, 0x0

    .line 1217
    invoke-static {p1, v0, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 1218
    .line 1219
    .line 1220
    move-result v0

    .line 1221
    if-eqz v0, :cond_20

    .line 1222
    .line 1223
    iget-object p0, p0, La60/j;->i:Lbd0/c;

    .line 1224
    .line 1225
    const/16 v0, 0x1e

    .line 1226
    .line 1227
    and-int/lit8 v2, v0, 0x2

    .line 1228
    .line 1229
    const/4 v3, 0x1

    .line 1230
    if-eqz v2, :cond_1c

    .line 1231
    .line 1232
    move v6, v3

    .line 1233
    goto :goto_c

    .line 1234
    :cond_1c
    move v6, v1

    .line 1235
    :goto_c
    and-int/lit8 v2, v0, 0x4

    .line 1236
    .line 1237
    if-eqz v2, :cond_1d

    .line 1238
    .line 1239
    move v7, v3

    .line 1240
    goto :goto_d

    .line 1241
    :cond_1d
    move v7, v1

    .line 1242
    :goto_d
    and-int/lit8 v2, v0, 0x8

    .line 1243
    .line 1244
    if-eqz v2, :cond_1e

    .line 1245
    .line 1246
    move v8, v1

    .line 1247
    goto :goto_e

    .line 1248
    :cond_1e
    move v8, v3

    .line 1249
    :goto_e
    and-int/lit8 v0, v0, 0x10

    .line 1250
    .line 1251
    if-eqz v0, :cond_1f

    .line 1252
    .line 1253
    move v9, v1

    .line 1254
    goto :goto_f

    .line 1255
    :cond_1f
    move v9, v3

    .line 1256
    :goto_f
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 1257
    .line 1258
    new-instance v5, Ljava/net/URL;

    .line 1259
    .line 1260
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 1261
    .line 1262
    .line 1263
    move-object v4, p0

    .line 1264
    check-cast v4, Lzc0/b;

    .line 1265
    .line 1266
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 1267
    .line 1268
    .line 1269
    goto :goto_10

    .line 1270
    :cond_20
    iget-object p0, p0, La60/j;->j:Lgf0/e;

    .line 1271
    .line 1272
    new-instance v0, Lhf0/b;

    .line 1273
    .line 1274
    invoke-direct {v0, p1}, Lhf0/b;-><init>(Ljava/lang/String;)V

    .line 1275
    .line 1276
    .line 1277
    iget-object p0, p0, Lgf0/e;->a:Lgf0/a;

    .line 1278
    .line 1279
    check-cast p0, Lef0/a;

    .line 1280
    .line 1281
    iget-object p0, p0, Lef0/a;->a:Lyy0/q1;

    .line 1282
    .line 1283
    invoke-virtual {p0, v0}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 1284
    .line 1285
    .line 1286
    :goto_10
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1287
    .line 1288
    return-object p0

    .line 1289
    :pswitch_17
    check-cast p1, Ljava/lang/Number;

    .line 1290
    .line 1291
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 1292
    .line 1293
    .line 1294
    move-result p1

    .line 1295
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1296
    .line 1297
    check-cast p0, La60/e;

    .line 1298
    .line 1299
    iget-object v0, p0, La60/e;->i:Ly50/h;

    .line 1300
    .line 1301
    invoke-virtual {v0, p1}, Ly50/h;->a(I)Lne0/t;

    .line 1302
    .line 1303
    .line 1304
    move-result-object p1

    .line 1305
    instance-of v0, p1, Lne0/e;

    .line 1306
    .line 1307
    if-eqz v0, :cond_21

    .line 1308
    .line 1309
    move-object v0, p1

    .line 1310
    check-cast v0, Lne0/e;

    .line 1311
    .line 1312
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 1313
    .line 1314
    check-cast v0, Llx0/b0;

    .line 1315
    .line 1316
    iget-object v0, p0, La60/e;->j:Ly50/g;

    .line 1317
    .line 1318
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1319
    .line 1320
    .line 1321
    :cond_21
    instance-of v0, p1, Lne0/c;

    .line 1322
    .line 1323
    if-eqz v0, :cond_22

    .line 1324
    .line 1325
    check-cast p1, Lne0/c;

    .line 1326
    .line 1327
    new-instance v0, La60/a;

    .line 1328
    .line 1329
    const/4 v1, 0x0

    .line 1330
    invoke-direct {v0, p1, v1}, La60/a;-><init>(Lne0/c;I)V

    .line 1331
    .line 1332
    .line 1333
    const/4 p1, 0x0

    .line 1334
    invoke-static {p1, p0, v0}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 1335
    .line 1336
    .line 1337
    :cond_22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1338
    .line 1339
    return-object p0

    .line 1340
    :pswitch_18
    check-cast p1, Ljava/lang/Boolean;

    .line 1341
    .line 1342
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1343
    .line 1344
    .line 1345
    move-result p1

    .line 1346
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1347
    .line 1348
    check-cast p0, La10/d;

    .line 1349
    .line 1350
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1351
    .line 1352
    .line 1353
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1354
    .line 1355
    .line 1356
    move-result-object v0

    .line 1357
    new-instance v1, La10/b;

    .line 1358
    .line 1359
    const/4 v2, 0x0

    .line 1360
    invoke-direct {v1, p0, p1, v2}, La10/b;-><init>(La10/d;ZLkotlin/coroutines/Continuation;)V

    .line 1361
    .line 1362
    .line 1363
    const/4 p0, 0x3

    .line 1364
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1365
    .line 1366
    .line 1367
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1368
    .line 1369
    return-object p0

    .line 1370
    :pswitch_19
    check-cast p1, Ljava/lang/String;

    .line 1371
    .line 1372
    const-string v0, "p0"

    .line 1373
    .line 1374
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1375
    .line 1376
    .line 1377
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1378
    .line 1379
    check-cast p0, Lzi0/f;

    .line 1380
    .line 1381
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1382
    .line 1383
    .line 1384
    iget-object p0, p0, Lzi0/f;->j:Lbd0/c;

    .line 1385
    .line 1386
    const/16 v0, 0x1e

    .line 1387
    .line 1388
    and-int/lit8 v1, v0, 0x2

    .line 1389
    .line 1390
    const/4 v2, 0x0

    .line 1391
    const/4 v3, 0x1

    .line 1392
    if-eqz v1, :cond_23

    .line 1393
    .line 1394
    move v6, v3

    .line 1395
    goto :goto_11

    .line 1396
    :cond_23
    move v6, v2

    .line 1397
    :goto_11
    and-int/lit8 v1, v0, 0x4

    .line 1398
    .line 1399
    if-eqz v1, :cond_24

    .line 1400
    .line 1401
    move v7, v3

    .line 1402
    goto :goto_12

    .line 1403
    :cond_24
    move v7, v2

    .line 1404
    :goto_12
    and-int/lit8 v1, v0, 0x8

    .line 1405
    .line 1406
    if-eqz v1, :cond_25

    .line 1407
    .line 1408
    move v8, v2

    .line 1409
    goto :goto_13

    .line 1410
    :cond_25
    move v8, v3

    .line 1411
    :goto_13
    and-int/lit8 v0, v0, 0x10

    .line 1412
    .line 1413
    if-eqz v0, :cond_26

    .line 1414
    .line 1415
    move v9, v2

    .line 1416
    goto :goto_14

    .line 1417
    :cond_26
    move v9, v3

    .line 1418
    :goto_14
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 1419
    .line 1420
    new-instance v5, Ljava/net/URL;

    .line 1421
    .line 1422
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 1423
    .line 1424
    .line 1425
    move-object v4, p0

    .line 1426
    check-cast v4, Lzc0/b;

    .line 1427
    .line 1428
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 1429
    .line 1430
    .line 1431
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1432
    .line 1433
    return-object p0

    .line 1434
    :pswitch_1a
    check-cast p1, Ljava/lang/String;

    .line 1435
    .line 1436
    const-string v0, "p0"

    .line 1437
    .line 1438
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1439
    .line 1440
    .line 1441
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1442
    .line 1443
    check-cast p0, Lzi0/d;

    .line 1444
    .line 1445
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1446
    .line 1447
    .line 1448
    iget-object p0, p0, Lzi0/d;->l:Lbd0/c;

    .line 1449
    .line 1450
    const/16 v0, 0x1e

    .line 1451
    .line 1452
    and-int/lit8 v1, v0, 0x2

    .line 1453
    .line 1454
    const/4 v2, 0x0

    .line 1455
    const/4 v3, 0x1

    .line 1456
    if-eqz v1, :cond_27

    .line 1457
    .line 1458
    move v6, v3

    .line 1459
    goto :goto_15

    .line 1460
    :cond_27
    move v6, v2

    .line 1461
    :goto_15
    and-int/lit8 v1, v0, 0x4

    .line 1462
    .line 1463
    if-eqz v1, :cond_28

    .line 1464
    .line 1465
    move v7, v3

    .line 1466
    goto :goto_16

    .line 1467
    :cond_28
    move v7, v2

    .line 1468
    :goto_16
    and-int/lit8 v1, v0, 0x8

    .line 1469
    .line 1470
    if-eqz v1, :cond_29

    .line 1471
    .line 1472
    move v8, v2

    .line 1473
    goto :goto_17

    .line 1474
    :cond_29
    move v8, v3

    .line 1475
    :goto_17
    and-int/lit8 v0, v0, 0x10

    .line 1476
    .line 1477
    if-eqz v0, :cond_2a

    .line 1478
    .line 1479
    move v9, v2

    .line 1480
    goto :goto_18

    .line 1481
    :cond_2a
    move v9, v3

    .line 1482
    :goto_18
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 1483
    .line 1484
    new-instance v5, Ljava/net/URL;

    .line 1485
    .line 1486
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 1487
    .line 1488
    .line 1489
    move-object v4, p0

    .line 1490
    check-cast v4, Lzc0/b;

    .line 1491
    .line 1492
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 1493
    .line 1494
    .line 1495
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1496
    .line 1497
    return-object p0

    .line 1498
    :pswitch_1b
    if-nez p1, :cond_2b

    .line 1499
    .line 1500
    const-string p0, "p0"

    .line 1501
    .line 1502
    const/4 p1, 0x0

    .line 1503
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1504
    .line 1505
    .line 1506
    throw p1

    .line 1507
    :cond_2b
    new-instance p0, Ljava/lang/ClassCastException;

    .line 1508
    .line 1509
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 1510
    .line 1511
    .line 1512
    throw p0

    .line 1513
    :pswitch_1c
    check-cast p1, Laf/c;

    .line 1514
    .line 1515
    const-string v0, "p0"

    .line 1516
    .line 1517
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1518
    .line 1519
    .line 1520
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1521
    .line 1522
    check-cast p0, Laf/e;

    .line 1523
    .line 1524
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1525
    .line 1526
    .line 1527
    sget-object v0, Laf/c;->a:Laf/c;

    .line 1528
    .line 1529
    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1530
    .line 1531
    .line 1532
    move-result p1

    .line 1533
    if-eqz p1, :cond_2c

    .line 1534
    .line 1535
    iget-object p0, p0, Laf/e;->d:Lle/a;

    .line 1536
    .line 1537
    invoke-virtual {p0}, Lle/a;->invoke()Ljava/lang/Object;

    .line 1538
    .line 1539
    .line 1540
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1541
    .line 1542
    return-object p0

    .line 1543
    :cond_2c
    new-instance p0, La8/r0;

    .line 1544
    .line 1545
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1546
    .line 1547
    .line 1548
    throw p0

    .line 1549
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
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
