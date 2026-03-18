.class public final Lnt0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnt0/i;


# direct methods
.method public synthetic constructor <init>(Lnt0/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lnt0/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnt0/c;->e:Lnt0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lnt0/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lss0/d0;

    .line 7
    .line 8
    instance-of p1, p1, Lss0/g;

    .line 9
    .line 10
    const/4 p2, 0x0

    .line 11
    iget-object p0, p0, Lnt0/c;->e:Lnt0/i;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    iget-object p1, p0, Lnt0/i;->k:Lgn0/f;

    .line 16
    .line 17
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    new-instance v0, Lnt0/f;

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    invoke-direct {v0, v1, p2, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance v0, Lnt0/g;

    .line 32
    .line 33
    const/4 v1, 0x0

    .line 34
    invoke-direct {v0, v1, p2, p0}, Lnt0/g;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 35
    .line 36
    .line 37
    new-instance v1, Lne0/n;

    .line 38
    .line 39
    invoke-direct {v1, v0, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 40
    .line 41
    .line 42
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    new-instance v0, Lnt0/h;

    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    invoke-direct {v0, v1, p2, p0}, Lnt0/h;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 50
    .line 51
    .line 52
    new-instance p2, Lyy0/x;

    .line 53
    .line 54
    invoke-direct {p2, p1, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 55
    .line 56
    .line 57
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-static {p2, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_0
    iget-object p1, p0, Lnt0/i;->j:Lkf0/m;

    .line 66
    .line 67
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    new-instance v0, Lnt0/f;

    .line 72
    .line 73
    const/4 v1, 0x3

    .line 74
    invoke-direct {v0, v1, p2, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 75
    .line 76
    .line 77
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    new-instance v0, Lnt0/g;

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    invoke-direct {v0, v1, p2, p0}, Lnt0/g;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 85
    .line 86
    .line 87
    new-instance v1, Lne0/n;

    .line 88
    .line 89
    invoke-direct {v1, v0, p1}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 90
    .line 91
    .line 92
    invoke-static {v1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 93
    .line 94
    .line 95
    move-result-object p1

    .line 96
    new-instance v0, Lnt0/h;

    .line 97
    .line 98
    const/4 v1, 0x1

    .line 99
    invoke-direct {v0, v1, p2, p0}, Lnt0/h;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 100
    .line 101
    .line 102
    new-instance p2, Lyy0/x;

    .line 103
    .line 104
    invoke-direct {p2, p1, v0}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 105
    .line 106
    .line 107
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    invoke-static {p2, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 112
    .line 113
    .line 114
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0

    .line 117
    :pswitch_0
    check-cast p1, Lne0/t;

    .line 118
    .line 119
    instance-of p2, p1, Lne0/c;

    .line 120
    .line 121
    if-eqz p2, :cond_1

    .line 122
    .line 123
    iget-object p0, p0, Lnt0/c;->e:Lnt0/i;

    .line 124
    .line 125
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 126
    .line 127
    .line 128
    move-result-object p2

    .line 129
    move-object v0, p2

    .line 130
    check-cast v0, Lnt0/e;

    .line 131
    .line 132
    check-cast p1, Lne0/c;

    .line 133
    .line 134
    iget-object p2, p0, Lnt0/i;->r:Lij0/a;

    .line 135
    .line 136
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    const/4 v7, 0x0

    .line 141
    const/16 v8, 0x7e

    .line 142
    .line 143
    const/4 v2, 0x0

    .line 144
    const/4 v3, 0x0

    .line 145
    const/4 v4, 0x0

    .line 146
    const/4 v5, 0x0

    .line 147
    const/4 v6, 0x0

    .line 148
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 153
    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_1
    instance-of p0, p1, Lne0/e;

    .line 157
    .line 158
    if-eqz p0, :cond_2

    .line 159
    .line 160
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 161
    .line 162
    return-object p0

    .line 163
    :cond_2
    new-instance p0, La8/r0;

    .line 164
    .line 165
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 166
    .line 167
    .line 168
    throw p0

    .line 169
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 170
    .line 171
    instance-of p2, p1, Lne0/c;

    .line 172
    .line 173
    iget-object p0, p0, Lnt0/c;->e:Lnt0/i;

    .line 174
    .line 175
    if-eqz p2, :cond_3

    .line 176
    .line 177
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 178
    .line 179
    .line 180
    move-result-object p2

    .line 181
    move-object v0, p2

    .line 182
    check-cast v0, Lnt0/e;

    .line 183
    .line 184
    check-cast p1, Lne0/c;

    .line 185
    .line 186
    iget-object p2, p0, Lnt0/i;->r:Lij0/a;

    .line 187
    .line 188
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 189
    .line 190
    .line 191
    move-result-object v1

    .line 192
    const/4 v7, 0x0

    .line 193
    const/16 v8, 0x74

    .line 194
    .line 195
    const/4 v2, 0x0

    .line 196
    const/4 v3, 0x0

    .line 197
    const/4 v4, 0x1

    .line 198
    const/4 v5, 0x0

    .line 199
    const/4 v6, 0x0

    .line 200
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    goto :goto_2

    .line 205
    :cond_3
    instance-of p2, p1, Lne0/d;

    .line 206
    .line 207
    if-eqz p2, :cond_4

    .line 208
    .line 209
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 210
    .line 211
    .line 212
    move-result-object p1

    .line 213
    move-object v0, p1

    .line 214
    check-cast v0, Lnt0/e;

    .line 215
    .line 216
    const/4 v7, 0x0

    .line 217
    const/16 v8, 0x7d

    .line 218
    .line 219
    const/4 v1, 0x0

    .line 220
    const/4 v2, 0x1

    .line 221
    const/4 v3, 0x0

    .line 222
    const/4 v4, 0x0

    .line 223
    const/4 v5, 0x0

    .line 224
    const/4 v6, 0x0

    .line 225
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    goto :goto_2

    .line 230
    :cond_4
    instance-of p2, p1, Lne0/e;

    .line 231
    .line 232
    if-eqz p2, :cond_5

    .line 233
    .line 234
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 235
    .line 236
    .line 237
    move-result-object p2

    .line 238
    move-object v0, p2

    .line 239
    check-cast v0, Lnt0/e;

    .line 240
    .line 241
    check-cast p1, Lne0/e;

    .line 242
    .line 243
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 244
    .line 245
    move-object v6, p1

    .line 246
    check-cast v6, Ljava/util/List;

    .line 247
    .line 248
    const/4 v7, 0x0

    .line 249
    const/16 v8, 0x55

    .line 250
    .line 251
    const/4 v1, 0x0

    .line 252
    const/4 v2, 0x0

    .line 253
    const/4 v3, 0x0

    .line 254
    const/4 v4, 0x0

    .line 255
    const/4 v5, 0x0

    .line 256
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 257
    .line 258
    .line 259
    move-result-object p1

    .line 260
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 261
    .line 262
    .line 263
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 264
    .line 265
    return-object p0

    .line 266
    :cond_5
    new-instance p0, La8/r0;

    .line 267
    .line 268
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 269
    .line 270
    .line 271
    throw p0

    .line 272
    :pswitch_2
    check-cast p1, Lne0/s;

    .line 273
    .line 274
    instance-of p2, p1, Lne0/c;

    .line 275
    .line 276
    iget-object p0, p0, Lnt0/c;->e:Lnt0/i;

    .line 277
    .line 278
    if-eqz p2, :cond_6

    .line 279
    .line 280
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 281
    .line 282
    .line 283
    move-result-object p2

    .line 284
    move-object v0, p2

    .line 285
    check-cast v0, Lnt0/e;

    .line 286
    .line 287
    check-cast p1, Lne0/c;

    .line 288
    .line 289
    iget-object p2, p0, Lnt0/i;->r:Lij0/a;

    .line 290
    .line 291
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 292
    .line 293
    .line 294
    move-result-object v1

    .line 295
    const/4 v7, 0x0

    .line 296
    const/16 v8, 0x74

    .line 297
    .line 298
    const/4 v2, 0x0

    .line 299
    const/4 v3, 0x0

    .line 300
    const/4 v4, 0x1

    .line 301
    const/4 v5, 0x0

    .line 302
    const/4 v6, 0x0

    .line 303
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 304
    .line 305
    .line 306
    move-result-object p1

    .line 307
    goto :goto_3

    .line 308
    :cond_6
    instance-of p2, p1, Lne0/d;

    .line 309
    .line 310
    if-eqz p2, :cond_7

    .line 311
    .line 312
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 313
    .line 314
    .line 315
    move-result-object p1

    .line 316
    move-object v0, p1

    .line 317
    check-cast v0, Lnt0/e;

    .line 318
    .line 319
    const/4 v7, 0x0

    .line 320
    const/16 v8, 0x7d

    .line 321
    .line 322
    const/4 v1, 0x0

    .line 323
    const/4 v2, 0x1

    .line 324
    const/4 v3, 0x0

    .line 325
    const/4 v4, 0x0

    .line 326
    const/4 v5, 0x0

    .line 327
    const/4 v6, 0x0

    .line 328
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 329
    .line 330
    .line 331
    move-result-object p1

    .line 332
    goto :goto_3

    .line 333
    :cond_7
    instance-of p2, p1, Lne0/e;

    .line 334
    .line 335
    if-eqz p2, :cond_8

    .line 336
    .line 337
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 338
    .line 339
    .line 340
    move-result-object p2

    .line 341
    move-object v0, p2

    .line 342
    check-cast v0, Lnt0/e;

    .line 343
    .line 344
    check-cast p1, Lne0/e;

    .line 345
    .line 346
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 347
    .line 348
    move-object v6, p1

    .line 349
    check-cast v6, Ljava/util/List;

    .line 350
    .line 351
    const/4 v7, 0x0

    .line 352
    const/16 v8, 0x55

    .line 353
    .line 354
    const/4 v1, 0x0

    .line 355
    const/4 v2, 0x0

    .line 356
    const/4 v3, 0x0

    .line 357
    const/4 v4, 0x0

    .line 358
    const/4 v5, 0x0

    .line 359
    invoke-static/range {v0 .. v8}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 360
    .line 361
    .line 362
    move-result-object p1

    .line 363
    :goto_3
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 364
    .line 365
    .line 366
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 367
    .line 368
    return-object p0

    .line 369
    :cond_8
    new-instance p0, La8/r0;

    .line 370
    .line 371
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 372
    .line 373
    .line 374
    throw p0

    .line 375
    :pswitch_3
    check-cast p1, Lss0/d0;

    .line 376
    .line 377
    instance-of p1, p1, Lss0/g;

    .line 378
    .line 379
    const/4 v0, 0x0

    .line 380
    iget-object p0, p0, Lnt0/c;->e:Lnt0/i;

    .line 381
    .line 382
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 383
    .line 384
    if-eqz p1, :cond_a

    .line 385
    .line 386
    iget-object p1, p0, Lnt0/i;->k:Lgn0/f;

    .line 387
    .line 388
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 389
    .line 390
    .line 391
    move-result-object p1

    .line 392
    new-instance v2, Lnt0/f;

    .line 393
    .line 394
    const/4 v3, 0x1

    .line 395
    invoke-direct {v2, v3, v0, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 396
    .line 397
    .line 398
    invoke-static {p1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 399
    .line 400
    .line 401
    move-result-object p1

    .line 402
    new-instance v0, Lnt0/c;

    .line 403
    .line 404
    const/4 v2, 0x2

    .line 405
    invoke-direct {v0, p0, v2}, Lnt0/c;-><init>(Lnt0/i;I)V

    .line 406
    .line 407
    .line 408
    invoke-virtual {p1, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object p0

    .line 412
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 413
    .line 414
    if-ne p0, p1, :cond_9

    .line 415
    .line 416
    goto :goto_4

    .line 417
    :cond_9
    move-object p0, v1

    .line 418
    :goto_4
    if-ne p0, p1, :cond_c

    .line 419
    .line 420
    :goto_5
    move-object v1, p0

    .line 421
    goto :goto_7

    .line 422
    :cond_a
    iget-object p1, p0, Lnt0/i;->j:Lkf0/m;

    .line 423
    .line 424
    invoke-static {p1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 425
    .line 426
    .line 427
    move-result-object p1

    .line 428
    new-instance v2, Lnt0/f;

    .line 429
    .line 430
    const/4 v3, 0x0

    .line 431
    invoke-direct {v2, v3, v0, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 432
    .line 433
    .line 434
    invoke-static {p1, v2}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 435
    .line 436
    .line 437
    move-result-object p1

    .line 438
    new-instance v0, Lnt0/c;

    .line 439
    .line 440
    const/4 v2, 0x1

    .line 441
    invoke-direct {v0, p0, v2}, Lnt0/c;-><init>(Lnt0/i;I)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {p1, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 445
    .line 446
    .line 447
    move-result-object p0

    .line 448
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 449
    .line 450
    if-ne p0, p1, :cond_b

    .line 451
    .line 452
    goto :goto_6

    .line 453
    :cond_b
    move-object p0, v1

    .line 454
    :goto_6
    if-ne p0, p1, :cond_c

    .line 455
    .line 456
    goto :goto_5

    .line 457
    :cond_c
    :goto_7
    return-object v1

    .line 458
    nop

    .line 459
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
