.class public final synthetic Lc4/i;
.super Lkotlin/jvm/internal/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Lc4/i;->d:I

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
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lc4/i;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    const-string v0, "p0"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Ltz/l3;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    new-instance v1, Ltz/k3;

    .line 25
    .line 26
    const/4 v2, 0x1

    .line 27
    const/4 v3, 0x0

    .line 28
    invoke-direct {v1, p0, p1, v3, v2}, Ltz/k3;-><init>(Ltz/l3;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x3

    .line 32
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 39
    .line 40
    const-string v0, "p0"

    .line 41
    .line 42
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Ltz/l3;

    .line 48
    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    new-instance v1, Ltz/k3;

    .line 57
    .line 58
    const/4 v2, 0x0

    .line 59
    const/4 v3, 0x0

    .line 60
    invoke-direct {v1, p0, p1, v3, v2}, Ltz/k3;-><init>(Ltz/l3;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 61
    .line 62
    .line 63
    const/4 p0, 0x3

    .line 64
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 65
    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0

    .line 70
    :pswitch_1
    check-cast p1, Ljava/lang/String;

    .line 71
    .line 72
    const-string v0, "p0"

    .line 73
    .line 74
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lr60/p;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    iget-object p0, p0, Lr60/p;->o:Lbd0/c;

    .line 85
    .line 86
    const/16 v0, 0x1e

    .line 87
    .line 88
    and-int/lit8 v1, v0, 0x2

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    const/4 v3, 0x1

    .line 92
    if-eqz v1, :cond_0

    .line 93
    .line 94
    move v6, v3

    .line 95
    goto :goto_0

    .line 96
    :cond_0
    move v6, v2

    .line 97
    :goto_0
    and-int/lit8 v1, v0, 0x4

    .line 98
    .line 99
    if-eqz v1, :cond_1

    .line 100
    .line 101
    move v7, v3

    .line 102
    goto :goto_1

    .line 103
    :cond_1
    move v7, v2

    .line 104
    :goto_1
    and-int/lit8 v1, v0, 0x8

    .line 105
    .line 106
    if-eqz v1, :cond_2

    .line 107
    .line 108
    move v8, v2

    .line 109
    goto :goto_2

    .line 110
    :cond_2
    move v8, v3

    .line 111
    :goto_2
    and-int/lit8 v0, v0, 0x10

    .line 112
    .line 113
    if-eqz v0, :cond_3

    .line 114
    .line 115
    move v9, v2

    .line 116
    goto :goto_3

    .line 117
    :cond_3
    move v9, v3

    .line 118
    :goto_3
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 119
    .line 120
    new-instance v5, Ljava/net/URL;

    .line 121
    .line 122
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    move-object v4, p0

    .line 126
    check-cast v4, Lzc0/b;

    .line 127
    .line 128
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 129
    .line 130
    .line 131
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    return-object p0

    .line 134
    :pswitch_2
    check-cast p1, Ljava/lang/String;

    .line 135
    .line 136
    const-string v0, "p0"

    .line 137
    .line 138
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 139
    .line 140
    .line 141
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p0, Lq40/t;

    .line 144
    .line 145
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    iget-object p0, p0, Lq40/t;->i:Lbd0/c;

    .line 149
    .line 150
    const/16 v0, 0x1e

    .line 151
    .line 152
    and-int/lit8 v1, v0, 0x2

    .line 153
    .line 154
    const/4 v2, 0x0

    .line 155
    const/4 v3, 0x1

    .line 156
    if-eqz v1, :cond_4

    .line 157
    .line 158
    move v6, v3

    .line 159
    goto :goto_4

    .line 160
    :cond_4
    move v6, v2

    .line 161
    :goto_4
    and-int/lit8 v1, v0, 0x4

    .line 162
    .line 163
    if-eqz v1, :cond_5

    .line 164
    .line 165
    move v7, v3

    .line 166
    goto :goto_5

    .line 167
    :cond_5
    move v7, v2

    .line 168
    :goto_5
    and-int/lit8 v1, v0, 0x8

    .line 169
    .line 170
    if-eqz v1, :cond_6

    .line 171
    .line 172
    move v8, v2

    .line 173
    goto :goto_6

    .line 174
    :cond_6
    move v8, v3

    .line 175
    :goto_6
    and-int/lit8 v0, v0, 0x10

    .line 176
    .line 177
    if-eqz v0, :cond_7

    .line 178
    .line 179
    move v9, v2

    .line 180
    goto :goto_7

    .line 181
    :cond_7
    move v9, v3

    .line 182
    :goto_7
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 183
    .line 184
    new-instance v5, Ljava/net/URL;

    .line 185
    .line 186
    invoke-direct {v5, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    move-object v4, p0

    .line 190
    check-cast v4, Lzc0/b;

    .line 191
    .line 192
    invoke-virtual/range {v4 .. v9}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 193
    .line 194
    .line 195
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 196
    .line 197
    return-object p0

    .line 198
    :pswitch_3
    check-cast p1, Ljava/lang/Boolean;

    .line 199
    .line 200
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 201
    .line 202
    .line 203
    move-result p1

    .line 204
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 205
    .line 206
    check-cast p0, Lnz/j;

    .line 207
    .line 208
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 209
    .line 210
    .line 211
    const/4 v0, 0x3

    .line 212
    const/4 v1, 0x0

    .line 213
    if-eqz p1, :cond_8

    .line 214
    .line 215
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 216
    .line 217
    .line 218
    move-result-object p1

    .line 219
    new-instance v2, Lny/f0;

    .line 220
    .line 221
    const/4 v3, 0x2

    .line 222
    invoke-direct {v2, p0, v1, v3}, Lny/f0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 223
    .line 224
    .line 225
    invoke-static {p1, v1, v1, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 226
    .line 227
    .line 228
    goto :goto_8

    .line 229
    :cond_8
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    new-instance v2, Lnz/f;

    .line 234
    .line 235
    const/4 v3, 0x1

    .line 236
    invoke-direct {v2, p0, v1, v3}, Lnz/f;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 237
    .line 238
    .line 239
    invoke-static {p1, v1, v1, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 240
    .line 241
    .line 242
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    return-object p0

    .line 245
    :pswitch_4
    check-cast p1, Ll70/h;

    .line 246
    .line 247
    const-string v0, "p0"

    .line 248
    .line 249
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast p0, Lm70/m0;

    .line 255
    .line 256
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 257
    .line 258
    .line 259
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    new-instance v1, Llb0/q0;

    .line 264
    .line 265
    const/16 v2, 0xd

    .line 266
    .line 267
    const/4 v3, 0x0

    .line 268
    invoke-direct {v1, v2, p0, p1, v3}, Llb0/q0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 269
    .line 270
    .line 271
    const/4 p0, 0x3

    .line 272
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 273
    .line 274
    .line 275
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 276
    .line 277
    return-object p0

    .line 278
    :pswitch_5
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 279
    .line 280
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p0, Ldj/f;

    .line 283
    .line 284
    iget-object p0, p0, Ldj/f;->a:Ldj/g;

    .line 285
    .line 286
    iget-object v0, p0, Ldj/g;->g:Lyy0/c2;

    .line 287
    .line 288
    :cond_9
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object p0

    .line 292
    move-object p1, p0

    .line 293
    check-cast p1, Ljava/lang/Number;

    .line 294
    .line 295
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 296
    .line 297
    .line 298
    move-result p1

    .line 299
    add-int/lit8 p1, p1, 0x1

    .line 300
    .line 301
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 306
    .line 307
    .line 308
    move-result p0

    .line 309
    if-eqz p0, :cond_9

    .line 310
    .line 311
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 312
    .line 313
    return-object p0

    .line 314
    :pswitch_6
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 315
    .line 316
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast p0, Lyw0/e;

    .line 319
    .line 320
    invoke-virtual {p0, p1}, Lyw0/e;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 325
    .line 326
    if-ne p0, p1, :cond_a

    .line 327
    .line 328
    goto :goto_9

    .line 329
    :cond_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 330
    .line 331
    :goto_9
    return-object p0

    .line 332
    :pswitch_7
    check-cast p1, Ljava/lang/Boolean;

    .line 333
    .line 334
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 335
    .line 336
    .line 337
    move-result p1

    .line 338
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast p0, Lc00/t;

    .line 341
    .line 342
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 343
    .line 344
    .line 345
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 346
    .line 347
    .line 348
    move-result-object v0

    .line 349
    new-instance v1, Lbp0/g;

    .line 350
    .line 351
    const/4 v2, 0x2

    .line 352
    const/4 v3, 0x0

    .line 353
    invoke-direct {v1, p0, p1, v3, v2}, Lbp0/g;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 354
    .line 355
    .line 356
    const/4 p0, 0x3

    .line 357
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 358
    .line 359
    .line 360
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 361
    .line 362
    return-object p0

    .line 363
    :pswitch_8
    check-cast p1, Ljava/lang/Boolean;

    .line 364
    .line 365
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 366
    .line 367
    .line 368
    move-result p1

    .line 369
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 370
    .line 371
    check-cast p0, Lc00/p;

    .line 372
    .line 373
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 374
    .line 375
    .line 376
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    new-instance v1, Lbp0/g;

    .line 381
    .line 382
    const/4 v2, 0x0

    .line 383
    invoke-direct {v1, p1, p0, v2}, Lbp0/g;-><init>(ZLc00/p;Lkotlin/coroutines/Continuation;)V

    .line 384
    .line 385
    .line 386
    const/4 p0, 0x3

    .line 387
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 388
    .line 389
    .line 390
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 391
    .line 392
    return-object p0

    .line 393
    :pswitch_9
    check-cast p1, Ljava/lang/Boolean;

    .line 394
    .line 395
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 396
    .line 397
    .line 398
    move-result p1

    .line 399
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 400
    .line 401
    check-cast p0, Lc00/h;

    .line 402
    .line 403
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 404
    .line 405
    .line 406
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    new-instance v1, Lac0/m;

    .line 411
    .line 412
    const/4 v2, 0x1

    .line 413
    const/4 v3, 0x0

    .line 414
    invoke-direct {v1, p0, p1, v3, v2}, Lac0/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 415
    .line 416
    .line 417
    const/4 p0, 0x3

    .line 418
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 419
    .line 420
    .line 421
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 422
    .line 423
    return-object p0

    .line 424
    :pswitch_a
    check-cast p1, Ljava/lang/Number;

    .line 425
    .line 426
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 427
    .line 428
    .line 429
    move-result-wide v2

    .line 430
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 431
    .line 432
    move-object v1, p0

    .line 433
    check-cast v1, Lbo0/k;

    .line 434
    .line 435
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 436
    .line 437
    .line 438
    invoke-static {v1}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 439
    .line 440
    .line 441
    move-result-object p0

    .line 442
    new-instance v0, Lb1/c1;

    .line 443
    .line 444
    const/4 v5, 0x1

    .line 445
    const/4 v4, 0x0

    .line 446
    invoke-direct/range {v0 .. v5}, Lb1/c1;-><init>(Ljava/lang/Object;JLkotlin/coroutines/Continuation;I)V

    .line 447
    .line 448
    .line 449
    const/4 p1, 0x3

    .line 450
    invoke-static {p0, v4, v4, v0, p1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 451
    .line 452
    .line 453
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object p0

    .line 456
    :pswitch_b
    check-cast p1, Lc4/j;

    .line 457
    .line 458
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 459
    .line 460
    check-cast p0, Ln2/b;

    .line 461
    .line 462
    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 463
    .line 464
    .line 465
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 466
    .line 467
    return-object p0

    .line 468
    nop

    .line 469
    :pswitch_data_0
    .packed-switch 0x0
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
