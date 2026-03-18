.class public final synthetic Lw00/h;
.super Lkotlin/jvm/internal/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Lw00/h;->d:I

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
.method public final invoke()Ljava/lang/Object;
    .locals 15

    .line 1
    iget v0, p0, Lw00/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw30/t;

    .line 9
    .line 10
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    move-object v1, v0

    .line 15
    check-cast v1, Lw30/s;

    .line 16
    .line 17
    const/4 v13, 0x0

    .line 18
    const/16 v14, 0xffe

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    const/4 v3, 0x0

    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    const/4 v6, 0x0

    .line 25
    const/4 v7, 0x0

    .line 26
    const/4 v8, 0x0

    .line 27
    const/4 v9, 0x0

    .line 28
    const/4 v10, 0x0

    .line 29
    const/4 v11, 0x0

    .line 30
    const/4 v12, 0x0

    .line 31
    invoke-static/range {v1 .. v14}, Lw30/s;->a(Lw30/s;Lql0/g;ZZZZZZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/s;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast p0, Lw30/t;

    .line 44
    .line 45
    iget-object p0, p0, Lw30/t;->s:Lu30/q;

    .line 46
    .line 47
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lw30/t;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    new-instance v1, Lw30/q;

    .line 65
    .line 66
    const/4 v2, 0x3

    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-direct {v1, p0, v3, v2}, Lw30/q;-><init>(Lw30/t;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    const/4 p0, 0x3

    .line 72
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 73
    .line 74
    .line 75
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object p0

    .line 78
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lw30/t;

    .line 81
    .line 82
    iget-object p0, p0, Lw30/t;->r:Lu30/a0;

    .line 83
    .line 84
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast p0, Lw30/t;

    .line 93
    .line 94
    iget-object p0, p0, Lw30/t;->n:Lu30/z;

    .line 95
    .line 96
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Lw30/t;

    .line 105
    .line 106
    iget-object p0, p0, Lw30/t;->h:Ltr0/b;

    .line 107
    .line 108
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0

    .line 114
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast p0, Lw30/n;

    .line 117
    .line 118
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    move-object v1, v0

    .line 123
    check-cast v1, Lw30/m;

    .line 124
    .line 125
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    check-cast v0, Lw30/m;

    .line 130
    .line 131
    iget-boolean v0, v0, Lw30/m;->a:Z

    .line 132
    .line 133
    xor-int/lit8 v2, v0, 0x1

    .line 134
    .line 135
    const/4 v5, 0x0

    .line 136
    const/16 v6, 0x1e

    .line 137
    .line 138
    const/4 v3, 0x0

    .line 139
    const/4 v4, 0x0

    .line 140
    invoke-static/range {v1 .. v6}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 145
    .line 146
    .line 147
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 148
    .line 149
    .line 150
    move-result-object v0

    .line 151
    new-instance v1, Lw30/l;

    .line 152
    .line 153
    const/4 v2, 0x1

    .line 154
    const/4 v3, 0x0

    .line 155
    invoke-direct {v1, p0, v3, v2}, Lw30/l;-><init>(Lw30/n;Lkotlin/coroutines/Continuation;I)V

    .line 156
    .line 157
    .line 158
    const/4 p0, 0x3

    .line 159
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 160
    .line 161
    .line 162
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    return-object p0

    .line 165
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast p0, Lw30/j;

    .line 168
    .line 169
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    check-cast v0, Lw30/i;

    .line 174
    .line 175
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 176
    .line 177
    .line 178
    move-result-object v1

    .line 179
    check-cast v1, Lw30/i;

    .line 180
    .line 181
    iget-boolean v1, v1, Lw30/i;->a:Z

    .line 182
    .line 183
    xor-int/lit8 v1, v1, 0x1

    .line 184
    .line 185
    iget-object v0, v0, Lw30/i;->b:Ljava/lang/String;

    .line 186
    .line 187
    const-string v2, "link"

    .line 188
    .line 189
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    new-instance v2, Lw30/i;

    .line 193
    .line 194
    invoke-direct {v2, v1, v0}, Lw30/i;-><init>(ZLjava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {p0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 198
    .line 199
    .line 200
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    new-instance v1, Lvo0/e;

    .line 205
    .line 206
    const/4 v2, 0x3

    .line 207
    const/4 v3, 0x0

    .line 208
    invoke-direct {v1, p0, v3, v2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 209
    .line 210
    .line 211
    const/4 p0, 0x3

    .line 212
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 213
    .line 214
    .line 215
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 216
    .line 217
    return-object p0

    .line 218
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast p0, Lw30/h;

    .line 221
    .line 222
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    check-cast v0, Lw30/g;

    .line 227
    .line 228
    const/4 v1, 0x7

    .line 229
    invoke-static {v0, v1}, Lw30/g;->a(Lw30/g;I)Lw30/g;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 234
    .line 235
    .line 236
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object p0

    .line 239
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast p0, Lw30/h;

    .line 242
    .line 243
    iget-object v0, p0, Lw30/h;->j:Lbd0/c;

    .line 244
    .line 245
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 246
    .line 247
    .line 248
    move-result-object p0

    .line 249
    check-cast p0, Lw30/g;

    .line 250
    .line 251
    iget-object p0, p0, Lw30/g;->b:Ljava/lang/String;

    .line 252
    .line 253
    const/16 v1, 0x1e

    .line 254
    .line 255
    and-int/lit8 v2, v1, 0x2

    .line 256
    .line 257
    const/4 v3, 0x0

    .line 258
    const/4 v4, 0x1

    .line 259
    if-eqz v2, :cond_0

    .line 260
    .line 261
    move v7, v4

    .line 262
    goto :goto_0

    .line 263
    :cond_0
    move v7, v3

    .line 264
    :goto_0
    and-int/lit8 v2, v1, 0x4

    .line 265
    .line 266
    if-eqz v2, :cond_1

    .line 267
    .line 268
    move v8, v4

    .line 269
    goto :goto_1

    .line 270
    :cond_1
    move v8, v3

    .line 271
    :goto_1
    and-int/lit8 v2, v1, 0x8

    .line 272
    .line 273
    if-eqz v2, :cond_2

    .line 274
    .line 275
    move v9, v3

    .line 276
    goto :goto_2

    .line 277
    :cond_2
    move v9, v4

    .line 278
    :goto_2
    and-int/lit8 v1, v1, 0x10

    .line 279
    .line 280
    if-eqz v1, :cond_3

    .line 281
    .line 282
    move v10, v3

    .line 283
    goto :goto_3

    .line 284
    :cond_3
    move v10, v4

    .line 285
    :goto_3
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 286
    .line 287
    new-instance v6, Ljava/net/URL;

    .line 288
    .line 289
    invoke-direct {v6, p0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    move-object v5, v0

    .line 293
    check-cast v5, Lzc0/b;

    .line 294
    .line 295
    invoke-virtual/range {v5 .. v10}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 296
    .line 297
    .line 298
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 299
    .line 300
    return-object p0

    .line 301
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast p0, Lw30/h;

    .line 304
    .line 305
    iget-object p0, p0, Lw30/h;->i:Ltr0/b;

    .line 306
    .line 307
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 311
    .line 312
    return-object p0

    .line 313
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast p0, Lw30/f;

    .line 316
    .line 317
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 318
    .line 319
    .line 320
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    new-instance v1, Lw30/c;

    .line 325
    .line 326
    const/4 v2, 0x2

    .line 327
    const/4 v3, 0x0

    .line 328
    invoke-direct {v1, p0, v3, v2}, Lw30/c;-><init>(Lw30/f;Lkotlin/coroutines/Continuation;I)V

    .line 329
    .line 330
    .line 331
    const/4 p0, 0x3

    .line 332
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 333
    .line 334
    .line 335
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 336
    .line 337
    return-object p0

    .line 338
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast p0, Lw30/f;

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
    new-instance v1, Lw30/c;

    .line 350
    .line 351
    const/4 v2, 0x3

    .line 352
    const/4 v3, 0x0

    .line 353
    invoke-direct {v1, p0, v3, v2}, Lw30/c;-><init>(Lw30/f;Lkotlin/coroutines/Continuation;I)V

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
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 364
    .line 365
    check-cast p0, Lw30/b;

    .line 366
    .line 367
    iget-object p0, p0, Lw30/b;->h:Ltr0/b;

    .line 368
    .line 369
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 373
    .line 374
    return-object p0

    .line 375
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 376
    .line 377
    check-cast p0, Lw30/b;

    .line 378
    .line 379
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    new-instance v1, Lvo0/e;

    .line 387
    .line 388
    const/4 v2, 0x1

    .line 389
    const/4 v3, 0x0

    .line 390
    invoke-direct {v1, p0, v3, v2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 391
    .line 392
    .line 393
    const/4 p0, 0x3

    .line 394
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 395
    .line 396
    .line 397
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 398
    .line 399
    return-object p0

    .line 400
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast p0, Lw30/b;

    .line 403
    .line 404
    iget-object p0, p0, Lw30/b;->h:Ltr0/b;

    .line 405
    .line 406
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 407
    .line 408
    .line 409
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 410
    .line 411
    return-object p0

    .line 412
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 413
    .line 414
    check-cast p0, Lvy/v;

    .line 415
    .line 416
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    new-instance v0, Lvy/i;

    .line 420
    .line 421
    const/4 v1, 0x0

    .line 422
    invoke-direct {v0, p0, v1}, Lvy/i;-><init>(Lvy/v;I)V

    .line 423
    .line 424
    .line 425
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 426
    .line 427
    .line 428
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 429
    .line 430
    .line 431
    move-result-object v0

    .line 432
    new-instance v1, Lvy/k;

    .line 433
    .line 434
    const/4 v2, 0x2

    .line 435
    const/4 v3, 0x0

    .line 436
    invoke-direct {v1, v2, v3, p0}, Lvy/k;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 437
    .line 438
    .line 439
    const/4 p0, 0x3

    .line 440
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 441
    .line 442
    .line 443
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 444
    .line 445
    return-object p0

    .line 446
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 447
    .line 448
    check-cast p0, Lvy/v;

    .line 449
    .line 450
    iget-object p0, p0, Lvy/v;->i:Ltr0/b;

    .line 451
    .line 452
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 453
    .line 454
    .line 455
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 456
    .line 457
    return-object p0

    .line 458
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 459
    .line 460
    check-cast p0, Lvy/h;

    .line 461
    .line 462
    invoke-virtual {p0}, Lvy/h;->h()V

    .line 463
    .line 464
    .line 465
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 466
    .line 467
    return-object p0

    .line 468
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 469
    .line 470
    check-cast p0, Lvy/h;

    .line 471
    .line 472
    invoke-virtual {p0}, Lvy/h;->h()V

    .line 473
    .line 474
    .line 475
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 476
    .line 477
    return-object p0

    .line 478
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 479
    .line 480
    check-cast p0, Lvy/h;

    .line 481
    .line 482
    invoke-virtual {p0}, Lvy/h;->h()V

    .line 483
    .line 484
    .line 485
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 486
    .line 487
    return-object p0

    .line 488
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 489
    .line 490
    check-cast p0, Lvy/h;

    .line 491
    .line 492
    invoke-virtual {p0}, Lvy/h;->h()V

    .line 493
    .line 494
    .line 495
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 496
    .line 497
    return-object p0

    .line 498
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 499
    .line 500
    check-cast p0, Lvl0/b;

    .line 501
    .line 502
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 503
    .line 504
    .line 505
    move-result-object v0

    .line 506
    check-cast v0, Lvl0/a;

    .line 507
    .line 508
    const/4 v1, 0x0

    .line 509
    const/4 v2, 0x2

    .line 510
    const/4 v3, 0x0

    .line 511
    invoke-static {v0, v3, v1, v2}, Lvl0/a;->a(Lvl0/a;Lul0/e;ZI)Lvl0/a;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 516
    .line 517
    .line 518
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 519
    .line 520
    return-object p0

    .line 521
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast p0, Lv90/b;

    .line 524
    .line 525
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 526
    .line 527
    .line 528
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 529
    .line 530
    .line 531
    move-result-object v0

    .line 532
    new-instance v1, Lci0/a;

    .line 533
    .line 534
    const/4 v2, 0x6

    .line 535
    const/4 v3, 0x0

    .line 536
    invoke-direct {v1, p0, v3, v2}, Lci0/a;-><init>(Landroidx/lifecycle/b1;Lkotlin/coroutines/Continuation;I)V

    .line 537
    .line 538
    .line 539
    const/4 p0, 0x3

    .line 540
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 541
    .line 542
    .line 543
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 544
    .line 545
    return-object p0

    .line 546
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 547
    .line 548
    check-cast p0, Lv90/b;

    .line 549
    .line 550
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 551
    .line 552
    .line 553
    move-result-object v0

    .line 554
    move-object v1, v0

    .line 555
    check-cast v1, Lv90/a;

    .line 556
    .line 557
    const/4 v6, 0x0

    .line 558
    const/16 v7, 0xf

    .line 559
    .line 560
    const/4 v2, 0x0

    .line 561
    const/4 v3, 0x0

    .line 562
    const/4 v4, 0x0

    .line 563
    const/4 v5, 0x0

    .line 564
    invoke-static/range {v1 .. v7}, Lv90/a;->a(Lv90/a;Ljava/lang/String;ZZZLql0/g;I)Lv90/a;

    .line 565
    .line 566
    .line 567
    move-result-object v0

    .line 568
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 569
    .line 570
    .line 571
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 572
    .line 573
    return-object p0

    .line 574
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 575
    .line 576
    check-cast p0, Lv90/b;

    .line 577
    .line 578
    iget-object p0, p0, Lv90/b;->h:Ltr0/b;

    .line 579
    .line 580
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 581
    .line 582
    .line 583
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 584
    .line 585
    return-object p0

    .line 586
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 587
    .line 588
    check-cast p0, Landroid/view/View;

    .line 589
    .line 590
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 591
    .line 592
    const/16 v1, 0x1e

    .line 593
    .line 594
    if-lt v0, v1, :cond_4

    .line 595
    .line 596
    invoke-static {p0}, Ld6/h;->h(Landroid/view/View;)V

    .line 597
    .line 598
    .line 599
    :cond_4
    invoke-virtual {p0}, Landroid/view/View;->getContentCaptureSession()Landroid/view/contentcapture/ContentCaptureSession;

    .line 600
    .line 601
    .line 602
    move-result-object v0

    .line 603
    if-nez v0, :cond_5

    .line 604
    .line 605
    const/4 p0, 0x0

    .line 606
    goto :goto_4

    .line 607
    :cond_5
    new-instance v1, Ly/a;

    .line 608
    .line 609
    invoke-direct {v1, v0, p0}, Ly/a;-><init>(Landroid/view/contentcapture/ContentCaptureSession;Landroid/view/View;)V

    .line 610
    .line 611
    .line 612
    move-object p0, v1

    .line 613
    :goto_4
    return-object p0

    .line 614
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 615
    .line 616
    check-cast p0, Lv00/i;

    .line 617
    .line 618
    iget-object p0, p0, Lv00/i;->k:Lz00/g;

    .line 619
    .line 620
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 621
    .line 622
    .line 623
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 624
    .line 625
    return-object p0

    .line 626
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 627
    .line 628
    check-cast p0, Lv00/i;

    .line 629
    .line 630
    iget-object p0, p0, Lv00/i;->i:Ltr0/b;

    .line 631
    .line 632
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 633
    .line 634
    .line 635
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 636
    .line 637
    return-object p0

    .line 638
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 639
    .line 640
    check-cast p0, Lv00/i;

    .line 641
    .line 642
    iget-object p0, p0, Lv00/i;->i:Ltr0/b;

    .line 643
    .line 644
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 645
    .line 646
    .line 647
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 648
    .line 649
    return-object p0

    .line 650
    nop

    .line 651
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
