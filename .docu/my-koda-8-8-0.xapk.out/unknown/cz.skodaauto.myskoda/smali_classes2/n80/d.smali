.class public final synthetic Ln80/d;
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
    iput p7, p0, Ln80/d;->d:I

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
    .locals 9

    .line 1
    iget v0, p0, Ln80/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ln00/c;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    new-instance v0, Lmz0/b;

    .line 14
    .line 15
    const/4 v1, 0x4

    .line 16
    invoke-direct {v0, v1}, Lmz0/b;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    new-instance v1, Ln00/a;

    .line 27
    .line 28
    const/4 v2, 0x2

    .line 29
    const/4 v3, 0x0

    .line 30
    invoke-direct {v1, p0, v3, v2}, Ln00/a;-><init>(Ln00/c;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast p0, Ln00/c;

    .line 43
    .line 44
    iget-object p0, p0, Ln00/c;->j:Ll00/k;

    .line 45
    .line 46
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p0, Lmy/t;

    .line 55
    .line 56
    invoke-virtual {p0}, Lmy/t;->j()V

    .line 57
    .line 58
    .line 59
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 60
    .line 61
    return-object p0

    .line 62
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p0, Lmy/t;

    .line 65
    .line 66
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    sget-object v0, Lsq0/d;->e:Lsq0/d;

    .line 70
    .line 71
    invoke-virtual {p0, v0}, Lmy/t;->k(Lsq0/d;)V

    .line 72
    .line 73
    .line 74
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 75
    .line 76
    return-object p0

    .line 77
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast p0, Lmy/t;

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    sget-object v0, Lsq0/d;->d:Lsq0/d;

    .line 85
    .line 86
    invoke-virtual {p0, v0}, Lmy/t;->k(Lsq0/d;)V

    .line 87
    .line 88
    .line 89
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 90
    .line 91
    return-object p0

    .line 92
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast p0, Lns/c;

    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-virtual {p0}, Landroid/os/Looper;->isCurrentThread()Z

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    xor-int/lit8 p0, p0, 0x1

    .line 108
    .line 109
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0

    .line 114
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 115
    .line 116
    check-cast p0, Lns/c;

    .line 117
    .line 118
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 119
    .line 120
    .line 121
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-virtual {p0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    const-string v0, "<get-threadName>(...)"

    .line 130
    .line 131
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    const-string v0, "Firebase Blocking Thread #"

    .line 135
    .line 136
    const/4 v1, 0x0

    .line 137
    invoke-static {p0, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    return-object p0

    .line 146
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 147
    .line 148
    check-cast p0, Lns/c;

    .line 149
    .line 150
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 151
    .line 152
    .line 153
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-virtual {p0}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    const-string v0, "<get-threadName>(...)"

    .line 162
    .line 163
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    const-string v0, "Firebase Background Thread #"

    .line 167
    .line 168
    const/4 v1, 0x0

    .line 169
    invoke-static {p0, v0, v1}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 170
    .line 171
    .line 172
    move-result p0

    .line 173
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    return-object p0

    .line 178
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast p0, Lmf0/b;

    .line 181
    .line 182
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    move-object v1, v0

    .line 187
    check-cast v1, Lmf0/a;

    .line 188
    .line 189
    const/4 v6, 0x0

    .line 190
    const/16 v7, 0x1d

    .line 191
    .line 192
    const/4 v2, 0x0

    .line 193
    const/4 v3, 0x0

    .line 194
    const/4 v4, 0x0

    .line 195
    const/4 v5, 0x0

    .line 196
    invoke-static/range {v1 .. v7}, Lmf0/a;->a(Lmf0/a;Llf0/i;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lmf0/a;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 201
    .line 202
    .line 203
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast p0, Lmf0/b;

    .line 209
    .line 210
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    move-object v1, v0

    .line 215
    check-cast v1, Lmf0/a;

    .line 216
    .line 217
    const/4 v6, 0x0

    .line 218
    const/16 v7, 0x1d

    .line 219
    .line 220
    const/4 v2, 0x0

    .line 221
    const/4 v3, 0x1

    .line 222
    const/4 v4, 0x0

    .line 223
    const/4 v5, 0x0

    .line 224
    invoke-static/range {v1 .. v7}, Lmf0/a;->a(Lmf0/a;Llf0/i;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lmf0/a;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 229
    .line 230
    .line 231
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 232
    .line 233
    return-object p0

    .line 234
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 235
    .line 236
    check-cast p0, Lmd0/b;

    .line 237
    .line 238
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 239
    .line 240
    .line 241
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 242
    .line 243
    .line 244
    move-result-object v0

    .line 245
    new-instance v1, Lk20/a;

    .line 246
    .line 247
    const/16 v2, 0x18

    .line 248
    .line 249
    const/4 v3, 0x0

    .line 250
    invoke-direct {v1, p0, v3, v2}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 251
    .line 252
    .line 253
    const/4 p0, 0x3

    .line 254
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 255
    .line 256
    .line 257
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 258
    .line 259
    return-object p0

    .line 260
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast p0, Lmd0/b;

    .line 263
    .line 264
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    check-cast v0, Lmd0/a;

    .line 269
    .line 270
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 271
    .line 272
    .line 273
    new-instance v0, Lmd0/a;

    .line 274
    .line 275
    const/4 v1, 0x0

    .line 276
    invoke-direct {v0, v1}, Lmd0/a;-><init>(Z)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 280
    .line 281
    .line 282
    iget-object p0, p0, Lmd0/b;->j:Ltr0/b;

    .line 283
    .line 284
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    return-object p0

    .line 290
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast p0, Lmd0/b;

    .line 293
    .line 294
    iget-object p0, p0, Lmd0/b;->i:Ltn0/e;

    .line 295
    .line 296
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 297
    .line 298
    .line 299
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 300
    .line 301
    return-object p0

    .line 302
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 303
    .line 304
    check-cast p0, Lmc0/f;

    .line 305
    .line 306
    iget-object p0, p0, Lmc0/f;->i:Lkc0/a0;

    .line 307
    .line 308
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 312
    .line 313
    return-object p0

    .line 314
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast p0, Lmc0/d;

    .line 317
    .line 318
    invoke-virtual {p0}, Lmc0/d;->j()V

    .line 319
    .line 320
    .line 321
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 322
    .line 323
    return-object p0

    .line 324
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 325
    .line 326
    check-cast p0, Lmc0/d;

    .line 327
    .line 328
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 329
    .line 330
    .line 331
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 332
    .line 333
    .line 334
    move-result-object v0

    .line 335
    new-instance v1, Lm70/i0;

    .line 336
    .line 337
    const/16 v2, 0x8

    .line 338
    .line 339
    const/4 v3, 0x0

    .line 340
    invoke-direct {v1, p0, v3, v2}, Lm70/i0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 341
    .line 342
    .line 343
    const/4 p0, 0x3

    .line 344
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 345
    .line 346
    .line 347
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 348
    .line 349
    return-object p0

    .line 350
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 351
    .line 352
    check-cast p0, Lmc0/d;

    .line 353
    .line 354
    invoke-virtual {p0}, Lmc0/d;->j()V

    .line 355
    .line 356
    .line 357
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 358
    .line 359
    return-object p0

    .line 360
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast p0, Lma0/g;

    .line 363
    .line 364
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 365
    .line 366
    .line 367
    move-result-object v0

    .line 368
    move-object v1, v0

    .line 369
    check-cast v1, Lma0/f;

    .line 370
    .line 371
    const/4 v7, 0x0

    .line 372
    const/16 v8, 0x3e

    .line 373
    .line 374
    const/4 v2, 0x0

    .line 375
    const/4 v3, 0x0

    .line 376
    const/4 v4, 0x0

    .line 377
    const/4 v5, 0x0

    .line 378
    const/4 v6, 0x0

    .line 379
    invoke-static/range {v1 .. v8}, Lma0/f;->a(Lma0/f;Lql0/g;ZZZLjava/util/ArrayList;Ljava/util/List;I)Lma0/f;

    .line 380
    .line 381
    .line 382
    move-result-object v0

    .line 383
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 384
    .line 385
    .line 386
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 387
    .line 388
    return-object p0

    .line 389
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast p0, Lma0/g;

    .line 392
    .line 393
    iget-object v0, p0, Lma0/g;->i:Lgn0/f;

    .line 394
    .line 395
    invoke-static {v0}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 396
    .line 397
    .line 398
    move-result-object v0

    .line 399
    new-instance v1, Lma0/d;

    .line 400
    .line 401
    const/4 v2, 0x1

    .line 402
    const/4 v3, 0x0

    .line 403
    invoke-direct {v1, v3, p0, v2}, Lma0/d;-><init>(Lkotlin/coroutines/Continuation;Lma0/g;I)V

    .line 404
    .line 405
    .line 406
    invoke-static {v0, v1}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 407
    .line 408
    .line 409
    move-result-object v0

    .line 410
    new-instance v1, Lm70/f1;

    .line 411
    .line 412
    invoke-direct {v1, p0, v3, v2}, Lm70/f1;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 413
    .line 414
    .line 415
    new-instance v2, Lne0/n;

    .line 416
    .line 417
    invoke-direct {v2, v1, v0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 418
    .line 419
    .line 420
    invoke-static {v2}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 421
    .line 422
    .line 423
    move-result-object v0

    .line 424
    new-instance v1, Lbv0/d;

    .line 425
    .line 426
    const/16 v2, 0xa

    .line 427
    .line 428
    invoke-direct {v1, p0, v3, v2}, Lbv0/d;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 429
    .line 430
    .line 431
    new-instance v2, Lyy0/x;

    .line 432
    .line 433
    invoke-direct {v2, v0, v1}, Lyy0/x;-><init>(Lyy0/i;Lay0/o;)V

    .line 434
    .line 435
    .line 436
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 437
    .line 438
    .line 439
    move-result-object p0

    .line 440
    invoke-static {v2, p0}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 441
    .line 442
    .line 443
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 444
    .line 445
    return-object p0

    .line 446
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 447
    .line 448
    check-cast p0, Lma0/g;

    .line 449
    .line 450
    iget-object p0, p0, Lma0/g;->h:Ltr0/b;

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
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 459
    .line 460
    check-cast p0, Lma0/b;

    .line 461
    .line 462
    iget-object p0, p0, Lma0/b;->h:Lka0/d;

    .line 463
    .line 464
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 468
    .line 469
    return-object p0

    .line 470
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 471
    .line 472
    check-cast p0, Lm80/o;

    .line 473
    .line 474
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 475
    .line 476
    .line 477
    move-result-object v0

    .line 478
    check-cast v0, Lm80/n;

    .line 479
    .line 480
    iget-object v0, v0, Lm80/n;->a:Ljava/lang/String;

    .line 481
    .line 482
    if-eqz v0, :cond_0

    .line 483
    .line 484
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 485
    .line 486
    .line 487
    move-result-object v1

    .line 488
    new-instance v2, Llb0/q0;

    .line 489
    .line 490
    const/16 v3, 0xf

    .line 491
    .line 492
    const/4 v4, 0x0

    .line 493
    invoke-direct {v2, v3, p0, v0, v4}, Llb0/q0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 494
    .line 495
    .line 496
    const/4 p0, 0x3

    .line 497
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 498
    .line 499
    .line 500
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 501
    .line 502
    return-object p0

    .line 503
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 504
    .line 505
    check-cast p0, Lm80/o;

    .line 506
    .line 507
    iget-object p0, p0, Lm80/o;->h:Ltr0/b;

    .line 508
    .line 509
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 510
    .line 511
    .line 512
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 513
    .line 514
    return-object p0

    .line 515
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 516
    .line 517
    check-cast p0, Lm80/m;

    .line 518
    .line 519
    iget-object p0, p0, Lm80/m;->h:Lq80/i;

    .line 520
    .line 521
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 525
    .line 526
    return-object p0

    .line 527
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 528
    .line 529
    check-cast p0, Lm80/k;

    .line 530
    .line 531
    iget-object p0, p0, Lm80/k;->h:Lk80/d;

    .line 532
    .line 533
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 534
    .line 535
    .line 536
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 537
    .line 538
    return-object p0

    .line 539
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 540
    .line 541
    check-cast p0, Lm80/h;

    .line 542
    .line 543
    iget-object p0, p0, Lm80/h;->j:Ltr0/b;

    .line 544
    .line 545
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 549
    .line 550
    return-object p0

    .line 551
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 552
    .line 553
    check-cast p0, Lm80/h;

    .line 554
    .line 555
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 556
    .line 557
    .line 558
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 559
    .line 560
    .line 561
    move-result-object v0

    .line 562
    new-instance v1, Lm80/f;

    .line 563
    .line 564
    const/4 v2, 0x1

    .line 565
    const/4 v3, 0x0

    .line 566
    invoke-direct {v1, p0, v3, v2}, Lm80/f;-><init>(Lm80/h;Lkotlin/coroutines/Continuation;I)V

    .line 567
    .line 568
    .line 569
    const/4 p0, 0x3

    .line 570
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 571
    .line 572
    .line 573
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 574
    .line 575
    return-object p0

    .line 576
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 577
    .line 578
    check-cast p0, Lm80/h;

    .line 579
    .line 580
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 581
    .line 582
    .line 583
    move-result-object v0

    .line 584
    move-object v1, v0

    .line 585
    check-cast v1, Lm80/g;

    .line 586
    .line 587
    const/4 v5, 0x0

    .line 588
    const/16 v6, 0xd

    .line 589
    .line 590
    const/4 v2, 0x0

    .line 591
    const/4 v3, 0x0

    .line 592
    const/4 v4, 0x0

    .line 593
    invoke-static/range {v1 .. v6}, Lm80/g;->a(Lm80/g;ZZLer0/g;Lql0/g;I)Lm80/g;

    .line 594
    .line 595
    .line 596
    move-result-object v0

    .line 597
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 598
    .line 599
    .line 600
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 601
    .line 602
    return-object p0

    .line 603
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 604
    .line 605
    check-cast p0, Lm80/h;

    .line 606
    .line 607
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 608
    .line 609
    .line 610
    move-result-object v0

    .line 611
    move-object v1, v0

    .line 612
    check-cast v1, Lm80/g;

    .line 613
    .line 614
    const/4 v5, 0x0

    .line 615
    const/16 v6, 0xd

    .line 616
    .line 617
    const/4 v2, 0x0

    .line 618
    const/4 v3, 0x1

    .line 619
    const/4 v4, 0x0

    .line 620
    invoke-static/range {v1 .. v6}, Lm80/g;->a(Lm80/g;ZZLer0/g;Lql0/g;I)Lm80/g;

    .line 621
    .line 622
    .line 623
    move-result-object v0

    .line 624
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 625
    .line 626
    .line 627
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 628
    .line 629
    return-object p0

    .line 630
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 631
    .line 632
    check-cast p0, Lm80/e;

    .line 633
    .line 634
    iget-object p0, p0, Lm80/e;->l:Ltr0/b;

    .line 635
    .line 636
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 637
    .line 638
    .line 639
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 640
    .line 641
    return-object p0

    .line 642
    nop

    .line 643
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
