.class public final synthetic Lr40/b;
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
    iput p7, p0, Lr40/b;->d:I

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
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lr40/b;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lr60/g;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    new-instance v2, Lr60/a;

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-direct {v2, v0, v4, v3}, Lr60/a;-><init>(Lr60/g;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x3

    .line 27
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 28
    .line 29
    .line 30
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    return-object v0

    .line 33
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lr60/g;

    .line 36
    .line 37
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    move-object v2, v1

    .line 42
    check-cast v2, Lr60/b;

    .line 43
    .line 44
    const/4 v12, 0x0

    .line 45
    const/16 v13, 0x3fd

    .line 46
    .line 47
    const/4 v3, 0x0

    .line 48
    const/4 v4, 0x1

    .line 49
    const/4 v5, 0x0

    .line 50
    const/4 v6, 0x0

    .line 51
    const/4 v7, 0x0

    .line 52
    const/4 v8, 0x0

    .line 53
    const/4 v9, 0x0

    .line 54
    const/4 v10, 0x0

    .line 55
    const/4 v11, 0x0

    .line 56
    invoke-static/range {v2 .. v13}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 61
    .line 62
    .line 63
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    return-object v0

    .line 66
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v0, Lr60/g;

    .line 69
    .line 70
    iget-object v0, v0, Lr60/g;->s:Lp60/u;

    .line 71
    .line 72
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    return-object v0

    .line 78
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Lr60/g;

    .line 81
    .line 82
    iget-object v0, v0, Lr60/g;->r:Lp60/o;

    .line 83
    .line 84
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Lr60/g;

    .line 93
    .line 94
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    move-object v2, v1

    .line 99
    check-cast v2, Lr60/b;

    .line 100
    .line 101
    const/4 v12, 0x0

    .line 102
    const/16 v13, 0x1ff

    .line 103
    .line 104
    const/4 v3, 0x0

    .line 105
    const/4 v4, 0x0

    .line 106
    const/4 v5, 0x0

    .line 107
    const/4 v6, 0x0

    .line 108
    const/4 v7, 0x0

    .line 109
    const/4 v8, 0x0

    .line 110
    const/4 v9, 0x0

    .line 111
    const/4 v10, 0x0

    .line 112
    const/4 v11, 0x0

    .line 113
    invoke-static/range {v2 .. v13}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 118
    .line 119
    .line 120
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object v0

    .line 123
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lr60/g;

    .line 126
    .line 127
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    move-object v2, v1

    .line 132
    check-cast v2, Lr60/b;

    .line 133
    .line 134
    const/4 v12, 0x0

    .line 135
    const/16 v13, 0x3fb

    .line 136
    .line 137
    const/4 v3, 0x0

    .line 138
    const/4 v4, 0x0

    .line 139
    const/4 v5, 0x0

    .line 140
    const/4 v6, 0x0

    .line 141
    const/4 v7, 0x0

    .line 142
    const/4 v8, 0x0

    .line 143
    const/4 v9, 0x0

    .line 144
    const/4 v10, 0x0

    .line 145
    const/4 v11, 0x0

    .line 146
    invoke-static/range {v2 .. v13}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 151
    .line 152
    .line 153
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    return-object v0

    .line 156
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v0, Lr60/g;

    .line 159
    .line 160
    iget-object v0, v0, Lr60/g;->p:Ltr0/b;

    .line 161
    .line 162
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    return-object v0

    .line 168
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Lr60/g;

    .line 171
    .line 172
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    move-object v2, v1

    .line 177
    check-cast v2, Lr60/b;

    .line 178
    .line 179
    const/4 v12, 0x0

    .line 180
    const/16 v13, 0x33f

    .line 181
    .line 182
    const/4 v3, 0x0

    .line 183
    const/4 v4, 0x0

    .line 184
    const/4 v5, 0x0

    .line 185
    const/4 v6, 0x0

    .line 186
    const/4 v7, 0x0

    .line 187
    const/4 v8, 0x0

    .line 188
    const/4 v9, 0x0

    .line 189
    const/4 v10, 0x0

    .line 190
    const/4 v11, 0x0

    .line 191
    invoke-static/range {v2 .. v13}, Lr60/b;->a(Lr60/b;Ljava/lang/String;ZLql0/g;ZLjava/lang/String;Ljava/util/List;Ljava/lang/String;ZLon0/a0;Ljava/lang/String;I)Lr60/b;

    .line 192
    .line 193
    .line 194
    move-result-object v1

    .line 195
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 196
    .line 197
    .line 198
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 199
    .line 200
    return-object v0

    .line 201
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v0, Lr60/g;

    .line 204
    .line 205
    iget-object v1, v0, Lr60/g;->o:Lnn0/g;

    .line 206
    .line 207
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Lon0/b;

    .line 212
    .line 213
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    if-eqz v1, :cond_1

    .line 218
    .line 219
    const/4 v2, 0x1

    .line 220
    if-ne v1, v2, :cond_0

    .line 221
    .line 222
    iget-object v0, v0, Lr60/g;->t:Lp60/a0;

    .line 223
    .line 224
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    goto :goto_0

    .line 228
    :cond_0
    new-instance v0, La8/r0;

    .line 229
    .line 230
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 231
    .line 232
    .line 233
    throw v0

    .line 234
    :cond_1
    iget-object v0, v0, Lr60/g;->q:Lp60/j;

    .line 235
    .line 236
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    return-object v0

    .line 242
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 243
    .line 244
    check-cast v0, Ls10/l;

    .line 245
    .line 246
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    check-cast v1, Ls10/j;

    .line 251
    .line 252
    const/4 v2, 0x1

    .line 253
    const/4 v3, 0x3

    .line 254
    const/4 v4, 0x0

    .line 255
    invoke-static {v1, v4, v4, v2, v3}, Ls10/j;->a(Ls10/j;Lql0/g;Ljava/util/ArrayList;ZI)Ls10/j;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 260
    .line 261
    .line 262
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 263
    .line 264
    return-object v0

    .line 265
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 266
    .line 267
    check-cast v0, Lql0/j;

    .line 268
    .line 269
    invoke-virtual {v0}, Lql0/j;->d()V

    .line 270
    .line 271
    .line 272
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 273
    .line 274
    return-object v0

    .line 275
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 276
    .line 277
    check-cast v0, Lql0/j;

    .line 278
    .line 279
    iget-object v0, v0, Lql0/j;->e:Lyy0/c2;

    .line 280
    .line 281
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 282
    .line 283
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 284
    .line 285
    .line 286
    const/4 v2, 0x0

    .line 287
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 288
    .line 289
    .line 290
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 291
    .line 292
    return-object v0

    .line 293
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast v0, Lqk0/c;

    .line 296
    .line 297
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    check-cast v1, Lqk0/a;

    .line 302
    .line 303
    const/4 v2, 0x0

    .line 304
    const/4 v3, 0x1

    .line 305
    const/4 v4, 0x0

    .line 306
    invoke-static {v1, v4, v2, v3}, Lqk0/a;->a(Lqk0/a;Ljava/util/List;ZI)Lqk0/a;

    .line 307
    .line 308
    .line 309
    move-result-object v1

    .line 310
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 311
    .line 312
    .line 313
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 314
    .line 315
    return-object v0

    .line 316
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v0, Lqk0/c;

    .line 319
    .line 320
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 321
    .line 322
    .line 323
    move-result-object v1

    .line 324
    check-cast v1, Lqk0/a;

    .line 325
    .line 326
    const/4 v2, 0x0

    .line 327
    const/4 v3, 0x1

    .line 328
    const/4 v4, 0x0

    .line 329
    invoke-static {v1, v4, v2, v3}, Lqk0/a;->a(Lqk0/a;Ljava/util/List;ZI)Lqk0/a;

    .line 330
    .line 331
    .line 332
    move-result-object v1

    .line 333
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 334
    .line 335
    .line 336
    iget-object v0, v0, Lqk0/c;->i:Ltn0/e;

    .line 337
    .line 338
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 339
    .line 340
    .line 341
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 342
    .line 343
    return-object v0

    .line 344
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v0, Lqi0/d;

    .line 347
    .line 348
    invoke-virtual {v0}, Lqi0/d;->h()V

    .line 349
    .line 350
    .line 351
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 352
    .line 353
    return-object v0

    .line 354
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 355
    .line 356
    check-cast v0, Lqi0/d;

    .line 357
    .line 358
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 359
    .line 360
    .line 361
    move-result-object v1

    .line 362
    check-cast v1, Lqi0/a;

    .line 363
    .line 364
    iget-object v1, v1, Lqi0/a;->b:Ljava/util/List;

    .line 365
    .line 366
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 367
    .line 368
    .line 369
    move-result-object v2

    .line 370
    check-cast v2, Lqi0/a;

    .line 371
    .line 372
    iget v2, v2, Lqi0/a;->a:I

    .line 373
    .line 374
    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    check-cast v1, Ljava/net/URL;

    .line 379
    .line 380
    new-instance v2, Llg0/c;

    .line 381
    .line 382
    sget-object v3, Llg0/b;->f:Llg0/b;

    .line 383
    .line 384
    invoke-static {v1}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 385
    .line 386
    .line 387
    move-result-object v4

    .line 388
    invoke-virtual {v4}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 389
    .line 390
    .line 391
    move-result-object v4

    .line 392
    const-string v5, "toString(...)"

    .line 393
    .line 394
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    invoke-virtual {v1}, Ljava/net/URL;->getPath()Ljava/lang/String;

    .line 398
    .line 399
    .line 400
    move-result-object v5

    .line 401
    const-string v1, "getPath(...)"

    .line 402
    .line 403
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 404
    .line 405
    .line 406
    iget-object v1, v0, Lqi0/d;->k:Lij0/a;

    .line 407
    .line 408
    const/4 v6, 0x0

    .line 409
    new-array v7, v6, [Ljava/lang/Object;

    .line 410
    .line 411
    check-cast v1, Ljj0/f;

    .line 412
    .line 413
    const v8, 0x7f1214a8

    .line 414
    .line 415
    .line 416
    invoke-virtual {v1, v8, v7}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 417
    .line 418
    .line 419
    move-result-object v7

    .line 420
    const v8, 0x7f1214a7

    .line 421
    .line 422
    .line 423
    new-array v6, v6, [Ljava/lang/Object;

    .line 424
    .line 425
    invoke-virtual {v1, v8, v6}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 426
    .line 427
    .line 428
    move-result-object v1

    .line 429
    const/4 v8, 0x0

    .line 430
    move-object v6, v7

    .line 431
    move-object v7, v1

    .line 432
    invoke-direct/range {v2 .. v8}, Llg0/c;-><init>(Llg0/b;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/HashMap;)V

    .line 433
    .line 434
    .line 435
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 436
    .line 437
    .line 438
    move-result-object v1

    .line 439
    new-instance v3, Lna/e;

    .line 440
    .line 441
    const/16 v4, 0x19

    .line 442
    .line 443
    const/4 v5, 0x0

    .line 444
    invoke-direct {v3, v4, v0, v2, v5}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 445
    .line 446
    .line 447
    const/4 v0, 0x3

    .line 448
    invoke-static {v1, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 449
    .line 450
    .line 451
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 452
    .line 453
    return-object v0

    .line 454
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 455
    .line 456
    check-cast v0, Lqi0/d;

    .line 457
    .line 458
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 459
    .line 460
    .line 461
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 462
    .line 463
    .line 464
    move-result-object v1

    .line 465
    new-instance v2, Lqi0/c;

    .line 466
    .line 467
    const/4 v3, 0x1

    .line 468
    const/4 v4, 0x0

    .line 469
    invoke-direct {v2, v0, v4, v3}, Lqi0/c;-><init>(Lqi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 470
    .line 471
    .line 472
    const/4 v0, 0x3

    .line 473
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 474
    .line 475
    .line 476
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 477
    .line 478
    return-object v0

    .line 479
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 480
    .line 481
    check-cast v0, Lqi0/d;

    .line 482
    .line 483
    iget-object v0, v0, Lqi0/d;->h:Ltr0/b;

    .line 484
    .line 485
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 489
    .line 490
    return-object v0

    .line 491
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 492
    .line 493
    check-cast v0, Lwg/b;

    .line 494
    .line 495
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 496
    .line 497
    .line 498
    :try_start_0
    iget-object v0, v0, Lwg/b;->b:Lbh/c;

    .line 499
    .line 500
    if-eqz v0, :cond_2

    .line 501
    .line 502
    goto :goto_1

    .line 503
    :cond_2
    const-string v0, "cacheWallbox"

    .line 504
    .line 505
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 506
    .line 507
    .line 508
    const/4 v0, 0x0

    .line 509
    throw v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 510
    :catchall_0
    move-exception v0

    .line 511
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 512
    .line 513
    .line 514
    move-result-object v0

    .line 515
    :goto_1
    new-instance v1, Llx0/o;

    .line 516
    .line 517
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 518
    .line 519
    .line 520
    return-object v1

    .line 521
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v0, Lqg0/b;

    .line 524
    .line 525
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 526
    .line 527
    .line 528
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 529
    .line 530
    .line 531
    move-result-object v1

    .line 532
    new-instance v2, Ln00/f;

    .line 533
    .line 534
    const/16 v3, 0x14

    .line 535
    .line 536
    const/4 v4, 0x0

    .line 537
    invoke-direct {v2, v0, v4, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 538
    .line 539
    .line 540
    const/4 v0, 0x3

    .line 541
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 542
    .line 543
    .line 544
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 545
    .line 546
    return-object v0

    .line 547
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 548
    .line 549
    check-cast v0, Lcz/skodaauto/myskoda/feature/mapfueling/system/StartSessionPollingService;

    .line 550
    .line 551
    invoke-virtual {v0}, Landroid/app/Service;->stopSelf()V

    .line 552
    .line 553
    .line 554
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 555
    .line 556
    return-object v0

    .line 557
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 558
    .line 559
    check-cast v0, Lq40/t;

    .line 560
    .line 561
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 562
    .line 563
    .line 564
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 565
    .line 566
    .line 567
    move-result-object v1

    .line 568
    new-instance v2, Ln00/f;

    .line 569
    .line 570
    const/16 v3, 0xf

    .line 571
    .line 572
    const/4 v4, 0x0

    .line 573
    invoke-direct {v2, v0, v4, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 574
    .line 575
    .line 576
    const/4 v0, 0x3

    .line 577
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 578
    .line 579
    .line 580
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 581
    .line 582
    return-object v0

    .line 583
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 584
    .line 585
    check-cast v0, Lq40/t;

    .line 586
    .line 587
    iget-object v0, v0, Lq40/t;->m:Ltr0/b;

    .line 588
    .line 589
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 593
    .line 594
    return-object v0

    .line 595
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 596
    .line 597
    check-cast v0, Lq40/t;

    .line 598
    .line 599
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 600
    .line 601
    .line 602
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 603
    .line 604
    .line 605
    move-result-object v1

    .line 606
    new-instance v2, Ln00/f;

    .line 607
    .line 608
    const/16 v3, 0xf

    .line 609
    .line 610
    const/4 v4, 0x0

    .line 611
    invoke-direct {v2, v0, v4, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 612
    .line 613
    .line 614
    const/4 v0, 0x3

    .line 615
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 616
    .line 617
    .line 618
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 619
    .line 620
    return-object v0

    .line 621
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 622
    .line 623
    check-cast v0, Lq40/o;

    .line 624
    .line 625
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 626
    .line 627
    .line 628
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 629
    .line 630
    .line 631
    move-result-object v1

    .line 632
    new-instance v2, Lq40/k;

    .line 633
    .line 634
    const/4 v3, 0x1

    .line 635
    const/4 v4, 0x0

    .line 636
    invoke-direct {v2, v0, v4, v3}, Lq40/k;-><init>(Lq40/o;Lkotlin/coroutines/Continuation;I)V

    .line 637
    .line 638
    .line 639
    const/4 v0, 0x3

    .line 640
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 641
    .line 642
    .line 643
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 644
    .line 645
    return-object v0

    .line 646
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 647
    .line 648
    check-cast v0, Lq40/o;

    .line 649
    .line 650
    iget-object v0, v0, Lq40/o;->p:Lo40/m;

    .line 651
    .line 652
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 656
    .line 657
    return-object v0

    .line 658
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 659
    .line 660
    check-cast v0, Lq40/j;

    .line 661
    .line 662
    iget-object v0, v0, Lq40/j;->h:Lo40/l;

    .line 663
    .line 664
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 665
    .line 666
    .line 667
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 668
    .line 669
    return-object v0

    .line 670
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 671
    .line 672
    check-cast v0, Lq40/h;

    .line 673
    .line 674
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 675
    .line 676
    .line 677
    move-result-object v1

    .line 678
    move-object v2, v1

    .line 679
    check-cast v2, Lq40/d;

    .line 680
    .line 681
    const/16 v16, 0x0

    .line 682
    .line 683
    const/16 v17, 0x3cff

    .line 684
    .line 685
    const/4 v3, 0x0

    .line 686
    const/4 v4, 0x0

    .line 687
    const/4 v5, 0x0

    .line 688
    const/4 v6, 0x0

    .line 689
    const/4 v7, 0x0

    .line 690
    const/4 v8, 0x0

    .line 691
    const/4 v9, 0x0

    .line 692
    const/4 v10, 0x0

    .line 693
    const/4 v11, 0x0

    .line 694
    const/4 v12, 0x0

    .line 695
    const/4 v13, 0x0

    .line 696
    const/4 v14, 0x0

    .line 697
    const/4 v15, 0x0

    .line 698
    invoke-static/range {v2 .. v17}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 699
    .line 700
    .line 701
    move-result-object v1

    .line 702
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 703
    .line 704
    .line 705
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 706
    .line 707
    return-object v0

    .line 708
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 709
    .line 710
    check-cast v0, Lq40/h;

    .line 711
    .line 712
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 713
    .line 714
    .line 715
    move-result-object v1

    .line 716
    move-object v2, v1

    .line 717
    check-cast v2, Lq40/d;

    .line 718
    .line 719
    const/16 v16, 0x0

    .line 720
    .line 721
    const/16 v17, 0x3dff

    .line 722
    .line 723
    const/4 v3, 0x0

    .line 724
    const/4 v4, 0x0

    .line 725
    const/4 v5, 0x0

    .line 726
    const/4 v6, 0x0

    .line 727
    const/4 v7, 0x0

    .line 728
    const/4 v8, 0x0

    .line 729
    const/4 v9, 0x0

    .line 730
    const/4 v10, 0x0

    .line 731
    const/4 v11, 0x0

    .line 732
    const/4 v12, 0x1

    .line 733
    const/4 v13, 0x0

    .line 734
    const/4 v14, 0x0

    .line 735
    const/4 v15, 0x0

    .line 736
    invoke-static/range {v2 .. v17}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 737
    .line 738
    .line 739
    move-result-object v1

    .line 740
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 741
    .line 742
    .line 743
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 744
    .line 745
    return-object v0

    .line 746
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 747
    .line 748
    check-cast v0, Lq40/h;

    .line 749
    .line 750
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 751
    .line 752
    .line 753
    move-result-object v1

    .line 754
    move-object v2, v1

    .line 755
    check-cast v2, Lq40/d;

    .line 756
    .line 757
    const/16 v16, 0x0

    .line 758
    .line 759
    const/16 v17, 0x3eff

    .line 760
    .line 761
    const/4 v3, 0x0

    .line 762
    const/4 v4, 0x0

    .line 763
    const/4 v5, 0x0

    .line 764
    const/4 v6, 0x0

    .line 765
    const/4 v7, 0x0

    .line 766
    const/4 v8, 0x0

    .line 767
    const/4 v9, 0x0

    .line 768
    const/4 v10, 0x0

    .line 769
    const/4 v11, 0x1

    .line 770
    const/4 v12, 0x0

    .line 771
    const/4 v13, 0x0

    .line 772
    const/4 v14, 0x0

    .line 773
    const/4 v15, 0x0

    .line 774
    invoke-static/range {v2 .. v17}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 775
    .line 776
    .line 777
    move-result-object v1

    .line 778
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 779
    .line 780
    .line 781
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 782
    .line 783
    return-object v0

    .line 784
    nop

    .line 785
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
