.class public final synthetic Li40/t2;
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
    iput p7, p0, Li40/t2;->d:I

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
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Li40/t2;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lh50/o;

    .line 11
    .line 12
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    move-object v2, v1

    .line 17
    check-cast v2, Lh50/k;

    .line 18
    .line 19
    const/4 v6, 0x0

    .line 20
    const/4 v7, 0x7

    .line 21
    const/4 v3, 0x0

    .line 22
    const/4 v4, 0x0

    .line 23
    const/4 v5, 0x0

    .line 24
    invoke-static/range {v2 .. v7}, Lh50/k;->a(Lh50/k;Ljava/lang/String;Lh50/j;ZZI)Lh50/k;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 29
    .line 30
    .line 31
    iget-object v0, v0, Lh50/o;->h:Ltr0/b;

    .line 32
    .line 33
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lh50/o;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 44
    .line 45
    .line 46
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    new-instance v2, Lh50/m;

    .line 51
    .line 52
    const/4 v3, 0x0

    .line 53
    invoke-direct {v2, v0, v3}, Lh50/m;-><init>(Lh50/o;Lkotlin/coroutines/Continuation;)V

    .line 54
    .line 55
    .line 56
    const/4 v0, 0x3

    .line 57
    invoke-static {v1, v3, v3, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 58
    .line 59
    .line 60
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    return-object v0

    .line 63
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast v0, Lh50/h;

    .line 66
    .line 67
    iget-object v1, v0, Lh50/h;->p:Lvy0/x1;

    .line 68
    .line 69
    const/4 v2, 0x0

    .line 70
    if-eqz v1, :cond_0

    .line 71
    .line 72
    invoke-virtual {v1, v2}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 73
    .line 74
    .line 75
    :cond_0
    iput-object v2, v0, Lh50/h;->p:Lvy0/x1;

    .line 76
    .line 77
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    move-object v2, v1

    .line 82
    check-cast v2, Lh50/e;

    .line 83
    .line 84
    const/4 v6, 0x0

    .line 85
    const/16 v7, 0xe

    .line 86
    .line 87
    const/4 v3, 0x0

    .line 88
    const/4 v4, 0x0

    .line 89
    const/4 v5, 0x0

    .line 90
    invoke-static/range {v2 .. v7}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 95
    .line 96
    .line 97
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object v0

    .line 100
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Lh50/h;

    .line 103
    .line 104
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 105
    .line 106
    .line 107
    move-result-object v1

    .line 108
    move-object v2, v1

    .line 109
    check-cast v2, Lh50/e;

    .line 110
    .line 111
    const/4 v6, 0x0

    .line 112
    const/16 v7, 0xd

    .line 113
    .line 114
    const/4 v3, 0x0

    .line 115
    const/4 v4, 0x1

    .line 116
    const/4 v5, 0x0

    .line 117
    invoke-static/range {v2 .. v7}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 122
    .line 123
    .line 124
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object v0

    .line 127
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v0, Lh50/h;

    .line 130
    .line 131
    iget-object v1, v0, Lh50/h;->i:Lpp0/c1;

    .line 132
    .line 133
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v2

    .line 137
    check-cast v2, Lh50/e;

    .line 138
    .line 139
    iget-object v2, v2, Lh50/e;->c:Ljava/lang/String;

    .line 140
    .line 141
    iget-object v1, v1, Lpp0/c1;->a:Lpp0/c0;

    .line 142
    .line 143
    check-cast v1, Lnp0/b;

    .line 144
    .line 145
    iput-object v2, v1, Lnp0/b;->o:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v0, v0, Lh50/h;->o:Ltr0/b;

    .line 148
    .line 149
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 153
    .line 154
    return-object v0

    .line 155
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v0, Lh50/h;

    .line 158
    .line 159
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    check-cast v1, Lh50/e;

    .line 164
    .line 165
    iget-object v1, v1, Lh50/e;->c:Ljava/lang/String;

    .line 166
    .line 167
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-eqz v1, :cond_1

    .line 172
    .line 173
    goto :goto_0

    .line 174
    :cond_1
    iget-object v1, v0, Lh50/h;->i:Lpp0/c1;

    .line 175
    .line 176
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    check-cast v2, Lh50/e;

    .line 181
    .line 182
    iget-object v2, v2, Lh50/e;->c:Ljava/lang/String;

    .line 183
    .line 184
    iget-object v1, v1, Lpp0/c1;->a:Lpp0/c0;

    .line 185
    .line 186
    check-cast v1, Lnp0/b;

    .line 187
    .line 188
    iput-object v2, v1, Lnp0/b;->o:Ljava/lang/String;

    .line 189
    .line 190
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    new-instance v2, Lh50/f;

    .line 195
    .line 196
    const/4 v3, 0x1

    .line 197
    const/4 v4, 0x0

    .line 198
    invoke-direct {v2, v0, v4, v3}, Lh50/f;-><init>(Lh50/h;Lkotlin/coroutines/Continuation;I)V

    .line 199
    .line 200
    .line 201
    const/4 v3, 0x3

    .line 202
    invoke-static {v1, v4, v4, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 203
    .line 204
    .line 205
    move-result-object v1

    .line 206
    iput-object v1, v0, Lh50/h;->p:Lvy0/x1;

    .line 207
    .line 208
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 209
    .line 210
    return-object v0

    .line 211
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 212
    .line 213
    check-cast v0, Lh50/h;

    .line 214
    .line 215
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    move-object v2, v1

    .line 220
    check-cast v2, Lh50/e;

    .line 221
    .line 222
    const/4 v6, 0x0

    .line 223
    const/16 v7, 0xb

    .line 224
    .line 225
    const/4 v3, 0x0

    .line 226
    const/4 v4, 0x0

    .line 227
    const-string v5, ""

    .line 228
    .line 229
    invoke-static/range {v2 .. v7}, Lh50/e;->a(Lh50/e;ZZLjava/lang/String;Lyj0/a;I)Lh50/e;

    .line 230
    .line 231
    .line 232
    move-result-object v1

    .line 233
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 234
    .line 235
    .line 236
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 237
    .line 238
    return-object v0

    .line 239
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v0, Lh50/d;

    .line 242
    .line 243
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 244
    .line 245
    .line 246
    move-result-object v1

    .line 247
    move-object v2, v1

    .line 248
    check-cast v2, Lh50/c;

    .line 249
    .line 250
    const/4 v7, 0x0

    .line 251
    const/16 v8, 0x17

    .line 252
    .line 253
    const/4 v3, 0x0

    .line 254
    const/4 v4, 0x0

    .line 255
    const/4 v5, 0x0

    .line 256
    const/4 v6, 0x0

    .line 257
    invoke-static/range {v2 .. v8}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 262
    .line 263
    .line 264
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 265
    .line 266
    return-object v0

    .line 267
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 268
    .line 269
    check-cast v0, Lh50/d;

    .line 270
    .line 271
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    move-object v2, v1

    .line 276
    check-cast v2, Lh50/c;

    .line 277
    .line 278
    const/4 v7, 0x0

    .line 279
    const/16 v8, 0x17

    .line 280
    .line 281
    const/4 v3, 0x0

    .line 282
    const/4 v4, 0x0

    .line 283
    const/4 v5, 0x0

    .line 284
    const/4 v6, 0x0

    .line 285
    invoke-static/range {v2 .. v8}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 286
    .line 287
    .line 288
    move-result-object v1

    .line 289
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 290
    .line 291
    .line 292
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 293
    .line 294
    .line 295
    move-result-object v1

    .line 296
    new-instance v2, Lh50/b;

    .line 297
    .line 298
    const/4 v3, 0x1

    .line 299
    invoke-direct {v2, v0, v4, v3}, Lh50/b;-><init>(Lh50/d;Lkotlin/coroutines/Continuation;I)V

    .line 300
    .line 301
    .line 302
    const/4 v0, 0x3

    .line 303
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 304
    .line 305
    .line 306
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 307
    .line 308
    return-object v0

    .line 309
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v0, Lh50/d;

    .line 312
    .line 313
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 314
    .line 315
    .line 316
    move-result-object v1

    .line 317
    move-object v2, v1

    .line 318
    check-cast v2, Lh50/c;

    .line 319
    .line 320
    const/4 v7, 0x0

    .line 321
    const/16 v8, 0x17

    .line 322
    .line 323
    const/4 v3, 0x0

    .line 324
    const/4 v4, 0x0

    .line 325
    const/4 v5, 0x0

    .line 326
    const/4 v6, 0x1

    .line 327
    invoke-static/range {v2 .. v8}, Lh50/c;->a(Lh50/c;Ljava/util/UUID;Ljava/util/ArrayList;IZZI)Lh50/c;

    .line 328
    .line 329
    .line 330
    move-result-object v1

    .line 331
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 332
    .line 333
    .line 334
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 335
    .line 336
    return-object v0

    .line 337
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 338
    .line 339
    check-cast v0, Lh50/d;

    .line 340
    .line 341
    iget-object v0, v0, Lh50/d;->h:Ltr0/b;

    .line 342
    .line 343
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 347
    .line 348
    return-object v0

    .line 349
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v0, Lh40/i4;

    .line 352
    .line 353
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 354
    .line 355
    .line 356
    move-result-object v1

    .line 357
    move-object v2, v1

    .line 358
    check-cast v2, Lh40/d4;

    .line 359
    .line 360
    const/16 v21, 0x0

    .line 361
    .line 362
    const v22, 0x7ffff

    .line 363
    .line 364
    .line 365
    const/4 v3, 0x0

    .line 366
    const/4 v4, 0x0

    .line 367
    const/4 v5, 0x0

    .line 368
    const/4 v6, 0x0

    .line 369
    const/4 v7, 0x0

    .line 370
    const/4 v8, 0x0

    .line 371
    const/4 v9, 0x0

    .line 372
    const/4 v10, 0x0

    .line 373
    const/4 v11, 0x0

    .line 374
    const/4 v12, 0x0

    .line 375
    const/4 v13, 0x0

    .line 376
    const/4 v14, 0x0

    .line 377
    const/4 v15, 0x0

    .line 378
    const/16 v16, 0x0

    .line 379
    .line 380
    const/16 v17, 0x0

    .line 381
    .line 382
    const/16 v18, 0x0

    .line 383
    .line 384
    const/16 v19, 0x0

    .line 385
    .line 386
    const/16 v20, 0x0

    .line 387
    .line 388
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 393
    .line 394
    .line 395
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 396
    .line 397
    return-object v0

    .line 398
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 399
    .line 400
    check-cast v0, Lh40/i4;

    .line 401
    .line 402
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 403
    .line 404
    .line 405
    move-result-object v1

    .line 406
    move-object v2, v1

    .line 407
    check-cast v2, Lh40/d4;

    .line 408
    .line 409
    const/16 v21, 0x0

    .line 410
    .line 411
    const v22, 0xbffff

    .line 412
    .line 413
    .line 414
    const/4 v3, 0x0

    .line 415
    const/4 v4, 0x0

    .line 416
    const/4 v5, 0x0

    .line 417
    const/4 v6, 0x0

    .line 418
    const/4 v7, 0x0

    .line 419
    const/4 v8, 0x0

    .line 420
    const/4 v9, 0x0

    .line 421
    const/4 v10, 0x0

    .line 422
    const/4 v11, 0x0

    .line 423
    const/4 v12, 0x0

    .line 424
    const/4 v13, 0x0

    .line 425
    const/4 v14, 0x0

    .line 426
    const/4 v15, 0x0

    .line 427
    const/16 v16, 0x0

    .line 428
    .line 429
    const/16 v17, 0x0

    .line 430
    .line 431
    const/16 v18, 0x0

    .line 432
    .line 433
    const/16 v19, 0x0

    .line 434
    .line 435
    const/16 v20, 0x0

    .line 436
    .line 437
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 442
    .line 443
    .line 444
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 445
    .line 446
    return-object v0

    .line 447
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast v0, Lh40/i4;

    .line 450
    .line 451
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 452
    .line 453
    .line 454
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 455
    .line 456
    .line 457
    move-result-object v1

    .line 458
    new-instance v2, Lh40/z3;

    .line 459
    .line 460
    const/4 v3, 0x1

    .line 461
    const/4 v4, 0x0

    .line 462
    invoke-direct {v2, v0, v4, v3}, Lh40/z3;-><init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V

    .line 463
    .line 464
    .line 465
    const/4 v0, 0x3

    .line 466
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 467
    .line 468
    .line 469
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 470
    .line 471
    return-object v0

    .line 472
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 473
    .line 474
    check-cast v0, Lh40/i4;

    .line 475
    .line 476
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    move-object v2, v1

    .line 481
    check-cast v2, Lh40/d4;

    .line 482
    .line 483
    const/16 v21, 0x0

    .line 484
    .line 485
    const v22, 0xdffff

    .line 486
    .line 487
    .line 488
    const/4 v3, 0x0

    .line 489
    const/4 v4, 0x0

    .line 490
    const/4 v5, 0x0

    .line 491
    const/4 v6, 0x0

    .line 492
    const/4 v7, 0x0

    .line 493
    const/4 v8, 0x0

    .line 494
    const/4 v9, 0x0

    .line 495
    const/4 v10, 0x0

    .line 496
    const/4 v11, 0x0

    .line 497
    const/4 v12, 0x0

    .line 498
    const/4 v13, 0x0

    .line 499
    const/4 v14, 0x0

    .line 500
    const/4 v15, 0x0

    .line 501
    const/16 v16, 0x0

    .line 502
    .line 503
    const/16 v17, 0x0

    .line 504
    .line 505
    const/16 v18, 0x0

    .line 506
    .line 507
    const/16 v19, 0x0

    .line 508
    .line 509
    const/16 v20, 0x0

    .line 510
    .line 511
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 512
    .line 513
    .line 514
    move-result-object v1

    .line 515
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 516
    .line 517
    .line 518
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 519
    .line 520
    return-object v0

    .line 521
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v0, Lh40/i4;

    .line 524
    .line 525
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 526
    .line 527
    .line 528
    move-result-object v1

    .line 529
    move-object v2, v1

    .line 530
    check-cast v2, Lh40/d4;

    .line 531
    .line 532
    const/16 v21, 0x0

    .line 533
    .line 534
    const v22, 0xdffff

    .line 535
    .line 536
    .line 537
    const/4 v3, 0x0

    .line 538
    const/4 v4, 0x0

    .line 539
    const/4 v5, 0x0

    .line 540
    const/4 v6, 0x0

    .line 541
    const/4 v7, 0x0

    .line 542
    const/4 v8, 0x0

    .line 543
    const/4 v9, 0x0

    .line 544
    const/4 v10, 0x0

    .line 545
    const/4 v11, 0x0

    .line 546
    const/4 v12, 0x0

    .line 547
    const/4 v13, 0x0

    .line 548
    const/4 v14, 0x0

    .line 549
    const/4 v15, 0x0

    .line 550
    const/16 v16, 0x0

    .line 551
    .line 552
    const/16 v17, 0x0

    .line 553
    .line 554
    const/16 v18, 0x0

    .line 555
    .line 556
    const/16 v19, 0x0

    .line 557
    .line 558
    const/16 v20, 0x0

    .line 559
    .line 560
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 561
    .line 562
    .line 563
    move-result-object v1

    .line 564
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 565
    .line 566
    .line 567
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 568
    .line 569
    .line 570
    move-result-object v1

    .line 571
    new-instance v2, Lh40/z3;

    .line 572
    .line 573
    const/4 v3, 0x2

    .line 574
    const/4 v4, 0x0

    .line 575
    invoke-direct {v2, v0, v4, v3}, Lh40/z3;-><init>(Lh40/i4;Lkotlin/coroutines/Continuation;I)V

    .line 576
    .line 577
    .line 578
    const/4 v0, 0x3

    .line 579
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 580
    .line 581
    .line 582
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 583
    .line 584
    return-object v0

    .line 585
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 586
    .line 587
    check-cast v0, Lh40/i4;

    .line 588
    .line 589
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 590
    .line 591
    .line 592
    move-result-object v1

    .line 593
    move-object v2, v1

    .line 594
    check-cast v2, Lh40/d4;

    .line 595
    .line 596
    const/16 v21, 0x0

    .line 597
    .line 598
    const v22, 0xeffff

    .line 599
    .line 600
    .line 601
    const/4 v3, 0x0

    .line 602
    const/4 v4, 0x0

    .line 603
    const/4 v5, 0x0

    .line 604
    const/4 v6, 0x0

    .line 605
    const/4 v7, 0x0

    .line 606
    const/4 v8, 0x0

    .line 607
    const/4 v9, 0x0

    .line 608
    const/4 v10, 0x0

    .line 609
    const/4 v11, 0x0

    .line 610
    const/4 v12, 0x0

    .line 611
    const/4 v13, 0x0

    .line 612
    const/4 v14, 0x0

    .line 613
    const/4 v15, 0x0

    .line 614
    const/16 v16, 0x0

    .line 615
    .line 616
    const/16 v17, 0x0

    .line 617
    .line 618
    const/16 v18, 0x0

    .line 619
    .line 620
    const/16 v19, 0x0

    .line 621
    .line 622
    const/16 v20, 0x0

    .line 623
    .line 624
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 625
    .line 626
    .line 627
    move-result-object v1

    .line 628
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 629
    .line 630
    .line 631
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 632
    .line 633
    return-object v0

    .line 634
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 635
    .line 636
    check-cast v0, Lh40/i4;

    .line 637
    .line 638
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 639
    .line 640
    .line 641
    move-result-object v1

    .line 642
    move-object v2, v1

    .line 643
    check-cast v2, Lh40/d4;

    .line 644
    .line 645
    const/16 v21, 0x0

    .line 646
    .line 647
    const v22, 0xf7fff

    .line 648
    .line 649
    .line 650
    const/4 v3, 0x0

    .line 651
    const/4 v4, 0x0

    .line 652
    const/4 v5, 0x0

    .line 653
    const/4 v6, 0x0

    .line 654
    const/4 v7, 0x0

    .line 655
    const/4 v8, 0x0

    .line 656
    const/4 v9, 0x0

    .line 657
    const/4 v10, 0x0

    .line 658
    const/4 v11, 0x0

    .line 659
    const/4 v12, 0x0

    .line 660
    const/4 v13, 0x0

    .line 661
    const/4 v14, 0x0

    .line 662
    const/4 v15, 0x0

    .line 663
    const/16 v16, 0x0

    .line 664
    .line 665
    const/16 v17, 0x0

    .line 666
    .line 667
    const/16 v18, 0x0

    .line 668
    .line 669
    const/16 v19, 0x0

    .line 670
    .line 671
    const/16 v20, 0x0

    .line 672
    .line 673
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 674
    .line 675
    .line 676
    move-result-object v1

    .line 677
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 678
    .line 679
    .line 680
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 681
    .line 682
    return-object v0

    .line 683
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 684
    .line 685
    check-cast v0, Lh40/i4;

    .line 686
    .line 687
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 688
    .line 689
    .line 690
    move-result-object v1

    .line 691
    move-object v2, v1

    .line 692
    check-cast v2, Lh40/d4;

    .line 693
    .line 694
    const/16 v21, 0x0

    .line 695
    .line 696
    const v22, 0xfe7ff

    .line 697
    .line 698
    .line 699
    const/4 v3, 0x0

    .line 700
    const/4 v4, 0x0

    .line 701
    const/4 v5, 0x0

    .line 702
    const/4 v6, 0x0

    .line 703
    const/4 v7, 0x0

    .line 704
    const/4 v8, 0x0

    .line 705
    const/4 v9, 0x0

    .line 706
    const/4 v10, 0x0

    .line 707
    const/4 v11, 0x0

    .line 708
    const/4 v12, 0x0

    .line 709
    const/4 v13, 0x0

    .line 710
    const/4 v14, 0x0

    .line 711
    const/4 v15, 0x0

    .line 712
    const/16 v16, 0x0

    .line 713
    .line 714
    const/16 v17, 0x0

    .line 715
    .line 716
    const/16 v18, 0x0

    .line 717
    .line 718
    const/16 v19, 0x0

    .line 719
    .line 720
    const/16 v20, 0x0

    .line 721
    .line 722
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 723
    .line 724
    .line 725
    move-result-object v1

    .line 726
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 727
    .line 728
    .line 729
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 730
    .line 731
    return-object v0

    .line 732
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 733
    .line 734
    check-cast v0, Lh40/i4;

    .line 735
    .line 736
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 737
    .line 738
    .line 739
    move-result-object v1

    .line 740
    move-object v2, v1

    .line 741
    check-cast v2, Lh40/d4;

    .line 742
    .line 743
    const/16 v21, 0x0

    .line 744
    .line 745
    const v22, 0xff7ff

    .line 746
    .line 747
    .line 748
    const/4 v3, 0x0

    .line 749
    const/4 v4, 0x0

    .line 750
    const/4 v5, 0x0

    .line 751
    const/4 v6, 0x0

    .line 752
    const/4 v7, 0x0

    .line 753
    const/4 v8, 0x0

    .line 754
    const/4 v9, 0x0

    .line 755
    const/4 v10, 0x0

    .line 756
    const/4 v11, 0x0

    .line 757
    const/4 v12, 0x0

    .line 758
    const/4 v13, 0x0

    .line 759
    const/4 v14, 0x0

    .line 760
    const/4 v15, 0x0

    .line 761
    const/16 v16, 0x0

    .line 762
    .line 763
    const/16 v17, 0x0

    .line 764
    .line 765
    const/16 v18, 0x0

    .line 766
    .line 767
    const/16 v19, 0x0

    .line 768
    .line 769
    const/16 v20, 0x0

    .line 770
    .line 771
    invoke-static/range {v2 .. v22}, Lh40/d4;->a(Lh40/d4;IZZZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/List;Lh40/b4;Lh40/a4;ZLjava/lang/String;ZZLql0/g;ZZZZI)Lh40/d4;

    .line 772
    .line 773
    .line 774
    move-result-object v1

    .line 775
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 776
    .line 777
    .line 778
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 779
    .line 780
    .line 781
    move-result-object v1

    .line 782
    check-cast v1, Lh40/d4;

    .line 783
    .line 784
    iget-object v1, v1, Lh40/d4;->m:Ljava/lang/String;

    .line 785
    .line 786
    if-eqz v1, :cond_2

    .line 787
    .line 788
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 789
    .line 790
    .line 791
    move-result-object v2

    .line 792
    new-instance v3, Lh40/f4;

    .line 793
    .line 794
    const/4 v4, 0x2

    .line 795
    const/4 v5, 0x0

    .line 796
    invoke-direct {v3, v0, v1, v5, v4}, Lh40/f4;-><init>(Lh40/i4;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 797
    .line 798
    .line 799
    const/4 v0, 0x3

    .line 800
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 801
    .line 802
    .line 803
    :cond_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 804
    .line 805
    return-object v0

    .line 806
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 807
    .line 808
    check-cast v0, Lh40/x3;

    .line 809
    .line 810
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 811
    .line 812
    .line 813
    new-instance v1, Lh40/p3;

    .line 814
    .line 815
    const/4 v2, 0x1

    .line 816
    invoke-direct {v1, v0, v2}, Lh40/p3;-><init>(Lh40/x3;I)V

    .line 817
    .line 818
    .line 819
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 820
    .line 821
    .line 822
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 823
    .line 824
    .line 825
    move-result-object v1

    .line 826
    move-object v2, v1

    .line 827
    check-cast v2, Lh40/s3;

    .line 828
    .line 829
    const/16 v26, 0x0

    .line 830
    .line 831
    const v27, 0x1fffeff

    .line 832
    .line 833
    .line 834
    const/4 v3, 0x0

    .line 835
    const/4 v4, 0x0

    .line 836
    const/4 v5, 0x0

    .line 837
    const/4 v6, 0x0

    .line 838
    const/4 v7, 0x0

    .line 839
    const/4 v8, 0x0

    .line 840
    const/4 v9, 0x0

    .line 841
    const/4 v10, 0x0

    .line 842
    const/4 v11, 0x0

    .line 843
    const/4 v12, 0x0

    .line 844
    const/4 v13, 0x0

    .line 845
    const/4 v14, 0x0

    .line 846
    const/4 v15, 0x0

    .line 847
    const/16 v16, 0x0

    .line 848
    .line 849
    const/16 v17, 0x0

    .line 850
    .line 851
    const/16 v18, 0x0

    .line 852
    .line 853
    const/16 v19, 0x0

    .line 854
    .line 855
    const/16 v20, 0x0

    .line 856
    .line 857
    const/16 v21, 0x0

    .line 858
    .line 859
    const/16 v22, 0x0

    .line 860
    .line 861
    const/16 v23, 0x0

    .line 862
    .line 863
    const/16 v24, 0x0

    .line 864
    .line 865
    const/16 v25, 0x0

    .line 866
    .line 867
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 868
    .line 869
    .line 870
    move-result-object v1

    .line 871
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 872
    .line 873
    .line 874
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 875
    .line 876
    return-object v0

    .line 877
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 878
    .line 879
    check-cast v0, Lh40/x3;

    .line 880
    .line 881
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 882
    .line 883
    .line 884
    move-result-object v1

    .line 885
    move-object v2, v1

    .line 886
    check-cast v2, Lh40/s3;

    .line 887
    .line 888
    const/16 v26, 0x0

    .line 889
    .line 890
    const v27, 0x1fffeff

    .line 891
    .line 892
    .line 893
    const/4 v3, 0x0

    .line 894
    const/4 v4, 0x0

    .line 895
    const/4 v5, 0x0

    .line 896
    const/4 v6, 0x0

    .line 897
    const/4 v7, 0x0

    .line 898
    const/4 v8, 0x0

    .line 899
    const/4 v9, 0x0

    .line 900
    const/4 v10, 0x0

    .line 901
    const/4 v11, 0x0

    .line 902
    const/4 v12, 0x0

    .line 903
    const/4 v13, 0x0

    .line 904
    const/4 v14, 0x0

    .line 905
    const/4 v15, 0x0

    .line 906
    const/16 v16, 0x0

    .line 907
    .line 908
    const/16 v17, 0x0

    .line 909
    .line 910
    const/16 v18, 0x0

    .line 911
    .line 912
    const/16 v19, 0x0

    .line 913
    .line 914
    const/16 v20, 0x0

    .line 915
    .line 916
    const/16 v21, 0x0

    .line 917
    .line 918
    const/16 v22, 0x0

    .line 919
    .line 920
    const/16 v23, 0x0

    .line 921
    .line 922
    const/16 v24, 0x0

    .line 923
    .line 924
    const/16 v25, 0x0

    .line 925
    .line 926
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 927
    .line 928
    .line 929
    move-result-object v1

    .line 930
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 931
    .line 932
    .line 933
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 934
    .line 935
    .line 936
    move-result-object v1

    .line 937
    new-instance v2, Lg60/w;

    .line 938
    .line 939
    const/16 v3, 0x1c

    .line 940
    .line 941
    const/4 v4, 0x0

    .line 942
    invoke-direct {v2, v0, v4, v3}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 943
    .line 944
    .line 945
    const/4 v0, 0x3

    .line 946
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 947
    .line 948
    .line 949
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 950
    .line 951
    return-object v0

    .line 952
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 953
    .line 954
    check-cast v0, Lh40/x3;

    .line 955
    .line 956
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 957
    .line 958
    .line 959
    move-result-object v1

    .line 960
    move-object v2, v1

    .line 961
    check-cast v2, Lh40/s3;

    .line 962
    .line 963
    const/16 v26, 0x0

    .line 964
    .line 965
    const v27, 0x1fffeff

    .line 966
    .line 967
    .line 968
    const/4 v3, 0x0

    .line 969
    const/4 v4, 0x0

    .line 970
    const/4 v5, 0x0

    .line 971
    const/4 v6, 0x0

    .line 972
    const/4 v7, 0x0

    .line 973
    const/4 v8, 0x0

    .line 974
    const/4 v9, 0x0

    .line 975
    const/4 v10, 0x0

    .line 976
    const/4 v11, 0x1

    .line 977
    const/4 v12, 0x0

    .line 978
    const/4 v13, 0x0

    .line 979
    const/4 v14, 0x0

    .line 980
    const/4 v15, 0x0

    .line 981
    const/16 v16, 0x0

    .line 982
    .line 983
    const/16 v17, 0x0

    .line 984
    .line 985
    const/16 v18, 0x0

    .line 986
    .line 987
    const/16 v19, 0x0

    .line 988
    .line 989
    const/16 v20, 0x0

    .line 990
    .line 991
    const/16 v21, 0x0

    .line 992
    .line 993
    const/16 v22, 0x0

    .line 994
    .line 995
    const/16 v23, 0x0

    .line 996
    .line 997
    const/16 v24, 0x0

    .line 998
    .line 999
    const/16 v25, 0x0

    .line 1000
    .line 1001
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 1002
    .line 1003
    .line 1004
    move-result-object v1

    .line 1005
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1006
    .line 1007
    .line 1008
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1009
    .line 1010
    return-object v0

    .line 1011
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1012
    .line 1013
    check-cast v0, Lh40/x3;

    .line 1014
    .line 1015
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1016
    .line 1017
    .line 1018
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1019
    .line 1020
    .line 1021
    move-result-object v1

    .line 1022
    new-instance v2, Lh40/q3;

    .line 1023
    .line 1024
    const/4 v3, 0x3

    .line 1025
    const/4 v4, 0x0

    .line 1026
    invoke-direct {v2, v0, v4, v3}, Lh40/q3;-><init>(Lh40/x3;Lkotlin/coroutines/Continuation;I)V

    .line 1027
    .line 1028
    .line 1029
    const/4 v0, 0x3

    .line 1030
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1031
    .line 1032
    .line 1033
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1034
    .line 1035
    return-object v0

    .line 1036
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1037
    .line 1038
    check-cast v0, Lh40/x3;

    .line 1039
    .line 1040
    iget-object v0, v0, Lh40/x3;->k:Lf40/e2;

    .line 1041
    .line 1042
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1043
    .line 1044
    .line 1045
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1046
    .line 1047
    return-object v0

    .line 1048
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1049
    .line 1050
    check-cast v0, Lh40/x3;

    .line 1051
    .line 1052
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1053
    .line 1054
    .line 1055
    move-result-object v1

    .line 1056
    move-object v2, v1

    .line 1057
    check-cast v2, Lh40/s3;

    .line 1058
    .line 1059
    const/16 v26, 0x0

    .line 1060
    .line 1061
    const v27, 0x17fffff

    .line 1062
    .line 1063
    .line 1064
    const/4 v3, 0x0

    .line 1065
    const/4 v4, 0x0

    .line 1066
    const/4 v5, 0x0

    .line 1067
    const/4 v6, 0x0

    .line 1068
    const/4 v7, 0x0

    .line 1069
    const/4 v8, 0x0

    .line 1070
    const/4 v9, 0x0

    .line 1071
    const/4 v10, 0x0

    .line 1072
    const/4 v11, 0x0

    .line 1073
    const/4 v12, 0x0

    .line 1074
    const/4 v13, 0x0

    .line 1075
    const/4 v14, 0x0

    .line 1076
    const/4 v15, 0x0

    .line 1077
    const/16 v16, 0x0

    .line 1078
    .line 1079
    const/16 v17, 0x0

    .line 1080
    .line 1081
    const/16 v18, 0x0

    .line 1082
    .line 1083
    const/16 v19, 0x0

    .line 1084
    .line 1085
    const/16 v20, 0x0

    .line 1086
    .line 1087
    const/16 v21, 0x0

    .line 1088
    .line 1089
    const/16 v22, 0x0

    .line 1090
    .line 1091
    const/16 v23, 0x0

    .line 1092
    .line 1093
    const/16 v24, 0x0

    .line 1094
    .line 1095
    const/16 v25, 0x0

    .line 1096
    .line 1097
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 1098
    .line 1099
    .line 1100
    move-result-object v1

    .line 1101
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1102
    .line 1103
    .line 1104
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1105
    .line 1106
    return-object v0

    .line 1107
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1108
    .line 1109
    check-cast v0, Lh40/x3;

    .line 1110
    .line 1111
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 1112
    .line 1113
    .line 1114
    move-result-object v1

    .line 1115
    move-object v2, v1

    .line 1116
    check-cast v2, Lh40/s3;

    .line 1117
    .line 1118
    const/16 v26, 0x0

    .line 1119
    .line 1120
    const v27, 0x1bfffff

    .line 1121
    .line 1122
    .line 1123
    const/4 v3, 0x0

    .line 1124
    const/4 v4, 0x0

    .line 1125
    const/4 v5, 0x0

    .line 1126
    const/4 v6, 0x0

    .line 1127
    const/4 v7, 0x0

    .line 1128
    const/4 v8, 0x0

    .line 1129
    const/4 v9, 0x0

    .line 1130
    const/4 v10, 0x0

    .line 1131
    const/4 v11, 0x0

    .line 1132
    const/4 v12, 0x0

    .line 1133
    const/4 v13, 0x0

    .line 1134
    const/4 v14, 0x0

    .line 1135
    const/4 v15, 0x0

    .line 1136
    const/16 v16, 0x0

    .line 1137
    .line 1138
    const/16 v17, 0x0

    .line 1139
    .line 1140
    const/16 v18, 0x0

    .line 1141
    .line 1142
    const/16 v19, 0x0

    .line 1143
    .line 1144
    const/16 v20, 0x0

    .line 1145
    .line 1146
    const/16 v21, 0x0

    .line 1147
    .line 1148
    const/16 v22, 0x0

    .line 1149
    .line 1150
    const/16 v23, 0x0

    .line 1151
    .line 1152
    const/16 v24, 0x0

    .line 1153
    .line 1154
    const/16 v25, 0x0

    .line 1155
    .line 1156
    invoke-static/range {v2 .. v27}, Lh40/s3;->a(Lh40/s3;ZZZZZZLjava/util/ArrayList;Ljava/util/ArrayList;ZLh40/u;IZLjava/lang/String;Lh40/g0;Lql0/g;ZZZZZZZZLh40/r3;I)Lh40/s3;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v1

    .line 1160
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 1161
    .line 1162
    .line 1163
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1164
    .line 1165
    return-object v0

    .line 1166
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1167
    .line 1168
    check-cast v0, Lh40/x3;

    .line 1169
    .line 1170
    iget-object v0, v0, Lh40/x3;->h:Lwr0/l;

    .line 1171
    .line 1172
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1173
    .line 1174
    .line 1175
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1176
    .line 1177
    return-object v0

    .line 1178
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1179
    .line 1180
    check-cast v0, Lh40/x3;

    .line 1181
    .line 1182
    iget-object v0, v0, Lh40/x3;->N:Lf40/t2;

    .line 1183
    .line 1184
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 1185
    .line 1186
    .line 1187
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1188
    .line 1189
    return-object v0

    .line 1190
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 1191
    .line 1192
    check-cast v0, Lh40/x3;

    .line 1193
    .line 1194
    iget-object v0, v0, Lh40/x3;->K:Lf40/k4;

    .line 1195
    .line 1196
    sget-object v1, Lg40/u0;->e:Lg40/u0;

    .line 1197
    .line 1198
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1199
    .line 1200
    .line 1201
    iget-object v0, v0, Lf40/k4;->a:Lf40/c1;

    .line 1202
    .line 1203
    check-cast v0, Ld40/e;

    .line 1204
    .line 1205
    iget-object v0, v0, Ld40/e;->g:Lyy0/q1;

    .line 1206
    .line 1207
    invoke-virtual {v0, v1}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 1208
    .line 1209
    .line 1210
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1211
    .line 1212
    return-object v0

    .line 1213
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
