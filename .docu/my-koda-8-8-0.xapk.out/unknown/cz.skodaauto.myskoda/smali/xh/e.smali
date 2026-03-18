.class public final synthetic Lxh/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lxh/e;->d:I

    iput-object p2, p0, Lxh/e;->f:Ljava/lang/Object;

    iput-object p3, p0, Lxh/e;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lay0/k;Lxj0/s;)V
    .locals 1

    .line 2
    const/16 v0, 0xa

    iput v0, p0, Lxh/e;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lxh/e;->e:Ljava/lang/Object;

    iput-object p2, p0, Lxh/e;->f:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Lxh/e;->d:I

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/16 v3, 0x13

    .line 7
    .line 8
    const-string v4, "it"

    .line 9
    .line 10
    const/4 v5, 0x3

    .line 11
    const v6, 0x2fd4df92

    .line 12
    .line 13
    .line 14
    const/4 v7, 0x7

    .line 15
    const-string v8, "$this$LazyColumn"

    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x1

    .line 19
    sget-object v11, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    iget-object v12, p0, Lxh/e;->e:Ljava/lang/Object;

    .line 22
    .line 23
    iget-object p0, p0, Lxh/e;->f:Ljava/lang/Object;

    .line 24
    .line 25
    packed-switch v0, :pswitch_data_0

    .line 26
    .line 27
    .line 28
    check-cast p0, Lyj0/f;

    .line 29
    .line 30
    check-cast v12, Lay0/k;

    .line 31
    .line 32
    check-cast p1, Lxj0/b;

    .line 33
    .line 34
    const-string v0, "cameraPosition"

    .line 35
    .line 36
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lyj0/f;->k:Lwj0/y;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lwj0/y;->a(Lxj0/b;)V

    .line 45
    .line 46
    .line 47
    invoke-interface {v12, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    return-object v11

    .line 51
    :pswitch_0
    check-cast v12, Lay0/k;

    .line 52
    .line 53
    check-cast p0, Lxj0/s;

    .line 54
    .line 55
    check-cast p1, Lsp/o;

    .line 56
    .line 57
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-interface {v12, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    return-object v11

    .line 64
    :pswitch_1
    check-cast p0, Lz9/y;

    .line 65
    .line 66
    check-cast v12, Ll2/b1;

    .line 67
    .line 68
    check-cast p1, Ljava/lang/String;

    .line 69
    .line 70
    const-string v0, "inPcid"

    .line 71
    .line 72
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-interface {v12, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    const-string p1, "/pcidshare"

    .line 79
    .line 80
    const/4 v0, 0x6

    .line 81
    invoke-static {p0, p1, v9, v0}, Lz9/y;->f(Lz9/y;Ljava/lang/String;Lz9/b0;I)V

    .line 82
    .line 83
    .line 84
    return-object v11

    .line 85
    :pswitch_2
    check-cast p0, Lzb/v0;

    .line 86
    .line 87
    check-cast v12, Lay0/n;

    .line 88
    .line 89
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    new-instance v0, Lxh/e;

    .line 93
    .line 94
    invoke-direct {v0, v7, v12, p1}, Lxh/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0, v0}, Lzb/v0;->g(Lay0/k;)V

    .line 98
    .line 99
    .line 100
    return-object v11

    .line 101
    :pswitch_3
    check-cast p0, Lay0/n;

    .line 102
    .line 103
    check-cast p1, Lzb/u0;

    .line 104
    .line 105
    const-string v0, "$this$wthReferences"

    .line 106
    .line 107
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-object p1, p1, Lzb/u0;->a:Lz9/y;

    .line 111
    .line 112
    invoke-interface {p0, p1, v12}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    return-object v11

    .line 116
    :pswitch_4
    check-cast p0, Lzb/q;

    .line 117
    .line 118
    check-cast v12, Ljc/a;

    .line 119
    .line 120
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 121
    .line 122
    const-string v0, "$this$DisposableEffect"

    .line 123
    .line 124
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Landroid/app/Dialog;->show()V

    .line 128
    .line 129
    .line 130
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    iget-object p1, v12, Ljc/a;->a:Ljava/util/ArrayList;

    .line 134
    .line 135
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    new-instance p1, Laa/t;

    .line 139
    .line 140
    invoke-direct {p1, v3, v12, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    return-object p1

    .line 144
    :pswitch_5
    check-cast p0, Lz9/u;

    .line 145
    .line 146
    check-cast v12, Lz9/y;

    .line 147
    .line 148
    iget-object v0, v12, Lz9/y;->b:Lca/g;

    .line 149
    .line 150
    check-cast p1, Lz9/c0;

    .line 151
    .line 152
    const-string v3, "$this$navOptions"

    .line 153
    .line 154
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    iget-object v3, p1, Lz9/c0;->a:Lz9/a0;

    .line 158
    .line 159
    iput v2, v3, Lz9/a0;->h:I

    .line 160
    .line 161
    iput v2, v3, Lz9/a0;->i:I

    .line 162
    .line 163
    instance-of v3, p0, Lz9/v;

    .line 164
    .line 165
    if-eqz v3, :cond_3

    .line 166
    .line 167
    sget v3, Lz9/u;->h:I

    .line 168
    .line 169
    invoke-static {p0}, Ljp/q0;->d(Lz9/u;)Lky0/j;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    invoke-interface {p0}, Lky0/j;->iterator()Ljava/util/Iterator;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    :cond_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 178
    .line 179
    .line 180
    move-result v3

    .line 181
    if-eqz v3, :cond_2

    .line 182
    .line 183
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    check-cast v3, Lz9/u;

    .line 188
    .line 189
    invoke-virtual {v0}, Lca/g;->h()Lz9/u;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    if-eqz v4, :cond_1

    .line 194
    .line 195
    iget-object v4, v4, Lz9/u;->f:Lz9/v;

    .line 196
    .line 197
    goto :goto_0

    .line 198
    :cond_1
    move-object v4, v9

    .line 199
    :goto_0
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 200
    .line 201
    .line 202
    move-result v3

    .line 203
    if-eqz v3, :cond_0

    .line 204
    .line 205
    goto :goto_1

    .line 206
    :cond_2
    sget p0, Lz9/v;->j:I

    .line 207
    .line 208
    invoke-virtual {v0}, Lca/g;->i()Lz9/v;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    new-instance v0, Lz70/e0;

    .line 213
    .line 214
    invoke-direct {v0, v1}, Lz70/e0;-><init>(I)V

    .line 215
    .line 216
    .line 217
    invoke-static {p0, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-static {p0}, Lky0/l;->m(Lky0/j;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    check-cast p0, Lz9/u;

    .line 226
    .line 227
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 228
    .line 229
    iget p0, p0, Lca/j;->a:I

    .line 230
    .line 231
    iput p0, p1, Lz9/c0;->d:I

    .line 232
    .line 233
    iput-boolean v2, p1, Lz9/c0;->f:Z

    .line 234
    .line 235
    new-instance p0, Lz9/l0;

    .line 236
    .line 237
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 238
    .line 239
    .line 240
    iput-boolean v10, p0, Lz9/l0;->b:Z

    .line 241
    .line 242
    iget-boolean v0, p0, Lz9/l0;->a:Z

    .line 243
    .line 244
    iput-boolean v0, p1, Lz9/c0;->f:Z

    .line 245
    .line 246
    iget-boolean p0, p0, Lz9/l0;->b:Z

    .line 247
    .line 248
    iput-boolean p0, p1, Lz9/c0;->g:Z

    .line 249
    .line 250
    :cond_3
    :goto_1
    return-object v11

    .line 251
    :pswitch_6
    check-cast p0, Ly70/k0;

    .line 252
    .line 253
    check-cast v12, Lay0/k;

    .line 254
    .line 255
    check-cast p1, Lm1/f;

    .line 256
    .line 257
    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    iget-object p0, p0, Ly70/k0;->b:Ljava/util/List;

    .line 261
    .line 262
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 263
    .line 264
    .line 265
    move-result v0

    .line 266
    new-instance v1, Lnu0/c;

    .line 267
    .line 268
    const/16 v2, 0xd

    .line 269
    .line 270
    invoke-direct {v1, p0, v2}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 271
    .line 272
    .line 273
    new-instance v2, Lak/q;

    .line 274
    .line 275
    const/16 v3, 0xc

    .line 276
    .line 277
    invoke-direct {v2, p0, v12, v3}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 278
    .line 279
    .line 280
    new-instance p0, Lt2/b;

    .line 281
    .line 282
    invoke-direct {p0, v2, v10, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {p1, v0, v9, v1, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 286
    .line 287
    .line 288
    return-object v11

    .line 289
    :pswitch_7
    check-cast p0, Ly20/h;

    .line 290
    .line 291
    check-cast v12, Lay0/k;

    .line 292
    .line 293
    check-cast p1, Lm1/f;

    .line 294
    .line 295
    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    sget-object v0, Lz20/a;->b:Lt2/b;

    .line 299
    .line 300
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 301
    .line 302
    .line 303
    iget-boolean v0, p0, Ly20/h;->d:Z

    .line 304
    .line 305
    if-eqz v0, :cond_4

    .line 306
    .line 307
    sget-object p0, Lz20/a;->c:Lt2/b;

    .line 308
    .line 309
    invoke-static {p1, p0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 310
    .line 311
    .line 312
    goto :goto_2

    .line 313
    :cond_4
    iget-boolean v0, p0, Ly20/h;->b:Z

    .line 314
    .line 315
    if-eqz v0, :cond_5

    .line 316
    .line 317
    sget-object p0, Lz20/a;->d:Lt2/b;

    .line 318
    .line 319
    invoke-static {p1, p0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 320
    .line 321
    .line 322
    goto :goto_2

    .line 323
    :cond_5
    iget-object p0, p0, Ly20/h;->i:Ljava/util/List;

    .line 324
    .line 325
    new-instance v0, Lxy/f;

    .line 326
    .line 327
    const/16 v1, 0x15

    .line 328
    .line 329
    invoke-direct {v0, v1}, Lxy/f;-><init>(I)V

    .line 330
    .line 331
    .line 332
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 333
    .line 334
    .line 335
    move-result v1

    .line 336
    new-instance v2, Lc41/g;

    .line 337
    .line 338
    const/16 v3, 0x19

    .line 339
    .line 340
    invoke-direct {v2, v3, v0, p0}, Lc41/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    new-instance v0, Lnu0/c;

    .line 344
    .line 345
    const/16 v3, 0xa

    .line 346
    .line 347
    invoke-direct {v0, p0, v3}, Lnu0/c;-><init>(Ljava/util/List;I)V

    .line 348
    .line 349
    .line 350
    new-instance v4, Lak/q;

    .line 351
    .line 352
    invoke-direct {v4, p0, v12, v3}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 353
    .line 354
    .line 355
    new-instance p0, Lt2/b;

    .line 356
    .line 357
    invoke-direct {p0, v4, v10, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 358
    .line 359
    .line 360
    invoke-virtual {p1, v1, v2, v0, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 361
    .line 362
    .line 363
    :goto_2
    return-object v11

    .line 364
    :pswitch_8
    check-cast p0, Ljd/i;

    .line 365
    .line 366
    check-cast v12, Lay0/k;

    .line 367
    .line 368
    check-cast p1, Lm1/f;

    .line 369
    .line 370
    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 371
    .line 372
    .line 373
    new-instance v0, Lx40/j;

    .line 374
    .line 375
    invoke-direct {v0, v7, p0, v12}, Lx40/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 376
    .line 377
    .line 378
    new-instance v4, Lt2/b;

    .line 379
    .line 380
    const v6, -0x74b094bd

    .line 381
    .line 382
    .line 383
    invoke-direct {v4, v0, v10, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 384
    .line 385
    .line 386
    invoke-static {p1, v4, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 387
    .line 388
    .line 389
    iget-object v0, p0, Ljd/i;->b:Ljava/util/ArrayList;

    .line 390
    .line 391
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 392
    .line 393
    .line 394
    move-result v4

    .line 395
    new-instance v6, Lal/n;

    .line 396
    .line 397
    invoke-direct {v6, v0, v1}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 398
    .line 399
    .line 400
    new-instance v1, Lyj/d;

    .line 401
    .line 402
    invoke-direct {v1, v0, v12, p0, v2}, Lyj/d;-><init>(Ljava/util/ArrayList;Lay0/k;Ljd/i;I)V

    .line 403
    .line 404
    .line 405
    new-instance v0, Lt2/b;

    .line 406
    .line 407
    const v2, 0x799532c4

    .line 408
    .line 409
    .line 410
    invoke-direct {v0, v1, v10, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 411
    .line 412
    .line 413
    invoke-virtual {p1, v4, v9, v6, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 414
    .line 415
    .line 416
    sget-object v0, Lyj/a;->e:Lt2/b;

    .line 417
    .line 418
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 419
    .line 420
    .line 421
    iget-object v0, p0, Ljd/i;->c:Ljava/util/ArrayList;

    .line 422
    .line 423
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 424
    .line 425
    .line 426
    move-result v1

    .line 427
    new-instance v4, Lal/n;

    .line 428
    .line 429
    const/16 v6, 0x9

    .line 430
    .line 431
    invoke-direct {v4, v0, v6}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 432
    .line 433
    .line 434
    new-instance v6, Lyj/d;

    .line 435
    .line 436
    invoke-direct {v6, v0, v12, p0, v10}, Lyj/d;-><init>(Ljava/util/ArrayList;Lay0/k;Ljd/i;I)V

    .line 437
    .line 438
    .line 439
    new-instance p0, Lt2/b;

    .line 440
    .line 441
    invoke-direct {p0, v6, v10, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 442
    .line 443
    .line 444
    invoke-virtual {p1, v1, v9, v4, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 445
    .line 446
    .line 447
    new-instance p0, Llk/k;

    .line 448
    .line 449
    invoke-direct {p0, v3, v12}, Llk/k;-><init>(ILay0/k;)V

    .line 450
    .line 451
    .line 452
    new-instance v0, Lt2/b;

    .line 453
    .line 454
    const v1, -0x54a42f85

    .line 455
    .line 456
    .line 457
    invoke-direct {v0, p0, v10, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 458
    .line 459
    .line 460
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 461
    .line 462
    .line 463
    return-object v11

    .line 464
    :pswitch_9
    check-cast p0, Lzc/h;

    .line 465
    .line 466
    check-cast v12, Lay0/k;

    .line 467
    .line 468
    check-cast p1, Lm1/f;

    .line 469
    .line 470
    invoke-static {p1, v8}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 471
    .line 472
    .line 473
    iget-object v0, p0, Lzc/h;->b:Ljp/z0;

    .line 474
    .line 475
    instance-of v1, v0, Lzc/l;

    .line 476
    .line 477
    const/4 v2, 0x2

    .line 478
    if-eqz v1, :cond_6

    .line 479
    .line 480
    sget-object v0, Lxj/f;->c:Lt2/b;

    .line 481
    .line 482
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 483
    .line 484
    .line 485
    goto :goto_3

    .line 486
    :cond_6
    instance-of v0, v0, Lzc/m;

    .line 487
    .line 488
    if-eqz v0, :cond_8

    .line 489
    .line 490
    sget-object v0, Lxj/f;->d:Lt2/b;

    .line 491
    .line 492
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 493
    .line 494
    .line 495
    iget-boolean v0, p0, Lzc/h;->c:Z

    .line 496
    .line 497
    if-eqz v0, :cond_7

    .line 498
    .line 499
    sget-object v0, Lxj/f;->e:Lt2/b;

    .line 500
    .line 501
    invoke-static {p1, v0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 502
    .line 503
    .line 504
    :cond_7
    iget-object v0, p0, Lzc/h;->a:Ljava/util/ArrayList;

    .line 505
    .line 506
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 507
    .line 508
    .line 509
    move-result v1

    .line 510
    new-instance v3, Lal/n;

    .line 511
    .line 512
    invoke-direct {v3, v0, v7}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 513
    .line 514
    .line 515
    new-instance v4, Lca0/g;

    .line 516
    .line 517
    invoke-direct {v4, v0, v12, v2}, Lca0/g;-><init>(Ljava/util/ArrayList;Lay0/k;I)V

    .line 518
    .line 519
    .line 520
    new-instance v0, Lt2/b;

    .line 521
    .line 522
    invoke-direct {v0, v4, v10, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 523
    .line 524
    .line 525
    invoke-virtual {p1, v1, v9, v3, v0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 526
    .line 527
    .line 528
    :goto_3
    iget-object p0, p0, Lzc/h;->b:Ljp/z0;

    .line 529
    .line 530
    new-instance v0, Lx40/j;

    .line 531
    .line 532
    invoke-direct {v0, v2, p0, v12}, Lx40/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 533
    .line 534
    .line 535
    new-instance p0, Lt2/b;

    .line 536
    .line 537
    const v1, 0xae514e1

    .line 538
    .line 539
    .line 540
    invoke-direct {p0, v0, v10, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 541
    .line 542
    .line 543
    invoke-static {p1, p0, v5}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 544
    .line 545
    .line 546
    return-object v11

    .line 547
    :cond_8
    new-instance p0, La8/r0;

    .line 548
    .line 549
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 550
    .line 551
    .line 552
    throw p0

    .line 553
    :pswitch_a
    check-cast p0, Lzg/f1;

    .line 554
    .line 555
    check-cast v12, Lay0/k;

    .line 556
    .line 557
    check-cast p1, Lhi/a;

    .line 558
    .line 559
    const-string v0, "$this$sdkViewModel"

    .line 560
    .line 561
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 562
    .line 563
    .line 564
    new-instance p1, Lxh/f;

    .line 565
    .line 566
    invoke-direct {p1, p0, v12}, Lxh/f;-><init>(Lzg/f1;Lay0/k;)V

    .line 567
    .line 568
    .line 569
    return-object p1

    .line 570
    nop

    .line 571
    :pswitch_data_0
    .packed-switch 0x0
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
