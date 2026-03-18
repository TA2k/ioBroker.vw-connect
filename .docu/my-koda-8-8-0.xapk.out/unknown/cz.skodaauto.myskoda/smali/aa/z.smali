.class public final synthetic Laa/z;
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
    iput p1, p0, Laa/z;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Laa/z;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Laa/z;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Laa/z;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Len0/g;

    .line 9
    .line 10
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Lua/a;

    .line 13
    .line 14
    check-cast p1, Landroidx/collection/f;

    .line 15
    .line 16
    const-string v1, "_tmpMap"

    .line 17
    .line 18
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p0, p1}, Len0/g;->c(Lua/a;Landroidx/collection/f;)V

    .line 22
    .line 23
    .line 24
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_0
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v0, Len0/g;

    .line 30
    .line 31
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, [Len0/i;

    .line 34
    .line 35
    check-cast p1, Lua/a;

    .line 36
    .line 37
    const-string v1, "_connection"

    .line 38
    .line 39
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v0, v0, Len0/g;->b:Las0/h;

    .line 43
    .line 44
    invoke-virtual {v0, p1, p0}, Llp/ef;->f(Lua/a;[Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    :pswitch_1
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v0, Len0/c;

    .line 53
    .line 54
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p0, Ljava/util/List;

    .line 57
    .line 58
    check-cast p1, Lua/a;

    .line 59
    .line 60
    const-string v1, "_connection"

    .line 61
    .line 62
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object v0, v0, Len0/c;->b:Las0/h;

    .line 66
    .line 67
    check-cast p0, Ljava/lang/Iterable;

    .line 68
    .line 69
    invoke-virtual {v0, p1, p0}, Llp/ef;->d(Lua/a;Ljava/lang/Iterable;)V

    .line 70
    .line 71
    .line 72
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 73
    .line 74
    return-object p0

    .line 75
    :pswitch_2
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v0, Lg4/g;

    .line 78
    .line 79
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Lc71/d;

    .line 82
    .line 83
    check-cast p1, Ljava/lang/Integer;

    .line 84
    .line 85
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    iget-object v0, v0, Lg4/g;->d:Ljava/util/List;

    .line 90
    .line 91
    if-eqz v0, :cond_1

    .line 92
    .line 93
    new-instance v1, Ljava/util/ArrayList;

    .line 94
    .line 95
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 100
    .line 101
    .line 102
    move-object v2, v0

    .line 103
    check-cast v2, Ljava/util/Collection;

    .line 104
    .line 105
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    const/4 v3, 0x0

    .line 110
    :goto_0
    if-ge v3, v2, :cond_2

    .line 111
    .line 112
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    check-cast v4, Lg4/e;

    .line 117
    .line 118
    iget-object v5, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 119
    .line 120
    iget v6, v4, Lg4/e;->c:I

    .line 121
    .line 122
    iget v7, v4, Lg4/e;->b:I

    .line 123
    .line 124
    instance-of v5, v5, Lg4/i0;

    .line 125
    .line 126
    if-eqz v5, :cond_0

    .line 127
    .line 128
    invoke-static {p1, p1, v7, v6}, Lg4/h;->b(IIII)Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-eqz v5, :cond_0

    .line 133
    .line 134
    new-instance v5, Lg4/e;

    .line 135
    .line 136
    iget-object v8, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 137
    .line 138
    const-string v9, "null cannot be cast to non-null type androidx.compose.ui.text.StringAnnotation"

    .line 139
    .line 140
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    check-cast v8, Lg4/i0;

    .line 144
    .line 145
    iget-object v8, v8, Lg4/i0;->a:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v4, v4, Lg4/e;->d:Ljava/lang/String;

    .line 148
    .line 149
    invoke-direct {v5, v8, v7, v6, v4}, Lg4/e;-><init>(Ljava/lang/Object;IILjava/lang/String;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    :cond_0
    add-int/lit8 v3, v3, 0x1

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_1
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 159
    .line 160
    :cond_2
    move-object p1, v1

    .line 161
    check-cast p1, Ljava/util/Collection;

    .line 162
    .line 163
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 164
    .line 165
    .line 166
    move-result p1

    .line 167
    if-nez p1, :cond_3

    .line 168
    .line 169
    invoke-static {v1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    check-cast p1, Lg4/e;

    .line 174
    .line 175
    iget-object p1, p1, Lg4/e;->d:Ljava/lang/String;

    .line 176
    .line 177
    invoke-interface {p0, p1}, Lc71/d;->a(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_3
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v0, Le51/e;

    .line 186
    .line 187
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast p0, Ljava/lang/String;

    .line 190
    .line 191
    check-cast p1, Lkw0/c;

    .line 192
    .line 193
    const-string v1, "$this$catRequest"

    .line 194
    .line 195
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    sget-object v1, Low0/v;->f:Low0/v;

    .line 199
    .line 200
    invoke-static {v1}, Ljp/m1;->k(Ljava/lang/Object;)Ljava/util/Set;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    invoke-static {p1, v1}, Lkp/i7;->a(Lkw0/c;Ljava/util/Set;)V

    .line 205
    .line 206
    .line 207
    sget-object v1, Low0/s;->b:Low0/s;

    .line 208
    .line 209
    invoke-virtual {p1, v1}, Lkw0/c;->b(Low0/s;)V

    .line 210
    .line 211
    .line 212
    iget-object v0, v0, Le51/e;->b:Ly41/g;

    .line 213
    .line 214
    iget-object v0, v0, Ly41/g;->a:Ljava/lang/String;

    .line 215
    .line 216
    new-instance v1, Ljava/lang/StringBuilder;

    .line 217
    .line 218
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 222
    .line 223
    .line 224
    const-string v0, "/user/v1/mobiledevicekeys/"

    .line 225
    .line 226
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 227
    .line 228
    .line 229
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 230
    .line 231
    .line 232
    const-string p0, "/pairing"

    .line 233
    .line 234
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 235
    .line 236
    .line 237
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    invoke-static {p1, p0}, Lkw0/d;->a(Lkw0/c;Ljava/lang/String;)V

    .line 242
    .line 243
    .line 244
    sget-object p0, Low0/b;->a:Low0/e;

    .line 245
    .line 246
    invoke-static {p1, p0}, Ljp/pc;->d(Lkw0/c;Low0/e;)V

    .line 247
    .line 248
    .line 249
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    return-object p0

    .line 252
    :pswitch_4
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v0, Li1/l;

    .line 255
    .line 256
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 257
    .line 258
    check-cast p0, Li1/k;

    .line 259
    .line 260
    check-cast p1, Ljava/lang/Throwable;

    .line 261
    .line 262
    invoke-virtual {v0, p0}, Li1/l;->b(Li1/k;)V

    .line 263
    .line 264
    .line 265
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 266
    .line 267
    return-object p0

    .line 268
    :pswitch_5
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast v0, Le3/d0;

    .line 271
    .line 272
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 273
    .line 274
    move-object v3, p0

    .line 275
    check-cast v3, Le3/p;

    .line 276
    .line 277
    move-object v1, p1

    .line 278
    check-cast v1, Lv3/j0;

    .line 279
    .line 280
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 281
    .line 282
    .line 283
    iget-object v2, v0, Le3/d0;->a:Le3/i;

    .line 284
    .line 285
    const/4 v5, 0x0

    .line 286
    const/16 v6, 0x3c

    .line 287
    .line 288
    const/4 v4, 0x0

    .line 289
    invoke-static/range {v1 .. v6}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 290
    .line 291
    .line 292
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 293
    .line 294
    return-object p0

    .line 295
    :pswitch_6
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 296
    .line 297
    move-object v2, v0

    .line 298
    check-cast v2, Le3/i;

    .line 299
    .line 300
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 301
    .line 302
    move-object v3, p0

    .line 303
    check-cast v3, Le3/p;

    .line 304
    .line 305
    move-object v1, p1

    .line 306
    check-cast v1, Lv3/j0;

    .line 307
    .line 308
    invoke-virtual {v1}, Lv3/j0;->b()V

    .line 309
    .line 310
    .line 311
    const/4 v5, 0x0

    .line 312
    const/16 v6, 0x3c

    .line 313
    .line 314
    const/4 v4, 0x0

    .line 315
    invoke-static/range {v1 .. v6}, Lg3/d;->q0(Lg3/d;Le3/i;Le3/p;FLg3/h;I)V

    .line 316
    .line 317
    .line 318
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 319
    .line 320
    return-object p0

    .line 321
    :pswitch_7
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v0, Lay0/k;

    .line 324
    .line 325
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast p0, Lrh/d;

    .line 328
    .line 329
    check-cast p1, Ljava/lang/String;

    .line 330
    .line 331
    const-string v1, "it"

    .line 332
    .line 333
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 334
    .line 335
    .line 336
    new-instance v1, Lrh/n;

    .line 337
    .line 338
    iget-object p0, p0, Lrh/d;->a:Ljava/lang/String;

    .line 339
    .line 340
    invoke-direct {v1, p0, p1}, Lrh/n;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    invoke-interface {v0, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 347
    .line 348
    return-object p0

    .line 349
    :pswitch_8
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v0, Ljava/lang/String;

    .line 352
    .line 353
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast p0, Llc/l;

    .line 356
    .line 357
    check-cast p1, Lm1/f;

    .line 358
    .line 359
    const-string v1, "$this$LazyColumn"

    .line 360
    .line 361
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    sget-object v1, Ldk/b;->a:Lt2/b;

    .line 365
    .line 366
    const/4 v2, 0x3

    .line 367
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 368
    .line 369
    .line 370
    new-instance v1, Ldk/f;

    .line 371
    .line 372
    const/4 v3, 0x0

    .line 373
    invoke-direct {v1, p0, v0, v3}, Ldk/f;-><init>(Llc/l;Ljava/lang/String;I)V

    .line 374
    .line 375
    .line 376
    new-instance v3, Lt2/b;

    .line 377
    .line 378
    const/4 v4, 0x1

    .line 379
    const v5, -0x7d59753

    .line 380
    .line 381
    .line 382
    invoke-direct {v3, v1, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 383
    .line 384
    .line 385
    invoke-static {p1, v3, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 386
    .line 387
    .line 388
    iget-boolean v1, p0, Llc/l;->c:Z

    .line 389
    .line 390
    if-eqz v1, :cond_4

    .line 391
    .line 392
    sget-object v1, Ldk/b;->b:Lt2/b;

    .line 393
    .line 394
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 395
    .line 396
    .line 397
    new-instance v1, Ldk/f;

    .line 398
    .line 399
    const/4 v3, 0x2

    .line 400
    invoke-direct {v1, p0, v0, v3}, Ldk/f;-><init>(Llc/l;Ljava/lang/String;I)V

    .line 401
    .line 402
    .line 403
    new-instance v3, Lt2/b;

    .line 404
    .line 405
    const v5, -0x3b6f8fe5

    .line 406
    .line 407
    .line 408
    invoke-direct {v3, v1, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 409
    .line 410
    .line 411
    invoke-static {p1, v3, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 412
    .line 413
    .line 414
    :cond_4
    new-instance v1, Ldk/f;

    .line 415
    .line 416
    const/4 v3, 0x1

    .line 417
    invoke-direct {v1, p0, v0, v3}, Ldk/f;-><init>(Llc/l;Ljava/lang/String;I)V

    .line 418
    .line 419
    .line 420
    new-instance v3, Lt2/b;

    .line 421
    .line 422
    const v5, -0x1d51c512

    .line 423
    .line 424
    .line 425
    invoke-direct {v3, v1, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 426
    .line 427
    .line 428
    invoke-static {p1, v3, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 429
    .line 430
    .line 431
    iget-boolean v1, p0, Llc/l;->f:Z

    .line 432
    .line 433
    if-eqz v1, :cond_5

    .line 434
    .line 435
    sget-object v1, Ldk/b;->c:Lt2/b;

    .line 436
    .line 437
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 438
    .line 439
    .line 440
    new-instance v1, Ldk/f;

    .line 441
    .line 442
    const/4 v3, 0x4

    .line 443
    invoke-direct {v1, p0, v0, v3}, Ldk/f;-><init>(Llc/l;Ljava/lang/String;I)V

    .line 444
    .line 445
    .line 446
    new-instance v3, Lt2/b;

    .line 447
    .line 448
    const v5, -0x69ef5263

    .line 449
    .line 450
    .line 451
    invoke-direct {v3, v1, v4, v5}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 452
    .line 453
    .line 454
    invoke-static {p1, v3, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 455
    .line 456
    .line 457
    :cond_5
    iget-boolean v1, p0, Llc/l;->h:Z

    .line 458
    .line 459
    if-eqz v1, :cond_6

    .line 460
    .line 461
    sget-object v1, Ldk/b;->d:Lt2/b;

    .line 462
    .line 463
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 464
    .line 465
    .line 466
    new-instance v1, Ldk/f;

    .line 467
    .line 468
    const/4 v3, 0x3

    .line 469
    invoke-direct {v1, p0, v0, v3}, Ldk/f;-><init>(Llc/l;Ljava/lang/String;I)V

    .line 470
    .line 471
    .line 472
    new-instance p0, Lt2/b;

    .line 473
    .line 474
    const v0, 0x47d5fb89

    .line 475
    .line 476
    .line 477
    invoke-direct {p0, v1, v4, v0}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 478
    .line 479
    .line 480
    invoke-static {p1, p0, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 481
    .line 482
    .line 483
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 484
    .line 485
    return-object p0

    .line 486
    :pswitch_9
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v0, Lc90/e0;

    .line 489
    .line 490
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 491
    .line 492
    check-cast p0, Lay0/k;

    .line 493
    .line 494
    check-cast p1, Lm1/f;

    .line 495
    .line 496
    const-string v1, "$this$LazyColumn"

    .line 497
    .line 498
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 499
    .line 500
    .line 501
    iget-object v1, v0, Lc90/e0;->c:Ljava/util/List;

    .line 502
    .line 503
    check-cast v1, Ljava/lang/Iterable;

    .line 504
    .line 505
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 506
    .line 507
    .line 508
    move-result-object v1

    .line 509
    const/4 v2, 0x0

    .line 510
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 511
    .line 512
    .line 513
    move-result v3

    .line 514
    if-eqz v3, :cond_8

    .line 515
    .line 516
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    move-result-object v3

    .line 520
    add-int/lit8 v4, v2, 0x1

    .line 521
    .line 522
    if-ltz v2, :cond_7

    .line 523
    .line 524
    check-cast v3, Lc90/a;

    .line 525
    .line 526
    new-instance v5, Ld90/k;

    .line 527
    .line 528
    invoke-direct {v5, v2, v3, p0, v0}, Ld90/k;-><init>(ILc90/a;Lay0/k;Lc90/e0;)V

    .line 529
    .line 530
    .line 531
    new-instance v2, Lt2/b;

    .line 532
    .line 533
    const/4 v3, 0x1

    .line 534
    const v6, 0x1e8c0d75

    .line 535
    .line 536
    .line 537
    invoke-direct {v2, v5, v3, v6}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 538
    .line 539
    .line 540
    const/4 v3, 0x3

    .line 541
    invoke-static {p1, v2, v3}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 542
    .line 543
    .line 544
    move v2, v4

    .line 545
    goto :goto_1

    .line 546
    :cond_7
    invoke-static {}, Ljp/k1;->r()V

    .line 547
    .line 548
    .line 549
    const/4 p0, 0x0

    .line 550
    throw p0

    .line 551
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 552
    .line 553
    return-object p0

    .line 554
    :pswitch_a
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 555
    .line 556
    check-cast v0, Lay0/n;

    .line 557
    .line 558
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 559
    .line 560
    check-cast p0, Lc00/m1;

    .line 561
    .line 562
    check-cast p1, Ljava/lang/Boolean;

    .line 563
    .line 564
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 565
    .line 566
    .line 567
    iget-wide v1, p0, Lc00/m1;->a:J

    .line 568
    .line 569
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 570
    .line 571
    .line 572
    move-result-object p0

    .line 573
    invoke-interface {v0, p0, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 574
    .line 575
    .line 576
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 577
    .line 578
    return-object p0

    .line 579
    :pswitch_b
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 580
    .line 581
    check-cast v0, Lcp0/t;

    .line 582
    .line 583
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 584
    .line 585
    check-cast p0, Lcp0/u;

    .line 586
    .line 587
    check-cast p1, Lua/a;

    .line 588
    .line 589
    const-string v1, "_connection"

    .line 590
    .line 591
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 592
    .line 593
    .line 594
    iget-object v0, v0, Lcp0/t;->b:Las0/h;

    .line 595
    .line 596
    invoke-virtual {v0, p1, p0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 597
    .line 598
    .line 599
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 600
    .line 601
    return-object p0

    .line 602
    :pswitch_c
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 603
    .line 604
    check-cast v0, Lcp0/b;

    .line 605
    .line 606
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast p0, Lcp0/c;

    .line 609
    .line 610
    check-cast p1, Lua/a;

    .line 611
    .line 612
    const-string v1, "_connection"

    .line 613
    .line 614
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 615
    .line 616
    .line 617
    iget-object v0, v0, Lcp0/b;->b:Las0/h;

    .line 618
    .line 619
    invoke-virtual {v0, p1, p0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 620
    .line 621
    .line 622
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 623
    .line 624
    return-object p0

    .line 625
    :pswitch_d
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 626
    .line 627
    check-cast v0, Lay0/n;

    .line 628
    .line 629
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast p0, Lbo0/h;

    .line 632
    .line 633
    check-cast p1, Ljava/lang/Boolean;

    .line 634
    .line 635
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 636
    .line 637
    .line 638
    iget-wide v1, p0, Lbo0/h;->a:J

    .line 639
    .line 640
    invoke-static {v1, v2}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 641
    .line 642
    .line 643
    move-result-object p1

    .line 644
    iget-boolean p0, p0, Lbo0/h;->e:Z

    .line 645
    .line 646
    xor-int/lit8 p0, p0, 0x1

    .line 647
    .line 648
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 649
    .line 650
    .line 651
    move-result-object p0

    .line 652
    invoke-interface {v0, p1, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 656
    .line 657
    return-object p0

    .line 658
    :pswitch_e
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 659
    .line 660
    check-cast v0, Ly1/i;

    .line 661
    .line 662
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 663
    .line 664
    check-cast p0, Lzg/h;

    .line 665
    .line 666
    check-cast p1, Lhi/a;

    .line 667
    .line 668
    const-string v1, "$this$sdkViewModel"

    .line 669
    .line 670
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 671
    .line 672
    .line 673
    const-class v1, Ldh/u;

    .line 674
    .line 675
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 676
    .line 677
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 678
    .line 679
    .line 680
    move-result-object v1

    .line 681
    check-cast p1, Lii/a;

    .line 682
    .line 683
    invoke-virtual {p1, v1}, Lii/a;->b(Lhy0/d;)Ljava/lang/Object;

    .line 684
    .line 685
    .line 686
    move-result-object p1

    .line 687
    check-cast p1, Ldh/u;

    .line 688
    .line 689
    new-instance v1, Lci/e;

    .line 690
    .line 691
    new-instance v2, La90/c;

    .line 692
    .line 693
    const/16 v3, 0x13

    .line 694
    .line 695
    const/4 v4, 0x0

    .line 696
    invoke-direct {v2, p1, v4, v3}, La90/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 697
    .line 698
    .line 699
    new-instance v3, Lci/a;

    .line 700
    .line 701
    const/4 v5, 0x0

    .line 702
    invoke-direct {v3, p1, v4, v5}, Lci/a;-><init>(Ldh/u;Lkotlin/coroutines/Continuation;I)V

    .line 703
    .line 704
    .line 705
    invoke-direct {v1, v0, p0, v2, v3}, Lci/e;-><init>(Ly1/i;Lzg/h;La90/c;Lci/a;)V

    .line 706
    .line 707
    .line 708
    return-object v1

    .line 709
    :pswitch_f
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 710
    .line 711
    check-cast v0, Lba0/u;

    .line 712
    .line 713
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 714
    .line 715
    check-cast p0, Lay0/k;

    .line 716
    .line 717
    check-cast p1, Lm1/f;

    .line 718
    .line 719
    const-string v1, "$this$LazyColumn"

    .line 720
    .line 721
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 722
    .line 723
    .line 724
    iget-object v1, v0, Lba0/u;->f:Ljava/util/List;

    .line 725
    .line 726
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 727
    .line 728
    .line 729
    move-result v2

    .line 730
    new-instance v3, Lak/p;

    .line 731
    .line 732
    const/4 v4, 0x5

    .line 733
    invoke-direct {v3, v1, v4}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 734
    .line 735
    .line 736
    new-instance v4, Lal/o;

    .line 737
    .line 738
    const/4 v5, 0x1

    .line 739
    invoke-direct {v4, v1, p0, v0, v5}, Lal/o;-><init>(Ljava/util/List;Lay0/k;Ljava/lang/Object;I)V

    .line 740
    .line 741
    .line 742
    new-instance p0, Lt2/b;

    .line 743
    .line 744
    const/4 v0, 0x1

    .line 745
    const v1, 0x799532c4

    .line 746
    .line 747
    .line 748
    invoke-direct {p0, v4, v0, v1}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 749
    .line 750
    .line 751
    const/4 v0, 0x0

    .line 752
    invoke-virtual {p1, v2, v0, v3, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 753
    .line 754
    .line 755
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 756
    .line 757
    return-object p0

    .line 758
    :pswitch_10
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 759
    .line 760
    check-cast v0, Lba0/k;

    .line 761
    .line 762
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 763
    .line 764
    check-cast p0, Lay0/k;

    .line 765
    .line 766
    check-cast p1, Lm1/f;

    .line 767
    .line 768
    const-string v1, "$this$LazyColumn"

    .line 769
    .line 770
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 771
    .line 772
    .line 773
    iget-object v0, v0, Lba0/k;->d:Ljava/util/ArrayList;

    .line 774
    .line 775
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 776
    .line 777
    .line 778
    move-result v1

    .line 779
    new-instance v2, Lal/n;

    .line 780
    .line 781
    const/4 v3, 0x1

    .line 782
    invoke-direct {v2, v0, v3}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 783
    .line 784
    .line 785
    new-instance v3, Lca0/g;

    .line 786
    .line 787
    const/4 v4, 0x0

    .line 788
    invoke-direct {v3, v0, p0, v4}, Lca0/g;-><init>(Ljava/util/ArrayList;Lay0/k;I)V

    .line 789
    .line 790
    .line 791
    new-instance p0, Lt2/b;

    .line 792
    .line 793
    const/4 v0, 0x1

    .line 794
    const v4, 0x799532c4

    .line 795
    .line 796
    .line 797
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 798
    .line 799
    .line 800
    const/4 v0, 0x0

    .line 801
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 802
    .line 803
    .line 804
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 805
    .line 806
    return-object p0

    .line 807
    :pswitch_11
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 808
    .line 809
    check-cast v0, Lc1/w1;

    .line 810
    .line 811
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 812
    .line 813
    check-cast p0, Lc1/q1;

    .line 814
    .line 815
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 816
    .line 817
    new-instance p1, Laa/t;

    .line 818
    .line 819
    const/4 v1, 0x4

    .line 820
    invoke-direct {p1, v1, v0, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 821
    .line 822
    .line 823
    return-object p1

    .line 824
    :pswitch_12
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v0, Lc1/w1;

    .line 827
    .line 828
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 829
    .line 830
    check-cast p0, Lc1/w1;

    .line 831
    .line 832
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 833
    .line 834
    iget-object p1, v0, Lc1/w1;->j:Lv2/o;

    .line 835
    .line 836
    invoke-virtual {p1, p0}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 837
    .line 838
    .line 839
    new-instance p1, Laa/t;

    .line 840
    .line 841
    const/4 v1, 0x3

    .line 842
    invoke-direct {p1, v1, v0, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 843
    .line 844
    .line 845
    return-object p1

    .line 846
    :pswitch_13
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 847
    .line 848
    check-cast v0, Lc1/w1;

    .line 849
    .line 850
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 851
    .line 852
    check-cast p0, Lc1/t1;

    .line 853
    .line 854
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 855
    .line 856
    iget-object p1, v0, Lc1/w1;->i:Lv2/o;

    .line 857
    .line 858
    invoke-virtual {p1, p0}, Lv2/o;->add(Ljava/lang/Object;)Z

    .line 859
    .line 860
    .line 861
    new-instance p1, Laa/t;

    .line 862
    .line 863
    const/4 v1, 0x5

    .line 864
    invoke-direct {p1, v1, v0, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 865
    .line 866
    .line 867
    return-object p1

    .line 868
    :pswitch_14
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 869
    .line 870
    check-cast v0, Lvy0/b0;

    .line 871
    .line 872
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 873
    .line 874
    check-cast p0, Lc1/w1;

    .line 875
    .line 876
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 877
    .line 878
    sget-object p1, Lvy0/c0;->g:Lvy0/c0;

    .line 879
    .line 880
    new-instance v1, Laa/j0;

    .line 881
    .line 882
    const/4 v2, 0x0

    .line 883
    invoke-direct {v1, p0, v2}, Laa/j0;-><init>(Lc1/w1;Lkotlin/coroutines/Continuation;)V

    .line 884
    .line 885
    .line 886
    const/4 p0, 0x1

    .line 887
    invoke-static {v0, v2, p1, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 888
    .line 889
    .line 890
    new-instance p0, Lc1/v1;

    .line 891
    .line 892
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 893
    .line 894
    .line 895
    return-object p0

    .line 896
    :pswitch_15
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 897
    .line 898
    check-cast v0, Lc1/i0;

    .line 899
    .line 900
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 901
    .line 902
    check-cast p0, Lc1/g0;

    .line 903
    .line 904
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 905
    .line 906
    iget-object p1, v0, Lc1/i0;->a:Ln2/b;

    .line 907
    .line 908
    invoke-virtual {p1, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 909
    .line 910
    .line 911
    iget-object p1, v0, Lc1/i0;->b:Ll2/j1;

    .line 912
    .line 913
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 914
    .line 915
    invoke-virtual {p1, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 916
    .line 917
    .line 918
    new-instance p1, Laa/t;

    .line 919
    .line 920
    const/4 v1, 0x2

    .line 921
    invoke-direct {p1, v1, v0, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 922
    .line 923
    .line 924
    return-object p1

    .line 925
    :pswitch_16
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 926
    .line 927
    check-cast v0, Las0/i;

    .line 928
    .line 929
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 930
    .line 931
    check-cast p0, Las0/j;

    .line 932
    .line 933
    check-cast p1, Lua/a;

    .line 934
    .line 935
    const-string v1, "_connection"

    .line 936
    .line 937
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 938
    .line 939
    .line 940
    iget-object v0, v0, Las0/i;->b:Las0/h;

    .line 941
    .line 942
    invoke-virtual {v0, p1, p0}, Llp/ef;->e(Lua/a;Ljava/lang/Object;)V

    .line 943
    .line 944
    .line 945
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 946
    .line 947
    return-object p0

    .line 948
    :pswitch_17
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 949
    .line 950
    check-cast v0, Ljava/util/ArrayList;

    .line 951
    .line 952
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 953
    .line 954
    check-cast p0, Lay0/k;

    .line 955
    .line 956
    check-cast p1, Lm1/f;

    .line 957
    .line 958
    const-string v1, "$this$LazyColumn"

    .line 959
    .line 960
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 961
    .line 962
    .line 963
    sget-object v1, Lal/a;->g:Lt2/b;

    .line 964
    .line 965
    const/4 v2, 0x3

    .line 966
    invoke-static {p1, v1, v2}, Lm1/f;->o(Lm1/f;Lay0/o;I)V

    .line 967
    .line 968
    .line 969
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 970
    .line 971
    .line 972
    move-result v1

    .line 973
    new-instance v2, Lal/n;

    .line 974
    .line 975
    const/4 v3, 0x0

    .line 976
    invoke-direct {v2, v0, v3}, Lal/n;-><init>(Ljava/util/ArrayList;I)V

    .line 977
    .line 978
    .line 979
    new-instance v3, Lal/o;

    .line 980
    .line 981
    const/4 v4, 0x0

    .line 982
    invoke-direct {v3, v0, p0, v0, v4}, Lal/o;-><init>(Ljava/util/List;Lay0/k;Ljava/lang/Object;I)V

    .line 983
    .line 984
    .line 985
    new-instance p0, Lt2/b;

    .line 986
    .line 987
    const/4 v0, 0x1

    .line 988
    const v4, 0x799532c4

    .line 989
    .line 990
    .line 991
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 992
    .line 993
    .line 994
    const/4 v0, 0x0

    .line 995
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 996
    .line 997
    .line 998
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 999
    .line 1000
    return-object p0

    .line 1001
    :pswitch_18
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 1002
    .line 1003
    check-cast v0, Lnd/j;

    .line 1004
    .line 1005
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 1006
    .line 1007
    check-cast p0, Lay0/k;

    .line 1008
    .line 1009
    check-cast p1, Lm1/f;

    .line 1010
    .line 1011
    const-string v1, "$this$LazyColumn"

    .line 1012
    .line 1013
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1014
    .line 1015
    .line 1016
    iget-object v0, v0, Lnd/j;->a:Ljava/util/List;

    .line 1017
    .line 1018
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 1019
    .line 1020
    .line 1021
    move-result v1

    .line 1022
    new-instance v2, Lak/p;

    .line 1023
    .line 1024
    const/4 v3, 0x0

    .line 1025
    invoke-direct {v2, v0, v3}, Lak/p;-><init>(Ljava/util/List;I)V

    .line 1026
    .line 1027
    .line 1028
    new-instance v3, Lak/q;

    .line 1029
    .line 1030
    const/4 v4, 0x0

    .line 1031
    invoke-direct {v3, v0, p0, v4}, Lak/q;-><init>(Ljava/util/List;Lay0/k;I)V

    .line 1032
    .line 1033
    .line 1034
    new-instance p0, Lt2/b;

    .line 1035
    .line 1036
    const/4 v0, 0x1

    .line 1037
    const v4, 0x799532c4

    .line 1038
    .line 1039
    .line 1040
    invoke-direct {p0, v3, v0, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 1041
    .line 1042
    .line 1043
    const/4 v0, 0x0

    .line 1044
    invoke-virtual {p1, v1, v0, v2, p0}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 1045
    .line 1046
    .line 1047
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1048
    .line 1049
    return-object p0

    .line 1050
    :pswitch_19
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 1051
    .line 1052
    check-cast v0, Ljava/util/List;

    .line 1053
    .line 1054
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 1055
    .line 1056
    check-cast p0, Lle/a;

    .line 1057
    .line 1058
    check-cast p1, Lhi/a;

    .line 1059
    .line 1060
    const-string v1, "$this$sdkViewModel"

    .line 1061
    .line 1062
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1063
    .line 1064
    .line 1065
    new-instance p1, Laf/e;

    .line 1066
    .line 1067
    invoke-direct {p1, v0, p0}, Laf/e;-><init>(Ljava/util/List;Lle/a;)V

    .line 1068
    .line 1069
    .line 1070
    return-object p1

    .line 1071
    :pswitch_1a
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 1072
    .line 1073
    check-cast v0, Lac0/w;

    .line 1074
    .line 1075
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 1076
    .line 1077
    check-cast p0, Ljava/lang/String;

    .line 1078
    .line 1079
    check-cast p1, Ljava/lang/Throwable;

    .line 1080
    .line 1081
    new-instance p1, Lac0/a;

    .line 1082
    .line 1083
    const/4 v1, 0x2

    .line 1084
    invoke-direct {p1, p0, v1}, Lac0/a;-><init>(Ljava/lang/String;I)V

    .line 1085
    .line 1086
    .line 1087
    const/4 v1, 0x0

    .line 1088
    invoke-static {v1, v0, p1}, Llp/nd;->i(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 1089
    .line 1090
    .line 1091
    iget-object p1, v0, Lac0/w;->l:Ljava/util/concurrent/ConcurrentHashMap;

    .line 1092
    .line 1093
    new-instance v0, Ldc0/b;

    .line 1094
    .line 1095
    invoke-direct {v0, p0}, Ldc0/b;-><init>(Ljava/lang/String;)V

    .line 1096
    .line 1097
    .line 1098
    invoke-virtual {p1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1099
    .line 1100
    .line 1101
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 1102
    .line 1103
    return-object p0

    .line 1104
    :pswitch_1b
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 1105
    .line 1106
    check-cast v0, Ll2/t2;

    .line 1107
    .line 1108
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 1109
    .line 1110
    check-cast p0, Laa/i;

    .line 1111
    .line 1112
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 1113
    .line 1114
    new-instance p1, Laa/t;

    .line 1115
    .line 1116
    const/4 v1, 0x1

    .line 1117
    invoke-direct {p1, v1, v0, p0}, Laa/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 1118
    .line 1119
    .line 1120
    return-object p1

    .line 1121
    :pswitch_1c
    iget-object v0, p0, Laa/z;->e:Ljava/lang/Object;

    .line 1122
    .line 1123
    check-cast v0, Lz9/y;

    .line 1124
    .line 1125
    iget-object p0, p0, Laa/z;->f:Ljava/lang/Object;

    .line 1126
    .line 1127
    check-cast p0, Landroidx/lifecycle/x;

    .line 1128
    .line 1129
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 1130
    .line 1131
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1132
    .line 1133
    .line 1134
    const-string p1, "owner"

    .line 1135
    .line 1136
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1137
    .line 1138
    .line 1139
    iget-object p1, v0, Lz9/y;->b:Lca/g;

    .line 1140
    .line 1141
    iget-object v0, p1, Lca/g;->r:Landroidx/lifecycle/m;

    .line 1142
    .line 1143
    iget-object v1, p1, Lca/g;->n:Landroidx/lifecycle/x;

    .line 1144
    .line 1145
    invoke-virtual {p0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 1146
    .line 1147
    .line 1148
    move-result v1

    .line 1149
    if-eqz v1, :cond_9

    .line 1150
    .line 1151
    goto :goto_2

    .line 1152
    :cond_9
    iget-object v1, p1, Lca/g;->n:Landroidx/lifecycle/x;

    .line 1153
    .line 1154
    if-eqz v1, :cond_a

    .line 1155
    .line 1156
    invoke-interface {v1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 1157
    .line 1158
    .line 1159
    move-result-object v1

    .line 1160
    if-eqz v1, :cond_a

    .line 1161
    .line 1162
    invoke-virtual {v1, v0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 1163
    .line 1164
    .line 1165
    :cond_a
    iput-object p0, p1, Lca/g;->n:Landroidx/lifecycle/x;

    .line 1166
    .line 1167
    invoke-interface {p0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 1168
    .line 1169
    .line 1170
    move-result-object p0

    .line 1171
    invoke-virtual {p0, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 1172
    .line 1173
    .line 1174
    :goto_2
    new-instance p0, Laa/m0;

    .line 1175
    .line 1176
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 1177
    .line 1178
    .line 1179
    return-object p0

    .line 1180
    nop

    .line 1181
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
