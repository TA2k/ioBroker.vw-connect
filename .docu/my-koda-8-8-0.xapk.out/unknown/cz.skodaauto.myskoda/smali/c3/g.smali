.class public final synthetic Lc3/g;
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
    iput p7, p0, Lc3/g;->d:I

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
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc3/g;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lbo0/k;

    .line 11
    .line 12
    iget-object v1, v0, Lbo0/k;->n:Ljava/util/List;

    .line 13
    .line 14
    const/4 v2, 0x3

    .line 15
    const/4 v3, 0x0

    .line 16
    const-string v4, "<this>"

    .line 17
    .line 18
    const/4 v5, 0x0

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    iget-object v6, v0, Lbo0/k;->o:Ljava/util/List;

    .line 22
    .line 23
    invoke-static {v1, v6}, Landroidx/glance/appwidget/protobuf/f1;->e(Ljava/util/List;Ljava/util/List;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    check-cast v1, Lbo0/i;

    .line 34
    .line 35
    iget-boolean v1, v1, Lbo0/i;->c:Z

    .line 36
    .line 37
    if-nez v1, :cond_0

    .line 38
    .line 39
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Lbo0/i;

    .line 44
    .line 45
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const/4 v4, 0x1

    .line 49
    invoke-static {v1, v3, v5, v4, v2}, Lbo0/i;->a(Lbo0/i;Ljava/util/List;ZZI)Lbo0/i;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 54
    .line 55
    .line 56
    goto :goto_0

    .line 57
    :cond_0
    new-instance v1, Lbo0/f;

    .line 58
    .line 59
    const/4 v6, 0x1

    .line 60
    invoke-direct {v1, v0, v6}, Lbo0/f;-><init>(Lbo0/k;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Lbo0/i;

    .line 71
    .line 72
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    invoke-static {v1, v3, v5, v5, v2}, Lbo0/i;->a(Lbo0/i;Ljava/util/List;ZZI)Lbo0/i;

    .line 76
    .line 77
    .line 78
    move-result-object v1

    .line 79
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 80
    .line 81
    .line 82
    iget-object v0, v0, Lbo0/k;->h:Ltr0/b;

    .line 83
    .line 84
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Lbo0/d;

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
    check-cast v2, Lbo0/c;

    .line 100
    .line 101
    const/4 v6, 0x0

    .line 102
    const/4 v7, 0x3

    .line 103
    const/4 v3, 0x0

    .line 104
    const/4 v4, 0x0

    .line 105
    const/4 v5, 0x0

    .line 106
    invoke-static/range {v2 .. v7}, Lbo0/c;->a(Lbo0/c;Ljava/time/LocalTime;Ljava/time/LocalTime;ZZI)Lbo0/c;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 111
    .line 112
    .line 113
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object v0

    .line 116
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v0, Lbo0/d;

    .line 119
    .line 120
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    move-object v2, v1

    .line 125
    check-cast v2, Lbo0/c;

    .line 126
    .line 127
    const/4 v6, 0x1

    .line 128
    const/4 v7, 0x7

    .line 129
    const/4 v3, 0x0

    .line 130
    const/4 v4, 0x0

    .line 131
    const/4 v5, 0x0

    .line 132
    invoke-static/range {v2 .. v7}, Lbo0/c;->a(Lbo0/c;Ljava/time/LocalTime;Ljava/time/LocalTime;ZZI)Lbo0/c;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 137
    .line 138
    .line 139
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object v0

    .line 142
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v0, Lbo0/d;

    .line 145
    .line 146
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    move-object v2, v1

    .line 151
    check-cast v2, Lbo0/c;

    .line 152
    .line 153
    const/4 v6, 0x0

    .line 154
    const/16 v7, 0xb

    .line 155
    .line 156
    const/4 v3, 0x0

    .line 157
    const/4 v4, 0x0

    .line 158
    const/4 v5, 0x1

    .line 159
    invoke-static/range {v2 .. v7}, Lbo0/c;->a(Lbo0/c;Ljava/time/LocalTime;Ljava/time/LocalTime;ZZI)Lbo0/c;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 164
    .line 165
    .line 166
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 167
    .line 168
    return-object v0

    .line 169
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Lbo0/d;

    .line 172
    .line 173
    iget-object v1, v0, Lbo0/d;->i:Lyn0/l;

    .line 174
    .line 175
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    check-cast v2, Lbo0/c;

    .line 180
    .line 181
    iget-object v3, v0, Lbo0/d;->k:Lao0/a;

    .line 182
    .line 183
    const-string v4, "chargingTime"

    .line 184
    .line 185
    const/4 v5, 0x0

    .line 186
    if-eqz v3, :cond_3

    .line 187
    .line 188
    iget-object v6, v2, Lbo0/c;->a:Ljava/time/LocalTime;

    .line 189
    .line 190
    iget-object v2, v2, Lbo0/c;->b:Ljava/time/LocalTime;

    .line 191
    .line 192
    const/4 v7, 0x3

    .line 193
    const/4 v8, 0x0

    .line 194
    invoke-static {v3, v8, v6, v2, v7}, Lao0/a;->a(Lao0/a;ZLjava/time/LocalTime;Ljava/time/LocalTime;I)Lao0/a;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    iget-object v3, v0, Lbo0/d;->k:Lao0/a;

    .line 199
    .line 200
    if-eqz v3, :cond_2

    .line 201
    .line 202
    invoke-virtual {v3, v2}, Lao0/a;->equals(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v3

    .line 206
    if-nez v3, :cond_1

    .line 207
    .line 208
    const/4 v3, 0x1

    .line 209
    const/16 v4, 0xd

    .line 210
    .line 211
    invoke-static {v2, v3, v5, v5, v4}, Lao0/a;->a(Lao0/a;ZLjava/time/LocalTime;Ljava/time/LocalTime;I)Lao0/a;

    .line 212
    .line 213
    .line 214
    move-result-object v2

    .line 215
    iget-object v1, v1, Lyn0/l;->a:Lyn0/a;

    .line 216
    .line 217
    check-cast v1, Lwn0/a;

    .line 218
    .line 219
    iget-object v1, v1, Lwn0/a;->g:Lyy0/q1;

    .line 220
    .line 221
    invoke-virtual {v1, v2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    goto :goto_1

    .line 225
    :cond_1
    iget-object v1, v1, Lyn0/l;->a:Lyn0/a;

    .line 226
    .line 227
    check-cast v1, Lwn0/a;

    .line 228
    .line 229
    iget-object v1, v1, Lwn0/a;->g:Lyy0/q1;

    .line 230
    .line 231
    invoke-virtual {v1, v5}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    :goto_1
    iget-object v0, v0, Lbo0/d;->j:Ltr0/b;

    .line 235
    .line 236
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    return-object v0

    .line 242
    :cond_2
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    throw v5

    .line 246
    :cond_3
    invoke-static {v4}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    throw v5

    .line 250
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Lbo0/b;

    .line 253
    .line 254
    iget-object v1, v0, Lbo0/b;->h:Lyn0/k;

    .line 255
    .line 256
    new-instance v2, Lqr0/l;

    .line 257
    .line 258
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 259
    .line 260
    .line 261
    move-result-object v3

    .line 262
    check-cast v3, Lbo0/a;

    .line 263
    .line 264
    iget v3, v3, Lbo0/a;->a:I

    .line 265
    .line 266
    invoke-direct {v2, v3}, Lqr0/l;-><init>(I)V

    .line 267
    .line 268
    .line 269
    iget-object v1, v1, Lyn0/k;->a:Lyn0/a;

    .line 270
    .line 271
    check-cast v1, Lwn0/a;

    .line 272
    .line 273
    iget-object v1, v1, Lwn0/a;->k:Lyy0/q1;

    .line 274
    .line 275
    invoke-virtual {v1, v2}, Lyy0/q1;->a(Ljava/lang/Object;)Z

    .line 276
    .line 277
    .line 278
    iget-object v0, v0, Lbo0/b;->i:Ltr0/b;

    .line 279
    .line 280
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 284
    .line 285
    return-object v0

    .line 286
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v0, Lbo0/b;

    .line 289
    .line 290
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    check-cast v1, Lbo0/a;

    .line 295
    .line 296
    iget v1, v1, Lbo0/a;->a:I

    .line 297
    .line 298
    add-int/lit8 v1, v1, -0xa

    .line 299
    .line 300
    sget-object v2, Lbo0/b;->j:Lgy0/j;

    .line 301
    .line 302
    invoke-static {v1, v2}, Lkp/r9;->f(ILgy0/g;)I

    .line 303
    .line 304
    .line 305
    move-result v1

    .line 306
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 307
    .line 308
    .line 309
    move-result-object v2

    .line 310
    check-cast v2, Lbo0/a;

    .line 311
    .line 312
    invoke-static {v2, v1}, Lbo0/a;->a(Lbo0/a;I)Lbo0/a;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 317
    .line 318
    .line 319
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 320
    .line 321
    return-object v0

    .line 322
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v0, Lbo0/b;

    .line 325
    .line 326
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 327
    .line 328
    .line 329
    move-result-object v1

    .line 330
    check-cast v1, Lbo0/a;

    .line 331
    .line 332
    iget v1, v1, Lbo0/a;->a:I

    .line 333
    .line 334
    add-int/lit8 v1, v1, 0xa

    .line 335
    .line 336
    sget-object v2, Lbo0/b;->j:Lgy0/j;

    .line 337
    .line 338
    invoke-static {v1, v2}, Lkp/r9;->f(ILgy0/g;)I

    .line 339
    .line 340
    .line 341
    move-result v1

    .line 342
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 343
    .line 344
    .line 345
    move-result-object v2

    .line 346
    check-cast v2, Lbo0/a;

    .line 347
    .line 348
    invoke-static {v2, v1}, Lbo0/a;->a(Lbo0/a;I)Lbo0/a;

    .line 349
    .line 350
    .line 351
    move-result-object v1

    .line 352
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 353
    .line 354
    .line 355
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 356
    .line 357
    return-object v0

    .line 358
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast v0, Lba0/v;

    .line 361
    .line 362
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 363
    .line 364
    .line 365
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    new-instance v2, Lba0/s;

    .line 370
    .line 371
    const/4 v3, 0x3

    .line 372
    const/4 v4, 0x0

    .line 373
    invoke-direct {v2, v0, v4, v3}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 374
    .line 375
    .line 376
    const/4 v0, 0x3

    .line 377
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 378
    .line 379
    .line 380
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 381
    .line 382
    return-object v0

    .line 383
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast v0, Lba0/v;

    .line 386
    .line 387
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 388
    .line 389
    .line 390
    new-instance v1, La71/u;

    .line 391
    .line 392
    const/4 v2, 0x6

    .line 393
    invoke-direct {v1, v0, v2}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 394
    .line 395
    .line 396
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    move-object v2, v1

    .line 404
    check-cast v2, Lba0/u;

    .line 405
    .line 406
    const/4 v9, 0x1

    .line 407
    const/16 v10, 0x27

    .line 408
    .line 409
    const/4 v3, 0x0

    .line 410
    const/4 v4, 0x0

    .line 411
    const/4 v5, 0x0

    .line 412
    const/4 v6, 0x0

    .line 413
    const/4 v7, 0x0

    .line 414
    const/4 v8, 0x0

    .line 415
    invoke-static/range {v2 .. v10}, Lba0/u;->a(Lba0/u;Llf0/i;Ler0/g;Laa0/c;ZLql0/g;Ljava/util/List;ZI)Lba0/u;

    .line 416
    .line 417
    .line 418
    move-result-object v1

    .line 419
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 420
    .line 421
    .line 422
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 423
    .line 424
    return-object v0

    .line 425
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 426
    .line 427
    check-cast v0, Lba0/v;

    .line 428
    .line 429
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 430
    .line 431
    .line 432
    move-result-object v1

    .line 433
    check-cast v1, Lba0/u;

    .line 434
    .line 435
    iget-object v1, v1, Lba0/u;->c:Laa0/c;

    .line 436
    .line 437
    if-nez v1, :cond_4

    .line 438
    .line 439
    iget-object v0, v0, Lba0/v;->j:Lz90/u;

    .line 440
    .line 441
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    :cond_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 445
    .line 446
    return-object v0

    .line 447
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast v0, Lba0/v;

    .line 450
    .line 451
    iget-object v0, v0, Lba0/v;->i:Ltr0/b;

    .line 452
    .line 453
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 457
    .line 458
    return-object v0

    .line 459
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast v0, Lba0/q;

    .line 462
    .line 463
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 464
    .line 465
    .line 466
    new-instance v1, Lba0/i;

    .line 467
    .line 468
    const/4 v2, 0x0

    .line 469
    invoke-direct {v1, v0, v2}, Lba0/i;-><init>(Lba0/q;I)V

    .line 470
    .line 471
    .line 472
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 473
    .line 474
    .line 475
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 476
    .line 477
    .line 478
    move-result-object v1

    .line 479
    move-object v2, v1

    .line 480
    check-cast v2, Lba0/l;

    .line 481
    .line 482
    const/4 v8, 0x0

    .line 483
    const/16 v9, 0x3d

    .line 484
    .line 485
    const/4 v3, 0x0

    .line 486
    const/4 v4, 0x0

    .line 487
    const/4 v5, 0x0

    .line 488
    const/4 v6, 0x0

    .line 489
    const/4 v7, 0x0

    .line 490
    invoke-static/range {v2 .. v9}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 491
    .line 492
    .line 493
    move-result-object v1

    .line 494
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 495
    .line 496
    .line 497
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 498
    .line 499
    return-object v0

    .line 500
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast v0, Lba0/q;

    .line 503
    .line 504
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    new-instance v1, Lba0/i;

    .line 508
    .line 509
    const/4 v2, 0x2

    .line 510
    invoke-direct {v1, v0, v2}, Lba0/i;-><init>(Lba0/q;I)V

    .line 511
    .line 512
    .line 513
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 514
    .line 515
    .line 516
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 517
    .line 518
    .line 519
    move-result-object v1

    .line 520
    move-object v2, v1

    .line 521
    check-cast v2, Lba0/l;

    .line 522
    .line 523
    const/4 v8, 0x0

    .line 524
    const/16 v9, 0x37

    .line 525
    .line 526
    const/4 v3, 0x0

    .line 527
    const/4 v4, 0x0

    .line 528
    const/4 v5, 0x0

    .line 529
    const/4 v6, 0x0

    .line 530
    const/4 v7, 0x0

    .line 531
    invoke-static/range {v2 .. v9}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 532
    .line 533
    .line 534
    move-result-object v1

    .line 535
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 536
    .line 537
    .line 538
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 539
    .line 540
    return-object v0

    .line 541
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 542
    .line 543
    check-cast v0, Lba0/q;

    .line 544
    .line 545
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 546
    .line 547
    .line 548
    move-result-object v1

    .line 549
    move-object v2, v1

    .line 550
    check-cast v2, Lba0/l;

    .line 551
    .line 552
    const/4 v8, 0x0

    .line 553
    const/16 v9, 0x37

    .line 554
    .line 555
    const/4 v3, 0x0

    .line 556
    const/4 v4, 0x0

    .line 557
    const/4 v5, 0x0

    .line 558
    const/4 v6, 0x1

    .line 559
    const/4 v7, 0x0

    .line 560
    invoke-static/range {v2 .. v9}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 561
    .line 562
    .line 563
    move-result-object v1

    .line 564
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 565
    .line 566
    .line 567
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 568
    .line 569
    return-object v0

    .line 570
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 571
    .line 572
    check-cast v0, Lba0/q;

    .line 573
    .line 574
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 575
    .line 576
    .line 577
    new-instance v1, Lba0/i;

    .line 578
    .line 579
    const/4 v2, 0x1

    .line 580
    invoke-direct {v1, v0, v2}, Lba0/i;-><init>(Lba0/q;I)V

    .line 581
    .line 582
    .line 583
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 587
    .line 588
    .line 589
    move-result-object v1

    .line 590
    move-object v2, v1

    .line 591
    check-cast v2, Lba0/l;

    .line 592
    .line 593
    const/4 v8, 0x0

    .line 594
    const/16 v9, 0x3b

    .line 595
    .line 596
    const/4 v3, 0x0

    .line 597
    const/4 v4, 0x0

    .line 598
    const/4 v5, 0x0

    .line 599
    const/4 v6, 0x0

    .line 600
    const/4 v7, 0x0

    .line 601
    invoke-static/range {v2 .. v9}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 602
    .line 603
    .line 604
    move-result-object v1

    .line 605
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 606
    .line 607
    .line 608
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 609
    .line 610
    return-object v0

    .line 611
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 612
    .line 613
    check-cast v0, Lba0/q;

    .line 614
    .line 615
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 616
    .line 617
    .line 618
    move-result-object v1

    .line 619
    move-object v2, v1

    .line 620
    check-cast v2, Lba0/l;

    .line 621
    .line 622
    const/4 v8, 0x0

    .line 623
    const/16 v9, 0x3b

    .line 624
    .line 625
    const/4 v3, 0x0

    .line 626
    const/4 v4, 0x0

    .line 627
    const/4 v5, 0x1

    .line 628
    const/4 v6, 0x0

    .line 629
    const/4 v7, 0x0

    .line 630
    invoke-static/range {v2 .. v9}, Lba0/l;->a(Lba0/l;Lba0/k;Lql0/g;ZZZZI)Lba0/l;

    .line 631
    .line 632
    .line 633
    move-result-object v1

    .line 634
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 635
    .line 636
    .line 637
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 638
    .line 639
    return-object v0

    .line 640
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 641
    .line 642
    check-cast v0, Lba0/q;

    .line 643
    .line 644
    iget-object v0, v0, Lba0/q;->l:Ltr0/b;

    .line 645
    .line 646
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 647
    .line 648
    .line 649
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 650
    .line 651
    return-object v0

    .line 652
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 653
    .line 654
    check-cast v0, Lba0/g;

    .line 655
    .line 656
    iget-object v0, v0, Lba0/g;->i:Ltr0/b;

    .line 657
    .line 658
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 659
    .line 660
    .line 661
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 662
    .line 663
    return-object v0

    .line 664
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 665
    .line 666
    check-cast v0, Lba0/g;

    .line 667
    .line 668
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 669
    .line 670
    .line 671
    new-instance v1, La71/u;

    .line 672
    .line 673
    const/4 v2, 0x5

    .line 674
    invoke-direct {v1, v0, v2}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 675
    .line 676
    .line 677
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 678
    .line 679
    .line 680
    iget-object v0, v0, Lba0/g;->i:Ltr0/b;

    .line 681
    .line 682
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 686
    .line 687
    return-object v0

    .line 688
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 689
    .line 690
    check-cast v0, Lba0/d;

    .line 691
    .line 692
    iget-object v0, v0, Lba0/d;->h:Ltr0/b;

    .line 693
    .line 694
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 695
    .line 696
    .line 697
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 698
    .line 699
    return-object v0

    .line 700
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 701
    .line 702
    check-cast v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;

    .line 703
    .line 704
    invoke-static {v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;->access$onReconnect(Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/navigation/RPANavigationManager;)V

    .line 705
    .line 706
    .line 707
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 708
    .line 709
    return-object v0

    .line 710
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 711
    .line 712
    check-cast v0, Lb40/g;

    .line 713
    .line 714
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 715
    .line 716
    .line 717
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    new-instance v2, Lb40/d;

    .line 722
    .line 723
    const/4 v3, 0x2

    .line 724
    const/4 v4, 0x0

    .line 725
    invoke-direct {v2, v0, v4, v3}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 726
    .line 727
    .line 728
    const/4 v0, 0x3

    .line 729
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 730
    .line 731
    .line 732
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 733
    .line 734
    return-object v0

    .line 735
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 736
    .line 737
    check-cast v0, Lb40/g;

    .line 738
    .line 739
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 740
    .line 741
    .line 742
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    new-instance v2, Lb40/d;

    .line 747
    .line 748
    const/4 v3, 0x3

    .line 749
    const/4 v4, 0x0

    .line 750
    invoke-direct {v2, v0, v4, v3}, Lb40/d;-><init>(Lb40/g;Lkotlin/coroutines/Continuation;I)V

    .line 751
    .line 752
    .line 753
    const/4 v0, 0x3

    .line 754
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 755
    .line 756
    .line 757
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 758
    .line 759
    return-object v0

    .line 760
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 761
    .line 762
    check-cast v0, Lb40/c;

    .line 763
    .line 764
    iget-object v0, v0, Lb40/c;->k:Lz30/e;

    .line 765
    .line 766
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 767
    .line 768
    .line 769
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 770
    .line 771
    return-object v0

    .line 772
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 773
    .line 774
    check-cast v0, Lb40/c;

    .line 775
    .line 776
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 777
    .line 778
    .line 779
    new-instance v1, Lay/b;

    .line 780
    .line 781
    const/4 v2, 0x1

    .line 782
    invoke-direct {v1, v2}, Lay/b;-><init>(I)V

    .line 783
    .line 784
    .line 785
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 786
    .line 787
    .line 788
    iget-object v0, v0, Lb40/c;->j:Lzd0/a;

    .line 789
    .line 790
    new-instance v1, Lne0/e;

    .line 791
    .line 792
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 793
    .line 794
    invoke-direct {v1, v2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 795
    .line 796
    .line 797
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 798
    .line 799
    .line 800
    return-object v2

    .line 801
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 802
    .line 803
    check-cast v0, Lc30/i;

    .line 804
    .line 805
    check-cast v0, La30/a;

    .line 806
    .line 807
    iget-object v0, v0, La30/a;->b:Lwe0/a;

    .line 808
    .line 809
    check-cast v0, Lwe0/c;

    .line 810
    .line 811
    invoke-virtual {v0}, Lwe0/c;->b()Z

    .line 812
    .line 813
    .line 814
    move-result v0

    .line 815
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 816
    .line 817
    .line 818
    move-result-object v0

    .line 819
    return-object v0

    .line 820
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 821
    .line 822
    check-cast v0, Lc30/i;

    .line 823
    .line 824
    check-cast v0, La30/a;

    .line 825
    .line 826
    iget-object v0, v0, La30/a;->c:Lwe0/a;

    .line 827
    .line 828
    check-cast v0, Lwe0/c;

    .line 829
    .line 830
    invoke-virtual {v0}, Lwe0/c;->b()Z

    .line 831
    .line 832
    .line 833
    move-result v0

    .line 834
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 835
    .line 836
    .line 837
    move-result-object v0

    .line 838
    return-object v0

    .line 839
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 840
    .line 841
    check-cast v0, Lc30/i;

    .line 842
    .line 843
    check-cast v0, La30/a;

    .line 844
    .line 845
    iget-object v0, v0, La30/a;->a:Lwe0/a;

    .line 846
    .line 847
    check-cast v0, Lwe0/c;

    .line 848
    .line 849
    invoke-virtual {v0}, Lwe0/c;->b()Z

    .line 850
    .line 851
    .line 852
    move-result v0

    .line 853
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 854
    .line 855
    .line 856
    move-result-object v0

    .line 857
    return-object v0

    .line 858
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 859
    .line 860
    check-cast v0, Lc3/h;

    .line 861
    .line 862
    iget-object v1, v0, Lc3/h;->c:Landroidx/collection/r0;

    .line 863
    .line 864
    iget-object v2, v0, Lc3/h;->d:Landroidx/collection/r0;

    .line 865
    .line 866
    iget-object v3, v0, Lc3/h;->a:Lc3/l;

    .line 867
    .line 868
    iget-object v4, v3, Lc3/l;->h:Lc3/v;

    .line 869
    .line 870
    const/16 v12, 0x8

    .line 871
    .line 872
    const/4 v13, 0x0

    .line 873
    if-nez v4, :cond_8

    .line 874
    .line 875
    iget-object v4, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 876
    .line 877
    iget-object v14, v2, Landroidx/collection/r0;->a:[J

    .line 878
    .line 879
    array-length v15, v14

    .line 880
    add-int/lit8 v15, v15, -0x2

    .line 881
    .line 882
    if-ltz v15, :cond_15

    .line 883
    .line 884
    move v5, v13

    .line 885
    const-wide/16 v16, 0x80

    .line 886
    .line 887
    const-wide/16 v18, 0xff

    .line 888
    .line 889
    :goto_2
    aget-wide v7, v14, v5

    .line 890
    .line 891
    const/16 p0, 0x7

    .line 892
    .line 893
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 894
    .line 895
    .line 896
    .line 897
    .line 898
    not-long v9, v7

    .line 899
    shl-long v9, v9, p0

    .line 900
    .line 901
    and-long/2addr v9, v7

    .line 902
    and-long v9, v9, v20

    .line 903
    .line 904
    cmp-long v6, v9, v20

    .line 905
    .line 906
    if-eqz v6, :cond_7

    .line 907
    .line 908
    sub-int v6, v5, v15

    .line 909
    .line 910
    not-int v6, v6

    .line 911
    ushr-int/lit8 v6, v6, 0x1f

    .line 912
    .line 913
    rsub-int/lit8 v6, v6, 0x8

    .line 914
    .line 915
    move v9, v13

    .line 916
    :goto_3
    if-ge v9, v6, :cond_6

    .line 917
    .line 918
    and-long v10, v7, v18

    .line 919
    .line 920
    cmp-long v10, v10, v16

    .line 921
    .line 922
    if-gez v10, :cond_5

    .line 923
    .line 924
    shl-int/lit8 v10, v5, 0x3

    .line 925
    .line 926
    add-int/2addr v10, v9

    .line 927
    aget-object v10, v4, v10

    .line 928
    .line 929
    check-cast v10, Lc3/e;

    .line 930
    .line 931
    sget-object v11, Lc3/u;->g:Lc3/u;

    .line 932
    .line 933
    invoke-interface {v10, v11}, Lc3/e;->F(Lc3/u;)V

    .line 934
    .line 935
    .line 936
    :cond_5
    shr-long/2addr v7, v12

    .line 937
    add-int/lit8 v9, v9, 0x1

    .line 938
    .line 939
    goto :goto_3

    .line 940
    :cond_6
    if-ne v6, v12, :cond_15

    .line 941
    .line 942
    :cond_7
    if-eq v5, v15, :cond_15

    .line 943
    .line 944
    add-int/lit8 v5, v5, 0x1

    .line 945
    .line 946
    goto :goto_2

    .line 947
    :cond_8
    const/16 p0, 0x7

    .line 948
    .line 949
    const-wide/16 v16, 0x80

    .line 950
    .line 951
    const-wide/16 v18, 0xff

    .line 952
    .line 953
    const-wide v20, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 954
    .line 955
    .line 956
    .line 957
    .line 958
    iget-boolean v5, v4, Lx2/r;->q:Z

    .line 959
    .line 960
    if-eqz v5, :cond_15

    .line 961
    .line 962
    invoke-virtual {v1, v4}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 963
    .line 964
    .line 965
    move-result v5

    .line 966
    if-eqz v5, :cond_9

    .line 967
    .line 968
    invoke-virtual {v4}, Lc3/v;->a1()V

    .line 969
    .line 970
    .line 971
    :cond_9
    invoke-virtual {v4}, Lc3/v;->Z0()Lc3/u;

    .line 972
    .line 973
    .line 974
    move-result-object v5

    .line 975
    iget-object v6, v4, Lx2/r;->d:Lx2/r;

    .line 976
    .line 977
    iget-boolean v6, v6, Lx2/r;->q:Z

    .line 978
    .line 979
    if-nez v6, :cond_a

    .line 980
    .line 981
    const-string v6, "visitAncestors called on an unattached node"

    .line 982
    .line 983
    invoke-static {v6}, Ls3/a;->b(Ljava/lang/String;)V

    .line 984
    .line 985
    .line 986
    :cond_a
    iget-object v6, v4, Lx2/r;->d:Lx2/r;

    .line 987
    .line 988
    invoke-static {v4}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 989
    .line 990
    .line 991
    move-result-object v4

    .line 992
    move v7, v13

    .line 993
    :goto_4
    if-eqz v4, :cond_11

    .line 994
    .line 995
    iget-object v8, v4, Lv3/h0;->H:Lg1/q;

    .line 996
    .line 997
    iget-object v8, v8, Lg1/q;->g:Ljava/lang/Object;

    .line 998
    .line 999
    check-cast v8, Lx2/r;

    .line 1000
    .line 1001
    iget v8, v8, Lx2/r;->g:I

    .line 1002
    .line 1003
    and-int/lit16 v8, v8, 0x1400

    .line 1004
    .line 1005
    if-eqz v8, :cond_f

    .line 1006
    .line 1007
    :goto_5
    if-eqz v6, :cond_f

    .line 1008
    .line 1009
    iget v8, v6, Lx2/r;->f:I

    .line 1010
    .line 1011
    and-int/lit16 v9, v8, 0x1400

    .line 1012
    .line 1013
    if-eqz v9, :cond_e

    .line 1014
    .line 1015
    and-int/lit16 v8, v8, 0x400

    .line 1016
    .line 1017
    if-eqz v8, :cond_b

    .line 1018
    .line 1019
    add-int/lit8 v7, v7, 0x1

    .line 1020
    .line 1021
    :cond_b
    instance-of v8, v6, Lc3/e;

    .line 1022
    .line 1023
    if-eqz v8, :cond_e

    .line 1024
    .line 1025
    invoke-virtual {v2, v6}, Landroidx/collection/r0;->c(Ljava/lang/Object;)Z

    .line 1026
    .line 1027
    .line 1028
    move-result v8

    .line 1029
    if-nez v8, :cond_c

    .line 1030
    .line 1031
    goto :goto_7

    .line 1032
    :cond_c
    const/4 v8, 0x1

    .line 1033
    if-gt v7, v8, :cond_d

    .line 1034
    .line 1035
    move-object v8, v6

    .line 1036
    check-cast v8, Lc3/e;

    .line 1037
    .line 1038
    invoke-interface {v8, v5}, Lc3/e;->F(Lc3/u;)V

    .line 1039
    .line 1040
    .line 1041
    goto :goto_6

    .line 1042
    :cond_d
    move-object v8, v6

    .line 1043
    check-cast v8, Lc3/e;

    .line 1044
    .line 1045
    sget-object v9, Lc3/u;->e:Lc3/u;

    .line 1046
    .line 1047
    invoke-interface {v8, v9}, Lc3/e;->F(Lc3/u;)V

    .line 1048
    .line 1049
    .line 1050
    :goto_6
    invoke-virtual {v2, v6}, Landroidx/collection/r0;->l(Ljava/lang/Object;)Z

    .line 1051
    .line 1052
    .line 1053
    :cond_e
    :goto_7
    iget-object v6, v6, Lx2/r;->h:Lx2/r;

    .line 1054
    .line 1055
    goto :goto_5

    .line 1056
    :cond_f
    invoke-virtual {v4}, Lv3/h0;->v()Lv3/h0;

    .line 1057
    .line 1058
    .line 1059
    move-result-object v4

    .line 1060
    if-eqz v4, :cond_10

    .line 1061
    .line 1062
    iget-object v6, v4, Lv3/h0;->H:Lg1/q;

    .line 1063
    .line 1064
    if-eqz v6, :cond_10

    .line 1065
    .line 1066
    iget-object v6, v6, Lg1/q;->f:Ljava/lang/Object;

    .line 1067
    .line 1068
    check-cast v6, Lv3/z1;

    .line 1069
    .line 1070
    goto :goto_4

    .line 1071
    :cond_10
    const/4 v6, 0x0

    .line 1072
    goto :goto_4

    .line 1073
    :cond_11
    iget-object v4, v2, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 1074
    .line 1075
    iget-object v5, v2, Landroidx/collection/r0;->a:[J

    .line 1076
    .line 1077
    array-length v6, v5

    .line 1078
    add-int/lit8 v6, v6, -0x2

    .line 1079
    .line 1080
    if-ltz v6, :cond_15

    .line 1081
    .line 1082
    move v7, v13

    .line 1083
    :goto_8
    aget-wide v8, v5, v7

    .line 1084
    .line 1085
    not-long v10, v8

    .line 1086
    shl-long v10, v10, p0

    .line 1087
    .line 1088
    and-long/2addr v10, v8

    .line 1089
    and-long v10, v10, v20

    .line 1090
    .line 1091
    cmp-long v10, v10, v20

    .line 1092
    .line 1093
    if-eqz v10, :cond_14

    .line 1094
    .line 1095
    sub-int v10, v7, v6

    .line 1096
    .line 1097
    not-int v10, v10

    .line 1098
    ushr-int/lit8 v10, v10, 0x1f

    .line 1099
    .line 1100
    rsub-int/lit8 v10, v10, 0x8

    .line 1101
    .line 1102
    move v11, v13

    .line 1103
    :goto_9
    if-ge v11, v10, :cond_13

    .line 1104
    .line 1105
    and-long v14, v8, v18

    .line 1106
    .line 1107
    cmp-long v14, v14, v16

    .line 1108
    .line 1109
    if-gez v14, :cond_12

    .line 1110
    .line 1111
    shl-int/lit8 v14, v7, 0x3

    .line 1112
    .line 1113
    add-int/2addr v14, v11

    .line 1114
    aget-object v14, v4, v14

    .line 1115
    .line 1116
    check-cast v14, Lc3/e;

    .line 1117
    .line 1118
    sget-object v15, Lc3/u;->g:Lc3/u;

    .line 1119
    .line 1120
    invoke-interface {v14, v15}, Lc3/e;->F(Lc3/u;)V

    .line 1121
    .line 1122
    .line 1123
    :cond_12
    shr-long/2addr v8, v12

    .line 1124
    add-int/lit8 v11, v11, 0x1

    .line 1125
    .line 1126
    goto :goto_9

    .line 1127
    :cond_13
    if-ne v10, v12, :cond_15

    .line 1128
    .line 1129
    :cond_14
    if-eq v7, v6, :cond_15

    .line 1130
    .line 1131
    add-int/lit8 v7, v7, 0x1

    .line 1132
    .line 1133
    goto :goto_8

    .line 1134
    :cond_15
    iget-object v4, v3, Lc3/l;->h:Lc3/v;

    .line 1135
    .line 1136
    if-eqz v4, :cond_16

    .line 1137
    .line 1138
    iget-object v4, v3, Lc3/l;->c:Lc3/v;

    .line 1139
    .line 1140
    invoke-virtual {v4}, Lc3/v;->Z0()Lc3/u;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v4

    .line 1144
    sget-object v5, Lc3/u;->g:Lc3/u;

    .line 1145
    .line 1146
    if-ne v4, v5, :cond_17

    .line 1147
    .line 1148
    :cond_16
    invoke-virtual {v3}, Lc3/l;->e()V

    .line 1149
    .line 1150
    .line 1151
    :cond_17
    invoke-virtual {v1}, Landroidx/collection/r0;->b()V

    .line 1152
    .line 1153
    .line 1154
    invoke-virtual {v2}, Landroidx/collection/r0;->b()V

    .line 1155
    .line 1156
    .line 1157
    iput-boolean v13, v0, Lc3/h;->e:Z

    .line 1158
    .line 1159
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1160
    .line 1161
    return-object v0

    .line 1162
    nop

    .line 1163
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
