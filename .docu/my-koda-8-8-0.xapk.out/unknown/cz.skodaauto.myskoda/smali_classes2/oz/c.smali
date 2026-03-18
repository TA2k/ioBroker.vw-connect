.class public final synthetic Loz/c;
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
    iput p7, p0, Loz/c;->d:I

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
    iget v1, v0, Loz/c;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lq40/h;

    .line 11
    .line 12
    iget-object v0, v0, Lq40/h;->r:Ltr0/b;

    .line 13
    .line 14
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    return-object v0

    .line 20
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v0, Lq40/h;

    .line 23
    .line 24
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    move-object v2, v1

    .line 29
    check-cast v2, Lq40/d;

    .line 30
    .line 31
    const/16 v16, 0x0

    .line 32
    .line 33
    const/16 v17, 0x37ff

    .line 34
    .line 35
    const/4 v3, 0x0

    .line 36
    const/4 v4, 0x0

    .line 37
    const/4 v5, 0x0

    .line 38
    const/4 v6, 0x0

    .line 39
    const/4 v7, 0x0

    .line 40
    const/4 v8, 0x0

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v10, 0x0

    .line 43
    const/4 v11, 0x0

    .line 44
    const/4 v12, 0x0

    .line 45
    const/4 v13, 0x0

    .line 46
    const/4 v14, 0x0

    .line 47
    const/4 v15, 0x0

    .line 48
    invoke-static/range {v2 .. v17}, Lq40/d;->a(Lq40/d;Lon0/j;Ljava/lang/String;Lon0/x;Lon0/z;Lon0/w;Ljava/util/ArrayList;Ljava/util/List;ZZZZLql0/g;Ler0/g;Lqr0/s;I)Lq40/d;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 53
    .line 54
    .line 55
    iget-object v0, v0, Lq40/h;->r:Ltr0/b;

    .line 56
    .line 57
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

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
    check-cast v0, Lq40/h;

    .line 66
    .line 67
    iget-object v1, v0, Lq40/h;->x:Lo40/c0;

    .line 68
    .line 69
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 70
    .line 71
    .line 72
    move-result-object v2

    .line 73
    check-cast v2, Lq40/d;

    .line 74
    .line 75
    iget-object v2, v2, Lq40/d;->c:Lon0/x;

    .line 76
    .line 77
    const-string v3, ""

    .line 78
    .line 79
    if-eqz v2, :cond_0

    .line 80
    .line 81
    iget-object v2, v2, Lon0/x;->d:Ljava/lang/String;

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_0
    move-object v2, v3

    .line 85
    :goto_0
    iget-object v1, v1, Lo40/c0;->a:Lm40/b;

    .line 86
    .line 87
    iput-object v2, v1, Lm40/b;->a:Ljava/lang/String;

    .line 88
    .line 89
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    check-cast v1, Lq40/d;

    .line 94
    .line 95
    iget-object v5, v1, Lq40/d;->c:Lon0/x;

    .line 96
    .line 97
    if-eqz v5, :cond_5

    .line 98
    .line 99
    iget-object v1, v0, Lq40/h;->y:Lo40/b0;

    .line 100
    .line 101
    new-instance v4, Lon0/m;

    .line 102
    .line 103
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object v2

    .line 107
    check-cast v2, Lq40/d;

    .line 108
    .line 109
    iget-object v6, v2, Lq40/d;->e:Lon0/w;

    .line 110
    .line 111
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    check-cast v2, Lq40/d;

    .line 116
    .line 117
    iget-object v2, v2, Lq40/d;->d:Lon0/z;

    .line 118
    .line 119
    if-eqz v2, :cond_2

    .line 120
    .line 121
    iget-object v2, v2, Lon0/z;->a:Ljava/lang/String;

    .line 122
    .line 123
    if-nez v2, :cond_1

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_1
    move-object v7, v2

    .line 127
    goto :goto_2

    .line 128
    :cond_2
    :goto_1
    move-object v7, v3

    .line 129
    :goto_2
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 130
    .line 131
    .line 132
    move-result-object v2

    .line 133
    check-cast v2, Lq40/d;

    .line 134
    .line 135
    iget-object v2, v2, Lq40/d;->d:Lon0/z;

    .line 136
    .line 137
    const/4 v3, 0x0

    .line 138
    if-eqz v2, :cond_3

    .line 139
    .line 140
    iget-object v2, v2, Lon0/z;->b:Ljava/lang/String;

    .line 141
    .line 142
    move-object v8, v2

    .line 143
    goto :goto_3

    .line 144
    :cond_3
    move-object v8, v3

    .line 145
    :goto_3
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 146
    .line 147
    .line 148
    move-result-object v2

    .line 149
    check-cast v2, Lq40/d;

    .line 150
    .line 151
    iget-object v2, v2, Lq40/d;->d:Lon0/z;

    .line 152
    .line 153
    if-eqz v2, :cond_4

    .line 154
    .line 155
    iget-object v3, v2, Lon0/z;->c:Lon0/y;

    .line 156
    .line 157
    :cond_4
    move-object v9, v3

    .line 158
    iget-object v10, v0, Lq40/h;->B:Ljava/lang/String;

    .line 159
    .line 160
    invoke-direct/range {v4 .. v10}, Lon0/m;-><init>(Lon0/x;Lon0/w;Ljava/lang/String;Ljava/lang/String;Lon0/y;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    iget-object v1, v1, Lo40/b0;->a:Lln0/g;

    .line 164
    .line 165
    iput-object v4, v1, Lln0/g;->a:Lon0/m;

    .line 166
    .line 167
    :cond_5
    iget-object v0, v0, Lq40/h;->q:Lo40/u;

    .line 168
    .line 169
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    return-object v0

    .line 175
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lq40/h;

    .line 178
    .line 179
    iget-object v0, v0, Lq40/h;->p:Lo40/k;

    .line 180
    .line 181
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 185
    .line 186
    return-object v0

    .line 187
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v0, Lq40/c;

    .line 190
    .line 191
    iget-object v0, v0, Lq40/c;->n:Ltr0/b;

    .line 192
    .line 193
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    return-object v0

    .line 199
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Lq30/b;

    .line 202
    .line 203
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 204
    .line 205
    .line 206
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 207
    .line 208
    .line 209
    move-result-object v1

    .line 210
    new-instance v2, Ln00/f;

    .line 211
    .line 212
    const/16 v3, 0xd

    .line 213
    .line 214
    const/4 v4, 0x0

    .line 215
    invoke-direct {v2, v0, v4, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 216
    .line 217
    .line 218
    const/4 v0, 0x3

    .line 219
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 220
    .line 221
    .line 222
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    return-object v0

    .line 225
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v0, Lq30/b;

    .line 228
    .line 229
    iget-object v0, v0, Lq30/b;->h:Ltr0/b;

    .line 230
    .line 231
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 235
    .line 236
    return-object v0

    .line 237
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Lq30/h;

    .line 240
    .line 241
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    check-cast v1, Lq30/g;

    .line 246
    .line 247
    iget-object v1, v1, Lq30/g;->c:Ljava/lang/String;

    .line 248
    .line 249
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 250
    .line 251
    .line 252
    move-result-object v2

    .line 253
    move-object v3, v2

    .line 254
    check-cast v3, Lq30/g;

    .line 255
    .line 256
    const/4 v7, 0x0

    .line 257
    const/16 v8, 0x19

    .line 258
    .line 259
    const/4 v4, 0x0

    .line 260
    const-string v5, ""

    .line 261
    .line 262
    const/4 v6, 0x0

    .line 263
    invoke-static/range {v3 .. v8}, Lq30/g;->a(Lq30/g;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;ZI)Lq30/g;

    .line 264
    .line 265
    .line 266
    move-result-object v2

    .line 267
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 268
    .line 269
    .line 270
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 271
    .line 272
    .line 273
    move-result-object v2

    .line 274
    new-instance v3, Lny/f0;

    .line 275
    .line 276
    const/16 v4, 0xc

    .line 277
    .line 278
    const/4 v5, 0x0

    .line 279
    invoke-direct {v3, v4, v0, v1, v5}, Lny/f0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 280
    .line 281
    .line 282
    const/4 v0, 0x3

    .line 283
    invoke-static {v2, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 284
    .line 285
    .line 286
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object v0

    .line 289
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v0, Lq30/h;

    .line 292
    .line 293
    iget-object v0, v0, Lq30/h;->h:Ltr0/b;

    .line 294
    .line 295
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 299
    .line 300
    return-object v0

    .line 301
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 302
    .line 303
    check-cast v0, Lq20/b;

    .line 304
    .line 305
    iget-object v0, v0, Lq20/b;->h:Ltr0/b;

    .line 306
    .line 307
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 311
    .line 312
    return-object v0

    .line 313
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 314
    .line 315
    check-cast v0, Lq00/d;

    .line 316
    .line 317
    iget-object v0, v0, Lq00/d;->m:Lcf0/h;

    .line 318
    .line 319
    const/4 v1, 0x1

    .line 320
    iget-object v0, v0, Lcf0/h;->a:Laf0/a;

    .line 321
    .line 322
    iput-boolean v1, v0, Laf0/a;->a:Z

    .line 323
    .line 324
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 325
    .line 326
    return-object v0

    .line 327
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 328
    .line 329
    check-cast v0, Lq00/d;

    .line 330
    .line 331
    iget-object v0, v0, Lq00/d;->m:Lcf0/h;

    .line 332
    .line 333
    const/4 v1, 0x0

    .line 334
    iget-object v0, v0, Lcf0/h;->a:Laf0/a;

    .line 335
    .line 336
    iput-boolean v1, v0, Laf0/a;->a:Z

    .line 337
    .line 338
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 339
    .line 340
    return-object v0

    .line 341
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Lq00/d;

    .line 344
    .line 345
    iget-object v0, v0, Lq00/d;->k:Ltr0/b;

    .line 346
    .line 347
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 351
    .line 352
    return-object v0

    .line 353
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v0, Lq00/d;

    .line 356
    .line 357
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 358
    .line 359
    .line 360
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 361
    .line 362
    .line 363
    move-result-object v1

    .line 364
    new-instance v2, Lq00/c;

    .line 365
    .line 366
    const/4 v3, 0x1

    .line 367
    const/4 v4, 0x0

    .line 368
    invoke-direct {v2, v0, v4, v3}, Lq00/c;-><init>(Lq00/d;Lkotlin/coroutines/Continuation;I)V

    .line 369
    .line 370
    .line 371
    const/4 v0, 0x3

    .line 372
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 373
    .line 374
    .line 375
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 376
    .line 377
    return-object v0

    .line 378
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 379
    .line 380
    check-cast v0, Lq00/d;

    .line 381
    .line 382
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 383
    .line 384
    .line 385
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 386
    .line 387
    .line 388
    move-result-object v1

    .line 389
    new-instance v2, Lq00/c;

    .line 390
    .line 391
    const/4 v3, 0x0

    .line 392
    const/4 v4, 0x0

    .line 393
    invoke-direct {v2, v0, v4, v3}, Lq00/c;-><init>(Lq00/d;Lkotlin/coroutines/Continuation;I)V

    .line 394
    .line 395
    .line 396
    const/4 v0, 0x3

    .line 397
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 398
    .line 399
    .line 400
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 401
    .line 402
    return-object v0

    .line 403
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 404
    .line 405
    check-cast v0, Lpv0/g;

    .line 406
    .line 407
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 408
    .line 409
    .line 410
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    new-instance v2, Lpv0/e;

    .line 415
    .line 416
    const/4 v3, 0x1

    .line 417
    const/4 v4, 0x0

    .line 418
    invoke-direct {v2, v0, v4, v3}, Lpv0/e;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 419
    .line 420
    .line 421
    const/4 v0, 0x3

    .line 422
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 423
    .line 424
    .line 425
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 426
    .line 427
    return-object v0

    .line 428
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 429
    .line 430
    check-cast v0, Lpv0/g;

    .line 431
    .line 432
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 433
    .line 434
    .line 435
    move-result-object v1

    .line 436
    move-object v2, v1

    .line 437
    check-cast v2, Lpv0/f;

    .line 438
    .line 439
    const/4 v10, 0x0

    .line 440
    const/16 v11, 0x17f

    .line 441
    .line 442
    const/4 v3, 0x0

    .line 443
    const/4 v4, 0x0

    .line 444
    const/4 v5, 0x0

    .line 445
    const/4 v6, 0x0

    .line 446
    const/4 v7, 0x0

    .line 447
    const/4 v8, 0x0

    .line 448
    const/4 v9, 0x0

    .line 449
    invoke-static/range {v2 .. v11}, Lpv0/f;->a(Lpv0/f;ZZZZZZLjava/lang/String;ZI)Lpv0/f;

    .line 450
    .line 451
    .line 452
    move-result-object v1

    .line 453
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 454
    .line 455
    .line 456
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 457
    .line 458
    .line 459
    move-result-object v1

    .line 460
    new-instance v2, Lpv0/a;

    .line 461
    .line 462
    const/4 v3, 0x3

    .line 463
    const/4 v4, 0x0

    .line 464
    invoke-direct {v2, v0, v4, v3}, Lpv0/a;-><init>(Lpv0/g;Lkotlin/coroutines/Continuation;I)V

    .line 465
    .line 466
    .line 467
    const/4 v0, 0x3

    .line 468
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 469
    .line 470
    .line 471
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 472
    .line 473
    return-object v0

    .line 474
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 475
    .line 476
    check-cast v0, Lpv0/g;

    .line 477
    .line 478
    iget-object v0, v0, Lpv0/g;->m:Lov0/b;

    .line 479
    .line 480
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 484
    .line 485
    return-object v0

    .line 486
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v0, Lpv0/g;

    .line 489
    .line 490
    iget-object v0, v0, Lpv0/g;->n:Lov0/c;

    .line 491
    .line 492
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 496
    .line 497
    return-object v0

    .line 498
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 499
    .line 500
    check-cast v0, Lpv0/g;

    .line 501
    .line 502
    iget-object v0, v0, Lpv0/g;->k:Lov0/d;

    .line 503
    .line 504
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 508
    .line 509
    return-object v0

    .line 510
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 511
    .line 512
    check-cast v0, Lpv0/g;

    .line 513
    .line 514
    iget-object v0, v0, Lpv0/g;->j:Lov0/f;

    .line 515
    .line 516
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 520
    .line 521
    return-object v0

    .line 522
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 523
    .line 524
    check-cast v0, Lpv0/g;

    .line 525
    .line 526
    iget-object v0, v0, Lpv0/g;->i:Lov0/e;

    .line 527
    .line 528
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 529
    .line 530
    .line 531
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 532
    .line 533
    return-object v0

    .line 534
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 535
    .line 536
    check-cast v0, Lor0/d;

    .line 537
    .line 538
    iget-object v0, v0, Lor0/d;->h:Lnr0/e;

    .line 539
    .line 540
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 544
    .line 545
    return-object v0

    .line 546
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 547
    .line 548
    check-cast v0, Lor0/b;

    .line 549
    .line 550
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 551
    .line 552
    .line 553
    move-result-object v1

    .line 554
    check-cast v1, Lor0/a;

    .line 555
    .line 556
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 557
    .line 558
    .line 559
    new-instance v1, Lor0/a;

    .line 560
    .line 561
    const/4 v2, 0x0

    .line 562
    invoke-direct {v1, v2}, Lor0/a;-><init>(Z)V

    .line 563
    .line 564
    .line 565
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 566
    .line 567
    .line 568
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 569
    .line 570
    return-object v0

    .line 571
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 572
    .line 573
    check-cast v0, Lor0/b;

    .line 574
    .line 575
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 576
    .line 577
    .line 578
    move-result-object v1

    .line 579
    check-cast v1, Lor0/a;

    .line 580
    .line 581
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 582
    .line 583
    .line 584
    new-instance v1, Lor0/a;

    .line 585
    .line 586
    const/4 v2, 0x1

    .line 587
    invoke-direct {v1, v2}, Lor0/a;-><init>(Z)V

    .line 588
    .line 589
    .line 590
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 591
    .line 592
    .line 593
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 594
    .line 595
    return-object v0

    .line 596
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 597
    .line 598
    check-cast v0, Lor0/b;

    .line 599
    .line 600
    iget-object v0, v0, Lor0/b;->j:Lnr0/e;

    .line 601
    .line 602
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 603
    .line 604
    .line 605
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 606
    .line 607
    return-object v0

    .line 608
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 609
    .line 610
    check-cast v0, Lpg/p;

    .line 611
    .line 612
    iget-object v1, v0, Lpg/p;->a:Lxh/e;

    .line 613
    .line 614
    new-instance v2, Lpg/r;

    .line 615
    .line 616
    iget-object v3, v0, Lpg/p;->f:Lkg/d0;

    .line 617
    .line 618
    const/4 v4, 0x0

    .line 619
    if-eqz v3, :cond_7

    .line 620
    .line 621
    iget-object v0, v0, Lpg/p;->g:Lug/a;

    .line 622
    .line 623
    if-eqz v0, :cond_6

    .line 624
    .line 625
    invoke-direct {v2, v3, v0}, Lpg/r;-><init>(Lkg/d0;Lug/a;)V

    .line 626
    .line 627
    .line 628
    invoke-virtual {v1, v2}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 629
    .line 630
    .line 631
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 632
    .line 633
    return-object v0

    .line 634
    :cond_6
    const-string v0, "selectedTariffActivationOption"

    .line 635
    .line 636
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 637
    .line 638
    .line 639
    throw v4

    .line 640
    :cond_7
    const-string v0, "updatedSubscription"

    .line 641
    .line 642
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 643
    .line 644
    .line 645
    throw v4

    .line 646
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 647
    .line 648
    check-cast v0, Lpg/c;

    .line 649
    .line 650
    iget-object v0, v0, Lpg/c;->a:Lyj/b;

    .line 651
    .line 652
    invoke-virtual {v0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 653
    .line 654
    .line 655
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 656
    .line 657
    return-object v0

    .line 658
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 659
    .line 660
    check-cast v0, Lpc/c;

    .line 661
    .line 662
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 663
    .line 664
    .line 665
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 666
    .line 667
    .line 668
    move-result-object v1

    .line 669
    new-instance v2, Ln00/f;

    .line 670
    .line 671
    const/16 v3, 0xa

    .line 672
    .line 673
    const/4 v4, 0x0

    .line 674
    invoke-direct {v2, v0, v4, v3}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 675
    .line 676
    .line 677
    const/4 v0, 0x3

    .line 678
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 679
    .line 680
    .line 681
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 682
    .line 683
    return-object v0

    .line 684
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 685
    .line 686
    check-cast v0, Lnz/z;

    .line 687
    .line 688
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 689
    .line 690
    .line 691
    new-instance v1, Lnz/l;

    .line 692
    .line 693
    const/4 v2, 0x0

    .line 694
    invoke-direct {v1, v0, v2}, Lnz/l;-><init>(Lnz/z;I)V

    .line 695
    .line 696
    .line 697
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 698
    .line 699
    .line 700
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 701
    .line 702
    .line 703
    move-result-object v1

    .line 704
    move-object v2, v1

    .line 705
    check-cast v2, Lnz/s;

    .line 706
    .line 707
    const/16 v26, 0x0

    .line 708
    .line 709
    const v27, 0xffffdff

    .line 710
    .line 711
    .line 712
    const/4 v3, 0x0

    .line 713
    const/4 v4, 0x0

    .line 714
    const/4 v5, 0x0

    .line 715
    const/4 v6, 0x0

    .line 716
    const/4 v7, 0x0

    .line 717
    const/4 v8, 0x0

    .line 718
    const/4 v9, 0x1

    .line 719
    const/4 v10, 0x0

    .line 720
    const/4 v11, 0x0

    .line 721
    const/4 v12, 0x0

    .line 722
    const/4 v13, 0x0

    .line 723
    const/4 v14, 0x0

    .line 724
    const/4 v15, 0x0

    .line 725
    const/16 v16, 0x0

    .line 726
    .line 727
    const/16 v17, 0x0

    .line 728
    .line 729
    const/16 v18, 0x0

    .line 730
    .line 731
    const/16 v19, 0x0

    .line 732
    .line 733
    const/16 v20, 0x0

    .line 734
    .line 735
    const/16 v21, 0x0

    .line 736
    .line 737
    const/16 v22, 0x0

    .line 738
    .line 739
    const/16 v23, 0x0

    .line 740
    .line 741
    const/16 v24, 0x0

    .line 742
    .line 743
    const/16 v25, 0x0

    .line 744
    .line 745
    invoke-static/range {v2 .. v27}, Lnz/s;->a(Lnz/s;Ler0/g;Llf0/i;ZZZZZZLjava/lang/String;Ljava/lang/String;Lnz/r;Lnz/q;Lbo0/l;Lnz/p;ZZLjava/lang/String;Lmz/a;Lqr0/q;Lqr0/q;Lmy0/c;ZLmb0/c;ZI)Lnz/s;

    .line 746
    .line 747
    .line 748
    move-result-object v1

    .line 749
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 750
    .line 751
    .line 752
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 753
    .line 754
    return-object v0

    .line 755
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
