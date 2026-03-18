.class public final synthetic Lf20/h;
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
    iput p7, p0, Lf20/h;->d:I

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
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lf20/h;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lg10/f;

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
    check-cast v2, Lg10/d;

    .line 18
    .line 19
    const/4 v13, 0x0

    .line 20
    const/16 v14, 0x7fe

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x0

    .line 24
    const/4 v5, 0x0

    .line 25
    const/4 v6, 0x0

    .line 26
    const/4 v7, 0x0

    .line 27
    const/4 v8, 0x0

    .line 28
    const/4 v9, 0x0

    .line 29
    const/4 v10, 0x0

    .line 30
    const/4 v11, 0x0

    .line 31
    const/4 v12, 0x0

    .line 32
    invoke-static/range {v2 .. v14}, Lg10/d;->a(Lg10/d;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZI)Lg10/d;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 37
    .line 38
    .line 39
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    return-object v0

    .line 42
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Lg10/f;

    .line 45
    .line 46
    iget-object v1, v0, Lg10/f;->q:Lf10/a;

    .line 47
    .line 48
    if-eqz v1, :cond_0

    .line 49
    .line 50
    iget-object v0, v0, Lg10/f;->l:Le10/f;

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Le10/f;->a(Lf10/a;)V

    .line 53
    .line 54
    .line 55
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    return-object v0

    .line 58
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lg10/f;

    .line 61
    .line 62
    iget-object v0, v0, Lg10/f;->h:Ltr0/b;

    .line 63
    .line 64
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object v0

    .line 70
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v0, Lg10/b;

    .line 73
    .line 74
    iget-object v0, v0, Lg10/b;->h:Le10/e;

    .line 75
    .line 76
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object v0

    .line 82
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lfr0/h;

    .line 85
    .line 86
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 87
    .line 88
    .line 89
    new-instance v1, Ld2/g;

    .line 90
    .line 91
    const/16 v2, 0xe

    .line 92
    .line 93
    invoke-direct {v1, v0, v2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 94
    .line 95
    .line 96
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 97
    .line 98
    .line 99
    iget-object v0, v0, Lfr0/h;->h:Lcr0/l;

    .line 100
    .line 101
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 105
    .line 106
    return-object v0

    .line 107
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast v0, Lfr0/h;

    .line 110
    .line 111
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    move-object v2, v1

    .line 116
    check-cast v2, Lfr0/g;

    .line 117
    .line 118
    const/4 v8, 0x0

    .line 119
    const/16 v9, 0x3d

    .line 120
    .line 121
    const/4 v3, 0x0

    .line 122
    const/4 v4, 0x0

    .line 123
    const/4 v5, 0x0

    .line 124
    const/4 v6, 0x0

    .line 125
    const/4 v7, 0x0

    .line 126
    invoke-static/range {v2 .. v9}, Lfr0/g;->a(Lfr0/g;Ler0/g;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lkp/f8;I)Lfr0/g;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 131
    .line 132
    .line 133
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    return-object v0

    .line 136
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast v0, Lfr0/h;

    .line 139
    .line 140
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 141
    .line 142
    .line 143
    move-result-object v1

    .line 144
    move-object v2, v1

    .line 145
    check-cast v2, Lfr0/g;

    .line 146
    .line 147
    const/4 v8, 0x0

    .line 148
    const/16 v9, 0x3d

    .line 149
    .line 150
    const/4 v3, 0x0

    .line 151
    const/4 v4, 0x1

    .line 152
    const/4 v5, 0x0

    .line 153
    const/4 v6, 0x0

    .line 154
    const/4 v7, 0x0

    .line 155
    invoke-static/range {v2 .. v9}, Lfr0/g;->a(Lfr0/g;Ler0/g;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lkp/f8;I)Lfr0/g;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 160
    .line 161
    .line 162
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    return-object v0

    .line 165
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 166
    .line 167
    check-cast v0, Lz9/y;

    .line 168
    .line 169
    new-instance v1, Lg4/a0;

    .line 170
    .line 171
    const/16 v2, 0x14

    .line 172
    .line 173
    invoke-direct {v1, v2}, Lg4/a0;-><init>(I)V

    .line 174
    .line 175
    .line 176
    const-string v2, "REMOTE_START_ROUTE"

    .line 177
    .line 178
    invoke-virtual {v0, v2, v1}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 179
    .line 180
    .line 181
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    return-object v0

    .line 184
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v0, Lz9/y;

    .line 187
    .line 188
    new-instance v1, Lg4/a0;

    .line 189
    .line 190
    const/16 v2, 0x13

    .line 191
    .line 192
    invoke-direct {v1, v2}, Lg4/a0;-><init>(I)V

    .line 193
    .line 194
    .line 195
    const-string v2, "REMOTE_STOP_ROUTE"

    .line 196
    .line 197
    invoke-virtual {v0, v2, v1}, Lz9/y;->d(Ljava/lang/String;Lay0/k;)V

    .line 198
    .line 199
    .line 200
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 201
    .line 202
    return-object v0

    .line 203
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Le30/u;

    .line 206
    .line 207
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Le30/s;

    .line 212
    .line 213
    const/4 v2, 0x0

    .line 214
    const/16 v3, 0xe

    .line 215
    .line 216
    const/4 v4, 0x0

    .line 217
    invoke-static {v1, v4, v4, v2, v3}, Le30/s;->a(Le30/s;ZZLe30/v;I)Le30/s;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 222
    .line 223
    .line 224
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 225
    .line 226
    return-object v0

    .line 227
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 228
    .line 229
    check-cast v0, Le30/u;

    .line 230
    .line 231
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 232
    .line 233
    .line 234
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    new-instance v2, Le30/r;

    .line 239
    .line 240
    const/4 v3, 0x1

    .line 241
    const/4 v4, 0x0

    .line 242
    invoke-direct {v2, v0, v4, v3}, Le30/r;-><init>(Le30/u;Lkotlin/coroutines/Continuation;I)V

    .line 243
    .line 244
    .line 245
    const/4 v0, 0x3

    .line 246
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 247
    .line 248
    .line 249
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    return-object v0

    .line 252
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v0, Le30/u;

    .line 255
    .line 256
    iget-object v0, v0, Le30/u;->h:Ltr0/b;

    .line 257
    .line 258
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    return-object v0

    .line 264
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast v0, Le30/q;

    .line 267
    .line 268
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 269
    .line 270
    .line 271
    move-result-object v1

    .line 272
    move-object v2, v1

    .line 273
    check-cast v2, Le30/o;

    .line 274
    .line 275
    const/4 v7, 0x0

    .line 276
    const/16 v8, 0x17

    .line 277
    .line 278
    const/4 v3, 0x0

    .line 279
    const/4 v4, 0x0

    .line 280
    const/4 v5, 0x0

    .line 281
    const/4 v6, 0x0

    .line 282
    invoke-static/range {v2 .. v8}, Le30/o;->a(Le30/o;Ljava/util/ArrayList;ZZLql0/g;Le30/n;I)Le30/o;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 287
    .line 288
    .line 289
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    return-object v0

    .line 292
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 293
    .line 294
    check-cast v0, Le30/q;

    .line 295
    .line 296
    iget-object v0, v0, Le30/q;->i:Ltr0/b;

    .line 297
    .line 298
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 299
    .line 300
    .line 301
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 302
    .line 303
    return-object v0

    .line 304
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 305
    .line 306
    check-cast v0, Le30/q;

    .line 307
    .line 308
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 309
    .line 310
    .line 311
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 312
    .line 313
    .line 314
    move-result-object v1

    .line 315
    new-instance v2, Le30/l;

    .line 316
    .line 317
    const/4 v3, 0x1

    .line 318
    const/4 v4, 0x0

    .line 319
    invoke-direct {v2, v0, v4, v3}, Le30/l;-><init>(Le30/q;Lkotlin/coroutines/Continuation;I)V

    .line 320
    .line 321
    .line 322
    const/4 v0, 0x3

    .line 323
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 324
    .line 325
    .line 326
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 327
    .line 328
    return-object v0

    .line 329
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 330
    .line 331
    check-cast v0, Le30/j;

    .line 332
    .line 333
    iget-object v0, v0, Le30/j;->k:Lc30/o;

    .line 334
    .line 335
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 339
    .line 340
    return-object v0

    .line 341
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 342
    .line 343
    check-cast v0, Le30/j;

    .line 344
    .line 345
    iget-object v0, v0, Le30/j;->l:Lc30/n;

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
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 354
    .line 355
    check-cast v0, Le30/d;

    .line 356
    .line 357
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 358
    .line 359
    .line 360
    move-result-object v1

    .line 361
    move-object v2, v1

    .line 362
    check-cast v2, Le30/b;

    .line 363
    .line 364
    const/4 v6, 0x0

    .line 365
    const/16 v7, 0xe

    .line 366
    .line 367
    const/4 v3, 0x0

    .line 368
    const/4 v4, 0x0

    .line 369
    const/4 v5, 0x0

    .line 370
    invoke-static/range {v2 .. v7}, Le30/b;->a(Le30/b;Lql0/g;Le30/v;ZZI)Le30/b;

    .line 371
    .line 372
    .line 373
    move-result-object v1

    .line 374
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 375
    .line 376
    .line 377
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 378
    .line 379
    return-object v0

    .line 380
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 381
    .line 382
    check-cast v0, Le30/d;

    .line 383
    .line 384
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 385
    .line 386
    .line 387
    new-instance v1, Le30/a;

    .line 388
    .line 389
    const/4 v2, 0x0

    .line 390
    invoke-direct {v1, v0, v2}, Le30/a;-><init>(Le30/d;I)V

    .line 391
    .line 392
    .line 393
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 394
    .line 395
    .line 396
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 397
    .line 398
    .line 399
    move-result-object v1

    .line 400
    move-object v2, v1

    .line 401
    check-cast v2, Le30/b;

    .line 402
    .line 403
    const/4 v6, 0x0

    .line 404
    const/16 v7, 0xb

    .line 405
    .line 406
    const/4 v3, 0x0

    .line 407
    const/4 v4, 0x0

    .line 408
    const/4 v5, 0x0

    .line 409
    invoke-static/range {v2 .. v7}, Le30/b;->a(Le30/b;Lql0/g;Le30/v;ZZI)Le30/b;

    .line 410
    .line 411
    .line 412
    move-result-object v1

    .line 413
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 414
    .line 415
    .line 416
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 417
    .line 418
    return-object v0

    .line 419
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast v0, Le30/d;

    .line 422
    .line 423
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 424
    .line 425
    .line 426
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 427
    .line 428
    .line 429
    move-result-object v1

    .line 430
    new-instance v2, Lc80/l;

    .line 431
    .line 432
    const/16 v3, 0x1d

    .line 433
    .line 434
    const/4 v4, 0x0

    .line 435
    invoke-direct {v2, v0, v4, v3}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 436
    .line 437
    .line 438
    const/4 v0, 0x3

    .line 439
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 440
    .line 441
    .line 442
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 443
    .line 444
    return-object v0

    .line 445
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 446
    .line 447
    check-cast v0, Le30/d;

    .line 448
    .line 449
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 450
    .line 451
    .line 452
    move-result-object v1

    .line 453
    move-object v2, v1

    .line 454
    check-cast v2, Le30/b;

    .line 455
    .line 456
    const/4 v6, 0x0

    .line 457
    const/16 v7, 0xb

    .line 458
    .line 459
    const/4 v3, 0x0

    .line 460
    const/4 v4, 0x0

    .line 461
    const/4 v5, 0x1

    .line 462
    invoke-static/range {v2 .. v7}, Le30/b;->a(Le30/b;Lql0/g;Le30/v;ZZI)Le30/b;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 467
    .line 468
    .line 469
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 470
    .line 471
    return-object v0

    .line 472
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 473
    .line 474
    check-cast v0, Le30/d;

    .line 475
    .line 476
    iget-object v0, v0, Le30/d;->j:Ltr0/b;

    .line 477
    .line 478
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 479
    .line 480
    .line 481
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 482
    .line 483
    return-object v0

    .line 484
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 485
    .line 486
    check-cast v0, Le20/d;

    .line 487
    .line 488
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 489
    .line 490
    .line 491
    move-result-object v1

    .line 492
    check-cast v1, Le20/c;

    .line 493
    .line 494
    const/4 v2, 0x0

    .line 495
    const/4 v3, 0x5

    .line 496
    const/4 v4, 0x0

    .line 497
    const/4 v5, 0x1

    .line 498
    invoke-static {v1, v4, v5, v2, v3}, Le20/c;->a(Le20/c;ZZLjava/util/ArrayList;I)Le20/c;

    .line 499
    .line 500
    .line 501
    move-result-object v1

    .line 502
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 503
    .line 504
    .line 505
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 506
    .line 507
    return-object v0

    .line 508
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 509
    .line 510
    check-cast v0, Le20/d;

    .line 511
    .line 512
    iget-object v0, v0, Le20/d;->h:Ltr0/b;

    .line 513
    .line 514
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 515
    .line 516
    .line 517
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 518
    .line 519
    return-object v0

    .line 520
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v0, Le20/d;

    .line 523
    .line 524
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 525
    .line 526
    .line 527
    move-result-object v1

    .line 528
    check-cast v1, Le20/c;

    .line 529
    .line 530
    const/4 v2, 0x0

    .line 531
    const/4 v3, 0x5

    .line 532
    const/4 v4, 0x0

    .line 533
    invoke-static {v1, v4, v4, v2, v3}, Le20/c;->a(Le20/c;ZZLjava/util/ArrayList;I)Le20/c;

    .line 534
    .line 535
    .line 536
    move-result-object v1

    .line 537
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 538
    .line 539
    .line 540
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 541
    .line 542
    return-object v0

    .line 543
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast v0, Le20/g;

    .line 546
    .line 547
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 548
    .line 549
    .line 550
    move-result-object v1

    .line 551
    move-object v2, v1

    .line 552
    check-cast v2, Le20/f;

    .line 553
    .line 554
    const/4 v15, 0x0

    .line 555
    const/16 v16, 0x1ffb

    .line 556
    .line 557
    const/4 v3, 0x0

    .line 558
    const/4 v4, 0x0

    .line 559
    const/4 v5, 0x1

    .line 560
    const/4 v6, 0x0

    .line 561
    const/4 v7, 0x0

    .line 562
    const/4 v8, 0x0

    .line 563
    const/4 v9, 0x0

    .line 564
    const/4 v10, 0x0

    .line 565
    const/4 v11, 0x0

    .line 566
    const/4 v12, 0x0

    .line 567
    const/4 v13, 0x0

    .line 568
    const/4 v14, 0x0

    .line 569
    invoke-static/range {v2 .. v16}, Le20/f;->a(Le20/f;ZZZLe20/e;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ld20/a;Ld20/a;Ld20/a;Ld20/b;Ld20/b;Ld20/b;I)Le20/f;

    .line 570
    .line 571
    .line 572
    move-result-object v1

    .line 573
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 574
    .line 575
    .line 576
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 577
    .line 578
    return-object v0

    .line 579
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 580
    .line 581
    check-cast v0, Le20/g;

    .line 582
    .line 583
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 584
    .line 585
    .line 586
    new-instance v1, Ld2/g;

    .line 587
    .line 588
    const/4 v2, 0x7

    .line 589
    invoke-direct {v1, v0, v2}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 590
    .line 591
    .line 592
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 593
    .line 594
    .line 595
    iget-object v0, v0, Le20/g;->m:Lbd0/c;

    .line 596
    .line 597
    const/16 v1, 0x1e

    .line 598
    .line 599
    and-int/lit8 v2, v1, 0x2

    .line 600
    .line 601
    const/4 v3, 0x0

    .line 602
    const/4 v4, 0x1

    .line 603
    if-eqz v2, :cond_1

    .line 604
    .line 605
    move v7, v4

    .line 606
    goto :goto_0

    .line 607
    :cond_1
    move v7, v3

    .line 608
    :goto_0
    and-int/lit8 v2, v1, 0x4

    .line 609
    .line 610
    if-eqz v2, :cond_2

    .line 611
    .line 612
    move v8, v4

    .line 613
    goto :goto_1

    .line 614
    :cond_2
    move v8, v3

    .line 615
    :goto_1
    and-int/lit8 v2, v1, 0x8

    .line 616
    .line 617
    if-eqz v2, :cond_3

    .line 618
    .line 619
    move v9, v3

    .line 620
    goto :goto_2

    .line 621
    :cond_3
    move v9, v4

    .line 622
    :goto_2
    and-int/lit8 v1, v1, 0x10

    .line 623
    .line 624
    if-eqz v1, :cond_4

    .line 625
    .line 626
    move v10, v3

    .line 627
    goto :goto_3

    .line 628
    :cond_4
    move v10, v4

    .line 629
    :goto_3
    iget-object v0, v0, Lbd0/c;->a:Lbd0/a;

    .line 630
    .line 631
    new-instance v6, Ljava/net/URL;

    .line 632
    .line 633
    const-string v1, "https://go.skoda.eu/driving-score"

    .line 634
    .line 635
    invoke-direct {v6, v1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 636
    .line 637
    .line 638
    move-object v5, v0

    .line 639
    check-cast v5, Lzc0/b;

    .line 640
    .line 641
    invoke-virtual/range {v5 .. v10}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 642
    .line 643
    .line 644
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 645
    .line 646
    return-object v0

    .line 647
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 648
    .line 649
    check-cast v0, Le20/g;

    .line 650
    .line 651
    iget-object v0, v0, Le20/g;->l:Lc20/e;

    .line 652
    .line 653
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 654
    .line 655
    .line 656
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 657
    .line 658
    return-object v0

    .line 659
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 660
    .line 661
    check-cast v0, Le20/g;

    .line 662
    .line 663
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 664
    .line 665
    .line 666
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 667
    .line 668
    .line 669
    move-result-object v1

    .line 670
    new-instance v2, Ldm0/h;

    .line 671
    .line 672
    const/16 v3, 0x8

    .line 673
    .line 674
    const/4 v4, 0x0

    .line 675
    invoke-direct {v2, v0, v4, v3}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 676
    .line 677
    .line 678
    const/4 v0, 0x3

    .line 679
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 680
    .line 681
    .line 682
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 683
    .line 684
    return-object v0

    .line 685
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 686
    .line 687
    check-cast v0, Le20/g;

    .line 688
    .line 689
    iget-object v0, v0, Le20/g;->h:Ltr0/b;

    .line 690
    .line 691
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 692
    .line 693
    .line 694
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 695
    .line 696
    return-object v0

    .line 697
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
