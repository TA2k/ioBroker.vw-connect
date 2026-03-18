.class public final synthetic Ll20/c;
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
    iput p7, p0, Ll20/c;->d:I

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
    iget v0, p0, Ll20/c;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lmj/a;

    .line 9
    .line 10
    iget-object p0, p0, Lmj/a;->a:Landroid/content/SharedPreferences;

    .line 11
    .line 12
    const-string v0, "headless-subscription"

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    invoke-interface {p0, v0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    if-eqz p0, :cond_0

    .line 20
    .line 21
    sget-object v0, Lmj/b;->a:Lvz0/t;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    sget-object v1, Lnj/h;->Companion:Lnj/g;

    .line 27
    .line 28
    invoke-virtual {v1}, Lnj/g;->serializer()Lqz0/a;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Lqz0/a;

    .line 37
    .line 38
    invoke-virtual {v0, p0, v1}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    move-object v1, p0

    .line 43
    check-cast v1, Lnj/h;

    .line 44
    .line 45
    :cond_0
    return-object v1

    .line 46
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast p0, Lmj/k;

    .line 49
    .line 50
    invoke-virtual {p0}, Lmj/k;->b()V

    .line 51
    .line 52
    .line 53
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object p0

    .line 56
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Ll60/e;

    .line 59
    .line 60
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, Ll60/c;

    .line 65
    .line 66
    iget-object v0, v0, Ll60/c;->b:Lql0/g;

    .line 67
    .line 68
    if-eqz v0, :cond_1

    .line 69
    .line 70
    const/4 v0, 0x1

    .line 71
    :goto_0
    move v5, v0

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    const/4 v0, 0x0

    .line 74
    goto :goto_0

    .line 75
    :goto_1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 76
    .line 77
    .line 78
    move-result-object v0

    .line 79
    move-object v1, v0

    .line 80
    check-cast v1, Ll60/c;

    .line 81
    .line 82
    const/4 v8, 0x0

    .line 83
    const/16 v9, 0x71

    .line 84
    .line 85
    const/4 v2, 0x0

    .line 86
    const/4 v3, 0x0

    .line 87
    const/4 v4, 0x0

    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    invoke-static/range {v1 .. v9}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 95
    .line 96
    .line 97
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    return-object p0

    .line 100
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Ll60/e;

    .line 103
    .line 104
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    new-instance v1, Ll60/a;

    .line 112
    .line 113
    const/4 v2, 0x2

    .line 114
    const/4 v3, 0x0

    .line 115
    invoke-direct {v1, p0, v3, v2}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

    .line 116
    .line 117
    .line 118
    const/4 p0, 0x3

    .line 119
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 120
    .line 121
    .line 122
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0

    .line 125
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Ll60/e;

    .line 128
    .line 129
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 130
    .line 131
    .line 132
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    new-instance v1, Ll60/a;

    .line 137
    .line 138
    const/4 v2, 0x1

    .line 139
    const/4 v3, 0x0

    .line 140
    invoke-direct {v1, p0, v3, v2}, Ll60/a;-><init>(Ll60/e;Lkotlin/coroutines/Continuation;I)V

    .line 141
    .line 142
    .line 143
    const/4 p0, 0x3

    .line 144
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 145
    .line 146
    .line 147
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 148
    .line 149
    return-object p0

    .line 150
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast p0, Ll60/e;

    .line 153
    .line 154
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 155
    .line 156
    .line 157
    move-result-object v0

    .line 158
    move-object v1, v0

    .line 159
    check-cast v1, Ll60/c;

    .line 160
    .line 161
    const/4 v8, 0x0

    .line 162
    const/16 v9, 0x5f

    .line 163
    .line 164
    const/4 v2, 0x0

    .line 165
    const/4 v3, 0x0

    .line 166
    const/4 v4, 0x0

    .line 167
    const/4 v5, 0x0

    .line 168
    const/4 v6, 0x0

    .line 169
    const/4 v7, 0x0

    .line 170
    invoke-static/range {v1 .. v9}, Ll60/c;->a(Ll60/c;ZLql0/g;Lql0/g;ZLjava/util/ArrayList;ZZI)Ll60/c;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 175
    .line 176
    .line 177
    const/4 v0, 0x0

    .line 178
    iput-object v0, p0, Ll60/e;->r:Lap0/p;

    .line 179
    .line 180
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    return-object p0

    .line 183
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p0, Ll60/e;

    .line 186
    .line 187
    iget-object p0, p0, Ll60/e;->n:Ltr0/b;

    .line 188
    .line 189
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object p0

    .line 195
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast p0, Lqi/a;

    .line 198
    .line 199
    iget-object p0, p0, Lqi/a;->a:Landroid/content/SharedPreferences;

    .line 200
    .line 201
    const-string v0, "data"

    .line 202
    .line 203
    const/4 v1, 0x0

    .line 204
    invoke-interface {p0, v0, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    if-eqz p0, :cond_2

    .line 209
    .line 210
    sget-object v0, Lqi/b;->a:Lvz0/t;

    .line 211
    .line 212
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 213
    .line 214
    .line 215
    sget-object v1, Lmi/c;->Companion:Lmi/b;

    .line 216
    .line 217
    invoke-virtual {v1}, Lmi/b;->serializer()Lqz0/a;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 222
    .line 223
    .line 224
    move-result-object v1

    .line 225
    check-cast v1, Lqz0/a;

    .line 226
    .line 227
    invoke-virtual {v0, p0, v1}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object p0

    .line 231
    move-object v1, p0

    .line 232
    check-cast v1, Lmi/c;

    .line 233
    .line 234
    :cond_2
    return-object v1

    .line 235
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast p0, Lla/u;

    .line 238
    .line 239
    iget-object v0, p0, Lla/u;->a:Lpw0/a;

    .line 240
    .line 241
    const/4 v1, 0x0

    .line 242
    if-eqz v0, :cond_5

    .line 243
    .line 244
    invoke-static {v0, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {p0}, Lla/u;->h()Lla/h;

    .line 248
    .line 249
    .line 250
    iget-object p0, p0, Lla/u;->e:Lla/r;

    .line 251
    .line 252
    if-eqz p0, :cond_4

    .line 253
    .line 254
    iget-object v0, p0, Lla/r;->f:Lna/b;

    .line 255
    .line 256
    invoke-interface {v0}, Ljava/lang/AutoCloseable;->close()V

    .line 257
    .line 258
    .line 259
    iget-object p0, p0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 260
    .line 261
    if-eqz p0, :cond_3

    .line 262
    .line 263
    invoke-interface {p0}, Ljava/io/Closeable;->close()V

    .line 264
    .line 265
    .line 266
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 267
    .line 268
    return-object p0

    .line 269
    :cond_4
    const-string p0, "connectionManager"

    .line 270
    .line 271
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    throw v1

    .line 275
    :cond_5
    const-string p0, "coroutineScope"

    .line 276
    .line 277
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 278
    .line 279
    .line 280
    throw v1

    .line 281
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 282
    .line 283
    check-cast p0, Lk30/h;

    .line 284
    .line 285
    iget-object v0, p0, Lk30/h;->i:Li30/h;

    .line 286
    .line 287
    iget-object v0, v0, Li30/h;->a:Li30/d;

    .line 288
    .line 289
    check-cast v0, Lg30/a;

    .line 290
    .line 291
    const/4 v1, 0x0

    .line 292
    iput-boolean v1, v0, Lg30/a;->c:Z

    .line 293
    .line 294
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    move-object v1, v0

    .line 299
    check-cast v1, Lk30/e;

    .line 300
    .line 301
    const/4 v13, 0x0

    .line 302
    const/16 v14, 0xffd

    .line 303
    .line 304
    const/4 v2, 0x0

    .line 305
    const/4 v3, 0x0

    .line 306
    const/4 v4, 0x0

    .line 307
    const/4 v5, 0x0

    .line 308
    const/4 v6, 0x0

    .line 309
    const/4 v7, 0x0

    .line 310
    const/4 v8, 0x0

    .line 311
    const/4 v9, 0x0

    .line 312
    const/4 v10, 0x0

    .line 313
    const/4 v11, 0x0

    .line 314
    const/4 v12, 0x0

    .line 315
    invoke-static/range {v1 .. v14}, Lk30/e;->a(Lk30/e;Lss0/e;ZZLjava/lang/String;Ljava/lang/String;ZLjava/util/ArrayList;ZZLql0/g;Ler0/g;Llf0/i;I)Lk30/e;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 320
    .line 321
    .line 322
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 323
    .line 324
    return-object p0

    .line 325
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast p0, Lk30/h;

    .line 328
    .line 329
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 330
    .line 331
    .line 332
    new-instance v0, Lt61/d;

    .line 333
    .line 334
    const/16 v1, 0x15

    .line 335
    .line 336
    invoke-direct {v0, v1}, Lt61/d;-><init>(I)V

    .line 337
    .line 338
    .line 339
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 340
    .line 341
    .line 342
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    check-cast v0, Lk30/e;

    .line 347
    .line 348
    iget-boolean v0, v0, Lk30/e;->b:Z

    .line 349
    .line 350
    if-nez v0, :cond_6

    .line 351
    .line 352
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 353
    .line 354
    .line 355
    move-result-object v0

    .line 356
    new-instance v1, Lk30/c;

    .line 357
    .line 358
    const/4 v2, 0x1

    .line 359
    const/4 v3, 0x0

    .line 360
    invoke-direct {v1, p0, v3, v2}, Lk30/c;-><init>(Lk30/h;Lkotlin/coroutines/Continuation;I)V

    .line 361
    .line 362
    .line 363
    const/4 p0, 0x3

    .line 364
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 365
    .line 366
    .line 367
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 368
    .line 369
    return-object p0

    .line 370
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast p0, Lk30/h;

    .line 373
    .line 374
    iget-object p0, p0, Lk30/h;->k:Ltr0/b;

    .line 375
    .line 376
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 380
    .line 381
    return-object p0

    .line 382
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 383
    .line 384
    check-cast p0, Lk30/b;

    .line 385
    .line 386
    iget-object p0, p0, Lk30/b;->h:Li30/f;

    .line 387
    .line 388
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    return-object p0

    .line 394
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast p0, Lk20/r;

    .line 397
    .line 398
    iget-object p0, p0, Lk20/r;->j:Ltr0/b;

    .line 399
    .line 400
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 401
    .line 402
    .line 403
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 404
    .line 405
    return-object p0

    .line 406
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast p0, Lk20/q;

    .line 409
    .line 410
    iget-object p0, p0, Lk20/q;->m:Li20/k;

    .line 411
    .line 412
    iget-object p0, p0, Li20/k;->a:Li20/c;

    .line 413
    .line 414
    const/4 v0, 0x0

    .line 415
    check-cast p0, Liy/b;

    .line 416
    .line 417
    invoke-virtual {p0, v0}, Liy/b;->d(Lvg0/d;)V

    .line 418
    .line 419
    .line 420
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 421
    .line 422
    return-object p0

    .line 423
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 424
    .line 425
    check-cast p0, Lk20/q;

    .line 426
    .line 427
    iget-object p0, p0, Lk20/q;->l:Li20/m;

    .line 428
    .line 429
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 430
    .line 431
    .line 432
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 433
    .line 434
    return-object p0

    .line 435
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 436
    .line 437
    check-cast p0, Lk20/q;

    .line 438
    .line 439
    iget-object p0, p0, Lk20/q;->k:Li20/j;

    .line 440
    .line 441
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 442
    .line 443
    .line 444
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 445
    .line 446
    return-object p0

    .line 447
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 448
    .line 449
    check-cast p0, Lk20/q;

    .line 450
    .line 451
    iget-object p0, p0, Lk20/q;->j:Li20/l;

    .line 452
    .line 453
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 454
    .line 455
    .line 456
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 457
    .line 458
    return-object p0

    .line 459
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 460
    .line 461
    check-cast p0, Lk20/q;

    .line 462
    .line 463
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 464
    .line 465
    .line 466
    move-result-object v0

    .line 467
    move-object v1, v0

    .line 468
    check-cast v1, Lk20/o;

    .line 469
    .line 470
    const/4 v8, 0x0

    .line 471
    const/16 v9, 0x77

    .line 472
    .line 473
    const/4 v2, 0x0

    .line 474
    const/4 v3, 0x0

    .line 475
    const/4 v4, 0x0

    .line 476
    const/4 v5, 0x0

    .line 477
    const/4 v6, 0x0

    .line 478
    const/4 v7, 0x0

    .line 479
    invoke-static/range {v1 .. v9}, Lk20/o;->a(Lk20/o;Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Lj20/h;I)Lk20/o;

    .line 480
    .line 481
    .line 482
    move-result-object v0

    .line 483
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 484
    .line 485
    .line 486
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 487
    .line 488
    return-object p0

    .line 489
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 490
    .line 491
    check-cast p0, Lk20/q;

    .line 492
    .line 493
    iget-object p0, p0, Lk20/q;->r:Ltr0/b;

    .line 494
    .line 495
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 499
    .line 500
    return-object p0

    .line 501
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 502
    .line 503
    check-cast p0, Lk20/q;

    .line 504
    .line 505
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 506
    .line 507
    .line 508
    move-result-object v0

    .line 509
    check-cast v0, Lk20/o;

    .line 510
    .line 511
    iget-object v0, v0, Lk20/o;->a:Ljava/lang/String;

    .line 512
    .line 513
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 514
    .line 515
    .line 516
    move-result-object v1

    .line 517
    new-instance v2, Lk20/p;

    .line 518
    .line 519
    const/4 v3, 0x1

    .line 520
    const/4 v4, 0x0

    .line 521
    invoke-direct {v2, p0, v0, v4, v3}, Lk20/p;-><init>(Lk20/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 522
    .line 523
    .line 524
    const/4 p0, 0x3

    .line 525
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 526
    .line 527
    .line 528
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 529
    .line 530
    return-object p0

    .line 531
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 532
    .line 533
    check-cast p0, Lk20/n;

    .line 534
    .line 535
    iget-object p0, p0, Lk20/n;->h:Ltr0/b;

    .line 536
    .line 537
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 538
    .line 539
    .line 540
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 541
    .line 542
    return-object p0

    .line 543
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 544
    .line 545
    check-cast p0, Lk20/m;

    .line 546
    .line 547
    iget-object p0, p0, Lk20/m;->i:Ltr0/b;

    .line 548
    .line 549
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 550
    .line 551
    .line 552
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 553
    .line 554
    return-object p0

    .line 555
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast p0, Lk20/h;

    .line 558
    .line 559
    iget-object p0, p0, Lk20/h;->j:Li20/k;

    .line 560
    .line 561
    iget-object p0, p0, Li20/k;->a:Li20/c;

    .line 562
    .line 563
    check-cast p0, Liy/b;

    .line 564
    .line 565
    sget-object v0, Lvg0/d;->a:Lvg0/d;

    .line 566
    .line 567
    invoke-virtual {p0, v0}, Liy/b;->d(Lvg0/d;)V

    .line 568
    .line 569
    .line 570
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 571
    .line 572
    return-object p0

    .line 573
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 574
    .line 575
    check-cast p0, Lk20/h;

    .line 576
    .line 577
    iget-object p0, p0, Lk20/h;->h:Ltr0/b;

    .line 578
    .line 579
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 580
    .line 581
    .line 582
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 583
    .line 584
    return-object p0

    .line 585
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 586
    .line 587
    check-cast p0, Lk20/g;

    .line 588
    .line 589
    iget-object p0, p0, Lk20/g;->h:Ltr0/b;

    .line 590
    .line 591
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 592
    .line 593
    .line 594
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 595
    .line 596
    return-object p0

    .line 597
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 598
    .line 599
    check-cast p0, Lk20/e;

    .line 600
    .line 601
    iget-object p0, p0, Lk20/e;->j:Ltr0/b;

    .line 602
    .line 603
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 604
    .line 605
    .line 606
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 607
    .line 608
    return-object p0

    .line 609
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 610
    .line 611
    check-cast p0, Lk20/e;

    .line 612
    .line 613
    iget-object p0, p0, Lk20/e;->h:Li20/n;

    .line 614
    .line 615
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 616
    .line 617
    .line 618
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 619
    .line 620
    return-object p0

    .line 621
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 622
    .line 623
    check-cast p0, Lk20/c;

    .line 624
    .line 625
    iget-object p0, p0, Lk20/c;->j:Ltr0/b;

    .line 626
    .line 627
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 628
    .line 629
    .line 630
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 631
    .line 632
    return-object p0

    .line 633
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 634
    .line 635
    check-cast p0, Lk20/c;

    .line 636
    .line 637
    iget-object p0, p0, Lk20/c;->j:Ltr0/b;

    .line 638
    .line 639
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 640
    .line 641
    .line 642
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 643
    .line 644
    return-object p0

    .line 645
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
