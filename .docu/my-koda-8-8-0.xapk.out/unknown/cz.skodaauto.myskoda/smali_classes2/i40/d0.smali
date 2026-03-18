.class public final synthetic Li40/d0;
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
    iput p7, p0, Li40/d0;->d:I

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
    iget v0, p0, Li40/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lh40/f1;

    .line 9
    .line 10
    iget-object p0, p0, Lh40/f1;->k:Lf40/m2;

    .line 11
    .line 12
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lh40/f1;

    .line 21
    .line 22
    iget-object p0, p0, Lh40/f1;->j:Ltr0/b;

    .line 23
    .line 24
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lh40/a1;

    .line 33
    .line 34
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    check-cast v0, Lh40/z0;

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    const/4 v2, 0x3

    .line 42
    const/4 v3, 0x0

    .line 43
    invoke-static {v0, v3, v1, v3, v2}, Lh40/z0;->a(Lh40/z0;Lh40/y;ZLql0/g;I)Lh40/z0;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 48
    .line 49
    .line 50
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast p0, Lh40/a1;

    .line 56
    .line 57
    iget-object p0, p0, Lh40/a1;->h:Ltr0/b;

    .line 58
    .line 59
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Lh40/a1;

    .line 68
    .line 69
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    check-cast v0, Lh40/z0;

    .line 74
    .line 75
    iget-object v0, v0, Lh40/z0;->a:Lh40/y;

    .line 76
    .line 77
    if-nez v0, :cond_0

    .line 78
    .line 79
    goto :goto_0

    .line 80
    :cond_0
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    new-instance v2, Lg60/w;

    .line 85
    .line 86
    const/16 v3, 0x11

    .line 87
    .line 88
    const/4 v4, 0x0

    .line 89
    invoke-direct {v2, v3, p0, v0, v4}, Lg60/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x3

    .line 93
    invoke-static {v1, v4, v4, v2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 94
    .line 95
    .line 96
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0

    .line 99
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast p0, Lh40/y0;

    .line 102
    .line 103
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    move-object v1, v0

    .line 108
    check-cast v1, Lh40/x0;

    .line 109
    .line 110
    const/4 v5, 0x0

    .line 111
    const/16 v6, 0xe

    .line 112
    .line 113
    const/4 v2, 0x0

    .line 114
    const/4 v3, 0x0

    .line 115
    const/4 v4, 0x0

    .line 116
    invoke-static/range {v1 .. v6}, Lh40/x0;->a(Lh40/x0;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;I)Lh40/x0;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 121
    .line 122
    .line 123
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast p0, Lh40/y0;

    .line 129
    .line 130
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    move-object v1, v0

    .line 135
    check-cast v1, Lh40/x0;

    .line 136
    .line 137
    const/4 v5, 0x0

    .line 138
    const/16 v6, 0xe

    .line 139
    .line 140
    const/4 v2, 0x1

    .line 141
    const/4 v3, 0x0

    .line 142
    const/4 v4, 0x0

    .line 143
    invoke-static/range {v1 .. v6}, Lh40/x0;->a(Lh40/x0;ZLjava/lang/String;Ljava/lang/String;Landroid/net/Uri;I)Lh40/x0;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 148
    .line 149
    .line 150
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 151
    .line 152
    return-object p0

    .line 153
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 154
    .line 155
    check-cast p0, Lh40/y0;

    .line 156
    .line 157
    iget-object v0, p0, Lh40/y0;->k:Lf40/q0;

    .line 158
    .line 159
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    iget-object v0, p0, Lh40/y0;->l:Lf40/p0;

    .line 163
    .line 164
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    iget-object v0, p0, Lh40/y0;->m:Lf40/l4;

    .line 168
    .line 169
    sget-object v1, Lg40/u0;->f:Lg40/u0;

    .line 170
    .line 171
    iget-object v0, v0, Lf40/l4;->a:Lf40/c1;

    .line 172
    .line 173
    check-cast v0, Ld40/e;

    .line 174
    .line 175
    iput-object v1, v0, Ld40/e;->b:Lg40/u0;

    .line 176
    .line 177
    iget-object p0, p0, Lh40/y0;->n:Lf40/o2;

    .line 178
    .line 179
    iget-object p0, p0, Lf40/o2;->a:Lf40/f1;

    .line 180
    .line 181
    check-cast p0, Liy/b;

    .line 182
    .line 183
    new-instance v0, Lul0/c;

    .line 184
    .line 185
    sget-object v1, Lly/b;->Y3:Lly/b;

    .line 186
    .line 187
    sget-object v3, Lly/b;->i:Lly/b;

    .line 188
    .line 189
    const/4 v4, 0x0

    .line 190
    const/16 v5, 0x38

    .line 191
    .line 192
    const/4 v2, 0x1

    .line 193
    invoke-direct/range {v0 .. v5}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 194
    .line 195
    .line 196
    invoke-virtual {p0, v0}, Liy/b;->b(Lul0/e;)V

    .line 197
    .line 198
    .line 199
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    return-object p0

    .line 202
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast p0, Lh40/w0;

    .line 205
    .line 206
    iget-object p0, p0, Lh40/w0;->i:Ltr0/b;

    .line 207
    .line 208
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 212
    .line 213
    return-object p0

    .line 214
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 215
    .line 216
    check-cast p0, Lh40/w0;

    .line 217
    .line 218
    iget-object p0, p0, Lh40/w0;->h:Lf40/a2;

    .line 219
    .line 220
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 221
    .line 222
    .line 223
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 224
    .line 225
    return-object p0

    .line 226
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 227
    .line 228
    check-cast p0, Lh40/u0;

    .line 229
    .line 230
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    check-cast v0, Lh40/t0;

    .line 235
    .line 236
    const/4 v1, 0x0

    .line 237
    const/16 v2, 0xb

    .line 238
    .line 239
    const/4 v3, 0x0

    .line 240
    invoke-static {v0, v3, v1, v2}, Lh40/t0;->a(Lh40/t0;ZLql0/g;I)Lh40/t0;

    .line 241
    .line 242
    .line 243
    move-result-object v0

    .line 244
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 245
    .line 246
    .line 247
    iget-object p0, p0, Lh40/u0;->h:Ltr0/b;

    .line 248
    .line 249
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 250
    .line 251
    .line 252
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 253
    .line 254
    return-object p0

    .line 255
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 256
    .line 257
    check-cast p0, Lh40/u0;

    .line 258
    .line 259
    iget-object v0, p0, Lh40/u0;->i:Lf40/l4;

    .line 260
    .line 261
    sget-object v1, Lg40/u0;->f:Lg40/u0;

    .line 262
    .line 263
    invoke-virtual {v0, v1}, Lf40/l4;->a(Lg40/u0;)V

    .line 264
    .line 265
    .line 266
    iget-object p0, p0, Lh40/u0;->h:Ltr0/b;

    .line 267
    .line 268
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object p0

    .line 274
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast p0, Lh40/u0;

    .line 277
    .line 278
    iget-object v0, p0, Lh40/u0;->i:Lf40/l4;

    .line 279
    .line 280
    sget-object v1, Lg40/u0;->e:Lg40/u0;

    .line 281
    .line 282
    invoke-virtual {v0, v1}, Lf40/l4;->a(Lg40/u0;)V

    .line 283
    .line 284
    .line 285
    iget-object p0, p0, Lh40/u0;->h:Ltr0/b;

    .line 286
    .line 287
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 291
    .line 292
    return-object p0

    .line 293
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 294
    .line 295
    check-cast p0, Lh40/k;

    .line 296
    .line 297
    invoke-virtual {p0}, Lh40/k;->h()V

    .line 298
    .line 299
    .line 300
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    return-object p0

    .line 303
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 304
    .line 305
    check-cast p0, Lh40/k;

    .line 306
    .line 307
    iget-object p0, p0, Lh40/k;->r:Lf40/b3;

    .line 308
    .line 309
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    return-object p0

    .line 315
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast p0, Lh40/k;

    .line 318
    .line 319
    iget-object p0, p0, Lh40/k;->n:Lf40/q1;

    .line 320
    .line 321
    iget-object p0, p0, Lf40/q1;->a:Lf40/f1;

    .line 322
    .line 323
    check-cast p0, Liy/b;

    .line 324
    .line 325
    sget-object v0, Lly/b;->F1:Lly/b;

    .line 326
    .line 327
    invoke-interface {p0, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 328
    .line 329
    .line 330
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 331
    .line 332
    return-object p0

    .line 333
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 334
    .line 335
    check-cast p0, Lh40/k;

    .line 336
    .line 337
    iget-object p0, p0, Lh40/k;->n:Lf40/q1;

    .line 338
    .line 339
    iget-object p0, p0, Lf40/q1;->a:Lf40/f1;

    .line 340
    .line 341
    check-cast p0, Liy/b;

    .line 342
    .line 343
    sget-object v0, Lly/b;->F1:Lly/b;

    .line 344
    .line 345
    invoke-interface {p0, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 346
    .line 347
    .line 348
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 349
    .line 350
    return-object p0

    .line 351
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 352
    .line 353
    check-cast p0, Lh40/k;

    .line 354
    .line 355
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 356
    .line 357
    .line 358
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 359
    .line 360
    .line 361
    move-result-object v0

    .line 362
    new-instance v1, Lh40/h;

    .line 363
    .line 364
    const/4 v2, 0x0

    .line 365
    const/4 v3, 0x0

    .line 366
    invoke-direct {v1, p0, v3, v2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 367
    .line 368
    .line 369
    const/4 p0, 0x3

    .line 370
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 371
    .line 372
    .line 373
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 374
    .line 375
    return-object p0

    .line 376
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 377
    .line 378
    check-cast p0, Lh40/k;

    .line 379
    .line 380
    iget-object p0, p0, Lh40/k;->m:Lf40/y2;

    .line 381
    .line 382
    iget-object p0, p0, Lf40/y2;->a:Lf40/f1;

    .line 383
    .line 384
    check-cast p0, Liy/b;

    .line 385
    .line 386
    sget-object v0, Lly/b;->e3:Lly/b;

    .line 387
    .line 388
    invoke-interface {p0, v0}, Ltl0/a;->a(Lul0/f;)V

    .line 389
    .line 390
    .line 391
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    return-object p0

    .line 394
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast p0, Lh40/k;

    .line 397
    .line 398
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 399
    .line 400
    .line 401
    move-result-object v0

    .line 402
    move-object v1, v0

    .line 403
    check-cast v1, Lh40/f;

    .line 404
    .line 405
    const/4 v5, 0x1

    .line 406
    const/4 v6, 0x7

    .line 407
    const/4 v2, 0x0

    .line 408
    const/4 v3, 0x0

    .line 409
    const/4 v4, 0x0

    .line 410
    invoke-static/range {v1 .. v6}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 411
    .line 412
    .line 413
    move-result-object v0

    .line 414
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 415
    .line 416
    .line 417
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 418
    .line 419
    return-object p0

    .line 420
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 421
    .line 422
    check-cast p0, Lh40/k;

    .line 423
    .line 424
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 425
    .line 426
    .line 427
    move-result-object v0

    .line 428
    move-object v1, v0

    .line 429
    check-cast v1, Lh40/f;

    .line 430
    .line 431
    const/4 v5, 0x0

    .line 432
    const/4 v6, 0x7

    .line 433
    const/4 v2, 0x0

    .line 434
    const/4 v3, 0x0

    .line 435
    const/4 v4, 0x0

    .line 436
    invoke-static/range {v1 .. v6}, Lh40/f;->a(Lh40/f;Lh40/m;ZLjava/lang/String;ZI)Lh40/f;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 441
    .line 442
    .line 443
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 444
    .line 445
    return-object p0

    .line 446
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 447
    .line 448
    check-cast p0, Lh40/k;

    .line 449
    .line 450
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 451
    .line 452
    .line 453
    new-instance v0, Ld2/g;

    .line 454
    .line 455
    const/16 v1, 0x1a

    .line 456
    .line 457
    invoke-direct {v0, p0, v1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 458
    .line 459
    .line 460
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 461
    .line 462
    .line 463
    iget-object p0, p0, Lh40/k;->h:Ltr0/b;

    .line 464
    .line 465
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 466
    .line 467
    .line 468
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 469
    .line 470
    return-object p0

    .line 471
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 472
    .line 473
    check-cast p0, Lh40/s0;

    .line 474
    .line 475
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 476
    .line 477
    .line 478
    move-result-object v0

    .line 479
    move-object v1, v0

    .line 480
    check-cast v1, Lh40/r0;

    .line 481
    .line 482
    const/4 v7, 0x0

    .line 483
    const/16 v8, 0x3d

    .line 484
    .line 485
    const/4 v2, 0x0

    .line 486
    const/4 v3, 0x0

    .line 487
    const/4 v4, 0x0

    .line 488
    const/4 v5, 0x0

    .line 489
    const/4 v6, 0x0

    .line 490
    invoke-static/range {v1 .. v8}, Lh40/r0;->a(Lh40/r0;ZLql0/g;ZZLh40/b;Ljava/util/List;I)Lh40/r0;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 495
    .line 496
    .line 497
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 498
    .line 499
    return-object p0

    .line 500
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 501
    .line 502
    check-cast p0, Lh40/s0;

    .line 503
    .line 504
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 505
    .line 506
    .line 507
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 508
    .line 509
    .line 510
    move-result-object v0

    .line 511
    new-instance v1, Lh40/q0;

    .line 512
    .line 513
    const/4 v2, 0x1

    .line 514
    const/4 v3, 0x0

    .line 515
    invoke-direct {v1, p0, v3, v2}, Lh40/q0;-><init>(Lh40/s0;Lkotlin/coroutines/Continuation;I)V

    .line 516
    .line 517
    .line 518
    const/4 p0, 0x3

    .line 519
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 520
    .line 521
    .line 522
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 523
    .line 524
    return-object p0

    .line 525
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 526
    .line 527
    check-cast p0, Lh40/s0;

    .line 528
    .line 529
    iget-object p0, p0, Lh40/s0;->h:Ltr0/b;

    .line 530
    .line 531
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 535
    .line 536
    return-object p0

    .line 537
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 538
    .line 539
    check-cast p0, Lh40/p0;

    .line 540
    .line 541
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 542
    .line 543
    .line 544
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 545
    .line 546
    .line 547
    move-result-object v0

    .line 548
    new-instance v1, Lh40/o0;

    .line 549
    .line 550
    const/4 v2, 0x1

    .line 551
    const/4 v3, 0x0

    .line 552
    invoke-direct {v1, p0, v3, v2}, Lh40/o0;-><init>(Lh40/p0;Lkotlin/coroutines/Continuation;I)V

    .line 553
    .line 554
    .line 555
    const/4 p0, 0x3

    .line 556
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 557
    .line 558
    .line 559
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 560
    .line 561
    return-object p0

    .line 562
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 563
    .line 564
    check-cast p0, Lh40/p0;

    .line 565
    .line 566
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 567
    .line 568
    .line 569
    new-instance v0, Ld2/g;

    .line 570
    .line 571
    const/16 v1, 0x1c

    .line 572
    .line 573
    invoke-direct {v0, p0, v1}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 574
    .line 575
    .line 576
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 577
    .line 578
    .line 579
    iget-object p0, p0, Lh40/p0;->i:Ltr0/b;

    .line 580
    .line 581
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 582
    .line 583
    .line 584
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 585
    .line 586
    return-object p0

    .line 587
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 588
    .line 589
    check-cast p0, Lh40/p0;

    .line 590
    .line 591
    iget-object p0, p0, Lh40/p0;->i:Ltr0/b;

    .line 592
    .line 593
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 594
    .line 595
    .line 596
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 597
    .line 598
    return-object p0

    .line 599
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 600
    .line 601
    check-cast p0, Lh40/l0;

    .line 602
    .line 603
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 604
    .line 605
    .line 606
    move-result-object v0

    .line 607
    check-cast v0, Lh40/k0;

    .line 608
    .line 609
    iget v0, v0, Lh40/k0;->d:I

    .line 610
    .line 611
    add-int/lit8 v0, v0, 0x1

    .line 612
    .line 613
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 614
    .line 615
    .line 616
    move-result-object v1

    .line 617
    check-cast v1, Lh40/k0;

    .line 618
    .line 619
    iget-object v1, v1, Lh40/k0;->c:Ljava/util/List;

    .line 620
    .line 621
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 622
    .line 623
    .line 624
    move-result v1

    .line 625
    add-int/lit8 v1, v1, -0x1

    .line 626
    .line 627
    if-le v0, v1, :cond_1

    .line 628
    .line 629
    move v0, v1

    .line 630
    :cond_1
    invoke-virtual {p0, v0}, Lh40/l0;->h(I)V

    .line 631
    .line 632
    .line 633
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 634
    .line 635
    return-object p0

    .line 636
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 637
    .line 638
    check-cast p0, Lh40/l0;

    .line 639
    .line 640
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 641
    .line 642
    .line 643
    move-result-object v0

    .line 644
    check-cast v0, Lh40/k0;

    .line 645
    .line 646
    iget v0, v0, Lh40/k0;->d:I

    .line 647
    .line 648
    add-int/lit8 v0, v0, -0x1

    .line 649
    .line 650
    if-gez v0, :cond_2

    .line 651
    .line 652
    const/4 v0, 0x0

    .line 653
    :cond_2
    invoke-virtual {p0, v0}, Lh40/l0;->h(I)V

    .line 654
    .line 655
    .line 656
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 657
    .line 658
    return-object p0

    .line 659
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
