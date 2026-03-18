.class public final synthetic Ld90/n;
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
    iput p7, p0, Ld90/n;->d:I

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
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld90/n;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Le20/g;

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
    check-cast v2, Le20/f;

    .line 18
    .line 19
    const/4 v15, 0x0

    .line 20
    const/16 v16, 0x1ffb

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
    const/4 v13, 0x0

    .line 33
    const/4 v14, 0x0

    .line 34
    invoke-static/range {v2 .. v16}, Le20/f;->a(Le20/f;ZZZLe20/e;Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Ld20/a;Ld20/a;Ld20/a;Ld20/b;Ld20/b;Ld20/b;I)Le20/f;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 39
    .line 40
    .line 41
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object v0

    .line 44
    :pswitch_0
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v0, Le20/b;

    .line 47
    .line 48
    iget-object v0, v0, Le20/b;->h:Lc20/f;

    .line 49
    .line 50
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    return-object v0

    .line 56
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v0, Le1/g0;

    .line 59
    .line 60
    iget-object v0, v0, Le1/g0;->y:Lc3/v;

    .line 61
    .line 62
    invoke-static {v0}, Lc3/v;->c1(Lc3/v;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    return-object v0

    .line 71
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v0, Lct0/h;

    .line 74
    .line 75
    iget-object v0, v0, Lct0/h;->p:Lat0/i;

    .line 76
    .line 77
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 81
    .line 82
    return-object v0

    .line 83
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v0, Lct0/h;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    new-instance v2, Lct0/b;

    .line 95
    .line 96
    const/4 v3, 0x3

    .line 97
    const/4 v4, 0x0

    .line 98
    invoke-direct {v2, v0, v4, v3}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    const/4 v0, 0x3

    .line 102
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 103
    .line 104
    .line 105
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    return-object v0

    .line 108
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v0, Lct0/h;

    .line 111
    .line 112
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    new-instance v2, Lct0/b;

    .line 120
    .line 121
    const/4 v3, 0x4

    .line 122
    const/4 v4, 0x0

    .line 123
    invoke-direct {v2, v0, v4, v3}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 124
    .line 125
    .line 126
    const/4 v0, 0x3

    .line 127
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 128
    .line 129
    .line 130
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object v0

    .line 133
    :pswitch_5
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v0, Lct0/h;

    .line 136
    .line 137
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    new-instance v1, La71/u;

    .line 141
    .line 142
    const/16 v2, 0x1d

    .line 143
    .line 144
    invoke-direct {v1, v0, v2}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 145
    .line 146
    .line 147
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 148
    .line 149
    .line 150
    iget-object v0, v0, Lct0/h;->l:Lat0/h;

    .line 151
    .line 152
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 156
    .line 157
    return-object v0

    .line 158
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v0, Lct0/h;

    .line 161
    .line 162
    iget-object v0, v0, Lct0/h;->i:Lat0/a;

    .line 163
    .line 164
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    return-object v0

    .line 170
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast v0, Lcl0/v;

    .line 173
    .line 174
    iget-object v0, v0, Lcl0/v;->h:Ltr0/b;

    .line 175
    .line 176
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    return-object v0

    .line 182
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 183
    .line 184
    check-cast v0, Lcl0/v;

    .line 185
    .line 186
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 187
    .line 188
    .line 189
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    new-instance v2, Lcl0/u;

    .line 194
    .line 195
    const/4 v3, 0x0

    .line 196
    const/4 v4, 0x0

    .line 197
    invoke-direct {v2, v0, v4, v3}, Lcl0/u;-><init>(Lcl0/v;Lkotlin/coroutines/Continuation;I)V

    .line 198
    .line 199
    .line 200
    const/4 v0, 0x3

    .line 201
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 202
    .line 203
    .line 204
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 205
    .line 206
    return-object v0

    .line 207
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 208
    .line 209
    check-cast v0, Lcl0/s;

    .line 210
    .line 211
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Lcl0/r;

    .line 216
    .line 217
    const/4 v2, 0x0

    .line 218
    const/4 v3, 0x1

    .line 219
    const/4 v4, 0x0

    .line 220
    invoke-static {v1, v4, v2, v3}, Lcl0/r;->a(Lcl0/r;Ljava/util/ArrayList;ZI)Lcl0/r;

    .line 221
    .line 222
    .line 223
    move-result-object v1

    .line 224
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 225
    .line 226
    .line 227
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 228
    .line 229
    return-object v0

    .line 230
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v0, Lcl0/s;

    .line 233
    .line 234
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    check-cast v1, Lcl0/r;

    .line 239
    .line 240
    const/4 v2, 0x0

    .line 241
    const/4 v3, 0x1

    .line 242
    invoke-static {v1, v2, v3, v3}, Lcl0/r;->a(Lcl0/r;Ljava/util/ArrayList;ZI)Lcl0/r;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 247
    .line 248
    .line 249
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 250
    .line 251
    return-object v0

    .line 252
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast v0, Lcl0/p;

    .line 255
    .line 256
    iget-object v0, v0, Lcl0/p;->h:Lal0/a1;

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
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 265
    .line 266
    check-cast v0, Lcl0/n;

    .line 267
    .line 268
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 269
    .line 270
    .line 271
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 272
    .line 273
    .line 274
    move-result-object v1

    .line 275
    new-instance v2, La50/a;

    .line 276
    .line 277
    const/16 v3, 0x18

    .line 278
    .line 279
    const/4 v4, 0x0

    .line 280
    invoke-direct {v2, v0, v4, v3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 281
    .line 282
    .line 283
    const/4 v0, 0x3

    .line 284
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 285
    .line 286
    .line 287
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    return-object v0

    .line 290
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 291
    .line 292
    check-cast v0, Lcl0/l;

    .line 293
    .line 294
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 295
    .line 296
    .line 297
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    new-instance v2, La50/a;

    .line 302
    .line 303
    const/16 v3, 0x17

    .line 304
    .line 305
    const/4 v4, 0x0

    .line 306
    invoke-direct {v2, v0, v4, v3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 307
    .line 308
    .line 309
    const/4 v0, 0x3

    .line 310
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 311
    .line 312
    .line 313
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 314
    .line 315
    return-object v0

    .line 316
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 317
    .line 318
    check-cast v0, Lcl0/j;

    .line 319
    .line 320
    iget-object v1, v0, Lcl0/j;->l:Lbl0/h;

    .line 321
    .line 322
    if-eqz v1, :cond_0

    .line 323
    .line 324
    iget-boolean v2, v1, Lbl0/h;->b:Z

    .line 325
    .line 326
    xor-int/lit8 v3, v2, 0x1

    .line 327
    .line 328
    const/4 v6, 0x0

    .line 329
    const/16 v7, 0x1d

    .line 330
    .line 331
    const/4 v2, 0x0

    .line 332
    const/4 v4, 0x0

    .line 333
    const/4 v5, 0x0

    .line 334
    invoke-static/range {v1 .. v7}, Lbl0/h;->a(Lbl0/h;Lbl0/e;ZLjava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;I)Lbl0/h;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    invoke-virtual {v0, v1}, Lcl0/j;->h(Lbl0/h;)V

    .line 339
    .line 340
    .line 341
    :cond_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 342
    .line 343
    return-object v0

    .line 344
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v0, Lcl0/j;

    .line 347
    .line 348
    iget-object v1, v0, Lcl0/j;->j:Lal0/c1;

    .line 349
    .line 350
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 351
    .line 352
    .line 353
    iget-object v0, v0, Lcl0/j;->h:Ltr0/b;

    .line 354
    .line 355
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 359
    .line 360
    return-object v0

    .line 361
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v0, Lcl0/j;

    .line 364
    .line 365
    iget-object v1, v0, Lcl0/j;->l:Lbl0/h;

    .line 366
    .line 367
    if-eqz v1, :cond_1

    .line 368
    .line 369
    iget-object v2, v0, Lcl0/j;->i:Lal0/d1;

    .line 370
    .line 371
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 372
    .line 373
    .line 374
    iget-object v2, v2, Lal0/d1;->a:Lal0/z;

    .line 375
    .line 376
    check-cast v2, Lyk0/a;

    .line 377
    .line 378
    iget-object v2, v2, Lyk0/a;->a:Lyy0/c2;

    .line 379
    .line 380
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 381
    .line 382
    .line 383
    const/4 v3, 0x0

    .line 384
    invoke-virtual {v2, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 385
    .line 386
    .line 387
    :cond_1
    iget-object v0, v0, Lcl0/j;->h:Ltr0/b;

    .line 388
    .line 389
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 393
    .line 394
    return-object v0

    .line 395
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 396
    .line 397
    check-cast v0, Lcl0/j;

    .line 398
    .line 399
    iget-object v0, v0, Lcl0/j;->h:Ltr0/b;

    .line 400
    .line 401
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 405
    .line 406
    return-object v0

    .line 407
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 408
    .line 409
    check-cast v0, Lc90/n0;

    .line 410
    .line 411
    iget-object v0, v0, Lc90/n0;->m:Lnr0/b;

    .line 412
    .line 413
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 417
    .line 418
    return-object v0

    .line 419
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 420
    .line 421
    check-cast v0, Lc90/n0;

    .line 422
    .line 423
    iget-object v0, v0, Lc90/n0;->l:Lnr0/c;

    .line 424
    .line 425
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 426
    .line 427
    .line 428
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 429
    .line 430
    return-object v0

    .line 431
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 432
    .line 433
    check-cast v0, Lc90/n0;

    .line 434
    .line 435
    iget-object v0, v0, Lc90/n0;->k:Lnr0/d;

    .line 436
    .line 437
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 438
    .line 439
    .line 440
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 441
    .line 442
    return-object v0

    .line 443
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 444
    .line 445
    check-cast v0, Lc90/n0;

    .line 446
    .line 447
    iget-object v0, v0, Lc90/n0;->j:Lnr0/f;

    .line 448
    .line 449
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 453
    .line 454
    return-object v0

    .line 455
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v0, Lc90/n0;

    .line 458
    .line 459
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 460
    .line 461
    .line 462
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 463
    .line 464
    .line 465
    move-result-object v1

    .line 466
    new-instance v2, Lc90/l0;

    .line 467
    .line 468
    const/4 v3, 0x1

    .line 469
    const/4 v4, 0x0

    .line 470
    invoke-direct {v2, v0, v4, v3}, Lc90/l0;-><init>(Lc90/n0;Lkotlin/coroutines/Continuation;I)V

    .line 471
    .line 472
    .line 473
    const/4 v0, 0x3

    .line 474
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 475
    .line 476
    .line 477
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 478
    .line 479
    return-object v0

    .line 480
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 481
    .line 482
    check-cast v0, Lc90/n0;

    .line 483
    .line 484
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 485
    .line 486
    .line 487
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 488
    .line 489
    .line 490
    move-result-object v1

    .line 491
    new-instance v2, Lc90/l0;

    .line 492
    .line 493
    const/4 v3, 0x0

    .line 494
    const/4 v4, 0x0

    .line 495
    invoke-direct {v2, v0, v4, v3}, Lc90/l0;-><init>(Lc90/n0;Lkotlin/coroutines/Continuation;I)V

    .line 496
    .line 497
    .line 498
    const/4 v0, 0x3

    .line 499
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 500
    .line 501
    .line 502
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 503
    .line 504
    return-object v0

    .line 505
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 506
    .line 507
    check-cast v0, Lc90/n0;

    .line 508
    .line 509
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 510
    .line 511
    .line 512
    move-result-object v1

    .line 513
    move-object v2, v1

    .line 514
    check-cast v2, Lc90/k0;

    .line 515
    .line 516
    const/16 v17, 0x0

    .line 517
    .line 518
    const/16 v18, 0x7bff

    .line 519
    .line 520
    const/4 v3, 0x0

    .line 521
    const/4 v4, 0x0

    .line 522
    const/4 v5, 0x0

    .line 523
    const/4 v6, 0x0

    .line 524
    const/4 v7, 0x0

    .line 525
    const/4 v8, 0x0

    .line 526
    const/4 v9, 0x0

    .line 527
    const/4 v10, 0x0

    .line 528
    const/4 v11, 0x0

    .line 529
    const/4 v12, 0x0

    .line 530
    const/4 v13, 0x0

    .line 531
    const/4 v14, 0x0

    .line 532
    const/4 v15, 0x0

    .line 533
    const/16 v16, 0x0

    .line 534
    .line 535
    invoke-static/range {v2 .. v18}, Lc90/k0;->a(Lc90/k0;Lc90/a;Lb90/m;Ljava/time/LocalDate;Ljava/time/LocalTime;Ljava/lang/String;Lb90/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZLb90/e;Ljava/util/List;Ljava/lang/String;I)Lc90/k0;

    .line 536
    .line 537
    .line 538
    move-result-object v1

    .line 539
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 540
    .line 541
    .line 542
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 543
    .line 544
    return-object v0

    .line 545
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 546
    .line 547
    check-cast v0, Lc90/n0;

    .line 548
    .line 549
    iget-object v0, v0, Lc90/n0;->i:Ltr0/b;

    .line 550
    .line 551
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 555
    .line 556
    return-object v0

    .line 557
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 558
    .line 559
    check-cast v0, Lc90/j0;

    .line 560
    .line 561
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 562
    .line 563
    .line 564
    move-result-object v1

    .line 565
    check-cast v1, Lc90/i0;

    .line 566
    .line 567
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 568
    .line 569
    .line 570
    new-instance v1, Lc90/i0;

    .line 571
    .line 572
    const/4 v2, 0x0

    .line 573
    invoke-direct {v1, v2}, Lc90/i0;-><init>(Z)V

    .line 574
    .line 575
    .line 576
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 577
    .line 578
    .line 579
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 580
    .line 581
    return-object v0

    .line 582
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast v0, Lc90/j0;

    .line 585
    .line 586
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 587
    .line 588
    .line 589
    move-result-object v1

    .line 590
    check-cast v1, Lc90/i0;

    .line 591
    .line 592
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 593
    .line 594
    .line 595
    new-instance v1, Lc90/i0;

    .line 596
    .line 597
    const/4 v2, 0x1

    .line 598
    invoke-direct {v1, v2}, Lc90/i0;-><init>(Z)V

    .line 599
    .line 600
    .line 601
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 602
    .line 603
    .line 604
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 605
    .line 606
    return-object v0

    .line 607
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 608
    .line 609
    check-cast v0, Lc90/j0;

    .line 610
    .line 611
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 612
    .line 613
    .line 614
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 615
    .line 616
    .line 617
    move-result-object v1

    .line 618
    new-instance v2, Lc90/h0;

    .line 619
    .line 620
    const/4 v3, 0x1

    .line 621
    const/4 v4, 0x0

    .line 622
    invoke-direct {v2, v0, v4, v3}, Lc90/h0;-><init>(Lc90/j0;Lkotlin/coroutines/Continuation;I)V

    .line 623
    .line 624
    .line 625
    const/4 v0, 0x3

    .line 626
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 627
    .line 628
    .line 629
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 630
    .line 631
    return-object v0

    .line 632
    nop

    .line 633
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
