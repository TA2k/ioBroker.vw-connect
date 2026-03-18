.class public final synthetic Ld80/l;
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
    iput p7, p0, Ld80/l;->d:I

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
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Ld80/l;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lc90/g0;

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
    new-instance v2, Lc90/d0;

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    const/4 v4, 0x0

    .line 23
    invoke-direct {v2, v0, v4, v3}, Lc90/d0;-><init>(Lc90/g0;Lkotlin/coroutines/Continuation;I)V

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
    check-cast v0, Lc90/g0;

    .line 36
    .line 37
    iget-object v0, v0, Lc90/g0;->h:Ltr0/b;

    .line 38
    .line 39
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_1
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v0, Lc90/c0;

    .line 48
    .line 49
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    move-object v2, v1

    .line 54
    check-cast v2, Lc90/z;

    .line 55
    .line 56
    const/4 v6, 0x0

    .line 57
    const/16 v7, 0xe

    .line 58
    .line 59
    const/4 v3, 0x0

    .line 60
    const/4 v4, 0x0

    .line 61
    const/4 v5, 0x0

    .line 62
    invoke-static/range {v2 .. v7}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 67
    .line 68
    .line 69
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object v0

    .line 72
    :pswitch_2
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v0, Lc90/c0;

    .line 75
    .line 76
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    move-object v2, v1

    .line 81
    check-cast v2, Lc90/z;

    .line 82
    .line 83
    const/4 v6, 0x0

    .line 84
    const/16 v7, 0xe

    .line 85
    .line 86
    const/4 v3, 0x1

    .line 87
    const/4 v4, 0x0

    .line 88
    const/4 v5, 0x0

    .line 89
    invoke-static/range {v2 .. v7}, Lc90/z;->a(Lc90/z;ZLql0/g;ZLjava/util/ArrayList;I)Lc90/z;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 94
    .line 95
    .line 96
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object v0

    .line 99
    :pswitch_3
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lc90/c0;

    .line 102
    .line 103
    iget-object v0, v0, Lc90/c0;->k:Lnr0/f;

    .line 104
    .line 105
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 109
    .line 110
    return-object v0

    .line 111
    :pswitch_4
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast v0, Lc90/c0;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 116
    .line 117
    .line 118
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    new-instance v2, Lc90/y;

    .line 123
    .line 124
    const/4 v3, 0x2

    .line 125
    const/4 v4, 0x0

    .line 126
    invoke-direct {v2, v0, v4, v3}, Lc90/y;-><init>(Lc90/c0;Lkotlin/coroutines/Continuation;I)V

    .line 127
    .line 128
    .line 129
    const/4 v0, 0x3

    .line 130
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

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
    check-cast v0, Lc90/x;

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
    check-cast v2, Lc90/t;

    .line 146
    .line 147
    const/4 v10, 0x0

    .line 148
    const/16 v11, 0x17f

    .line 149
    .line 150
    const/4 v3, 0x0

    .line 151
    const/4 v4, 0x0

    .line 152
    const/4 v5, 0x0

    .line 153
    const/4 v6, 0x0

    .line 154
    const/4 v7, 0x0

    .line 155
    const/4 v8, 0x0

    .line 156
    const/4 v9, 0x0

    .line 157
    invoke-static/range {v2 .. v11}, Lc90/t;->a(Lc90/t;ZZLjava/lang/Boolean;Ljava/util/List;Ljava/lang/String;Lql0/g;ZLb90/e;I)Lc90/t;

    .line 158
    .line 159
    .line 160
    move-result-object v1

    .line 161
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 162
    .line 163
    .line 164
    iget-object v0, v0, Lc90/x;->n:Ltn0/e;

    .line 165
    .line 166
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object v0

    .line 172
    :pswitch_6
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast v0, Lc90/x;

    .line 175
    .line 176
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 177
    .line 178
    .line 179
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 180
    .line 181
    .line 182
    move-result-object v1

    .line 183
    new-instance v2, Lc90/l;

    .line 184
    .line 185
    const/4 v3, 0x1

    .line 186
    const/4 v4, 0x0

    .line 187
    invoke-direct {v2, v0, v4, v3}, Lc90/l;-><init>(Lc90/x;Lkotlin/coroutines/Continuation;I)V

    .line 188
    .line 189
    .line 190
    const/4 v0, 0x3

    .line 191
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 192
    .line 193
    .line 194
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 195
    .line 196
    return-object v0

    .line 197
    :pswitch_7
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 198
    .line 199
    check-cast v0, Lc90/x;

    .line 200
    .line 201
    iget-object v0, v0, Lc90/x;->h:Ltr0/b;

    .line 202
    .line 203
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 204
    .line 205
    .line 206
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 207
    .line 208
    return-object v0

    .line 209
    :pswitch_8
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 210
    .line 211
    check-cast v0, Lc90/x;

    .line 212
    .line 213
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 214
    .line 215
    .line 216
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 217
    .line 218
    .line 219
    move-result-object v1

    .line 220
    new-instance v2, La7/o;

    .line 221
    .line 222
    const/16 v3, 0x16

    .line 223
    .line 224
    const/4 v4, 0x0

    .line 225
    invoke-direct {v2, v0, v4, v3}, La7/o;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 226
    .line 227
    .line 228
    const/4 v0, 0x3

    .line 229
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 230
    .line 231
    .line 232
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    return-object v0

    .line 235
    :pswitch_9
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v0, Lc90/x;

    .line 238
    .line 239
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    new-instance v2, Lc90/l;

    .line 247
    .line 248
    const/4 v3, 0x2

    .line 249
    const/4 v4, 0x0

    .line 250
    invoke-direct {v2, v0, v4, v3}, Lc90/l;-><init>(Lc90/x;Lkotlin/coroutines/Continuation;I)V

    .line 251
    .line 252
    .line 253
    const/4 v0, 0x3

    .line 254
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 255
    .line 256
    .line 257
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 258
    .line 259
    return-object v0

    .line 260
    :pswitch_a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast v0, Lc90/x;

    .line 263
    .line 264
    iget-object v0, v0, Lc90/x;->l:Lfg0/f;

    .line 265
    .line 266
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 270
    .line 271
    return-object v0

    .line 272
    :pswitch_b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 273
    .line 274
    check-cast v0, Lc90/x;

    .line 275
    .line 276
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 277
    .line 278
    .line 279
    new-instance v1, Lc90/j;

    .line 280
    .line 281
    const/4 v2, 0x0

    .line 282
    invoke-direct {v1, v0, v2}, Lc90/j;-><init>(Lc90/x;I)V

    .line 283
    .line 284
    .line 285
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 289
    .line 290
    .line 291
    move-result-object v1

    .line 292
    move-object v2, v1

    .line 293
    check-cast v2, Lc90/t;

    .line 294
    .line 295
    const/4 v10, 0x0

    .line 296
    const/16 v11, 0x17f

    .line 297
    .line 298
    const/4 v3, 0x0

    .line 299
    const/4 v4, 0x0

    .line 300
    const/4 v5, 0x0

    .line 301
    const/4 v6, 0x0

    .line 302
    const/4 v7, 0x0

    .line 303
    const/4 v8, 0x0

    .line 304
    const/4 v9, 0x1

    .line 305
    invoke-static/range {v2 .. v11}, Lc90/t;->a(Lc90/t;ZZLjava/lang/Boolean;Ljava/util/List;Ljava/lang/String;Lql0/g;ZLb90/e;I)Lc90/t;

    .line 306
    .line 307
    .line 308
    move-result-object v1

    .line 309
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 310
    .line 311
    .line 312
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 313
    .line 314
    return-object v0

    .line 315
    :pswitch_c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 316
    .line 317
    check-cast v0, Lc90/x;

    .line 318
    .line 319
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 320
    .line 321
    .line 322
    new-instance v1, Lc90/j;

    .line 323
    .line 324
    const/4 v2, 0x1

    .line 325
    invoke-direct {v1, v0, v2}, Lc90/j;-><init>(Lc90/x;I)V

    .line 326
    .line 327
    .line 328
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 332
    .line 333
    .line 334
    move-result-object v1

    .line 335
    move-object v2, v1

    .line 336
    check-cast v2, Lc90/t;

    .line 337
    .line 338
    const/4 v10, 0x0

    .line 339
    const/16 v11, 0x17f

    .line 340
    .line 341
    const/4 v3, 0x0

    .line 342
    const/4 v4, 0x0

    .line 343
    const/4 v5, 0x0

    .line 344
    const/4 v6, 0x0

    .line 345
    const/4 v7, 0x0

    .line 346
    const/4 v8, 0x0

    .line 347
    const/4 v9, 0x0

    .line 348
    invoke-static/range {v2 .. v11}, Lc90/t;->a(Lc90/t;ZZLjava/lang/Boolean;Ljava/util/List;Ljava/lang/String;Lql0/g;ZLb90/e;I)Lc90/t;

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
    :pswitch_d
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 359
    .line 360
    check-cast v0, Lc90/x;

    .line 361
    .line 362
    iget-object v0, v0, Lc90/x;->k:Lfg0/e;

    .line 363
    .line 364
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 368
    .line 369
    return-object v0

    .line 370
    :pswitch_e
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 371
    .line 372
    check-cast v0, Lc90/i;

    .line 373
    .line 374
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 375
    .line 376
    .line 377
    move-result-object v1

    .line 378
    move-object v2, v1

    .line 379
    check-cast v2, Lc90/h;

    .line 380
    .line 381
    const/4 v9, 0x0

    .line 382
    const/16 v10, 0x77

    .line 383
    .line 384
    const/4 v3, 0x0

    .line 385
    const/4 v4, 0x0

    .line 386
    const/4 v5, 0x0

    .line 387
    const/4 v6, 0x0

    .line 388
    const/4 v7, 0x0

    .line 389
    const/4 v8, 0x0

    .line 390
    invoke-static/range {v2 .. v10}, Lc90/h;->a(Lc90/h;ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;I)Lc90/h;

    .line 391
    .line 392
    .line 393
    move-result-object v1

    .line 394
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 395
    .line 396
    .line 397
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 398
    .line 399
    return-object v0

    .line 400
    :pswitch_f
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 401
    .line 402
    check-cast v0, Lc90/i;

    .line 403
    .line 404
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 405
    .line 406
    .line 407
    move-result-object v1

    .line 408
    move-object v2, v1

    .line 409
    check-cast v2, Lc90/h;

    .line 410
    .line 411
    const/4 v9, 0x0

    .line 412
    const/16 v10, 0x7b

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
    invoke-static/range {v2 .. v10}, Lc90/h;->a(Lc90/h;ZZZZLjava/time/LocalDate;Ljava/time/LocalTime;Lb90/e;I)Lc90/h;

    .line 421
    .line 422
    .line 423
    move-result-object v1

    .line 424
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 425
    .line 426
    .line 427
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 428
    .line 429
    return-object v0

    .line 430
    :pswitch_10
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 431
    .line 432
    check-cast v0, Lc90/i;

    .line 433
    .line 434
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    new-instance v2, La10/a;

    .line 442
    .line 443
    const/4 v3, 0x6

    .line 444
    const/4 v4, 0x0

    .line 445
    invoke-direct {v2, v0, v4, v3}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 446
    .line 447
    .line 448
    const/4 v0, 0x3

    .line 449
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 450
    .line 451
    .line 452
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 453
    .line 454
    return-object v0

    .line 455
    :pswitch_11
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 456
    .line 457
    check-cast v0, Lc90/i;

    .line 458
    .line 459
    iget-object v1, v0, Lc90/i;->j:La90/d0;

    .line 460
    .line 461
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 462
    .line 463
    .line 464
    move-result-object v2

    .line 465
    check-cast v2, Lc90/h;

    .line 466
    .line 467
    iget-object v2, v2, Lc90/h;->e:Ljava/time/LocalDate;

    .line 468
    .line 469
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 470
    .line 471
    .line 472
    move-result-object v3

    .line 473
    check-cast v3, Lc90/h;

    .line 474
    .line 475
    iget-object v3, v3, Lc90/h;->f:Ljava/time/LocalTime;

    .line 476
    .line 477
    iget-object v1, v1, La90/d0;->a:La90/q;

    .line 478
    .line 479
    check-cast v1, Ly80/a;

    .line 480
    .line 481
    iput-object v2, v1, Ly80/a;->e:Ljava/time/LocalDate;

    .line 482
    .line 483
    iput-object v3, v1, Ly80/a;->f:Ljava/time/LocalTime;

    .line 484
    .line 485
    iget-object v0, v0, Lc90/i;->i:Lnr0/b;

    .line 486
    .line 487
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 491
    .line 492
    return-object v0

    .line 493
    :pswitch_12
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 494
    .line 495
    check-cast v0, Lc90/i;

    .line 496
    .line 497
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 498
    .line 499
    .line 500
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    new-instance v2, La50/a;

    .line 505
    .line 506
    const/16 v3, 0x14

    .line 507
    .line 508
    const/4 v4, 0x0

    .line 509
    invoke-direct {v2, v0, v4, v3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 510
    .line 511
    .line 512
    const/4 v0, 0x3

    .line 513
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 514
    .line 515
    .line 516
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 517
    .line 518
    return-object v0

    .line 519
    :pswitch_13
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 520
    .line 521
    check-cast v0, Lc90/i;

    .line 522
    .line 523
    iget-object v0, v0, Lc90/i;->h:Ltr0/b;

    .line 524
    .line 525
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 526
    .line 527
    .line 528
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 529
    .line 530
    return-object v0

    .line 531
    :pswitch_14
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 532
    .line 533
    check-cast v0, Lc90/f;

    .line 534
    .line 535
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 536
    .line 537
    .line 538
    move-result-object v1

    .line 539
    move-object v2, v1

    .line 540
    check-cast v2, Lc90/c;

    .line 541
    .line 542
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 543
    .line 544
    .line 545
    move-result-object v1

    .line 546
    check-cast v1, Lc90/c;

    .line 547
    .line 548
    iget-boolean v1, v1, Lc90/c;->j:Z

    .line 549
    .line 550
    xor-int/lit8 v12, v1, 0x1

    .line 551
    .line 552
    const/4 v14, 0x0

    .line 553
    const/16 v15, 0xdff

    .line 554
    .line 555
    const/4 v3, 0x0

    .line 556
    const/4 v4, 0x0

    .line 557
    const/4 v5, 0x0

    .line 558
    const/4 v6, 0x0

    .line 559
    const/4 v7, 0x0

    .line 560
    const/4 v8, 0x0

    .line 561
    const/4 v9, 0x0

    .line 562
    const/4 v10, 0x0

    .line 563
    const/4 v11, 0x0

    .line 564
    const/4 v13, 0x0

    .line 565
    invoke-static/range {v2 .. v15}, Lc90/c;->a(Lc90/c;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/Set;ZLjava/util/Set;Ljava/util/Set;Ljava/util/Set;Ljava/util/ArrayList;ZLql0/g;Lb90/e;I)Lc90/c;

    .line 566
    .line 567
    .line 568
    move-result-object v1

    .line 569
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 570
    .line 571
    .line 572
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 573
    .line 574
    return-object v0

    .line 575
    :pswitch_15
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 576
    .line 577
    check-cast v0, Lc90/f;

    .line 578
    .line 579
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 580
    .line 581
    .line 582
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 583
    .line 584
    .line 585
    move-result-object v1

    .line 586
    new-instance v2, Lc90/b;

    .line 587
    .line 588
    const/4 v3, 0x1

    .line 589
    const/4 v4, 0x0

    .line 590
    invoke-direct {v2, v0, v4, v3}, Lc90/b;-><init>(Lc90/f;Lkotlin/coroutines/Continuation;I)V

    .line 591
    .line 592
    .line 593
    const/4 v0, 0x3

    .line 594
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 595
    .line 596
    .line 597
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 598
    .line 599
    return-object v0

    .line 600
    :pswitch_16
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 601
    .line 602
    check-cast v0, Lc90/f;

    .line 603
    .line 604
    iget-object v0, v0, Lc90/f;->h:Ltr0/b;

    .line 605
    .line 606
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 607
    .line 608
    .line 609
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 610
    .line 611
    return-object v0

    .line 612
    :pswitch_17
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 613
    .line 614
    check-cast v0, Lc90/f;

    .line 615
    .line 616
    iget-object v1, v0, Lc90/f;->l:La90/b0;

    .line 617
    .line 618
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 619
    .line 620
    .line 621
    move-result-object v2

    .line 622
    check-cast v2, Lc90/c;

    .line 623
    .line 624
    const-string v3, "<this>"

    .line 625
    .line 626
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 627
    .line 628
    .line 629
    iget-object v3, v2, Lc90/c;->a:Ljava/util/Map;

    .line 630
    .line 631
    sget-object v4, Lb90/q;->e:Lb90/q;

    .line 632
    .line 633
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 634
    .line 635
    .line 636
    move-result-object v4

    .line 637
    move-object v7, v4

    .line 638
    check-cast v7, Lb90/g;

    .line 639
    .line 640
    sget-object v4, Lb90/q;->f:Lb90/q;

    .line 641
    .line 642
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 643
    .line 644
    .line 645
    move-result-object v4

    .line 646
    move-object v8, v4

    .line 647
    check-cast v8, Lb90/g;

    .line 648
    .line 649
    sget-object v4, Lb90/q;->g:Lb90/q;

    .line 650
    .line 651
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v4

    .line 655
    move-object v9, v4

    .line 656
    check-cast v9, Lb90/g;

    .line 657
    .line 658
    sget-object v4, Lb90/q;->i:Lb90/q;

    .line 659
    .line 660
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 661
    .line 662
    .line 663
    move-result-object v4

    .line 664
    move-object v10, v4

    .line 665
    check-cast v10, Lb90/g;

    .line 666
    .line 667
    sget-object v4, Lb90/q;->h:Lb90/q;

    .line 668
    .line 669
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v4

    .line 673
    move-object v12, v4

    .line 674
    check-cast v12, Lb90/g;

    .line 675
    .line 676
    sget-object v4, Lb90/q;->n:Lb90/q;

    .line 677
    .line 678
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v4

    .line 682
    move-object v13, v4

    .line 683
    check-cast v13, Lb90/g;

    .line 684
    .line 685
    sget-object v4, Lb90/q;->o:Lb90/q;

    .line 686
    .line 687
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 688
    .line 689
    .line 690
    move-result-object v4

    .line 691
    move-object v14, v4

    .line 692
    check-cast v14, Lb90/g;

    .line 693
    .line 694
    sget-object v4, Lb90/q;->p:Lb90/q;

    .line 695
    .line 696
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v4

    .line 700
    move-object v15, v4

    .line 701
    check-cast v15, Lb90/g;

    .line 702
    .line 703
    sget-object v4, Lb90/q;->j:Lb90/q;

    .line 704
    .line 705
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 706
    .line 707
    .line 708
    move-result-object v4

    .line 709
    move-object/from16 v16, v4

    .line 710
    .line 711
    check-cast v16, Lb90/g;

    .line 712
    .line 713
    sget-object v4, Lb90/q;->u:Lb90/q;

    .line 714
    .line 715
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 716
    .line 717
    .line 718
    move-result-object v3

    .line 719
    move-object v11, v3

    .line 720
    check-cast v11, Lb90/g;

    .line 721
    .line 722
    iget-object v3, v2, Lc90/c;->b:Ljava/util/Map;

    .line 723
    .line 724
    sget-object v4, Lb90/q;->d:Lb90/q;

    .line 725
    .line 726
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 727
    .line 728
    .line 729
    move-result-object v4

    .line 730
    move-object v6, v4

    .line 731
    check-cast v6, Lb90/g;

    .line 732
    .line 733
    sget-object v4, Lb90/q;->l:Lb90/q;

    .line 734
    .line 735
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 736
    .line 737
    .line 738
    move-result-object v4

    .line 739
    move-object/from16 v17, v4

    .line 740
    .line 741
    check-cast v17, Lb90/g;

    .line 742
    .line 743
    sget-object v4, Lb90/q;->k:Lb90/q;

    .line 744
    .line 745
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 746
    .line 747
    .line 748
    move-result-object v4

    .line 749
    move-object/from16 v18, v4

    .line 750
    .line 751
    check-cast v18, Lb90/g;

    .line 752
    .line 753
    sget-object v4, Lb90/q;->w:Lb90/q;

    .line 754
    .line 755
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 756
    .line 757
    .line 758
    move-result-object v3

    .line 759
    move-object/from16 v20, v3

    .line 760
    .line 761
    check-cast v20, Lb90/g;

    .line 762
    .line 763
    iget-object v3, v2, Lc90/c;->c:Ljava/util/Map;

    .line 764
    .line 765
    sget-object v4, Lb90/q;->m:Lb90/q;

    .line 766
    .line 767
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 768
    .line 769
    .line 770
    move-result-object v3

    .line 771
    move-object/from16 v19, v3

    .line 772
    .line 773
    check-cast v19, Lb90/g;

    .line 774
    .line 775
    iget-object v3, v2, Lc90/c;->d:Ljava/util/Set;

    .line 776
    .line 777
    iget-object v4, v2, Lc90/c;->g:Ljava/util/Set;

    .line 778
    .line 779
    check-cast v4, Ljava/lang/Iterable;

    .line 780
    .line 781
    invoke-static {v4}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 782
    .line 783
    .line 784
    move-result-object v4

    .line 785
    move-object v5, v3

    .line 786
    check-cast v5, Ljava/lang/Iterable;

    .line 787
    .line 788
    invoke-static {v4, v5}, Ljp/m1;->f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;

    .line 789
    .line 790
    .line 791
    move-result-object v22

    .line 792
    iget-object v2, v2, Lc90/c;->h:Ljava/util/Set;

    .line 793
    .line 794
    new-instance v5, Lb90/a;

    .line 795
    .line 796
    move-object/from16 v23, v2

    .line 797
    .line 798
    move-object/from16 v21, v3

    .line 799
    .line 800
    invoke-direct/range {v5 .. v23}, Lb90/a;-><init>(Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Lb90/g;Ljava/util/Set;Ljava/util/Set;Ljava/util/Set;)V

    .line 801
    .line 802
    .line 803
    iget-object v1, v1, La90/b0;->a:La90/q;

    .line 804
    .line 805
    check-cast v1, Ly80/a;

    .line 806
    .line 807
    iput-object v5, v1, Ly80/a;->i:Lb90/a;

    .line 808
    .line 809
    iget-object v0, v0, Lc90/f;->o:Lnr0/h;

    .line 810
    .line 811
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 812
    .line 813
    .line 814
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 815
    .line 816
    return-object v0

    .line 817
    :pswitch_18
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 818
    .line 819
    check-cast v0, Lc90/f;

    .line 820
    .line 821
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 822
    .line 823
    .line 824
    move-result-object v1

    .line 825
    move-object v2, v1

    .line 826
    check-cast v2, Lc90/c;

    .line 827
    .line 828
    const/4 v14, 0x0

    .line 829
    const/16 v15, 0xbff

    .line 830
    .line 831
    const/4 v3, 0x0

    .line 832
    const/4 v4, 0x0

    .line 833
    const/4 v5, 0x0

    .line 834
    const/4 v6, 0x0

    .line 835
    const/4 v7, 0x0

    .line 836
    const/4 v8, 0x0

    .line 837
    const/4 v9, 0x0

    .line 838
    const/4 v10, 0x0

    .line 839
    const/4 v11, 0x0

    .line 840
    const/4 v12, 0x0

    .line 841
    const/4 v13, 0x0

    .line 842
    invoke-static/range {v2 .. v15}, Lc90/c;->a(Lc90/c;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/LinkedHashMap;Ljava/util/Set;ZLjava/util/Set;Ljava/util/Set;Ljava/util/Set;Ljava/util/ArrayList;ZLql0/g;Lb90/e;I)Lc90/c;

    .line 843
    .line 844
    .line 845
    move-result-object v1

    .line 846
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 847
    .line 848
    .line 849
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 850
    .line 851
    return-object v0

    .line 852
    :pswitch_19
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 853
    .line 854
    check-cast v0, Lc80/g0;

    .line 855
    .line 856
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 857
    .line 858
    .line 859
    new-instance v1, Lc80/e0;

    .line 860
    .line 861
    const/4 v2, 0x1

    .line 862
    invoke-direct {v1, v0, v2}, Lc80/e0;-><init>(Lc80/g0;I)V

    .line 863
    .line 864
    .line 865
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 866
    .line 867
    .line 868
    iget-object v0, v0, Lc80/g0;->i:Lzd0/a;

    .line 869
    .line 870
    new-instance v1, Lne0/c;

    .line 871
    .line 872
    new-instance v2, Ljava/util/concurrent/CancellationException;

    .line 873
    .line 874
    const-string v3, "The warning screen was cancelled"

    .line 875
    .line 876
    invoke-direct {v2, v3}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 877
    .line 878
    .line 879
    const/4 v5, 0x0

    .line 880
    const/16 v6, 0x1e

    .line 881
    .line 882
    const/4 v3, 0x0

    .line 883
    const/4 v4, 0x0

    .line 884
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 885
    .line 886
    .line 887
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 888
    .line 889
    .line 890
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 891
    .line 892
    return-object v0

    .line 893
    :pswitch_1a
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 894
    .line 895
    check-cast v0, Lc80/g0;

    .line 896
    .line 897
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 898
    .line 899
    .line 900
    new-instance v1, Lc80/e0;

    .line 901
    .line 902
    const/4 v2, 0x2

    .line 903
    invoke-direct {v1, v0, v2}, Lc80/e0;-><init>(Lc80/g0;I)V

    .line 904
    .line 905
    .line 906
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 907
    .line 908
    .line 909
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 910
    .line 911
    .line 912
    move-result-object v1

    .line 913
    check-cast v1, Lc80/f0;

    .line 914
    .line 915
    iget-boolean v1, v1, Lc80/f0;->c:Z

    .line 916
    .line 917
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 918
    .line 919
    if-eqz v1, :cond_0

    .line 920
    .line 921
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 922
    .line 923
    .line 924
    move-result-object v1

    .line 925
    new-instance v3, Lc80/l;

    .line 926
    .line 927
    const/4 v4, 0x3

    .line 928
    const/4 v5, 0x0

    .line 929
    invoke-direct {v3, v0, v5, v4}, Lc80/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 930
    .line 931
    .line 932
    const/4 v0, 0x3

    .line 933
    invoke-static {v1, v5, v5, v3, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 934
    .line 935
    .line 936
    goto :goto_0

    .line 937
    :cond_0
    iget-object v0, v0, Lc80/g0;->i:Lzd0/a;

    .line 938
    .line 939
    new-instance v1, Lne0/e;

    .line 940
    .line 941
    invoke-direct {v1, v2}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 942
    .line 943
    .line 944
    invoke-virtual {v0, v1}, Lzd0/a;->a(Lne0/t;)V

    .line 945
    .line 946
    .line 947
    :goto_0
    return-object v2

    .line 948
    :pswitch_1b
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 949
    .line 950
    check-cast v0, Lc80/g0;

    .line 951
    .line 952
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 953
    .line 954
    .line 955
    new-instance v1, Lc80/e0;

    .line 956
    .line 957
    const/4 v2, 0x0

    .line 958
    invoke-direct {v1, v0, v2}, Lc80/e0;-><init>(Lc80/g0;I)V

    .line 959
    .line 960
    .line 961
    invoke-static {v0, v1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 962
    .line 963
    .line 964
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 965
    .line 966
    .line 967
    move-result-object v1

    .line 968
    check-cast v1, Lc80/f0;

    .line 969
    .line 970
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 971
    .line 972
    .line 973
    move-result-object v2

    .line 974
    check-cast v2, Lc80/f0;

    .line 975
    .line 976
    iget-boolean v2, v2, Lc80/f0;->c:Z

    .line 977
    .line 978
    xor-int/lit8 v2, v2, 0x1

    .line 979
    .line 980
    const/4 v3, 0x3

    .line 981
    const/4 v4, 0x0

    .line 982
    invoke-static {v1, v4, v4, v2, v3}, Lc80/f0;->a(Lc80/f0;Ljava/lang/String;Ljava/lang/String;ZI)Lc80/f0;

    .line 983
    .line 984
    .line 985
    move-result-object v1

    .line 986
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 987
    .line 988
    .line 989
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 990
    .line 991
    return-object v0

    .line 992
    :pswitch_1c
    iget-object v0, v0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 993
    .line 994
    check-cast v0, Lc80/d0;

    .line 995
    .line 996
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 997
    .line 998
    .line 999
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 1000
    .line 1001
    .line 1002
    move-result-object v1

    .line 1003
    new-instance v2, Lc80/a0;

    .line 1004
    .line 1005
    const/4 v3, 0x3

    .line 1006
    const/4 v4, 0x0

    .line 1007
    invoke-direct {v2, v0, v4, v3}, Lc80/a0;-><init>(Lc80/d0;Lkotlin/coroutines/Continuation;I)V

    .line 1008
    .line 1009
    .line 1010
    const/4 v0, 0x3

    .line 1011
    invoke-static {v1, v4, v4, v2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 1012
    .line 1013
    .line 1014
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 1015
    .line 1016
    return-object v0

    .line 1017
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
