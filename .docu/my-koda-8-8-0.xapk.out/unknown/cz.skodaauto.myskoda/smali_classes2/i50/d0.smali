.class public final synthetic Li50/d0;
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
    iput p7, p0, Li50/d0;->d:I

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
    .locals 10

    .line 1
    iget v0, p0, Li50/d0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljv0/i;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    new-instance v1, Ljv0/f;

    .line 18
    .line 19
    const/4 v2, 0x4

    .line 20
    const/4 v3, 0x0

    .line 21
    invoke-direct {v1, p0, v3, v2}, Ljv0/f;-><init>(Ljv0/i;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    const/4 p0, 0x3

    .line 25
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 26
    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    return-object p0

    .line 31
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Ljv0/i;

    .line 34
    .line 35
    iget-object p0, p0, Ljv0/i;->z:Lhv0/x;

    .line 36
    .line 37
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Ljv0/i;

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    new-instance v1, Li50/p;

    .line 55
    .line 56
    const/4 v2, 0x6

    .line 57
    const/4 v3, 0x0

    .line 58
    invoke-direct {v1, p0, v3, v2}, Li50/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    const/4 p0, 0x3

    .line 62
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 63
    .line 64
    .line 65
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 66
    .line 67
    return-object p0

    .line 68
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast p0, Ljv0/i;

    .line 71
    .line 72
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    new-instance v0, Ljv0/c;

    .line 76
    .line 77
    const/4 v1, 0x0

    .line 78
    invoke-direct {v0, v1}, Ljv0/c;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-static {p0, v0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 82
    .line 83
    .line 84
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    new-instance v1, Ljv0/f;

    .line 89
    .line 90
    const/4 v2, 0x5

    .line 91
    const/4 v3, 0x0

    .line 92
    invoke-direct {v1, p0, v3, v2}, Ljv0/f;-><init>(Ljv0/i;Lkotlin/coroutines/Continuation;I)V

    .line 93
    .line 94
    .line 95
    const/4 p0, 0x3

    .line 96
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 97
    .line 98
    .line 99
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    return-object p0

    .line 102
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 103
    .line 104
    check-cast p0, Ljv0/i;

    .line 105
    .line 106
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 107
    .line 108
    .line 109
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    new-instance v1, Ljv0/f;

    .line 114
    .line 115
    const/4 v2, 0x7

    .line 116
    const/4 v3, 0x0

    .line 117
    invoke-direct {v1, p0, v3, v2}, Ljv0/f;-><init>(Ljv0/i;Lkotlin/coroutines/Continuation;I)V

    .line 118
    .line 119
    .line 120
    const/4 p0, 0x3

    .line 121
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 122
    .line 123
    .line 124
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 125
    .line 126
    return-object p0

    .line 127
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p0, Ljv0/i;

    .line 130
    .line 131
    iget-object p0, p0, Ljv0/i;->l:Ltr0/b;

    .line 132
    .line 133
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0

    .line 139
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast p0, Ljv0/i;

    .line 142
    .line 143
    iget-object p0, p0, Ljv0/i;->o:Lfg0/f;

    .line 144
    .line 145
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    return-object p0

    .line 151
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast p0, Ljv0/i;

    .line 154
    .line 155
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 156
    .line 157
    .line 158
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    new-instance v1, Ljv0/f;

    .line 163
    .line 164
    const/4 v2, 0x6

    .line 165
    const/4 v3, 0x0

    .line 166
    invoke-direct {v1, p0, v3, v2}, Ljv0/f;-><init>(Ljv0/i;Lkotlin/coroutines/Continuation;I)V

    .line 167
    .line 168
    .line 169
    const/4 p0, 0x3

    .line 170
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 171
    .line 172
    .line 173
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 174
    .line 175
    return-object p0

    .line 176
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast p0, Ljv0/i;

    .line 179
    .line 180
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 181
    .line 182
    .line 183
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    new-instance v1, Ljv0/f;

    .line 188
    .line 189
    const/16 v2, 0x8

    .line 190
    .line 191
    const/4 v3, 0x0

    .line 192
    invoke-direct {v1, p0, v3, v2}, Ljv0/f;-><init>(Ljv0/i;Lkotlin/coroutines/Continuation;I)V

    .line 193
    .line 194
    .line 195
    const/4 p0, 0x3

    .line 196
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 197
    .line 198
    .line 199
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 200
    .line 201
    return-object p0

    .line 202
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast p0, Lhz/f;

    .line 205
    .line 206
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 207
    .line 208
    .line 209
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 210
    .line 211
    .line 212
    move-result-object v0

    .line 213
    new-instance v1, Lh40/h;

    .line 214
    .line 215
    const/16 v2, 0xe

    .line 216
    .line 217
    const/4 v3, 0x0

    .line 218
    invoke-direct {v1, p0, v3, v2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 219
    .line 220
    .line 221
    const/4 p0, 0x3

    .line 222
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 223
    .line 224
    .line 225
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 226
    .line 227
    return-object p0

    .line 228
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p0, Lhz/f;

    .line 231
    .line 232
    iget-object p0, p0, Lhz/f;->i:Ltr0/b;

    .line 233
    .line 234
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 238
    .line 239
    return-object p0

    .line 240
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast p0, Lh2/t9;

    .line 243
    .line 244
    invoke-interface {p0}, Lh2/t9;->b()V

    .line 245
    .line 246
    .line 247
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 248
    .line 249
    return-object p0

    .line 250
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast p0, Lh80/g;

    .line 253
    .line 254
    iget-object p0, p0, Lh80/g;->h:Ltr0/b;

    .line 255
    .line 256
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 260
    .line 261
    return-object p0

    .line 262
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast p0, Lh80/g;

    .line 265
    .line 266
    iget-object p0, p0, Lh80/g;->i:Lq80/g;

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
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 275
    .line 276
    check-cast p0, Lh80/g;

    .line 277
    .line 278
    iget-object p0, p0, Lh80/g;->j:Lq80/f;

    .line 279
    .line 280
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 284
    .line 285
    return-object p0

    .line 286
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast p0, Lh80/g;

    .line 289
    .line 290
    iget-object p0, p0, Lh80/g;->h:Ltr0/b;

    .line 291
    .line 292
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object p0

    .line 298
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast p0, Lh80/d;

    .line 301
    .line 302
    iget-object p0, p0, Lh80/d;->h:Ltr0/b;

    .line 303
    .line 304
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 305
    .line 306
    .line 307
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 308
    .line 309
    return-object p0

    .line 310
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 311
    .line 312
    check-cast p0, Lh80/d;

    .line 313
    .line 314
    iget-object p0, p0, Lh80/d;->h:Ltr0/b;

    .line 315
    .line 316
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 320
    .line 321
    return-object p0

    .line 322
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast p0, Lh80/b;

    .line 325
    .line 326
    iget-object p0, p0, Lh80/b;->h:Ltr0/b;

    .line 327
    .line 328
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 332
    .line 333
    return-object p0

    .line 334
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 335
    .line 336
    check-cast p0, Lh80/b;

    .line 337
    .line 338
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 339
    .line 340
    .line 341
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    new-instance v1, Lh40/h;

    .line 346
    .line 347
    const/16 v2, 0xa

    .line 348
    .line 349
    const/4 v3, 0x0

    .line 350
    invoke-direct {v1, p0, v3, v2}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 351
    .line 352
    .line 353
    const/4 p0, 0x3

    .line 354
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 355
    .line 356
    .line 357
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 358
    .line 359
    return-object p0

    .line 360
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast p0, Lh80/b;

    .line 363
    .line 364
    iget-object p0, p0, Lh80/b;->h:Ltr0/b;

    .line 365
    .line 366
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 367
    .line 368
    .line 369
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 370
    .line 371
    return-object p0

    .line 372
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 373
    .line 374
    check-cast p0, Lh50/b1;

    .line 375
    .line 376
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    check-cast v0, Lh50/a1;

    .line 381
    .line 382
    iget-boolean v0, v0, Lh50/a1;->g:Z

    .line 383
    .line 384
    xor-int/lit8 v8, v0, 0x1

    .line 385
    .line 386
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 387
    .line 388
    .line 389
    move-result-object v0

    .line 390
    move-object v1, v0

    .line 391
    check-cast v1, Lh50/a1;

    .line 392
    .line 393
    const/4 v7, 0x0

    .line 394
    const/16 v9, 0x3f

    .line 395
    .line 396
    const/4 v2, 0x0

    .line 397
    const/4 v3, 0x0

    .line 398
    const/4 v4, 0x0

    .line 399
    const/4 v5, 0x0

    .line 400
    const/4 v6, 0x0

    .line 401
    invoke-static/range {v1 .. v9}, Lh50/a1;->a(Lh50/a1;ZZZZZZZI)Lh50/a1;

    .line 402
    .line 403
    .line 404
    move-result-object v0

    .line 405
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 406
    .line 407
    .line 408
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 409
    .line 410
    .line 411
    move-result-object v0

    .line 412
    new-instance v1, Lac0/m;

    .line 413
    .line 414
    const/4 v2, 0x5

    .line 415
    const/4 v3, 0x0

    .line 416
    invoke-direct {v1, p0, v8, v3, v2}, Lac0/m;-><init>(Ljava/lang/Object;ZLkotlin/coroutines/Continuation;I)V

    .line 417
    .line 418
    .line 419
    const/4 p0, 0x3

    .line 420
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 421
    .line 422
    .line 423
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 424
    .line 425
    return-object p0

    .line 426
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 427
    .line 428
    check-cast p0, Lh50/b1;

    .line 429
    .line 430
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 431
    .line 432
    .line 433
    move-result-object v0

    .line 434
    move-object v1, v0

    .line 435
    check-cast v1, Lh50/a1;

    .line 436
    .line 437
    const/4 v8, 0x0

    .line 438
    const/16 v9, 0x5f

    .line 439
    .line 440
    const/4 v2, 0x0

    .line 441
    const/4 v3, 0x0

    .line 442
    const/4 v4, 0x0

    .line 443
    const/4 v5, 0x0

    .line 444
    const/4 v6, 0x0

    .line 445
    const/4 v7, 0x0

    .line 446
    invoke-static/range {v1 .. v9}, Lh50/a1;->a(Lh50/a1;ZZZZZZZI)Lh50/a1;

    .line 447
    .line 448
    .line 449
    move-result-object v0

    .line 450
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 451
    .line 452
    .line 453
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 454
    .line 455
    return-object p0

    .line 456
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 457
    .line 458
    check-cast p0, Lh50/b1;

    .line 459
    .line 460
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 461
    .line 462
    .line 463
    move-result-object v0

    .line 464
    move-object v1, v0

    .line 465
    check-cast v1, Lh50/a1;

    .line 466
    .line 467
    const/4 v8, 0x0

    .line 468
    const/16 v9, 0x5f

    .line 469
    .line 470
    const/4 v2, 0x0

    .line 471
    const/4 v3, 0x0

    .line 472
    const/4 v4, 0x0

    .line 473
    const/4 v5, 0x0

    .line 474
    const/4 v6, 0x0

    .line 475
    const/4 v7, 0x1

    .line 476
    invoke-static/range {v1 .. v9}, Lh50/a1;->a(Lh50/a1;ZZZZZZZI)Lh50/a1;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 481
    .line 482
    .line 483
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 484
    .line 485
    return-object p0

    .line 486
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast p0, Lh50/b1;

    .line 489
    .line 490
    iget-object v0, p0, Lh50/b1;->m:Lqp0/r;

    .line 491
    .line 492
    if-eqz v0, :cond_0

    .line 493
    .line 494
    iget-boolean v1, v0, Lqp0/r;->g:Z

    .line 495
    .line 496
    xor-int/lit8 v7, v1, 0x1

    .line 497
    .line 498
    const/16 v8, 0x3f

    .line 499
    .line 500
    const/4 v1, 0x0

    .line 501
    const/4 v2, 0x0

    .line 502
    const/4 v3, 0x0

    .line 503
    const/4 v4, 0x0

    .line 504
    const/4 v5, 0x0

    .line 505
    const/4 v6, 0x0

    .line 506
    invoke-static/range {v0 .. v8}, Lqp0/r;->a(Lqp0/r;ZZZZLqr0/l;Lqr0/l;ZI)Lqp0/r;

    .line 507
    .line 508
    .line 509
    move-result-object v0

    .line 510
    invoke-virtual {p0, v0}, Lh50/b1;->h(Lqp0/r;)V

    .line 511
    .line 512
    .line 513
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 514
    .line 515
    return-object p0

    .line 516
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast p0, Lh50/b1;

    .line 519
    .line 520
    iget-object v0, p0, Lh50/b1;->m:Lqp0/r;

    .line 521
    .line 522
    if-eqz v0, :cond_1

    .line 523
    .line 524
    iget-boolean v1, v0, Lqp0/r;->d:Z

    .line 525
    .line 526
    xor-int/lit8 v4, v1, 0x1

    .line 527
    .line 528
    const/4 v7, 0x0

    .line 529
    const/16 v8, 0x77

    .line 530
    .line 531
    const/4 v1, 0x0

    .line 532
    const/4 v2, 0x0

    .line 533
    const/4 v3, 0x0

    .line 534
    const/4 v5, 0x0

    .line 535
    const/4 v6, 0x0

    .line 536
    invoke-static/range {v0 .. v8}, Lqp0/r;->a(Lqp0/r;ZZZZLqr0/l;Lqr0/l;ZI)Lqp0/r;

    .line 537
    .line 538
    .line 539
    move-result-object v0

    .line 540
    invoke-virtual {p0, v0}, Lh50/b1;->h(Lqp0/r;)V

    .line 541
    .line 542
    .line 543
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 544
    .line 545
    return-object p0

    .line 546
    :pswitch_19
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 547
    .line 548
    check-cast p0, Lh50/b1;

    .line 549
    .line 550
    iget-object v0, p0, Lh50/b1;->m:Lqp0/r;

    .line 551
    .line 552
    if-eqz v0, :cond_2

    .line 553
    .line 554
    iget-boolean v1, v0, Lqp0/r;->c:Z

    .line 555
    .line 556
    xor-int/lit8 v3, v1, 0x1

    .line 557
    .line 558
    const/4 v7, 0x0

    .line 559
    const/16 v8, 0x7b

    .line 560
    .line 561
    const/4 v1, 0x0

    .line 562
    const/4 v2, 0x0

    .line 563
    const/4 v4, 0x0

    .line 564
    const/4 v5, 0x0

    .line 565
    const/4 v6, 0x0

    .line 566
    invoke-static/range {v0 .. v8}, Lqp0/r;->a(Lqp0/r;ZZZZLqr0/l;Lqr0/l;ZI)Lqp0/r;

    .line 567
    .line 568
    .line 569
    move-result-object v0

    .line 570
    invoke-virtual {p0, v0}, Lh50/b1;->h(Lqp0/r;)V

    .line 571
    .line 572
    .line 573
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 574
    .line 575
    return-object p0

    .line 576
    :pswitch_1a
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 577
    .line 578
    check-cast p0, Lh50/b1;

    .line 579
    .line 580
    iget-object v0, p0, Lh50/b1;->m:Lqp0/r;

    .line 581
    .line 582
    if-eqz v0, :cond_3

    .line 583
    .line 584
    iget-boolean v1, v0, Lqp0/r;->b:Z

    .line 585
    .line 586
    xor-int/lit8 v2, v1, 0x1

    .line 587
    .line 588
    const/4 v7, 0x0

    .line 589
    const/16 v8, 0x7d

    .line 590
    .line 591
    const/4 v1, 0x0

    .line 592
    const/4 v3, 0x0

    .line 593
    const/4 v4, 0x0

    .line 594
    const/4 v5, 0x0

    .line 595
    const/4 v6, 0x0

    .line 596
    invoke-static/range {v0 .. v8}, Lqp0/r;->a(Lqp0/r;ZZZZLqr0/l;Lqr0/l;ZI)Lqp0/r;

    .line 597
    .line 598
    .line 599
    move-result-object v0

    .line 600
    invoke-virtual {p0, v0}, Lh50/b1;->h(Lqp0/r;)V

    .line 601
    .line 602
    .line 603
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 604
    .line 605
    return-object p0

    .line 606
    :pswitch_1b
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 607
    .line 608
    check-cast p0, Lh50/b1;

    .line 609
    .line 610
    iget-object v0, p0, Lh50/b1;->m:Lqp0/r;

    .line 611
    .line 612
    if-eqz v0, :cond_4

    .line 613
    .line 614
    iget-boolean v1, v0, Lqp0/r;->a:Z

    .line 615
    .line 616
    xor-int/lit8 v1, v1, 0x1

    .line 617
    .line 618
    const/4 v7, 0x0

    .line 619
    const/16 v8, 0x7e

    .line 620
    .line 621
    const/4 v2, 0x0

    .line 622
    const/4 v3, 0x0

    .line 623
    const/4 v4, 0x0

    .line 624
    const/4 v5, 0x0

    .line 625
    const/4 v6, 0x0

    .line 626
    invoke-static/range {v0 .. v8}, Lqp0/r;->a(Lqp0/r;ZZZZLqr0/l;Lqr0/l;ZI)Lqp0/r;

    .line 627
    .line 628
    .line 629
    move-result-object v0

    .line 630
    invoke-virtual {p0, v0}, Lh50/b1;->h(Lqp0/r;)V

    .line 631
    .line 632
    .line 633
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 634
    .line 635
    return-object p0

    .line 636
    :pswitch_1c
    iget-object p0, p0, Lkotlin/jvm/internal/d;->receiver:Ljava/lang/Object;

    .line 637
    .line 638
    check-cast p0, Lh50/b1;

    .line 639
    .line 640
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 641
    .line 642
    .line 643
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 644
    .line 645
    .line 646
    move-result-object v0

    .line 647
    new-instance v1, Lh50/z0;

    .line 648
    .line 649
    const/4 v2, 0x2

    .line 650
    const/4 v3, 0x0

    .line 651
    invoke-direct {v1, p0, v3, v2}, Lh50/z0;-><init>(Lh50/b1;Lkotlin/coroutines/Continuation;I)V

    .line 652
    .line 653
    .line 654
    const/4 p0, 0x3

    .line 655
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 656
    .line 657
    .line 658
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 659
    .line 660
    return-object p0

    .line 661
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
