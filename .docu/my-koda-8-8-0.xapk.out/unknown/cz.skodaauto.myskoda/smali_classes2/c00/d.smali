.class public final synthetic Lc00/d;
.super Lkotlin/jvm/internal/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V
    .locals 1

    .line 1
    iput p7, p0, Lc00/d;->d:I

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
    invoke-direct/range {p0 .. p6}, Lkotlin/jvm/internal/a;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lc00/d;->d:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/16 v2, 0xa

    .line 5
    .line 6
    const/4 v3, 0x5

    .line 7
    const/4 v4, 0x4

    .line 8
    const/4 v5, 0x2

    .line 9
    const/4 v6, 0x0

    .line 10
    sget-object v7, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v8, 0x3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Ly20/m;

    .line 19
    .line 20
    sget-object v0, Ly20/m;->H:Ljava/util/List;

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v1, Lwp0/c;

    .line 30
    .line 31
    invoke-direct {v1, v2, p0, v6, v6}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 32
    .line 33
    .line 34
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 35
    .line 36
    .line 37
    return-object v7

    .line 38
    :pswitch_0
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p0, Ly20/m;

    .line 41
    .line 42
    sget-object v0, Ly20/m;->H:Ljava/util/List;

    .line 43
    .line 44
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    new-instance v1, Lwp0/c;

    .line 52
    .line 53
    invoke-direct {v1, v2, p0, v6, v6}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 57
    .line 58
    .line 59
    return-object v7

    .line 60
    :pswitch_1
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast p0, Lvy/v;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    new-instance v1, Lvy/m;

    .line 72
    .line 73
    invoke-direct {v1, v8, v6, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 74
    .line 75
    .line 76
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 77
    .line 78
    .line 79
    return-object v7

    .line 80
    :pswitch_2
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast p0, Lvy/v;

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    new-instance v1, Lvy/m;

    .line 92
    .line 93
    invoke-direct {v1, v5, v6, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 97
    .line 98
    .line 99
    return-object v7

    .line 100
    :pswitch_3
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast p0, Lvy/v;

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
    new-instance v1, Lvy/m;

    .line 112
    .line 113
    invoke-direct {v1, v4, v6, p0}, Lvy/m;-><init>(ILkotlin/coroutines/Continuation;Lvy/v;)V

    .line 114
    .line 115
    .line 116
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 117
    .line 118
    .line 119
    return-object v7

    .line 120
    :pswitch_4
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast p0, Ltz/l3;

    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    new-instance v1, Ltz/o2;

    .line 132
    .line 133
    invoke-direct {v1, p0, v6, v8}, Ltz/o2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 134
    .line 135
    .line 136
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 137
    .line 138
    .line 139
    return-object v7

    .line 140
    :pswitch_5
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast p0, Lrh/u;

    .line 143
    .line 144
    invoke-virtual {p0}, Lrh/u;->b()Lvy0/x1;

    .line 145
    .line 146
    .line 147
    return-object v7

    .line 148
    :pswitch_6
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast p0, Lnz/z;

    .line 151
    .line 152
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 153
    .line 154
    .line 155
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    new-instance v1, Lnz/o;

    .line 160
    .line 161
    invoke-direct {v1, v5, v6, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 162
    .line 163
    .line 164
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 165
    .line 166
    .line 167
    return-object v7

    .line 168
    :pswitch_7
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast p0, Lnz/z;

    .line 171
    .line 172
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    new-instance v1, Lnz/o;

    .line 180
    .line 181
    invoke-direct {v1, v3, v6, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 182
    .line 183
    .line 184
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 185
    .line 186
    .line 187
    return-object v7

    .line 188
    :pswitch_8
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast p0, Lnz/z;

    .line 191
    .line 192
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 193
    .line 194
    .line 195
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    new-instance v1, Lnz/o;

    .line 200
    .line 201
    invoke-direct {v1, v8, v6, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 202
    .line 203
    .line 204
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 205
    .line 206
    .line 207
    return-object v7

    .line 208
    :pswitch_9
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p0, Lnz/z;

    .line 211
    .line 212
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 213
    .line 214
    .line 215
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 216
    .line 217
    .line 218
    move-result-object v0

    .line 219
    new-instance v1, Lnz/o;

    .line 220
    .line 221
    invoke-direct {v1, v4, v6, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 222
    .line 223
    .line 224
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 225
    .line 226
    .line 227
    return-object v7

    .line 228
    :pswitch_a
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p0, Lnz/z;

    .line 231
    .line 232
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 233
    .line 234
    .line 235
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    new-instance v1, Lnz/n;

    .line 240
    .line 241
    invoke-direct {v1, v5, v6, p0}, Lnz/n;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 242
    .line 243
    .line 244
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 245
    .line 246
    .line 247
    return-object v7

    .line 248
    :pswitch_b
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast p0, Lnt0/i;

    .line 251
    .line 252
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 253
    .line 254
    .line 255
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    new-instance v1, Lnt0/d;

    .line 260
    .line 261
    invoke-direct {v1, v5, v6, p0}, Lnt0/d;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 262
    .line 263
    .line 264
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 265
    .line 266
    .line 267
    return-object v7

    .line 268
    :pswitch_c
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast p0, Lk40/b;

    .line 271
    .line 272
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    new-instance v1, Lk20/a;

    .line 280
    .line 281
    invoke-direct {v1, p0, v6, v4}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 282
    .line 283
    .line 284
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 285
    .line 286
    .line 287
    return-object v7

    .line 288
    :pswitch_d
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 289
    .line 290
    check-cast p0, Lga0/o;

    .line 291
    .line 292
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 293
    .line 294
    .line 295
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    new-instance v1, Lga0/c;

    .line 300
    .line 301
    invoke-direct {v1, p0, v6, v3}, Lga0/c;-><init>(Lga0/o;Lkotlin/coroutines/Continuation;I)V

    .line 302
    .line 303
    .line 304
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 305
    .line 306
    .line 307
    return-object v7

    .line 308
    :pswitch_e
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 309
    .line 310
    check-cast p0, Lgg/c;

    .line 311
    .line 312
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 313
    .line 314
    .line 315
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    new-instance v1, Lg60/w;

    .line 320
    .line 321
    invoke-direct {v1, p0, v6, v4}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 322
    .line 323
    .line 324
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 325
    .line 326
    .line 327
    return-object v7

    .line 328
    :pswitch_f
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast p0, Lc00/q0;

    .line 331
    .line 332
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 333
    .line 334
    .line 335
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 336
    .line 337
    .line 338
    move-result-object v0

    .line 339
    new-instance v1, Lc00/p0;

    .line 340
    .line 341
    invoke-direct {v1, p0, v6}, Lc00/p0;-><init>(Lc00/q0;Lkotlin/coroutines/Continuation;)V

    .line 342
    .line 343
    .line 344
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 345
    .line 346
    .line 347
    return-object v7

    .line 348
    :pswitch_10
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast p0, Lc00/k1;

    .line 351
    .line 352
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 353
    .line 354
    .line 355
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 356
    .line 357
    .line 358
    move-result-object v0

    .line 359
    new-instance v1, Lc00/s0;

    .line 360
    .line 361
    invoke-direct {v1, p0, v6, v8}, Lc00/s0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 362
    .line 363
    .line 364
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 365
    .line 366
    .line 367
    return-object v7

    .line 368
    :pswitch_11
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 369
    .line 370
    check-cast p0, Lc00/k1;

    .line 371
    .line 372
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 373
    .line 374
    .line 375
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 376
    .line 377
    .line 378
    move-result-object v0

    .line 379
    new-instance v1, Lc00/s0;

    .line 380
    .line 381
    const/4 v2, 0x6

    .line 382
    invoke-direct {v1, p0, v6, v2}, Lc00/s0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 383
    .line 384
    .line 385
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 386
    .line 387
    .line 388
    return-object v7

    .line 389
    :pswitch_12
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 390
    .line 391
    check-cast p0, Lc00/k1;

    .line 392
    .line 393
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 394
    .line 395
    .line 396
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 397
    .line 398
    .line 399
    move-result-object v0

    .line 400
    new-instance v1, Lc00/s0;

    .line 401
    .line 402
    invoke-direct {v1, p0, v6, v3}, Lc00/s0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 403
    .line 404
    .line 405
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 406
    .line 407
    .line 408
    return-object v7

    .line 409
    :pswitch_13
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 410
    .line 411
    check-cast p0, Lc00/k1;

    .line 412
    .line 413
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 414
    .line 415
    .line 416
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 417
    .line 418
    .line 419
    move-result-object v0

    .line 420
    new-instance v1, Lc00/s0;

    .line 421
    .line 422
    invoke-direct {v1, p0, v6, v5}, Lc00/s0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 423
    .line 424
    .line 425
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 426
    .line 427
    .line 428
    return-object v7

    .line 429
    :pswitch_14
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast p0, Lc00/k1;

    .line 432
    .line 433
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 434
    .line 435
    .line 436
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 437
    .line 438
    .line 439
    move-result-object v0

    .line 440
    new-instance v1, Lc00/s0;

    .line 441
    .line 442
    invoke-direct {v1, p0, v6, v4}, Lc00/s0;-><init>(Lc00/k1;Lkotlin/coroutines/Continuation;I)V

    .line 443
    .line 444
    .line 445
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 446
    .line 447
    .line 448
    return-object v7

    .line 449
    :pswitch_15
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 450
    .line 451
    check-cast p0, Lc00/i0;

    .line 452
    .line 453
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 454
    .line 455
    .line 456
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 457
    .line 458
    .line 459
    move-result-object v0

    .line 460
    new-instance v2, Lc00/w;

    .line 461
    .line 462
    invoke-direct {v2, v1, p0, v6}, Lc00/w;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 463
    .line 464
    .line 465
    invoke-static {v0, v6, v6, v2, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 466
    .line 467
    .line 468
    return-object v7

    .line 469
    :pswitch_16
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 470
    .line 471
    check-cast p0, Lc00/i0;

    .line 472
    .line 473
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 474
    .line 475
    .line 476
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 477
    .line 478
    .line 479
    move-result-object v0

    .line 480
    new-instance v1, Lc00/w;

    .line 481
    .line 482
    invoke-direct {v1, v5, p0, v6}, Lc00/w;-><init>(ILc00/i0;Lkotlin/coroutines/Continuation;)V

    .line 483
    .line 484
    .line 485
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 486
    .line 487
    .line 488
    return-object v7

    .line 489
    :pswitch_17
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 490
    .line 491
    check-cast p0, Lbo0/k;

    .line 492
    .line 493
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 494
    .line 495
    .line 496
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 497
    .line 498
    .line 499
    move-result-object v0

    .line 500
    new-instance v2, Lbo0/g;

    .line 501
    .line 502
    invoke-direct {v2, p0, v6, v1}, Lbo0/g;-><init>(Lbo0/k;Lkotlin/coroutines/Continuation;I)V

    .line 503
    .line 504
    .line 505
    invoke-static {v0, v6, v6, v2, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 506
    .line 507
    .line 508
    return-object v7

    .line 509
    :pswitch_18
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 510
    .line 511
    check-cast p0, Lc00/h;

    .line 512
    .line 513
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 514
    .line 515
    .line 516
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 517
    .line 518
    .line 519
    move-result-object v0

    .line 520
    new-instance v1, La10/a;

    .line 521
    .line 522
    invoke-direct {v1, p0, v6, v4}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 523
    .line 524
    .line 525
    invoke-static {v0, v6, v6, v1, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 526
    .line 527
    .line 528
    return-object v7

    .line 529
    :pswitch_data_0
    .packed-switch 0x0
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
