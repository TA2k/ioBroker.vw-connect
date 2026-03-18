.class public final La30/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, La30/b;->d:I

    iput-object p2, p0, La30/b;->g:Ljava/lang/Object;

    iput-object p3, p0, La30/b;->f:Ljava/lang/Object;

    iput-object p4, p0, La30/b;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Landroidx/glance/session/SessionWorker;Lh7/a0;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, La30/b;->d:I

    .line 2
    iput-object p1, p0, La30/b;->f:Ljava/lang/Object;

    iput-object p2, p0, La30/b;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lna/o;Lla/b0;Lay0/n;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/16 v0, 0x1b

    iput v0, p0, La30/b;->d:I

    .line 3
    iput-object p1, p0, La30/b;->g:Ljava/lang/Object;

    iput-object p2, p0, La30/b;->f:Ljava/lang/Object;

    check-cast p3, Lrx0/i;

    iput-object p3, p0, La30/b;->h:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, La30/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, La30/b;

    .line 7
    .line 8
    iget-object v0, p0, La30/b;->g:Ljava/lang/Object;

    .line 9
    .line 10
    move-object v3, v0

    .line 11
    check-cast v3, Lnp0/c;

    .line 12
    .line 13
    iget-object v0, p0, La30/b;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Ljava/lang/String;

    .line 17
    .line 18
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 19
    .line 20
    move-object v5, p0

    .line 21
    check-cast v5, Ljava/util/List;

    .line 22
    .line 23
    const/16 v2, 0x1d

    .line 24
    .line 25
    move-object v6, p1

    .line 26
    invoke-direct/range {v1 .. v6}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 27
    .line 28
    .line 29
    return-object v1

    .line 30
    :pswitch_0
    move-object v7, p1

    .line 31
    new-instance v2, La30/b;

    .line 32
    .line 33
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 34
    .line 35
    move-object v4, p1

    .line 36
    check-cast v4, Lke/f;

    .line 37
    .line 38
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 39
    .line 40
    move-object v5, p1

    .line 41
    check-cast v5, Ljava/lang/String;

    .line 42
    .line 43
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 44
    .line 45
    move-object v6, p0

    .line 46
    check-cast v6, Ljava/lang/String;

    .line 47
    .line 48
    const/16 v3, 0x1c

    .line 49
    .line 50
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 51
    .line 52
    .line 53
    return-object v2

    .line 54
    :pswitch_1
    move-object v7, p1

    .line 55
    new-instance p1, La30/b;

    .line 56
    .line 57
    iget-object v0, p0, La30/b;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lna/o;

    .line 60
    .line 61
    iget-object v1, p0, La30/b;->f:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v1, Lla/b0;

    .line 64
    .line 65
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Lrx0/i;

    .line 68
    .line 69
    invoke-direct {p1, v0, v1, p0, v7}, La30/b;-><init>(Lna/o;Lla/b0;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 70
    .line 71
    .line 72
    return-object p1

    .line 73
    :pswitch_2
    move-object v7, p1

    .line 74
    new-instance v2, La30/b;

    .line 75
    .line 76
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v4, p1

    .line 79
    check-cast v4, Lm40/g;

    .line 80
    .line 81
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 82
    .line 83
    move-object v5, p1

    .line 84
    check-cast v5, Ljava/lang/String;

    .line 85
    .line 86
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 87
    .line 88
    move-object v6, p0

    .line 89
    check-cast v6, Ljava/lang/String;

    .line 90
    .line 91
    const/16 v3, 0x1a

    .line 92
    .line 93
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 94
    .line 95
    .line 96
    return-object v2

    .line 97
    :pswitch_3
    move-object v7, p1

    .line 98
    new-instance v2, La30/b;

    .line 99
    .line 100
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 101
    .line 102
    move-object v4, p1

    .line 103
    check-cast v4, Lm30/e;

    .line 104
    .line 105
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 106
    .line 107
    move-object v5, p1

    .line 108
    check-cast v5, Ljava/lang/String;

    .line 109
    .line 110
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 111
    .line 112
    move-object v6, p0

    .line 113
    check-cast v6, Lp30/d;

    .line 114
    .line 115
    const/16 v3, 0x19

    .line 116
    .line 117
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 118
    .line 119
    .line 120
    return-object v2

    .line 121
    :pswitch_4
    move-object v7, p1

    .line 122
    new-instance v2, La30/b;

    .line 123
    .line 124
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 125
    .line 126
    move-object v4, p1

    .line 127
    check-cast v4, Ljk0/c;

    .line 128
    .line 129
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 130
    .line 131
    move-object v5, p1

    .line 132
    check-cast v5, Ljava/lang/String;

    .line 133
    .line 134
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 135
    .line 136
    move-object v6, p0

    .line 137
    check-cast v6, Lxj0/f;

    .line 138
    .line 139
    const/16 v3, 0x18

    .line 140
    .line 141
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 142
    .line 143
    .line 144
    return-object v2

    .line 145
    :pswitch_5
    move-object v7, p1

    .line 146
    new-instance v2, La30/b;

    .line 147
    .line 148
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 149
    .line 150
    move-object v4, p1

    .line 151
    check-cast v4, Ljb0/x;

    .line 152
    .line 153
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 154
    .line 155
    move-object v5, p1

    .line 156
    check-cast v5, Ljava/lang/String;

    .line 157
    .line 158
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 159
    .line 160
    move-object v6, p0

    .line 161
    check-cast v6, Llx0/q;

    .line 162
    .line 163
    const/16 v3, 0x17

    .line 164
    .line 165
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 166
    .line 167
    .line 168
    return-object v2

    .line 169
    :pswitch_6
    move-object v7, p1

    .line 170
    new-instance v2, La30/b;

    .line 171
    .line 172
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 173
    .line 174
    move-object v4, p1

    .line 175
    check-cast v4, Ljb0/x;

    .line 176
    .line 177
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 178
    .line 179
    move-object v5, p1

    .line 180
    check-cast v5, Ljava/lang/String;

    .line 181
    .line 182
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 183
    .line 184
    move-object v6, p0

    .line 185
    check-cast v6, Lqr0/q;

    .line 186
    .line 187
    const/16 v3, 0x16

    .line 188
    .line 189
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 190
    .line 191
    .line 192
    return-object v2

    .line 193
    :pswitch_7
    move-object v7, p1

    .line 194
    new-instance v2, La30/b;

    .line 195
    .line 196
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 197
    .line 198
    move-object v4, p1

    .line 199
    check-cast v4, Ljb0/x;

    .line 200
    .line 201
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 202
    .line 203
    move-object v5, p1

    .line 204
    check-cast v5, Ljava/lang/String;

    .line 205
    .line 206
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 207
    .line 208
    move-object v6, p0

    .line 209
    check-cast v6, Ljava/util/ArrayList;

    .line 210
    .line 211
    const/16 v3, 0x15

    .line 212
    .line 213
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 214
    .line 215
    .line 216
    return-object v2

    .line 217
    :pswitch_8
    move-object v7, p1

    .line 218
    new-instance v2, La30/b;

    .line 219
    .line 220
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 221
    .line 222
    move-object v4, p1

    .line 223
    check-cast v4, Ljb0/x;

    .line 224
    .line 225
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 226
    .line 227
    move-object v5, p1

    .line 228
    check-cast v5, Ljava/lang/String;

    .line 229
    .line 230
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 231
    .line 232
    move-object v6, p0

    .line 233
    check-cast v6, Lmb0/l;

    .line 234
    .line 235
    const/16 v3, 0x14

    .line 236
    .line 237
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 238
    .line 239
    .line 240
    return-object v2

    .line 241
    :pswitch_9
    move-object v7, p1

    .line 242
    new-instance v2, La30/b;

    .line 243
    .line 244
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 245
    .line 246
    move-object v4, p1

    .line 247
    check-cast v4, Lif0/u;

    .line 248
    .line 249
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 250
    .line 251
    move-object v5, p1

    .line 252
    check-cast v5, Ljava/lang/String;

    .line 253
    .line 254
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 255
    .line 256
    move-object v6, p0

    .line 257
    check-cast v6, Ljava/lang/String;

    .line 258
    .line 259
    const/16 v3, 0x13

    .line 260
    .line 261
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 262
    .line 263
    .line 264
    return-object v2

    .line 265
    :pswitch_a
    move-object v7, p1

    .line 266
    new-instance v2, La30/b;

    .line 267
    .line 268
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 269
    .line 270
    move-object v4, p1

    .line 271
    check-cast v4, Lif0/u;

    .line 272
    .line 273
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 274
    .line 275
    move-object v5, p1

    .line 276
    check-cast v5, Ljava/lang/String;

    .line 277
    .line 278
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 279
    .line 280
    move-object v6, p0

    .line 281
    check-cast v6, Llf0/b;

    .line 282
    .line 283
    const/16 v3, 0x12

    .line 284
    .line 285
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 286
    .line 287
    .line 288
    return-object v2

    .line 289
    :pswitch_b
    move-object v7, p1

    .line 290
    new-instance v2, La30/b;

    .line 291
    .line 292
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 293
    .line 294
    move-object v4, p1

    .line 295
    check-cast v4, Lif0/h;

    .line 296
    .line 297
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 298
    .line 299
    move-object v5, p1

    .line 300
    check-cast v5, Ljava/lang/String;

    .line 301
    .line 302
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 303
    .line 304
    move-object v6, p0

    .line 305
    check-cast v6, Ljava/util/ArrayList;

    .line 306
    .line 307
    const/16 v3, 0x11

    .line 308
    .line 309
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 310
    .line 311
    .line 312
    return-object v2

    .line 313
    :pswitch_c
    move-object v7, p1

    .line 314
    new-instance v2, La30/b;

    .line 315
    .line 316
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 317
    .line 318
    move-object v4, p1

    .line 319
    check-cast v4, Lif0/e;

    .line 320
    .line 321
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 322
    .line 323
    move-object v5, p1

    .line 324
    check-cast v5, Ljava/lang/String;

    .line 325
    .line 326
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 327
    .line 328
    move-object v6, p0

    .line 329
    check-cast v6, Ljava/util/ArrayList;

    .line 330
    .line 331
    const/16 v3, 0x10

    .line 332
    .line 333
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 334
    .line 335
    .line 336
    return-object v2

    .line 337
    :pswitch_d
    move-object v7, p1

    .line 338
    new-instance v2, La30/b;

    .line 339
    .line 340
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 341
    .line 342
    move-object v4, p1

    .line 343
    check-cast v4, Lic0/a;

    .line 344
    .line 345
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 346
    .line 347
    move-object v5, p1

    .line 348
    check-cast v5, Ljava/lang/String;

    .line 349
    .line 350
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 351
    .line 352
    move-object v6, p0

    .line 353
    check-cast v6, Llc0/l;

    .line 354
    .line 355
    const/16 v3, 0xf

    .line 356
    .line 357
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 358
    .line 359
    .line 360
    return-object v2

    .line 361
    :pswitch_e
    move-object v7, p1

    .line 362
    new-instance v2, La30/b;

    .line 363
    .line 364
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 365
    .line 366
    move-object v4, p1

    .line 367
    check-cast v4, Li90/c;

    .line 368
    .line 369
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 370
    .line 371
    move-object v5, p1

    .line 372
    check-cast v5, Ljava/lang/String;

    .line 373
    .line 374
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 375
    .line 376
    move-object v6, p0

    .line 377
    check-cast v6, Lqr0/s;

    .line 378
    .line 379
    const/16 v3, 0xe

    .line 380
    .line 381
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 382
    .line 383
    .line 384
    return-object v2

    .line 385
    :pswitch_f
    move-object v7, p1

    .line 386
    new-instance v2, La30/b;

    .line 387
    .line 388
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 389
    .line 390
    move-object v4, p1

    .line 391
    check-cast v4, Li70/r;

    .line 392
    .line 393
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 394
    .line 395
    move-object v5, p1

    .line 396
    check-cast v5, Ljava/lang/String;

    .line 397
    .line 398
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 399
    .line 400
    move-object v6, p0

    .line 401
    check-cast v6, Ll70/h;

    .line 402
    .line 403
    const/16 v3, 0xd

    .line 404
    .line 405
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 406
    .line 407
    .line 408
    return-object v2

    .line 409
    :pswitch_10
    move-object v7, p1

    .line 410
    new-instance v2, La30/b;

    .line 411
    .line 412
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 413
    .line 414
    move-object v4, p1

    .line 415
    check-cast v4, Li70/r;

    .line 416
    .line 417
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 418
    .line 419
    move-object v5, p1

    .line 420
    check-cast v5, Ljava/lang/String;

    .line 421
    .line 422
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 423
    .line 424
    move-object v6, p0

    .line 425
    check-cast v6, Ljava/lang/String;

    .line 426
    .line 427
    const/16 v3, 0xc

    .line 428
    .line 429
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 430
    .line 431
    .line 432
    return-object v2

    .line 433
    :pswitch_11
    move-object v7, p1

    .line 434
    new-instance v2, La30/b;

    .line 435
    .line 436
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 437
    .line 438
    move-object v4, p1

    .line 439
    check-cast v4, Li70/r;

    .line 440
    .line 441
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 442
    .line 443
    move-object v5, p1

    .line 444
    check-cast v5, Ljava/lang/String;

    .line 445
    .line 446
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 447
    .line 448
    move-object v6, p0

    .line 449
    check-cast v6, Ll70/d;

    .line 450
    .line 451
    const/16 v3, 0xb

    .line 452
    .line 453
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 454
    .line 455
    .line 456
    return-object v2

    .line 457
    :pswitch_12
    move-object v7, p1

    .line 458
    new-instance v2, La30/b;

    .line 459
    .line 460
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 461
    .line 462
    move-object v4, p1

    .line 463
    check-cast v4, Li2/p;

    .line 464
    .line 465
    iget-object p1, p0, La30/b;->h:Ljava/lang/Object;

    .line 466
    .line 467
    move-object v6, p1

    .line 468
    check-cast v6, Lay0/p;

    .line 469
    .line 470
    const/16 v3, 0xa

    .line 471
    .line 472
    iget-object v5, p0, La30/b;->f:Ljava/lang/Object;

    .line 473
    .line 474
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 475
    .line 476
    .line 477
    return-object v2

    .line 478
    :pswitch_13
    move-object v7, p1

    .line 479
    new-instance p1, La30/b;

    .line 480
    .line 481
    iget-object v0, p0, La30/b;->f:Ljava/lang/Object;

    .line 482
    .line 483
    check-cast v0, Landroidx/glance/session/SessionWorker;

    .line 484
    .line 485
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 486
    .line 487
    check-cast p0, Lh7/a0;

    .line 488
    .line 489
    invoke-direct {p1, v0, p0, v7}, La30/b;-><init>(Landroidx/glance/session/SessionWorker;Lh7/a0;Lkotlin/coroutines/Continuation;)V

    .line 490
    .line 491
    .line 492
    return-object p1

    .line 493
    :pswitch_14
    move-object v7, p1

    .line 494
    new-instance v2, La30/b;

    .line 495
    .line 496
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 497
    .line 498
    move-object v4, p1

    .line 499
    check-cast v4, Lh2/yb;

    .line 500
    .line 501
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 502
    .line 503
    move-object v5, p1

    .line 504
    check-cast v5, La90/s;

    .line 505
    .line 506
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 507
    .line 508
    move-object v6, p0

    .line 509
    check-cast v6, Le1/w0;

    .line 510
    .line 511
    const/16 v3, 0x8

    .line 512
    .line 513
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 514
    .line 515
    .line 516
    return-object v2

    .line 517
    :pswitch_15
    move-object v7, p1

    .line 518
    new-instance v2, La30/b;

    .line 519
    .line 520
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 521
    .line 522
    move-object v4, p1

    .line 523
    check-cast v4, Lg1/q;

    .line 524
    .line 525
    iget-object p1, p0, La30/b;->h:Ljava/lang/Object;

    .line 526
    .line 527
    move-object v6, p1

    .line 528
    check-cast v6, Lay0/p;

    .line 529
    .line 530
    const/4 v3, 0x7

    .line 531
    iget-object v5, p0, La30/b;->f:Ljava/lang/Object;

    .line 532
    .line 533
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 534
    .line 535
    .line 536
    return-object v2

    .line 537
    :pswitch_16
    move-object v7, p1

    .line 538
    new-instance v2, La30/b;

    .line 539
    .line 540
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 541
    .line 542
    move-object v4, p1

    .line 543
    check-cast v4, Len0/c;

    .line 544
    .line 545
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 546
    .line 547
    move-object v5, p1

    .line 548
    check-cast v5, Ljava/lang/String;

    .line 549
    .line 550
    iget-object v6, p0, La30/b;->h:Ljava/lang/Object;

    .line 551
    .line 552
    const/4 v3, 0x6

    .line 553
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 554
    .line 555
    .line 556
    return-object v2

    .line 557
    :pswitch_17
    move-object v7, p1

    .line 558
    new-instance v2, La30/b;

    .line 559
    .line 560
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 561
    .line 562
    move-object v4, p1

    .line 563
    check-cast v4, Le80/b;

    .line 564
    .line 565
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 566
    .line 567
    move-object v5, p1

    .line 568
    check-cast v5, Ljava/lang/String;

    .line 569
    .line 570
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 571
    .line 572
    move-object v6, p0

    .line 573
    check-cast v6, Lg80/f;

    .line 574
    .line 575
    const/4 v3, 0x5

    .line 576
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 577
    .line 578
    .line 579
    return-object v2

    .line 580
    :pswitch_18
    move-object v7, p1

    .line 581
    new-instance v2, La30/b;

    .line 582
    .line 583
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 584
    .line 585
    move-object v4, p1

    .line 586
    check-cast v4, Ld40/n;

    .line 587
    .line 588
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 589
    .line 590
    move-object v5, p1

    .line 591
    check-cast v5, Ljava/lang/String;

    .line 592
    .line 593
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 594
    .line 595
    move-object v6, p0

    .line 596
    check-cast v6, Lg40/m0;

    .line 597
    .line 598
    const/4 v3, 0x4

    .line 599
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 600
    .line 601
    .line 602
    return-object v2

    .line 603
    :pswitch_19
    move-object v7, p1

    .line 604
    new-instance v2, La30/b;

    .line 605
    .line 606
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 607
    .line 608
    move-object v4, p1

    .line 609
    check-cast v4, Lar0/c;

    .line 610
    .line 611
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 612
    .line 613
    move-object v5, p1

    .line 614
    check-cast v5, Ljava/lang/String;

    .line 615
    .line 616
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 617
    .line 618
    move-object v6, p0

    .line 619
    check-cast v6, Ler0/l;

    .line 620
    .line 621
    const/4 v3, 0x3

    .line 622
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 623
    .line 624
    .line 625
    return-object v2

    .line 626
    :pswitch_1a
    move-object v7, p1

    .line 627
    new-instance v2, La30/b;

    .line 628
    .line 629
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 630
    .line 631
    move-object v4, p1

    .line 632
    check-cast v4, Lak0/c;

    .line 633
    .line 634
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 635
    .line 636
    move-object v5, p1

    .line 637
    check-cast v5, Ljava/util/UUID;

    .line 638
    .line 639
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 640
    .line 641
    move-object v6, p0

    .line 642
    check-cast v6, Ljava/util/List;

    .line 643
    .line 644
    const/4 v3, 0x2

    .line 645
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 646
    .line 647
    .line 648
    return-object v2

    .line 649
    :pswitch_1b
    move-object v7, p1

    .line 650
    new-instance v2, La30/b;

    .line 651
    .line 652
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 653
    .line 654
    move-object v4, p1

    .line 655
    check-cast v4, Lai0/a;

    .line 656
    .line 657
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 658
    .line 659
    move-object v5, p1

    .line 660
    check-cast v5, Ljava/lang/String;

    .line 661
    .line 662
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 663
    .line 664
    move-object v6, p0

    .line 665
    check-cast v6, Llf0/f;

    .line 666
    .line 667
    const/4 v3, 0x1

    .line 668
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 669
    .line 670
    .line 671
    return-object v2

    .line 672
    :pswitch_1c
    move-object v7, p1

    .line 673
    new-instance v2, La30/b;

    .line 674
    .line 675
    iget-object p1, p0, La30/b;->g:Ljava/lang/Object;

    .line 676
    .line 677
    move-object v4, p1

    .line 678
    check-cast v4, La30/d;

    .line 679
    .line 680
    iget-object p1, p0, La30/b;->f:Ljava/lang/Object;

    .line 681
    .line 682
    move-object v5, p1

    .line 683
    check-cast v5, Ljava/lang/String;

    .line 684
    .line 685
    iget-object p0, p0, La30/b;->h:Ljava/lang/Object;

    .line 686
    .line 687
    move-object v6, p0

    .line 688
    check-cast v6, Ljava/lang/String;

    .line 689
    .line 690
    const/4 v3, 0x0

    .line 691
    invoke-direct/range {v2 .. v7}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 692
    .line 693
    .line 694
    return-object v2

    .line 695
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

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, La30/b;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, La30/b;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, La30/b;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    :pswitch_1
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, La30/b;

    .line 39
    .line 40
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_2
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, La30/b;

    .line 52
    .line 53
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    return-object p0

    .line 60
    :pswitch_3
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, La30/b;

    .line 65
    .line 66
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0

    .line 73
    :pswitch_4
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    check-cast p0, La30/b;

    .line 78
    .line 79
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_5
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, La30/b;

    .line 91
    .line 92
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :pswitch_6
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    check-cast p0, La30/b;

    .line 104
    .line 105
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 106
    .line 107
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :pswitch_7
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    check-cast p0, La30/b;

    .line 117
    .line 118
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    return-object p0

    .line 125
    :pswitch_8
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    check-cast p0, La30/b;

    .line 130
    .line 131
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 132
    .line 133
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0

    .line 138
    :pswitch_9
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    check-cast p0, La30/b;

    .line 143
    .line 144
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 145
    .line 146
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    return-object p0

    .line 151
    :pswitch_a
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    check-cast p0, La30/b;

    .line 156
    .line 157
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 158
    .line 159
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    return-object p0

    .line 164
    :pswitch_b
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    check-cast p0, La30/b;

    .line 169
    .line 170
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object p0

    .line 176
    return-object p0

    .line 177
    :pswitch_c
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    check-cast p0, La30/b;

    .line 182
    .line 183
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    return-object p0

    .line 190
    :pswitch_d
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    check-cast p0, La30/b;

    .line 195
    .line 196
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 197
    .line 198
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    return-object p0

    .line 203
    :pswitch_e
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    check-cast p0, La30/b;

    .line 208
    .line 209
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    return-object p0

    .line 216
    :pswitch_f
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    check-cast p0, La30/b;

    .line 221
    .line 222
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 223
    .line 224
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p0

    .line 228
    return-object p0

    .line 229
    :pswitch_10
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 230
    .line 231
    .line 232
    move-result-object p0

    .line 233
    check-cast p0, La30/b;

    .line 234
    .line 235
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 236
    .line 237
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    return-object p0

    .line 242
    :pswitch_11
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 243
    .line 244
    .line 245
    move-result-object p0

    .line 246
    check-cast p0, La30/b;

    .line 247
    .line 248
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 249
    .line 250
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    return-object p0

    .line 255
    :pswitch_12
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 256
    .line 257
    .line 258
    move-result-object p0

    .line 259
    check-cast p0, La30/b;

    .line 260
    .line 261
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 262
    .line 263
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object p0

    .line 267
    return-object p0

    .line 268
    :pswitch_13
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    check-cast p0, La30/b;

    .line 273
    .line 274
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 275
    .line 276
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    return-object p0

    .line 281
    :pswitch_14
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    check-cast p0, La30/b;

    .line 286
    .line 287
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 288
    .line 289
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object p0

    .line 293
    return-object p0

    .line 294
    :pswitch_15
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 295
    .line 296
    .line 297
    move-result-object p0

    .line 298
    check-cast p0, La30/b;

    .line 299
    .line 300
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 301
    .line 302
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    return-object p0

    .line 307
    :pswitch_16
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 308
    .line 309
    .line 310
    move-result-object p0

    .line 311
    check-cast p0, La30/b;

    .line 312
    .line 313
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 314
    .line 315
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 316
    .line 317
    .line 318
    move-result-object p0

    .line 319
    return-object p0

    .line 320
    :pswitch_17
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    check-cast p0, La30/b;

    .line 325
    .line 326
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 327
    .line 328
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    return-object p0

    .line 333
    :pswitch_18
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 334
    .line 335
    .line 336
    move-result-object p0

    .line 337
    check-cast p0, La30/b;

    .line 338
    .line 339
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 340
    .line 341
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object p0

    .line 345
    return-object p0

    .line 346
    :pswitch_19
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 347
    .line 348
    .line 349
    move-result-object p0

    .line 350
    check-cast p0, La30/b;

    .line 351
    .line 352
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 353
    .line 354
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object p0

    .line 358
    return-object p0

    .line 359
    :pswitch_1a
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    check-cast p0, La30/b;

    .line 364
    .line 365
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 368
    .line 369
    .line 370
    move-result-object p0

    .line 371
    return-object p0

    .line 372
    :pswitch_1b
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 373
    .line 374
    .line 375
    move-result-object p0

    .line 376
    check-cast p0, La30/b;

    .line 377
    .line 378
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 379
    .line 380
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 381
    .line 382
    .line 383
    move-result-object p0

    .line 384
    return-object p0

    .line 385
    :pswitch_1c
    invoke-virtual {p0, p1}, La30/b;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 386
    .line 387
    .line 388
    move-result-object p0

    .line 389
    check-cast p0, La30/b;

    .line 390
    .line 391
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 392
    .line 393
    invoke-virtual {p0, p1}, La30/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 394
    .line 395
    .line 396
    move-result-object p0

    .line 397
    return-object p0

    .line 398
    nop

    .line 399
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

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v5, p0

    .line 2
    .line 3
    iget v0, v5, La30/b;->d:I

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v6, 0x3

    .line 7
    const/4 v7, 0x4

    .line 8
    const/16 v2, 0xa

    .line 9
    .line 10
    const-string v3, "<this>"

    .line 11
    .line 12
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v9, 0x2

    .line 15
    iget-object v10, v5, La30/b;->h:Ljava/lang/Object;

    .line 16
    .line 17
    iget-object v11, v5, La30/b;->f:Ljava/lang/Object;

    .line 18
    .line 19
    const-string v12, "call to \'resume\' before \'invoke\' with coroutine"

    .line 20
    .line 21
    const/4 v13, 0x1

    .line 22
    packed-switch v0, :pswitch_data_0

    .line 23
    .line 24
    .line 25
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    iget v1, v5, La30/b;->e:I

    .line 28
    .line 29
    if-eqz v1, :cond_2

    .line 30
    .line 31
    if-eq v1, v13, :cond_1

    .line 32
    .line 33
    if-ne v1, v9, :cond_0

    .line 34
    .line 35
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    move-object/from16 v0, p1

    .line 39
    .line 40
    goto/16 :goto_3

    .line 41
    .line 42
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v0

    .line 48
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    move-object/from16 v1, p1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v1, Lnp0/c;

    .line 60
    .line 61
    iget-object v1, v1, Lnp0/c;->b:Lti0/a;

    .line 62
    .line 63
    iput v13, v5, La30/b;->e:I

    .line 64
    .line 65
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    if-ne v1, v0, :cond_3

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    :goto_0
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 73
    .line 74
    check-cast v11, Ljava/lang/String;

    .line 75
    .line 76
    check-cast v10, Ljava/util/List;

    .line 77
    .line 78
    check-cast v10, Ljava/lang/Iterable;

    .line 79
    .line 80
    new-instance v4, Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-static {v10, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object v2

    .line 93
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    if-eqz v6, :cond_5

    .line 98
    .line 99
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Lqp0/b0;

    .line 104
    .line 105
    sget-object v7, Lnp0/h;->a:Ljava/util/List;

    .line 106
    .line 107
    invoke-static {v6, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    iget-object v7, v6, Lqp0/b0;->a:Ljava/lang/String;

    .line 111
    .line 112
    iget-object v10, v6, Lqp0/b0;->c:Lqp0/t0;

    .line 113
    .line 114
    invoke-static {v10}, Lnp0/h;->a(Lqp0/t0;)Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v10

    .line 118
    iget-object v6, v6, Lqp0/b0;->d:Lxj0/f;

    .line 119
    .line 120
    if-eqz v6, :cond_4

    .line 121
    .line 122
    new-instance v12, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;

    .line 123
    .line 124
    iget-wide v13, v6, Lxj0/f;->a:D

    .line 125
    .line 126
    iget-wide v8, v6, Lxj0/f;->b:D

    .line 127
    .line 128
    invoke-direct {v12, v13, v14, v8, v9}, Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;-><init>(DD)V

    .line 129
    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    const/4 v12, 0x0

    .line 133
    :goto_2
    new-instance v6, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;

    .line 134
    .line 135
    invoke-direct {v6, v10, v7, v12}, Lcz/myskoda/api/bff_maps/v3/RouteRequestWaypointDto;-><init>(Ljava/lang/String;Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/GpsCoordinatesDto;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    const/4 v9, 0x2

    .line 142
    goto :goto_1

    .line 143
    :cond_5
    new-instance v2, Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;

    .line 144
    .line 145
    invoke-direct {v2, v4}, Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;-><init>(Ljava/util/List;)V

    .line 146
    .line 147
    .line 148
    const/4 v3, 0x2

    .line 149
    iput v3, v5, La30/b;->e:I

    .line 150
    .line 151
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->sendRoute(Ljava/lang/String;Lcz/myskoda/api/bff_maps/v3/SendRouteRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    if-ne v1, v0, :cond_6

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_6
    move-object v0, v1

    .line 159
    :goto_3
    return-object v0

    .line 160
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 161
    .line 162
    iget v1, v5, La30/b;->e:I

    .line 163
    .line 164
    if-eqz v1, :cond_8

    .line 165
    .line 166
    if-ne v1, v13, :cond_7

    .line 167
    .line 168
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    move-object/from16 v0, p1

    .line 172
    .line 173
    check-cast v0, Llx0/o;

    .line 174
    .line 175
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 176
    .line 177
    goto :goto_4

    .line 178
    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 179
    .line 180
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 181
    .line 182
    .line 183
    throw v0

    .line 184
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v1, Lke/f;

    .line 190
    .line 191
    check-cast v11, Ljava/lang/String;

    .line 192
    .line 193
    check-cast v10, Ljava/lang/String;

    .line 194
    .line 195
    iput v13, v5, La30/b;->e:I

    .line 196
    .line 197
    invoke-virtual {v1, v11, v10, v5}, Lke/f;->c(Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v1

    .line 201
    if-ne v1, v0, :cond_9

    .line 202
    .line 203
    goto :goto_5

    .line 204
    :cond_9
    move-object v0, v1

    .line 205
    :goto_4
    new-instance v1, Llx0/o;

    .line 206
    .line 207
    invoke-direct {v1, v0}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    move-object v0, v1

    .line 211
    :goto_5
    return-object v0

    .line 212
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 213
    .line 214
    iget v1, v5, La30/b;->e:I

    .line 215
    .line 216
    if-eqz v1, :cond_b

    .line 217
    .line 218
    if-ne v1, v13, :cond_a

    .line 219
    .line 220
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    move-object/from16 v0, p1

    .line 224
    .line 225
    goto :goto_6

    .line 226
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 227
    .line 228
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 229
    .line 230
    .line 231
    throw v0

    .line 232
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 236
    .line 237
    check-cast v1, Lna/o;

    .line 238
    .line 239
    check-cast v11, Lla/b0;

    .line 240
    .line 241
    check-cast v10, Lrx0/i;

    .line 242
    .line 243
    iput v13, v5, La30/b;->e:I

    .line 244
    .line 245
    invoke-virtual {v1, v11, v10, v5}, Lna/o;->e(Lla/b0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v1

    .line 249
    if-ne v1, v0, :cond_c

    .line 250
    .line 251
    goto :goto_6

    .line 252
    :cond_c
    move-object v0, v1

    .line 253
    :goto_6
    return-object v0

    .line 254
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 255
    .line 256
    iget v1, v5, La30/b;->e:I

    .line 257
    .line 258
    if-eqz v1, :cond_f

    .line 259
    .line 260
    if-eq v1, v13, :cond_e

    .line 261
    .line 262
    const/4 v3, 0x2

    .line 263
    if-ne v1, v3, :cond_d

    .line 264
    .line 265
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    move-object/from16 v0, p1

    .line 269
    .line 270
    goto :goto_a

    .line 271
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 272
    .line 273
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 274
    .line 275
    .line 276
    throw v0

    .line 277
    :cond_e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    move-object/from16 v1, p1

    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v1, Lm40/g;

    .line 289
    .line 290
    iget-object v1, v1, Lm40/g;->b:Lti0/a;

    .line 291
    .line 292
    iput v13, v5, La30/b;->e:I

    .line 293
    .line 294
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v1

    .line 298
    if-ne v1, v0, :cond_10

    .line 299
    .line 300
    goto :goto_a

    .line 301
    :cond_10
    :goto_7
    check-cast v1, Lcz/myskoda/api/bff_fueling/v2/FuelingApi;

    .line 302
    .line 303
    check-cast v11, Ljava/lang/String;

    .line 304
    .line 305
    check-cast v10, Ljava/lang/String;

    .line 306
    .line 307
    if-nez v10, :cond_11

    .line 308
    .line 309
    const/4 v8, 0x0

    .line 310
    :goto_8
    const/4 v3, 0x2

    .line 311
    goto :goto_9

    .line 312
    :cond_11
    move-object v8, v10

    .line 313
    goto :goto_8

    .line 314
    :goto_9
    iput v3, v5, La30/b;->e:I

    .line 315
    .line 316
    invoke-interface {v1, v11, v8, v5}, Lcz/myskoda/api/bff_fueling/v2/FuelingApi;->getGasStation(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    if-ne v1, v0, :cond_12

    .line 321
    .line 322
    goto :goto_a

    .line 323
    :cond_12
    move-object v0, v1

    .line 324
    :goto_a
    return-object v0

    .line 325
    :pswitch_3
    move v3, v9

    .line 326
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 327
    .line 328
    iget v1, v5, La30/b;->e:I

    .line 329
    .line 330
    if-eqz v1, :cond_15

    .line 331
    .line 332
    if-eq v1, v13, :cond_14

    .line 333
    .line 334
    if-ne v1, v3, :cond_13

    .line 335
    .line 336
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 337
    .line 338
    .line 339
    move-object/from16 v0, p1

    .line 340
    .line 341
    goto :goto_c

    .line 342
    :cond_13
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 343
    .line 344
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 345
    .line 346
    .line 347
    throw v0

    .line 348
    :cond_14
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 349
    .line 350
    .line 351
    move-object/from16 v1, p1

    .line 352
    .line 353
    goto :goto_b

    .line 354
    :cond_15
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 355
    .line 356
    .line 357
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 358
    .line 359
    check-cast v1, Lm30/e;

    .line 360
    .line 361
    iget-object v1, v1, Lm30/e;->b:Lti0/a;

    .line 362
    .line 363
    iput v13, v5, La30/b;->e:I

    .line 364
    .line 365
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 366
    .line 367
    .line 368
    move-result-object v1

    .line 369
    if-ne v1, v0, :cond_16

    .line 370
    .line 371
    goto :goto_c

    .line 372
    :cond_16
    :goto_b
    check-cast v1, Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;

    .line 373
    .line 374
    check-cast v11, Ljava/lang/String;

    .line 375
    .line 376
    check-cast v10, Lp30/d;

    .line 377
    .line 378
    new-instance v2, Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;

    .line 379
    .line 380
    iget-object v3, v10, Lp30/d;->a:Ljava/lang/String;

    .line 381
    .line 382
    invoke-direct {v2, v3}, Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    const/4 v3, 0x2

    .line 386
    iput v3, v5, La30/b;->e:I

    .line 387
    .line 388
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_ai_assistant/v2/AiAssistantApi;->aiAssistantConversation(Ljava/lang/String;Lcz/myskoda/api/bff_ai_assistant/v2/ConversationRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v1

    .line 392
    if-ne v1, v0, :cond_17

    .line 393
    .line 394
    goto :goto_c

    .line 395
    :cond_17
    move-object v0, v1

    .line 396
    :goto_c
    return-object v0

    .line 397
    :pswitch_4
    check-cast v10, Lxj0/f;

    .line 398
    .line 399
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 400
    .line 401
    iget v1, v5, La30/b;->e:I

    .line 402
    .line 403
    if-eqz v1, :cond_1a

    .line 404
    .line 405
    if-eq v1, v13, :cond_19

    .line 406
    .line 407
    const/4 v3, 0x2

    .line 408
    if-ne v1, v3, :cond_18

    .line 409
    .line 410
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 411
    .line 412
    .line 413
    move-object/from16 v0, p1

    .line 414
    .line 415
    goto :goto_11

    .line 416
    :cond_18
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 417
    .line 418
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 419
    .line 420
    .line 421
    throw v0

    .line 422
    :cond_19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 423
    .line 424
    .line 425
    move-object/from16 v1, p1

    .line 426
    .line 427
    goto :goto_d

    .line 428
    :cond_1a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 429
    .line 430
    .line 431
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 432
    .line 433
    check-cast v1, Ljk0/c;

    .line 434
    .line 435
    iget-object v1, v1, Ljk0/c;->b:Lti0/a;

    .line 436
    .line 437
    iput v13, v5, La30/b;->e:I

    .line 438
    .line 439
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-result-object v1

    .line 443
    if-ne v1, v0, :cond_1b

    .line 444
    .line 445
    goto :goto_11

    .line 446
    :cond_1b
    :goto_d
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 447
    .line 448
    move-object v2, v11

    .line 449
    check-cast v2, Ljava/lang/String;

    .line 450
    .line 451
    if-nez v2, :cond_1c

    .line 452
    .line 453
    const/4 v2, 0x0

    .line 454
    :cond_1c
    if-eqz v10, :cond_1d

    .line 455
    .line 456
    iget-wide v3, v10, Lxj0/f;->a:D

    .line 457
    .line 458
    new-instance v6, Ljava/lang/Double;

    .line 459
    .line 460
    invoke-direct {v6, v3, v4}, Ljava/lang/Double;-><init>(D)V

    .line 461
    .line 462
    .line 463
    goto :goto_e

    .line 464
    :cond_1d
    const/4 v6, 0x0

    .line 465
    :goto_e
    if-eqz v10, :cond_1e

    .line 466
    .line 467
    iget-wide v3, v10, Lxj0/f;->b:D

    .line 468
    .line 469
    new-instance v8, Ljava/lang/Double;

    .line 470
    .line 471
    invoke-direct {v8, v3, v4}, Ljava/lang/Double;-><init>(D)V

    .line 472
    .line 473
    .line 474
    :goto_f
    const/4 v3, 0x2

    .line 475
    goto :goto_10

    .line 476
    :cond_1e
    const/4 v8, 0x0

    .line 477
    goto :goto_f

    .line 478
    :goto_10
    iput v3, v5, La30/b;->e:I

    .line 479
    .line 480
    invoke-interface {v1, v2, v6, v8, v5}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->getFavouritePlaces(Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Double;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 481
    .line 482
    .line 483
    move-result-object v1

    .line 484
    if-ne v1, v0, :cond_1f

    .line 485
    .line 486
    goto :goto_11

    .line 487
    :cond_1f
    move-object v0, v1

    .line 488
    :goto_11
    return-object v0

    .line 489
    :pswitch_5
    move v3, v9

    .line 490
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 491
    .line 492
    iget v1, v5, La30/b;->e:I

    .line 493
    .line 494
    if-eqz v1, :cond_22

    .line 495
    .line 496
    if-eq v1, v13, :cond_21

    .line 497
    .line 498
    if-ne v1, v3, :cond_20

    .line 499
    .line 500
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 501
    .line 502
    .line 503
    move-object/from16 v0, p1

    .line 504
    .line 505
    goto :goto_13

    .line 506
    :cond_20
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 507
    .line 508
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 509
    .line 510
    .line 511
    throw v0

    .line 512
    :cond_21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 513
    .line 514
    .line 515
    move-object/from16 v1, p1

    .line 516
    .line 517
    goto :goto_12

    .line 518
    :cond_22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 519
    .line 520
    .line 521
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 522
    .line 523
    check-cast v1, Ljb0/x;

    .line 524
    .line 525
    iget-object v1, v1, Ljb0/x;->b:Lti0/a;

    .line 526
    .line 527
    iput v13, v5, La30/b;->e:I

    .line 528
    .line 529
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object v1

    .line 533
    if-ne v1, v0, :cond_23

    .line 534
    .line 535
    goto :goto_13

    .line 536
    :cond_23
    :goto_12
    check-cast v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 537
    .line 538
    check-cast v11, Ljava/lang/String;

    .line 539
    .line 540
    check-cast v10, Llx0/q;

    .line 541
    .line 542
    invoke-virtual {v10}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 543
    .line 544
    .line 545
    move-result-object v2

    .line 546
    check-cast v2, Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;

    .line 547
    .line 548
    const/4 v3, 0x2

    .line 549
    iput v3, v5, La30/b;->e:I

    .line 550
    .line 551
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->startAirConditioning(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/StartAirConditioningConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 552
    .line 553
    .line 554
    move-result-object v1

    .line 555
    if-ne v1, v0, :cond_24

    .line 556
    .line 557
    goto :goto_13

    .line 558
    :cond_24
    move-object v0, v1

    .line 559
    :goto_13
    return-object v0

    .line 560
    :pswitch_6
    move v3, v9

    .line 561
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 562
    .line 563
    iget v1, v5, La30/b;->e:I

    .line 564
    .line 565
    if-eqz v1, :cond_27

    .line 566
    .line 567
    if-eq v1, v13, :cond_26

    .line 568
    .line 569
    if-ne v1, v3, :cond_25

    .line 570
    .line 571
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 572
    .line 573
    .line 574
    move-object/from16 v0, p1

    .line 575
    .line 576
    goto :goto_15

    .line 577
    :cond_25
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 578
    .line 579
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 580
    .line 581
    .line 582
    throw v0

    .line 583
    :cond_26
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 584
    .line 585
    .line 586
    move-object/from16 v1, p1

    .line 587
    .line 588
    goto :goto_14

    .line 589
    :cond_27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 590
    .line 591
    .line 592
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 593
    .line 594
    check-cast v1, Ljb0/x;

    .line 595
    .line 596
    iget-object v1, v1, Ljb0/x;->b:Lti0/a;

    .line 597
    .line 598
    iput v13, v5, La30/b;->e:I

    .line 599
    .line 600
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 601
    .line 602
    .line 603
    move-result-object v1

    .line 604
    if-ne v1, v0, :cond_28

    .line 605
    .line 606
    goto :goto_15

    .line 607
    :cond_28
    :goto_14
    check-cast v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 608
    .line 609
    check-cast v11, Ljava/lang/String;

    .line 610
    .line 611
    check-cast v10, Lqr0/q;

    .line 612
    .line 613
    invoke-static {v10}, Ljb0/k;->a(Lqr0/q;)Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;

    .line 614
    .line 615
    .line 616
    move-result-object v2

    .line 617
    const/4 v3, 0x2

    .line 618
    iput v3, v5, La30/b;->e:I

    .line 619
    .line 620
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningTargetTemperature(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTargetTemperatureDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 621
    .line 622
    .line 623
    move-result-object v1

    .line 624
    if-ne v1, v0, :cond_29

    .line 625
    .line 626
    goto :goto_15

    .line 627
    :cond_29
    move-object v0, v1

    .line 628
    :goto_15
    return-object v0

    .line 629
    :pswitch_7
    move v3, v9

    .line 630
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 631
    .line 632
    iget v1, v5, La30/b;->e:I

    .line 633
    .line 634
    if-eqz v1, :cond_2c

    .line 635
    .line 636
    if-eq v1, v13, :cond_2b

    .line 637
    .line 638
    if-ne v1, v3, :cond_2a

    .line 639
    .line 640
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 641
    .line 642
    .line 643
    move-object/from16 v0, p1

    .line 644
    .line 645
    goto :goto_18

    .line 646
    :cond_2a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 647
    .line 648
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 649
    .line 650
    .line 651
    throw v0

    .line 652
    :cond_2b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 653
    .line 654
    .line 655
    move-object/from16 v1, p1

    .line 656
    .line 657
    goto :goto_16

    .line 658
    :cond_2c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 659
    .line 660
    .line 661
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 662
    .line 663
    check-cast v1, Ljb0/x;

    .line 664
    .line 665
    iget-object v1, v1, Ljb0/x;->b:Lti0/a;

    .line 666
    .line 667
    iput v13, v5, La30/b;->e:I

    .line 668
    .line 669
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 670
    .line 671
    .line 672
    move-result-object v1

    .line 673
    if-ne v1, v0, :cond_2d

    .line 674
    .line 675
    goto :goto_18

    .line 676
    :cond_2d
    :goto_16
    check-cast v1, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 677
    .line 678
    check-cast v11, Ljava/lang/String;

    .line 679
    .line 680
    check-cast v10, Ljava/util/ArrayList;

    .line 681
    .line 682
    new-instance v3, Ljava/util/ArrayList;

    .line 683
    .line 684
    invoke-static {v10, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 685
    .line 686
    .line 687
    move-result v2

    .line 688
    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 689
    .line 690
    .line 691
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 692
    .line 693
    .line 694
    move-result-object v2

    .line 695
    :goto_17
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 696
    .line 697
    .line 698
    move-result v4

    .line 699
    if-eqz v4, :cond_2e

    .line 700
    .line 701
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 702
    .line 703
    .line 704
    move-result-object v4

    .line 705
    check-cast v4, Lao0/c;

    .line 706
    .line 707
    invoke-static {v4}, Lwn0/c;->a(Lao0/c;)Lcz/myskoda/api/bff_air_conditioning/v2/TimerDto;

    .line 708
    .line 709
    .line 710
    move-result-object v4

    .line 711
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 712
    .line 713
    .line 714
    goto :goto_17

    .line 715
    :cond_2e
    new-instance v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;

    .line 716
    .line 717
    invoke-direct {v2, v3}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;-><init>(Ljava/util/List;)V

    .line 718
    .line 719
    .line 720
    const/4 v3, 0x2

    .line 721
    iput v3, v5, La30/b;->e:I

    .line 722
    .line 723
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningTimers(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningTimersConfigurationDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v1

    .line 727
    if-ne v1, v0, :cond_2f

    .line 728
    .line 729
    goto :goto_18

    .line 730
    :cond_2f
    move-object v0, v1

    .line 731
    :goto_18
    return-object v0

    .line 732
    :pswitch_8
    move v3, v9

    .line 733
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 734
    .line 735
    iget v2, v5, La30/b;->e:I

    .line 736
    .line 737
    if-eqz v2, :cond_32

    .line 738
    .line 739
    if-eq v2, v13, :cond_31

    .line 740
    .line 741
    if-ne v2, v3, :cond_30

    .line 742
    .line 743
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 744
    .line 745
    .line 746
    move-object/from16 v0, p1

    .line 747
    .line 748
    goto/16 :goto_1d

    .line 749
    .line 750
    :cond_30
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 751
    .line 752
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 753
    .line 754
    .line 755
    throw v0

    .line 756
    :cond_31
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 757
    .line 758
    .line 759
    move-object/from16 v2, p1

    .line 760
    .line 761
    goto :goto_19

    .line 762
    :cond_32
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 763
    .line 764
    .line 765
    iget-object v2, v5, La30/b;->g:Ljava/lang/Object;

    .line 766
    .line 767
    check-cast v2, Ljb0/x;

    .line 768
    .line 769
    iget-object v2, v2, Ljb0/x;->b:Lti0/a;

    .line 770
    .line 771
    iput v13, v5, La30/b;->e:I

    .line 772
    .line 773
    invoke-interface {v2, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 774
    .line 775
    .line 776
    move-result-object v2

    .line 777
    if-ne v2, v0, :cond_33

    .line 778
    .line 779
    goto :goto_1d

    .line 780
    :cond_33
    :goto_19
    check-cast v2, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;

    .line 781
    .line 782
    check-cast v11, Ljava/lang/String;

    .line 783
    .line 784
    check-cast v10, Lmb0/l;

    .line 785
    .line 786
    new-instance v3, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;

    .line 787
    .line 788
    iget-object v4, v10, Lmb0/l;->a:Ljava/lang/Boolean;

    .line 789
    .line 790
    if-eqz v4, :cond_34

    .line 791
    .line 792
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 793
    .line 794
    .line 795
    move-result v4

    .line 796
    goto :goto_1a

    .line 797
    :cond_34
    move v4, v1

    .line 798
    :goto_1a
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 799
    .line 800
    .line 801
    move-result-object v4

    .line 802
    iget-object v6, v10, Lmb0/l;->b:Ljava/lang/Boolean;

    .line 803
    .line 804
    if-eqz v6, :cond_35

    .line 805
    .line 806
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 807
    .line 808
    .line 809
    move-result v6

    .line 810
    goto :goto_1b

    .line 811
    :cond_35
    move v6, v1

    .line 812
    :goto_1b
    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 813
    .line 814
    .line 815
    move-result-object v6

    .line 816
    iget-object v7, v10, Lmb0/l;->c:Ljava/lang/Boolean;

    .line 817
    .line 818
    if-eqz v7, :cond_36

    .line 819
    .line 820
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 821
    .line 822
    .line 823
    move-result v7

    .line 824
    goto :goto_1c

    .line 825
    :cond_36
    move v7, v1

    .line 826
    :goto_1c
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 827
    .line 828
    .line 829
    move-result-object v7

    .line 830
    iget-object v8, v10, Lmb0/l;->d:Ljava/lang/Boolean;

    .line 831
    .line 832
    if-eqz v8, :cond_37

    .line 833
    .line 834
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 835
    .line 836
    .line 837
    move-result v1

    .line 838
    :cond_37
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 839
    .line 840
    .line 841
    move-result-object v1

    .line 842
    invoke-direct {v3, v4, v6, v7, v1}, Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;-><init>(Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;Ljava/lang/Boolean;)V

    .line 843
    .line 844
    .line 845
    const/4 v1, 0x2

    .line 846
    iput v1, v5, La30/b;->e:I

    .line 847
    .line 848
    invoke-interface {v2, v11, v3, v5}, Lcz/myskoda/api/bff_air_conditioning/v2/AirConditioningApi;->setAirConditioningSeatsHeating(Ljava/lang/String;Lcz/myskoda/api/bff_air_conditioning/v2/SeatHeatingSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 849
    .line 850
    .line 851
    move-result-object v1

    .line 852
    if-ne v1, v0, :cond_38

    .line 853
    .line 854
    goto :goto_1d

    .line 855
    :cond_38
    move-object v0, v1

    .line 856
    :goto_1d
    return-object v0

    .line 857
    :pswitch_9
    move v1, v9

    .line 858
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 859
    .line 860
    iget v2, v5, La30/b;->e:I

    .line 861
    .line 862
    if-eqz v2, :cond_3b

    .line 863
    .line 864
    if-eq v2, v13, :cond_3a

    .line 865
    .line 866
    if-ne v2, v1, :cond_39

    .line 867
    .line 868
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 869
    .line 870
    .line 871
    move-object/from16 v0, p1

    .line 872
    .line 873
    goto :goto_1f

    .line 874
    :cond_39
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 875
    .line 876
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 877
    .line 878
    .line 879
    throw v0

    .line 880
    :cond_3a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 881
    .line 882
    .line 883
    move-object/from16 v1, p1

    .line 884
    .line 885
    goto :goto_1e

    .line 886
    :cond_3b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 887
    .line 888
    .line 889
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 890
    .line 891
    check-cast v1, Lif0/u;

    .line 892
    .line 893
    iget-object v1, v1, Lif0/u;->b:Lti0/a;

    .line 894
    .line 895
    iput v13, v5, La30/b;->e:I

    .line 896
    .line 897
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 898
    .line 899
    .line 900
    move-result-object v1

    .line 901
    if-ne v1, v0, :cond_3c

    .line 902
    .line 903
    goto :goto_1f

    .line 904
    :cond_3c
    :goto_1e
    check-cast v1, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 905
    .line 906
    check-cast v11, Ljava/lang/String;

    .line 907
    .line 908
    check-cast v10, Ljava/lang/String;

    .line 909
    .line 910
    const-string v2, "$v$c$cz-skodaauto-myskoda-library-deliveredvehicle-model-LicensePlate$-$this$toDto$0"

    .line 911
    .line 912
    invoke-static {v10, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 913
    .line 914
    .line 915
    new-instance v2, Lcz/myskoda/api/bff_garage/v2/LicensePlateDto;

    .line 916
    .line 917
    invoke-direct {v2, v10}, Lcz/myskoda/api/bff_garage/v2/LicensePlateDto;-><init>(Ljava/lang/String;)V

    .line 918
    .line 919
    .line 920
    const/4 v4, 0x2

    .line 921
    iput v4, v5, La30/b;->e:I

    .line 922
    .line 923
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_garage/v2/GarageApi;->updateVehicleLicensePlate(Ljava/lang/String;Lcz/myskoda/api/bff_garage/v2/LicensePlateDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 924
    .line 925
    .line 926
    move-result-object v1

    .line 927
    if-ne v1, v0, :cond_3d

    .line 928
    .line 929
    goto :goto_1f

    .line 930
    :cond_3d
    move-object v0, v1

    .line 931
    :goto_1f
    return-object v0

    .line 932
    :pswitch_a
    move v4, v9

    .line 933
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 934
    .line 935
    iget v1, v5, La30/b;->e:I

    .line 936
    .line 937
    if-eqz v1, :cond_40

    .line 938
    .line 939
    if-eq v1, v13, :cond_3f

    .line 940
    .line 941
    if-ne v1, v4, :cond_3e

    .line 942
    .line 943
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 944
    .line 945
    .line 946
    move-object/from16 v0, p1

    .line 947
    .line 948
    goto :goto_22

    .line 949
    :cond_3e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 950
    .line 951
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 952
    .line 953
    .line 954
    throw v0

    .line 955
    :cond_3f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 956
    .line 957
    .line 958
    move-object/from16 v1, p1

    .line 959
    .line 960
    goto :goto_20

    .line 961
    :cond_40
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 962
    .line 963
    .line 964
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 965
    .line 966
    check-cast v1, Lif0/u;

    .line 967
    .line 968
    iget-object v1, v1, Lif0/u;->b:Lti0/a;

    .line 969
    .line 970
    iput v13, v5, La30/b;->e:I

    .line 971
    .line 972
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 973
    .line 974
    .line 975
    move-result-object v1

    .line 976
    if-ne v1, v0, :cond_41

    .line 977
    .line 978
    goto :goto_22

    .line 979
    :cond_41
    :goto_20
    check-cast v1, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 980
    .line 981
    check-cast v11, Ljava/lang/String;

    .line 982
    .line 983
    check-cast v10, Llf0/b;

    .line 984
    .line 985
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 986
    .line 987
    .line 988
    iget-boolean v2, v10, Llf0/b;->a:Z

    .line 989
    .line 990
    sget-object v3, Lss0/e;->d:Lss0/e;

    .line 991
    .line 992
    sget-object v3, Lif0/a;->b:[I

    .line 993
    .line 994
    const/16 v4, 0x3f

    .line 995
    .line 996
    aget v3, v3, v4

    .line 997
    .line 998
    if-ne v3, v13, :cond_42

    .line 999
    .line 1000
    const-string v3, "PREDICTIVE_WAKE_UP"

    .line 1001
    .line 1002
    goto :goto_21

    .line 1003
    :cond_42
    const-string v3, "UNKNOWN"

    .line 1004
    .line 1005
    :goto_21
    new-instance v4, Lcz/myskoda/api/bff_garage/v2/UserCapabilitySettingDto;

    .line 1006
    .line 1007
    invoke-direct {v4, v3, v2}, Lcz/myskoda/api/bff_garage/v2/UserCapabilitySettingDto;-><init>(Ljava/lang/String;Z)V

    .line 1008
    .line 1009
    .line 1010
    const/4 v3, 0x2

    .line 1011
    iput v3, v5, La30/b;->e:I

    .line 1012
    .line 1013
    invoke-interface {v1, v11, v4, v5}, Lcz/myskoda/api/bff_garage/v2/GarageApi;->changeUserCapability(Ljava/lang/String;Lcz/myskoda/api/bff_garage/v2/UserCapabilitySettingDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1014
    .line 1015
    .line 1016
    move-result-object v1

    .line 1017
    if-ne v1, v0, :cond_43

    .line 1018
    .line 1019
    goto :goto_22

    .line 1020
    :cond_43
    move-object v0, v1

    .line 1021
    :goto_22
    return-object v0

    .line 1022
    :pswitch_b
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1023
    .line 1024
    iget v1, v5, La30/b;->e:I

    .line 1025
    .line 1026
    if-eqz v1, :cond_45

    .line 1027
    .line 1028
    if-ne v1, v13, :cond_44

    .line 1029
    .line 1030
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1031
    .line 1032
    .line 1033
    goto :goto_23

    .line 1034
    :cond_44
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1035
    .line 1036
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1037
    .line 1038
    .line 1039
    throw v0

    .line 1040
    :cond_45
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1041
    .line 1042
    .line 1043
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 1044
    .line 1045
    check-cast v1, Lif0/h;

    .line 1046
    .line 1047
    check-cast v11, Ljava/lang/String;

    .line 1048
    .line 1049
    check-cast v10, Ljava/util/ArrayList;

    .line 1050
    .line 1051
    iput v13, v5, La30/b;->e:I

    .line 1052
    .line 1053
    invoke-static {v1, v11, v10, v5}, Lif0/h;->a(Lif0/h;Ljava/lang/String;Ljava/util/ArrayList;Lrx0/c;)Ljava/lang/Object;

    .line 1054
    .line 1055
    .line 1056
    move-result-object v1

    .line 1057
    if-ne v1, v0, :cond_46

    .line 1058
    .line 1059
    move-object v4, v0

    .line 1060
    :cond_46
    :goto_23
    return-object v4

    .line 1061
    :pswitch_c
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1062
    .line 1063
    iget v1, v5, La30/b;->e:I

    .line 1064
    .line 1065
    if-eqz v1, :cond_48

    .line 1066
    .line 1067
    if-ne v1, v13, :cond_47

    .line 1068
    .line 1069
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1070
    .line 1071
    .line 1072
    goto :goto_24

    .line 1073
    :cond_47
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1074
    .line 1075
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1076
    .line 1077
    .line 1078
    throw v0

    .line 1079
    :cond_48
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1080
    .line 1081
    .line 1082
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 1083
    .line 1084
    check-cast v1, Lif0/e;

    .line 1085
    .line 1086
    check-cast v11, Ljava/lang/String;

    .line 1087
    .line 1088
    check-cast v10, Ljava/util/ArrayList;

    .line 1089
    .line 1090
    iput v13, v5, La30/b;->e:I

    .line 1091
    .line 1092
    invoke-static {v1, v11, v10, v5}, Lif0/e;->a(Lif0/e;Ljava/lang/String;Ljava/util/ArrayList;Lrx0/c;)Ljava/lang/Object;

    .line 1093
    .line 1094
    .line 1095
    move-result-object v1

    .line 1096
    if-ne v1, v0, :cond_49

    .line 1097
    .line 1098
    move-object v4, v0

    .line 1099
    :cond_49
    :goto_24
    return-object v4

    .line 1100
    :pswitch_d
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1101
    .line 1102
    check-cast v0, Lic0/a;

    .line 1103
    .line 1104
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1105
    .line 1106
    iget v2, v5, La30/b;->e:I

    .line 1107
    .line 1108
    if-eqz v2, :cond_4c

    .line 1109
    .line 1110
    if-eq v2, v13, :cond_4b

    .line 1111
    .line 1112
    const/4 v3, 0x2

    .line 1113
    if-ne v2, v3, :cond_4a

    .line 1114
    .line 1115
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1116
    .line 1117
    .line 1118
    move-object/from16 v0, p1

    .line 1119
    .line 1120
    goto :goto_28

    .line 1121
    :cond_4a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1122
    .line 1123
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1124
    .line 1125
    .line 1126
    throw v0

    .line 1127
    :cond_4b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1128
    .line 1129
    .line 1130
    move-object/from16 v2, p1

    .line 1131
    .line 1132
    goto :goto_25

    .line 1133
    :cond_4c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1134
    .line 1135
    .line 1136
    iget-object v2, v0, Lic0/a;->c:Lti0/a;

    .line 1137
    .line 1138
    iput v13, v5, La30/b;->e:I

    .line 1139
    .line 1140
    invoke-interface {v2, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v2

    .line 1144
    if-ne v2, v1, :cond_4d

    .line 1145
    .line 1146
    goto :goto_27

    .line 1147
    :cond_4d
    :goto_25
    check-cast v2, Lcz/myskoda/api/bff/v1/AuthenticationApi;

    .line 1148
    .line 1149
    new-instance v3, Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;

    .line 1150
    .line 1151
    check-cast v11, Ljava/lang/String;

    .line 1152
    .line 1153
    iget-object v0, v0, Lic0/a;->g:Ljava/util/HashMap;

    .line 1154
    .line 1155
    check-cast v10, Llc0/l;

    .line 1156
    .line 1157
    invoke-virtual {v0, v10}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1158
    .line 1159
    .line 1160
    move-result-object v0

    .line 1161
    check-cast v0, Llc0/f;

    .line 1162
    .line 1163
    if-eqz v0, :cond_4e

    .line 1164
    .line 1165
    iget-object v0, v0, Llc0/f;->b:Ljava/lang/String;

    .line 1166
    .line 1167
    goto :goto_26

    .line 1168
    :cond_4e
    const-string v0, ""

    .line 1169
    .line 1170
    :goto_26
    const-string v4, "myskoda://redirect/login/"

    .line 1171
    .line 1172
    invoke-direct {v3, v11, v4, v0}, Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 1173
    .line 1174
    .line 1175
    const/4 v4, 0x2

    .line 1176
    iput v4, v5, La30/b;->e:I

    .line 1177
    .line 1178
    const-string v0, "CONNECT"

    .line 1179
    .line 1180
    invoke-interface {v2, v0, v3, v5}, Lcz/myskoda/api/bff/v1/AuthenticationApi;->exchangeAuthorizationCode(Ljava/lang/String;Lcz/myskoda/api/bff/v1/AuthorizationCodeExchangeDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1181
    .line 1182
    .line 1183
    move-result-object v0

    .line 1184
    if-ne v0, v1, :cond_4f

    .line 1185
    .line 1186
    :goto_27
    move-object v0, v1

    .line 1187
    :cond_4f
    :goto_28
    return-object v0

    .line 1188
    :pswitch_e
    check-cast v10, Lqr0/s;

    .line 1189
    .line 1190
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1191
    .line 1192
    check-cast v0, Li90/c;

    .line 1193
    .line 1194
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1195
    .line 1196
    iget v2, v5, La30/b;->e:I

    .line 1197
    .line 1198
    if-eqz v2, :cond_52

    .line 1199
    .line 1200
    if-eq v2, v13, :cond_51

    .line 1201
    .line 1202
    const/4 v3, 0x2

    .line 1203
    if-ne v2, v3, :cond_50

    .line 1204
    .line 1205
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1206
    .line 1207
    .line 1208
    move-object/from16 v0, p1

    .line 1209
    .line 1210
    goto :goto_2f

    .line 1211
    :cond_50
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1212
    .line 1213
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1214
    .line 1215
    .line 1216
    throw v0

    .line 1217
    :cond_51
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1218
    .line 1219
    .line 1220
    move-object/from16 v0, p1

    .line 1221
    .line 1222
    goto :goto_29

    .line 1223
    :cond_52
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1224
    .line 1225
    .line 1226
    iget-object v0, v0, Li90/c;->b:Lti0/a;

    .line 1227
    .line 1228
    iput v13, v5, La30/b;->e:I

    .line 1229
    .line 1230
    invoke-interface {v0, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1231
    .line 1232
    .line 1233
    move-result-object v0

    .line 1234
    if-ne v0, v1, :cond_53

    .line 1235
    .line 1236
    goto :goto_2e

    .line 1237
    :cond_53
    :goto_29
    check-cast v0, Lcz/myskoda/api/bff/v1/VehicleInformationApi;

    .line 1238
    .line 1239
    check-cast v11, Ljava/lang/String;

    .line 1240
    .line 1241
    new-instance v2, Lcz/myskoda/api/bff/v1/CertificateSettingsDto;

    .line 1242
    .line 1243
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 1244
    .line 1245
    .line 1246
    move-result v3

    .line 1247
    if-eqz v3, :cond_56

    .line 1248
    .line 1249
    if-eq v3, v13, :cond_55

    .line 1250
    .line 1251
    const/4 v4, 0x2

    .line 1252
    if-ne v3, v4, :cond_54

    .line 1253
    .line 1254
    goto :goto_2a

    .line 1255
    :cond_54
    new-instance v0, La8/r0;

    .line 1256
    .line 1257
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1258
    .line 1259
    .line 1260
    throw v0

    .line 1261
    :cond_55
    :goto_2a
    const-string v3, "mi"

    .line 1262
    .line 1263
    goto :goto_2b

    .line 1264
    :cond_56
    const-string v3, "km"

    .line 1265
    .line 1266
    :goto_2b
    invoke-virtual {v10}, Ljava/lang/Enum;->ordinal()I

    .line 1267
    .line 1268
    .line 1269
    move-result v4

    .line 1270
    if-eqz v4, :cond_59

    .line 1271
    .line 1272
    const/4 v6, 0x2

    .line 1273
    if-eq v4, v13, :cond_58

    .line 1274
    .line 1275
    if-ne v4, v6, :cond_57

    .line 1276
    .line 1277
    goto :goto_2c

    .line 1278
    :cond_57
    new-instance v0, La8/r0;

    .line 1279
    .line 1280
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 1281
    .line 1282
    .line 1283
    throw v0

    .line 1284
    :cond_58
    :goto_2c
    const-string v4, "hp"

    .line 1285
    .line 1286
    goto :goto_2d

    .line 1287
    :cond_59
    const/4 v6, 0x2

    .line 1288
    const-string v4, "kw"

    .line 1289
    .line 1290
    :goto_2d
    invoke-direct {v2, v3, v4}, Lcz/myskoda/api/bff/v1/CertificateSettingsDto;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 1291
    .line 1292
    .line 1293
    iput v6, v5, La30/b;->e:I

    .line 1294
    .line 1295
    invoke-interface {v0, v11, v2, v5}, Lcz/myskoda/api/bff/v1/VehicleInformationApi;->generateCertificate(Ljava/lang/String;Lcz/myskoda/api/bff/v1/CertificateSettingsDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1296
    .line 1297
    .line 1298
    move-result-object v0

    .line 1299
    if-ne v0, v1, :cond_5a

    .line 1300
    .line 1301
    :goto_2e
    move-object v0, v1

    .line 1302
    :cond_5a
    :goto_2f
    return-object v0

    .line 1303
    :pswitch_f
    move v6, v9

    .line 1304
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1305
    .line 1306
    iget v1, v5, La30/b;->e:I

    .line 1307
    .line 1308
    if-eqz v1, :cond_5d

    .line 1309
    .line 1310
    if-eq v1, v13, :cond_5c

    .line 1311
    .line 1312
    if-ne v1, v6, :cond_5b

    .line 1313
    .line 1314
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1315
    .line 1316
    .line 1317
    move-object/from16 v0, p1

    .line 1318
    .line 1319
    goto :goto_31

    .line 1320
    :cond_5b
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1321
    .line 1322
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1323
    .line 1324
    .line 1325
    throw v0

    .line 1326
    :cond_5c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1327
    .line 1328
    .line 1329
    move-object/from16 v1, p1

    .line 1330
    .line 1331
    goto :goto_30

    .line 1332
    :cond_5d
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1333
    .line 1334
    .line 1335
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 1336
    .line 1337
    check-cast v1, Li70/r;

    .line 1338
    .line 1339
    iget-object v1, v1, Li70/r;->b:Lti0/a;

    .line 1340
    .line 1341
    iput v13, v5, La30/b;->e:I

    .line 1342
    .line 1343
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1344
    .line 1345
    .line 1346
    move-result-object v1

    .line 1347
    if-ne v1, v0, :cond_5e

    .line 1348
    .line 1349
    goto :goto_31

    .line 1350
    :cond_5e
    :goto_30
    check-cast v1, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 1351
    .line 1352
    check-cast v11, Ljava/lang/String;

    .line 1353
    .line 1354
    check-cast v10, Ll70/h;

    .line 1355
    .line 1356
    invoke-static {v10}, Llp/z9;->b(Ll70/h;)Ljava/lang/String;

    .line 1357
    .line 1358
    .line 1359
    move-result-object v2

    .line 1360
    const/4 v3, 0x2

    .line 1361
    iput v3, v5, La30/b;->e:I

    .line 1362
    .line 1363
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->getFuelPrices(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1364
    .line 1365
    .line 1366
    move-result-object v1

    .line 1367
    if-ne v1, v0, :cond_5f

    .line 1368
    .line 1369
    goto :goto_31

    .line 1370
    :cond_5f
    move-object v0, v1

    .line 1371
    :goto_31
    return-object v0

    .line 1372
    :pswitch_10
    move v3, v9

    .line 1373
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1374
    .line 1375
    iget v1, v5, La30/b;->e:I

    .line 1376
    .line 1377
    if-eqz v1, :cond_62

    .line 1378
    .line 1379
    if-eq v1, v13, :cond_61

    .line 1380
    .line 1381
    if-ne v1, v3, :cond_60

    .line 1382
    .line 1383
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1384
    .line 1385
    .line 1386
    move-object/from16 v0, p1

    .line 1387
    .line 1388
    goto :goto_33

    .line 1389
    :cond_60
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1390
    .line 1391
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1392
    .line 1393
    .line 1394
    throw v0

    .line 1395
    :cond_61
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1396
    .line 1397
    .line 1398
    move-object/from16 v1, p1

    .line 1399
    .line 1400
    goto :goto_32

    .line 1401
    :cond_62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1402
    .line 1403
    .line 1404
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 1405
    .line 1406
    check-cast v1, Li70/r;

    .line 1407
    .line 1408
    iget-object v1, v1, Li70/r;->b:Lti0/a;

    .line 1409
    .line 1410
    iput v13, v5, La30/b;->e:I

    .line 1411
    .line 1412
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1413
    .line 1414
    .line 1415
    move-result-object v1

    .line 1416
    if-ne v1, v0, :cond_63

    .line 1417
    .line 1418
    goto :goto_33

    .line 1419
    :cond_63
    :goto_32
    check-cast v1, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 1420
    .line 1421
    check-cast v11, Ljava/lang/String;

    .line 1422
    .line 1423
    check-cast v10, Ljava/lang/String;

    .line 1424
    .line 1425
    const/4 v4, 0x2

    .line 1426
    iput v4, v5, La30/b;->e:I

    .line 1427
    .line 1428
    invoke-interface {v1, v11, v10, v5}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->deleteFuelPrice(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1429
    .line 1430
    .line 1431
    move-result-object v1

    .line 1432
    if-ne v1, v0, :cond_64

    .line 1433
    .line 1434
    goto :goto_33

    .line 1435
    :cond_64
    move-object v0, v1

    .line 1436
    :goto_33
    return-object v0

    .line 1437
    :pswitch_11
    move v4, v9

    .line 1438
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1439
    .line 1440
    iget v1, v5, La30/b;->e:I

    .line 1441
    .line 1442
    if-eqz v1, :cond_67

    .line 1443
    .line 1444
    if-eq v1, v13, :cond_66

    .line 1445
    .line 1446
    if-ne v1, v4, :cond_65

    .line 1447
    .line 1448
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1449
    .line 1450
    .line 1451
    move-object/from16 v0, p1

    .line 1452
    .line 1453
    goto :goto_35

    .line 1454
    :cond_65
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1455
    .line 1456
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1457
    .line 1458
    .line 1459
    throw v0

    .line 1460
    :cond_66
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1461
    .line 1462
    .line 1463
    move-object/from16 v1, p1

    .line 1464
    .line 1465
    goto :goto_34

    .line 1466
    :cond_67
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1467
    .line 1468
    .line 1469
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 1470
    .line 1471
    check-cast v1, Li70/r;

    .line 1472
    .line 1473
    iget-object v1, v1, Li70/r;->b:Lti0/a;

    .line 1474
    .line 1475
    iput v13, v5, La30/b;->e:I

    .line 1476
    .line 1477
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1478
    .line 1479
    .line 1480
    move-result-object v1

    .line 1481
    if-ne v1, v0, :cond_68

    .line 1482
    .line 1483
    goto :goto_35

    .line 1484
    :cond_68
    :goto_34
    check-cast v1, Lcz/myskoda/api/bff/v1/TripStatisticsApi;

    .line 1485
    .line 1486
    check-cast v11, Ljava/lang/String;

    .line 1487
    .line 1488
    check-cast v10, Ll70/d;

    .line 1489
    .line 1490
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1491
    .line 1492
    .line 1493
    new-instance v2, Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;

    .line 1494
    .line 1495
    iget-object v3, v10, Ll70/d;->c:Ljava/lang/String;

    .line 1496
    .line 1497
    iget-object v4, v10, Ll70/d;->b:Ljava/math/BigDecimal;

    .line 1498
    .line 1499
    invoke-virtual {v4}, Ljava/math/BigDecimal;->floatValue()F

    .line 1500
    .line 1501
    .line 1502
    move-result v4

    .line 1503
    iget-object v6, v10, Ll70/d;->d:Ll70/h;

    .line 1504
    .line 1505
    invoke-static {v6}, Llp/z9;->b(Ll70/h;)Ljava/lang/String;

    .line 1506
    .line 1507
    .line 1508
    move-result-object v6

    .line 1509
    iget-object v7, v10, Ll70/d;->e:Ljava/time/LocalDate;

    .line 1510
    .line 1511
    invoke-direct {v2, v3, v4, v6, v7}, Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;-><init>(Ljava/lang/String;FLjava/lang/String;Ljava/time/LocalDate;)V

    .line 1512
    .line 1513
    .line 1514
    const/4 v3, 0x2

    .line 1515
    iput v3, v5, La30/b;->e:I

    .line 1516
    .line 1517
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff/v1/TripStatisticsApi;->createFuelPrice(Ljava/lang/String;Lcz/myskoda/api/bff/v1/FuelPriceRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v1

    .line 1521
    if-ne v1, v0, :cond_69

    .line 1522
    .line 1523
    goto :goto_35

    .line 1524
    :cond_69
    move-object v0, v1

    .line 1525
    :goto_35
    return-object v0

    .line 1526
    :pswitch_12
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1527
    .line 1528
    check-cast v0, Li2/p;

    .line 1529
    .line 1530
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1531
    .line 1532
    iget v2, v5, La30/b;->e:I

    .line 1533
    .line 1534
    if-eqz v2, :cond_6b

    .line 1535
    .line 1536
    if-ne v2, v13, :cond_6a

    .line 1537
    .line 1538
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1539
    .line 1540
    .line 1541
    goto :goto_36

    .line 1542
    :cond_6a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1543
    .line 1544
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1545
    .line 1546
    .line 1547
    throw v0

    .line 1548
    :cond_6b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1549
    .line 1550
    .line 1551
    invoke-virtual {v0, v11}, Li2/p;->h(Ljava/lang/Object;)V

    .line 1552
    .line 1553
    .line 1554
    new-instance v2, Li2/k;

    .line 1555
    .line 1556
    invoke-direct {v2, v0, v7}, Li2/k;-><init>(Li2/p;I)V

    .line 1557
    .line 1558
    .line 1559
    new-instance v3, Lg1/y2;

    .line 1560
    .line 1561
    check-cast v10, Lay0/p;

    .line 1562
    .line 1563
    const/16 v6, 0x12

    .line 1564
    .line 1565
    const/4 v15, 0x0

    .line 1566
    invoke-direct {v3, v6, v10, v0, v15}, Lg1/y2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1567
    .line 1568
    .line 1569
    iput v13, v5, La30/b;->e:I

    .line 1570
    .line 1571
    invoke-static {v2, v3, v5}, Landroidx/compose/material3/internal/a;->a(Lay0/a;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 1572
    .line 1573
    .line 1574
    move-result-object v0

    .line 1575
    if-ne v0, v1, :cond_6c

    .line 1576
    .line 1577
    move-object v4, v1

    .line 1578
    :cond_6c
    :goto_36
    return-object v4

    .line 1579
    :pswitch_13
    check-cast v11, Landroidx/glance/session/SessionWorker;

    .line 1580
    .line 1581
    iget-object v0, v11, Landroidx/glance/session/SessionWorker;->n:Ljava/lang/String;

    .line 1582
    .line 1583
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 1584
    .line 1585
    iget v2, v5, La30/b;->e:I

    .line 1586
    .line 1587
    const/16 v9, 0xc

    .line 1588
    .line 1589
    if-eqz v2, :cond_71

    .line 1590
    .line 1591
    if-eq v2, v13, :cond_70

    .line 1592
    .line 1593
    const/4 v3, 0x2

    .line 1594
    if-eq v2, v3, :cond_6f

    .line 1595
    .line 1596
    if-eq v2, v6, :cond_6e

    .line 1597
    .line 1598
    if-eq v2, v7, :cond_6d

    .line 1599
    .line 1600
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1601
    .line 1602
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1603
    .line 1604
    .line 1605
    throw v0

    .line 1606
    :cond_6d
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1607
    .line 1608
    check-cast v0, Ljava/lang/Throwable;

    .line 1609
    .line 1610
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1611
    .line 1612
    .line 1613
    goto/16 :goto_3c

    .line 1614
    .line 1615
    :cond_6e
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1616
    .line 1617
    .line 1618
    goto/16 :goto_39

    .line 1619
    .line 1620
    :cond_6f
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1621
    .line 1622
    move-object v1, v0

    .line 1623
    check-cast v1, La7/n;

    .line 1624
    .line 1625
    :try_start_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 1626
    .line 1627
    .line 1628
    goto/16 :goto_38

    .line 1629
    .line 1630
    :catchall_0
    move-exception v0

    .line 1631
    goto/16 :goto_3a

    .line 1632
    .line 1633
    :cond_70
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1634
    .line 1635
    .line 1636
    move-object/from16 v2, p1

    .line 1637
    .line 1638
    goto :goto_37

    .line 1639
    :cond_71
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1640
    .line 1641
    .line 1642
    iget-object v2, v11, Landroidx/glance/session/SessionWorker;->k:Lh7/h;

    .line 1643
    .line 1644
    new-instance v3, Le30/p;

    .line 1645
    .line 1646
    const/16 v4, 0x19

    .line 1647
    .line 1648
    const/4 v15, 0x0

    .line 1649
    invoke-direct {v3, v11, v15, v4}, Le30/p;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 1650
    .line 1651
    .line 1652
    iput v13, v5, La30/b;->e:I

    .line 1653
    .line 1654
    check-cast v2, Lh7/m;

    .line 1655
    .line 1656
    invoke-virtual {v2, v3, v5}, Lh7/m;->a(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 1657
    .line 1658
    .line 1659
    move-result-object v2

    .line 1660
    if-ne v2, v8, :cond_72

    .line 1661
    .line 1662
    goto/16 :goto_3b

    .line 1663
    .line 1664
    :cond_72
    :goto_37
    check-cast v2, La7/n;

    .line 1665
    .line 1666
    if-nez v2, :cond_74

    .line 1667
    .line 1668
    iget-object v1, v11, Landroidx/glance/session/SessionWorker;->j:Landroidx/work/WorkerParameters;

    .line 1669
    .line 1670
    iget v1, v1, Landroidx/work/WorkerParameters;->c:I

    .line 1671
    .line 1672
    if-eqz v1, :cond_73

    .line 1673
    .line 1674
    new-instance v1, Ljava/lang/StringBuilder;

    .line 1675
    .line 1676
    const-string v2, "SessionWorker attempted restart but Session is not available for "

    .line 1677
    .line 1678
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1679
    .line 1680
    .line 1681
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1682
    .line 1683
    .line 1684
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1685
    .line 1686
    .line 1687
    move-result-object v0

    .line 1688
    const-string v1, "GlanceSessionWorker"

    .line 1689
    .line 1690
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 1691
    .line 1692
    .line 1693
    new-instance v8, Leb/t;

    .line 1694
    .line 1695
    sget-object v0, Leb/h;->b:Leb/h;

    .line 1696
    .line 1697
    invoke-direct {v8, v0}, Leb/t;-><init>(Leb/h;)V

    .line 1698
    .line 1699
    .line 1700
    goto :goto_3b

    .line 1701
    :cond_73
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 1702
    .line 1703
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1704
    .line 1705
    const-string v3, "No session available for key "

    .line 1706
    .line 1707
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1708
    .line 1709
    .line 1710
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1711
    .line 1712
    .line 1713
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1714
    .line 1715
    .line 1716
    move-result-object v0

    .line 1717
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 1718
    .line 1719
    .line 1720
    move-result-object v0

    .line 1721
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1722
    .line 1723
    .line 1724
    throw v1

    .line 1725
    :cond_74
    :try_start_1
    move-object v0, v10

    .line 1726
    check-cast v0, Lh7/a0;

    .line 1727
    .line 1728
    iget-object v3, v11, Leb/v;->d:Landroid/content/Context;

    .line 1729
    .line 1730
    move-object v4, v3

    .line 1731
    iget-object v3, v11, Landroidx/glance/session/SessionWorker;->l:Lh7/x;

    .line 1732
    .line 1733
    move-object v10, v4

    .line 1734
    new-instance v4, Lh7/p;

    .line 1735
    .line 1736
    invoke-direct {v4, v1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 1737
    .line 1738
    .line 1739
    iput-object v2, v5, La30/b;->g:Ljava/lang/Object;

    .line 1740
    .line 1741
    const/4 v1, 0x2

    .line 1742
    iput v1, v5, La30/b;->e:I

    .line 1743
    .line 1744
    move-object v1, v10

    .line 1745
    invoke-static/range {v0 .. v5}, Llp/o0;->a(Lh7/a0;Landroid/content/Context;La7/n;Lh7/x;Lh7/p;Lrx0/c;)Ljava/lang/Object;

    .line 1746
    .line 1747
    .line 1748
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 1749
    if-ne v0, v8, :cond_75

    .line 1750
    .line 1751
    goto :goto_3b

    .line 1752
    :cond_75
    move-object v1, v2

    .line 1753
    :goto_38
    sget-object v0, Lvy0/t1;->d:Lvy0/t1;

    .line 1754
    .line 1755
    new-instance v2, Lh40/w3;

    .line 1756
    .line 1757
    const/4 v15, 0x0

    .line 1758
    invoke-direct {v2, v9, v11, v1, v15}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1759
    .line 1760
    .line 1761
    iput-object v15, v5, La30/b;->g:Ljava/lang/Object;

    .line 1762
    .line 1763
    iput v6, v5, La30/b;->e:I

    .line 1764
    .line 1765
    invoke-static {v0, v2, v5}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1766
    .line 1767
    .line 1768
    move-result-object v0

    .line 1769
    if-ne v0, v8, :cond_76

    .line 1770
    .line 1771
    goto :goto_3b

    .line 1772
    :cond_76
    :goto_39
    new-instance v8, Leb/t;

    .line 1773
    .line 1774
    sget-object v0, Leb/h;->b:Leb/h;

    .line 1775
    .line 1776
    invoke-direct {v8, v0}, Leb/t;-><init>(Leb/h;)V

    .line 1777
    .line 1778
    .line 1779
    goto :goto_3b

    .line 1780
    :catchall_1
    move-exception v0

    .line 1781
    move-object v1, v2

    .line 1782
    :goto_3a
    sget-object v2, Lvy0/t1;->d:Lvy0/t1;

    .line 1783
    .line 1784
    new-instance v3, Lh40/w3;

    .line 1785
    .line 1786
    const/4 v15, 0x0

    .line 1787
    invoke-direct {v3, v9, v11, v1, v15}, Lh40/w3;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1788
    .line 1789
    .line 1790
    iput-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1791
    .line 1792
    iput v7, v5, La30/b;->e:I

    .line 1793
    .line 1794
    invoke-static {v2, v3, v5}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 1795
    .line 1796
    .line 1797
    move-result-object v1

    .line 1798
    if-ne v1, v8, :cond_77

    .line 1799
    .line 1800
    :goto_3b
    return-object v8

    .line 1801
    :cond_77
    :goto_3c
    throw v0

    .line 1802
    :pswitch_14
    check-cast v10, Le1/w0;

    .line 1803
    .line 1804
    check-cast v11, La90/s;

    .line 1805
    .line 1806
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1807
    .line 1808
    move-object v1, v0

    .line 1809
    check-cast v1, Lh2/yb;

    .line 1810
    .line 1811
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1812
    .line 1813
    iget v2, v5, La30/b;->e:I

    .line 1814
    .line 1815
    if-eqz v2, :cond_7a

    .line 1816
    .line 1817
    if-eq v2, v13, :cond_78

    .line 1818
    .line 1819
    const/4 v3, 0x2

    .line 1820
    if-ne v2, v3, :cond_79

    .line 1821
    .line 1822
    :cond_78
    :try_start_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 1823
    .line 1824
    .line 1825
    goto :goto_3d

    .line 1826
    :catchall_2
    move-exception v0

    .line 1827
    goto :goto_3f

    .line 1828
    :cond_79
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1829
    .line 1830
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1831
    .line 1832
    .line 1833
    throw v0

    .line 1834
    :cond_7a
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1835
    .line 1836
    .line 1837
    :try_start_3
    new-instance v2, Ldm0/h;

    .line 1838
    .line 1839
    const/16 v3, 0x1c

    .line 1840
    .line 1841
    const/4 v15, 0x0

    .line 1842
    invoke-direct {v2, v11, v15, v3}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 1843
    .line 1844
    .line 1845
    const/4 v3, 0x2

    .line 1846
    iput v3, v5, La30/b;->e:I

    .line 1847
    .line 1848
    const-wide/16 v6, 0x5dc

    .line 1849
    .line 1850
    invoke-static {v6, v7, v2, v5}, Lvy0/e0;->S(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 1851
    .line 1852
    .line 1853
    move-result-object v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 1854
    if-ne v2, v0, :cond_7b

    .line 1855
    .line 1856
    move-object v4, v0

    .line 1857
    goto :goto_3e

    .line 1858
    :cond_7b
    :goto_3d
    sget-object v0, Le1/w0;->f:Le1/w0;

    .line 1859
    .line 1860
    if-eq v10, v0, :cond_7c

    .line 1861
    .line 1862
    invoke-virtual {v1}, Lh2/yb;->a()V

    .line 1863
    .line 1864
    .line 1865
    :cond_7c
    :goto_3e
    return-object v4

    .line 1866
    :goto_3f
    sget-object v2, Le1/w0;->f:Le1/w0;

    .line 1867
    .line 1868
    if-eq v10, v2, :cond_7d

    .line 1869
    .line 1870
    invoke-virtual {v1}, Lh2/yb;->a()V

    .line 1871
    .line 1872
    .line 1873
    :cond_7d
    throw v0

    .line 1874
    :pswitch_15
    iget-object v0, v5, La30/b;->g:Ljava/lang/Object;

    .line 1875
    .line 1876
    check-cast v0, Lg1/q;

    .line 1877
    .line 1878
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 1879
    .line 1880
    iget v2, v5, La30/b;->e:I

    .line 1881
    .line 1882
    if-eqz v2, :cond_7f

    .line 1883
    .line 1884
    if-ne v2, v13, :cond_7e

    .line 1885
    .line 1886
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1887
    .line 1888
    .line 1889
    goto :goto_40

    .line 1890
    :cond_7e
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1891
    .line 1892
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1893
    .line 1894
    .line 1895
    throw v0

    .line 1896
    :cond_7f
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1897
    .line 1898
    .line 1899
    iget-object v2, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 1900
    .line 1901
    check-cast v2, Ll2/j1;

    .line 1902
    .line 1903
    invoke-virtual {v2, v11}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 1904
    .line 1905
    .line 1906
    new-instance v2, Lg1/n;

    .line 1907
    .line 1908
    invoke-direct {v2, v0, v6}, Lg1/n;-><init>(Lg1/q;I)V

    .line 1909
    .line 1910
    .line 1911
    new-instance v3, Le1/e;

    .line 1912
    .line 1913
    check-cast v10, Lay0/p;

    .line 1914
    .line 1915
    const/16 v6, 0x18

    .line 1916
    .line 1917
    const/4 v15, 0x0

    .line 1918
    invoke-direct {v3, v6, v10, v0, v15}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 1919
    .line 1920
    .line 1921
    iput v13, v5, La30/b;->e:I

    .line 1922
    .line 1923
    invoke-static {v2, v3, v5}, Landroidx/compose/foundation/gestures/a;->b(Lay0/a;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 1924
    .line 1925
    .line 1926
    move-result-object v2

    .line 1927
    if-ne v2, v1, :cond_80

    .line 1928
    .line 1929
    move-object v4, v1

    .line 1930
    goto :goto_41

    .line 1931
    :cond_80
    :goto_40
    iget-object v1, v0, Lg1/q;->b:Ljava/lang/Object;

    .line 1932
    .line 1933
    check-cast v1, Lay0/k;

    .line 1934
    .line 1935
    invoke-interface {v1, v11}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1936
    .line 1937
    .line 1938
    move-result-object v1

    .line 1939
    check-cast v1, Ljava/lang/Boolean;

    .line 1940
    .line 1941
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1942
    .line 1943
    .line 1944
    move-result v1

    .line 1945
    if-eqz v1, :cond_81

    .line 1946
    .line 1947
    invoke-virtual {v0}, Lg1/q;->g()Lg1/z;

    .line 1948
    .line 1949
    .line 1950
    move-result-object v1

    .line 1951
    invoke-virtual {v1, v11}, Lg1/z;->c(Ljava/lang/Object;)F

    .line 1952
    .line 1953
    .line 1954
    move-result v1

    .line 1955
    iget-object v2, v0, Lg1/q;->k:Ljava/lang/Object;

    .line 1956
    .line 1957
    check-cast v2, Lg1/p;

    .line 1958
    .line 1959
    iget-object v3, v0, Lg1/q;->j:Ljava/lang/Object;

    .line 1960
    .line 1961
    check-cast v3, Ll2/f1;

    .line 1962
    .line 1963
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 1964
    .line 1965
    .line 1966
    move-result v3

    .line 1967
    invoke-virtual {v2, v1, v3}, Lg1/p;->a(FF)V

    .line 1968
    .line 1969
    .line 1970
    iget-object v1, v0, Lg1/q;->e:Ljava/lang/Object;

    .line 1971
    .line 1972
    check-cast v1, Ll2/j1;

    .line 1973
    .line 1974
    invoke-virtual {v1, v11}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 1975
    .line 1976
    .line 1977
    invoke-virtual {v0, v11}, Lg1/q;->m(Ljava/lang/Object;)V

    .line 1978
    .line 1979
    .line 1980
    :cond_81
    :goto_41
    return-object v4

    .line 1981
    :pswitch_16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 1982
    .line 1983
    iget v1, v5, La30/b;->e:I

    .line 1984
    .line 1985
    if-eqz v1, :cond_83

    .line 1986
    .line 1987
    if-ne v1, v13, :cond_82

    .line 1988
    .line 1989
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 1990
    .line 1991
    .line 1992
    goto :goto_42

    .line 1993
    :cond_82
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1994
    .line 1995
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1996
    .line 1997
    .line 1998
    throw v0

    .line 1999
    :cond_83
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2000
    .line 2001
    .line 2002
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2003
    .line 2004
    check-cast v1, Len0/c;

    .line 2005
    .line 2006
    check-cast v11, Ljava/lang/String;

    .line 2007
    .line 2008
    iput v13, v5, La30/b;->e:I

    .line 2009
    .line 2010
    invoke-static {v1, v11, v10, v5}, Len0/c;->a(Len0/c;Ljava/lang/String;Ljava/util/List;Lrx0/c;)Ljava/lang/Object;

    .line 2011
    .line 2012
    .line 2013
    move-result-object v1

    .line 2014
    if-ne v1, v0, :cond_84

    .line 2015
    .line 2016
    move-object v4, v0

    .line 2017
    :cond_84
    :goto_42
    return-object v4

    .line 2018
    :pswitch_17
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2019
    .line 2020
    iget v1, v5, La30/b;->e:I

    .line 2021
    .line 2022
    if-eqz v1, :cond_87

    .line 2023
    .line 2024
    if-eq v1, v13, :cond_86

    .line 2025
    .line 2026
    const/4 v3, 0x2

    .line 2027
    if-ne v1, v3, :cond_85

    .line 2028
    .line 2029
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2030
    .line 2031
    .line 2032
    move-object/from16 v0, p1

    .line 2033
    .line 2034
    goto :goto_44

    .line 2035
    :cond_85
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2036
    .line 2037
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2038
    .line 2039
    .line 2040
    throw v0

    .line 2041
    :cond_86
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2042
    .line 2043
    .line 2044
    move-object/from16 v1, p1

    .line 2045
    .line 2046
    goto :goto_43

    .line 2047
    :cond_87
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2048
    .line 2049
    .line 2050
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2051
    .line 2052
    check-cast v1, Le80/b;

    .line 2053
    .line 2054
    iget-object v1, v1, Le80/b;->b:Lti0/a;

    .line 2055
    .line 2056
    iput v13, v5, La30/b;->e:I

    .line 2057
    .line 2058
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2059
    .line 2060
    .line 2061
    move-result-object v1

    .line 2062
    if-ne v1, v0, :cond_88

    .line 2063
    .line 2064
    goto :goto_44

    .line 2065
    :cond_88
    :goto_43
    check-cast v1, Lcz/myskoda/api/bff_shop/v2/ShopApi;

    .line 2066
    .line 2067
    check-cast v11, Ljava/lang/String;

    .line 2068
    .line 2069
    check-cast v10, Lg80/f;

    .line 2070
    .line 2071
    new-instance v2, Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;

    .line 2072
    .line 2073
    iget-object v3, v10, Lg80/f;->a:Ljava/lang/String;

    .line 2074
    .line 2075
    iget-boolean v4, v10, Lg80/f;->b:Z

    .line 2076
    .line 2077
    invoke-direct {v2, v3, v4}, Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;-><init>(Ljava/lang/String;Z)V

    .line 2078
    .line 2079
    .line 2080
    const/4 v3, 0x2

    .line 2081
    iput v3, v5, La30/b;->e:I

    .line 2082
    .line 2083
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_shop/v2/ShopApi;->createLoyaltyProductsOrder(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/LoyaltyProductsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2084
    .line 2085
    .line 2086
    move-result-object v1

    .line 2087
    if-ne v1, v0, :cond_89

    .line 2088
    .line 2089
    goto :goto_44

    .line 2090
    :cond_89
    move-object v0, v1

    .line 2091
    :goto_44
    return-object v0

    .line 2092
    :pswitch_18
    move v3, v9

    .line 2093
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2094
    .line 2095
    iget v1, v5, La30/b;->e:I

    .line 2096
    .line 2097
    if-eqz v1, :cond_8c

    .line 2098
    .line 2099
    if-eq v1, v13, :cond_8b

    .line 2100
    .line 2101
    if-ne v1, v3, :cond_8a

    .line 2102
    .line 2103
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2104
    .line 2105
    .line 2106
    move-object/from16 v0, p1

    .line 2107
    .line 2108
    goto :goto_46

    .line 2109
    :cond_8a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2110
    .line 2111
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2112
    .line 2113
    .line 2114
    throw v0

    .line 2115
    :cond_8b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2116
    .line 2117
    .line 2118
    move-object/from16 v1, p1

    .line 2119
    .line 2120
    goto :goto_45

    .line 2121
    :cond_8c
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2122
    .line 2123
    .line 2124
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2125
    .line 2126
    check-cast v1, Ld40/n;

    .line 2127
    .line 2128
    iget-object v1, v1, Ld40/n;->b:Lti0/a;

    .line 2129
    .line 2130
    iput v13, v5, La30/b;->e:I

    .line 2131
    .line 2132
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2133
    .line 2134
    .line 2135
    move-result-object v1

    .line 2136
    if-ne v1, v0, :cond_8d

    .line 2137
    .line 2138
    goto :goto_46

    .line 2139
    :cond_8d
    :goto_45
    check-cast v1, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;

    .line 2140
    .line 2141
    check-cast v11, Ljava/lang/String;

    .line 2142
    .line 2143
    new-instance v2, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;

    .line 2144
    .line 2145
    invoke-direct {v2, v13}, Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;-><init>(Z)V

    .line 2146
    .line 2147
    .line 2148
    const/4 v4, 0x2

    .line 2149
    iput v4, v5, La30/b;->e:I

    .line 2150
    .line 2151
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_loyalty_program/v2/LoyaltyProgramApi;->updateLoyaltyMemberProfile(Ljava/lang/String;Lcz/myskoda/api/bff_loyalty_program/v2/MemberProfilePatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2152
    .line 2153
    .line 2154
    move-result-object v1

    .line 2155
    if-ne v1, v0, :cond_8e

    .line 2156
    .line 2157
    goto :goto_46

    .line 2158
    :cond_8e
    move-object v0, v1

    .line 2159
    :goto_46
    return-object v0

    .line 2160
    :pswitch_19
    move v4, v9

    .line 2161
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2162
    .line 2163
    iget v1, v5, La30/b;->e:I

    .line 2164
    .line 2165
    if-eqz v1, :cond_91

    .line 2166
    .line 2167
    if-eq v1, v13, :cond_90

    .line 2168
    .line 2169
    if-ne v1, v4, :cond_8f

    .line 2170
    .line 2171
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2172
    .line 2173
    .line 2174
    move-object/from16 v0, p1

    .line 2175
    .line 2176
    goto :goto_49

    .line 2177
    :cond_8f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2178
    .line 2179
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2180
    .line 2181
    .line 2182
    throw v0

    .line 2183
    :cond_90
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2184
    .line 2185
    .line 2186
    move-object/from16 v1, p1

    .line 2187
    .line 2188
    goto :goto_47

    .line 2189
    :cond_91
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2190
    .line 2191
    .line 2192
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2193
    .line 2194
    check-cast v1, Lar0/c;

    .line 2195
    .line 2196
    iget-object v1, v1, Lar0/c;->b:Lti0/a;

    .line 2197
    .line 2198
    iput v13, v5, La30/b;->e:I

    .line 2199
    .line 2200
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2201
    .line 2202
    .line 2203
    move-result-object v1

    .line 2204
    if-ne v1, v0, :cond_92

    .line 2205
    .line 2206
    goto :goto_49

    .line 2207
    :cond_92
    :goto_47
    check-cast v1, Lcz/myskoda/api/bff_shop/v2/ShopApi;

    .line 2208
    .line 2209
    check-cast v11, Ljava/lang/String;

    .line 2210
    .line 2211
    check-cast v10, Ler0/l;

    .line 2212
    .line 2213
    iget-object v4, v10, Ler0/l;->a:Ljava/util/List;

    .line 2214
    .line 2215
    check-cast v4, Ljava/lang/Iterable;

    .line 2216
    .line 2217
    new-instance v6, Ljava/util/ArrayList;

    .line 2218
    .line 2219
    invoke-static {v4, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2220
    .line 2221
    .line 2222
    move-result v2

    .line 2223
    invoke-direct {v6, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2224
    .line 2225
    .line 2226
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2227
    .line 2228
    .line 2229
    move-result-object v2

    .line 2230
    :goto_48
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 2231
    .line 2232
    .line 2233
    move-result v4

    .line 2234
    if-eqz v4, :cond_93

    .line 2235
    .line 2236
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2237
    .line 2238
    .line 2239
    move-result-object v4

    .line 2240
    check-cast v4, Ler0/h;

    .line 2241
    .line 2242
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2243
    .line 2244
    .line 2245
    new-instance v7, Lcz/myskoda/api/bff_shop/v2/SubscriptionOrderDto;

    .line 2246
    .line 2247
    iget-object v4, v4, Ler0/h;->a:Ljava/lang/String;

    .line 2248
    .line 2249
    invoke-direct {v7, v4}, Lcz/myskoda/api/bff_shop/v2/SubscriptionOrderDto;-><init>(Ljava/lang/String;)V

    .line 2250
    .line 2251
    .line 2252
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2253
    .line 2254
    .line 2255
    goto :goto_48

    .line 2256
    :cond_93
    new-instance v2, Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;

    .line 2257
    .line 2258
    invoke-direct {v2, v6}, Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;-><init>(Ljava/util/List;)V

    .line 2259
    .line 2260
    .line 2261
    const/4 v4, 0x2

    .line 2262
    iput v4, v5, La30/b;->e:I

    .line 2263
    .line 2264
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_shop/v2/ShopApi;->createSubscriptionsOrder(Ljava/lang/String;Lcz/myskoda/api/bff_shop/v2/SubscriptionsOrderRequestDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2265
    .line 2266
    .line 2267
    move-result-object v1

    .line 2268
    if-ne v1, v0, :cond_94

    .line 2269
    .line 2270
    goto :goto_49

    .line 2271
    :cond_94
    move-object v0, v1

    .line 2272
    :goto_49
    return-object v0

    .line 2273
    :pswitch_1a
    move v4, v9

    .line 2274
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2275
    .line 2276
    iget v1, v5, La30/b;->e:I

    .line 2277
    .line 2278
    if-eqz v1, :cond_97

    .line 2279
    .line 2280
    if-eq v1, v13, :cond_96

    .line 2281
    .line 2282
    if-ne v1, v4, :cond_95

    .line 2283
    .line 2284
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2285
    .line 2286
    .line 2287
    move-object/from16 v0, p1

    .line 2288
    .line 2289
    goto/16 :goto_4d

    .line 2290
    .line 2291
    :cond_95
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2292
    .line 2293
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2294
    .line 2295
    .line 2296
    throw v0

    .line 2297
    :cond_96
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2298
    .line 2299
    .line 2300
    move-object/from16 v1, p1

    .line 2301
    .line 2302
    goto :goto_4a

    .line 2303
    :cond_97
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2304
    .line 2305
    .line 2306
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2307
    .line 2308
    check-cast v1, Lak0/c;

    .line 2309
    .line 2310
    iget-object v1, v1, Lak0/c;->b:Lti0/a;

    .line 2311
    .line 2312
    iput v13, v5, La30/b;->e:I

    .line 2313
    .line 2314
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2315
    .line 2316
    .line 2317
    move-result-object v1

    .line 2318
    if-ne v1, v0, :cond_98

    .line 2319
    .line 2320
    goto/16 :goto_4d

    .line 2321
    .line 2322
    :cond_98
    :goto_4a
    check-cast v1, Lcz/myskoda/api/bff_maps/v3/MapsApi;

    .line 2323
    .line 2324
    new-instance v4, Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;

    .line 2325
    .line 2326
    check-cast v11, Ljava/util/UUID;

    .line 2327
    .line 2328
    check-cast v10, Ljava/util/List;

    .line 2329
    .line 2330
    invoke-static {v10, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2331
    .line 2332
    .line 2333
    check-cast v10, Ljava/lang/Iterable;

    .line 2334
    .line 2335
    new-instance v8, Ljava/util/ArrayList;

    .line 2336
    .line 2337
    invoke-static {v10, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 2338
    .line 2339
    .line 2340
    move-result v2

    .line 2341
    invoke-direct {v8, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 2342
    .line 2343
    .line 2344
    invoke-interface {v10}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 2345
    .line 2346
    .line 2347
    move-result-object v2

    .line 2348
    :goto_4b
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 2349
    .line 2350
    .line 2351
    move-result v9

    .line 2352
    if-eqz v9, :cond_9e

    .line 2353
    .line 2354
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2355
    .line 2356
    .line 2357
    move-result-object v9

    .line 2358
    check-cast v9, Ldk0/a;

    .line 2359
    .line 2360
    new-instance v10, Lcz/myskoda/api/bff_maps/v3/OfferAnalyticsEventDto;

    .line 2361
    .line 2362
    iget-object v12, v9, Ldk0/a;->a:Ljava/lang/String;

    .line 2363
    .line 2364
    iget-object v14, v9, Ldk0/a;->b:Ldk0/b;

    .line 2365
    .line 2366
    invoke-static {v14, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2367
    .line 2368
    .line 2369
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 2370
    .line 2371
    .line 2372
    move-result v14

    .line 2373
    if-eqz v14, :cond_9d

    .line 2374
    .line 2375
    if-eq v14, v13, :cond_9c

    .line 2376
    .line 2377
    const/4 v15, 0x2

    .line 2378
    if-eq v14, v15, :cond_9b

    .line 2379
    .line 2380
    if-eq v14, v6, :cond_9a

    .line 2381
    .line 2382
    if-ne v14, v7, :cond_99

    .line 2383
    .line 2384
    const-string v14, "OFFER_DETAIL"

    .line 2385
    .line 2386
    goto :goto_4c

    .line 2387
    :cond_99
    new-instance v0, La8/r0;

    .line 2388
    .line 2389
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 2390
    .line 2391
    .line 2392
    throw v0

    .line 2393
    :cond_9a
    const-string v14, "OFFER_BOTTOM_SHEET_EXPANDED"

    .line 2394
    .line 2395
    goto :goto_4c

    .line 2396
    :cond_9b
    const-string v14, "NAVIGATION_START"

    .line 2397
    .line 2398
    goto :goto_4c

    .line 2399
    :cond_9c
    const-string v14, "NAVIGATION_OVERVIEW"

    .line 2400
    .line 2401
    goto :goto_4c

    .line 2402
    :cond_9d
    const-string v14, "OFFER_DISPLAYED"

    .line 2403
    .line 2404
    :goto_4c
    iget-object v9, v9, Ldk0/a;->c:Ljava/time/OffsetDateTime;

    .line 2405
    .line 2406
    invoke-direct {v10, v12, v14, v9}, Lcz/myskoda/api/bff_maps/v3/OfferAnalyticsEventDto;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/time/OffsetDateTime;)V

    .line 2407
    .line 2408
    .line 2409
    invoke-virtual {v8, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 2410
    .line 2411
    .line 2412
    goto :goto_4b

    .line 2413
    :cond_9e
    invoke-direct {v4, v11, v8}, Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;-><init>(Ljava/util/UUID;Ljava/util/List;)V

    .line 2414
    .line 2415
    .line 2416
    const/4 v3, 0x2

    .line 2417
    iput v3, v5, La30/b;->e:I

    .line 2418
    .line 2419
    invoke-interface {v1, v4, v5}, Lcz/myskoda/api/bff_maps/v3/MapsApi;->sendOffersAnalytics(Lcz/myskoda/api/bff_maps/v3/OffersAnalyticsDataDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2420
    .line 2421
    .line 2422
    move-result-object v1

    .line 2423
    if-ne v1, v0, :cond_9f

    .line 2424
    .line 2425
    goto :goto_4d

    .line 2426
    :cond_9f
    move-object v0, v1

    .line 2427
    :goto_4d
    return-object v0

    .line 2428
    :pswitch_1b
    move v3, v9

    .line 2429
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2430
    .line 2431
    iget v1, v5, La30/b;->e:I

    .line 2432
    .line 2433
    if-eqz v1, :cond_a2

    .line 2434
    .line 2435
    if-eq v1, v13, :cond_a1

    .line 2436
    .line 2437
    if-ne v1, v3, :cond_a0

    .line 2438
    .line 2439
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2440
    .line 2441
    .line 2442
    move-object/from16 v0, p1

    .line 2443
    .line 2444
    goto :goto_4f

    .line 2445
    :cond_a0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2446
    .line 2447
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2448
    .line 2449
    .line 2450
    throw v0

    .line 2451
    :cond_a1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2452
    .line 2453
    .line 2454
    move-object/from16 v1, p1

    .line 2455
    .line 2456
    goto :goto_4e

    .line 2457
    :cond_a2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2458
    .line 2459
    .line 2460
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2461
    .line 2462
    check-cast v1, Lai0/a;

    .line 2463
    .line 2464
    iget-object v1, v1, Lai0/a;->b:Lti0/a;

    .line 2465
    .line 2466
    iput v13, v5, La30/b;->e:I

    .line 2467
    .line 2468
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2469
    .line 2470
    .line 2471
    move-result-object v1

    .line 2472
    if-ne v1, v0, :cond_a3

    .line 2473
    .line 2474
    goto :goto_4f

    .line 2475
    :cond_a3
    :goto_4e
    check-cast v1, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 2476
    .line 2477
    check-cast v11, Ljava/lang/String;

    .line 2478
    .line 2479
    check-cast v10, Llf0/f;

    .line 2480
    .line 2481
    new-instance v2, Lcz/myskoda/api/bff_garage/v2/VehiclePatchDto;

    .line 2482
    .line 2483
    iget-object v3, v10, Llf0/f;->a:Ljava/lang/String;

    .line 2484
    .line 2485
    invoke-direct {v2, v3}, Lcz/myskoda/api/bff_garage/v2/VehiclePatchDto;-><init>(Ljava/lang/String;)V

    .line 2486
    .line 2487
    .line 2488
    const/4 v3, 0x2

    .line 2489
    iput v3, v5, La30/b;->e:I

    .line 2490
    .line 2491
    invoke-interface {v1, v11, v2, v5}, Lcz/myskoda/api/bff_garage/v2/GarageApi;->updateVehicle(Ljava/lang/String;Lcz/myskoda/api/bff_garage/v2/VehiclePatchDto;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2492
    .line 2493
    .line 2494
    move-result-object v1

    .line 2495
    if-ne v1, v0, :cond_a4

    .line 2496
    .line 2497
    goto :goto_4f

    .line 2498
    :cond_a4
    move-object v0, v1

    .line 2499
    :goto_4f
    return-object v0

    .line 2500
    :pswitch_1c
    move v3, v9

    .line 2501
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2502
    .line 2503
    iget v1, v5, La30/b;->e:I

    .line 2504
    .line 2505
    if-eqz v1, :cond_a7

    .line 2506
    .line 2507
    if-eq v1, v13, :cond_a6

    .line 2508
    .line 2509
    if-ne v1, v3, :cond_a5

    .line 2510
    .line 2511
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2512
    .line 2513
    .line 2514
    move-object/from16 v0, p1

    .line 2515
    .line 2516
    goto :goto_51

    .line 2517
    :cond_a5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 2518
    .line 2519
    invoke-direct {v0, v12}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 2520
    .line 2521
    .line 2522
    throw v0

    .line 2523
    :cond_a6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2524
    .line 2525
    .line 2526
    move-object/from16 v1, p1

    .line 2527
    .line 2528
    goto :goto_50

    .line 2529
    :cond_a7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 2530
    .line 2531
    .line 2532
    iget-object v1, v5, La30/b;->g:Ljava/lang/Object;

    .line 2533
    .line 2534
    check-cast v1, La30/d;

    .line 2535
    .line 2536
    iget-object v1, v1, La30/d;->b:Lti0/a;

    .line 2537
    .line 2538
    iput v13, v5, La30/b;->e:I

    .line 2539
    .line 2540
    invoke-interface {v1, v5}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2541
    .line 2542
    .line 2543
    move-result-object v1

    .line 2544
    if-ne v1, v0, :cond_a8

    .line 2545
    .line 2546
    goto :goto_51

    .line 2547
    :cond_a8
    :goto_50
    check-cast v1, Lcz/myskoda/api/bff_garage/v2/GarageApi;

    .line 2548
    .line 2549
    check-cast v11, Ljava/lang/String;

    .line 2550
    .line 2551
    check-cast v10, Ljava/lang/String;

    .line 2552
    .line 2553
    const/4 v3, 0x2

    .line 2554
    iput v3, v5, La30/b;->e:I

    .line 2555
    .line 2556
    invoke-interface {v1, v11, v10, v5}, Lcz/myskoda/api/bff_garage/v2/GarageApi;->removeVehicleGuestUser(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 2557
    .line 2558
    .line 2559
    move-result-object v1

    .line 2560
    if-ne v1, v0, :cond_a9

    .line 2561
    .line 2562
    goto :goto_51

    .line 2563
    :cond_a9
    move-object v0, v1

    .line 2564
    :goto_51
    return-object v0

    .line 2565
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
