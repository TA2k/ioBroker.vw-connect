.class public final Lcn0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Lrx0/i;


# direct methods
.method public constructor <init>(Lyy0/j;Lay0/k;I)V
    .locals 0

    iput p3, p0, Lcn0/e;->d:I

    packed-switch p3, :pswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    return-void

    .line 2
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lyy0/j;Lay0/n;I)V
    .locals 0

    iput p3, p0, Lcn0/e;->d:I

    packed-switch p3, :pswitch_data_0

    .line 3
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    return-void

    .line 4
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    return-void

    .line 5
    :pswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    return-void

    .line 6
    :pswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lcn0/e;->f:Lrx0/i;

    iput-object p1, p0, Lcn0/e;->e:Lyy0/j;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lcn0/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lyy0/d1;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lyy0/d1;

    .line 12
    .line 13
    iget v1, v0, Lyy0/d1;->e:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lyy0/d1;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lyy0/d1;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lyy0/d1;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lyy0/d1;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lyy0/d1;->e:I

    .line 35
    .line 36
    const/4 v3, 0x2

    .line 37
    const/4 v4, 0x1

    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    iget-object p0, v0, Lyy0/d1;->h:Lyy0/j;

    .line 57
    .line 58
    iget-object p1, v0, Lyy0/d1;->g:Ljava/lang/Object;

    .line 59
    .line 60
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput-object p1, v0, Lyy0/d1;->g:Ljava/lang/Object;

    .line 68
    .line 69
    iget-object p2, p0, Lcn0/e;->e:Lyy0/j;

    .line 70
    .line 71
    iput-object p2, v0, Lyy0/d1;->h:Lyy0/j;

    .line 72
    .line 73
    iput v4, v0, Lyy0/d1;->e:I

    .line 74
    .line 75
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 76
    .line 77
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    if-ne p0, v1, :cond_4

    .line 82
    .line 83
    goto :goto_3

    .line 84
    :cond_4
    move-object p0, p2

    .line 85
    :goto_1
    const/4 p2, 0x0

    .line 86
    iput-object p2, v0, Lyy0/d1;->g:Ljava/lang/Object;

    .line 87
    .line 88
    iput-object p2, v0, Lyy0/d1;->h:Lyy0/j;

    .line 89
    .line 90
    iput v3, v0, Lyy0/d1;->e:I

    .line 91
    .line 92
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    :goto_3
    return-object v1

    .line 102
    :pswitch_0
    instance-of v0, p2, Lyy0/o0;

    .line 103
    .line 104
    if-eqz v0, :cond_6

    .line 105
    .line 106
    move-object v0, p2

    .line 107
    check-cast v0, Lyy0/o0;

    .line 108
    .line 109
    iget v1, v0, Lyy0/o0;->e:I

    .line 110
    .line 111
    const/high16 v2, -0x80000000

    .line 112
    .line 113
    and-int v3, v1, v2

    .line 114
    .line 115
    if-eqz v3, :cond_6

    .line 116
    .line 117
    sub-int/2addr v1, v2

    .line 118
    iput v1, v0, Lyy0/o0;->e:I

    .line 119
    .line 120
    goto :goto_4

    .line 121
    :cond_6
    new-instance v0, Lyy0/o0;

    .line 122
    .line 123
    invoke-direct {v0, p0, p2}, Lyy0/o0;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 124
    .line 125
    .line 126
    :goto_4
    iget-object p2, v0, Lyy0/o0;->d:Ljava/lang/Object;

    .line 127
    .line 128
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 129
    .line 130
    iget v2, v0, Lyy0/o0;->e:I

    .line 131
    .line 132
    const/4 v3, 0x2

    .line 133
    const/4 v4, 0x1

    .line 134
    if-eqz v2, :cond_9

    .line 135
    .line 136
    if-eq v2, v4, :cond_8

    .line 137
    .line 138
    if-ne v2, v3, :cond_7

    .line 139
    .line 140
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    goto :goto_6

    .line 144
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 145
    .line 146
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 147
    .line 148
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    throw p0

    .line 152
    :cond_8
    iget-object p0, v0, Lyy0/o0;->f:Lyy0/j;

    .line 153
    .line 154
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    goto :goto_5

    .line 158
    :cond_9
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    iget-object p2, p0, Lcn0/e;->e:Lyy0/j;

    .line 162
    .line 163
    iput-object p2, v0, Lyy0/o0;->f:Lyy0/j;

    .line 164
    .line 165
    iput v4, v0, Lyy0/o0;->e:I

    .line 166
    .line 167
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 168
    .line 169
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-ne p0, v1, :cond_a

    .line 174
    .line 175
    goto :goto_7

    .line 176
    :cond_a
    move-object v8, p2

    .line 177
    move-object p2, p0

    .line 178
    move-object p0, v8

    .line 179
    :goto_5
    const/4 p1, 0x0

    .line 180
    iput-object p1, v0, Lyy0/o0;->f:Lyy0/j;

    .line 181
    .line 182
    iput v3, v0, Lyy0/o0;->e:I

    .line 183
    .line 184
    invoke-interface {p0, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object p0

    .line 188
    if-ne p0, v1, :cond_b

    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_b
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    :goto_7
    return-object v1

    .line 194
    :pswitch_1
    instance-of v0, p2, Lne0/m;

    .line 195
    .line 196
    if-eqz v0, :cond_c

    .line 197
    .line 198
    move-object v0, p2

    .line 199
    check-cast v0, Lne0/m;

    .line 200
    .line 201
    iget v1, v0, Lne0/m;->e:I

    .line 202
    .line 203
    const/high16 v2, -0x80000000

    .line 204
    .line 205
    and-int v3, v1, v2

    .line 206
    .line 207
    if-eqz v3, :cond_c

    .line 208
    .line 209
    sub-int/2addr v1, v2

    .line 210
    iput v1, v0, Lne0/m;->e:I

    .line 211
    .line 212
    goto :goto_8

    .line 213
    :cond_c
    new-instance v0, Lne0/m;

    .line 214
    .line 215
    invoke-direct {v0, p0, p2}, Lne0/m;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 216
    .line 217
    .line 218
    :goto_8
    iget-object p2, v0, Lne0/m;->d:Ljava/lang/Object;

    .line 219
    .line 220
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 221
    .line 222
    iget v2, v0, Lne0/m;->e:I

    .line 223
    .line 224
    const/4 v3, 0x2

    .line 225
    const/4 v4, 0x1

    .line 226
    if-eqz v2, :cond_f

    .line 227
    .line 228
    if-eq v2, v4, :cond_e

    .line 229
    .line 230
    if-ne v2, v3, :cond_d

    .line 231
    .line 232
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    goto :goto_a

    .line 236
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 237
    .line 238
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 239
    .line 240
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    throw p0

    .line 244
    :cond_e
    iget p0, v0, Lne0/m;->i:I

    .line 245
    .line 246
    iget-object p1, v0, Lne0/m;->h:Lyy0/j;

    .line 247
    .line 248
    iget-object v2, v0, Lne0/m;->g:Ljava/lang/Object;

    .line 249
    .line 250
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 251
    .line 252
    .line 253
    goto :goto_9

    .line 254
    :cond_f
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    move-object p2, p1

    .line 258
    check-cast p2, Lne0/s;

    .line 259
    .line 260
    iput-object p1, v0, Lne0/m;->g:Ljava/lang/Object;

    .line 261
    .line 262
    iget-object p2, p0, Lcn0/e;->e:Lyy0/j;

    .line 263
    .line 264
    iput-object p2, v0, Lne0/m;->h:Lyy0/j;

    .line 265
    .line 266
    const/4 v2, 0x0

    .line 267
    iput v2, v0, Lne0/m;->i:I

    .line 268
    .line 269
    iput v4, v0, Lne0/m;->e:I

    .line 270
    .line 271
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 272
    .line 273
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    if-ne p0, v1, :cond_10

    .line 278
    .line 279
    goto :goto_b

    .line 280
    :cond_10
    move-object v8, p2

    .line 281
    move-object p2, p0

    .line 282
    move p0, v2

    .line 283
    move-object v2, p1

    .line 284
    move-object p1, v8

    .line 285
    :goto_9
    check-cast p2, Ljava/lang/Boolean;

    .line 286
    .line 287
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 288
    .line 289
    .line 290
    move-result p2

    .line 291
    if-eqz p2, :cond_11

    .line 292
    .line 293
    const/4 p2, 0x0

    .line 294
    iput-object p2, v0, Lne0/m;->g:Ljava/lang/Object;

    .line 295
    .line 296
    iput-object p2, v0, Lne0/m;->h:Lyy0/j;

    .line 297
    .line 298
    iput p0, v0, Lne0/m;->i:I

    .line 299
    .line 300
    iput v3, v0, Lne0/m;->e:I

    .line 301
    .line 302
    invoke-interface {p1, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    if-ne p0, v1, :cond_11

    .line 307
    .line 308
    goto :goto_b

    .line 309
    :cond_11
    :goto_a
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 310
    .line 311
    :goto_b
    return-object v1

    .line 312
    :pswitch_2
    instance-of v0, p2, Llf0/c;

    .line 313
    .line 314
    if-eqz v0, :cond_12

    .line 315
    .line 316
    move-object v0, p2

    .line 317
    check-cast v0, Llf0/c;

    .line 318
    .line 319
    iget v1, v0, Llf0/c;->e:I

    .line 320
    .line 321
    const/high16 v2, -0x80000000

    .line 322
    .line 323
    and-int v3, v1, v2

    .line 324
    .line 325
    if-eqz v3, :cond_12

    .line 326
    .line 327
    sub-int/2addr v1, v2

    .line 328
    iput v1, v0, Llf0/c;->e:I

    .line 329
    .line 330
    goto :goto_c

    .line 331
    :cond_12
    new-instance v0, Llf0/c;

    .line 332
    .line 333
    invoke-direct {v0, p0, p2}, Llf0/c;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 334
    .line 335
    .line 336
    :goto_c
    iget-object p2, v0, Llf0/c;->d:Ljava/lang/Object;

    .line 337
    .line 338
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 339
    .line 340
    iget v2, v0, Llf0/c;->e:I

    .line 341
    .line 342
    const/4 v3, 0x2

    .line 343
    const/4 v4, 0x1

    .line 344
    if-eqz v2, :cond_15

    .line 345
    .line 346
    if-eq v2, v4, :cond_14

    .line 347
    .line 348
    if-ne v2, v3, :cond_13

    .line 349
    .line 350
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 351
    .line 352
    .line 353
    goto :goto_e

    .line 354
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 355
    .line 356
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 357
    .line 358
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    throw p0

    .line 362
    :cond_14
    iget p0, v0, Llf0/c;->j:I

    .line 363
    .line 364
    iget-object p1, v0, Llf0/c;->h:Lyy0/j;

    .line 365
    .line 366
    iget-object v2, v0, Llf0/c;->g:Lne0/t;

    .line 367
    .line 368
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 369
    .line 370
    .line 371
    goto :goto_d

    .line 372
    :cond_15
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 373
    .line 374
    .line 375
    move-object v2, p1

    .line 376
    check-cast v2, Lne0/t;

    .line 377
    .line 378
    iput-object v2, v0, Llf0/c;->g:Lne0/t;

    .line 379
    .line 380
    iget-object p1, p0, Lcn0/e;->e:Lyy0/j;

    .line 381
    .line 382
    iput-object p1, v0, Llf0/c;->h:Lyy0/j;

    .line 383
    .line 384
    const/4 p2, 0x0

    .line 385
    iput p2, v0, Llf0/c;->j:I

    .line 386
    .line 387
    iput v4, v0, Llf0/c;->e:I

    .line 388
    .line 389
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 390
    .line 391
    invoke-static {v2, p0, v0}, Llp/sf;->b(Lne0/t;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object p0

    .line 395
    if-ne p0, v1, :cond_16

    .line 396
    .line 397
    goto :goto_f

    .line 398
    :cond_16
    move v8, p2

    .line 399
    move-object p2, p0

    .line 400
    move p0, v8

    .line 401
    :goto_d
    move-object v4, p2

    .line 402
    check-cast v4, Lne0/t;

    .line 403
    .line 404
    instance-of v5, v4, Lne0/e;

    .line 405
    .line 406
    if-nez v5, :cond_17

    .line 407
    .line 408
    instance-of v5, v4, Lne0/c;

    .line 409
    .line 410
    if-eqz v5, :cond_18

    .line 411
    .line 412
    check-cast v4, Lne0/c;

    .line 413
    .line 414
    iget-object v4, v4, Lne0/c;->a:Ljava/lang/Throwable;

    .line 415
    .line 416
    sget-object v5, Lss0/i0;->d:Lss0/i0;

    .line 417
    .line 418
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 419
    .line 420
    .line 421
    move-result v4

    .line 422
    if-nez v4, :cond_18

    .line 423
    .line 424
    :cond_17
    const/4 v4, 0x0

    .line 425
    iput-object v4, v0, Llf0/c;->g:Lne0/t;

    .line 426
    .line 427
    iput-object v4, v0, Llf0/c;->h:Lyy0/j;

    .line 428
    .line 429
    iput-object p2, v0, Llf0/c;->i:Ljava/lang/Object;

    .line 430
    .line 431
    iput p0, v0, Llf0/c;->j:I

    .line 432
    .line 433
    iput v3, v0, Llf0/c;->e:I

    .line 434
    .line 435
    invoke-interface {p1, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    move-result-object p0

    .line 439
    if-ne p0, v1, :cond_18

    .line 440
    .line 441
    goto :goto_f

    .line 442
    :cond_18
    :goto_e
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 443
    .line 444
    :goto_f
    return-object v1

    .line 445
    :pswitch_3
    instance-of v0, p2, Lko0/b;

    .line 446
    .line 447
    if-eqz v0, :cond_19

    .line 448
    .line 449
    move-object v0, p2

    .line 450
    check-cast v0, Lko0/b;

    .line 451
    .line 452
    iget v1, v0, Lko0/b;->e:I

    .line 453
    .line 454
    const/high16 v2, -0x80000000

    .line 455
    .line 456
    and-int v3, v1, v2

    .line 457
    .line 458
    if-eqz v3, :cond_19

    .line 459
    .line 460
    sub-int/2addr v1, v2

    .line 461
    iput v1, v0, Lko0/b;->e:I

    .line 462
    .line 463
    goto :goto_10

    .line 464
    :cond_19
    new-instance v0, Lko0/b;

    .line 465
    .line 466
    invoke-direct {v0, p0, p2}, Lko0/b;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 467
    .line 468
    .line 469
    :goto_10
    iget-object p2, v0, Lko0/b;->d:Ljava/lang/Object;

    .line 470
    .line 471
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 472
    .line 473
    iget v2, v0, Lko0/b;->e:I

    .line 474
    .line 475
    const/4 v3, 0x2

    .line 476
    const/4 v4, 0x1

    .line 477
    if-eqz v2, :cond_1c

    .line 478
    .line 479
    if-eq v2, v4, :cond_1b

    .line 480
    .line 481
    if-ne v2, v3, :cond_1a

    .line 482
    .line 483
    goto :goto_11

    .line 484
    :cond_1a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 485
    .line 486
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 487
    .line 488
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 489
    .line 490
    .line 491
    throw p0

    .line 492
    :cond_1b
    :goto_11
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 493
    .line 494
    .line 495
    goto :goto_12

    .line 496
    :cond_1c
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 497
    .line 498
    .line 499
    check-cast p1, Lne0/t;

    .line 500
    .line 501
    instance-of p2, p1, Lne0/c;

    .line 502
    .line 503
    if-eqz p2, :cond_1d

    .line 504
    .line 505
    move-object p2, p1

    .line 506
    check-cast p2, Lne0/c;

    .line 507
    .line 508
    invoke-static {p2}, Llp/ae;->b(Lne0/c;)Z

    .line 509
    .line 510
    .line 511
    move-result p2

    .line 512
    if-eqz p2, :cond_1d

    .line 513
    .line 514
    iput v4, v0, Lko0/b;->e:I

    .line 515
    .line 516
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 517
    .line 518
    invoke-interface {p0, p1, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object p0

    .line 522
    if-ne p0, v1, :cond_1e

    .line 523
    .line 524
    goto :goto_13

    .line 525
    :cond_1d
    iput v3, v0, Lko0/b;->e:I

    .line 526
    .line 527
    iget-object p0, p0, Lcn0/e;->e:Lyy0/j;

    .line 528
    .line 529
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 530
    .line 531
    .line 532
    move-result-object p0

    .line 533
    if-ne p0, v1, :cond_1e

    .line 534
    .line 535
    goto :goto_13

    .line 536
    :cond_1e
    :goto_12
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 537
    .line 538
    :goto_13
    return-object v1

    .line 539
    :pswitch_4
    instance-of v0, p2, Lcn0/d;

    .line 540
    .line 541
    if-eqz v0, :cond_1f

    .line 542
    .line 543
    move-object v0, p2

    .line 544
    check-cast v0, Lcn0/d;

    .line 545
    .line 546
    iget v1, v0, Lcn0/d;->e:I

    .line 547
    .line 548
    const/high16 v2, -0x80000000

    .line 549
    .line 550
    and-int v3, v1, v2

    .line 551
    .line 552
    if-eqz v3, :cond_1f

    .line 553
    .line 554
    sub-int/2addr v1, v2

    .line 555
    iput v1, v0, Lcn0/d;->e:I

    .line 556
    .line 557
    goto :goto_14

    .line 558
    :cond_1f
    new-instance v0, Lcn0/d;

    .line 559
    .line 560
    invoke-direct {v0, p0, p2}, Lcn0/d;-><init>(Lcn0/e;Lkotlin/coroutines/Continuation;)V

    .line 561
    .line 562
    .line 563
    :goto_14
    iget-object p2, v0, Lcn0/d;->d:Ljava/lang/Object;

    .line 564
    .line 565
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 566
    .line 567
    iget v2, v0, Lcn0/d;->e:I

    .line 568
    .line 569
    const/4 v3, 0x2

    .line 570
    const/4 v4, 0x1

    .line 571
    const/4 v5, 0x0

    .line 572
    if-eqz v2, :cond_22

    .line 573
    .line 574
    if-eq v2, v4, :cond_21

    .line 575
    .line 576
    if-ne v2, v3, :cond_20

    .line 577
    .line 578
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 579
    .line 580
    .line 581
    goto :goto_17

    .line 582
    :cond_20
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 583
    .line 584
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 585
    .line 586
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    throw p0

    .line 590
    :cond_21
    iget p0, v0, Lcn0/d;->i:I

    .line 591
    .line 592
    iget-object p1, v0, Lcn0/d;->h:Lne0/e;

    .line 593
    .line 594
    iget-object v2, v0, Lcn0/d;->g:Lyy0/j;

    .line 595
    .line 596
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 597
    .line 598
    .line 599
    goto :goto_15

    .line 600
    :cond_22
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 601
    .line 602
    .line 603
    check-cast p1, Lne0/t;

    .line 604
    .line 605
    instance-of p2, p1, Lne0/e;

    .line 606
    .line 607
    const/4 v2, 0x0

    .line 608
    iget-object v6, p0, Lcn0/e;->e:Lyy0/j;

    .line 609
    .line 610
    if-eqz p2, :cond_25

    .line 611
    .line 612
    move-object p2, p1

    .line 613
    check-cast p2, Lne0/e;

    .line 614
    .line 615
    iget-object v7, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 616
    .line 617
    check-cast v7, Lcn0/c;

    .line 618
    .line 619
    invoke-static {v7}, Ljp/sd;->b(Lcn0/c;)Z

    .line 620
    .line 621
    .line 622
    move-result v7

    .line 623
    if-eqz v7, :cond_24

    .line 624
    .line 625
    iput-object v6, v0, Lcn0/d;->g:Lyy0/j;

    .line 626
    .line 627
    iput-object p2, v0, Lcn0/d;->h:Lne0/e;

    .line 628
    .line 629
    iput v2, v0, Lcn0/d;->i:I

    .line 630
    .line 631
    iput v4, v0, Lcn0/d;->e:I

    .line 632
    .line 633
    iget-object p0, p0, Lcn0/e;->f:Lrx0/i;

    .line 634
    .line 635
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 636
    .line 637
    .line 638
    move-result-object p0

    .line 639
    if-ne p0, v1, :cond_23

    .line 640
    .line 641
    goto :goto_18

    .line 642
    :cond_23
    move p0, v2

    .line 643
    move-object v2, v6

    .line 644
    :goto_15
    move-object v6, v2

    .line 645
    move v2, p0

    .line 646
    :cond_24
    check-cast p1, Lne0/e;

    .line 647
    .line 648
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 649
    .line 650
    check-cast p0, Lcn0/c;

    .line 651
    .line 652
    goto :goto_16

    .line 653
    :cond_25
    instance-of p0, p1, Lne0/c;

    .line 654
    .line 655
    if-eqz p0, :cond_27

    .line 656
    .line 657
    move-object p0, v5

    .line 658
    :goto_16
    iput-object v5, v0, Lcn0/d;->g:Lyy0/j;

    .line 659
    .line 660
    iput-object v5, v0, Lcn0/d;->h:Lne0/e;

    .line 661
    .line 662
    iput v2, v0, Lcn0/d;->i:I

    .line 663
    .line 664
    iput v3, v0, Lcn0/d;->e:I

    .line 665
    .line 666
    invoke-interface {v6, p0, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 667
    .line 668
    .line 669
    move-result-object p0

    .line 670
    if-ne p0, v1, :cond_26

    .line 671
    .line 672
    goto :goto_18

    .line 673
    :cond_26
    :goto_17
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 674
    .line 675
    :goto_18
    return-object v1

    .line 676
    :cond_27
    new-instance p0, La8/r0;

    .line 677
    .line 678
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 679
    .line 680
    .line 681
    throw p0

    .line 682
    nop

    .line 683
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
