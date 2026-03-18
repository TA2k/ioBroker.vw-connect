.class public final Lxc/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lxc/h;


# direct methods
.method public synthetic constructor <init>(Lxc/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lxc/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lxc/g;->f:Lxc/h;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lxc/g;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lxc/g;

    .line 7
    .line 8
    iget-object p0, p0, Lxc/g;->f:Lxc/h;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lxc/g;-><init>(Lxc/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lxc/g;

    .line 16
    .line 17
    iget-object p0, p0, Lxc/g;->f:Lxc/h;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lxc/g;-><init>(Lxc/h;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lxc/g;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lxc/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lxc/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lxc/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lxc/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lxc/g;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lxc/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lxc/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lxc/g;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    const/4 v3, 0x0

    .line 12
    iget-object v4, p0, Lxc/g;->f:Lxc/h;

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    iget-object p1, v4, Lxc/h;->k:Lyy0/c2;

    .line 34
    .line 35
    new-instance v1, Llc/q;

    .line 36
    .line 37
    sget-object v5, Llc/a;->c:Llc/c;

    .line 38
    .line 39
    invoke-direct {v1, v5}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 43
    .line 44
    .line 45
    invoke-virtual {p1, v3, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    new-instance p1, Lxc/a;

    .line 49
    .line 50
    new-instance v1, Ltc/h;

    .line 51
    .line 52
    iget-object v5, v4, Lxc/h;->j:Lac/f;

    .line 53
    .line 54
    iget-object v6, v4, Lxc/h;->l:Lac/i;

    .line 55
    .line 56
    invoke-virtual {v6}, Lac/i;->e()Lac/e;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    invoke-static {v6}, Lac/f;->a(Lac/e;)Lac/c;

    .line 64
    .line 65
    .line 66
    move-result-object v5

    .line 67
    invoke-direct {v1, v5}, Ltc/h;-><init>(Lac/c;)V

    .line 68
    .line 69
    .line 70
    iget-object v5, v4, Lxc/h;->h:Ljava/lang/String;

    .line 71
    .line 72
    invoke-direct {p1, v1, v5}, Lxc/a;-><init>(Ltc/h;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object v1, v4, Lxc/h;->e:Lth/b;

    .line 76
    .line 77
    iput v2, p0, Lxc/g;->e:I

    .line 78
    .line 79
    invoke-virtual {v1, p1, p0}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1

    .line 83
    if-ne p1, v0, :cond_2

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_2
    :goto_0
    check-cast p1, Llx0/o;

    .line 87
    .line 88
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 89
    .line 90
    instance-of p1, p0, Llx0/n;

    .line 91
    .line 92
    if-nez p1, :cond_3

    .line 93
    .line 94
    move-object p1, p0

    .line 95
    check-cast p1, Llx0/b0;

    .line 96
    .line 97
    iget-object p1, v4, Lxc/h;->f:Lyj/b;

    .line 98
    .line 99
    invoke-virtual {p1}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    :cond_3
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    if-eqz p0, :cond_5

    .line 107
    .line 108
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    sget-object p1, Lgi/b;->h:Lgi/b;

    .line 112
    .line 113
    new-instance v0, Lw81/d;

    .line 114
    .line 115
    const/16 v1, 0xf

    .line 116
    .line 117
    invoke-direct {v0, v1}, Lw81/d;-><init>(I)V

    .line 118
    .line 119
    .line 120
    sget-object v1, Lgi/a;->e:Lgi/a;

    .line 121
    .line 122
    const-class v2, Lxc/h;

    .line 123
    .line 124
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    const/16 v5, 0x24

    .line 129
    .line 130
    invoke-static {v2, v5}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v5

    .line 134
    const/16 v6, 0x2e

    .line 135
    .line 136
    invoke-static {v6, v5, v5}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v5

    .line 140
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 141
    .line 142
    .line 143
    move-result v6

    .line 144
    if-nez v6, :cond_4

    .line 145
    .line 146
    goto :goto_1

    .line 147
    :cond_4
    const-string v2, "Kt"

    .line 148
    .line 149
    invoke-static {v5, v2}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    :goto_1
    invoke-static {v2, v1, p1, p0, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 154
    .line 155
    .line 156
    iget-object p1, v4, Lxc/h;->k:Lyy0/c2;

    .line 157
    .line 158
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-static {p0, p1, v3}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    :cond_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 166
    .line 167
    :goto_2
    return-object v0

    .line 168
    :pswitch_0
    iget-object v0, p0, Lxc/g;->f:Lxc/h;

    .line 169
    .line 170
    iget-object v1, v0, Lxc/h;->k:Lyy0/c2;

    .line 171
    .line 172
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 173
    .line 174
    iget v3, p0, Lxc/g;->e:I

    .line 175
    .line 176
    const/4 v4, 0x1

    .line 177
    const/4 v5, 0x0

    .line 178
    if-eqz v3, :cond_7

    .line 179
    .line 180
    if-ne v3, v4, :cond_6

    .line 181
    .line 182
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    goto :goto_3

    .line 186
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 187
    .line 188
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 189
    .line 190
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw p0

    .line 194
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    new-instance p1, Llc/q;

    .line 198
    .line 199
    sget-object v3, Llc/a;->c:Llc/c;

    .line 200
    .line 201
    invoke-direct {p1, v3}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 205
    .line 206
    .line 207
    invoke-virtual {v1, v5, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    iget-object p1, v0, Lxc/h;->d:Lwc/a;

    .line 211
    .line 212
    iput v4, p0, Lxc/g;->e:I

    .line 213
    .line 214
    invoke-virtual {p1, p0}, Lwc/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    move-result-object p1

    .line 218
    if-ne p1, v2, :cond_8

    .line 219
    .line 220
    goto/16 :goto_6

    .line 221
    .line 222
    :cond_8
    :goto_3
    check-cast p1, Llx0/o;

    .line 223
    .line 224
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 225
    .line 226
    instance-of p1, p0, Llx0/n;

    .line 227
    .line 228
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    if-nez p1, :cond_c

    .line 231
    .line 232
    move-object p1, p0

    .line 233
    check-cast p1, Ltc/k;

    .line 234
    .line 235
    iget-object v3, p1, Ltc/k;->d:Ljava/util/List;

    .line 236
    .line 237
    iput-object v3, v0, Lxc/h;->i:Ljava/util/List;

    .line 238
    .line 239
    check-cast v3, Ljava/lang/Iterable;

    .line 240
    .line 241
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    :cond_9
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    if-eqz v4, :cond_a

    .line 250
    .line 251
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v4

    .line 255
    move-object v6, v4

    .line 256
    check-cast v6, Lac/a0;

    .line 257
    .line 258
    iget-object v6, v6, Lac/a0;->e:Ljava/lang/String;

    .line 259
    .line 260
    iget-object v7, p1, Ltc/k;->e:Ljava/lang/String;

    .line 261
    .line 262
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    move-result v6

    .line 266
    if-eqz v6, :cond_9

    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_a
    move-object v4, v5

    .line 270
    :goto_4
    check-cast v4, Lac/a0;

    .line 271
    .line 272
    if-nez v4, :cond_b

    .line 273
    .line 274
    iget-object p1, v0, Lxc/h;->i:Ljava/util/List;

    .line 275
    .line 276
    const/4 v3, 0x0

    .line 277
    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object p1

    .line 281
    move-object v4, p1

    .line 282
    check-cast v4, Lac/a0;

    .line 283
    .line 284
    :cond_b
    new-instance p1, Lac/p;

    .line 285
    .line 286
    iget-object v3, v0, Lxc/h;->i:Ljava/util/List;

    .line 287
    .line 288
    invoke-direct {p1, v3, v4}, Lac/p;-><init>(Ljava/util/List;Lac/a0;)V

    .line 289
    .line 290
    .line 291
    iget-object v0, v0, Lxc/h;->l:Lac/i;

    .line 292
    .line 293
    invoke-virtual {v0, p1}, Lac/i;->g(Lac/w;)V

    .line 294
    .line 295
    .line 296
    new-instance p1, Llc/q;

    .line 297
    .line 298
    invoke-direct {p1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 299
    .line 300
    .line 301
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 302
    .line 303
    .line 304
    invoke-virtual {v1, v5, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 305
    .line 306
    .line 307
    :cond_c
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 308
    .line 309
    .line 310
    move-result-object p0

    .line 311
    if-eqz p0, :cond_e

    .line 312
    .line 313
    sget-object p1, Lgi/b;->h:Lgi/b;

    .line 314
    .line 315
    new-instance v0, Lw81/d;

    .line 316
    .line 317
    const/16 v3, 0x10

    .line 318
    .line 319
    invoke-direct {v0, v3}, Lw81/d;-><init>(I)V

    .line 320
    .line 321
    .line 322
    sget-object v3, Lgi/a;->e:Lgi/a;

    .line 323
    .line 324
    const-class v4, Lxc/h;

    .line 325
    .line 326
    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 327
    .line 328
    .line 329
    move-result-object v4

    .line 330
    const/16 v6, 0x24

    .line 331
    .line 332
    invoke-static {v4, v6}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 333
    .line 334
    .line 335
    move-result-object v6

    .line 336
    const/16 v7, 0x2e

    .line 337
    .line 338
    invoke-static {v7, v6, v6}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 339
    .line 340
    .line 341
    move-result-object v6

    .line 342
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 343
    .line 344
    .line 345
    move-result v7

    .line 346
    if-nez v7, :cond_d

    .line 347
    .line 348
    goto :goto_5

    .line 349
    :cond_d
    const-string v4, "Kt"

    .line 350
    .line 351
    invoke-static {v6, v4}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 352
    .line 353
    .line 354
    move-result-object v4

    .line 355
    :goto_5
    invoke-static {v4, v3, p1, p0, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 356
    .line 357
    .line 358
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 359
    .line 360
    .line 361
    move-result-object p0

    .line 362
    invoke-static {p0, v1, v5}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 363
    .line 364
    .line 365
    :cond_e
    :goto_6
    return-object v2

    .line 366
    nop

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
