.class public final Lau0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lyy0/j;Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p3, p0, Lau0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lau0/d;->e:Lyy0/j;

    .line 4
    .line 5
    iput-object p2, p0, Lau0/d;->f:Ljava/lang/String;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lau0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lve0/p;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lve0/p;

    .line 12
    .line 13
    iget v1, v0, Lve0/p;->e:I

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
    iput v1, v0, Lve0/p;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lve0/p;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lve0/p;-><init>(Lau0/d;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lve0/p;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lve0/p;->e:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    check-cast p1, Lq6/b;

    .line 57
    .line 58
    iget-object p2, p0, Lau0/d;->f:Ljava/lang/String;

    .line 59
    .line 60
    invoke-static {p2}, Llp/m1;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    invoke-static {p2}, Ljp/ne;->b(Ljava/lang/String;)Lq6/e;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    invoke-virtual {p1, p2}, Lq6/b;->c(Lq6/e;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iput v3, v0, Lve0/p;->e:I

    .line 73
    .line 74
    iget-object p0, p0, Lau0/d;->e:Lyy0/j;

    .line 75
    .line 76
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    if-ne p0, v1, :cond_3

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_3
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    :goto_2
    return-object v1

    .line 86
    :pswitch_0
    instance-of v0, p2, Luk0/b;

    .line 87
    .line 88
    if-eqz v0, :cond_4

    .line 89
    .line 90
    move-object v0, p2

    .line 91
    check-cast v0, Luk0/b;

    .line 92
    .line 93
    iget v1, v0, Luk0/b;->e:I

    .line 94
    .line 95
    const/high16 v2, -0x80000000

    .line 96
    .line 97
    and-int v3, v1, v2

    .line 98
    .line 99
    if-eqz v3, :cond_4

    .line 100
    .line 101
    sub-int/2addr v1, v2

    .line 102
    iput v1, v0, Luk0/b;->e:I

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_4
    new-instance v0, Luk0/b;

    .line 106
    .line 107
    invoke-direct {v0, p0, p2}, Luk0/b;-><init>(Lau0/d;Lkotlin/coroutines/Continuation;)V

    .line 108
    .line 109
    .line 110
    :goto_3
    iget-object p2, v0, Luk0/b;->d:Ljava/lang/Object;

    .line 111
    .line 112
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 113
    .line 114
    iget v2, v0, Luk0/b;->e:I

    .line 115
    .line 116
    const/4 v3, 0x1

    .line 117
    if-eqz v2, :cond_6

    .line 118
    .line 119
    if-ne v2, v3, :cond_5

    .line 120
    .line 121
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 128
    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0

    .line 133
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    check-cast p1, Lne0/t;

    .line 137
    .line 138
    new-instance p2, Lag/t;

    .line 139
    .line 140
    iget-object v2, p0, Lau0/d;->f:Ljava/lang/String;

    .line 141
    .line 142
    const/16 v4, 0x11

    .line 143
    .line 144
    invoke-direct {p2, v2, v4}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 145
    .line 146
    .line 147
    invoke-static {p1, p2}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    iput v3, v0, Luk0/b;->e:I

    .line 152
    .line 153
    iget-object p0, p0, Lau0/d;->e:Lyy0/j;

    .line 154
    .line 155
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v1, :cond_7

    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_7
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 163
    .line 164
    :goto_5
    return-object v1

    .line 165
    :pswitch_1
    instance-of v0, p2, Llk0/e;

    .line 166
    .line 167
    if-eqz v0, :cond_8

    .line 168
    .line 169
    move-object v0, p2

    .line 170
    check-cast v0, Llk0/e;

    .line 171
    .line 172
    iget v1, v0, Llk0/e;->e:I

    .line 173
    .line 174
    const/high16 v2, -0x80000000

    .line 175
    .line 176
    and-int v3, v1, v2

    .line 177
    .line 178
    if-eqz v3, :cond_8

    .line 179
    .line 180
    sub-int/2addr v1, v2

    .line 181
    iput v1, v0, Llk0/e;->e:I

    .line 182
    .line 183
    goto :goto_6

    .line 184
    :cond_8
    new-instance v0, Llk0/e;

    .line 185
    .line 186
    invoke-direct {v0, p0, p2}, Llk0/e;-><init>(Lau0/d;Lkotlin/coroutines/Continuation;)V

    .line 187
    .line 188
    .line 189
    :goto_6
    iget-object p2, v0, Llk0/e;->d:Ljava/lang/Object;

    .line 190
    .line 191
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 192
    .line 193
    iget v2, v0, Llk0/e;->e:I

    .line 194
    .line 195
    const/4 v3, 0x1

    .line 196
    if-eqz v2, :cond_a

    .line 197
    .line 198
    if-ne v2, v3, :cond_9

    .line 199
    .line 200
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    goto :goto_8

    .line 204
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 205
    .line 206
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 207
    .line 208
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    throw p0

    .line 212
    :cond_a
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    check-cast p1, Lne0/s;

    .line 216
    .line 217
    instance-of p2, p1, Lne0/e;

    .line 218
    .line 219
    const/4 v2, 0x0

    .line 220
    if-eqz p2, :cond_b

    .line 221
    .line 222
    check-cast p1, Lne0/e;

    .line 223
    .line 224
    goto :goto_7

    .line 225
    :cond_b
    move-object p1, v2

    .line 226
    :goto_7
    if-eqz p1, :cond_e

    .line 227
    .line 228
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast p1, Ljava/util/List;

    .line 231
    .line 232
    if-eqz p1, :cond_e

    .line 233
    .line 234
    check-cast p1, Ljava/lang/Iterable;

    .line 235
    .line 236
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    :cond_c
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 241
    .line 242
    .line 243
    move-result p2

    .line 244
    if-eqz p2, :cond_d

    .line 245
    .line 246
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object p2

    .line 250
    move-object v4, p2

    .line 251
    check-cast v4, Lmk0/a;

    .line 252
    .line 253
    iget-object v4, v4, Lmk0/a;->c:Ljava/lang/String;

    .line 254
    .line 255
    iget-object v5, p0, Lau0/d;->f:Ljava/lang/String;

    .line 256
    .line 257
    invoke-virtual {v4, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v4

    .line 261
    if-eqz v4, :cond_c

    .line 262
    .line 263
    move-object v2, p2

    .line 264
    :cond_d
    check-cast v2, Lmk0/a;

    .line 265
    .line 266
    :cond_e
    iput v3, v0, Llk0/e;->e:I

    .line 267
    .line 268
    iget-object p0, p0, Lau0/d;->e:Lyy0/j;

    .line 269
    .line 270
    invoke-interface {p0, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 271
    .line 272
    .line 273
    move-result-object p0

    .line 274
    if-ne p0, v1, :cond_f

    .line 275
    .line 276
    goto :goto_9

    .line 277
    :cond_f
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 278
    .line 279
    :goto_9
    return-object v1

    .line 280
    :pswitch_2
    instance-of v0, p2, Lau0/c;

    .line 281
    .line 282
    if-eqz v0, :cond_10

    .line 283
    .line 284
    move-object v0, p2

    .line 285
    check-cast v0, Lau0/c;

    .line 286
    .line 287
    iget v1, v0, Lau0/c;->e:I

    .line 288
    .line 289
    const/high16 v2, -0x80000000

    .line 290
    .line 291
    and-int v3, v1, v2

    .line 292
    .line 293
    if-eqz v3, :cond_10

    .line 294
    .line 295
    sub-int/2addr v1, v2

    .line 296
    iput v1, v0, Lau0/c;->e:I

    .line 297
    .line 298
    goto :goto_a

    .line 299
    :cond_10
    new-instance v0, Lau0/c;

    .line 300
    .line 301
    invoke-direct {v0, p0, p2}, Lau0/c;-><init>(Lau0/d;Lkotlin/coroutines/Continuation;)V

    .line 302
    .line 303
    .line 304
    :goto_a
    iget-object p2, v0, Lau0/c;->d:Ljava/lang/Object;

    .line 305
    .line 306
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 307
    .line 308
    iget v2, v0, Lau0/c;->e:I

    .line 309
    .line 310
    const/4 v3, 0x1

    .line 311
    if-eqz v2, :cond_12

    .line 312
    .line 313
    if-ne v2, v3, :cond_11

    .line 314
    .line 315
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 316
    .line 317
    .line 318
    goto :goto_b

    .line 319
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 320
    .line 321
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 322
    .line 323
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 324
    .line 325
    .line 326
    throw p0

    .line 327
    :cond_12
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 328
    .line 329
    .line 330
    move-object p2, p1

    .line 331
    check-cast p2, Lau0/l;

    .line 332
    .line 333
    iget-object p2, p2, Lau0/l;->a:Ljava/lang/String;

    .line 334
    .line 335
    iget-object v2, p0, Lau0/d;->f:Ljava/lang/String;

    .line 336
    .line 337
    invoke-virtual {p2, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result p2

    .line 341
    if-eqz p2, :cond_13

    .line 342
    .line 343
    iput v3, v0, Lau0/c;->e:I

    .line 344
    .line 345
    iget-object p0, p0, Lau0/d;->e:Lyy0/j;

    .line 346
    .line 347
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 348
    .line 349
    .line 350
    move-result-object p0

    .line 351
    if-ne p0, v1, :cond_13

    .line 352
    .line 353
    goto :goto_c

    .line 354
    :cond_13
    :goto_b
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 355
    .line 356
    :goto_c
    return-object v1

    .line 357
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
