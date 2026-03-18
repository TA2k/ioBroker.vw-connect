.class public final Lzi0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lzi0/d;


# direct methods
.method public synthetic constructor <init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lzi0/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lzi0/a;->f:Lzi0/d;

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
    iget p1, p0, Lzi0/a;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lzi0/a;

    .line 7
    .line 8
    iget-object p0, p0, Lzi0/a;->f:Lzi0/d;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lzi0/a;

    .line 16
    .line 17
    iget-object p0, p0, Lzi0/a;->f:Lzi0/d;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lzi0/a;

    .line 25
    .line 26
    iget-object p0, p0, Lzi0/a;->f:Lzi0/d;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lzi0/a;

    .line 34
    .line 35
    iget-object p0, p0, Lzi0/a;->f:Lzi0/d;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lzi0/a;->d:I

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
    invoke-virtual {p0, p1, p2}, Lzi0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lzi0/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lzi0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lzi0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lzi0/a;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lzi0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lzi0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lzi0/a;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lzi0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lzi0/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lzi0/a;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lzi0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lzi0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lzi0/a;->e:I

    .line 9
    .line 10
    iget-object v2, p0, Lzi0/a;->f:Lzi0/d;

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v3, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v2, Lzi0/d;->j:Lcs0/j0;

    .line 33
    .line 34
    new-instance v1, Lds0/c;

    .line 35
    .line 36
    invoke-direct {v1}, Lds0/c;-><init>()V

    .line 37
    .line 38
    .line 39
    iput v3, p0, Lzi0/a;->e:I

    .line 40
    .line 41
    invoke-virtual {p1, v1, p0}, Lcs0/j0;->b(Lds0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-ne p0, v0, :cond_2

    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    :goto_0
    invoke-virtual {v2}, Lzi0/d;->j()V

    .line 49
    .line 50
    .line 51
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    :goto_1
    return-object v0

    .line 54
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 55
    .line 56
    iget v1, p0, Lzi0/a;->e:I

    .line 57
    .line 58
    iget-object v2, p0, Lzi0/a;->f:Lzi0/d;

    .line 59
    .line 60
    const/4 v3, 0x2

    .line 61
    const/4 v4, 0x1

    .line 62
    if-eqz v1, :cond_5

    .line 63
    .line 64
    if-eq v1, v4, :cond_4

    .line 65
    .line 66
    if-ne v1, v3, :cond_3

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0

    .line 80
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-object p1, v2, Lzi0/d;->j:Lcs0/j0;

    .line 88
    .line 89
    new-instance v1, Lds0/a;

    .line 90
    .line 91
    invoke-direct {v1}, Lds0/a;-><init>()V

    .line 92
    .line 93
    .line 94
    iput v4, p0, Lzi0/a;->e:I

    .line 95
    .line 96
    invoke-virtual {p1, v1, p0}, Lcs0/j0;->b(Lds0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    if-ne p1, v0, :cond_6

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_6
    :goto_2
    iput v3, p0, Lzi0/a;->e:I

    .line 104
    .line 105
    invoke-static {v2, p0}, Lzi0/d;->h(Lzi0/d;Lrx0/c;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-ne p0, v0, :cond_7

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    :goto_4
    return-object v0

    .line 115
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 116
    .line 117
    iget v1, p0, Lzi0/a;->e:I

    .line 118
    .line 119
    iget-object v2, p0, Lzi0/a;->f:Lzi0/d;

    .line 120
    .line 121
    const/4 v3, 0x1

    .line 122
    if-eqz v1, :cond_9

    .line 123
    .line 124
    if-ne v1, v3, :cond_8

    .line 125
    .line 126
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    goto :goto_5

    .line 130
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 133
    .line 134
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iget-object p1, v2, Lzi0/d;->k:Lwi0/d;

    .line 142
    .line 143
    iput v3, p0, Lzi0/a;->e:I

    .line 144
    .line 145
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    invoke-virtual {p1, p0}, Lwi0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    if-ne p1, v0, :cond_a

    .line 153
    .line 154
    goto :goto_6

    .line 155
    :cond_a
    :goto_5
    check-cast p1, Ljava/lang/String;

    .line 156
    .line 157
    invoke-virtual {v2}, Lql0/j;->a()Lql0/h;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    check-cast p0, Lzi0/b;

    .line 162
    .line 163
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 164
    .line 165
    .line 166
    const-string p0, "link"

    .line 167
    .line 168
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    new-instance p0, Lzi0/b;

    .line 172
    .line 173
    invoke-direct {p0, v3, p1}, Lzi0/b;-><init>(ZLjava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-virtual {v2, p0}, Lql0/j;->g(Lql0/h;)V

    .line 177
    .line 178
    .line 179
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 180
    .line 181
    :goto_6
    return-object v0

    .line 182
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 183
    .line 184
    iget v1, p0, Lzi0/a;->e:I

    .line 185
    .line 186
    const/4 v2, 0x4

    .line 187
    const/4 v3, 0x3

    .line 188
    const/4 v4, 0x2

    .line 189
    const/4 v5, 0x1

    .line 190
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 191
    .line 192
    iget-object v7, p0, Lzi0/a;->f:Lzi0/d;

    .line 193
    .line 194
    if-eqz v1, :cond_10

    .line 195
    .line 196
    if-eq v1, v5, :cond_f

    .line 197
    .line 198
    if-eq v1, v4, :cond_e

    .line 199
    .line 200
    if-eq v1, v3, :cond_d

    .line 201
    .line 202
    if-ne v1, v2, :cond_c

    .line 203
    .line 204
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    :cond_b
    :goto_7
    move-object v0, v6

    .line 208
    goto/16 :goto_b

    .line 209
    .line 210
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 211
    .line 212
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 213
    .line 214
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    throw p0

    .line 218
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 219
    .line 220
    .line 221
    goto :goto_a

    .line 222
    :cond_e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    goto :goto_9

    .line 226
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    goto :goto_8

    .line 230
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    iget-object p1, v7, Lzi0/d;->h:Lwi0/p;

    .line 234
    .line 235
    iput v5, p0, Lzi0/a;->e:I

    .line 236
    .line 237
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 238
    .line 239
    .line 240
    invoke-virtual {p1, p0}, Lwi0/p;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    if-ne p1, v0, :cond_11

    .line 245
    .line 246
    goto :goto_b

    .line 247
    :cond_11
    :goto_8
    iget-object p1, v7, Lzi0/d;->o:Lwi0/f;

    .line 248
    .line 249
    iput v4, p0, Lzi0/a;->e:I

    .line 250
    .line 251
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 252
    .line 253
    .line 254
    invoke-virtual {p1, p0}, Lwi0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    if-ne p1, v0, :cond_12

    .line 259
    .line 260
    goto :goto_b

    .line 261
    :cond_12
    :goto_9
    check-cast p1, Ljava/lang/Boolean;

    .line 262
    .line 263
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 264
    .line 265
    .line 266
    move-result p1

    .line 267
    if-eqz p1, :cond_13

    .line 268
    .line 269
    invoke-static {v7}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 270
    .line 271
    .line 272
    move-result-object p0

    .line 273
    new-instance p1, Lzi0/a;

    .line 274
    .line 275
    const/4 v0, 0x1

    .line 276
    const/4 v1, 0x0

    .line 277
    invoke-direct {p1, v7, v1, v0}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 278
    .line 279
    .line 280
    invoke-static {p0, v1, v1, p1, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 281
    .line 282
    .line 283
    goto :goto_7

    .line 284
    :cond_13
    iget-object p1, v7, Lzi0/d;->i:Lcs0/i;

    .line 285
    .line 286
    iput v3, p0, Lzi0/a;->e:I

    .line 287
    .line 288
    invoke-virtual {p1, v6, p0}, Lcs0/i;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object p1

    .line 292
    if-ne p1, v0, :cond_14

    .line 293
    .line 294
    goto :goto_b

    .line 295
    :cond_14
    :goto_a
    check-cast p1, Lds0/b;

    .line 296
    .line 297
    instance-of v1, p1, Lds0/a;

    .line 298
    .line 299
    if-eqz v1, :cond_15

    .line 300
    .line 301
    iput v2, p0, Lzi0/a;->e:I

    .line 302
    .line 303
    invoke-static {v7, p0}, Lzi0/d;->h(Lzi0/d;Lrx0/c;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object p0

    .line 307
    if-ne p0, v0, :cond_b

    .line 308
    .line 309
    goto :goto_b

    .line 310
    :cond_15
    instance-of p0, p1, Lds0/c;

    .line 311
    .line 312
    if-eqz p0, :cond_16

    .line 313
    .line 314
    invoke-virtual {v7}, Lzi0/d;->j()V

    .line 315
    .line 316
    .line 317
    goto :goto_7

    .line 318
    :cond_16
    if-nez p1, :cond_17

    .line 319
    .line 320
    goto :goto_7

    .line 321
    :goto_b
    return-object v0

    .line 322
    :cond_17
    new-instance p0, La8/r0;

    .line 323
    .line 324
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 325
    .line 326
    .line 327
    throw p0

    .line 328
    nop

    .line 329
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
