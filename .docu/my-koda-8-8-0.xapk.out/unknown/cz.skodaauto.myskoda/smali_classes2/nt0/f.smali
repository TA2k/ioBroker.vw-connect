.class public final Lnt0/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Lyy0/j;

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lnt0/i;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V
    .locals 0

    .line 1
    iput p1, p0, Lnt0/f;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnt0/f;->h:Lnt0/i;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lnt0/f;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    new-instance v0, Lnt0/f;

    .line 11
    .line 12
    iget-object p0, p0, Lnt0/f;->h:Lnt0/i;

    .line 13
    .line 14
    const/4 v1, 0x3

    .line 15
    invoke-direct {v0, v1, p3, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 16
    .line 17
    .line 18
    iput-object p1, v0, Lnt0/f;->f:Lyy0/j;

    .line 19
    .line 20
    iput-object p2, v0, Lnt0/f;->g:Ljava/lang/Object;

    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    invoke-virtual {v0, p0}, Lnt0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :pswitch_0
    new-instance v0, Lnt0/f;

    .line 30
    .line 31
    iget-object p0, p0, Lnt0/f;->h:Lnt0/i;

    .line 32
    .line 33
    const/4 v1, 0x2

    .line 34
    invoke-direct {v0, v1, p3, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 35
    .line 36
    .line 37
    iput-object p1, v0, Lnt0/f;->f:Lyy0/j;

    .line 38
    .line 39
    iput-object p2, v0, Lnt0/f;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    invoke-virtual {v0, p0}, Lnt0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    return-object p0

    .line 48
    :pswitch_1
    new-instance v0, Lnt0/f;

    .line 49
    .line 50
    iget-object p0, p0, Lnt0/f;->h:Lnt0/i;

    .line 51
    .line 52
    const/4 v1, 0x1

    .line 53
    invoke-direct {v0, v1, p3, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 54
    .line 55
    .line 56
    iput-object p1, v0, Lnt0/f;->f:Lyy0/j;

    .line 57
    .line 58
    iput-object p2, v0, Lnt0/f;->g:Ljava/lang/Object;

    .line 59
    .line 60
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 61
    .line 62
    invoke-virtual {v0, p0}, Lnt0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :pswitch_2
    new-instance v0, Lnt0/f;

    .line 68
    .line 69
    iget-object p0, p0, Lnt0/f;->h:Lnt0/i;

    .line 70
    .line 71
    const/4 v1, 0x0

    .line 72
    invoke-direct {v0, v1, p3, p0}, Lnt0/f;-><init>(ILkotlin/coroutines/Continuation;Lnt0/i;)V

    .line 73
    .line 74
    .line 75
    iput-object p1, v0, Lnt0/f;->f:Lyy0/j;

    .line 76
    .line 77
    iput-object p2, v0, Lnt0/f;->g:Ljava/lang/Object;

    .line 78
    .line 79
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    invoke-virtual {v0, p0}, Lnt0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lnt0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lnt0/f;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lnt0/f;->f:Lyy0/j;

    .line 31
    .line 32
    iget-object v1, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lne0/t;

    .line 35
    .line 36
    instance-of v3, v1, Lne0/e;

    .line 37
    .line 38
    if-eqz v3, :cond_2

    .line 39
    .line 40
    check-cast v1, Lne0/e;

    .line 41
    .line 42
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Lss0/k;

    .line 45
    .line 46
    iget-object v3, p0, Lnt0/f;->h:Lnt0/i;

    .line 47
    .line 48
    iget-object v3, v3, Lnt0/i;->i:Llt0/a;

    .line 49
    .line 50
    iget-object v1, v1, Lss0/k;->a:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {v3, v1}, Llt0/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    instance-of v3, v1, Lne0/c;

    .line 58
    .line 59
    if-eqz v3, :cond_4

    .line 60
    .line 61
    new-instance v3, Lyy0/m;

    .line 62
    .line 63
    const/4 v4, 0x0

    .line 64
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 65
    .line 66
    .line 67
    move-object v1, v3

    .line 68
    :goto_0
    const/4 v3, 0x0

    .line 69
    iput-object v3, p0, Lnt0/f;->f:Lyy0/j;

    .line 70
    .line 71
    iput-object v3, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 72
    .line 73
    iput v2, p0, Lnt0/f;->e:I

    .line 74
    .line 75
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    if-ne p0, v0, :cond_3

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    :goto_2
    return-object v0

    .line 85
    :cond_4
    new-instance p0, La8/r0;

    .line 86
    .line 87
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 92
    .line 93
    iget v1, p0, Lnt0/f;->e:I

    .line 94
    .line 95
    const/4 v2, 0x1

    .line 96
    if-eqz v1, :cond_6

    .line 97
    .line 98
    if-ne v1, v2, :cond_5

    .line 99
    .line 100
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_4

    .line 104
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 105
    .line 106
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 107
    .line 108
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    throw p0

    .line 112
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    iget-object p1, p0, Lnt0/f;->f:Lyy0/j;

    .line 116
    .line 117
    iget-object v1, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 118
    .line 119
    check-cast v1, Lne0/t;

    .line 120
    .line 121
    instance-of v3, v1, Lne0/e;

    .line 122
    .line 123
    if-eqz v3, :cond_7

    .line 124
    .line 125
    check-cast v1, Lne0/e;

    .line 126
    .line 127
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast v1, Lss0/u;

    .line 130
    .line 131
    iget-object v3, p0, Lnt0/f;->h:Lnt0/i;

    .line 132
    .line 133
    iget-object v3, v3, Lnt0/i;->h:Llt0/b;

    .line 134
    .line 135
    iget-object v1, v1, Lss0/u;->a:Ljava/lang/String;

    .line 136
    .line 137
    invoke-virtual {v3, v1}, Llt0/b;->a(Ljava/lang/String;)Lyy0/i;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    goto :goto_3

    .line 142
    :cond_7
    instance-of v3, v1, Lne0/c;

    .line 143
    .line 144
    if-eqz v3, :cond_9

    .line 145
    .line 146
    new-instance v3, Lyy0/m;

    .line 147
    .line 148
    const/4 v4, 0x0

    .line 149
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 150
    .line 151
    .line 152
    move-object v1, v3

    .line 153
    :goto_3
    const/4 v3, 0x0

    .line 154
    iput-object v3, p0, Lnt0/f;->f:Lyy0/j;

    .line 155
    .line 156
    iput-object v3, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 157
    .line 158
    iput v2, p0, Lnt0/f;->e:I

    .line 159
    .line 160
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-ne p0, v0, :cond_8

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 168
    .line 169
    :goto_5
    return-object v0

    .line 170
    :cond_9
    new-instance p0, La8/r0;

    .line 171
    .line 172
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 173
    .line 174
    .line 175
    throw p0

    .line 176
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 177
    .line 178
    iget v1, p0, Lnt0/f;->e:I

    .line 179
    .line 180
    const/4 v2, 0x1

    .line 181
    if-eqz v1, :cond_b

    .line 182
    .line 183
    if-ne v1, v2, :cond_a

    .line 184
    .line 185
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    goto :goto_7

    .line 189
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 190
    .line 191
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 192
    .line 193
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    throw p0

    .line 197
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 198
    .line 199
    .line 200
    iget-object p1, p0, Lnt0/f;->f:Lyy0/j;

    .line 201
    .line 202
    iget-object v1, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v1, Lne0/t;

    .line 205
    .line 206
    instance-of v3, v1, Lne0/e;

    .line 207
    .line 208
    if-eqz v3, :cond_c

    .line 209
    .line 210
    check-cast v1, Lne0/e;

    .line 211
    .line 212
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v1, Lss0/u;

    .line 215
    .line 216
    iget-object v3, p0, Lnt0/f;->h:Lnt0/i;

    .line 217
    .line 218
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    move-object v5, v4

    .line 223
    check-cast v5, Lnt0/e;

    .line 224
    .line 225
    iget-object v10, v1, Lss0/u;->b:Ljava/lang/String;

    .line 226
    .line 227
    const/4 v12, 0x0

    .line 228
    const/16 v13, 0x6f

    .line 229
    .line 230
    const/4 v6, 0x0

    .line 231
    const/4 v7, 0x0

    .line 232
    const/4 v8, 0x0

    .line 233
    const/4 v9, 0x0

    .line 234
    const/4 v11, 0x0

    .line 235
    invoke-static/range {v5 .. v13}, Lnt0/e;->a(Lnt0/e;Lql0/g;ZZZLjava/lang/String;Ljava/util/List;ZI)Lnt0/e;

    .line 236
    .line 237
    .line 238
    move-result-object v4

    .line 239
    invoke-virtual {v3, v4}, Lql0/j;->g(Lql0/h;)V

    .line 240
    .line 241
    .line 242
    iget-object v3, v3, Lnt0/i;->h:Llt0/b;

    .line 243
    .line 244
    iget-object v1, v1, Lss0/u;->a:Ljava/lang/String;

    .line 245
    .line 246
    invoke-virtual {v3, v1}, Llt0/b;->a(Ljava/lang/String;)Lyy0/i;

    .line 247
    .line 248
    .line 249
    move-result-object v1

    .line 250
    goto :goto_6

    .line 251
    :cond_c
    instance-of v3, v1, Lne0/c;

    .line 252
    .line 253
    if-eqz v3, :cond_e

    .line 254
    .line 255
    new-instance v3, Lyy0/m;

    .line 256
    .line 257
    const/4 v4, 0x0

    .line 258
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 259
    .line 260
    .line 261
    move-object v1, v3

    .line 262
    :goto_6
    const/4 v3, 0x0

    .line 263
    iput-object v3, p0, Lnt0/f;->f:Lyy0/j;

    .line 264
    .line 265
    iput-object v3, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 266
    .line 267
    iput v2, p0, Lnt0/f;->e:I

    .line 268
    .line 269
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object p0

    .line 273
    if-ne p0, v0, :cond_d

    .line 274
    .line 275
    goto :goto_8

    .line 276
    :cond_d
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 277
    .line 278
    :goto_8
    return-object v0

    .line 279
    :cond_e
    new-instance p0, La8/r0;

    .line 280
    .line 281
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 282
    .line 283
    .line 284
    throw p0

    .line 285
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 286
    .line 287
    iget v1, p0, Lnt0/f;->e:I

    .line 288
    .line 289
    const/4 v2, 0x1

    .line 290
    if-eqz v1, :cond_10

    .line 291
    .line 292
    if-ne v1, v2, :cond_f

    .line 293
    .line 294
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 295
    .line 296
    .line 297
    goto :goto_a

    .line 298
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 299
    .line 300
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 301
    .line 302
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 303
    .line 304
    .line 305
    throw p0

    .line 306
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    iget-object p1, p0, Lnt0/f;->f:Lyy0/j;

    .line 310
    .line 311
    iget-object v1, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 312
    .line 313
    check-cast v1, Lne0/t;

    .line 314
    .line 315
    instance-of v3, v1, Lne0/e;

    .line 316
    .line 317
    if-eqz v3, :cond_11

    .line 318
    .line 319
    check-cast v1, Lne0/e;

    .line 320
    .line 321
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v1, Lss0/k;

    .line 324
    .line 325
    iget-object v3, p0, Lnt0/f;->h:Lnt0/i;

    .line 326
    .line 327
    iget-object v3, v3, Lnt0/i;->i:Llt0/a;

    .line 328
    .line 329
    iget-object v1, v1, Lss0/k;->a:Ljava/lang/String;

    .line 330
    .line 331
    invoke-virtual {v3, v1}, Llt0/a;->a(Ljava/lang/String;)Lyy0/i;

    .line 332
    .line 333
    .line 334
    move-result-object v1

    .line 335
    goto :goto_9

    .line 336
    :cond_11
    instance-of v3, v1, Lne0/c;

    .line 337
    .line 338
    if-eqz v3, :cond_13

    .line 339
    .line 340
    new-instance v3, Lyy0/m;

    .line 341
    .line 342
    const/4 v4, 0x0

    .line 343
    invoke-direct {v3, v1, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 344
    .line 345
    .line 346
    move-object v1, v3

    .line 347
    :goto_9
    const/4 v3, 0x0

    .line 348
    iput-object v3, p0, Lnt0/f;->f:Lyy0/j;

    .line 349
    .line 350
    iput-object v3, p0, Lnt0/f;->g:Ljava/lang/Object;

    .line 351
    .line 352
    iput v2, p0, Lnt0/f;->e:I

    .line 353
    .line 354
    invoke-static {p1, v1, p0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object p0

    .line 358
    if-ne p0, v0, :cond_12

    .line 359
    .line 360
    goto :goto_b

    .line 361
    :cond_12
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 362
    .line 363
    :goto_b
    return-object v0

    .line 364
    :cond_13
    new-instance p0, La8/r0;

    .line 365
    .line 366
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 367
    .line 368
    .line 369
    throw p0

    .line 370
    nop

    .line 371
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
