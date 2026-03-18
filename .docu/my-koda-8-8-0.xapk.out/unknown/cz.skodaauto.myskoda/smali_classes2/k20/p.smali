.class public final Lk20/p;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lk20/q;

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Lk20/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lk20/p;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lk20/p;->f:Lk20/q;

    .line 4
    .line 5
    iput-object p2, p0, Lk20/p;->g:Ljava/lang/String;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget p1, p0, Lk20/p;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lk20/p;

    .line 7
    .line 8
    iget-object v0, p0, Lk20/p;->g:Ljava/lang/String;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lk20/p;->f:Lk20/q;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lk20/p;-><init>(Lk20/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lk20/p;

    .line 18
    .line 19
    iget-object v0, p0, Lk20/p;->g:Ljava/lang/String;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lk20/p;->f:Lk20/q;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lk20/p;-><init>(Lk20/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lk20/p;->d:I

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
    invoke-virtual {p0, p1, p2}, Lk20/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lk20/p;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lk20/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lk20/p;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lk20/p;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lk20/p;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lk20/p;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lk20/p;->f:Lk20/q;

    .line 7
    .line 8
    iget-object v1, v0, Lk20/q;->t:Lij0/a;

    .line 9
    .line 10
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v3, p0, Lk20/p;->e:I

    .line 13
    .line 14
    iget-object v4, p0, Lk20/p;->g:Ljava/lang/String;

    .line 15
    .line 16
    const/4 v5, 0x1

    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    if-ne v3, v5, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, v0, Lk20/q;->n:Lkf0/i;

    .line 37
    .line 38
    iput v5, p0, Lk20/p;->e:I

    .line 39
    .line 40
    invoke-virtual {p1, v4, p0}, Lkf0/i;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    if-ne p1, v2, :cond_2

    .line 45
    .line 46
    goto/16 :goto_4

    .line 47
    .line 48
    :cond_2
    :goto_0
    check-cast p1, Lss0/k;

    .line 49
    .line 50
    const/4 p0, 0x0

    .line 51
    if-eqz p1, :cond_5

    .line 52
    .line 53
    iget-object v2, p1, Lss0/k;->d:Lss0/m;

    .line 54
    .line 55
    sget-object v3, Lss0/m;->d:Lss0/m;

    .line 56
    .line 57
    if-eq v2, v3, :cond_3

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    move-object v3, v2

    .line 65
    check-cast v3, Lk20/o;

    .line 66
    .line 67
    new-array v2, p0, [Ljava/lang/Object;

    .line 68
    .line 69
    move-object v4, v1

    .line 70
    check-cast v4, Ljj0/f;

    .line 71
    .line 72
    const v5, 0x7f1202a7

    .line 73
    .line 74
    .line 75
    invoke-virtual {v4, v5, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    iget-object p1, p1, Lss0/k;->b:Ljava/lang/String;

    .line 80
    .line 81
    if-nez p1, :cond_4

    .line 82
    .line 83
    new-array p0, p0, [Ljava/lang/Object;

    .line 84
    .line 85
    move-object p1, v1

    .line 86
    check-cast p1, Ljj0/f;

    .line 87
    .line 88
    const v2, 0x7f12029a

    .line 89
    .line 90
    .line 91
    invoke-virtual {p1, v2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    :cond_4
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast v1, Ljj0/f;

    .line 100
    .line 101
    const p1, 0x7f1202a6

    .line 102
    .line 103
    .line 104
    invoke-virtual {v1, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    const/4 v10, 0x0

    .line 109
    const/16 v11, 0x47

    .line 110
    .line 111
    const/4 v4, 0x0

    .line 112
    const/4 v5, 0x0

    .line 113
    const/4 v6, 0x0

    .line 114
    const/4 v7, 0x1

    .line 115
    invoke-static/range {v3 .. v11}, Lk20/o;->a(Lk20/o;Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Lj20/h;I)Lk20/o;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    invoke-virtual {v0, p0}, Lql0/j;->g(Lql0/h;)V

    .line 120
    .line 121
    .line 122
    goto/16 :goto_3

    .line 123
    .line 124
    :cond_5
    :goto_1
    iget-object p1, v0, Lk20/q;->i:Lkf0/a;

    .line 125
    .line 126
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 127
    .line 128
    .line 129
    invoke-static {v4}, Lkf0/a;->a(Ljava/lang/String;)Llf0/j;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    const/4 v2, 0x3

    .line 138
    if-eqz p1, :cond_9

    .line 139
    .line 140
    if-eq p1, v5, :cond_8

    .line 141
    .line 142
    const/4 v3, 0x2

    .line 143
    if-eq p1, v3, :cond_7

    .line 144
    .line 145
    if-eq p1, v2, :cond_8

    .line 146
    .line 147
    const/4 v2, 0x4

    .line 148
    if-ne p1, v2, :cond_6

    .line 149
    .line 150
    goto :goto_2

    .line 151
    :cond_6
    new-instance p0, La8/r0;

    .line 152
    .line 153
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 154
    .line 155
    .line 156
    throw p0

    .line 157
    :cond_7
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    move-object v2, p1

    .line 162
    check-cast v2, Lk20/o;

    .line 163
    .line 164
    new-array p0, p0, [Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v1, Ljj0/f;

    .line 167
    .line 168
    const p1, 0x7f1202a5

    .line 169
    .line 170
    .line 171
    invoke-virtual {v1, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    move-result-object v4

    .line 175
    const/4 v9, 0x0

    .line 176
    const/16 v10, 0x7d

    .line 177
    .line 178
    const/4 v3, 0x0

    .line 179
    const/4 v5, 0x0

    .line 180
    const/4 v6, 0x0

    .line 181
    const/4 v7, 0x0

    .line 182
    const/4 v8, 0x0

    .line 183
    invoke-static/range {v2 .. v10}, Lk20/o;->a(Lk20/o;Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Lj20/h;I)Lk20/o;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    invoke-virtual {v0, p0}, Lql0/j;->g(Lql0/h;)V

    .line 188
    .line 189
    .line 190
    goto :goto_3

    .line 191
    :cond_8
    :goto_2
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    move-object v2, p1

    .line 196
    check-cast v2, Lk20/o;

    .line 197
    .line 198
    new-array p0, p0, [Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v1, Ljj0/f;

    .line 201
    .line 202
    const p1, 0x7f1202a8

    .line 203
    .line 204
    .line 205
    invoke-virtual {v1, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object v4

    .line 209
    const/4 v9, 0x0

    .line 210
    const/16 v10, 0x7d

    .line 211
    .line 212
    const/4 v3, 0x0

    .line 213
    const/4 v5, 0x0

    .line 214
    const/4 v6, 0x0

    .line 215
    const/4 v7, 0x0

    .line 216
    const/4 v8, 0x0

    .line 217
    invoke-static/range {v2 .. v10}, Lk20/o;->a(Lk20/o;Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;Ljava/lang/String;Lj20/h;I)Lk20/o;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-virtual {v0, p0}, Lql0/j;->g(Lql0/h;)V

    .line 222
    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_9
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    new-instance p1, Lk20/p;

    .line 230
    .line 231
    const/4 v1, 0x0

    .line 232
    const/4 v3, 0x0

    .line 233
    invoke-direct {p1, v0, v4, v3, v1}, Lk20/p;-><init>(Lk20/q;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 234
    .line 235
    .line 236
    invoke-static {p0, v3, v3, p1, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 237
    .line 238
    .line 239
    :goto_3
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    :goto_4
    return-object v2

    .line 242
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 243
    .line 244
    iget v1, p0, Lk20/p;->e:I

    .line 245
    .line 246
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 247
    .line 248
    const/4 v3, 0x1

    .line 249
    if-eqz v1, :cond_b

    .line 250
    .line 251
    if-ne v1, v3, :cond_a

    .line 252
    .line 253
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    goto :goto_6

    .line 257
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 258
    .line 259
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 260
    .line 261
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw p0

    .line 265
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iget-object p1, p0, Lk20/p;->f:Lk20/q;

    .line 269
    .line 270
    iget-object v1, p1, Lk20/q;->h:Li20/t;

    .line 271
    .line 272
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    iget-object v4, v1, Li20/t;->a:Lkf0/f;

    .line 276
    .line 277
    iget-object v5, p0, Lk20/p;->g:Ljava/lang/String;

    .line 278
    .line 279
    invoke-virtual {v4, v5}, Lkf0/f;->a(Ljava/lang/String;)Lyy0/i;

    .line 280
    .line 281
    .line 282
    move-result-object v4

    .line 283
    new-instance v6, Laa/s;

    .line 284
    .line 285
    const/4 v7, 0x0

    .line 286
    const/16 v8, 0x9

    .line 287
    .line 288
    invoke-direct {v6, v8, v1, v5, v7}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 289
    .line 290
    .line 291
    new-instance v1, Lh50/y0;

    .line 292
    .line 293
    const/4 v5, 0x4

    .line 294
    invoke-direct {v1, p1, v5}, Lh50/y0;-><init>(Ljava/lang/Object;I)V

    .line 295
    .line 296
    .line 297
    iput v3, p0, Lk20/p;->e:I

    .line 298
    .line 299
    new-instance p1, Lcn0/e;

    .line 300
    .line 301
    const/4 v3, 0x5

    .line 302
    invoke-direct {p1, v1, v6, v3}, Lcn0/e;-><init>(Lyy0/j;Lay0/n;I)V

    .line 303
    .line 304
    .line 305
    invoke-interface {v4, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object p0

    .line 309
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 310
    .line 311
    if-ne p0, p1, :cond_c

    .line 312
    .line 313
    goto :goto_5

    .line 314
    :cond_c
    move-object p0, v2

    .line 315
    :goto_5
    if-ne p0, v0, :cond_d

    .line 316
    .line 317
    goto :goto_7

    .line 318
    :cond_d
    :goto_6
    move-object v0, v2

    .line 319
    :goto_7
    return-object v0

    .line 320
    nop

    .line 321
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
