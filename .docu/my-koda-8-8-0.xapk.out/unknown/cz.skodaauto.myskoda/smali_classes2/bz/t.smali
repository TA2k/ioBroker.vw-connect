.class public final Lbz/t;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lbz/w;


# direct methods
.method public synthetic constructor <init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbz/t;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbz/t;->f:Lbz/w;

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
    iget p1, p0, Lbz/t;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lbz/t;

    .line 7
    .line 8
    iget-object p0, p0, Lbz/t;->f:Lbz/w;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lbz/t;

    .line 16
    .line 17
    iget-object p0, p0, Lbz/t;->f:Lbz/w;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lbz/t;

    .line 25
    .line 26
    iget-object p0, p0, Lbz/t;->f:Lbz/w;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lbz/t;

    .line 34
    .line 35
    iget-object p0, p0, Lbz/t;->f:Lbz/w;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lbz/t;

    .line 43
    .line 44
    iget-object p0, p0, Lbz/t;->f:Lbz/w;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lbz/t;-><init>(Lbz/w;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lbz/t;->d:I

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
    invoke-virtual {p0, p1, p2}, Lbz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lbz/t;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lbz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lbz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lbz/t;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lbz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lbz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lbz/t;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lbz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lbz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lbz/t;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lbz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lbz/t;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lbz/t;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lbz/t;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lbz/t;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 7
    .line 8
    const/4 v4, 0x1

    .line 9
    iget-object v5, p0, Lbz/t;->f:Lbz/w;

    .line 10
    .line 11
    packed-switch v0, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    iget v6, p0, Lbz/t;->e:I

    .line 17
    .line 18
    if-eqz v6, :cond_2

    .line 19
    .line 20
    if-eq v6, v4, :cond_1

    .line 21
    .line 22
    if-ne v6, v1, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_2

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, v5, Lbz/w;->l:Lgl0/e;

    .line 42
    .line 43
    sget-object v3, Lbz/w;->r:Lhl0/b;

    .line 44
    .line 45
    iput v4, p0, Lbz/t;->e:I

    .line 46
    .line 47
    invoke-virtual {p1, v3, p0}, Lgl0/e;->b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    if-ne p1, v0, :cond_3

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    :goto_0
    check-cast p1, Lhl0/i;

    .line 55
    .line 56
    if-eqz p1, :cond_4

    .line 57
    .line 58
    sget-object v3, Lbz/w;->r:Lhl0/b;

    .line 59
    .line 60
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    move-object v6, v3

    .line 65
    check-cast v6, Lbz/u;

    .line 66
    .line 67
    iget-object v3, v5, Lbz/w;->o:Lij0/a;

    .line 68
    .line 69
    invoke-static {p1, v3}, Ljp/pb;->b(Lhl0/i;Lij0/a;)Laz/d;

    .line 70
    .line 71
    .line 72
    move-result-object v7

    .line 73
    const/4 v10, 0x0

    .line 74
    const/16 v11, 0xe

    .line 75
    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v9, 0x0

    .line 78
    invoke-static/range {v6 .. v11}, Lbz/u;->a(Lbz/u;Laz/d;Laz/d;ZLjava/util/List;I)Lbz/u;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-virtual {v5, p1}, Lql0/j;->g(Lql0/h;)V

    .line 83
    .line 84
    .line 85
    iput v1, p0, Lbz/t;->e:I

    .line 86
    .line 87
    invoke-static {v5, p0}, Lbz/w;->h(Lbz/w;Lrx0/c;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-ne p0, v0, :cond_4

    .line 92
    .line 93
    :goto_1
    move-object v2, v0

    .line 94
    :cond_4
    :goto_2
    return-object v2

    .line 95
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v6, p0, Lbz/t;->e:I

    .line 98
    .line 99
    if-eqz v6, :cond_7

    .line 100
    .line 101
    if-eq v6, v4, :cond_6

    .line 102
    .line 103
    if-ne v6, v1, :cond_5

    .line 104
    .line 105
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    goto :goto_5

    .line 109
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    iget-object p1, v5, Lbz/w;->l:Lgl0/e;

    .line 123
    .line 124
    sget-object v3, Lbz/w;->r:Lhl0/b;

    .line 125
    .line 126
    iput v4, p0, Lbz/t;->e:I

    .line 127
    .line 128
    invoke-virtual {p1, v3, p0}, Lgl0/e;->b(Lhl0/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-ne p1, v0, :cond_8

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_8
    :goto_3
    check-cast p1, Lhl0/i;

    .line 136
    .line 137
    if-eqz p1, :cond_9

    .line 138
    .line 139
    sget-object v3, Lbz/w;->r:Lhl0/b;

    .line 140
    .line 141
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 142
    .line 143
    .line 144
    move-result-object v3

    .line 145
    move-object v6, v3

    .line 146
    check-cast v6, Lbz/u;

    .line 147
    .line 148
    iget-object v3, v5, Lbz/w;->o:Lij0/a;

    .line 149
    .line 150
    invoke-static {p1, v3}, Ljp/pb;->b(Lhl0/i;Lij0/a;)Laz/d;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    const/4 v10, 0x0

    .line 155
    const/16 v11, 0xd

    .line 156
    .line 157
    const/4 v7, 0x0

    .line 158
    const/4 v9, 0x0

    .line 159
    invoke-static/range {v6 .. v11}, Lbz/u;->a(Lbz/u;Laz/d;Laz/d;ZLjava/util/List;I)Lbz/u;

    .line 160
    .line 161
    .line 162
    move-result-object p1

    .line 163
    invoke-virtual {v5, p1}, Lql0/j;->g(Lql0/h;)V

    .line 164
    .line 165
    .line 166
    iput v1, p0, Lbz/t;->e:I

    .line 167
    .line 168
    invoke-static {v5, p0}, Lbz/w;->h(Lbz/w;Lrx0/c;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    if-ne p0, v0, :cond_9

    .line 173
    .line 174
    :goto_4
    move-object v2, v0

    .line 175
    :cond_9
    :goto_5
    return-object v2

    .line 176
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 177
    .line 178
    iget v1, p0, Lbz/t;->e:I

    .line 179
    .line 180
    if-eqz v1, :cond_b

    .line 181
    .line 182
    if-ne v1, v4, :cond_a

    .line 183
    .line 184
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    goto :goto_7

    .line 188
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 189
    .line 190
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw p0

    .line 194
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    sget-object p1, Lbz/w;->r:Lhl0/b;

    .line 198
    .line 199
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 200
    .line 201
    .line 202
    move-result-object p1

    .line 203
    check-cast p1, Lbz/u;

    .line 204
    .line 205
    iget-object p1, p1, Lbz/u;->a:Laz/d;

    .line 206
    .line 207
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Lbz/u;

    .line 212
    .line 213
    iget-object v1, v1, Lbz/u;->b:Laz/d;

    .line 214
    .line 215
    if-eqz p1, :cond_10

    .line 216
    .line 217
    if-eqz v1, :cond_10

    .line 218
    .line 219
    iget-object v6, v5, Lbz/w;->k:Lzy/i;

    .line 220
    .line 221
    iput v4, p0, Lbz/t;->e:I

    .line 222
    .line 223
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 224
    .line 225
    .line 226
    new-instance v7, Lzy/h;

    .line 227
    .line 228
    invoke-direct {v7, v6, p0}, Lzy/h;-><init>(Lzy/i;Lkotlin/coroutines/Continuation;)V

    .line 229
    .line 230
    .line 231
    iget-object p0, v7, Lzy/h;->d:Ljava/lang/Object;

    .line 232
    .line 233
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 234
    .line 235
    iget v9, v7, Lzy/h;->f:I

    .line 236
    .line 237
    if-eqz v9, :cond_e

    .line 238
    .line 239
    if-ne v9, v4, :cond_d

    .line 240
    .line 241
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    :cond_c
    move-object v8, v2

    .line 245
    goto :goto_6

    .line 246
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 247
    .line 248
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    throw p0

    .line 252
    :cond_e
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    iget-object p0, v6, Lzy/i;->a:Lxy/e;

    .line 256
    .line 257
    iput v4, v7, Lzy/h;->f:I

    .line 258
    .line 259
    iput-object p1, p0, Lxy/e;->b:Laz/d;

    .line 260
    .line 261
    iput-object v1, p0, Lxy/e;->c:Laz/d;

    .line 262
    .line 263
    if-ne v2, v8, :cond_c

    .line 264
    .line 265
    :goto_6
    if-ne v8, v0, :cond_f

    .line 266
    .line 267
    move-object v2, v0

    .line 268
    goto :goto_8

    .line 269
    :cond_f
    :goto_7
    iget-object p0, v5, Lbz/w;->n:Lzy/v;

    .line 270
    .line 271
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    :cond_10
    :goto_8
    return-object v2

    .line 275
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 276
    .line 277
    iget v1, p0, Lbz/t;->e:I

    .line 278
    .line 279
    if-eqz v1, :cond_12

    .line 280
    .line 281
    if-ne v1, v4, :cond_11

    .line 282
    .line 283
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 284
    .line 285
    .line 286
    goto :goto_a

    .line 287
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    throw p0

    .line 293
    :cond_12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 294
    .line 295
    .line 296
    iget-object p1, v5, Lbz/w;->m:Lzy/q;

    .line 297
    .line 298
    const/4 v1, 0x0

    .line 299
    invoke-virtual {p1, v1}, Lzy/q;->a(Z)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 303
    .line 304
    .line 305
    move-result-object p1

    .line 306
    check-cast p1, Lbz/u;

    .line 307
    .line 308
    iget-object p1, p1, Lbz/u;->a:Laz/d;

    .line 309
    .line 310
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 311
    .line 312
    .line 313
    move-result-object v1

    .line 314
    check-cast v1, Lbz/u;

    .line 315
    .line 316
    iget-object v1, v1, Lbz/u;->b:Laz/d;

    .line 317
    .line 318
    if-eqz p1, :cond_17

    .line 319
    .line 320
    if-eqz v1, :cond_17

    .line 321
    .line 322
    iget-object v6, v5, Lbz/w;->k:Lzy/i;

    .line 323
    .line 324
    iput v4, p0, Lbz/t;->e:I

    .line 325
    .line 326
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    new-instance v7, Lzy/h;

    .line 330
    .line 331
    invoke-direct {v7, v6, p0}, Lzy/h;-><init>(Lzy/i;Lkotlin/coroutines/Continuation;)V

    .line 332
    .line 333
    .line 334
    iget-object p0, v7, Lzy/h;->d:Ljava/lang/Object;

    .line 335
    .line 336
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 337
    .line 338
    iget v9, v7, Lzy/h;->f:I

    .line 339
    .line 340
    if-eqz v9, :cond_15

    .line 341
    .line 342
    if-ne v9, v4, :cond_14

    .line 343
    .line 344
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 345
    .line 346
    .line 347
    :cond_13
    move-object v8, v2

    .line 348
    goto :goto_9

    .line 349
    :cond_14
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 350
    .line 351
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 352
    .line 353
    .line 354
    throw p0

    .line 355
    :cond_15
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    iget-object p0, v6, Lzy/i;->a:Lxy/e;

    .line 359
    .line 360
    iput v4, v7, Lzy/h;->f:I

    .line 361
    .line 362
    iput-object p1, p0, Lxy/e;->b:Laz/d;

    .line 363
    .line 364
    iput-object v1, p0, Lxy/e;->c:Laz/d;

    .line 365
    .line 366
    if-ne v2, v8, :cond_13

    .line 367
    .line 368
    :goto_9
    if-ne v8, v0, :cond_16

    .line 369
    .line 370
    move-object v2, v0

    .line 371
    goto :goto_b

    .line 372
    :cond_16
    :goto_a
    iget-object p0, v5, Lbz/w;->j:Lzy/u;

    .line 373
    .line 374
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    :cond_17
    :goto_b
    return-object v2

    .line 378
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 379
    .line 380
    iget v1, p0, Lbz/t;->e:I

    .line 381
    .line 382
    if-eqz v1, :cond_19

    .line 383
    .line 384
    if-ne v1, v4, :cond_18

    .line 385
    .line 386
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 387
    .line 388
    .line 389
    goto :goto_c

    .line 390
    :cond_18
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 391
    .line 392
    invoke-direct {p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 393
    .line 394
    .line 395
    throw p0

    .line 396
    :cond_19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 397
    .line 398
    .line 399
    iput v4, p0, Lbz/t;->e:I

    .line 400
    .line 401
    invoke-static {v5, p0}, Lbz/w;->h(Lbz/w;Lrx0/c;)Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object p0

    .line 405
    if-ne p0, v0, :cond_1a

    .line 406
    .line 407
    move-object v2, v0

    .line 408
    :cond_1a
    :goto_c
    return-object v2

    .line 409
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
