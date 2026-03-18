.class public final Lct0/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lct0/h;


# direct methods
.method public synthetic constructor <init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lct0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lct0/b;->f:Lct0/h;

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
    iget p1, p0, Lct0/b;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lct0/b;

    .line 7
    .line 8
    iget-object p0, p0, Lct0/b;->f:Lct0/h;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lct0/b;

    .line 16
    .line 17
    iget-object p0, p0, Lct0/b;->f:Lct0/h;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lct0/b;

    .line 25
    .line 26
    iget-object p0, p0, Lct0/b;->f:Lct0/h;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lct0/b;

    .line 34
    .line 35
    iget-object p0, p0, Lct0/b;->f:Lct0/h;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lct0/b;

    .line 43
    .line 44
    iget-object p0, p0, Lct0/b;->f:Lct0/h;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lct0/b;-><init>(Lct0/h;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lct0/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lct0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lct0/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lct0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lct0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lct0/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lct0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lct0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lct0/b;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lct0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lct0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lct0/b;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lct0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lct0/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lct0/b;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lct0/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lct0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lct0/b;->e:I

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
    goto :goto_0

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
    iget-object p1, p0, Lct0/b;->f:Lct0/h;

    .line 31
    .line 32
    iget-object p1, p1, Lct0/h;->o:Lat0/n;

    .line 33
    .line 34
    new-instance v1, Lbt0/c;

    .line 35
    .line 36
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 37
    .line 38
    .line 39
    move-result-wide v3

    .line 40
    invoke-direct {v1, v3, v4}, Lbt0/c;-><init>(J)V

    .line 41
    .line 42
    .line 43
    iput v2, p0, Lct0/b;->e:I

    .line 44
    .line 45
    invoke-virtual {p1, v1, p0}, Lat0/n;->b(Lbt0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    if-ne p0, v0, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    :goto_1
    return-object v0

    .line 55
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    iget v1, p0, Lct0/b;->e:I

    .line 58
    .line 59
    const/4 v2, 0x1

    .line 60
    if-eqz v1, :cond_4

    .line 61
    .line 62
    if-ne v1, v2, :cond_3

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 71
    .line 72
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p0

    .line 76
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    iget-object p1, p0, Lct0/b;->f:Lct0/h;

    .line 80
    .line 81
    iget-object p1, p1, Lct0/h;->o:Lat0/n;

    .line 82
    .line 83
    new-instance v1, Lbt0/c;

    .line 84
    .line 85
    const-wide/16 v3, 0x0

    .line 86
    .line 87
    invoke-direct {v1, v3, v4}, Lbt0/c;-><init>(J)V

    .line 88
    .line 89
    .line 90
    iput v2, p0, Lct0/b;->e:I

    .line 91
    .line 92
    invoke-virtual {p1, v1, p0}, Lat0/n;->b(Lbt0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    if-ne p0, v0, :cond_5

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 100
    .line 101
    :goto_3
    return-object v0

    .line 102
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    iget v1, p0, Lct0/b;->e:I

    .line 105
    .line 106
    const/4 v2, 0x1

    .line 107
    if-eqz v1, :cond_7

    .line 108
    .line 109
    if-ne v1, v2, :cond_6

    .line 110
    .line 111
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 116
    .line 117
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    iget-object p1, p0, Lct0/b;->f:Lct0/h;

    .line 127
    .line 128
    iget-object v1, p1, Lct0/h;->j:Lat0/d;

    .line 129
    .line 130
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    check-cast v1, Lyy0/i;

    .line 135
    .line 136
    new-instance v3, La50/h;

    .line 137
    .line 138
    const/16 v4, 0x10

    .line 139
    .line 140
    invoke-direct {v3, v1, v4}, La50/h;-><init>(Lyy0/i;I)V

    .line 141
    .line 142
    .line 143
    new-instance v1, Lam0/i;

    .line 144
    .line 145
    const/4 v4, 0x1

    .line 146
    invoke-direct {v1, v3, v4}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 147
    .line 148
    .line 149
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    new-instance v3, Lbq0/a;

    .line 154
    .line 155
    const/4 v4, 0x3

    .line 156
    const/4 v5, 0x1

    .line 157
    const/4 v6, 0x0

    .line 158
    invoke-direct {v3, v4, v6, v5}, Lbq0/a;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    new-instance v3, Lct0/a;

    .line 166
    .line 167
    const/4 v4, 0x2

    .line 168
    invoke-direct {v3, p1, v4}, Lct0/a;-><init>(Lct0/h;I)V

    .line 169
    .line 170
    .line 171
    iput v2, p0, Lct0/b;->e:I

    .line 172
    .line 173
    invoke-virtual {v1, v3, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    if-ne p0, v0, :cond_8

    .line 178
    .line 179
    goto :goto_5

    .line 180
    :cond_8
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 181
    .line 182
    :goto_5
    return-object v0

    .line 183
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 184
    .line 185
    iget v1, p0, Lct0/b;->e:I

    .line 186
    .line 187
    const/4 v2, 0x1

    .line 188
    if-eqz v1, :cond_a

    .line 189
    .line 190
    if-ne v1, v2, :cond_9

    .line 191
    .line 192
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 193
    .line 194
    .line 195
    goto :goto_6

    .line 196
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 197
    .line 198
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 199
    .line 200
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 201
    .line 202
    .line 203
    throw p0

    .line 204
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    iget-object p1, p0, Lct0/b;->f:Lct0/h;

    .line 208
    .line 209
    iget-object v1, p1, Lct0/h;->j:Lat0/d;

    .line 210
    .line 211
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v1

    .line 215
    check-cast v1, Lyy0/i;

    .line 216
    .line 217
    new-instance v3, Lct0/a;

    .line 218
    .line 219
    const/4 v4, 0x1

    .line 220
    invoke-direct {v3, p1, v4}, Lct0/a;-><init>(Lct0/h;I)V

    .line 221
    .line 222
    .line 223
    iput v2, p0, Lct0/b;->e:I

    .line 224
    .line 225
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    if-ne p0, v0, :cond_b

    .line 230
    .line 231
    goto :goto_7

    .line 232
    :cond_b
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 233
    .line 234
    :goto_7
    return-object v0

    .line 235
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 236
    .line 237
    iget v1, p0, Lct0/b;->e:I

    .line 238
    .line 239
    const/4 v2, 0x1

    .line 240
    if-eqz v1, :cond_d

    .line 241
    .line 242
    if-ne v1, v2, :cond_c

    .line 243
    .line 244
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    goto :goto_8

    .line 248
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 249
    .line 250
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 251
    .line 252
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw p0

    .line 256
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 257
    .line 258
    .line 259
    iget-object p1, p0, Lct0/b;->f:Lct0/h;

    .line 260
    .line 261
    iget-object v1, p1, Lct0/h;->m:Lpg0/c;

    .line 262
    .line 263
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v1

    .line 267
    check-cast v1, Lyy0/i;

    .line 268
    .line 269
    new-instance v3, Lct0/a;

    .line 270
    .line 271
    const/4 v4, 0x0

    .line 272
    invoke-direct {v3, p1, v4}, Lct0/a;-><init>(Lct0/h;I)V

    .line 273
    .line 274
    .line 275
    iput v2, p0, Lct0/b;->e:I

    .line 276
    .line 277
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object p0

    .line 281
    if-ne p0, v0, :cond_e

    .line 282
    .line 283
    goto :goto_9

    .line 284
    :cond_e
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 285
    .line 286
    :goto_9
    return-object v0

    .line 287
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
