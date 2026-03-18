.class public final Lwk0/j1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lwk0/s1;


# direct methods
.method public synthetic constructor <init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lwk0/j1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

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
    iget p1, p0, Lwk0/j1;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lwk0/j1;

    .line 7
    .line 8
    iget-object p0, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lwk0/j1;

    .line 16
    .line 17
    iget-object p0, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lwk0/j1;

    .line 25
    .line 26
    iget-object p0, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lwk0/j1;

    .line 34
    .line 35
    iget-object p0, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Lwk0/j1;

    .line 43
    .line 44
    iget-object p0, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Lwk0/j1;-><init>(Lwk0/s1;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lwk0/j1;->d:I

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
    invoke-virtual {p0, p1, p2}, Lwk0/j1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lwk0/j1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lwk0/j1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lwk0/j1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lwk0/j1;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lwk0/j1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lwk0/j1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lwk0/j1;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lwk0/j1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lwk0/j1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lwk0/j1;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lwk0/j1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Lwk0/j1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lwk0/j1;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Lwk0/j1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 6

    .line 1
    iget v0, p0, Lwk0/j1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lwk0/j1;->e:I

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
    iget-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 31
    .line 32
    iget-object p1, p1, Lwk0/s1;->t:Lrq0/f;

    .line 33
    .line 34
    new-instance v1, Lsq0/c;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    const/4 v4, 0x6

    .line 38
    const v5, 0x7f1206f1

    .line 39
    .line 40
    .line 41
    invoke-direct {v1, v5, v4, v3}, Lsq0/c;-><init>(IILjava/lang/Integer;)V

    .line 42
    .line 43
    .line 44
    iput v2, p0, Lwk0/j1;->e:I

    .line 45
    .line 46
    const/4 v2, 0x0

    .line 47
    invoke-virtual {p1, v1, v2, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-ne p0, v0, :cond_2

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    :goto_1
    return-object v0

    .line 57
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 58
    .line 59
    iget v1, p0, Lwk0/j1;->e:I

    .line 60
    .line 61
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    const/4 v3, 0x2

    .line 64
    const/4 v4, 0x1

    .line 65
    if-eqz v1, :cond_6

    .line 66
    .line 67
    if-eq v1, v4, :cond_5

    .line 68
    .line 69
    if-ne v1, v3, :cond_4

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    move-object v0, v2

    .line 75
    goto :goto_3

    .line 76
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    iget-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 92
    .line 93
    iget-object p1, p1, Lwk0/s1;->l:Luk0/r0;

    .line 94
    .line 95
    iput v4, p0, Lwk0/j1;->e:I

    .line 96
    .line 97
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p1, p0}, Luk0/r0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    if-ne p1, v0, :cond_7

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_7
    :goto_2
    check-cast p1, Lyy0/i;

    .line 108
    .line 109
    iput v3, p0, Lwk0/j1;->e:I

    .line 110
    .line 111
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    if-ne p0, v0, :cond_3

    .line 116
    .line 117
    :goto_3
    return-object v0

    .line 118
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 119
    .line 120
    iget v1, p0, Lwk0/j1;->e:I

    .line 121
    .line 122
    const/4 v2, 0x1

    .line 123
    if-eqz v1, :cond_9

    .line 124
    .line 125
    if-ne v1, v2, :cond_8

    .line 126
    .line 127
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    goto :goto_4

    .line 131
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 132
    .line 133
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 134
    .line 135
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    throw p0

    .line 139
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 140
    .line 141
    .line 142
    iget-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 143
    .line 144
    iget-object v1, p1, Lwk0/s1;->x:Lpp0/l0;

    .line 145
    .line 146
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    check-cast v1, Lyy0/i;

    .line 151
    .line 152
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    new-instance v3, Lwk0/i1;

    .line 157
    .line 158
    const/4 v4, 0x2

    .line 159
    invoke-direct {v3, p1, v4}, Lwk0/i1;-><init>(Lwk0/s1;I)V

    .line 160
    .line 161
    .line 162
    iput v2, p0, Lwk0/j1;->e:I

    .line 163
    .line 164
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    if-ne p0, v0, :cond_a

    .line 169
    .line 170
    goto :goto_5

    .line 171
    :cond_a
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 172
    .line 173
    :goto_5
    return-object v0

    .line 174
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 175
    .line 176
    iget v1, p0, Lwk0/j1;->e:I

    .line 177
    .line 178
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 179
    .line 180
    const/4 v3, 0x1

    .line 181
    if-eqz v1, :cond_d

    .line 182
    .line 183
    if-ne v1, v3, :cond_c

    .line 184
    .line 185
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 186
    .line 187
    .line 188
    :cond_b
    move-object v0, v2

    .line 189
    goto :goto_7

    .line 190
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 191
    .line 192
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 193
    .line 194
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    throw p0

    .line 198
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    iget-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 202
    .line 203
    iget-object v1, p1, Lwk0/s1;->v:Luk0/c0;

    .line 204
    .line 205
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 206
    .line 207
    .line 208
    move-result-object v1

    .line 209
    check-cast v1, Lyy0/i;

    .line 210
    .line 211
    new-instance v4, Lwk0/i1;

    .line 212
    .line 213
    const/4 v5, 0x1

    .line 214
    invoke-direct {v4, p1, v5}, Lwk0/i1;-><init>(Lwk0/s1;I)V

    .line 215
    .line 216
    .line 217
    iput v3, p0, Lwk0/j1;->e:I

    .line 218
    .line 219
    new-instance p1, Lwk0/o0;

    .line 220
    .line 221
    const/4 v3, 0x1

    .line 222
    invoke-direct {p1, v4, v3}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 223
    .line 224
    .line 225
    invoke-interface {v1, p1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object p0

    .line 229
    if-ne p0, v0, :cond_e

    .line 230
    .line 231
    goto :goto_6

    .line 232
    :cond_e
    move-object p0, v2

    .line 233
    :goto_6
    if-ne p0, v0, :cond_b

    .line 234
    .line 235
    :goto_7
    return-object v0

    .line 236
    :pswitch_3
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 237
    .line 238
    iget v1, p0, Lwk0/j1;->e:I

    .line 239
    .line 240
    const/4 v2, 0x1

    .line 241
    if-eqz v1, :cond_10

    .line 242
    .line 243
    if-ne v1, v2, :cond_f

    .line 244
    .line 245
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 246
    .line 247
    .line 248
    goto :goto_8

    .line 249
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 250
    .line 251
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 252
    .line 253
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    throw p0

    .line 257
    :cond_10
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 258
    .line 259
    .line 260
    iget-object p1, p0, Lwk0/j1;->f:Lwk0/s1;

    .line 261
    .line 262
    iget-object v1, p1, Lwk0/s1;->j:Luk0/b0;

    .line 263
    .line 264
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v1

    .line 268
    check-cast v1, Lyy0/i;

    .line 269
    .line 270
    new-instance v3, Lwk0/i1;

    .line 271
    .line 272
    const/4 v4, 0x0

    .line 273
    invoke-direct {v3, p1, v4}, Lwk0/i1;-><init>(Lwk0/s1;I)V

    .line 274
    .line 275
    .line 276
    iput v2, p0, Lwk0/j1;->e:I

    .line 277
    .line 278
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object p0

    .line 282
    if-ne p0, v0, :cond_11

    .line 283
    .line 284
    goto :goto_9

    .line 285
    :cond_11
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 286
    .line 287
    :goto_9
    return-object v0

    .line 288
    nop

    .line 289
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
