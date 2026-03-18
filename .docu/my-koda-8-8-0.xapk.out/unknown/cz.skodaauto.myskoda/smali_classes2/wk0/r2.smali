.class public final Lwk0/r2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lwk0/t2;


# direct methods
.method public synthetic constructor <init>(Lwk0/t2;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lwk0/r2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lwk0/r2;->f:Lwk0/t2;

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
    iget p1, p0, Lwk0/r2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lwk0/r2;

    .line 7
    .line 8
    iget-object p0, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lwk0/r2;-><init>(Lwk0/t2;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lwk0/r2;

    .line 16
    .line 17
    iget-object p0, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lwk0/r2;-><init>(Lwk0/t2;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lwk0/r2;

    .line 25
    .line 26
    iget-object p0, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lwk0/r2;-><init>(Lwk0/t2;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lwk0/r2;->d:I

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
    invoke-virtual {p0, p1, p2}, Lwk0/r2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lwk0/r2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lwk0/r2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lwk0/r2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lwk0/r2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lwk0/r2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lwk0/r2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lwk0/r2;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lwk0/r2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lwk0/r2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lwk0/r2;->e:I

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
    iget-object p1, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 31
    .line 32
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Lwk0/x1;

    .line 37
    .line 38
    iget-object v1, v1, Lwk0/x1;->m:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lwk0/p2;

    .line 41
    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    iget-object v3, p1, Lwk0/t2;->o:Lbq0/p;

    .line 45
    .line 46
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Lwk0/x1;

    .line 51
    .line 52
    iget-object v4, v4, Lwk0/x1;->a:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v3, v4}, Lbq0/p;->a(Ljava/lang/String;)Lyy0/i;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    new-instance v4, Lwa0/c;

    .line 59
    .line 60
    const/4 v5, 0x3

    .line 61
    const/4 v6, 0x0

    .line 62
    invoke-direct {v4, v5, p1, v1, v6}, Lwa0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lne0/n;

    .line 66
    .line 67
    invoke-direct {v1, v4, v3}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 68
    .line 69
    .line 70
    new-instance v3, Lwk0/q2;

    .line 71
    .line 72
    const/4 v4, 0x1

    .line 73
    invoke-direct {v3, p1, v4}, Lwk0/q2;-><init>(Lwk0/t2;I)V

    .line 74
    .line 75
    .line 76
    iput v2, p0, Lwk0/r2;->e:I

    .line 77
    .line 78
    invoke-virtual {v1, v3, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, v0, :cond_2

    .line 83
    .line 84
    goto :goto_1

    .line 85
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 86
    .line 87
    :goto_1
    return-object v0

    .line 88
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 89
    .line 90
    iget v1, p0, Lwk0/r2;->e:I

    .line 91
    .line 92
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    iget-object v3, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 95
    .line 96
    const/4 v4, 0x3

    .line 97
    const/4 v5, 0x2

    .line 98
    const/4 v6, 0x1

    .line 99
    if-eqz v1, :cond_7

    .line 100
    .line 101
    if-eq v1, v6, :cond_6

    .line 102
    .line 103
    if-eq v1, v5, :cond_5

    .line 104
    .line 105
    if-ne v1, v4, :cond_4

    .line 106
    .line 107
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    :cond_3
    move-object v0, v2

    .line 111
    goto :goto_4

    .line 112
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 113
    .line 114
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 115
    .line 116
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget-object p1, v3, Lwk0/t2;->r:Luk0/r0;

    .line 132
    .line 133
    iput v6, p0, Lwk0/r2;->e:I

    .line 134
    .line 135
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 136
    .line 137
    .line 138
    invoke-virtual {p1, p0}, Luk0/r0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    if-ne p1, v0, :cond_8

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_8
    :goto_2
    check-cast p1, Lyy0/i;

    .line 146
    .line 147
    iput v5, p0, Lwk0/r2;->e:I

    .line 148
    .line 149
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-ne p1, v0, :cond_9

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_9
    :goto_3
    iget-object p1, v3, Lwk0/t2;->s:Lbq0/c;

    .line 157
    .line 158
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    check-cast p1, Lyy0/i;

    .line 163
    .line 164
    iput v4, p0, Lwk0/r2;->e:I

    .line 165
    .line 166
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object p0

    .line 170
    if-ne p0, v0, :cond_3

    .line 171
    .line 172
    :goto_4
    return-object v0

    .line 173
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 174
    .line 175
    iget v1, p0, Lwk0/r2;->e:I

    .line 176
    .line 177
    iget-object v2, p0, Lwk0/r2;->f:Lwk0/t2;

    .line 178
    .line 179
    const/4 v3, 0x1

    .line 180
    const/4 v4, 0x2

    .line 181
    if-eqz v1, :cond_c

    .line 182
    .line 183
    if-eq v1, v3, :cond_b

    .line 184
    .line 185
    if-ne v1, v4, :cond_a

    .line 186
    .line 187
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    goto :goto_6

    .line 191
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 192
    .line 193
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 194
    .line 195
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw p0

    .line 199
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    goto :goto_5

    .line 203
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    iget-object p1, v2, Lwk0/t2;->q:Lbq0/q;

    .line 207
    .line 208
    iput v3, p0, Lwk0/r2;->e:I

    .line 209
    .line 210
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    iget-object v1, p1, Lbq0/q;->c:Lkf0/o;

    .line 214
    .line 215
    invoke-static {v1}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 216
    .line 217
    .line 218
    move-result-object v1

    .line 219
    new-instance v3, La90/c;

    .line 220
    .line 221
    const/16 v5, 0x9

    .line 222
    .line 223
    const/4 v6, 0x0

    .line 224
    invoke-direct {v3, v6, p1, v5}, La90/c;-><init>(Lkotlin/coroutines/Continuation;Ljava/lang/Object;I)V

    .line 225
    .line 226
    .line 227
    invoke-static {v1, v3}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    iget-object p1, p1, Lbq0/q;->d:Lsf0/a;

    .line 232
    .line 233
    invoke-static {v1, p1, v6}, Llp/o1;->d(Lyy0/i;Lsf0/a;Ljava/lang/String;)Lam0/i;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    if-ne p1, v0, :cond_d

    .line 238
    .line 239
    goto :goto_7

    .line 240
    :cond_d
    :goto_5
    check-cast p1, Lyy0/i;

    .line 241
    .line 242
    new-instance v1, Lwk0/q2;

    .line 243
    .line 244
    const/4 v3, 0x0

    .line 245
    invoke-direct {v1, v2, v3}, Lwk0/q2;-><init>(Lwk0/t2;I)V

    .line 246
    .line 247
    .line 248
    iput v4, p0, Lwk0/r2;->e:I

    .line 249
    .line 250
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    if-ne p0, v0, :cond_e

    .line 255
    .line 256
    goto :goto_7

    .line 257
    :cond_e
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 258
    .line 259
    :goto_7
    return-object v0

    .line 260
    nop

    .line 261
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
