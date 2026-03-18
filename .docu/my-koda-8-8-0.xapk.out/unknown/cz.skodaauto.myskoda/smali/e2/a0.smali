.class public final Le2/a0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Le2/a0;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Le2/a0;->h:Lay0/k;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Le2/a0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Le2/a0;

    .line 7
    .line 8
    iget-object p0, p0, Le2/a0;->h:Lay0/k;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Le2/a0;->g:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Le2/a0;

    .line 18
    .line 19
    iget-object p0, p0, Le2/a0;->h:Lay0/k;

    .line 20
    .line 21
    const/4 v1, 0x1

    .line 22
    invoke-direct {v0, p0, p2, v1}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Le2/a0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Le2/a0;

    .line 29
    .line 30
    iget-object p0, p0, Le2/a0;->h:Lay0/k;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    invoke-direct {v0, p0, p2, v1}, Le2/a0;-><init>(Lay0/k;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Le2/a0;->g:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Le2/a0;->e:I

    .line 2
    .line 3
    check-cast p1, Lp3/i0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Le2/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Le2/a0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Le2/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Le2/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Le2/a0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Le2/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Le2/a0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Le2/a0;

    .line 42
    .line 43
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Le2/a0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Le2/a0;->e:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x2

    .line 5
    iget-object v3, p0, Le2/a0;->h:Lay0/k;

    .line 6
    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    const/4 v5, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 14
    .line 15
    iget v6, p0, Le2/a0;->f:I

    .line 16
    .line 17
    if-eqz v6, :cond_2

    .line 18
    .line 19
    if-eq v6, v5, :cond_1

    .line 20
    .line 21
    if-ne v6, v2, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    iget-object v4, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v4, Lp3/i0;

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iget-object p1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 45
    .line 46
    move-object v4, p1

    .line 47
    check-cast v4, Lp3/i0;

    .line 48
    .line 49
    iput-object v4, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 50
    .line 51
    iput v5, p0, Le2/a0;->f:I

    .line 52
    .line 53
    invoke-static {v4, p0}, Llp/ae;->a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v0, :cond_3

    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    :goto_0
    check-cast p1, Lp3/t;

    .line 61
    .line 62
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 63
    .line 64
    .line 65
    iget-wide v5, p1, Lp3/t;->c:J

    .line 66
    .line 67
    new-instance p1, Ld3/b;

    .line 68
    .line 69
    invoke-direct {p1, v5, v6}, Ld3/b;-><init>(J)V

    .line 70
    .line 71
    .line 72
    invoke-interface {v3, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    iput-object v1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 76
    .line 77
    iput v2, p0, Le2/a0;->f:I

    .line 78
    .line 79
    sget-object p1, Lg1/g3;->a:Lg1/e1;

    .line 80
    .line 81
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 82
    .line 83
    invoke-static {v4, p1, p0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p1

    .line 87
    if-ne p1, v0, :cond_4

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    :goto_1
    check-cast p1, Lp3/t;

    .line 91
    .line 92
    if-eqz p1, :cond_5

    .line 93
    .line 94
    invoke-virtual {p1}, Lp3/t;->a()V

    .line 95
    .line 96
    .line 97
    :cond_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 98
    .line 99
    :goto_2
    return-object v0

    .line 100
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 101
    .line 102
    iget v6, p0, Le2/a0;->f:I

    .line 103
    .line 104
    if-eqz v6, :cond_7

    .line 105
    .line 106
    if-ne v6, v5, :cond_6

    .line 107
    .line 108
    iget-object v4, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 109
    .line 110
    check-cast v4, Lp3/i0;

    .line 111
    .line 112
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    goto :goto_4

    .line 116
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-object p1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p1, Lp3/i0;

    .line 128
    .line 129
    move-object v4, p1

    .line 130
    :cond_8
    :goto_3
    iput-object v4, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 131
    .line 132
    iput v5, p0, Le2/a0;->f:I

    .line 133
    .line 134
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 135
    .line 136
    invoke-virtual {v4, p1, p0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    if-ne p1, v0, :cond_9

    .line 141
    .line 142
    return-object v0

    .line 143
    :cond_9
    :goto_4
    check-cast p1, Lp3/k;

    .line 144
    .line 145
    iget v6, p1, Lp3/k;->e:I

    .line 146
    .line 147
    if-ne v6, v5, :cond_a

    .line 148
    .line 149
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 150
    .line 151
    invoke-static {p1}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    check-cast p1, Lp3/t;

    .line 156
    .line 157
    iget-wide v6, p1, Lp3/t;->c:J

    .line 158
    .line 159
    invoke-static {v6, v7}, Ld3/b;->e(J)F

    .line 160
    .line 161
    .line 162
    move-result p1

    .line 163
    invoke-static {v6, v7}, Ld3/b;->f(J)F

    .line 164
    .line 165
    .line 166
    move-result v6

    .line 167
    invoke-static {p1}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 168
    .line 169
    .line 170
    move-result p1

    .line 171
    int-to-long v7, p1

    .line 172
    invoke-static {v6}, Ljava/lang/Float;->floatToIntBits(F)I

    .line 173
    .line 174
    .line 175
    move-result p1

    .line 176
    int-to-long v9, p1

    .line 177
    const/16 p1, 0x20

    .line 178
    .line 179
    shl-long v6, v7, p1

    .line 180
    .line 181
    const-wide v11, 0xffffffffL

    .line 182
    .line 183
    .line 184
    .line 185
    .line 186
    and-long v8, v9, v11

    .line 187
    .line 188
    or-long/2addr v6, v8

    .line 189
    new-instance p1, Lpw/g;

    .line 190
    .line 191
    invoke-direct {p1, v6, v7}, Lpw/g;-><init>(J)V

    .line 192
    .line 193
    .line 194
    invoke-interface {v3, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    goto :goto_3

    .line 198
    :cond_a
    if-ne v6, v2, :cond_8

    .line 199
    .line 200
    invoke-interface {v3, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    goto :goto_3

    .line 204
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 205
    .line 206
    iget v1, p0, Le2/a0;->f:I

    .line 207
    .line 208
    if-eqz v1, :cond_c

    .line 209
    .line 210
    if-ne v1, v5, :cond_b

    .line 211
    .line 212
    iget-object v1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v1, Lp3/i0;

    .line 215
    .line 216
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    goto :goto_6

    .line 220
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 221
    .line 222
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    throw p0

    .line 226
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    iget-object p1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 230
    .line 231
    check-cast p1, Lp3/i0;

    .line 232
    .line 233
    move-object v1, p1

    .line 234
    :goto_5
    sget-object p1, Lp3/l;->d:Lp3/l;

    .line 235
    .line 236
    iput-object v1, p0, Le2/a0;->g:Ljava/lang/Object;

    .line 237
    .line 238
    iput v5, p0, Le2/a0;->f:I

    .line 239
    .line 240
    invoke-virtual {v1, p1, p0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    if-ne p1, v0, :cond_d

    .line 245
    .line 246
    return-object v0

    .line 247
    :cond_d
    :goto_6
    check-cast p1, Lp3/k;

    .line 248
    .line 249
    invoke-static {p1}, Lkp/s;->d(Lp3/k;)Z

    .line 250
    .line 251
    .line 252
    move-result p1

    .line 253
    xor-int/2addr p1, v5

    .line 254
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 255
    .line 256
    .line 257
    move-result-object p1

    .line 258
    invoke-interface {v3, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    goto :goto_5

    .line 262
    nop

    .line 263
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
