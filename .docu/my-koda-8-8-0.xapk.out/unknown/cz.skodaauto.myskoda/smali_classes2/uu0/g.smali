.class public final Luu0/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Luu0/x;


# direct methods
.method public synthetic constructor <init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Luu0/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Luu0/g;->g:Luu0/x;

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
    .locals 2

    .line 1
    iget v0, p0, Luu0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Luu0/g;

    .line 7
    .line 8
    iget-object p0, p0, Luu0/g;->g:Luu0/x;

    .line 9
    .line 10
    const/4 v1, 0x3

    .line 11
    invoke-direct {v0, p0, p2, v1}, Luu0/g;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Luu0/g;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Luu0/g;

    .line 18
    .line 19
    iget-object p0, p0, Luu0/g;->g:Luu0/x;

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    invoke-direct {v0, p0, p2, v1}, Luu0/g;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Luu0/g;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Luu0/g;

    .line 29
    .line 30
    iget-object p0, p0, Luu0/g;->g:Luu0/x;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, p0, p2, v1}, Luu0/g;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Luu0/g;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Luu0/g;

    .line 40
    .line 41
    iget-object p0, p0, Luu0/g;->g:Luu0/x;

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-direct {v0, p0, p2, v1}, Luu0/g;-><init>(Luu0/x;Lkotlin/coroutines/Continuation;I)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Luu0/g;->f:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    nop

    .line 51
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
    iget v0, p0, Luu0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Luu0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Luu0/g;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Luu0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lvy0/b0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Luu0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Luu0/g;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Luu0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lne0/s;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Luu0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Luu0/g;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Luu0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lvy0/b0;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Luu0/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Luu0/g;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Luu0/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Luu0/g;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    const-string v4, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    iget-object v5, p0, Luu0/g;->g:Luu0/x;

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    iget-object v0, v5, Luu0/x;->D:Lij0/a;

    .line 16
    .line 17
    iget-object v7, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v7, Lvy0/b0;

    .line 20
    .line 21
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    iget v9, p0, Luu0/g;->e:I

    .line 24
    .line 25
    if-eqz v9, :cond_1

    .line 26
    .line 27
    if-ne v9, v6, :cond_0

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p1, v5, Luu0/x;->E:Lrq0/f;

    .line 43
    .line 44
    new-instance v4, Lsq0/c;

    .line 45
    .line 46
    new-array v9, v1, [Ljava/lang/Object;

    .line 47
    .line 48
    move-object v10, v0

    .line 49
    check-cast v10, Ljj0/f;

    .line 50
    .line 51
    const v11, 0x7f1204b9

    .line 52
    .line 53
    .line 54
    invoke-virtual {v10, v11, v9}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v9

    .line 58
    new-array v10, v1, [Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Ljj0/f;

    .line 61
    .line 62
    const v11, 0x7f1204b8

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v11, v10}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    const/4 v10, 0x4

    .line 70
    invoke-direct {v4, v10, v9, v0, v3}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    iput-object v7, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 74
    .line 75
    iput v6, p0, Luu0/g;->e:I

    .line 76
    .line 77
    invoke-virtual {p1, v4, v1, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    if-ne p1, v8, :cond_2

    .line 82
    .line 83
    move-object v2, v8

    .line 84
    goto :goto_1

    .line 85
    :cond_2
    :goto_0
    check-cast p1, Lsq0/d;

    .line 86
    .line 87
    sget-object p0, Lsq0/d;->d:Lsq0/d;

    .line 88
    .line 89
    if-ne p1, p0, :cond_3

    .line 90
    .line 91
    new-instance p0, Lu2/a;

    .line 92
    .line 93
    const/4 p1, 0x7

    .line 94
    invoke-direct {p0, v5, p1}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 95
    .line 96
    .line 97
    invoke-static {v7, p0}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 98
    .line 99
    .line 100
    iget-object p0, v5, Luu0/x;->y:Lru0/f0;

    .line 101
    .line 102
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    :cond_3
    :goto_1
    return-object v2

    .line 106
    :pswitch_0
    iget-object v0, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v0, Lvy0/b0;

    .line 109
    .line 110
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 111
    .line 112
    iget v7, p0, Luu0/g;->e:I

    .line 113
    .line 114
    if-eqz v7, :cond_5

    .line 115
    .line 116
    if-ne v7, v6, :cond_4

    .line 117
    .line 118
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 123
    .line 124
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    iget-object p1, v5, Luu0/x;->S:Lep0/j;

    .line 132
    .line 133
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p1

    .line 137
    check-cast p1, Lyy0/i;

    .line 138
    .line 139
    new-instance v4, Luu0/f;

    .line 140
    .line 141
    invoke-direct {v4, v0, v5, v6}, Luu0/f;-><init>(Lvy0/b0;Luu0/x;I)V

    .line 142
    .line 143
    .line 144
    iput-object v3, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 145
    .line 146
    iput v6, p0, Luu0/g;->e:I

    .line 147
    .line 148
    invoke-interface {p1, v4, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    if-ne p0, v1, :cond_6

    .line 153
    .line 154
    move-object v2, v1

    .line 155
    :cond_6
    :goto_2
    return-object v2

    .line 156
    :pswitch_1
    iget-object v0, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v0, Lne0/s;

    .line 159
    .line 160
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 161
    .line 162
    iget v8, p0, Luu0/g;->e:I

    .line 163
    .line 164
    if-eqz v8, :cond_8

    .line 165
    .line 166
    if-ne v8, v6, :cond_7

    .line 167
    .line 168
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    goto :goto_3

    .line 172
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 173
    .line 174
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 175
    .line 176
    .line 177
    throw p0

    .line 178
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    iput-object v3, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 182
    .line 183
    iput v6, p0, Luu0/g;->e:I

    .line 184
    .line 185
    sget-object p1, Luu0/x;->q1:Ljava/util/List;

    .line 186
    .line 187
    invoke-virtual {v5, v0, v6, v1, p0}, Luu0/x;->B(Lne0/s;ZZLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object p0

    .line 191
    if-ne p0, v7, :cond_9

    .line 192
    .line 193
    move-object v2, v7

    .line 194
    :cond_9
    :goto_3
    return-object v2

    .line 195
    :pswitch_2
    iget-object v0, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Lvy0/b0;

    .line 198
    .line 199
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 200
    .line 201
    iget v8, p0, Luu0/g;->e:I

    .line 202
    .line 203
    const/4 v9, 0x2

    .line 204
    if-eqz v8, :cond_c

    .line 205
    .line 206
    if-eq v8, v6, :cond_b

    .line 207
    .line 208
    if-ne v8, v9, :cond_a

    .line 209
    .line 210
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    goto :goto_6

    .line 214
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 215
    .line 216
    invoke-direct {p0, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 217
    .line 218
    .line 219
    throw p0

    .line 220
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 225
    .line 226
    .line 227
    iget-object p1, v5, Luu0/x;->s:Lru0/b0;

    .line 228
    .line 229
    iput-object v0, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 230
    .line 231
    iput v6, p0, Luu0/g;->e:I

    .line 232
    .line 233
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p1, p0}, Lru0/b0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    if-ne p1, v7, :cond_d

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_d
    :goto_4
    check-cast p1, Lyy0/i;

    .line 244
    .line 245
    new-instance v4, Luu0/f;

    .line 246
    .line 247
    invoke-direct {v4, v0, v5, v1}, Luu0/f;-><init>(Lvy0/b0;Luu0/x;I)V

    .line 248
    .line 249
    .line 250
    iput-object v3, p0, Luu0/g;->f:Ljava/lang/Object;

    .line 251
    .line 252
    iput v9, p0, Luu0/g;->e:I

    .line 253
    .line 254
    invoke-interface {p1, v4, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    if-ne p0, v7, :cond_e

    .line 259
    .line 260
    :goto_5
    move-object v2, v7

    .line 261
    :cond_e
    :goto_6
    return-object v2

    .line 262
    nop

    .line 263
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
