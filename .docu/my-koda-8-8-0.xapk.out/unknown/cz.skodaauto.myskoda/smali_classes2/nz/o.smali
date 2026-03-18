.class public final Lnz/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lnz/z;


# direct methods
.method public synthetic constructor <init>(ILkotlin/coroutines/Continuation;Lnz/z;)V
    .locals 0

    .line 1
    iput p1, p0, Lnz/o;->d:I

    .line 2
    .line 3
    iput-object p3, p0, Lnz/o;->g:Lnz/z;

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
    iget v0, p0, Lnz/o;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lnz/o;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 9
    .line 10
    const/4 v1, 0x5

    .line 11
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lnz/o;

    .line 18
    .line 19
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 20
    .line 21
    const/4 v1, 0x4

    .line 22
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    :pswitch_1
    new-instance v0, Lnz/o;

    .line 29
    .line 30
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 31
    .line 32
    const/4 v1, 0x3

    .line 33
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 34
    .line 35
    .line 36
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 37
    .line 38
    return-object v0

    .line 39
    :pswitch_2
    new-instance v0, Lnz/o;

    .line 40
    .line 41
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 42
    .line 43
    const/4 v1, 0x2

    .line 44
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 48
    .line 49
    return-object v0

    .line 50
    :pswitch_3
    new-instance v0, Lnz/o;

    .line 51
    .line 52
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 53
    .line 54
    const/4 v1, 0x1

    .line 55
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 56
    .line 57
    .line 58
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_4
    new-instance v0, Lnz/o;

    .line 62
    .line 63
    iget-object p0, p0, Lnz/o;->g:Lnz/z;

    .line 64
    .line 65
    const/4 v1, 0x0

    .line 66
    invoke-direct {v0, v1, p2, p0}, Lnz/o;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, v0, Lnz/o;->f:Ljava/lang/Object;

    .line 70
    .line 71
    return-object v0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/o;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lnz/o;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Lnz/o;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Lnz/o;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :pswitch_3
    check-cast p1, Llx0/l;

    .line 75
    .line 76
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lnz/o;

    .line 83
    .line 84
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 85
    .line 86
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    return-object p0

    .line 91
    :pswitch_4
    check-cast p1, Lvy0/b0;

    .line 92
    .line 93
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 94
    .line 95
    invoke-virtual {p0, p1, p2}, Lnz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    check-cast p0, Lnz/o;

    .line 100
    .line 101
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    invoke-virtual {p0, p1}, Lnz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Lnz/o;->d:I

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    const/4 v3, 0x0

    .line 6
    iget-object v4, p0, Lnz/o;->g:Lnz/z;

    .line 7
    .line 8
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 9
    .line 10
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    const/4 v7, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lvy0/b0;

    .line 19
    .line 20
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    iget v2, p0, Lnz/o;->e:I

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    if-ne v2, v7, :cond_0

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    new-instance p1, Lnz/l;

    .line 42
    .line 43
    const/4 v2, 0x5

    .line 44
    invoke-direct {p1, v4, v2}, Lnz/l;-><init>(Lnz/z;I)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 48
    .line 49
    .line 50
    iget-object p1, v4, Lnz/z;->s:Llz/s;

    .line 51
    .line 52
    iput-object v3, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 53
    .line 54
    iput v7, p0, Lnz/o;->e:I

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 57
    .line 58
    .line 59
    invoke-virtual {p1, p0}, Llz/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_2

    .line 64
    .line 65
    move-object v6, v1

    .line 66
    goto :goto_1

    .line 67
    :cond_2
    :goto_0
    check-cast p1, Lne0/t;

    .line 68
    .line 69
    instance-of p0, p1, Lne0/e;

    .line 70
    .line 71
    if-eqz p0, :cond_3

    .line 72
    .line 73
    check-cast p1, Lne0/e;

    .line 74
    .line 75
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Llx0/b0;

    .line 78
    .line 79
    sget p0, Lnz/z;->B:I

    .line 80
    .line 81
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lnz/s;

    .line 86
    .line 87
    iget-object p1, v4, Lnz/z;->i:Lij0/a;

    .line 88
    .line 89
    invoke-static {p0, p1, v7}, Ljp/gb;->i(Lnz/s;Lij0/a;Z)Lnz/s;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 94
    .line 95
    .line 96
    :cond_3
    :goto_1
    return-object v6

    .line 97
    :pswitch_0
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v0, Lvy0/b0;

    .line 100
    .line 101
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 102
    .line 103
    iget v8, p0, Lnz/o;->e:I

    .line 104
    .line 105
    if-eqz v8, :cond_5

    .line 106
    .line 107
    if-ne v8, v7, :cond_4

    .line 108
    .line 109
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    goto :goto_5

    .line 113
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 114
    .line 115
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    throw p0

    .line 119
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    new-instance p1, Lnz/l;

    .line 123
    .line 124
    const/4 v5, 0x4

    .line 125
    invoke-direct {p1, v4, v5}, Lnz/l;-><init>(Lnz/z;I)V

    .line 126
    .line 127
    .line 128
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 129
    .line 130
    .line 131
    iget-object p1, v4, Lnz/z;->r:Llz/q;

    .line 132
    .line 133
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    check-cast v0, Lnz/s;

    .line 138
    .line 139
    iget-object v9, v0, Lnz/s;->v:Lmz/a;

    .line 140
    .line 141
    iget-boolean v5, v0, Lnz/s;->j:Z

    .line 142
    .line 143
    if-eqz v5, :cond_6

    .line 144
    .line 145
    sget-object v5, Lmz/d;->d:Lmz/d;

    .line 146
    .line 147
    :goto_2
    move-object v12, v5

    .line 148
    goto :goto_3

    .line 149
    :cond_6
    sget-object v5, Lmz/d;->e:Lmz/d;

    .line 150
    .line 151
    goto :goto_2

    .line 152
    :goto_3
    iget-object v5, v0, Lnz/s;->y:Lmy0/c;

    .line 153
    .line 154
    if-eqz v5, :cond_7

    .line 155
    .line 156
    iget-wide v10, v5, Lmy0/c;->d:J

    .line 157
    .line 158
    goto :goto_4

    .line 159
    :cond_7
    sget v5, Lmy0/c;->g:I

    .line 160
    .line 161
    const/16 v5, 0xa

    .line 162
    .line 163
    sget-object v8, Lmy0/e;->i:Lmy0/e;

    .line 164
    .line 165
    invoke-static {v5, v8}, Lmy0/h;->s(ILmy0/e;)J

    .line 166
    .line 167
    .line 168
    move-result-wide v10

    .line 169
    :goto_4
    iget-object v13, v0, Lnz/s;->w:Lqr0/q;

    .line 170
    .line 171
    new-instance v8, Lmz/b;

    .line 172
    .line 173
    invoke-direct/range {v8 .. v13}, Lmz/b;-><init>(Lmz/a;JLmz/d;Lqr0/q;)V

    .line 174
    .line 175
    .line 176
    iput-object v3, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 177
    .line 178
    iput v7, p0, Lnz/o;->e:I

    .line 179
    .line 180
    invoke-virtual {p1, v8, p0}, Llz/q;->b(Lmz/b;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    if-ne p1, v1, :cond_8

    .line 185
    .line 186
    move-object v6, v1

    .line 187
    goto :goto_6

    .line 188
    :cond_8
    :goto_5
    check-cast p1, Lne0/t;

    .line 189
    .line 190
    if-eqz p1, :cond_9

    .line 191
    .line 192
    instance-of p0, p1, Lne0/e;

    .line 193
    .line 194
    if-eqz p0, :cond_9

    .line 195
    .line 196
    check-cast p1, Lne0/e;

    .line 197
    .line 198
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast p0, Llx0/b0;

    .line 201
    .line 202
    sget p0, Lnz/z;->B:I

    .line 203
    .line 204
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 205
    .line 206
    .line 207
    move-result-object p0

    .line 208
    check-cast p0, Lnz/s;

    .line 209
    .line 210
    iget-object p1, v4, Lnz/z;->i:Lij0/a;

    .line 211
    .line 212
    invoke-static {p0, p1, v2}, Ljp/gb;->i(Lnz/s;Lij0/a;Z)Lnz/s;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 217
    .line 218
    .line 219
    :cond_9
    :goto_6
    return-object v6

    .line 220
    :pswitch_1
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 221
    .line 222
    check-cast v0, Lvy0/b0;

    .line 223
    .line 224
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 225
    .line 226
    iget v8, p0, Lnz/o;->e:I

    .line 227
    .line 228
    if-eqz v8, :cond_b

    .line 229
    .line 230
    if-ne v8, v7, :cond_a

    .line 231
    .line 232
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    goto :goto_7

    .line 236
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 237
    .line 238
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    throw p0

    .line 242
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 243
    .line 244
    .line 245
    new-instance p1, Lnz/l;

    .line 246
    .line 247
    const/4 v5, 0x3

    .line 248
    invoke-direct {p1, v4, v5}, Lnz/l;-><init>(Lnz/z;I)V

    .line 249
    .line 250
    .line 251
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 252
    .line 253
    .line 254
    sget p1, Lnz/z;->B:I

    .line 255
    .line 256
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 257
    .line 258
    .line 259
    move-result-object p1

    .line 260
    check-cast p1, Lnz/s;

    .line 261
    .line 262
    iget-object p1, p1, Lnz/s;->w:Lqr0/q;

    .line 263
    .line 264
    if-eqz p1, :cond_c

    .line 265
    .line 266
    iget-object v0, v4, Lnz/z;->v:Llb0/e0;

    .line 267
    .line 268
    invoke-virtual {v0, p1}, Llb0/e0;->a(Lqr0/q;)Lyy0/m1;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    new-instance v0, Lnz/x;

    .line 273
    .line 274
    invoke-direct {v0, v4, v1}, Lnz/x;-><init>(Lnz/z;I)V

    .line 275
    .line 276
    .line 277
    iput-object v3, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 278
    .line 279
    iput v7, p0, Lnz/o;->e:I

    .line 280
    .line 281
    invoke-virtual {p1, v0, p0}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object p0

    .line 285
    if-ne p0, v2, :cond_c

    .line 286
    .line 287
    move-object v6, v2

    .line 288
    :cond_c
    :goto_7
    return-object v6

    .line 289
    :pswitch_2
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v0, Lvy0/b0;

    .line 292
    .line 293
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 294
    .line 295
    iget v9, p0, Lnz/o;->e:I

    .line 296
    .line 297
    if-eqz v9, :cond_e

    .line 298
    .line 299
    if-ne v9, v7, :cond_d

    .line 300
    .line 301
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    goto :goto_8

    .line 305
    :cond_d
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 306
    .line 307
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw p0

    .line 311
    :cond_e
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    new-instance p1, Lnz/l;

    .line 315
    .line 316
    invoke-direct {p1, v4, v1}, Lnz/l;-><init>(Lnz/z;I)V

    .line 317
    .line 318
    .line 319
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 320
    .line 321
    .line 322
    iget-object p1, v4, Lnz/z;->k:Llz/k;

    .line 323
    .line 324
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object p1

    .line 328
    check-cast p1, Lyy0/i;

    .line 329
    .line 330
    invoke-static {p1}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 331
    .line 332
    .line 333
    move-result-object p1

    .line 334
    invoke-static {p1, v7}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 335
    .line 336
    .line 337
    move-result-object p1

    .line 338
    new-instance v0, Lnz/u;

    .line 339
    .line 340
    invoke-direct {v0, v7, v3, v4}, Lnz/u;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 341
    .line 342
    .line 343
    invoke-static {p1, v0}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 344
    .line 345
    .line 346
    move-result-object p1

    .line 347
    new-instance v0, Lnz/x;

    .line 348
    .line 349
    invoke-direct {v0, v4, v2}, Lnz/x;-><init>(Lnz/z;I)V

    .line 350
    .line 351
    .line 352
    iput-object v3, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 353
    .line 354
    iput v7, p0, Lnz/o;->e:I

    .line 355
    .line 356
    invoke-virtual {p1, v0, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    if-ne p0, v8, :cond_f

    .line 361
    .line 362
    move-object v6, v8

    .line 363
    :cond_f
    :goto_8
    return-object v6

    .line 364
    :pswitch_3
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 365
    .line 366
    check-cast v0, Llx0/l;

    .line 367
    .line 368
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 369
    .line 370
    iget v2, p0, Lnz/o;->e:I

    .line 371
    .line 372
    if-eqz v2, :cond_11

    .line 373
    .line 374
    if-ne v2, v7, :cond_10

    .line 375
    .line 376
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 377
    .line 378
    .line 379
    goto :goto_9

    .line 380
    :cond_10
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 381
    .line 382
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    throw p0

    .line 386
    :cond_11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 387
    .line 388
    .line 389
    iget-object p1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 390
    .line 391
    move-object v12, p1

    .line 392
    check-cast v12, Lne0/s;

    .line 393
    .line 394
    iget-object p1, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 395
    .line 396
    move-object v10, p1

    .line 397
    check-cast v10, Ljava/util/List;

    .line 398
    .line 399
    new-instance v8, Lh7/z;

    .line 400
    .line 401
    iget-object v11, p0, Lnz/o;->g:Lnz/z;

    .line 402
    .line 403
    const/16 v9, 0x10

    .line 404
    .line 405
    const/4 v13, 0x0

    .line 406
    invoke-direct/range {v8 .. v13}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 407
    .line 408
    .line 409
    iput-object v13, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 410
    .line 411
    iput v7, p0, Lnz/o;->e:I

    .line 412
    .line 413
    invoke-static {v8, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 414
    .line 415
    .line 416
    move-result-object p0

    .line 417
    if-ne p0, v1, :cond_12

    .line 418
    .line 419
    move-object v6, v1

    .line 420
    :cond_12
    :goto_9
    return-object v6

    .line 421
    :pswitch_4
    iget-object v0, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 422
    .line 423
    check-cast v0, Lvy0/b0;

    .line 424
    .line 425
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 426
    .line 427
    iget v8, p0, Lnz/o;->e:I

    .line 428
    .line 429
    if-eqz v8, :cond_14

    .line 430
    .line 431
    if-ne v8, v7, :cond_13

    .line 432
    .line 433
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 434
    .line 435
    .line 436
    goto :goto_a

    .line 437
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 438
    .line 439
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 440
    .line 441
    .line 442
    throw p0

    .line 443
    :cond_14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 444
    .line 445
    .line 446
    iget-object p1, v4, Lnz/z;->j:Lkf0/v;

    .line 447
    .line 448
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 449
    .line 450
    .line 451
    move-result-object p1

    .line 452
    check-cast p1, Lyy0/i;

    .line 453
    .line 454
    sget-object v5, Lss0/e;->m:Lss0/e;

    .line 455
    .line 456
    new-instance v8, Lnz/m;

    .line 457
    .line 458
    invoke-direct {v8, v2, v3, v4}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 459
    .line 460
    .line 461
    invoke-static {p1, v5, v8}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 462
    .line 463
    .line 464
    move-result-object p1

    .line 465
    new-instance v2, Lnz/m;

    .line 466
    .line 467
    invoke-direct {v2, v7, v3, v4}, Lnz/m;-><init>(ILkotlin/coroutines/Continuation;Lnz/z;)V

    .line 468
    .line 469
    .line 470
    invoke-static {p1, v5, v2}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 471
    .line 472
    .line 473
    move-result-object p1

    .line 474
    new-instance v2, Laa/s;

    .line 475
    .line 476
    const/16 v5, 0x1a

    .line 477
    .line 478
    invoke-direct {v2, v5, v4, v0, v3}, Laa/s;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 479
    .line 480
    .line 481
    iput-object v3, p0, Lnz/o;->f:Ljava/lang/Object;

    .line 482
    .line 483
    iput v7, p0, Lnz/o;->e:I

    .line 484
    .line 485
    invoke-static {v2, p0, p1}, Lbb/j0;->a(Lay0/n;Lkotlin/coroutines/Continuation;Lyy0/i;)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object p0

    .line 489
    if-ne p0, v1, :cond_15

    .line 490
    .line 491
    move-object v6, v1

    .line 492
    :cond_15
    :goto_a
    return-object v6

    .line 493
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
